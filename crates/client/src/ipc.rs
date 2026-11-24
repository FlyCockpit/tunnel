//! Command ↔ daemon IPC: newline-delimited JSON over `<state dir>/daemon.sock`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::time::Duration;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::time::Instant;
use tunnel_protocol::{EXIT_REPLACED, EXIT_REVOKED, IceConfig, read_json_line, write_json_line};

use crate::login::AccessInfo;
use crate::paths::{
    ENV_ICE_FILE, ENV_SERVER, ENV_TARGET, ENV_TOKEN, Paths, env_nonempty, env_token, validate_tunnel_token,
};
use crate::state::{Persisted, resolve_server};

const SPAWN_WAIT: Duration = Duration::from_secs(5);
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Expose {
        ports: Vec<u16>,
        /// The command's `TUNNEL_TOKEN`; a different token switches tunnels.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
        /// IP literal to dial for exposed ports instead of loopback; saved with
        /// the tunnel (a different token starts again from loopback).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
    },
    Unexpose {
        port: u16,
        /// Only if the daemon still serves this tunnel (checked atomically by the daemon).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect: Option<Expect>,
    },
    Status,
    Ice {
        fresh: bool,
    },
    Stop {
        /// Only if the daemon still serves this tunnel; otherwise an error and it keeps running.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect: Option<Expect>,
    },
}

/// The tunnel a request is meant for: its id, or before the daemon's first
/// Welcome (no id yet) its token. Needs the daemon feature `expect`: an
/// older daemon would ignore it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Expect {
    pub tunnel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status {
        status: Status,
    },
    Ice {
        ice: IceConfig,
        ice_file: String,
        /// `http://127.0.0.1:<port>/ice` and the bearer token it requires.
        #[serde(default)]
        ice_url: Option<String>,
        #[serde(default)]
        ice_token: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Connecting,
    Connected,
    /// Token rejected (401/410) or tunnel deleted/expired. Terminal.
    Revoked,
    /// Another client connected with the same token. Terminal for this daemon.
    Replaced,
    /// No daemon and no persisted tunnel.
    Stopped,
}

impl ConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnState::Connecting => "connecting",
            ConnState::Connected => "connected",
            ConnState::Revoked => "revoked",
            ConnState::Replaced => "replaced",
            ConnState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: ConnState,
    pub tunnel_id: Option<String>,
    pub host_template: Option<String>,
    pub ports: Vec<PortStatus>,
    pub last_error: Option<String>,
    pub ice_file: Option<String>,
    /// Address exposed ports are dialled on; `null`: loopback.
    #[serde(default)]
    pub target: Option<std::net::IpAddr>,
    /// What the answering daemon supports (see [`DAEMON_FEATURES`]); empty
    /// for a daemon that predates this list.
    #[serde(default)]
    pub features: Vec<String>,
}

/// Reported in `Status.features`. `target`: honours `Expose.target`;
/// `expect`: honours `Stop.expect` and `Unexpose.expect`.
pub const DAEMON_FEATURES: &[&str] = &["target", "expect"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStatus {
    pub port: u16,
    pub host: Option<String>,
    pub connected: bool,
}

pub fn host_for(template: &str, port: u16) -> String {
    template.replace("{port}", &port.to_string())
}

/// Where a person signs in to a password-protected preview, from its host
/// `{port}-{id}.<zone>`: `https://<zone>/__login?to={port}-{id}&next=%2F`
/// (the server's login form lives only on the zone host).
pub fn login_url(host: &str) -> Option<String> {
    let (label, zone) = host.split_once('.')?;
    let ok = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    (ok(label) && ok(zone)).then(|| format!("https://{zone}/__login?to={label}&next=%2F"))
}

impl Status {
    pub fn stopped() -> Self {
        Self {
            state: ConnState::Stopped,
            tunnel_id: None,
            host_template: None,
            ports: Vec::new(),
            last_error: None,
            ice_file: None,
            target: None,
            features: Vec::new(),
        }
    }

    /// Status of a tunnel whose daemon is gone (revoked or replaced).
    pub fn from_persisted(p: &Persisted, state: ConnState) -> Self {
        Self {
            state,
            tunnel_id: p.tunnel_id.clone(),
            host_template: p.host_template.clone(),
            ports: p
                .ports
                .iter()
                .map(|&port| PortStatus {
                    port,
                    host: p.host_template.as_deref().map(|t| host_for(t, port)),
                    connected: false,
                })
                .collect(),
            last_error: None,
            ice_file: None,
            target: p.target,
            features: Vec::new(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self.state {
            ConnState::Revoked => EXIT_REVOKED,
            ConnState::Replaced => EXIT_REPLACED,
            _ => 0,
        }
    }

    /// One line for a revoked or replaced tunnel (stderr, beside JSON output).
    pub fn terminal_summary(&self) -> String {
        let id = self.tunnel_id.as_deref().map(crate::paths::terminal_text).unwrap_or_else(|| "?".into());
        match self.state {
            ConnState::Revoked => format!("tunnel {id} is gone (deleted or expired, or its token was rejected)"),
            ConnState::Replaced => format!("tunnel {id} was taken over by another client with the same token"),
            other => format!("tunnel {id} is {}", other.as_str()),
        }
    }

    pub fn print(&self, json: bool) {
        self.print_access(json, None, None);
    }

    /// `--json` output: the daemon's status plus, when the CLI could read the
    /// tunnel from the server, `mode` (`link` | `password` | `public`),
    /// `username` (password mode; never the password) and each port's
    /// `login_url` (password mode).
    pub fn to_json(&self, access: Option<&AccessInfo>, name: Option<&str>) -> serde_json::Result<serde_json::Value> {
        let mut v = serde_json::to_value(self)?;
        if let Some(name) = name {
            v["name"] = name.into();
        }
        if let Some(access) = access {
            v["mode"] = access.mode.clone().into();
            if access.mode == "password" {
                v["username"] = access.username.clone().into();
                for (p, out) in self.ports.iter().zip(v["ports"].as_array_mut().into_iter().flatten()) {
                    if let Some(url) = p.host.as_deref().and_then(login_url) {
                        out["login_url"] = url.into();
                    }
                }
            }
        }
        Ok(v)
    }

    /// [`Status::print`] with the tunnel's access settings and display name, if known.
    pub fn print_access(&self, json: bool, access: Option<&AccessInfo>, name: Option<&str>) {
        if json {
            match self.to_json(access, name).and_then(|v| serde_json::to_string_pretty(&v)) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("tunnel: encoding status: {e}"),
            }
            return;
        }
        println!("state: {}", self.state.as_str());
        if let Some(id) = &self.tunnel_id {
            println!("tunnel: {}", crate::paths::terminal_text(id));
        }
        if let Some(name) = name {
            println!("name: {}", crate::paths::terminal_text(name));
        }
        match access {
            Some(a) if a.mode == "password" => println!(
                "access: password (username {})",
                crate::paths::terminal_text(a.username.as_deref().unwrap_or("?"))
            ),
            Some(a) => println!("access: {}", crate::paths::terminal_text(&a.mode)),
            None => {}
        }
        if let Some(target) = &self.target {
            println!("target: {target}");
        }
        if self.ports.is_empty() {
            println!("ports: none");
        } else {
            println!("ports:");
            for p in &self.ports {
                let url = p.host.as_deref().map_or_else(
                    || "(host pending)".to_string(),
                    |h| format!("https://{}", crate::paths::terminal_text(h)),
                );
                let conn = if p.connected { "connected" } else { "not connected" };
                println!("  {} -> {url} ({conn})", p.port);
                if let Some(login) = access.filter(|a| a.mode == "password").and(p.host.as_deref()).and_then(login_url)
                {
                    println!("       sign in: {}", crate::paths::terminal_text(&login));
                }
            }
        }
        if let Some(e) = &self.last_error {
            println!("last error: {}", crate::paths::terminal_text(e));
        }
        if let Some(f) = &self.ice_file {
            println!("ice file: {f}");
        }
        match self.state {
            ConnState::Revoked => {
                eprintln!("the tunnel was deleted, expired, or its token rejected; create a new tunnel")
            }
            ConnState::Replaced => eprintln!("another client connected with this tunnel token; this daemon stopped"),
            _ => {}
        }
    }
}

pub enum Reach {
    Running(UnixStream),
    /// The daemon is gone for a terminal reason and must not be restarted.
    Terminal(Persisted, ConnState),
    /// No daemon, no persisted tunnel, no token.
    Stopped,
}

/// Connect to the daemon, starting it if needed. `takeover` lets an explicit
/// `expose` restart a daemon that was replaced by another client.
/// `token`/`server` are what the request will carry (`expose` takes them from
/// the environment, `share` from its login); a token there counts as one to start with.
pub async fn ensure_daemon(
    paths: &Paths,
    takeover: bool,
    token: Option<&str>,
    server: Option<&str>,
    target: Option<&str>,
) -> anyhow::Result<Reach> {
    let env_token = daemon_token(token, env_token())?;
    if let Ok(stream) = UnixStream::connect(&paths.socket).await {
        return Ok(Reach::Running(stream));
    }
    let state = Persisted::load(&paths.state_file);
    let new_token = |p: &Persisted| env_token.as_deref().is_some_and(|t| t != p.token);
    if let Some(p) = &state {
        if p.revoked && !new_token(p) {
            return Ok(Reach::Terminal(p.clone(), ConnState::Revoked));
        }
        if p.replaced && !takeover && !new_token(p) {
            return Ok(Reach::Terminal(p.clone(), ConnState::Replaced));
        }
    }
    let has_token = env_token.is_some() || state.as_ref().is_some_and(|p| !p.token.is_empty());
    if !has_token {
        return Ok(Reach::Stopped);
    }
    // Fail here rather than in the detached daemon, where the error would only reach the log.
    let persisted_server = state.as_ref().filter(|p| !new_token(p)).map(|p| p.server.as_str());
    let server = server.map(str::to_string).or_else(|| env_nonempty(ENV_SERVER));
    resolve_server(server.as_deref(), persisted_server)?;

    // The daemon itself removes a stale socket, under its lock file, so a
    // concurrently starting daemon's fresh socket is never deleted here.
    let mut child = spawn_daemon(paths, env_token.as_deref(), server.as_deref(), target)?;
    let deadline = Instant::now() + SPAWN_WAIT;
    loop {
        if let Ok(stream) = UnixStream::connect(&paths.socket).await {
            return Ok(Reach::Running(stream));
        }
        // Exit 0 means another daemon won the lock; keep waiting for its socket.
        if let Some(status) = child.try_wait().context("waiting for daemon")?
            && !status.success()
        {
            if let Some(p) = Persisted::load(&paths.state_file).filter(|p| p.revoked) {
                return Ok(Reach::Terminal(p, ConnState::Revoked));
            }
            bail!("daemon exited ({status}); see {}", paths.log_file.display());
        }
        if Instant::now() >= deadline {
            bail!("daemon did not start within {}s; see {}", SPAWN_WAIT.as_secs(), paths.log_file.display());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn daemon_token(token: Option<&str>, inherited: anyhow::Result<Option<String>>) -> anyhow::Result<Option<String>> {
    if let Some(token) = token {
        validate_tunnel_token(token)?;
        return Ok(Some(token.to_string()));
    }
    Ok(inherited.unwrap_or_else(|_| {
        eprintln!("tunnel: warning: ignoring invalid {ENV_TOKEN}; using saved tunnel token if available");
        None
    }))
}

fn set_daemon_token(cmd: &mut std::process::Command, token: Option<&str>) {
    // Never leave an unvalidated inherited value for the daemon to read.
    cmd.env_remove(ENV_TOKEN);
    if let Some(token) = token {
        cmd.env(ENV_TOKEN, token);
    }
}

fn spawn_daemon(
    paths: &Paths,
    token: Option<&str>,
    server: Option<&str>,
    target: Option<&str>,
) -> anyhow::Result<Child> {
    let exe = std::env::current_exe().context("locating the tunnel executable")?;
    let log = open_log(paths)?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon");
    // An explicit state dir (flag or environment) must reach the daemon too.
    if crate::paths::explicit_state_dir()?.is_some() {
        cmd.arg("--state-dir").arg(&paths.dir);
    }
    if let Some(target) = target {
        cmd.env(ENV_TARGET, target);
    }
    cmd.current_dir("/").stdin(Stdio::null()).stdout(log.try_clone().context("duplicating log handle")?).stderr(log);
    // TUNNEL_TOKEN / _SERVER reach the daemon through its environment,
    // never argv (argv is visible in `ps`): only a validated token is set here.
    // Only a relative ICE file path needs fixing up because the daemon runs from `/`.
    set_daemon_token(&mut cmd, token);
    if let Some(s) = server {
        cmd.env(ENV_SERVER, s);
    }
    if let Some(file) = env_nonempty(ENV_ICE_FILE)
        && let Ok(abs) = std::path::absolute(&file)
    {
        cmd.env(ENV_ICE_FILE, abs);
    }
    // SAFETY: setsid is async-signal-safe and touches no Rust state.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().context("starting the Tunnel client daemon")
}

fn open_log(paths: &Paths) -> anyhow::Result<File> {
    if fs::metadata(&paths.log_file).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
        let _ = fs::remove_file(&paths.log_file);
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&paths.log_file)
        .with_context(|| format!("opening {}", paths.log_file.display()))
}

/// Send one request. `Ok(None)` means the daemon closed the connection
/// without answering (it exited, e.g. on revocation).
pub async fn call(mut stream: UnixStream, req: &Request, timeout: Duration) -> anyhow::Result<Option<Response>> {
    call_on(&mut stream, req, timeout).await
}

/// [`call`] on a connection that stays open for further requests.
pub async fn call_on(stream: &mut UnixStream, req: &Request, timeout: Duration) -> anyhow::Result<Option<Response>> {
    let (rd, mut wr) = stream.split();
    let mut rd = BufReader::new(rd);
    match write_json_line(&mut wr, req).await {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(None),
        Err(e) => return Err(e).context("sending request to daemon"),
    }
    let mut buf = String::new();
    match tokio::time::timeout(timeout, read_json_line::<_, Response>(&mut rd, &mut buf)).await {
        Err(_) => bail!("daemon did not answer within {}s", timeout.as_secs()),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => Ok(None),
        Ok(r) => r.context("reading daemon response"),
    }
}

/// Covers the daemon's per-port server round trips plus its connect wait.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) enum Answer {
    Response(Response),
    /// Already reported; exit with this code.
    Exit(i32),
    Stopped,
}

/// How `ask` reports a tunnel that is gone (revoked or replaced).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Report {
    /// The status as text on stdout.
    Text,
    /// The status as JSON on stdout (`status --json`).
    Json,
    /// One line on stderr, so stdout keeps its own JSON (`share --json`).
    Stderr,
}

pub(crate) async fn ask(req: Request, takeover: bool, report: Report) -> anyhow::Result<Answer> {
    let paths = Paths::resolve()?;
    let (token, server, target) = match &req {
        Request::Expose { token, server, target, .. } => (token.as_deref(), server.as_deref(), target.as_deref()),
        _ => (None, None, None),
    };
    let reach = ensure_daemon(&paths, takeover, token, server, target).await?;
    let reach = match (reach, target) {
        (Reach::Running(mut stream), Some(_)) => {
            require_target_support(&mut stream).await?;
            Reach::Running(stream)
        }
        (reach, _) => reach,
    };
    match reach {
        Reach::Running(stream) => match call(stream, &req, REQUEST_TIMEOUT).await? {
            Some(Response::Error { message }) => bail!("{message}"),
            Some(resp) => Ok(Answer::Response(resp)),
            None => daemon_gone(&paths, report).map(Answer::Exit),
        },
        Reach::Terminal(p, state) => Ok(Answer::Exit(report_terminal(&p, state, report))),
        Reach::Stopped => Ok(Answer::Stopped),
    }
}

/// A daemon started by an older binary would ignore the target and expose
/// loopback; ask first, before anything is exposed, on the same connection
/// the Expose then uses (so both reach the same daemon).
async fn require_target_support(stream: &mut UnixStream) -> anyhow::Result<()> {
    if !daemon_supports(stream, "target").await? {
        bail!("the running daemon does not support --target / {ENV_TARGET}; run `tunnel stop` and try again");
    }
    Ok(())
}

/// Whether the daemon on `stream` lists `feature` (asked on that connection).
pub(crate) async fn daemon_supports(stream: &mut UnixStream, feature: &str) -> anyhow::Result<bool> {
    Ok(match call_on(stream, &Request::Status, REQUEST_TIMEOUT).await? {
        Some(Response::Status { status }) => status.features.iter().any(|f| f == feature),
        _ => false,
    })
}

fn report_terminal(p: &Persisted, state: ConnState, report: Report) -> i32 {
    let status = Status::from_persisted(p, state);
    match report {
        Report::Text => status.print(false),
        Report::Json => status.print(true),
        Report::Stderr => eprintln!("tunnel: {}", status.terminal_summary()),
    }
    status.exit_code()
}

/// The daemon hung up mid-request: it exited, usually on revocation.
fn daemon_gone(paths: &Paths, report: Report) -> anyhow::Result<i32> {
    match Persisted::load(&paths.state_file) {
        Some(p) if p.revoked => Ok(report_terminal(&p, ConnState::Revoked, report)),
        Some(p) if p.replaced => Ok(report_terminal(&p, ConnState::Replaced, report)),
        _ => bail!("daemon exited unexpectedly; see {}", paths.log_file.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[test]
    fn login_urls_come_from_the_preview_host() {
        assert_eq!(
            login_url("3000-ab12cd3efg.previews.example.com").as_deref(),
            Some("https://previews.example.com/__login?to=3000-ab12cd3efg&next=%2F")
        );
        for host in ["3000-?", "", ".zone", "3000-x.", "3000-x.zone/evil", "a b.zone"] {
            assert_eq!(login_url(host), None, "{host}");
        }
    }

    #[test]
    fn status_json_names_mode_and_username_but_never_a_password() {
        let status = Status {
            state: ConnState::Connected,
            tunnel_id: Some("ab12cd3efg".into()),
            host_template: Some("{port}-ab12cd3efg.p.example".into()),
            ports: vec![
                PortStatus { port: 3000, host: Some("3000-ab12cd3efg.p.example".into()), connected: true },
                PortStatus { port: 5173, host: None, connected: false },
            ],
            last_error: None,
            ice_file: None,
            target: None,
            features: vec![],
        };
        let plain = status.to_json(None, None).unwrap();
        assert!(plain.get("mode").is_none() && plain.get("username").is_none());
        assert_eq!(plain, serde_json::to_value(&status).unwrap());

        let password = AccessInfo { mode: "password".into(), username: Some("preview".into()) };
        let v = status.to_json(Some(&password), None).unwrap();
        assert_eq!(v["mode"], "password");
        assert_eq!(v["username"], "preview");
        assert_eq!(v["ports"][0]["login_url"], "https://p.example/__login?to=3000-ab12cd3efg&next=%2F");
        assert!(v["ports"][1].get("login_url").is_none());
        assert!(!v.to_string().contains("password\":\"") && v.get("password").is_none());

        for mode in ["link", "public"] {
            let v = status.to_json(Some(&AccessInfo { mode: mode.into(), username: Some("x".into()) }), None).unwrap();
            assert_eq!(v["mode"], mode);
            assert!(v.get("username").is_none(), "{mode}");
            assert!(v["ports"][0].get("login_url").is_none(), "{mode}");
        }
    }

    #[test]
    fn invalid_env_token_is_ignored_without_an_explicit_token() {
        let inherited = Err(anyhow::anyhow!("invalid environment token"));
        assert!(daemon_token(None, inherited).unwrap().is_none());
    }

    #[test]
    fn valid_or_unset_env_token_keeps_existing_behavior() {
        let token = format!("{}test", tunnel_protocol::TUNNEL_TOKEN_PREFIX);
        assert!(daemon_token(None, Ok(Some(token.clone()))).unwrap().as_deref() == Some(token.as_str()));
        assert!(daemon_token(None, Ok(None)).unwrap().is_none());
    }

    #[test]
    fn explicit_token_is_validated_even_with_a_valid_env_token() {
        let valid = format!("{}test", tunnel_protocol::TUNNEL_TOKEN_PREFIX);
        for token in ["foreign-credential", "", " "] {
            let message = daemon_token(Some(token), Ok(Some(valid.clone()))).unwrap_err().to_string();
            assert!(message.contains("not a Tunnel token"));
            if !token.trim().is_empty() {
                assert!(!message.contains(token));
            }
        }
    }

    #[test]
    fn explicit_token_overrides_invalid_env_token() {
        let token = format!("{}test", tunnel_protocol::TUNNEL_TOKEN_PREFIX);
        let inherited = Err(anyhow::anyhow!("invalid environment token"));
        assert!(daemon_token(Some(&token), inherited).unwrap().as_deref() == Some(token.as_str()));
    }

    #[test]
    fn daemon_environment_removes_inherited_token_without_a_valid_replacement() {
        let mut cmd = std::process::Command::new("tunnel");
        cmd.env(ENV_TOKEN, "foreign-credential");
        set_daemon_token(&mut cmd, None);
        assert!(cmd.get_envs().any(|(name, value)| name == ENV_TOKEN && value.is_none()));
    }

    #[test]
    fn daemon_environment_sets_validated_token() {
        let token = format!("{}test", tunnel_protocol::TUNNEL_TOKEN_PREFIX);
        let mut cmd = std::process::Command::new("tunnel");
        cmd.env(ENV_TOKEN, "foreign-credential");
        set_daemon_token(&mut cmd, Some(&token));
        assert!(cmd.get_envs().any(|(name, value)| name == ENV_TOKEN && value == Some(token.as_ref())));
    }

    /// A daemon that answers every request with a status listing `features`.
    async fn fake_daemon(features: Vec<String>) -> Paths {
        let dir = std::env::temp_dir().join(format!("tunnel-cmd-test-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let paths = Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        };
        let listener = UnixListener::bind(&paths.socket).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let features = features.clone();
                tokio::spawn(async move {
                    let (rd, mut wr) = stream.into_split();
                    let mut rd = BufReader::new(rd);
                    let mut buf = String::new();
                    while let Ok(Some(_)) = read_json_line::<_, Request>(&mut rd, &mut buf).await {
                        let status = Status { features: features.clone(), ..Status::stopped() };
                        let _ = write_json_line(&mut wr, &Response::Status { status }).await;
                    }
                });
            }
        });
        paths
    }

    #[tokio::test]
    async fn targeted_expose_refuses_a_daemon_without_target_support() {
        let paths = fake_daemon(Vec::new()).await;
        let mut stream = UnixStream::connect(&paths.socket).await.unwrap();
        let err = require_target_support(&mut stream).await.unwrap_err().to_string();
        assert!(err.contains("does not support --target"), "{err}");
        std::fs::remove_dir_all(&paths.dir).unwrap();

        let paths = fake_daemon(vec!["target".into()]).await;
        let mut stream = UnixStream::connect(&paths.socket).await.unwrap();
        require_target_support(&mut stream).await.unwrap();
        // The request then goes to the same daemon on the same connection,
        // even if the socket path is replaced in between.
        std::fs::remove_file(&paths.socket).unwrap();
        let answer = call(stream, &Request::Status, REQUEST_TIMEOUT).await.unwrap();
        assert!(matches!(answer, Some(Response::Status { .. })));
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }
}
