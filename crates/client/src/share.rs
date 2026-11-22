//! `login`, `logout`, `share`, and `link`: create and expose tunnels from a
//! machine that logged in with `tunnel login`, without an admin token.
//!
//! `share` reuses the tunnel it created earlier while the daemon still runs
//! it, so `share 3000` then `share 5173` serve both ports from one tunnel (one
//! link covers both). `stop` deletes a tunnel that `share` created.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::commands::{Answer, Report, ask};
use crate::ipc::{Expect, Request, Response, Status, host_for};
use crate::login::{Api, Login, enroll};
use crate::paths::{Paths, env_nonempty, terminal_text};
use crate::state::{Persisted, write_atomic};

pub const ENV_SHARE_PASSWORD: &str = "TUNNEL_SHARE_PASSWORD";
/// How long a link printed by `share` (and `link` by default) works.
pub const LINK_TTL_S: u64 = 10 * 60;
const CONNECT_WAIT: Duration = Duration::from_secs(15);
/// The server's shortest tunnel lifetime, so the shortest `--for`.
const MIN_FOR_S: u64 = 60;

/// The tunnel `share` created, so later `share`/`link`/`stop` find it.
#[derive(Clone, Serialize, Deserialize)]
struct Shared {
    tunnel_id: String,
    api: String,
    /// Identify the daemon's target before Welcome supplies its tunnel id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

fn shared_path(paths: &Paths) -> PathBuf {
    paths.dir.join("share.json")
}

fn load_shared(paths: &Paths) -> Option<Shared> {
    std::fs::read(shared_path(paths)).ok().and_then(|b| serde_json::from_slice(&b).ok())
}

/// Hold while reading-then-changing `share.json`, so a check ("does it still
/// name this tunnel?") and the change cannot straddle another command's write.
fn share_lock(paths: &Paths) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let path = paths.dir.join("share.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: the fd is valid for the lifetime of `file`; the lock ends with it.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("locking share.lock");
    }
    Ok(file)
}

/// Forget `share.json` if it still names `tunnel_id` (a newer share keeps its record).
fn forget_shared_if(paths: &Paths, tunnel_id: &str) {
    let Ok(_lock) = share_lock(paths) else { return };
    if load_shared(paths).is_some_and(|s| s.tunnel_id == tunnel_id) {
        let _ = std::fs::remove_file(shared_path(paths));
    }
}

pub async fn login(arg: Option<&str>, name: Option<&str>, open_browser: bool) -> anyhow::Result<i32> {
    let arg = match arg.filter(|a| *a != "-") {
        Some(a) => a.to_string(),
        None => read_secret_line("Server (https://…) or login code (from `tunnel-server client add`): ")?,
    };
    let login = match crate::login::parse_login_target(&arg)? {
        crate::login::LoginTarget::Code { code, host } => enroll(&code, &host).await?,
        crate::login::LoginTarget::Browser { origin } => {
            let name = name.map(str::to_string).unwrap_or_else(crate::login::default_machine_name);
            crate::login::device_login(&origin, &name, open_browser).await?
        }
    };
    login.save()?;
    println!("Logged in to {} as {}.", terminal_text(&login.api), terminal_text(&login.name));
    println!("Share a local port with: tunnel share <PORT>");
    Ok(0)
}

pub fn logout() -> anyhow::Result<i32> {
    let p = crate::login::path()?;
    match std::fs::remove_file(&p) {
        Ok(()) => println!(
            "Logged out (removed {}). Ask the server admin to `client delete` this machine to revoke its token.",
            p.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => println!("Not logged in."),
        Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
    }
    Ok(0)
}

/// Requested access for `share`; `None` fields mean "not given".
pub struct ShareAccess {
    pub public: bool,
    pub password: bool,
    pub link: bool,
    pub username: Option<String>,
}

impl ShareAccess {
    fn explicit(&self) -> bool {
        self.public || self.password || self.link
    }

    fn to_json(&self) -> anyhow::Result<Value> {
        Ok(if self.public {
            json!({ "mode": "public" })
        } else if self.password {
            let username = self.username.clone().unwrap_or_else(|| "preview".to_string());
            json!({ "mode": "password", "username": username, "password": read_password()? })
        } else {
            json!({ "mode": "link" })
        })
    }
}

/// `$TUNNEL_SHARE_PASSWORD`, else a prompt on the terminal (not echoed).
fn read_password() -> anyhow::Result<String> {
    if let Some(p) = env_nonempty(ENV_SHARE_PASSWORD) {
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        bail!("set {ENV_SHARE_PASSWORD} (no terminal to prompt for the password)");
    }
    read_secret_line("Password for visitors (8+ characters): ")
}

/// One line from stdin: prompted without echo on a terminal, read as-is from a pipe.
fn read_secret_line(prompt: &str) -> anyhow::Result<String> {
    let tty = std::io::stdin().is_terminal();
    let mut echo_off = false;
    if tty {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
        echo_off = std::process::Command::new("stty").arg("-echo").status().is_ok_and(|s| s.success());
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if echo_off {
        let _ = std::process::Command::new("stty").arg("echo").status();
        eprintln!();
    }
    read?;
    let line = line.trim().to_string();
    if line.is_empty() {
        bail!("nothing entered");
    }
    Ok(line)
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "machine".to_string())
}

/// What `share` printed, also its `--json` output.
#[derive(Serialize)]
struct ShareOutput {
    tunnel: String,
    mode: String,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// Present (true) when the account reached its monthly traffic cap:
    /// visitors see "Traffic limit reached".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    traffic_limited: bool,
    links: Vec<LinkOutput>,
}

/// One port's URL: an access link in link mode, else the preview URL.
#[derive(Serialize)]
struct LinkOutput {
    port: u16,
    url: String,
    connected: bool,
    /// Access link id (link mode), for `tunnel unlink`.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    single_use: Option<bool>,
}

/// Output options shared by `share` and `link`.
pub struct Output {
    pub json: bool,
}

/// `share --for`: stay in the foreground, then delete the tunnel.
pub struct Foreground {
    pub duration_s: u64,
}

/// SIGINT/SIGTERM/SIGHUP, caught from the start of `share --for` so a signal
/// during setup also ends in an unshare instead of leaving the tunnel behind.
struct Signals {
    int: tokio::signal::unix::Signal,
    term: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
}

impl Signals {
    fn install() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            int: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
            hup: signal(SignalKind::hangup())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.int.recv() => {}
            _ = self.term.recv() => {}
            _ = self.hup.recv() => {}
        }
    }
}

pub async fn share(
    ports: Vec<u16>,
    access: ShareAccess,
    ttl_s: u64,
    label: Option<String>,
    target: Option<String>,
    out: Output,
    foreground: Option<Foreground>,
) -> anyhow::Result<i32> {
    if foreground.as_ref().is_some_and(|f| f.duration_s < MIN_FOR_S) {
        bail!("--for must be at least 1m (the server's shortest tunnel lifetime)");
    }
    let target = crate::commands::resolve_target(target)?;
    let login = Login::require()?;
    let api = Api::new(&login)?;
    let paths = Paths::resolve()?;
    let report = if out.json { Report::Stderr } else { Report::Text };

    // Reuse the tunnel an earlier `share` made, while the daemon still serves it.
    let running = Persisted::load(&paths.state_file);
    let mut reuse = None;
    if let Some(s) = load_shared(&paths).filter(|s| s.api == login.api)
        && let Some(token) = persisted_share_token(&s, running)
        && let Some(info) = api.tunnel(&s.tunnel_id).await?.filter(|i| !i.expired)
    {
        reuse = Some((s.tunnel_id, token, info.access.mode, info.expires_at, info.traffic_limited));
    }

    let Some(fg) = foreground else {
        let (tunnel_id, token, mode, expires_at, limited) = match reuse {
            Some((id, token, current_mode, expires_at, limited)) => {
                let mode = if access.explicit() {
                    let wanted = access.to_json()?;
                    api.set_access(&id, &wanted).await?;
                    wanted["mode"].as_str().unwrap_or("link").to_string()
                } else {
                    current_mode
                };
                (id, token, mode, expires_at, limited)
            }
            None => {
                let wanted = access.to_json()?;
                let (shared, expires_at, limited) = create_shared(&api, &login, &paths, label, ttl_s, &wanted).await?;
                let mode = wanted["mode"].as_str().unwrap_or("link").to_string();
                (shared.tunnel_id, shared.token.unwrap_or_default(), mode, expires_at, limited)
            }
        };
        let plan = Plan { ports, token, server: login.server.clone(), target, tunnel_id, mode, expires_at, limited };
        return match expose_and_show(&api, plan, &out, None, report).await? {
            Ok(_) => Ok(0),
            Err(code) => Ok(code),
        };
    };

    // `--for`: a new tunnel tied to this process. Its lifetime is the
    // duration, so it also ends if the process is killed.
    if let Some((id, ..)) = &reuse {
        bail!(
            "already sharing tunnel {} from this machine; run `tunnel unshare` first (--for makes a new tunnel)",
            terminal_text(id)
        );
    }
    // Prompt (for --password) before catching signals, so Ctrl-C still works there.
    let wanted = access.to_json()?;
    let mut signals = Signals::install()?;
    let (shared, expires_at, limited) = create_shared(&api, &login, &paths, label, fg.duration_s, &wanted).await?;
    let created = Instant::now();
    let plan = Plan {
        ports,
        token: shared.token.clone().unwrap_or_default(),
        server: login.server.clone(),
        target,
        tunnel_id: shared.tunnel_id.clone(),
        mode: wanted["mode"].as_str().unwrap_or("link").to_string(),
        expires_at,
        limited,
    };
    let end = End { created, duration_s: fg.duration_s, expires_at };
    let setup = tokio::select! {
        r = expose_and_show(&api, plan, &out, Some(&fg), report) => Setup::Done(r),
        _ = signals.recv() => Setup::Interrupted,
        _ = tokio::time::sleep(end.remaining(crate::ice::unix_now())) => Setup::Due,
    };
    let ended = match setup {
        Setup::Done(Ok(Ok(_))) => share_for(&paths, &shared, end, signals).await,
        // Expired at its end while still setting up (a very slow start): the normal end.
        Setup::Done(Ok(Err(tunnel_protocol::EXIT_REVOKED))) if end.is_due(crate::ice::unix_now()) => None,
        Setup::Due => None,
        // Interrupted, failed, or the tunnel is gone already: do not leave it behind.
        Setup::Done(Ok(Err(code))) => Some(code),
        Setup::Done(Err(e)) => {
            unshare_tunnel(&paths, &shared, Ok(Some(login.clone())), true).await;
            return Err(e);
        }
        Setup::Interrupted => Some(130),
    };
    // With the login it was created with, even if this machine logged in elsewhere meanwhile.
    let deleted = unshare_tunnel(&paths, &shared, Ok(Some(login.clone())), out.json).await;
    Ok(ended.unwrap_or(if deleted { 0 } else { 1 }))
}

/// How the setup of a `--for` share ended.
enum Setup {
    Done(anyhow::Result<Result<ShareOutput, i32>>),
    Interrupted,
    /// Its end came before the setup finished.
    Due,
}

/// What `share` exposes and prints.
struct Plan {
    ports: Vec<u16>,
    token: String,
    server: String,
    target: Option<String>,
    tunnel_id: String,
    mode: String,
    expires_at: i64,
    /// The account reached its monthly traffic cap.
    limited: bool,
}

/// Create a tunnel and record it in `share.json` (deleting it again if that fails).
async fn create_shared(
    api: &Api<'_>,
    login: &Login,
    paths: &Paths,
    label: Option<String>,
    ttl_s: u64,
    access: &Value,
) -> anyhow::Result<(Shared, i64, bool)> {
    let label = label.unwrap_or_else(|| format!("share-{}", hostname()));
    let created = api.create_tunnel(&label, ttl_s, access).await?;
    let shared = Shared { tunnel_id: created.id.clone(), api: login.api.clone(), token: Some(created.tunnel_token) };
    let written = share_lock(paths).and_then(|_lock| {
        write_atomic(&shared_path(paths), &serde_json::to_vec(&shared)?, 0o600).map_err(anyhow::Error::from)
    });
    if let Err(e) = written {
        if let Err(d) = api.delete_tunnel(&created.id).await {
            eprintln!("tunnel: warning: could not delete tunnel {}: {d:#}", terminal_text(&created.id));
        }
        return Err(e);
    }
    Ok((shared, created.expires_at, created.traffic_limited))
}

/// Expose the ports, mint links, print. `Ok(Err(code))`: the tunnel is gone (already reported).
async fn expose_and_show(
    api: &Api<'_>,
    plan: Plan,
    out: &Output,
    foreground: Option<&Foreground>,
    report: Report,
) -> anyhow::Result<Result<ShareOutput, i32>> {
    let Plan { ports, token, server, target, tunnel_id, mode, expires_at, limited } = plan;
    if limited {
        eprintln!(
            "tunnel: warning: this account reached its monthly traffic limit; visitors see \"Traffic limit reached\" \
             until an admin raises the limit or the month ends"
        );
    }
    let req = Request::Expose { ports: ports.clone(), token: Some(token), server: Some(server), target };
    let status = match ask(req, true, report).await? {
        Answer::Response(Response::Status { status }) => status,
        Answer::Response(_) => bail!("unexpected daemon response"),
        Answer::Exit(code) => return Ok(Err(code)),
        Answer::Stopped => bail!("the daemon did not start"),
    };
    let status = match wait_connected(status, &ports, report).await {
        Ok(status) => status,
        Err(code) => return Ok(Err(code)),
    };
    require_shared_tunnel(&status, &tunnel_id)?;

    let username = match mode.as_str() {
        "password" => api.tunnel(&tunnel_id).await?.and_then(|i| i.access.username),
        _ => None,
    };
    let mut links = Vec::with_capacity(ports.len());
    for &port in &ports {
        let connected = status.ports.iter().any(|p| p.port == port && p.connected);
        links.push(if mode == "link" {
            let ttl_s = link_ttl(LINK_TTL_S, expires_at, crate::ice::unix_now())?;
            let link = api.access_link(&tunnel_id, port, ttl_s, true, None).await?;
            LinkOutput {
                port,
                url: link.url,
                connected,
                id: Some(link.id),
                expires_at: Some(link.expires_at),
                single_use: Some(true),
            }
        } else {
            let url = format!("https://{}/", port_host(&status, port));
            LinkOutput { port, url, connected, id: None, expires_at: None, single_use: None }
        });
    }
    let shown = ShareOutput { tunnel: tunnel_id, mode, expires_at, username, traffic_limited: limited, links };
    print_share(&shown, out, foreground)?;
    Ok(Ok(shown))
}

fn print_share(shared: &ShareOutput, out: &Output, foreground: Option<&Foreground>) -> anyhow::Result<()> {
    if out.json {
        println!("{}", serde_json::to_string(shared)?);
        std::io::stdout().flush()?;
        return Ok(());
    }
    const PENDING: &str = "  (not connected yet; check `tunnel status`)";
    for l in &shared.links {
        let note = if l.connected { "" } else { PENDING };
        let url = terminal_text(&l.url);
        match shared.mode.as_str() {
            "public" => println!("{}  {url}  (public){note}", l.port),
            "password" => println!(
                "{}  {url}  (username {}, password as set){note}",
                l.port,
                terminal_text(shared.username.as_deref().unwrap_or("?"))
            ),
            _ => {
                let ttl_s = l.expires_at.map_or(0, |e| (e - crate::ice::unix_now() as i64).max(0) as u64);
                println!("{}  {url}  (works once, within {} min){note}", l.port, link_minutes(ttl_s));
            }
        }
    }
    if shared.mode == "link" {
        println!("More links: tunnel link [--port PORT] [--reusable]");
    }
    match foreground {
        Some(f) => println!("Sharing for {}; Ctrl-C stops sharing sooner.", human_duration(f.duration_s)),
        None => println!("Stop sharing: tunnel unshare"),
    }
    std::io::stdout().flush()?;
    Ok(())
}

/// `30m`, `1h`, `1h30m`, `2d`.
fn human_duration(s: u64) -> String {
    let (d, h, m, sec) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60, s % 60);
    let mut out = String::new();
    for (n, unit) in [(d, "d"), (h, "h"), (m, "m"), (sec, "s")] {
        if n > 0 {
            out.push_str(&format!("{n}{unit}"));
        }
    }
    if out.is_empty() { "0s".to_string() } else { out }
}

/// When a `--for` share ends: `duration_s` after the create call returned,
/// and no later than the server's `expires_at` (by this machine's clock).
struct End {
    created: Instant,
    duration_s: u64,
    expires_at: i64,
}

impl End {
    /// Time left until the end, a little early so the normal end is ours.
    fn remaining(&self, now_unix: u64) -> Duration {
        let by_clock = Duration::from_secs((self.expires_at.max(0) as u64).saturating_sub(now_unix));
        let by_timer = Duration::from_secs(self.duration_s).saturating_sub(self.created.elapsed());
        by_clock.min(by_timer).saturating_sub(Duration::from_secs(2))
    }

    /// The server expiring the tunnel at (about) its end is the normal end.
    fn is_due(&self, now_unix: u64) -> bool {
        self.remaining(now_unix) <= Duration::from_secs(15)
    }
}

/// Wait for the end, a signal, or the daemon ending. `Some(code)`: ended early.
async fn share_for(paths: &Paths, shared: &Shared, end: End, mut signals: Signals) -> Option<i32> {
    let deadline = tokio::time::sleep(end.remaining(crate::ice::unix_now()));
    tokio::pin!(deadline);
    let mut poll = tokio::time::interval(Duration::from_secs(5));
    poll.tick().await;
    loop {
        tokio::select! {
            _ = &mut deadline => return None,
            _ = signals.recv() => return None,
            _ = poll.tick() => {
                let Some(code) = daemon_ended(paths, shared).await else { continue };
                if code == tunnel_protocol::EXIT_REVOKED && end.is_due(crate::ice::unix_now()) {
                    return None;
                }
                eprintln!("tunnel: the daemon stopped serving the tunnel; unsharing");
                return Some(code);
            }
        }
    }
}

/// `Some(exit code)` once the daemon no longer serves `shared`'s tunnel.
async fn daemon_ended(paths: &Paths, shared: &Shared) -> Option<i32> {
    let Ok(stream) = tokio::net::UnixStream::connect(&paths.socket).await else {
        return Some(match Persisted::load(&paths.state_file) {
            Some(p) if p.revoked => tunnel_protocol::EXIT_REVOKED,
            Some(p) if p.replaced => tunnel_protocol::EXIT_REPLACED,
            _ => 1,
        });
    };
    match crate::ipc::call(stream, &Request::Status, Duration::from_secs(10)).await {
        Ok(Some(Response::Status { status })) => {
            // Before Welcome the daemon has no id: its saved token tells.
            let ours = match status.tunnel_id.as_deref() {
                Some(id) => id == shared.tunnel_id,
                None => persisted_share_token(shared, Persisted::load(&paths.state_file)).is_some(),
            };
            match (ours, status.exit_code()) {
                (false, _) => Some(tunnel_protocol::EXIT_REPLACED),
                (true, 0) => None,
                (true, code) => Some(code),
            }
        }
        // A slow or odd answer is not a reason to end sharing early.
        _ => None,
    }
}

fn persisted_share_token(shared: &Shared, persisted: Option<Persisted>) -> Option<String> {
    persisted
        .filter(|p| match p.tunnel_id.as_deref() {
            Some(id) => id == shared.tunnel_id,
            None => shared.token.as_deref() == Some(p.token.as_str()),
        })
        .map(|p| p.token)
}

fn require_shared_tunnel(status: &Status, tunnel_id: &str) -> anyhow::Result<()> {
    // A new target has no id until Welcome; links can be printed while it connects.
    if status.tunnel_id.as_deref().is_some_and(|id| id != tunnel_id) {
        bail!("the daemon is not serving shared tunnel {}; run `tunnel share <PORT>` first", terminal_text(tunnel_id));
    }
    Ok(())
}

fn require_link_tunnel(status: &Status, shared: &Shared, paths: &Paths) -> anyhow::Result<()> {
    require_shared_tunnel(status, &shared.tunnel_id)?;
    // Before Welcome, the persisted target must still belong to this share.
    if status.tunnel_id.is_none() && persisted_share_token(shared, Persisted::load(&paths.state_file)).is_none() {
        bail!(
            "the daemon is not serving shared tunnel {}; run `tunnel share <PORT>` first",
            terminal_text(&shared.tunnel_id)
        );
    }
    Ok(())
}

/// Leave a little time for the API request to reach the server.
fn link_ttl(requested: u64, expires_at: i64, now: u64) -> anyhow::Result<u64> {
    let remaining = (expires_at.max(0) as u64).saturating_sub(now).saturating_sub(5);
    let ttl = requested.min(remaining);
    if ttl < 30 {
        bail!("access links need at least 30 seconds before the tunnel expires (plus a 5 second margin)");
    }
    Ok(ttl)
}

fn link_minutes(ttl_s: u64) -> String {
    if ttl_s.is_multiple_of(60) { (ttl_s / 60).to_string() } else { format!("{:.1}", ttl_s as f64 / 60.0) }
}

fn port_host(status: &Status, port: u16) -> String {
    status
        .ports
        .iter()
        .find(|p| p.port == port)
        .and_then(|p| p.host.clone())
        .or_else(|| status.host_template.as_deref().map(|t| host_for(t, port)))
        .unwrap_or_else(|| format!("{port}-?"))
}

/// Poll the daemon until `ports` are connected (or give up after a while).
/// `Err(code)`: the tunnel went away meanwhile (reported per `report`).
async fn wait_connected(mut status: Status, ports: &[u16], report: Report) -> Result<Status, i32> {
    let deadline = Instant::now() + CONNECT_WAIT;
    let all = |s: &Status| ports.iter().all(|port| s.ports.iter().any(|p| p.port == *port && p.connected));
    while !all(&status) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(300)).await;
        match ask(Request::Status, false, report).await {
            Ok(Answer::Response(Response::Status { status: s })) => status = s,
            Ok(Answer::Exit(code)) => return Err(code),
            _ => break,
        }
    }
    Ok(status)
}

pub async fn link(
    port: Option<u16>,
    reusable: bool,
    ttl_s: u64,
    label: Option<String>,
    out: Output,
) -> anyhow::Result<i32> {
    let login = Login::require()?;
    let paths = Paths::resolve()?;
    let shared = require_shared(&paths, &login)?;
    let report = if out.json { Report::Stderr } else { Report::Text };
    let status = match ask(Request::Status, false, report).await? {
        Answer::Response(Response::Status { status }) => status,
        Answer::Exit(code) => return Ok(code),
        _ => bail!("the tunnel daemon is not running; run `tunnel share <PORT>`"),
    };
    require_link_tunnel(&status, &shared, &paths)?;
    let port = match port.or_else(|| status.ports.first().map(|p| p.port)) {
        Some(p) => p,
        None => bail!("no ports are shared"),
    };
    let api = Api::new(&login)?;
    let info = api
        .tunnel(&shared.tunnel_id)
        .await?
        .context("the shared tunnel no longer exists; run `tunnel share <PORT>`")?;
    let ttl_s = link_ttl(ttl_s, info.expires_at, crate::ice::unix_now())?;
    let link = api.access_link(&shared.tunnel_id, port, ttl_s, !reusable, label.as_deref()).await?;
    let connected = status.ports.iter().any(|p| p.port == port && p.connected);
    if out.json {
        let shown = ShareOutput {
            tunnel: shared.tunnel_id,
            mode: info.access.mode,
            expires_at: info.expires_at,
            username: None,
            traffic_limited: info.traffic_limited,
            links: vec![LinkOutput {
                port,
                url: link.url,
                connected,
                id: Some(link.id),
                expires_at: Some(link.expires_at),
                single_use: Some(!reusable),
            }],
        };
        println!("{}", serde_json::to_string(&shown)?);
        return Ok(0);
    }
    let uses = if reusable { "any number of times" } else { "once" };
    let note = if connected { "" } else { "  (not connected yet; check `tunnel status`)" };
    println!("{}  (works {uses}, for {} min){note}", terminal_text(&link.url), link_minutes(ttl_s));
    Ok(0)
}

fn require_shared(paths: &Paths, login: &Login) -> anyhow::Result<Shared> {
    load_shared(paths)
        .filter(|s| s.api == login.api)
        .context("nothing shared from this machine; run `tunnel share <PORT>` first")
}

/// `tunnel links`: the shared tunnel's access links (their URLs are not stored).
pub async fn links(json: bool) -> anyhow::Result<i32> {
    let login = Login::require()?;
    let paths = Paths::resolve()?;
    let shared = require_shared(&paths, &login)?;
    let api = Api::new(&login)?;
    let links = api
        .access_links(&shared.tunnel_id)
        .await?
        .context("the shared tunnel no longer exists; run `tunnel share <PORT>`")?;
    if json {
        println!("{}", serde_json::to_string(&json!({ "tunnel": shared.tunnel_id, "links": links }))?);
        return Ok(0);
    }
    if links.is_empty() {
        println!("No access links for tunnel {}.", terminal_text(&shared.tunnel_id));
        return Ok(0);
    }
    let now = crate::ice::unix_now() as i64;
    for l in &links {
        let state = if l.used_at.is_some() {
            "used".to_string()
        } else if l.expires_at <= now {
            "expired".to_string()
        } else {
            format!("expires in {}", human_duration((l.expires_at - now) as u64))
        };
        let uses = if l.single_use { "single-use" } else { "reusable" };
        let label = l.label.as_deref().map(|s| format!("  {}", terminal_text(s))).unwrap_or_default();
        println!("{}  {uses}, {state}{label}", terminal_text(&l.id));
    }
    println!("Revoke one (and end the visits it allowed): tunnel unlink <ID>");
    Ok(0)
}

/// `tunnel unlink <ID>`: revoke one of the shared tunnel's access links.
pub async fn unlink(id: &str) -> anyhow::Result<i32> {
    let login = Login::require()?;
    let paths = Paths::resolve()?;
    let shared = require_shared(&paths, &login)?;
    let api = Api::new(&login)?;
    // Only links of the tunnel this machine shares, not other tunnels of the account.
    let links = api.access_links(&shared.tunnel_id).await?.unwrap_or_default();
    if !links.iter().any(|l| l.id == id) {
        bail!("no access link {} on the shared tunnel; see `tunnel links`", terminal_text(id));
    }
    api.delete_access_link(id).await?;
    println!("revoked {}", terminal_text(id));
    Ok(0)
}

/// `tunnel unshare [PORT…]`: stop sharing those ports; with none (or none
/// left), delete the shared tunnel and stop the daemon serving it.
pub async fn unshare(mut ports: Vec<u16>) -> anyhow::Result<i32> {
    ports.sort_unstable();
    ports.dedup();
    let paths = Paths::resolve()?;
    let Some(shared) = load_shared(&paths) else {
        println!("nothing shared");
        return Ok(0);
    };
    if !ports.is_empty() {
        // Talk to a running daemon only: unsharing never restarts one.
        let Ok(mut stream) = tokio::net::UnixStream::connect(&paths.socket).await else {
            bail!("the tunnel daemon is not running; `tunnel unshare` (no ports) deletes the shared tunnel");
        };
        require_expect_support(&mut stream).await?;
        let expect = Some(expect_for(&shared));
        let mut left = None;
        let mut failed = None;
        for port in ports {
            let req = Request::Unexpose { port, expect: expect.clone() };
            match crate::ipc::call_on(&mut stream, &req, Duration::from_secs(30)).await {
                Ok(Some(Response::Status { status })) => left = Some(status.ports.len()),
                Ok(Some(Response::Error { message })) if message == crate::daemon::NOT_SERVING => {
                    failed = Some(anyhow::anyhow!(
                        "the daemon is not serving shared tunnel {} any more",
                        terminal_text(&shared.tunnel_id)
                    ));
                    break;
                }
                Ok(Some(Response::Error { message })) => {
                    failed = Some(anyhow::anyhow!("{message}"));
                    break;
                }
                Ok(_) => {
                    failed = Some(anyhow::anyhow!("the tunnel daemon exited"));
                    break;
                }
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        // Down to no ports: the tunnel goes, even if a later port failed.
        if left != Some(0) {
            return match failed {
                Some(e) => Err(e),
                None => {
                    let n = left.unwrap_or_default();
                    println!("{n} port(s) still shared; `tunnel unshare` stops sharing all of them");
                    Ok(0)
                }
            };
        }
        let deleted = unshare_tunnel(&paths, &shared, Login::load(), false).await;
        return match failed {
            Some(e) => Err(e),
            None => Ok(if deleted { 0 } else { 1 }),
        };
    }
    let deleted = unshare_tunnel(&paths, &shared, Login::load(), false).await;
    Ok(if deleted { 0 } else { 1 })
}

fn expect_for(shared: &Shared) -> Expect {
    Expect { tunnel_id: shared.tunnel_id.clone(), token: shared.token.clone() }
}

async fn require_expect_support(stream: &mut tokio::net::UnixStream) -> anyhow::Result<()> {
    if !crate::commands::daemon_supports(stream, "expect").await? {
        bail!("the running daemon is too old for `unshare`; run `tunnel stop` instead");
    }
    Ok(())
}

/// Stop the daemon only if it still serves `shared`'s tunnel (checked by the
/// daemon itself), then delete the tunnel and forget `share.json` only if it
/// still names it. Stopping first: a daemon whose tunnel is deleted exits on
/// its own and would leave its state behind. Returns whether the tunnel is
/// deleted. `quiet`: progress on stderr, so stdout keeps `--json` output alone.
async fn unshare_tunnel(paths: &Paths, shared: &Shared, login: anyhow::Result<Option<Login>>, quiet: bool) -> bool {
    let say = |line: String| if quiet { eprintln!("{line}") } else { println!("{line}") };
    match tokio::net::UnixStream::connect(&paths.socket).await {
        Ok(mut stream) => {
            let stop = Request::Stop { expect: Some(expect_for(shared)) };
            let answer = match require_expect_support(&mut stream).await {
                Ok(()) => crate::ipc::call_on(&mut stream, &stop, Duration::from_secs(30)).await,
                Err(e) => Err(e),
            };
            match answer {
                Ok(Some(Response::Status { .. })) | Ok(None) => say("stopped".into()),
                // Serving another tunnel (e.g. from `expose`): leave it running.
                Ok(Some(Response::Error { message })) if message == crate::daemon::NOT_SERVING => {}
                Ok(Some(Response::Error { message })) => {
                    eprintln!("tunnel: warning: daemon: {}", terminal_text(&message))
                }
                Ok(Some(_)) => eprintln!("tunnel: warning: unexpected daemon response"),
                Err(e) => eprintln!("tunnel: warning: {}", terminal_text(&format!("{e:#}"))),
            }
        }
        // No daemon: keep it from restarting from state that is this
        // tunnel's. Under the daemon lock, so none starts from it meanwhile
        // (a daemon that is just exiting holds it for a moment longer).
        Err(_) => {
            let deadline = Instant::now() + Duration::from_secs(3);
            let lock = loop {
                match crate::daemon::lock_daemon(paths) {
                    Ok(None) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(100)).await,
                    other => break other,
                }
            };
            if let Ok(Some(_lock)) = lock
                && persisted_share_token(shared, Persisted::load(&paths.state_file)).is_some()
            {
                let _ = std::fs::remove_file(&paths.state_file);
            }
        }
    }
    let deleted = delete_shared_with_login(paths, shared.clone(), login).await;
    if deleted {
        say(format!("unshared {}", terminal_text(&shared.tunnel_id)));
    }
    deleted
}

/// For `stop`: delete the tunnel `share` created, if any. Keep failures for retry.
pub async fn delete_shared(paths: &Paths) -> bool {
    let Some(shared) = load_shared(paths) else {
        return true;
    };
    delete_shared_with_login(paths, shared, Login::load()).await
}

async fn delete_shared_with_login(paths: &Paths, shared: Shared, login: anyhow::Result<Option<Login>>) -> bool {
    let result = async {
        let login = login?.context("not logged in; log in to the original server to retry deletion")?;
        if login.api != shared.api {
            bail!("logged in to a different API; log in to the original server to retry deletion");
        }
        Api::new(&login)?.delete_tunnel(&shared.tunnel_id).await
    }
    .await;
    match result {
        Ok(()) => {
            forget_shared_if(paths, &shared.tunnel_id);
            true
        }
        Err(e) => {
            eprintln!(
                "tunnel: warning: could not delete shared tunnel {}: {}",
                terminal_text(&shared.tunnel_id),
                terminal_text(&format!("{e:#}"))
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_paths(name: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("tunnel-{name}-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        }
    }

    #[test]
    fn share_json_shape() {
        let link = LinkOutput {
            port: 3000,
            url: "https://x/".into(),
            connected: true,
            id: Some("lnk".into()),
            expires_at: Some(5),
            single_use: Some(true),
        };
        let shown = ShareOutput {
            tunnel: "t".into(),
            mode: "link".into(),
            expires_at: 9,
            username: None,
            traffic_limited: false,
            links: vec![link],
        };
        assert_eq!(
            serde_json::to_value(&shown).unwrap(),
            json!({"tunnel":"t","mode":"link","expires_at":9,"links":[
                {"port":3000,"url":"https://x/","connected":true,"id":"lnk","expires_at":5,"single_use":true}]})
        );
        let public = LinkOutput {
            port: 80,
            url: "https://80-t.example/".into(),
            connected: false,
            id: None,
            expires_at: None,
            single_use: None,
        };
        let shown = ShareOutput {
            tunnel: "t".into(),
            mode: "password".into(),
            expires_at: 9,
            username: Some("bob".into()),
            traffic_limited: true,
            links: vec![public],
        };
        assert_eq!(
            serde_json::to_value(&shown).unwrap(),
            json!({"tunnel":"t","mode":"password","expires_at":9,"username":"bob","traffic_limited":true,"links":[
                {"port":80,"url":"https://80-t.example/","connected":false}]})
        );
    }

    #[test]
    fn human_durations() {
        assert_eq!(human_duration(0), "0s");
        assert_eq!(human_duration(45), "45s");
        assert_eq!(human_duration(3600), "1h");
        assert_eq!(human_duration(5400), "1h30m");
        assert_eq!(human_duration(2 * 86_400 + 60), "2d1m");
    }

    /// A daemon serving `tunnel_id` (feature `expect` if `expect`) that
    /// answers like the real one and counts the Stops it accepts.
    async fn status_daemon(paths: &Paths, tunnel_id: &str, expect: bool) -> Arc<AtomicUsize> {
        use tokio::io::BufReader;
        use tunnel_protocol::{read_json_line, write_json_line};
        let stops = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
        let (count, id) = (stops.clone(), tunnel_id.to_string());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (count, id) = (count.clone(), id.clone());
                tokio::spawn(async move {
                    let (rd, mut wr) = stream.into_split();
                    let mut rd = BufReader::new(rd);
                    let mut buf = String::new();
                    while let Ok(Some(req)) = read_json_line::<_, Request>(&mut rd, &mut buf).await {
                        let features = if expect { vec!["target".into(), "expect".into()] } else { vec![] };
                        let status = Status { tunnel_id: Some(id.clone()), features, ..Status::stopped() };
                        let resp = match req {
                            Request::Stop { expect: Some(e) } if e.tunnel_id != id => {
                                Response::Error { message: crate::daemon::NOT_SERVING.into() }
                            }
                            Request::Stop { .. } => {
                                count.fetch_add(1, Ordering::SeqCst);
                                Response::Status { status }
                            }
                            _ => Response::Status { status },
                        };
                        let _ = write_json_line(&mut wr, &resp).await;
                    }
                });
            }
        });
        stops
    }

    /// An API that answers one request with 204.
    async fn api_204() -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.unwrap();
            String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or_default().to_string()
        });
        (api, peer)
    }

    fn save_shared(paths: &Paths, tunnel_id: &str, api: &str) -> Shared {
        let shared = Shared { tunnel_id: tunnel_id.into(), api: api.into(), token: Some(format!("{tunnel_id}-token")) };
        write_atomic(&shared_path(paths), &serde_json::to_vec(&shared).unwrap(), 0o600).unwrap();
        shared
    }

    fn test_login(api: String) -> anyhow::Result<Option<Login>> {
        Ok(Some(Login { name: "test".into(), api, server: String::new(), token: String::new() }))
    }

    #[tokio::test]
    async fn unshare_deletes_the_tunnel_and_stops_only_its_own_daemon() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (daemon_serves, expect, stopped) in [("shared", true, 1), ("other", true, 0), ("shared", false, 0)] {
            let paths = test_paths("unshare");
            let stops = status_daemon(&paths, daemon_serves, expect).await;
            let (api, peer) = api_204().await;
            let shared = save_shared(&paths, "shared", &api);
            assert!(unshare_tunnel(&paths, &shared, test_login(api), true).await);
            assert_eq!(peer.await.unwrap(), "DELETE /v1/tunnels/shared HTTP/1.1");
            assert!(load_shared(&paths).is_none());
            assert_eq!(stops.load(Ordering::SeqCst), stopped, "daemon serving {daemon_serves}, expect {expect}");
            std::fs::remove_dir_all(&paths.dir).unwrap();
        }
    }

    #[tokio::test]
    async fn unshare_stops_the_daemon_before_deleting_the_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
        use tunnel_protocol::{read_json_line, write_json_line};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let paths = test_paths("unshare-order");
        let deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped_after_delete = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The API notes when the DELETE arrives.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        let flag = deleted.clone();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap();
            flag.store(true, Ordering::SeqCst);
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        // The daemon notes whether its Stop came after the DELETE.
        let sock = tokio::net::UnixListener::bind(&paths.socket).unwrap();
        let (flag, late) = (deleted.clone(), stopped_after_delete.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = sock.accept().await {
                let (rd, mut wr) = stream.into_split();
                let mut rd = BufReader::new(rd);
                let mut buf = String::new();
                while let Ok(Some(req)) = read_json_line::<_, Request>(&mut rd, &mut buf).await {
                    if matches!(req, Request::Stop { .. }) && flag.load(Ordering::SeqCst) {
                        late.store(true, Ordering::SeqCst);
                    }
                    let status = Status {
                        tunnel_id: Some("shared".into()),
                        features: vec!["expect".into()],
                        ..Status::stopped()
                    };
                    let _ = write_json_line(&mut wr, &Response::Status { status }).await;
                }
            }
        });
        let shared = save_shared(&paths, "shared", &api);
        assert!(unshare_tunnel(&paths, &shared, test_login(api), true).await);
        peer.await.unwrap();
        assert!(deleted.load(Ordering::SeqCst));
        assert!(!stopped_after_delete.load(Ordering::SeqCst), "Stop must reach the daemon before the DELETE");
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[tokio::test]
    async fn unshare_waits_for_an_exiting_daemon_before_removing_its_state() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let paths = test_paths("unshare-exiting");
        let (api, peer) = api_204().await;
        let shared = save_shared(&paths, "shared", &api);
        let left = Persisted { tunnel_id: Some("shared".into()), revoked: true, ..Persisted::default() };
        left.save(&paths.state_file).unwrap();
        // A daemon that has closed its socket but still holds its lock for a moment.
        let lock = crate::daemon::lock_daemon(&paths).unwrap().unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            drop(lock);
        });
        assert!(unshare_tunnel(&paths, &shared, test_login(api), true).await);
        release.join().unwrap();
        peer.await.unwrap();
        assert!(!paths.state_file.exists(), "the exited daemon's state is removed");
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[tokio::test]
    async fn unshare_keeps_a_newer_share_and_state_that_is_not_its_own() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let paths = test_paths("unshare-newer");
        let (api, peer) = api_204().await;
        let old = Shared { tunnel_id: "old".into(), api: api.clone(), token: Some("old-token".into()) };
        save_shared(&paths, "newer", &api);
        let state = Persisted { tunnel_id: Some("newer".into()), token: "newer-token".into(), ..Persisted::default() };
        state.save(&paths.state_file).unwrap();
        // No daemon is running: the newer share's state and record stay.
        assert!(unshare_tunnel(&paths, &old, test_login(api.clone()), true).await);
        assert_eq!(peer.await.unwrap(), "DELETE /v1/tunnels/old HTTP/1.1");
        assert_eq!(load_shared(&paths).unwrap().tunnel_id, "newer");
        assert!(paths.state_file.exists());
        // Its own state is removed, so nothing restarts the deleted tunnel.
        let (api, peer) = api_204().await;
        let newer = save_shared(&paths, "newer", &api);
        assert!(unshare_tunnel(&paths, &newer, test_login(api), true).await);
        peer.await.unwrap();
        assert!(!paths.state_file.exists() && load_shared(&paths).is_none());
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[tokio::test]
    async fn daemon_ended_reports_gone_revoked_and_other_tunnels() {
        let paths = test_paths("ended");
        let shared = |id: &str| Shared { tunnel_id: id.into(), api: String::new(), token: Some(format!("{id}-token")) };
        assert_eq!(daemon_ended(&paths, &shared("shared")).await, Some(1));
        let revoked = Persisted { revoked: true, ..Persisted::default() };
        revoked.save(&paths.state_file).unwrap();
        assert_eq!(daemon_ended(&paths, &shared("shared")).await, Some(tunnel_protocol::EXIT_REVOKED));
        let _stops = status_daemon(&paths, "shared", true).await;
        assert_eq!(daemon_ended(&paths, &shared("shared")).await, None);
        assert_eq!(daemon_ended(&paths, &shared("mine")).await, Some(tunnel_protocol::EXIT_REPLACED));
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[tokio::test]
    async fn daemon_ended_before_welcome_goes_by_the_saved_token() {
        use tokio::io::BufReader;
        use tunnel_protocol::{read_json_line, write_json_line};
        let paths = test_paths("ended-pending");
        // A daemon still connecting (no tunnel id yet).
        let listener = tokio::net::UnixListener::bind(&paths.socket).unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (rd, mut wr) = stream.into_split();
                let _ = read_json_line::<_, Request>(&mut BufReader::new(rd), &mut String::new()).await;
                let _ = write_json_line(&mut wr, &Response::Status { status: Status::stopped() }).await;
            }
        });
        let shared = Shared { tunnel_id: "shared".into(), api: String::new(), token: Some("shared-token".into()) };
        Persisted { token: "shared-token".into(), ..Persisted::default() }.save(&paths.state_file).unwrap();
        assert_eq!(daemon_ended(&paths, &shared).await, None);
        Persisted { token: "other-token".into(), ..Persisted::default() }.save(&paths.state_file).unwrap();
        assert_eq!(daemon_ended(&paths, &shared).await, Some(tunnel_protocol::EXIT_REPLACED));
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[test]
    fn foreground_end_follows_the_earlier_of_timer_and_server_expiry() {
        let now = 1_000_000;
        let end = End { created: Instant::now(), duration_s: 3600, expires_at: now as i64 + 3600 };
        let left = end.remaining(now);
        assert!(left <= Duration::from_secs(3598) && left > Duration::from_secs(3590), "{left:?}");
        assert!(!end.is_due(now));
        // A slow create response: the server's expiry comes first.
        let late = End { created: Instant::now(), duration_s: 3600, expires_at: now as i64 + 3570 };
        assert_eq!(late.remaining(now), Duration::from_secs(3568));
        assert!(late.is_due(now + 3560));
        assert_eq!(late.remaining(now + 4000), Duration::ZERO);
    }

    #[test]
    fn reused_share_uses_persisted_token_only_for_the_same_tunnel() {
        let state =
            || Persisted { tunnel_id: Some("shared".into()), token: "persisted-token".into(), ..Persisted::default() };
        let mut shared = Shared { tunnel_id: "shared".into(), api: String::new(), token: None };
        assert!(persisted_share_token(&shared, Some(state())).as_deref() == Some("persisted-token"));
        shared.tunnel_id = "other".into();
        assert!(persisted_share_token(&shared, Some(state())).is_none());
        assert!(persisted_share_token(&shared, None).is_none());
    }

    #[test]
    fn pending_share_reuses_only_its_saved_token_before_welcome() {
        let shared = Shared { tunnel_id: "shared".into(), api: String::new(), token: Some("pending-token".into()) };
        let state = || Persisted { token: "pending-token".into(), ..Persisted::default() };
        assert!(persisted_share_token(&shared, Some(state())).as_deref() == Some("pending-token"));
        let mut other = state();
        other.token = "other-token".into();
        assert!(persisted_share_token(&shared, Some(other)).is_none());
        let mut other = state();
        other.tunnel_id = Some("other".into());
        assert!(persisted_share_token(&shared, Some(other)).is_none());
        let without_token: Shared = serde_json::from_value(json!({ "tunnel_id": "shared", "api": "" })).unwrap();
        assert!(persisted_share_token(&without_token, Some(state())).is_none());
    }

    #[test]
    fn share_and_link_require_the_daemon_to_serve_the_shared_tunnel() {
        let mut status = Status::stopped();
        status.tunnel_id = Some("other".into());
        assert!(require_shared_tunnel(&status, "shared").is_err());
        status.tunnel_id = Some("shared".into());
        assert!(require_shared_tunnel(&status, "shared").is_ok());
    }

    #[test]
    fn share_and_link_allow_a_pending_tunnel_id() {
        let mut status = Status::stopped();
        status.state = crate::ipc::ConnState::Connecting;
        assert!(require_shared_tunnel(&status, "shared").is_ok());
    }

    #[test]
    fn link_requires_persisted_shared_target_before_welcome() {
        let dir = std::env::temp_dir().join(format!("tunnel-link-target-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let paths = Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        };
        let mut shared = Shared { tunnel_id: "shared".into(), api: String::new(), token: Some("shared-token".into()) };
        let mut status = Status::stopped();
        status.state = crate::ipc::ConnState::Connecting;
        let mut other = status.clone();
        other.tunnel_id = Some("other".into());
        let expected = require_shared_tunnel(&other, &shared.tunnel_id).unwrap_err().to_string();

        let mut persisted = Persisted { token: "other-token".into(), ..Persisted::default() };
        persisted.save(&paths.state_file).unwrap();
        assert_eq!(require_link_tunnel(&status, &shared, &paths).unwrap_err().to_string(), expected);

        persisted.token = "shared-token".into();
        persisted.save(&paths.state_file).unwrap();
        assert!(require_link_tunnel(&status, &shared, &paths).is_ok());
        assert_eq!(require_link_tunnel(&other, &shared, &paths).unwrap_err().to_string(), expected);

        shared.token = None;
        assert_eq!(require_link_tunnel(&status, &shared, &paths).unwrap_err().to_string(), expected);
        shared.token = Some("shared-token".into());
        std::fs::remove_file(&paths.state_file).unwrap();
        assert_eq!(require_link_tunnel(&status, &shared, &paths).unwrap_err().to_string(), expected);

        status.tunnel_id = Some("shared".into());
        assert!(require_link_tunnel(&status, &shared, &paths).is_ok());
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[test]
    fn link_ttl_clamps_new_and_reused_shares_and_explicit_links() {
        assert_eq!(link_ttl(LINK_TTL_S, 220, 100).unwrap(), 115);
        assert_eq!(link_ttl(LINK_TTL_S, 1000, 100).unwrap(), 600);
        assert_eq!(link_ttl(LINK_TTL_S, 1000, 900).unwrap(), 95);
        assert_eq!(link_ttl(3600, 1000, 100).unwrap(), 895);
        assert_eq!(link_ttl(60, 1000, 100).unwrap(), 60);
        assert!(link_ttl(LINK_TTL_S, 134, 100).is_err());
        assert!(link_ttl(LINK_TTL_S, 99, 100).is_err());
        assert!(link_ttl(LINK_TTL_S, -1, 100).is_err());
        assert_eq!(link_minutes(600), "10");
        assert_eq!(link_minutes(115), "1.9");
        assert_eq!(link_minutes(30), "0.5");
    }

    #[tokio::test]
    async fn failed_shared_deletion_keeps_retry_state() {
        let dir = std::env::temp_dir().join(format!("tunnel-delete-shared-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let paths = Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        };
        let shared = || Shared { tunnel_id: "shared".into(), api: "http://original.invalid".into(), token: None };
        write_atomic(&shared_path(&paths), &serde_json::to_vec(&shared()).unwrap(), 0o600).unwrap();
        assert!(!delete_shared_with_login(&paths, shared(), Ok(None)).await);
        assert!(load_shared(&paths).is_some());
        let login = Login {
            name: "test".into(),
            api: "http://other.invalid".into(),
            server: String::new(),
            token: String::new(),
        };
        assert!(!delete_shared_with_login(&paths, shared(), Ok(Some(login))).await);
        assert!(load_shared(&paths).is_some());
        assert!(!delete_shared_with_login(&paths, shared(), Err(anyhow::anyhow!("cannot read login"))).await);
        assert!(load_shared(&paths).is_some());
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }

    #[tokio::test]
    async fn shared_deletion_api_error_keeps_state_and_success_removes_it() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let dir = std::env::temp_dir().join(format!("tunnel-delete-api-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let paths = Paths {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        };
        for (status, deleted) in [("500 Internal Server Error", false), ("404 Not Found", true)] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let api = format!("http://{}", listener.local_addr().unwrap());
            let shared = Shared { tunnel_id: "shared".into(), api: api.clone(), token: None };
            write_atomic(&shared_path(&paths), &serde_json::to_vec(&shared).unwrap(), 0o600).unwrap();
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                assert!(stream.read(&mut buf).await.unwrap() > 0);
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream.write_all(response.as_bytes()).await.unwrap();
            });
            let login = Login { name: "test".into(), api, server: String::new(), token: String::new() };
            assert_eq!(delete_shared_with_login(&paths, shared, Ok(Some(login))).await, deleted);
            peer.await.unwrap();
            assert_eq!(load_shared(&paths).is_none(), deleted);
        }
        std::fs::remove_dir_all(&paths.dir).unwrap();
    }
}
