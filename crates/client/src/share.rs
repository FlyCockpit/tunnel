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

use crate::commands::{Answer, ask};
use crate::ipc::{Request, Response, Status, host_for};
use crate::login::{Api, Login, enroll};
use crate::paths::{Paths, env_nonempty, terminal_text};
use crate::state::{Persisted, write_atomic};

pub const ENV_SHARE_PASSWORD: &str = "TUNNEL_SHARE_PASSWORD";
/// How long a link printed by `share` (and `link` by default) works.
pub const LINK_TTL_S: u64 = 10 * 60;
const CONNECT_WAIT: Duration = Duration::from_secs(15);

/// The tunnel `share` created, so later `share`/`link`/`stop` find it.
#[derive(Serialize, Deserialize)]
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

pub fn forget_shared(paths: &Paths) {
    let _ = std::fs::remove_file(shared_path(paths));
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

pub async fn share(
    ports: Vec<u16>,
    access: ShareAccess,
    ttl_s: u64,
    label: Option<String>,
    target: Option<String>,
) -> anyhow::Result<i32> {
    let target = crate::commands::resolve_target(target)?;
    let login = Login::require()?;
    let api = Api::new(&login)?;
    let paths = Paths::resolve()?;

    // Reuse the tunnel an earlier `share` made, while the daemon still serves it.
    let running = Persisted::load(&paths.state_file);
    let mut reuse = None;
    if let Some(s) = load_shared(&paths).filter(|s| s.api == login.api)
        && let Some(token) = persisted_share_token(&s, running)
        && let Some(info) = api.tunnel(&s.tunnel_id).await?.filter(|i| !i.expired)
    {
        reuse = Some((s.tunnel_id, token, info.access.mode, info.expires_at));
    }

    let (tunnel_id, token, mode, expires_at) = match reuse {
        Some((id, token, current_mode, expires_at)) => {
            let mode = if access.explicit() {
                let wanted = access.to_json()?;
                api.set_access(&id, &wanted).await?;
                wanted["mode"].as_str().unwrap_or("link").to_string()
            } else {
                current_mode
            };
            (id, Some(token), mode, expires_at)
        }
        None => {
            let wanted = access.to_json()?;
            let label = label.unwrap_or_else(|| format!("share-{}", hostname()));
            let created = api.create_tunnel(&label, ttl_s, &wanted).await?;
            let shared = Shared {
                tunnel_id: created.id.clone(),
                api: login.api.clone(),
                token: Some(created.tunnel_token.clone()),
            };
            write_atomic(&shared_path(&paths), &serde_json::to_vec(&shared)?, 0o600)?;
            let mode = wanted["mode"].as_str().unwrap_or("link").to_string();
            (created.id, Some(created.tunnel_token), mode, created.expires_at)
        }
    };

    let req = Request::Expose { ports: ports.clone(), token, server: Some(login.server.clone()), target };
    let mut status = match ask(req, true, false).await? {
        Answer::Response(Response::Status { status }) => status,
        Answer::Response(_) => bail!("unexpected daemon response"),
        Answer::Exit(code) => return Ok(code),
        Answer::Stopped => bail!("the daemon did not start"),
    };
    status = wait_connected(status, &ports).await;
    require_shared_tunnel(&status, &tunnel_id)?;

    let username = match mode.as_str() {
        "password" => api.tunnel(&tunnel_id).await?.and_then(|i| i.access.username),
        _ => None,
    };
    for port in &ports {
        let host = terminal_text(&port_host(&status, *port));
        let connected = status.ports.iter().any(|p| p.port == *port && p.connected);
        let note = if connected { "" } else { "  (not connected yet; check `tunnel status`)" };
        match mode.as_str() {
            "public" => println!("{port}  https://{host}/  (public){note}"),
            "password" => println!(
                "{port}  https://{host}/  (username {}, password as set){note}",
                terminal_text(username.as_deref().unwrap_or("?"))
            ),
            _ => {
                let ttl_s = link_ttl(LINK_TTL_S, expires_at, crate::ice::unix_now())?;
                let url = api.access_link(&tunnel_id, *port, ttl_s, true).await?;
                println!("{port}  {}  (works once, within {} min){note}", terminal_text(&url), link_minutes(ttl_s));
            }
        }
    }
    if mode == "link" {
        println!("More links: tunnel link [--port PORT] [--reusable]");
    }
    println!("Stop sharing: tunnel stop");
    Ok(0)
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
async fn wait_connected(mut status: Status, ports: &[u16]) -> Status {
    let deadline = Instant::now() + CONNECT_WAIT;
    let all = |s: &Status| ports.iter().all(|port| s.ports.iter().any(|p| p.port == *port && p.connected));
    while !all(&status) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(300)).await;
        match ask(Request::Status, false, false).await {
            Ok(Answer::Response(Response::Status { status: s })) => status = s,
            _ => break,
        }
    }
    status
}

pub async fn link(port: Option<u16>, reusable: bool, ttl_s: u64) -> anyhow::Result<i32> {
    let login = Login::require()?;
    let paths = Paths::resolve()?;
    let Some(shared) = load_shared(&paths).filter(|s| s.api == login.api) else {
        bail!("nothing shared from this machine; run `tunnel share <PORT>` first");
    };
    let status = match ask(Request::Status, false, false).await? {
        Answer::Response(Response::Status { status }) => status,
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
    let url = api.access_link(&shared.tunnel_id, port, ttl_s, !reusable).await?;
    let uses = if reusable { "any number of times" } else { "once" };
    let note = if status.ports.iter().any(|p| p.port == port && p.connected) {
        ""
    } else {
        "  (not connected yet; check `tunnel status`)"
    };
    println!("{}  (works {uses}, for {} min){note}", terminal_text(&url), link_minutes(ttl_s));
    Ok(0)
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
            forget_shared(paths);
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
        let legacy: Shared = serde_json::from_value(json!({ "tunnel_id": "shared", "api": "" })).unwrap();
        assert!(persisted_share_token(&legacy, Some(state())).is_none());
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
