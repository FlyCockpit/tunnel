//! The background daemon: persisted state, the IPC socket, and the shared
//! state the tunnel session (`session.rs`) and ICE endpoint (`ice.rs`) use.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tracing::{info, warn};
use tunnel_protocol::{ClientMsg, EXIT_REPLACED, EXIT_REVOKED, IceConfig, read_json_line, write_json_line};

use crate::ice;
use crate::ipc::{ConnState, PortStatus, Request, Response, Status, host_for};
use crate::paths::{self, ENV_SERVER, ENV_TOKEN, Paths, env_nonempty, terminal_text};
use crate::session;
use crate::state::{Persisted, normalize_server, resolve_server, write_atomic};

/// Wait for a server reply on the control stream.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `expose`/`ice` wait for an in-progress connection before answering.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

pub struct Reply {
    pub ok: bool,
    pub error: Option<String>,
    pub ice: Option<IceConfig>,
}

pub type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Reply>>>>;

/// Handle to the live control stream of one connection.
#[derive(Clone)]
pub struct Link {
    pub ctrl_tx: mpsc::Sender<ClientMsg>,
    pub pending: Pending,
    pub webrtc: bool,
    /// Connection generation; stale links never touch newer state.
    pub generation: u64,
}

pub struct Welcome {
    pub tunnel_id: String,
    pub host_template: String,
    pub max_ports: u16,
    pub ports: Vec<u16>,
}

struct Inner {
    persisted: Persisted,
    /// Ports the server has acknowledged on the current connection.
    accepted: BTreeSet<u16>,
    last_error: Option<String>,
    link: Option<Link>,
    ice: Option<IceConfig>,
    /// Bumped when the target tunnel changes, so the old connection's late
    /// results are discarded.
    generation: u64,
}

pub struct Daemon {
    pub paths: Paths,
    pub ice_file: PathBuf,
    /// Bearer token for the local `/ice` endpoint (see `ice::serve_http`).
    pub ice_token: String,
    pub ice_port: u16,
    /// Whether `/ice` is actually served (the port may be taken by someone
    /// else, who must not be handed the token).
    ice_http: bool,
    inner: Mutex<Inner>,
    conn: watch::Sender<ConnState>,
    /// Signalled when the token or server changes: drop the connection now.
    pub reconnect: Notify,
    next_id: AtomicU64,
}

pub fn lock_poisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Daemon {
    fn new(
        paths: Paths,
        ice_file: PathBuf,
        ice_token: String,
        ice_port: u16,
        ice_http: bool,
        persisted: Persisted,
    ) -> Self {
        Self {
            paths,
            ice_file,
            ice_token,
            ice_port,
            ice_http,
            inner: Mutex::new(Inner {
                persisted,
                accepted: BTreeSet::new(),
                last_error: None,
                link: None,
                ice: None,
                generation: 0,
            }),
            conn: watch::channel(ConnState::Connecting).0,
            reconnect: Notify::new(),
            next_id: AtomicU64::new(1),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        lock_poisoned(&self.inner)
    }

    fn save(&self, inner: &Inner) {
        if let Err(e) = inner.persisted.save(&self.paths.state_file) {
            warn!(path = %self.paths.state_file.display(), error = %e, "cannot write state file");
        }
    }

    pub fn conn_state(&self) -> ConnState {
        *self.conn.borrow()
    }

    pub fn set_conn(&self, state: ConnState) {
        self.conn.send_replace(state);
    }

    async fn wait_connected(&self, within: Duration) {
        let mut rx = self.conn.subscribe();
        let _ = tokio::time::timeout(within, rx.wait_for(|s| *s == ConnState::Connected)).await;
    }

    /// `(server, token, generation)` for the next connection attempt.
    pub fn target(&self) -> (String, String, u64) {
        let g = self.lock();
        (g.persisted.server.clone(), g.persisted.token.clone(), g.generation)
    }

    pub fn ports(&self) -> Vec<u16> {
        self.lock().persisted.ports.clone()
    }

    pub fn is_exposed(&self, port: u16) -> bool {
        self.lock().persisted.ports.contains(&port)
    }

    /// Where to dial `port` for a stream from connection `generation`
    /// (`Some(None)`: loopback), checked under one lock; `None` if the port is
    /// not exposed or the connection is no longer the current one.
    pub fn dial_target(&self, port: u16, generation: u64) -> Option<Option<std::net::IpAddr>> {
        let g = self.lock();
        (g.generation == generation && g.persisted.ports.contains(&port)).then_some(g.persisted.target)
    }

    pub fn set_last_error(&self, error: String) {
        self.lock().last_error = Some(error);
    }

    /// Install a freshly welcomed connection. Returns stale ports to remove
    /// and ports persisted during the handshake that still need declaring,
    /// or `None` if the target changed meanwhile.
    pub fn connected(&self, link: Link, welcome: Welcome, hello: &[u16]) -> Option<(Vec<u16>, Vec<u16>)> {
        let mut g = self.lock();
        if g.generation != link.generation {
            return None;
        }
        let accepted: BTreeSet<u16> =
            welcome.ports.iter().copied().filter(|p| hello.contains(p) && g.persisted.ports.contains(p)).collect();
        let stale =
            welcome.ports.iter().copied().filter(|p| hello.contains(p) && !g.persisted.ports.contains(p)).collect();
        // The server keeps a prefix when over max_ports; drop the rest locally.
        let dropped: Vec<u16> = hello.iter().copied().filter(|p| !welcome.ports.contains(p)).collect();
        g.persisted.ports.retain(|p| !dropped.contains(p));
        let missing = g.persisted.ports.iter().copied().filter(|p| !hello.contains(p)).collect();
        g.last_error = (!dropped.is_empty())
            .then(|| format!("server allows at most {} ports; not exposed: {dropped:?}", welcome.max_ports));
        g.persisted.tunnel_id = Some(welcome.tunnel_id);
        g.persisted.host_template = Some(welcome.host_template);
        g.accepted = accepted;
        g.link = Some(link);
        self.save(&g);
        drop(g);
        self.set_conn(ConnState::Connected);
        Some((stale, missing))
    }

    /// Forget the connection of `generation` (no-op if already superseded).
    pub fn disconnected(&self, generation: u64) {
        let mut g = self.lock();
        if g.generation == generation {
            g.link = None;
            g.accepted.clear();
            drop(g);
            self.set_conn(ConnState::Connecting);
        }
    }

    /// Record a terminal outcome and exit. Revoked: 401/410 or tunnel
    /// deleted/expired. Replaced: another client holds the tunnel.
    pub fn terminate(&self, state: ConnState, why: &str) -> ! {
        {
            let mut g = self.lock();
            match state {
                ConnState::Revoked => g.persisted.revoked = true,
                ConnState::Replaced => g.persisted.replaced = true,
                _ => {}
            }
            g.link = None;
            g.accepted.clear();
            g.ice = None;
            g.last_error = Some(why.to_string());
            self.save(&g);
        }
        self.set_conn(state);
        if state == ConnState::Revoked {
            let _ = fs::remove_file(&self.ice_file);
        }
        let _ = fs::remove_file(&self.paths.socket);
        warn!("{why}; daemon exiting");
        std::process::exit(if state == ConnState::Revoked { EXIT_REVOKED } else { EXIT_REPLACED });
    }

    /// Send one request on the control stream and wait for its `Reply`.
    pub async fn call(&self, link: &Link, msg: impl FnOnce(u64) -> ClientMsg) -> anyhow::Result<Reply> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock_poisoned(&link.pending).insert(id, tx);
        if link.ctrl_tx.send(msg(id)).await.is_err() {
            lock_poisoned(&link.pending).remove(&id);
            bail!("not connected to the tunnel server");
        }
        self.wait_reply(link, id, rx).await
    }

    async fn wait_reply(&self, link: &Link, id: u64, rx: oneshot::Receiver<Reply>) -> anyhow::Result<Reply> {
        let reply = match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => bail!("connection to the tunnel server was lost"),
            Err(_) => {
                lock_poisoned(&link.pending).remove(&id);
                bail!("tunnel server did not reply within {}s", CALL_TIMEOUT.as_secs());
            }
        };
        if !reply.ok {
            bail!("{}", terminal_text(&reply.error.unwrap_or_else(|| "rejected by the tunnel server".to_string())));
        }
        Ok(reply)
    }

    /// Re-check a Hello-era removal and enqueue it atomically with respect to
    /// `expose` changing the desired ports. A later expose queues after this removal.
    pub async fn remove_stale_port(&self, link: &Link, port: u16) -> anyhow::Result<()> {
        // Reserve capacity before locking so the synchronous send cannot block.
        let permit = link.ctrl_tx.reserve().await.context("not connected to the tunnel server")?;
        let (id, rx) = {
            let g = self.lock();
            if g.generation != link.generation || g.persisted.ports.contains(&port) {
                return Ok(());
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            lock_poisoned(&link.pending).insert(id, tx);
            permit.send(ClientMsg::Unexpose { id, port });
            (id, rx)
        };
        self.wait_reply(link, id, rx).await?;
        Ok(())
    }

    /// Declare one port on a live connection.
    pub async fn declare(&self, link: &Link, port: u16) -> anyhow::Result<()> {
        self.call(link, |id| ClientMsg::Expose { id, port }).await?;
        let mut g = self.lock();
        if g.generation == link.generation && g.persisted.ports.contains(&port) {
            g.accepted.insert(port);
        }
        Ok(())
    }

    pub fn is_current(&self, generation: u64) -> bool {
        self.lock().generation == generation
    }

    pub fn set_last_error_if(&self, generation: u64, error: String) {
        let mut g = self.lock();
        if g.generation == generation {
            g.last_error = Some(error);
        }
    }

    pub fn drop_port_if(&self, port: u16, generation: u64) {
        let mut g = self.lock();
        if g.generation != generation {
            return;
        }
        g.persisted.ports.retain(|p| *p != port);
        g.accepted.remove(&port);
        self.save(&g);
    }

    pub fn status(&self) -> Status {
        let state = self.conn_state();
        let g = self.lock();
        let template = g.persisted.host_template.clone();
        Status {
            state,
            tunnel_id: g.persisted.tunnel_id.clone(),
            ports: g
                .persisted
                .ports
                .iter()
                .map(|&port| PortStatus {
                    port,
                    host: template.as_deref().map(|t| host_for(t, port)),
                    connected: state == ConnState::Connected && g.accepted.contains(&port),
                })
                .collect(),
            host_template: template,
            last_error: g.last_error.clone(),
            ice_file: Some(self.ice_file.display().to_string()),
            target: g.persisted.target,
            features: crate::ipc::DAEMON_FEATURES.iter().map(|f| f.to_string()).collect(),
        }
    }

    /// Switch tunnels when a command brings a different token (clears ports,
    /// the target and the revoked flag), or reconnect when the server URL
    /// changes. A new forwarding target applies to new visitor streams.
    fn retarget(&self, token: Option<String>, server: Option<String>, target: Option<String>) -> anyhow::Result<u64> {
        if let Some(token) = &token {
            paths::validate_tunnel_token(token)?;
        }
        let server = server.map(|s| normalize_server(&s)).transpose()?;
        let target = target.map(|t| paths::parse_target(&t)).transpose()?;
        let mut g = self.lock();
        let mut changed = false;
        if let Some(token) = token.filter(|t| *t != g.persisted.token) {
            info!("tunnel token changed; switching tunnels");
            let server = g.persisted.server.clone();
            g.persisted = Persisted { server, token, ..Persisted::default() };
            g.ice = None;
            g.last_error = None;
            changed = true;
        }
        if let Some(server) = server.filter(|s| *s != g.persisted.server) {
            info!(server = %server, "tunnel server changed; reconnecting");
            g.persisted.server = server;
            changed = true;
        }
        if let Some(target) = target.filter(|t| g.persisted.target != Some(*t)) {
            info!(%target, "forwarding target changed");
            g.persisted.target = Some(target);
            self.save(&g);
        }
        if changed {
            g.generation += 1;
            g.link = None;
            g.accepted.clear();
            self.save(&g);
            self.set_conn(ConnState::Connecting);
            self.reconnect.notify_one();
        }
        Ok(g.generation)
    }

    async fn expose(
        &self,
        ports: Vec<u16>,
        token: Option<String>,
        server: Option<String>,
        target: Option<String>,
    ) -> anyhow::Result<Status> {
        let generation = self.retarget(token, server, target)?;
        for port in ports {
            let link = {
                let mut g = self.lock();
                if g.generation != generation {
                    bail!("tunnel changed while exposing ports");
                }
                if g.persisted.ports.contains(&port) {
                    continue;
                }
                g.persisted.ports.push(port);
                g.persisted.ports.sort_unstable();
                self.save(&g);
                g.link.clone()
            };
            // Disconnected: persisted only; the next Hello declares it.
            let Some(link) = link else { continue };
            if let Err(e) = self.declare(&link, port).await {
                self.drop_port_if(port, generation);
                return Err(e.context(format!("exposing port {port}")));
            }
        }
        if self.conn_state() != ConnState::Connected {
            self.wait_connected(CONNECT_WAIT).await;
        }
        Ok(self.status())
    }

    async fn unexpose(&self, port: u16) -> anyhow::Result<Status> {
        let link = {
            let mut g = self.lock();
            if !g.persisted.ports.contains(&port) {
                bail!("port {port} is not exposed");
            }
            g.persisted.ports.retain(|p| *p != port);
            g.accepted.remove(&port);
            self.save(&g);
            g.link.clone()
        };
        // Local removal already stops routing (`is_exposed`); the server
        // message only updates its view.
        if let Some(link) = link
            && let Err(e) = self.call(&link, |id| ClientMsg::Unexpose { id, port }).await
        {
            warn!(port, error = %format!("{e:#}"), "server did not acknowledge unexpose");
        }
        Ok(self.status())
    }

    pub fn current_ice(&self) -> Option<IceConfig> {
        let now = ice::unix_now();
        self.lock().ice.clone().filter(|i| i.expires_at > now)
    }

    pub fn ice_needs_refresh(&self) -> bool {
        let cached = self.lock().ice.clone();
        cached.as_ref().is_none_or(ice::needs_refresh)
    }

    /// Fetch a new credential and rewrite the ICE file.
    pub async fn refresh_ice(&self, link: &Link) -> anyhow::Result<IceConfig> {
        let reply = self.call(link, |id| ClientMsg::IceRequest { id }).await?;
        let config = reply.ice.ok_or_else(|| anyhow!("tunnel server sent no ICE config"))?;
        let json = serde_json::to_vec_pretty(&config)?;
        let mut g = self.lock();
        if g.generation != link.generation {
            bail!("tunnel changed while fetching ICE config");
        }
        // Keep retargeting out until both the file and cache hold this generation.
        write_atomic(&self.ice_file, &json, 0o600).with_context(|| format!("writing {}", self.ice_file.display()))?;
        g.ice = Some(config.clone());
        Ok(config)
    }

    async fn ice(&self, fresh: bool) -> anyhow::Result<IceConfig> {
        if !fresh {
            let cached = self.lock().ice.clone();
            if let Some(config) = cached.filter(|i| !ice::needs_refresh(i)) {
                return Ok(config);
            }
        }
        if self.conn_state() != ConnState::Connected {
            self.wait_connected(CONNECT_WAIT).await;
        }
        let link = self.lock().link.clone();
        match link {
            Some(link) if link.webrtc => self.refresh_ice(&link).await,
            Some(_) => bail!("this tunnel server does not offer TURN/WebRTC"),
            None => match self.current_ice() {
                Some(config) if !fresh => Ok(config),
                _ => bail!("not connected to the tunnel server"),
            },
        }
    }

    async fn handle(&self, req: Request) -> Response {
        let result = match req {
            Request::Expose { ports, token, server, target } => {
                self.expose(ports, token, server, target).await.map(|status| Response::Status { status })
            }
            Request::Unexpose { port } => self.unexpose(port).await.map(|status| Response::Status { status }),
            Request::Status | Request::Stop => Ok(Response::Status { status: self.status() }),
            Request::Ice { fresh } => self.ice(fresh).await.map(|ice| Response::Ice {
                ice,
                ice_file: self.ice_file.display().to_string(),
                ice_url: self.ice_http.then(|| format!("http://127.0.0.1:{}/ice", self.ice_port)),
                ice_token: self.ice_http.then(|| self.ice_token.clone()),
            }),
        };
        result.unwrap_or_else(|e| Response::Error { message: format!("{e:#}") })
    }

    /// `stop`: forget the tunnel locally so no later command resurrects it.
    fn stop(&self) -> ! {
        let _ = fs::remove_file(&self.paths.state_file);
        let _ = fs::remove_file(&self.ice_file);
        let _ = fs::remove_file(&self.paths.socket);
        info!("stop requested; daemon exiting");
        std::process::exit(0);
    }
}

/// Entry point of the `daemon` subcommand (foreground; also what commands spawn).
pub async fn run() -> anyhow::Result<()> {
    harden_process();
    let paths = Paths::resolve()?;
    let Some(_lock) = lock_daemon(&paths)? else {
        info!("another daemon holds the lock; exiting");
        return Ok(());
    };

    // An unreadable saved state (e.g. a malformed target) stops the daemon
    // rather than being replaced by defaults such as a loopback target.
    let mut persisted = Persisted::load_strict(&paths.state_file)
        .with_context(|| format!("{}; `tunnel stop` removes it", paths.state_file.display()))?
        .unwrap_or_default();
    if let Some(token) = paths::env_token()?.filter(|t| *t != persisted.token) {
        // A different token is a different tunnel: start clean.
        persisted = Persisted { token, ..Persisted::default() };
    }
    if persisted.token.is_empty() {
        bail!("no tunnel token: set {ENV_TOKEN}");
    }
    if let Some(target) = paths::env_target()? {
        persisted.target = Some(target);
    }
    if persisted.revoked {
        warn!("tunnel was revoked; not reconnecting");
        std::process::exit(EXIT_REVOKED);
    }
    // Being started at all means a command chose to take the tunnel back.
    persisted.replaced = false;
    persisted.server = resolve_server(env_nonempty(ENV_SERVER).as_deref(), Some(persisted.server.as_str()))?;
    persisted.save(&paths.state_file).context("writing state file")?;

    match fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing stale {}", paths.socket.display())),
    }
    let listener = UnixListener::bind(&paths.socket).with_context(|| format!("binding {}", paths.socket.display()))?;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

    let ice_file = paths::ice_file(&paths.dir);
    let ice_port = paths::ice_port();
    let ice_token = ice::load_or_create_token(&paths.dir).context("ICE endpoint token")?;
    info!(
        server = %persisted.server,
        ports = ?persisted.ports,
        ice_file = %ice_file.display(),
        "daemon starting"
    );
    let ice_listener = ice::bind_http(ice_port).await;
    let daemon = Arc::new(Daemon::new(paths, ice_file, ice_token, ice_port, ice_listener.is_some(), persisted));
    tokio::spawn(accept_ipc(daemon.clone(), listener));
    if let Some(ice_listener) = ice_listener {
        tokio::spawn(ice::serve_http(daemon.clone(), ice_listener, ice_port));
    }
    tokio::spawn(exit_on_signal(daemon.clone()));
    session::run(daemon).await;
    Ok(())
}

/// The daemon holds the tunnel token in memory: keep other processes of the
/// same user from reading it through ptrace or `/proc/<pid>/mem` and
/// `environ`, and from core dumps (Linux).
fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) only changes this process's dumpable flag.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            warn!(error = %io::Error::last_os_error(), "could not mark the daemon non-dumpable");
        }
    }
}

/// One daemon per state dir; held for the process lifetime.
fn lock_daemon(paths: &Paths) -> anyhow::Result<Option<File>> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(&paths.lock_file)
        .with_context(|| format!("opening {}", paths.lock_file.display()))?;
    // SAFETY: the fd is valid for the lifetime of `file`.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock { Ok(None) } else { Err(err).context("locking daemon lock file") }
}

async fn accept_ipc(daemon: Arc<Daemon>, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(serve_ipc(daemon.clone(), stream));
            }
            Err(e) => {
                warn!(error = %e, "ipc accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn serve_ipc(daemon: Arc<Daemon>, stream: UnixStream) {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let mut buf = String::new();
    loop {
        let req = match read_json_line::<_, Request>(&mut rd, &mut buf).await {
            Ok(Some(req)) => req,
            Ok(None) => return,
            Err(e) => {
                // Not logged: a malformed request may carry the token.
                let message = format!("bad request: {e}");
                let _ = write_json_line(&mut wr, &Response::Error { message }).await;
                return;
            }
        };
        let stop = matches!(req, Request::Stop);
        let resp = daemon.handle(req).await;
        if write_json_line(&mut wr, &resp).await.is_err() {
            return;
        }
        if stop {
            daemon.stop();
        }
    }
}

/// SIGTERM/SIGINT: exit but keep the state file, so the next command restarts
/// the daemon with the same ports.
async fn exit_on_signal(daemon: Arc<Daemon>) {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
        warn!("cannot install signal handlers");
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    info!("signal received; daemon exiting");
    let _ = fs::remove_file(&daemon.paths.socket);
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expose_rejects_foreign_token_without_changing_the_target_or_ports() {
        let daemon = Daemon::new(
            Paths {
                dir: PathBuf::new(),
                socket: PathBuf::new(),
                state_file: PathBuf::new(),
                log_file: PathBuf::new(),
                lock_file: PathBuf::new(),
            },
            PathBuf::new(),
            String::new(),
            0,
            false,
            Persisted {
                token: format!("{}test", tunnel_protocol::TUNNEL_TOKEN_PREFIX),
                server: "wss://original.example.com".into(),
                ports: vec![3000],
                ..Persisted::default()
            },
        );
        let target = daemon.target();
        let response = daemon
            .handle(Request::Expose {
                ports: vec![8080],
                token: Some("foreign-credential".into()),
                server: Some("wss://other.example.com".into()),
                target: None,
            })
            .await;
        let Response::Error { message } = response else {
            panic!("expected an error for a foreign token");
        };
        assert!(message.contains(tunnel_protocol::TUNNEL_TOKEN_PREFIX));
        assert!(!message.contains("foreign-credential"));
        assert!(daemon.target() == target);
        assert_eq!(daemon.ports(), vec![3000]);
    }

    struct Fixture {
        daemon: Arc<Daemon>,
        dir: PathBuf,
    }

    impl Fixture {
        fn new(ports: Vec<u16>) -> Self {
            let dir = std::env::temp_dir().join(format!("tunnel-daemon-test-{}", rand::random::<u64>()));
            fs::create_dir(&dir).unwrap();
            let paths = Paths {
                socket: dir.join("daemon.sock"),
                state_file: dir.join("state.json"),
                log_file: dir.join("daemon.log"),
                lock_file: dir.join("daemon.lock"),
                dir: dir.clone(),
            };
            let persisted = Persisted {
                server: "wss://original.example.com".into(),
                token: "tntun_original".into(),
                ports,
                ..Persisted::default()
            };
            let daemon = Arc::new(Daemon::new(paths, dir.join("ice.json"), String::new(), 0, false, persisted));
            Self { daemon, dir }
        }

        fn link(&self) -> (Link, mpsc::Receiver<ClientMsg>) {
            let (ctrl_tx, rx) = mpsc::channel(16);
            let link = Link { ctrl_tx, pending: Pending::default(), webrtc: true, generation: self.daemon.target().2 };
            (link, rx)
        }

        fn connect(&self) -> (Link, mpsc::Receiver<ClientMsg>) {
            let (link, rx) = self.link();
            let ports = self.daemon.ports();
            let welcome = Welcome {
                tunnel_id: "original".into(),
                host_template: "{port}.example.com".into(),
                max_ports: 4,
                ports: ports.clone(),
            };
            assert!(self.daemon.connected(link.clone(), welcome, &ports).is_some());
            (link, rx)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    fn reply(link: &Link, id: u64, ok: bool, ice: Option<IceConfig>) {
        let tx = lock_poisoned(&link.pending).remove(&id).unwrap();
        assert!(tx.send(Reply { ok, error: (!ok).then(|| "rejected".into()), ice }).is_ok());
    }

    #[test]
    fn drop_port_if_preserves_ports_from_a_new_generation() {
        let fixture = Fixture::new(vec![3000]);
        let daemon = &fixture.daemon;
        let old = daemon.target().2;
        let generation = daemon.retarget(Some("tntun_new".into()), None, None).unwrap();
        {
            let mut g = daemon.lock();
            g.persisted.ports.push(3000);
            g.accepted.insert(3000);
        }
        daemon.drop_port_if(3000, old);
        assert_eq!(daemon.ports(), vec![3000]);
        assert!(daemon.lock().accepted.contains(&3000));
        daemon.drop_port_if(3000, generation);
        assert!(daemon.ports().is_empty());
        assert!(!daemon.lock().accepted.contains(&3000));
    }

    async fn expose_superseded_during_declare(ok: bool) {
        let fixture = Fixture::new(vec![]);
        let (link, mut rx) = fixture.connect();
        let daemon = fixture.daemon.clone();
        let request = tokio::spawn(async move { daemon.expose(vec![3000, 5173], None, None, None).await });
        let Some(ClientMsg::Expose { id, port: 3000 }) = rx.recv().await else {
            panic!("expected expose");
        };
        fixture.daemon.retarget(Some("tntun_new".into()), None, None).unwrap();
        fixture.daemon.lock().persisted.ports.push(3000);
        reply(&link, id, ok, None);
        assert!(request.await.unwrap().is_err());
        assert_eq!(fixture.daemon.ports(), vec![3000]);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn failed_declare_does_not_remove_a_retargeted_port() {
        expose_superseded_during_declare(false).await;
    }

    #[tokio::test]
    async fn superseded_expose_does_not_push_remaining_ports() {
        expose_superseded_during_declare(true).await;
    }

    #[test]
    fn welcome_reconciles_ports_removed_and_added_during_hello() {
        let fixture = Fixture::new(vec![5173, 8080]);
        let (link, _rx) = fixture.link();
        let welcome = Welcome {
            tunnel_id: "original".into(),
            host_template: "{port}.example.com".into(),
            max_ports: 4,
            // 9999 wasn't in Hello and must not be classified as stale.
            ports: vec![3000, 8080, 9999],
        };
        let (stale, missing) = fixture.daemon.connected(link, welcome, &[3000, 8080]).unwrap();
        assert_eq!(stale, vec![3000]);
        assert_eq!(missing, vec![5173]);
        assert_eq!(fixture.daemon.lock().accepted, BTreeSet::from([8080]));
    }

    #[tokio::test]
    async fn failed_ice_file_write_does_not_publish_cache_and_ipc_retries() {
        let fixture = Fixture::new(vec![]);
        let (link, mut rx) = fixture.connect();
        // An existing directory cannot be replaced by the atomic file rename.
        fs::create_dir(&fixture.daemon.ice_file).unwrap();
        let config = IceConfig { ice_servers: vec![], expires_at: ice::unix_now() + 60, ttl_s: 60 };
        let daemon = fixture.daemon.clone();
        let first = tokio::spawn(async move { daemon.handle(Request::Ice { fresh: false }).await });
        let Some(ClientMsg::IceRequest { id }) = rx.recv().await else {
            panic!("expected ICE request");
        };
        reply(&link, id, true, Some(config.clone()));
        assert!(matches!(first.await.unwrap(), Response::Error { .. }));
        assert!(fixture.daemon.current_ice().is_none());
        assert!(fixture.daemon.ice_needs_refresh());
        fs::remove_dir(&fixture.daemon.ice_file).unwrap();
        let daemon = fixture.daemon.clone();
        let retry = tokio::spawn(async move { daemon.handle(Request::Ice { fresh: false }).await });
        let Some(ClientMsg::IceRequest { id }) = rx.recv().await else {
            panic!("expected ICE retry");
        };
        reply(&link, id, true, Some(config.clone()));
        assert!(matches!(retry.await.unwrap(), Response::Ice { .. }));
        assert_eq!(fixture.daemon.current_ice().unwrap().expires_at, config.expires_at);
        let written: IceConfig = serde_json::from_slice(&fs::read(&fixture.daemon.ice_file).unwrap()).unwrap();
        assert_eq!(written.expires_at, config.expires_at);
    }

    #[tokio::test]
    async fn superseded_ice_refresh_does_not_write_file_or_cache() {
        let fixture = Fixture::new(vec![]);
        let (link, mut rx) = fixture.connect();
        let daemon = fixture.daemon.clone();
        let old_link = link.clone();
        let refresh = tokio::spawn(async move { daemon.refresh_ice(&old_link).await });
        let Some(ClientMsg::IceRequest { id }) = rx.recv().await else {
            panic!("expected ICE request");
        };
        fixture.daemon.retarget(Some("tntun_new".into()), None, None).unwrap();
        reply(&link, id, true, Some(IceConfig { ice_servers: vec![], expires_at: ice::unix_now() + 60, ttl_s: 60 }));
        assert!(refresh.await.unwrap().is_err());
        assert!(fixture.daemon.current_ice().is_none());
        assert!(!fixture.daemon.ice_file.exists());
    }

    #[tokio::test]
    async fn reconciliation_unexposes_stale_ports_before_declaring_missing() {
        let fixture = Fixture::new(vec![5173]);
        let (link, mut rx) = fixture.connect();
        let daemon = fixture.daemon.clone();
        let reconcile_link = link.clone();
        let task = tokio::spawn(crate::session::reconcile_ports(daemon, reconcile_link, vec![3000], vec![5173]));
        let Some(ClientMsg::Unexpose { id, port: 3000 }) = rx.recv().await else {
            panic!("expected stale unexpose first");
        };
        assert!(rx.try_recv().is_err());
        reply(&link, id, true, None);
        let Some(ClientMsg::Expose { id, port: 5173 }) = rx.recv().await else {
            panic!("expected missing expose second");
        };
        reply(&link, id, true, None);
        task.await.unwrap();
        assert!(fixture.daemon.lock().accepted.contains(&5173));
    }

    #[tokio::test]
    async fn reconciliation_preserves_a_stale_port_reexposed_after_welcome() {
        let fixture = Fixture::new(vec![]);
        let (link, mut rx) = fixture.link();
        let hello = vec![3000, 8080];
        let welcome = Welcome {
            tunnel_id: "original".into(),
            host_template: "{port}.example.com".into(),
            max_ports: 4,
            ports: hello.clone(),
        };
        let (stale, missing) = fixture.daemon.connected(link.clone(), welcome, &hello).unwrap();
        let task = tokio::spawn(crate::session::reconcile_ports(fixture.daemon.clone(), link.clone(), stale, missing));
        let Some(ClientMsg::Unexpose { id: removing, port: 3000 }) = rx.recv().await else {
            panic!("expected first stale removal");
        };
        // Re-expose the next stale port while reconciliation waits for the first reply.
        let daemon = fixture.daemon.clone();
        let expose = tokio::spawn(async move { daemon.expose(vec![8080], None, None, None).await });
        let Some(ClientMsg::Expose { id, port: 8080 }) = rx.recv().await else {
            panic!("expected re-expose");
        };
        reply(&link, id, true, None);
        assert!(expose.await.unwrap().unwrap().ports.iter().any(|p| p.port == 8080 && p.connected));
        reply(&link, removing, true, None);
        task.await.unwrap();
        assert!(rx.try_recv().is_err());
        assert!(fixture.daemon.lock().accepted.contains(&8080));
    }

    #[tokio::test]
    async fn stale_removal_rechecks_desired_ports_after_waiting_for_queue_capacity() {
        let fixture = Fixture::new(vec![]);
        let (link, mut rx) = fixture.connect();
        for _ in 0..16 {
            link.ctrl_tx.try_send(ClientMsg::IceRequest { id: 0 }).unwrap();
        }
        let removal = fixture.daemon.remove_stale_port(&link, 3000);
        tokio::pin!(removal);
        tokio::select! {
            biased;
            _ = &mut removal => panic!("removal must wait for queue capacity"),
            _ = std::future::ready(()) => {}
        }
        let expose = fixture.daemon.expose(vec![3000], None, None, None);
        tokio::pin!(expose);
        tokio::select! {
            biased;
            _ = &mut expose => panic!("expose must wait for queue capacity"),
            _ = std::future::ready(()) => {}
        }
        assert!(fixture.daemon.is_exposed(3000));
        for _ in 0..16 {
            assert!(matches!(rx.recv().await, Some(ClientMsg::IceRequest { id: 0 })));
        }
        removal.await.unwrap();
        let (status, ()) = tokio::join!(expose, async {
            let Some(ClientMsg::Expose { id, port: 3000 }) = rx.recv().await else {
                panic!("desired port must not be removed");
            };
            reply(&link, id, true, None);
        });
        assert!(status.unwrap().ports.iter().any(|p| p.port == 3000 && p.connected));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn stale_removal_rechecks_generation_after_waiting_for_queue_capacity() {
        let fixture = Fixture::new(vec![]);
        let (link, mut rx) = fixture.connect();
        for _ in 0..16 {
            link.ctrl_tx.try_send(ClientMsg::IceRequest { id: 0 }).unwrap();
        }
        let removal = fixture.daemon.remove_stale_port(&link, 3000);
        tokio::pin!(removal);
        tokio::select! {
            biased;
            _ = &mut removal => panic!("removal must wait for queue capacity"),
            _ = std::future::ready(()) => {}
        }
        fixture.daemon.retarget(Some("tntun_new".into()), None, None).unwrap();
        for _ in 0..16 {
            assert!(matches!(rx.recv().await, Some(ClientMsg::IceRequest { id: 0 })));
        }
        removal.await.unwrap();
        assert!(rx.try_recv().is_err());
        assert!(lock_poisoned(&link.pending).is_empty());
    }

    #[tokio::test]
    async fn superseded_reconciliation_preserves_new_ports_and_error() {
        let fixture = Fixture::new(vec![3000, 5173]);
        let (link, mut rx) = fixture.connect();
        let task = tokio::spawn(crate::session::reconcile_ports(
            fixture.daemon.clone(),
            link.clone(),
            vec![],
            vec![3000, 5173],
        ));
        let Some(ClientMsg::Expose { id, port: 3000 }) = rx.recv().await else {
            panic!("expected expose");
        };
        fixture.daemon.retarget(Some("tntun_new".into()), None, None).unwrap();
        fixture.daemon.lock().persisted.ports.push(3000);
        fixture.daemon.set_last_error("new generation error".into());
        reply(&link, id, false, None);
        task.await.unwrap();
        assert_eq!(fixture.daemon.ports(), vec![3000]);
        assert_eq!(fixture.daemon.status().last_error.as_deref(), Some("new generation error"));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn target_is_saved_with_the_tunnel_and_cleared_by_a_new_token() {
        let h = Fixture::new(vec![]);
        let token = h.daemon.target().1;
        h.daemon.retarget(None, None, Some("10.20.0.2".into())).unwrap();
        assert_eq!(h.daemon.status().target, Some("10.20.0.2".parse().unwrap()));
        assert_eq!(h.daemon.status().target, Some("10.20.0.2".parse().unwrap()));
        assert!(h.daemon.retarget(None, None, Some("sandbox.internal".into())).is_err());
        assert_eq!(h.daemon.status().target, Some("10.20.0.2".parse().unwrap()), "a refused target changes nothing");
        // The same token keeps it; a different token is a different tunnel.
        h.daemon.retarget(Some(token), None, None).unwrap();
        assert_eq!(h.daemon.status().target, Some("10.20.0.2".parse().unwrap()));
        h.daemon.retarget(Some(format!("{}other", tunnel_protocol::TUNNEL_TOKEN_PREFIX)), None, None).unwrap();
        assert_eq!(h.daemon.status().target, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_process_is_not_dumpable() {
        harden_process();
        // SAFETY: PR_GET_DUMPABLE only reads this process's flag.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }

    #[test]
    fn streams_from_a_previous_connection_cannot_dial() {
        let f = Fixture::new(vec![3000]);
        let generation = f.daemon.target().2;
        f.daemon.retarget(None, None, Some("10.20.0.2".into())).unwrap();
        assert_eq!(f.daemon.dial_target(3000, generation), Some(Some("10.20.0.2".parse().unwrap())));
        assert_eq!(f.daemon.dial_target(3001, generation), None, "not exposed");
        // Switching tunnels makes the old connection's streams stale.
        f.daemon.retarget(Some(format!("{}other", tunnel_protocol::TUNNEL_TOKEN_PREFIX)), None, None).unwrap();
        f.daemon.lock().persisted.ports.push(3000);
        assert_eq!(f.daemon.dial_target(3000, generation), None, "stale generation");
        assert_eq!(f.daemon.dial_target(3000, f.daemon.target().2), Some(None));
    }
}
