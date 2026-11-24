//! The tunnel connection: dial, Yamux, control stream, data streams, and the
//! reconnect loop.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use rand::RngExt;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode, header::AUTHORIZATION};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};
use tunnel_protocol::mux::{self, Stream as StreamHandle};
use tunnel_protocol::{
    CONNECT_PATH, ClientMsg, CloseReason, PING_INTERVAL, PROTOCOL_VERSION, STREAM_NOT_EXPOSED, STREAM_OK,
    STREAM_REFUSED, ServerMsg, decode_preamble, read_json_line, write_json_line, ws_bridge,
};

use crate::daemon::{Daemon, Link, Pending, Reply, Welcome, lock_poisoned};
use crate::ice;
use crate::ipc::ConnState;

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the backoff.
const STABLE_AFTER: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PREAMBLE_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a Close may trail the end of the session (see `drain_close`).
const CLOSE_DRAIN: Duration = Duration::from_secs(1);
/// Max frame on the outer socket (plan: control plane, item 7).
const MAX_FRAME: usize = 512 * 1024;
const ICE_CHECK_INTERVAL: Duration = Duration::from_secs(5 * 60);
const ICE_RETRY: Duration = Duration::from_secs(30);
const CONTROL_QUEUE: usize = 64;

enum End {
    Lost(String),
    Revoked(String),
    Replaced,
    Shutdown,
    /// Token or server changed; reconnect immediately.
    Superseded,
}

struct AbortOnDrop<T>(JoinHandle<T>);

/// Fails every call still waiting for a reply when the connection ends, so
/// callers holding a `Link` clone learn at once instead of timing out.
struct FailPendingOnDrop(Pending);

impl Drop for FailPendingOnDrop {
    fn drop(&mut self) {
        lock_poisoned(&self.0).clear();
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Connect forever. Returns only through `Daemon::terminate` (process exit).
pub async fn run(daemon: Arc<Daemon>) {
    let mut failures: u32 = 0;
    loop {
        let (server, token, generation) = daemon.target();
        daemon.set_conn(ConnState::Connecting);
        let mut connected_at: Option<Instant> = None;
        let end = tokio::select! {
            end = connect(&daemon, &server, &token, generation, &mut connected_at) => end,
            _ = daemon.retargeted() => End::Superseded,
        };
        daemon.disconnected(generation);
        match end {
            End::Revoked(why) => daemon.terminate(ConnState::Revoked, &why),
            End::Replaced => daemon.terminate(ConnState::Replaced, "another client connected with this tunnel token"),
            End::Superseded => {
                failures = 0;
                continue;
            }
            End::Shutdown => {
                info!("tunnel server is shutting down; reconnecting");
                daemon.set_last_error("tunnel server restarted".to_string());
            }
            End::Lost(why) => {
                warn!(error = %why, "tunnel connection lost");
                daemon.set_last_error(why);
            }
        }
        if connected_at.is_some_and(|t| t.elapsed() >= STABLE_AFTER) {
            failures = 0;
        }
        let delay = backoff(failures);
        failures = failures.saturating_add(1);
        debug!(delay_ms = delay.as_millis() as u64, "reconnecting after delay");
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = daemon.retargeted() => {
                failures = 0;
            }
        }
    }
}

/// Exponential 1s → 30s with jitter over the upper half, so a fleet of
/// sandboxes does not reconnect in lockstep after a server restart.
fn backoff(failures: u32) -> Duration {
    let base = BACKOFF_MIN.saturating_mul(1u32 << failures.min(5)).min(BACKOFF_MAX);
    let ms = base.as_millis() as u64;
    Duration::from_millis(rand::rng().random_range(ms / 2..=ms))
}

async fn connect(
    daemon: &Arc<Daemon>,
    server: &str,
    token: &str,
    generation: u64,
    connected_at: &mut Option<Instant>,
) -> End {
    match establish(daemon, server, token, generation, connected_at).await {
        Ok(end) => end,
        Err(e) => End::Lost(format!("{e:#}")),
    }
}

async fn establish(
    daemon: &Arc<Daemon>,
    server: &str,
    token: &str,
    generation: u64,
    connected_at: &mut Option<Instant>,
) -> anyhow::Result<End> {
    let url = format!("{server}{CONNECT_PATH}");
    let mut request = url.as_str().into_client_request().context("invalid tunnel server URL")?;
    let auth = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| anyhow!("tunnel token contains characters not allowed in a header"))?;
    request.headers_mut().insert(AUTHORIZATION, auth);
    // tungstenite never offers permessage-deflate, which the plan requires off.
    let config = WebSocketConfig::default().max_frame_size(Some(MAX_FRAME));

    let dial = tokio_tungstenite::connect_async_with_config(request, Some(config), true);
    let ws = match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Err(_) => bail!("timed out connecting to {server}"),
        Ok(Err(WsError::Http(resp))) if is_terminal(resp.status()) => {
            return Ok(End::Revoked(format!("tunnel server rejected the token ({})", resp.status())));
        }
        Ok(Err(e)) => return Err(anyhow::Error::new(e).context(format!("connecting to {server}"))),
        Ok(Ok((ws, _response))) => ws,
    };

    let (duplex, pump) = ws_bridge::bridge(ws, PING_INTERVAL);
    let _pump = AbortOnDrop(pump);
    let session = mux::Session::new_client(duplex);
    let mut control = session.control();
    let mut driver = AbortOnDrop(tokio::spawn(drive_session(daemon.clone(), session, generation)));

    let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, control.open_stream()).await {
        Err(_) => bail!("timed out opening the control stream"),
        Ok(Err(e)) => bail!("opening the control stream: {e}"),
        Ok(Ok(stream)) => stream,
    };
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);
    let mut buf = String::new();

    let hello = daemon.ports();
    write_json_line(&mut wr, &ClientMsg::Hello { version: PROTOCOL_VERSION, ports: hello.clone() })
        .await
        .context("sending hello")?;
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_json_line::<_, ServerMsg>(&mut rd, &mut buf))
        .await
        .map_err(|_| anyhow!("timed out waiting for welcome"))?
        .context("reading welcome")?;
    let (welcome, webrtc) = match first {
        Some(ServerMsg::Welcome { tunnel_id, host_template, max_ports, ports, webrtc }) => {
            (Welcome { tunnel_id, host_template, max_ports, ports }, webrtc)
        }
        Some(ServerMsg::Close { reason }) => return Ok(close_end(reason)),
        // Not formatted: a stray Reply could carry TURN credentials.
        Some(ServerMsg::Reply { .. }) => bail!("unexpected reply before welcome"),
        None => bail!("tunnel server closed the control stream before welcome"),
    };
    let tunnel_id = welcome.tunnel_id.clone();

    let (ctrl_tx, ctrl_rx) = mpsc::channel(CONTROL_QUEUE);
    let pending = Pending::default();
    let _fail_pending = FailPendingOnDrop(pending.clone());
    let link = Link { ctrl_tx, pending: pending.clone(), webrtc, generation };
    let _writer = AbortOnDrop(tokio::spawn(write_control(wr, ctrl_rx)));
    let Some((stale, missing)) = daemon.connected(link.clone(), welcome, &hello) else {
        return Ok(End::Superseded);
    };
    *connected_at = Some(Instant::now());
    info!(tunnel_id = %tunnel_id, ports = ?daemon.ports(), webrtc, "connected");

    let _declare = AbortOnDrop(tokio::spawn(reconcile_ports(daemon.clone(), link.clone(), stale, missing)));
    let _ice = webrtc.then(|| AbortOnDrop(tokio::spawn(maintain_ice(daemon.clone(), link.clone()))));
    drop(link);

    loop {
        tokio::select! {
            // A Close that arrived with the end of the session is read first.
            biased;
            msg = read_json_line::<_, ServerMsg>(&mut rd, &mut buf) => match msg {
                Ok(Some(ServerMsg::Reply { id, ok, error, ice })) => {
                    let tx = lock_poisoned(&pending).remove(&id);
                    if let Some(tx) = tx {
                        let _ = tx.send(Reply { ok, error, ice });
                    }
                }
                Ok(Some(ServerMsg::Close { reason })) => return Ok(close_end(reason)),
                Ok(Some(ServerMsg::Welcome { .. })) => warn!("ignoring duplicate welcome"),
                Ok(None) => return Ok(End::Lost("control stream closed".to_string())),
                Err(e) => return Ok(End::Lost(format!("control stream: {e}"))),
            },
            // Cancelling the read only happens on this exit path, so a
            // partially read line is never lost mid-session.
            _ = &mut driver.0 => return Ok(drain_close(&mut rd, &mut buf).await),
        }
    }
}

/// The session ended: the server may have sent `Close` just before hanging
/// up. Its reason decides the exit code (e.g. 4 for replaced, not a
/// reconnect that only finds the token rotated), so read what is buffered.
async fn drain_close<R: tokio::io::AsyncBufRead + Unpin>(rd: &mut R, buf: &mut String) -> End {
    loop {
        match tokio::time::timeout(CLOSE_DRAIN, read_json_line::<_, ServerMsg>(rd, buf)).await {
            Ok(Ok(Some(ServerMsg::Close { reason }))) => return close_end(reason),
            Ok(Ok(Some(_))) => {}
            _ => return End::Lost("tunnel session ended".to_string()),
        }
    }
}

fn is_terminal(status: StatusCode) -> bool {
    status == StatusCode::UNAUTHORIZED || status == StatusCode::GONE
}

fn close_end(reason: CloseReason) -> End {
    match reason {
        CloseReason::Deleted => End::Revoked("tunnel was deleted".to_string()),
        CloseReason::Expired => End::Revoked("tunnel expired".to_string()),
        // Another client holds the tunnel now; reconnecting would just fight it.
        CloseReason::Replaced => End::Replaced,
        CloseReason::Shutdown => End::Shutdown,
    }
}

/// Own the Yamux session: polling it drives all streams. Every inbound stream
/// is a server-opened data stream.
async fn drive_session(daemon: Arc<Daemon>, mut session: mux::Session, generation: u64) {
    while let Some(stream) = session.next().await {
        tokio::spawn(handle_data_stream(daemon.clone(), stream, generation));
    }
    debug!("yamux session ended");
}

async fn write_control<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<ClientMsg>) {
    while let Some(msg) = rx.recv().await {
        if let Err(e) = write_json_line(&mut wr, &msg).await {
            debug!(error = %e, "control stream write failed");
            break;
        }
    }
}

/// Undo removals made while Hello was in flight before declaring new ports.
pub(crate) async fn reconcile_ports(daemon: Arc<Daemon>, link: Link, stale: Vec<u16>, missing: Vec<u16>) {
    for port in stale {
        if !daemon.is_current(link.generation) {
            return;
        }
        if let Err(e) = daemon.remove_stale_port(&link, port).await {
            warn!(port, error = %format!("{e:#}"), "server did not acknowledge stale port removal");
        }
    }
    for port in missing {
        if !daemon.is_current(link.generation) {
            return;
        }
        if !daemon.is_exposed(port) {
            continue;
        }
        if let Err(e) = daemon.declare(&link, port).await {
            let msg = format!("exposing port {port}: {e:#}");
            warn!("{msg}");
            daemon.drop_port_if(port, link.generation);
            daemon.set_last_error_if(link.generation, msg);
        }
    }
}

/// Request ICE on connect, then whenever less than 25% of the TTL remains.
async fn maintain_ice(daemon: Arc<Daemon>, link: Link) {
    let mut force = true;
    loop {
        let wait = if force || daemon.ice_needs_refresh() {
            match daemon.refresh_ice(&link).await {
                Ok(ice) => {
                    info!(expires_at = ice.expires_at, "ICE credentials refreshed");
                    force = false;
                    ice_refresh_delay(&ice, ice::unix_now())
                }
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "ICE refresh failed");
                    ICE_RETRY
                }
            }
        } else {
            daemon.current_ice().as_ref().map_or(Duration::from_secs(5), |ice| ice_refresh_delay(ice, ice::unix_now()))
        };
        tokio::time::sleep(wait).await;
    }
}

fn ice_refresh_delay(config: &tunnel_protocol::IceConfig, now: u64) -> Duration {
    let refresh_at = config.expires_at.saturating_sub(config.ttl_s / 4);
    Duration::from_secs(refresh_at.saturating_sub(now)).min(ICE_CHECK_INTERVAL).max(Duration::from_secs(5))
}

/// `generation`: the connection the stream arrived on. A stream that outlives
/// a switch to another tunnel must not reach that tunnel's ports or target.
async fn handle_data_stream(daemon: Arc<Daemon>, mut stream: StreamHandle, generation: u64) {
    let mut preamble = [0u8; 2];
    match tokio::time::timeout(PREAMBLE_TIMEOUT, stream.read_exact(&mut preamble)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let port = decode_preamble(preamble);
    let Some(target) = daemon.dial_target(port, generation) else {
        debug!(port, "stream for a port that is not exposed");
        let _ = stream.write_all(&[STREAM_NOT_EXPOSED]).await;
        let _ = stream.shutdown().await;
        return;
    };
    let Some(mut local) = connect_local(port, target).await else {
        debug!(port, "local origin refused the connection");
        let _ = stream.write_all(&[STREAM_REFUSED]).await;
        let _ = stream.shutdown().await;
        return;
    };
    if stream.write_all(&[STREAM_OK]).await.is_err() {
        return;
    }
    if let Err(e) = tokio::io::copy_bidirectional(&mut stream, &mut local).await {
        debug!(port, error = %e, "stream ended with error");
    }
}

/// Loopback by default; Node ≥17 dev servers often bind `localhost` to `::1`
/// only, hence the fallback. With a target (`TUNNEL_TARGET_HOST`, an IP
/// literal set by whoever started the daemon, e.g. a sandbox host dialling its
/// guest), only `<target>:<port>` is dialled. Either way only exposed ports
/// are reached: the caller checks `is_exposed` first.
async fn connect_local(port: u16, target: Option<std::net::IpAddr>) -> Option<TcpStream> {
    let candidates = match target {
        Some(ip) => vec![SocketAddr::new(ip, port)],
        None => vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port)), SocketAddr::from((Ipv6Addr::LOCALHOST, port))],
    };
    for addr in candidates {
        if let Ok(Ok(tcp)) = tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            let _ = tcp.set_nodelay(true);
            return Some(tcp);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_protocol::IceConfig;

    #[test]
    fn ice_refresh_delay_tracks_short_ttls_and_bounds_long_or_expired_ones() {
        let config = |expires_at, ttl_s| IceConfig { ice_servers: vec![], expires_at, ttl_s };
        assert_eq!(ice_refresh_delay(&config(160, 60), 100), Duration::from_secs(45));
        assert_eq!(ice_refresh_delay(&config(130, 60), 100), Duration::from_secs(15));
        assert_eq!(ice_refresh_delay(&config(101, 60), 100), Duration::from_secs(5));
        assert_eq!(ice_refresh_delay(&config(99, 60), 100), Duration::from_secs(5));
        assert_eq!(ice_refresh_delay(&config(86_500, 86_400), 100), ICE_CHECK_INTERVAL);
    }

    #[tokio::test]
    async fn target_is_dialled_alone_without_loopback_fallback() {
        // Listen on IPv6 loopback only.
        let Ok(listener) = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await else {
            return; // No IPv6 loopback in this environment.
        };
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        // Loopback default falls back to ::1.
        assert!(connect_local(port, None).await.is_some());
        // An explicit target is the only address tried.
        assert!(connect_local(port, Some(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST))).await.is_some());
        assert!(connect_local(port, Some(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST))).await.is_none());
    }

    #[tokio::test]
    async fn close_buffered_at_session_end_decides_the_outcome() {
        let mut buf = String::new();
        let lines = b"{\"type\":\"reply\",\"id\":1,\"ok\":true}\n{\"type\":\"close\",\"reason\":\"replaced\"}\n";
        let mut rd = tokio::io::BufReader::new(&lines[..]);
        assert!(matches!(drain_close(&mut rd, &mut buf).await, End::Replaced));
        let mut rd = tokio::io::BufReader::new(&b"{\"type\":\"close\",\"reason\":\"deleted\"}\n"[..]);
        assert!(matches!(drain_close(&mut rd, &mut buf).await, End::Revoked(_)));
        let mut rd = tokio::io::BufReader::new(&b""[..]);
        assert!(matches!(drain_close(&mut rd, &mut buf).await, End::Lost(_)));
    }
}
