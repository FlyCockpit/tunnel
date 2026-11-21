//! Built-in STUN/TURN relay (RFC 5766 over UDP, TCP, and TLS), replacing
//! coturn so a rootless install can offer WebRTC.
//!
//! - UDP and TCP on `webrtc.stun_port` (3478); TLS arrives on 443 and is
//!   handed over by the listener after SNI routing (`turn_host`).
//! - Credentials are the TURN REST ones `ice::mint` hands out:
//!   `username = "<expiry>:<tunnel>:<subject>"`, checked for expiry, with
//!   `password = base64(HMAC-SHA1(static_auth_secret, username))`.
//! - Relays are UDP sockets in `relay_min_port..=relay_max_port`, advertised
//!   at the public IPv4. Relays never send to or
//!   accept from non-public addresses or the server's own non-relay ports, so
//!   a credential cannot reach the host, its metadata service, or a private
//!   network. Relay-to-relay traffic (both peers on this server) is delivered
//!   in-process instead of hairpinning through the public address.
//! - Limits: `MAX_ALLOCATIONS` relays in total, 240 per tunnel and 240 per
//!   source IP (IPv6 /64), each limited to `MAX_BPS` in both directions together.
//!   At most `MAX_STREAM_CONNS` TCP/TLS connections; Allocate must authenticate
//!   within 10 seconds. Expiry/revocation gates requests and relay traffic,
//!   and a 30-second sweep deletes expired or invalid allocations.
//!
//! Each TCP/TLS connection gets its own `turn` server instance, so its
//! allocations end when the connection does (RFC 5766 §2.1).
//!
//! Authentication supports legacy MD5 long-term keys and MESSAGE-INTEGRITY.
//! turn 0.17.3 advertises PASSWORD-ALGORITHMS=[MD5] in 401 challenges, but
//! requests using RFC 8489 password negotiation or MESSAGE-INTEGRITY-SHA256
//! are dropped by this guard. Clients insisting on these are unsupported;
//! clients must use the legacy mechanism used by browsers.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use stun::integrity::MessageIntegrity;
use stun::message::{Message, Setter};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use turn::auth::{AuthHandler, generate_auth_key};
use turn::relay::RelayAddressGenerator;
use turn::server::Server;
use turn::server::config::{ConnConfig, ServerConfig};
use webrtc_util::Conn;

use crate::config::Config;
use crate::metrics::Metrics;

/// Relays (allocations) open at once, server-wide.
pub const MAX_ALLOCATIONS: usize = 1200;
pub const MAX_ALLOCATIONS_PER_TUNNEL: usize = 240;
pub const MAX_ALLOCATIONS_PER_IP: usize = 240;
const STREAM_AUTH_DEADLINE: Duration = Duration::from_secs(10);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const VALIDATION_TTL: Duration = Duration::from_secs(90);
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(4);
// At least VALIDATION_TIMEOUT, so a stream never gives up on a lookup that is
// still allowed to finish (it cannot retransmit the request it holds).
const STREAM_VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const SECURITY_ENTRIES: usize = 50_000;
// Covers validation TTL + sweep interval + AppState's 5s cache, with slack.
const REVOCATION_TTL: Duration = Duration::from_secs(150);
const VALIDATION_LOOKUPS: usize = 8;
const MAX_STREAM_CONNS_PER_IP: usize = 32;
const CHALLENGE_IP_RATE: f64 = 10.0;
const CHALLENGE_IP_BURST: f64 = 20.0;
const CHALLENGE_GLOBAL_RATE: f64 = 200.0;
const CHALLENGE_GLOBAL_BURST: f64 = 400.0;
const CHALLENGE_IP_ENTRIES: usize = 4096;
const CHALLENGE_IDLE: Duration = Duration::from_secs(60);
/// Per-relay bandwidth cap, bits per second, both directions together.
const MAX_BPS: u64 = 3_000_000;
/// TURN-over-TCP/TLS connections open at once.
const MAX_STREAM_CONNS: usize = 1000;
/// A TCP/TLS connection that sends nothing for this long is closed (clients
/// refresh allocations every few minutes).
const STREAM_IDLE: Duration = Duration::from_secs(15 * 60);
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest TURN frame accepted over a stream (STUN or ChannelData).
const MAX_FRAME: usize = 4 + 65_535 + 3;
const BIND_ATTEMPTS: usize = 32;
/// Relay-to-relay packets queued for one relay before dropping.
const HUB_QUEUE: usize = 256;

/// A packet from another relay on this server, with its relay address.
type HubPacket = (Vec<u8>, SocketAddr);

pub struct Relay {
    shared: Arc<Shared>,
    streams: Arc<Semaphore>,
    udp: Mutex<Option<Arc<RelayServer>>>,
}

struct Shared {
    realm: String,
    secret: String,
    public_ip: Ipv4Addr,
    min_port: u16,
    max_port: u16,
    /// Inboxes of live relays by port, for relay-to-relay delivery.
    hub: Mutex<HashMap<u16, mpsc::Sender<HubPacket>>>,
    allocations: AtomicUsize,
    metrics: Arc<MetricsRef>,
    /// Peers that tests may relay to despite being non-public (loopback).
    allow_private_peers: bool,
    max_credential_ttl: i64,
    state: OnceLock<Weak<crate::state::AppState>>,
    servers: Mutex<Vec<Weak<RelayServer>>>,
    security: Mutex<Security>,
    revocation_epoch: AtomicU64,
    validation_slots: Arc<Semaphore>,
    challenges: Mutex<ChallengeLimiter>,
    stream_ips: Mutex<HashMap<IpAddr, usize>>,
    validation_changed: Notify,
    /// Seconds added to the Unix clock for credential expiry, so tests can
    /// expire a credential without waiting for the wall clock.
    #[cfg(test)]
    clock_skew: std::sync::atomic::AtomicI64,
}

/// Each turn server owns a 16-slot command channel. Serialize its command
/// producers independently; shutdown never waits for or holds this lock.
struct RelayServer {
    server: Server,
    commands: tokio::sync::Mutex<()>,
}

impl std::ops::Deref for RelayServer {
    type Target = Server;

    fn deref(&self) -> &Server {
        &self.server
    }
}

/// The relay only needs the allocation gauge; keeps `Metrics` borrowing simple.
#[derive(Default)]
pub struct MetricsRef {
    pub allocations: std::sync::atomic::AtomicI64,
}

impl Relay {
    /// Bind UDP and TCP `stun_port` and start serving. TLS connections are
    /// passed in through [`Relay::serve_stream`].
    pub async fn start(cfg: &Config, metrics: &Metrics) -> anyhow::Result<Arc<Self>> {
        let w = &cfg.webrtc;
        let public_ip = cfg.public_ipv4.context("WebRTC needs public_ipv4 in the config")?;
        anyhow::ensure!(!w.static_auth_secret.is_empty(), "webrtc.static_auth_secret is empty");
        anyhow::ensure!(w.relay_min_port <= w.relay_max_port, "relay port range is empty");
        let relay = Arc::new(Self::new(Shared {
            realm: cfg.turn_host.clone(),
            secret: w.static_auth_secret.clone(),
            public_ip,
            min_port: w.relay_min_port,
            max_port: w.relay_max_port,
            hub: Mutex::new(HashMap::new()),
            allocations: AtomicUsize::new(0),
            metrics: metrics.turn.clone(),
            allow_private_peers: false,
            max_credential_ttl: w.sandbox_ttl_s.max(w.browser_ttl_s).min(i64::MAX as u64) as i64,
            state: OnceLock::new(),
            servers: Mutex::new(Vec::new()),
            security: Mutex::new(Security::default()),
            revocation_epoch: AtomicU64::new(0),
            validation_slots: Arc::new(Semaphore::new(VALIDATION_LOOKUPS)),
            challenges: Mutex::new(ChallengeLimiter::new()),
            stream_ips: Mutex::new(HashMap::new()),
            validation_changed: Notify::new(),
            #[cfg(test)]
            clock_skew: Default::default(),
        }));
        let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, w.stun_port));
        let udp = UdpSocket::bind(bind).await.with_context(|| format!("binding udp {bind}"))?;
        let tcp = TcpListener::bind(bind).await.with_context(|| format!("binding tcp {bind}"))?;
        relay.serve_udp(udp).await?;
        tokio::spawn(relay.clone().accept_tcp(tcp));
        tracing::info!(port = w.stun_port, relays = %format!("{}-{}", w.relay_min_port, w.relay_max_port), %public_ip, "TURN relay started");
        Ok(relay)
    }

    fn new(shared: Shared) -> Self {
        Self { shared: Arc::new(shared), streams: Arc::new(Semaphore::new(MAX_STREAM_CONNS)), udp: Mutex::new(None) }
    }

    fn server_config(&self, conn: Arc<GuardConn>) -> ServerConfig {
        ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: conn.clone(),
                relay_addr_generator: Box::new(RelayGen {
                    shared: self.shared.clone(),
                    context: conn.context.clone(),
                    refused: conn.refused.clone(),
                    activity: conn.activity.clone(),
                }),
            }],
            realm: self.shared.realm.clone(),
            auth_handler: Arc::new(RestAuth { shared: self.shared.clone() }),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        }
    }

    async fn new_server(
        &self,
        conn: Arc<dyn Conn + Send + Sync>,
    ) -> anyhow::Result<(Arc<RelayServer>, Arc<GuardConn>)> {
        let conn = Arc::new(GuardConn::new(conn, self.shared.clone()));
        let server = Arc::new(RelayServer {
            server: Server::new(self.server_config(conn.clone())).await?,
            commands: tokio::sync::Mutex::new(()),
        });
        let _ = conn.server.set(Arc::downgrade(&server));
        let mut servers = self.shared.servers.lock().unwrap();
        servers.retain(|s| s.strong_count() > 0);
        servers.push(Arc::downgrade(&server));
        drop(servers);
        let weak = Arc::downgrade(&server);
        let shared = Arc::downgrade(&self.shared);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                let (Some(server), Some(shared)) = (weak.upgrade(), shared.upgrade()) else { break };
                sweep_server(&server, &shared).await;
            }
        });
        Ok((server, conn))
    }

    async fn serve_udp(&self, udp: UdpSocket) -> anyhow::Result<()> {
        let (server, _) = self.new_server(Arc::new(udp)).await.context("starting the TURN server")?;
        *self.udp.lock().unwrap() = Some(server);
        Ok(())
    }

    /// Install the lifecycle validator before making the relay available to callers.
    pub fn install_state(&self, state: Weak<crate::state::AppState>) {
        let _ = self.shared.state.set(state);
    }

    /// Drop cached lifecycle/expiry data and fence reads already in flight.
    /// This leaves allocations and credentials valid while fresh data loads.
    pub fn forget_validation(&self, id: &str) {
        let mut security = self.shared.security.lock().unwrap();
        security.validated.remove(id);
        if security.validating.contains(id) {
            security.validation_fenced.insert(id.to_owned());
        }
    }

    /// Fence synchronously so deleting a tunnel never waits for relay I/O.
    pub fn fence_tunnel(&self, id: &str) {
        self.shared.revoke(id);
    }

    /// Fence credentials first, then close allocations on UDP and every stream.
    pub async fn revoke_tunnel(&self, id: &str) {
        self.fence_tunnel(id);
        let servers: Vec<_> = self.shared.servers.lock().unwrap().iter().filter_map(Weak::upgrade).collect();
        let mut tasks = tokio::task::JoinSet::new();
        for server in servers {
            let id = id.to_owned();
            tasks.spawn(async move {
                // Bound lock acquisition and the whole batch too, so many
                // usernames or a closing server cannot delay other servers.
                let _ = tokio::time::timeout(SERVER_COMMAND_TIMEOUT, async {
                    let _commands = server.commands.lock().await;
                    if let Ok(Ok(infos)) =
                        tokio::time::timeout(SERVER_COMMAND_TIMEOUT, server.get_allocations_info(None)).await
                    {
                        let users: HashSet<_> = infos
                            .values()
                            .filter(|a| credential_parts(&a.username).is_some_and(|(_, tunnel)| tunnel == id))
                            .map(|a| a.username.clone())
                            .collect();
                        for user in users {
                            let _ = tokio::time::timeout(
                                SERVER_COMMAND_TIMEOUT,
                                server.delete_allocations_by_username(user),
                            )
                            .await;
                        }
                    }
                })
                .await;
            });
        }
        while tasks.join_next().await.is_some() {}
    }

    async fn accept_tcp(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((tcp, peer)) => {
                    let _ = tcp.set_nodelay(true);
                    let local = tcp.local_addr().unwrap_or(peer);
                    let relay = self.clone();
                    tokio::spawn(async move { relay.serve_stream(tcp, local, peer).await });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TURN tcp accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Serve TURN on one TCP or (already decrypted) TLS connection until it closes.
    pub async fn serve_stream<S>(&self, stream: S, local: SocketAddr, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let Ok(_permit) = self.streams.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "too many TURN stream connections");
            return;
        };
        let Some(_ip_permit) = self.shared.reserve_stream(peer.ip()) else { return };
        let conn = Arc::new(StreamConn::new(stream, local, peer));
        let closed = conn.closed.clone();
        let (server, guarded) = match self.new_server(conn).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "TURN stream server failed to start");
                return;
            }
        };
        // The server's read loop closes the conn (and its allocations) when
        // the stream ends or fails.
        tokio::select! {
            _ = closed.cancelled() => {},
            _ = guarded.activity.empty_timeout() => {},
        }
        let _ = server.close().await;
    }

    #[cfg(test)]
    fn for_test(public_ip: Ipv4Addr, min_port: u16, max_port: u16, secret: &str) -> Self {
        Self::new(Shared {
            realm: "turn.test".into(),
            secret: secret.into(),
            public_ip,
            min_port,
            max_port,
            hub: Mutex::new(HashMap::new()),
            allocations: AtomicUsize::new(0),
            metrics: Arc::new(MetricsRef { allocations: Default::default() }),
            allow_private_peers: true,
            max_credential_ttl: 86_400,
            state: OnceLock::new(),
            servers: Mutex::new(Vec::new()),
            security: Mutex::new(Security::default()),
            revocation_epoch: AtomicU64::new(0),
            validation_slots: Arc::new(Semaphore::new(VALIDATION_LOOKUPS)),
            challenges: Mutex::new(ChallengeLimiter::new()),
            stream_ips: Mutex::new(HashMap::new()),
            validation_changed: Notify::new(),
            #[cfg(test)]
            clock_skew: Default::default(),
        })
    }
}

// ---------------------------------------------------------------- auth

struct RestAuth {
    shared: Arc<Shared>,
}

impl AuthHandler for RestAuth {
    fn auth_handle(&self, username: &str, realm: &str, _src: SocketAddr) -> Result<Vec<u8>, turn::Error> {
        if !self.shared.credential_allowed(username) {
            return Err(turn::Error::Other("invalid or revoked credential".into()));
        }
        let password = crate::ice::credential(&self.shared.secret, username);
        Ok(generate_auth_key(username, realm, &password))
    }
}

/// The credential format is unchanged; reject malformed identities before any lookup.
fn credential_parts(username: &str) -> Option<(i64, &str)> {
    // RFC 5389 USERNAME bound also limits memory used by identity tables.
    if username.len() > 513 {
        return None;
    }
    let mut parts = username.splitn(3, ':');
    let expiry = parts.next()?.parse().ok()?;
    let tunnel = parts.next()?;
    let subject = parts.next()?;
    if tunnel.is_empty() || subject.is_empty() {
        return None;
    }
    Some((expiry, tunnel))
}

#[derive(Default)]
struct Security {
    revoked: HashMap<String, tokio::time::Instant>,
    // Zero expiry is a cached negative result, avoiding repeated invalid lookups.
    validated: HashMap<String, (tokio::time::Instant, i64)>,
    validating: HashSet<String>,
    // Only in-flight lookups need a fence; PendingValidation removes it.
    validation_fenced: HashSet<String>,
    tunnels: HashMap<String, TunnelQuota>,
    ips: HashMap<IpAddr, usize>,
}

#[derive(Default)]
struct TunnelQuota {
    count: usize,
    // Sticky for the lifetime of these allocations, even if a fence is evicted.
    revoked: AtomicBool,
}

fn source_network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            IpAddr::V6((u128::from(ip) & (u128::MAX << 64)).into())
        }
        ip => ip,
    }
}

impl Shared {
    /// Unix seconds that credential expiry is checked against.
    fn now(&self) -> i64 {
        #[cfg(test)]
        return crate::tokens::now() + self.clock_skew.load(Ordering::SeqCst);
        #[cfg(not(test))]
        crate::tokens::now()
    }

    fn credential_allowed(&self, username: &str) -> bool {
        let Some((expiry, tunnel)) = credential_parts(username) else { return false };
        let now = self.now();
        if expiry <= now || expiry > now.saturating_add(self.max_credential_ttl) {
            return false;
        }
        self.tunnel_allowed(tunnel)
    }

    fn tunnel_allowed(&self, tunnel: &str) -> bool {
        let security = self.security.lock().unwrap();
        security.revoked.get(tunnel).is_none_or(|until| *until <= tokio::time::Instant::now())
            && security.tunnels.get(tunnel).is_none_or(|q| !q.revoked.load(Ordering::Acquire))
    }

    fn revoke(&self, tunnel: &str) {
        let now = tokio::time::Instant::now();
        let mut security = self.security.lock().unwrap();
        let known = security.validated.remove(tunnel).is_some_and(|(_, expiry)| expiry > 0)
            || security.tunnels.contains_key(tunnel);
        if let Some(quota) = security.tunnels.get(tunnel) {
            quota.revoked.store(true, Ordering::Release);
        }
        if known {
            security.revoked.retain(|_, until| *until > now);
            if security.revoked.len() >= SECURITY_ENTRIES && !security.revoked.contains_key(tunnel) {
                if let Some(oldest) = security.revoked.iter().min_by_key(|(_, until)| **until).map(|(id, _)| id.clone())
                {
                    security.revoked.remove(&oldest);
                }
                // Evicting a fence must never revive a cached positive result.
                security.validated.clear();
            }
            security.revoked.insert(tunnel.to_owned(), now + REVOCATION_TTL);
        }
        // In-flight reads of unseen tunnels also need fencing. Churn of ids
        // with no relay state must not invalidate every relay's fast path.
        if known || security.validating.contains(tunnel) {
            self.revocation_epoch.fetch_add(1, Ordering::Release);
        }
    }

    fn cached_validation(&self, tunnel: &str) -> Option<bool> {
        if self.state.get().is_none() {
            return Some(self.allow_private_peers);
        }
        let security = self.security.lock().unwrap();
        security
            .validated
            .get(tunnel)
            .and_then(|(at, expiry)| (at.elapsed() < VALIDATION_TTL).then(|| *expiry > self.now()))
    }

    /// Never waits in the shared UDP receive loop: authenticated misses get one
    /// bounded, deduplicated background lookup, and clients retransmit the packet.
    fn request_validation(self: &Arc<Self>, username: &str) -> bool {
        self.request_validation_inner(username, false)
    }

    fn request_validation_inner(self: &Arc<Self>, username: &str, refresh: bool) -> bool {
        if !self.credential_allowed(username) {
            return false;
        }
        let (_, tunnel) = credential_parts(username).unwrap();
        if !refresh && let Some(valid) = self.cached_validation(tunnel) {
            return valid;
        }
        let Ok(permit) = self.validation_slots.clone().try_acquire_owned() else { return false };
        {
            let mut security = self.security.lock().unwrap();
            if !security.validating.insert(tunnel.to_owned()) {
                return false;
            }
        }
        let pending = PendingValidation { shared: self.clone(), tunnel: tunnel.to_owned(), _permit: permit };
        let username = username.to_owned();
        tokio::spawn(async move {
            let _pending = pending;
            _pending.shared.validate(&username).await;
        });
        false
    }

    /// Reliable transports send a request once. Await a shared lookup or run
    /// it inline, bounded by this stream's deadline, without stalling UDP.
    async fn validate_stream(self: &Arc<Self>, username: &str) -> bool {
        tokio::time::timeout(STREAM_VALIDATION_TIMEOUT, async {
            loop {
                let changed = self.validation_changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if !self.credential_allowed(username) {
                    return false;
                }
                let (_, tunnel) = credential_parts(username).unwrap();
                if let Some(valid) = self.cached_validation(tunnel) {
                    return valid;
                }
                if self.security.lock().unwrap().validating.contains(tunnel) {
                    changed.await;
                    continue;
                }
                // A short burst on other streams may occupy all eight slots.
                // Wait within this stream's deadline rather than lose its only
                // copy of the request merely because a slot is briefly busy.
                let Ok(permit) = self.validation_slots.clone().acquire_owned().await else { return false };
                if !self.credential_allowed(username) {
                    return false;
                }
                if let Some(valid) = self.cached_validation(tunnel) {
                    return valid;
                }
                let pending = {
                    let mut security = self.security.lock().unwrap();
                    if security.validating.insert(tunnel.to_owned()) {
                        Some(PendingValidation { shared: self.clone(), tunnel: tunnel.to_owned(), _permit: permit })
                    } else {
                        None
                    }
                };
                if let Some(_pending) = pending {
                    return self.validate(username).await;
                }
                changed.await;
            }
        })
        .await
        .unwrap_or(false)
    }

    async fn validate(&self, username: &str) -> bool {
        tokio::time::timeout(VALIDATION_TIMEOUT, self.validate_inner(username)).await.unwrap_or(false)
    }

    async fn validate_inner(&self, username: &str) -> bool {
        // A PATCH can race a lookup. Retry with fresh lifecycle data without
        // rejecting that request or invalidating unrelated relay fast paths.
        for attempt in 0..3 {
            if let Some((_, tunnel)) = credential_parts(username) {
                self.security.lock().unwrap().validation_fenced.remove(tunnel);
            }
            let epoch = self.revocation_epoch.load(Ordering::Acquire);
            if !self.credential_allowed(username) {
                return false;
            }
            let (_, tunnel) = credential_parts(username).unwrap();
            let Some(weak) = self.state.get() else { return self.allow_private_peers };
            let Some(state) = weak.upgrade() else { return false };
            let found = if attempt == 0 {
                state.tunnel_for_turn(tunnel).await
            } else {
                // A fenced read must reach the database even if it managed to
                // populate AppState's cache before the invalidation arrived.
                state.db.lookup_tunnel(tunnel.to_owned()).await.map(Arc::new)
            };
            let valid_until = match found {
                Ok(found) => match found.as_ref() {
                    crate::db::TunnelLookup::Live(row) if !row.is_expired() => row.expires_at,
                    _ => 0,
                },
                Err(_) => return false,
            };
            let mut security = self.security.lock().unwrap();
            // Check under the same lock as revoke/forget_validation. Neither an
            // old positive result nor an old expiry may overwrite fresh state.
            if self.revocation_epoch.load(Ordering::Acquire) != epoch {
                return false;
            }
            if security.validation_fenced.remove(tunnel) {
                continue;
            }
            if valid_until == 0
                && (security.validated.get(tunnel).is_some_and(|(_, expiry)| *expiry > 0)
                    || security.tunnels.contains_key(tunnel))
            {
                drop(security);
                self.revoke(tunnel);
                return false;
            }
            if security.validated.len() >= SECURITY_ENTRIES {
                security.validated.retain(|_, (at, _)| at.elapsed() < VALIDATION_TTL);
                if security.validated.len() >= SECURITY_ENTRIES {
                    security.validated.clear();
                }
            }
            security.validated.insert(tunnel.to_owned(), (tokio::time::Instant::now(), valid_until));
            return valid_until > self.now();
        }
        false
    }

    fn reserve(self: &Arc<Self>, identity: &Identity) -> Result<QuotaPermit, turn::Error> {
        if !self.credential_allowed(&identity.username) {
            return Err(turn::Error::Other("invalid or revoked credential".into()));
        }
        let (_, tunnel) = credential_parts(&identity.username).unwrap();
        let ip = source_network(identity.source.ip());
        let mut security = self.security.lock().unwrap();
        if security.revoked.get(tunnel).is_some_and(|until| *until > tokio::time::Instant::now())
            || security.tunnels.get(tunnel).is_some_and(|q| q.revoked.load(Ordering::Acquire))
        {
            return Err(turn::Error::Other("invalid or revoked credential".into()));
        }
        if security.tunnels.get(tunnel).map_or(0, |q| q.count) >= MAX_ALLOCATIONS_PER_TUNNEL
            || security.ips.get(&ip).copied().unwrap_or(0) >= MAX_ALLOCATIONS_PER_IP
        {
            return Err(turn::Error::Other("allocation quota reached".into()));
        }
        let quota = security.tunnels.entry(tunnel.to_owned()).or_default();
        quota.count += 1;
        *security.ips.entry(ip).or_default() += 1;
        Ok(QuotaPermit { shared: self.clone(), tunnel: tunnel.to_owned(), ip })
    }

    fn reserve_stream(self: &Arc<Self>, ip: IpAddr) -> Option<StreamPermit> {
        let ip = source_network(ip);
        let mut ips = self.stream_ips.lock().unwrap();
        let count = ips.entry(ip).or_default();
        if *count >= MAX_STREAM_CONNS_PER_IP {
            return None;
        }
        *count += 1;
        Some(StreamPermit { shared: self.clone(), ip })
    }
}

/// Removes in-flight identities and releases admission on completion,
/// cancellation, timeout, early return, or unwinding.
struct PendingValidation {
    shared: Arc<Shared>,
    tunnel: String,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for PendingValidation {
    fn drop(&mut self) {
        let mut security = self.shared.security.lock().unwrap();
        security.validating.remove(&self.tunnel);
        security.validation_fenced.remove(&self.tunnel);
        drop(security);
        self.shared.validation_changed.notify_waiters();
    }
}

struct StreamPermit {
    shared: Arc<Shared>,
    ip: IpAddr,
}

impl Drop for StreamPermit {
    fn drop(&mut self) {
        let mut ips = self.shared.stream_ips.lock().unwrap();
        if let Some(count) = ips.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                ips.remove(&self.ip);
            }
        }
    }
}

struct QuotaPermit {
    shared: Arc<Shared>,
    tunnel: String,
    ip: IpAddr,
}

impl Drop for QuotaPermit {
    fn drop(&mut self) {
        let mut security = self.shared.security.lock().unwrap();
        if let Some(count) = security.tunnels.get_mut(&self.tunnel) {
            count.count -= 1;
            if count.count == 0 {
                security.tunnels.remove(&self.tunnel);
            }
        }
        if let Some(count) = security.ips.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                security.ips.remove(&self.ip);
            }
        }
    }
}

#[derive(Clone)]
struct Identity {
    username: String,
    source: SocketAddr,
}

async fn sweep_server(server: &RelayServer, shared: &Arc<Shared>) {
    shared.security.lock().unwrap().revoked.retain(|_, until| *until > tokio::time::Instant::now());
    let _ = tokio::time::timeout(SERVER_COMMAND_TIMEOUT, async {
        let _commands = server.commands.lock().await;
        if let Ok(Ok(infos)) = tokio::time::timeout(SERVER_COMMAND_TIMEOUT, server.get_allocations_info(None)).await {
            let users: HashSet<_> = infos.values().map(|a| a.username.clone()).collect();
            for user in users {
                let allowed = shared.credential_allowed(&user);
                let cached = credential_parts(&user).and_then(|(_, tunnel)| shared.cached_validation(tunnel));
                if !allowed || cached == Some(false) {
                    // Rediscover every time: a broadcast lag may acknowledge a
                    // dropped deletion. Never treat an Ok as permanent completion.
                    let _ =
                        tokio::time::timeout(SERVER_COMMAND_TIMEOUT, server.delete_allocations_by_username(user)).await;
                } else {
                    // Refresh positive entries halfway through their lifetime.
                    // With 90s TTL and 30s sweeps this leaves time for a lookup.
                    let refresh = credential_parts(&user).is_some_and(|(_, tunnel)| {
                        shared
                            .security
                            .lock()
                            .unwrap()
                            .validated
                            .get(tunnel)
                            .is_none_or(|(at, _)| at.elapsed() >= VALIDATION_TTL / 2)
                    });
                    if refresh {
                        shared.request_validation_inner(&user, true);
                    }
                }
            }
        }
    })
    .await;
}

// ---------------------------------------------------------------- request gate

/// Minimal strict STUN envelope/attribute reader. The server crate does not expose
/// its STUN decoder. Duplicate usernames/integrity and identities outside the
/// authenticated prefix are rejected rather than parsed differently.
#[derive(Debug)]
struct StunPacket<'a> {
    kind: u16,
    username: Option<&'a str>,
    reservation: bool,
    modern_auth: bool,
}

fn stun_packet(raw: &[u8]) -> Result<Option<StunPacket<'_>>, ()> {
    if raw.first().is_none_or(|b| b & 0xc0 != 0) {
        return Ok(None);
    }
    if raw.len() < 20 || raw[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return Err(());
    }
    let len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if !len.is_multiple_of(4) || raw.len() != 20 + len {
        return Err(());
    }
    let mut packet = StunPacket {
        kind: u16::from_be_bytes([raw[0], raw[1]]),
        username: None,
        reservation: false,
        modern_auth: false,
    };
    let mut integrity = false;
    let mut pos = 20;
    while pos < raw.len() {
        let head = raw.get(pos..pos + 4).ok_or(())?;
        let typ = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[2], head[3]]) as usize;
        pos += 4;
        let value = raw.get(pos..pos + len).ok_or(())?;
        packet.modern_auth |= matches!(typ, 0x001c | 0x001d | 0x8002);
        if typ == 0x0008 {
            if integrity || len != 20 {
                return Err(());
            }
            integrity = true;
        }
        if typ == 0x0006 {
            if integrity || packet.username.is_some() || len > 513 {
                return Err(());
            }
            packet.username = Some(std::str::from_utf8(value).map_err(|_| ())?);
        }
        // Optional even-port/reservation-token allocations can move a relay socket
        // between usernames, bypassing ownership quotas. ICE does not need them.
        packet.reservation |= matches!(typ, 0x0018 | 0x0022);
        pos += (len + 3) & !3;
        if pos > raw.len() {
            return Err(());
        }
    }
    Ok(Some(packet))
}

fn integrity(username: &str, shared: &Shared) -> MessageIntegrity {
    MessageIntegrity::new_long_term_integrity(
        username.to_owned(),
        shared.realm.clone(),
        crate::ice::credential(&shared.secret, username),
    )
}

fn verify_integrity(raw: &[u8], username: &str, shared: &Shared) -> bool {
    let mut message = Message { raw: raw.to_vec(), ..Default::default() };
    message.decode().is_ok() && integrity(username, shared).check(&mut message).is_ok()
}

fn quota_response(raw: &[u8], username: &str, shared: &Shared) -> Result<Vec<u8>, stun::Error> {
    use stun::error_code::CODE_ALLOC_QUOTA_REACHED;
    use stun::message::{CLASS_ERROR_RESPONSE, METHOD_ALLOCATE, MessageType};
    let mut original = Message { raw: raw.to_vec(), ..Default::default() };
    original.decode()?;
    let mut response = Message::default();
    response.build(&[
        Box::new(original.transaction_id),
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)),
        Box::new(CODE_ALLOC_QUOTA_REACHED),
    ])?;
    integrity(username, shared).add_to(&mut response)?;
    Ok(response.raw)
}

struct RequestBucket {
    tokens: f64,
    at: tokio::time::Instant,
}

impl RequestBucket {
    fn new(burst: f64) -> Self {
        Self { tokens: burst, at: tokio::time::Instant::now() }
    }

    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let now = tokio::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct ChallengeLimiter {
    global: RequestBucket,
    ips: HashMap<IpAddr, RequestBucket>,
    pruned: tokio::time::Instant,
}

impl ChallengeLimiter {
    fn new() -> Self {
        Self {
            global: RequestBucket::new(CHALLENGE_GLOBAL_BURST),
            ips: HashMap::new(),
            pruned: tokio::time::Instant::now(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        // turn 0.17.3 scans its hour-long nonce table for every challenge.
        // This bounds unauthenticated challenge growth/work; residual O(N)
        // pruning remains at the admitted rate (~720k nonces/hour). A holder
        // of valid credentials can also provoke authenticated stale-nonce
        // challenges; this guard does not replace upstream nonce-table fixes.
        let now = tokio::time::Instant::now();
        if now.duration_since(self.pruned) >= SWEEP_INTERVAL {
            self.ips.retain(|_, bucket| now.duration_since(bucket.at) < CHALLENGE_IDLE);
            self.pruned = now;
        }
        let ip = source_network(ip);
        if self.ips.len() >= CHALLENGE_IP_ENTRIES
            && !self.ips.contains_key(&ip)
            && let Some(oldest) = self.ips.iter().min_by_key(|(_, bucket)| bucket.at).map(|(ip, _)| *ip)
        {
            self.ips.remove(&oldest);
        }
        self.ips
            .entry(ip)
            .or_insert_with(|| RequestBucket::new(CHALLENGE_IP_BURST))
            .take(CHALLENGE_IP_RATE, CHALLENGE_IP_BURST)
            && self.global.take(CHALLENGE_GLOBAL_RATE, CHALLENGE_GLOBAL_BURST)
    }
}

/// Tracks actual relay ownership, including Refresh(0), expiry, and socket
/// teardown. Binding traffic cannot extend the deadline of an empty stream.
struct AllocationActivity {
    state: Mutex<(usize, tokio::time::Instant)>,
    changed: Notify,
}

impl AllocationActivity {
    fn new() -> Self {
        Self { state: Mutex::new((0, tokio::time::Instant::now())), changed: Notify::new() }
    }

    fn open(&self) {
        self.state.lock().unwrap().0 += 1;
        self.changed.notify_waiters();
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.0 -= 1;
        if state.0 == 0 {
            state.1 = tokio::time::Instant::now();
        }
        drop(state);
        self.changed.notify_waiters();
    }

    async fn empty_timeout(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let (live, empty_since) = *self.state.lock().unwrap();
            if live == 0 {
                tokio::select! {
                    _ = &mut changed => {},
                    _ = tokio::time::sleep_until(empty_since + STREAM_AUTH_DEADLINE) => {
                        let state = self.state.lock().unwrap();
                        if state.0 == 0 && state.1 == empty_since {
                            return;
                        }
                    },
                }
            } else {
                changed.await;
            }
        }
    }
}

struct GuardConn {
    inner: Arc<dyn Conn + Send + Sync>,
    shared: Arc<Shared>,
    context: Arc<Mutex<Option<Identity>>>,
    activity: Arc<AllocationActivity>,
    refused: Arc<AtomicBool>,
    server: OnceLock<Weak<RelayServer>>,
    stream: bool,
}

impl GuardConn {
    fn new(inner: Arc<dyn Conn + Send + Sync>, shared: Arc<Shared>) -> Self {
        let stream = inner.remote_addr().is_some();
        Self {
            inner,
            shared,
            stream,
            context: Arc::new(Mutex::new(None)),
            activity: Arc::new(AllocationActivity::new()),
            refused: Arc::new(AtomicBool::new(false)),
            server: OnceLock::new(),
        }
    }
}

#[async_trait]
impl Conn for GuardConn {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
        self.inner.connect(addr).await
    }
    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.recv_from(buf).await.map(|(n, _)| n)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        loop {
            let (n, source) = self.inner.recv_from(buf).await?;
            let packet = match stun_packet(&buf[..n]) {
                Ok(packet) => packet,
                Err(()) => continue,
            };
            let mut identity = None;
            if let Some(packet) = packet
                && packet.kind & 0x0110 == 0
            {
                // turn 0.17.3 advertises PASSWORD-ALGORITHMS=[MD5] in 401.
                // Only legacy MD5 long-term keys + MESSAGE-INTEGRITY are
                // supported here; clients insisting on RFC 8489 negotiation
                // (including SHA-256) are unsupported and must fall back.
                if packet.modern_auth {
                    continue;
                }
                // Binding never touches turn's nonce table. Other message
                // classes also bypass challenge admission entirely.
                if packet.kind == 0x0001 {
                    *self.context.lock().unwrap() = None;
                    return Ok((n, source));
                }
                if packet.kind == 0x0003 && packet.reservation {
                    continue;
                }
                if let Some(username) = packet.username {
                    // Invalid integrity goes to turn for its normal auth error;
                    // it must never consume a database slot or cache entry.
                    if verify_integrity(&buf[..n], username, &self.shared) {
                        let valid = if self.stream {
                            self.shared.validate_stream(username).await
                        } else {
                            self.shared.request_validation(username)
                        };
                        if !valid {
                            continue;
                        }
                        identity = Some(Identity { username: username.to_owned(), source });
                    } else if !self.shared.challenges.lock().unwrap().allow(source.ip()) {
                        // Invalid USERNAME/MI requests also generate nonce
                        // challenges; do not let a dummy username bypass limits.
                        continue;
                    }
                } else if !self.shared.challenges.lock().unwrap().allow(source.ip()) {
                    continue;
                }
            }
            // Each turn Server processes requests serially. Its RelayGen sees
            // precisely this request's identity, never another stream's context.
            *self.context.lock().unwrap() = identity;
            self.refused.store(false, Ordering::SeqCst);
            return Ok((n, source));
        }
    }
    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.inner.send(buf).await
    }
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        // RelayGen failures are mapped to 508 by turn. Replace quota failures
        // with an authenticated 486 using the original transaction id.
        if buf.starts_with(&[0x01, 0x13]) && self.refused.swap(false, Ordering::SeqCst) {
            let identity = self.context.lock().unwrap().clone();
            if let Some(identity) = identity {
                let response = quota_response(buf, &identity.username, &self.shared)
                    .map_err(|_| stream_err("building quota response"))?;
                self.inner.send_to(&response, target).await?;
            }
            return Ok(buf.len());
        }
        let allocated = matches!(stun_packet(buf), Ok(Some(StunPacket { kind: 0x0103, .. })));
        if allocated {
            let identity = self.context.lock().unwrap().clone();
            if let Some(identity) = identity
                && !self.shared.credential_allowed(&identity.username)
            {
                if let Some(server) = self.server.get().and_then(Weak::upgrade) {
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(SERVER_COMMAND_TIMEOUT, async {
                            let _commands = server.commands.lock().await;
                            let _ = tokio::time::timeout(
                                SERVER_COMMAND_TIMEOUT,
                                server.delete_allocations_by_username(identity.username),
                            )
                            .await;
                        })
                        .await;
                    });
                }
                return Ok(buf.len());
            }
        }
        self.inner.send_to(buf, target).await
    }
    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }
    async fn close(&self) -> webrtc_util::Result<()> {
        self.inner.close().await
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

// ---------------------------------------------------------------- peers

/// Peers a relay must never talk to (see the module docs).
fn denied_peer(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let private = v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || o[0] == 100 && (o[1] & 0xC0) == 64 // 100.64.0.0/10
                || o[0] == 0;
            (private && !allow_private) || v4.is_multicast() || v4.is_broadcast() || v4.is_unspecified() || o[0] >= 240
        }
        // Relays are IPv4 only, so an IPv6 peer is never legitimate.
        IpAddr::V6(_) => true,
    }
}

// ---------------------------------------------------------------- relays

struct RelayGen {
    shared: Arc<Shared>,
    context: Arc<Mutex<Option<Identity>>>,
    refused: Arc<AtomicBool>,
    activity: Arc<AllocationActivity>,
}

#[async_trait]
impl RelayAddressGenerator for RelayGen {
    fn validate(&self) -> Result<(), turn::Error> {
        Ok(())
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), turn::Error> {
        let s = &self.shared;
        let identity = self
            .context
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| turn::Error::Other("missing allocation identity".into()))?;
        let quota = s.reserve(&identity).inspect_err(|error| {
            if matches!(error, turn::Error::Other(message) if message == "allocation quota reached") {
                self.refused.store(true, Ordering::SeqCst);
            }
        })?;
        if !use_ipv4 {
            return Err(turn::Error::Other("only IPv4 relays are offered".into()));
        }
        if s.allocations.fetch_add(1, Ordering::SeqCst) >= MAX_ALLOCATIONS {
            s.allocations.fetch_sub(1, Ordering::SeqCst);
            return Err(turn::Error::Other("relay capacity reached".into()));
        }
        let mut socket = None;
        for attempt in 0..BIND_ATTEMPTS {
            let port = if attempt == 0 && (s.min_port..=s.max_port).contains(&requested_port) {
                requested_port
            } else {
                // u32: the span of a full 0..=65535 range does not fit in u16.
                let span = u32::from(s.max_port - s.min_port) + 1;
                (rand::random::<u32>() % span) as u16 + s.min_port
            };
            if let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
                socket = Some((sock, port));
                break;
            }
        }
        let Some((sock, port)) = socket else {
            s.allocations.fetch_sub(1, Ordering::SeqCst);
            return Err(turn::Error::Other("no free relay port".into()));
        };
        let (tx, rx) = mpsc::channel(HUB_QUEUE);
        s.hub.lock().unwrap_or_else(|e| e.into_inner()).insert(port, tx);
        s.metrics.allocations.fetch_add(1, Ordering::Relaxed);
        let (expiry, tunnel) = credential_parts(&identity.username).unwrap();
        self.activity.open();
        let conn = RelayConn {
            sock,
            port,
            inbox: tokio::sync::Mutex::new(rx),
            shared: s.clone(),
            bucket: Mutex::new(Bucket::new()),
            released: AtomicBool::new(false),
            quota: Mutex::new(Some(quota)),
            expiry,
            tunnel: tunnel.to_owned(),
            epoch: AtomicU64::new(u64::MAX),
            revoked: AtomicBool::new(false),
            activity: self.activity.clone(),
        };
        Ok((Arc::new(conn), SocketAddr::from((s.public_ip, port))))
    }
}

/// Token bucket over bytes; one second of burst.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    const RATE: f64 = MAX_BPS as f64 / 8.0;

    fn new() -> Self {
        Self { tokens: Self::RATE, at: Instant::now() }
    }

    fn take(&mut self, n: usize) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * Self::RATE).min(Self::RATE);
        self.at = now;
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }
}

struct RelayConn {
    sock: UdpSocket,
    port: u16,
    /// Packets from other relays on this server.
    inbox: tokio::sync::Mutex<mpsc::Receiver<HubPacket>>,
    shared: Arc<Shared>,
    bucket: Mutex<Bucket>,
    released: AtomicBool,
    quota: Mutex<Option<QuotaPermit>>,
    expiry: i64,
    tunnel: String,
    epoch: AtomicU64,
    revoked: AtomicBool,
    activity: Arc<AllocationActivity>,
}

impl RelayConn {
    fn allow(&self, n: usize) -> bool {
        if self.released.load(Ordering::SeqCst) {
            return false;
        }
        if self.expiry <= self.shared.now() || self.revoked.load(Ordering::Acquire) {
            return false;
        }
        let epoch = self.shared.revocation_epoch.load(Ordering::Acquire);
        if self.epoch.load(Ordering::Acquire) != epoch {
            if !self.shared.tunnel_allowed(&self.tunnel) {
                self.revoked.store(true, Ordering::Release);
                return false;
            }
            self.epoch.store(epoch, Ordering::Release);
        }
        self.bucket.lock().unwrap_or_else(|e| e.into_inner()).take(n)
    }

    fn is_own_relay(&self, addr: SocketAddr) -> bool {
        addr.ip() == IpAddr::V4(self.shared.public_ip)
            && (self.shared.min_port..=self.shared.max_port).contains(&addr.port())
    }

    fn release(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut hub = self.shared.hub.lock().unwrap_or_else(|e| e.into_inner());
        hub.remove(&self.port);
        drop(hub);
        self.quota.lock().unwrap().take();
        self.activity.close();
        self.shared.allocations.fetch_sub(1, Ordering::SeqCst);
        self.shared.metrics.allocations.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for RelayConn {
    fn drop(&mut self) {
        self.release();
    }
}

fn unsupported() -> webrtc_util::Error {
    webrtc_util::Error::Other("not supported on a TURN relay".into())
}

#[async_trait]
impl Conn for RelayConn {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Err(unsupported())
    }

    async fn recv(&self, _buf: &mut [u8]) -> webrtc_util::Result<usize> {
        Err(unsupported())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let mut inbox = self.inbox.lock().await;
        loop {
            tokio::select! {
                r = self.sock.recv_from(buf) => {
                    let (n, src) = r?;
                    let own = src.ip() == IpAddr::V4(self.shared.public_ip);
                    if own || denied_peer(src.ip(), self.shared.allow_private_peers) || !self.allow(n) {
                        continue;
                    }
                    return Ok((n, src));
                }
                m = inbox.recv() => {
                    let Some((data, src)) = m else { return Err(webrtc_util::Error::Other("relay closed".into())) };
                    if !self.allow(data.len()) {
                        continue;
                    }
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, src));
                }
            }
        }
    }

    async fn send(&self, _buf: &[u8]) -> webrtc_util::Result<usize> {
        Err(unsupported())
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
        // Dropped packets still report success: UDP gives no delivery promise,
        // and an error would tear down the client's allocation.
        if !self.allow(buf.len()) {
            return Ok(buf.len());
        }
        if self.is_own_relay(target) {
            let inbox = self.shared.hub.lock().unwrap_or_else(|e| e.into_inner()).get(&target.port()).cloned();
            if let Some(inbox) = inbox {
                let _ = inbox.try_send((buf.to_vec(), SocketAddr::from((self.shared.public_ip, self.port))));
            }
            return Ok(buf.len());
        }
        if target.ip() == IpAddr::V4(self.shared.public_ip) || denied_peer(target.ip(), self.shared.allow_private_peers)
        {
            return Ok(buf.len());
        }
        Ok(self.sock.send_to(buf, target).await?)
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.sock.local_addr()?)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.release();
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

// ---------------------------------------------------------------- streams

/// TURN over a byte stream (RFC 5766 §2.1): STUN messages and ChannelData
/// (padded to 4 bytes over streams) framed back to back.
struct StreamConn<S> {
    reader: tokio::sync::Mutex<Option<ReadHalf<S>>>,
    writer: tokio::sync::Mutex<Option<WriteHalf<S>>>,
    local: SocketAddr,
    peer: SocketAddr,
    closed: CancellationToken,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> StreamConn<S> {
    fn new(stream: S, local: SocketAddr, peer: SocketAddr) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new(Some(r)),
            writer: tokio::sync::Mutex::new(Some(w)),
            local,
            peer,
            closed: CancellationToken::new(),
        }
    }
}

/// Bytes on the wire for a frame starting with `head`: (payload length to
/// deliver, padding to skip). `None` if it is neither STUN nor ChannelData.
fn frame_len(head: [u8; 4]) -> Option<(usize, usize)> {
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    match head[0] >> 6 {
        // STUN: 20-byte header; the length is already a multiple of 4.
        0b00 => Some((20 + len, 0)),
        // ChannelData: 4-byte header, padded to 4 over streams.
        0b01 => Some((4 + len, (4 - len % 4) % 4)),
        _ => None,
    }
}

fn stream_err(msg: &str) -> webrtc_util::Error {
    webrtc_util::Error::Other(msg.into())
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> Conn for StreamConn<S> {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        Err(unsupported())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        self.recv_from(buf).await.map(|(n, _)| n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        let reader = reader.as_mut().ok_or_else(|| stream_err("closed"))?;
        loop {
            let read = async {
                let mut head = [0u8; 4];
                reader.read_exact(&mut head).await?;
                let (total, pad) = frame_len(head).ok_or_else(|| stream_err("not a TURN frame"))?;
                if total > MAX_FRAME {
                    return Err(stream_err("frame too large"));
                }
                let mut frame = vec![0u8; total + pad];
                frame[..4].copy_from_slice(&head);
                reader.read_exact(&mut frame[4..]).await?;
                frame.truncate(total);
                Ok::<_, webrtc_util::Error>(frame)
            };
            let result = tokio::select! {
                _ = self.closed.cancelled() => return Err(stream_err("closed")),
                result = tokio::time::timeout(STREAM_IDLE, read) => result,
            };
            let frame = match result {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => {
                    self.closed.cancel();
                    return Err(e);
                }
                Err(_) => {
                    self.closed.cancel();
                    return Err(stream_err("idle"));
                }
            };
            // The server reads into an MTU-sized buffer; bigger frames are skipped.
            if frame.len() > buf.len() {
                continue;
            }
            buf[..frame.len()].copy_from_slice(&frame);
            return Ok((frame.len(), self.peer));
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.send_to(buf, self.peer).await
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> webrtc_util::Result<usize> {
        let pad = if buf.first().is_some_and(|b| b >> 6 == 0b01) { (4 - buf.len() % 4) % 4 } else { 0 };
        let mut writer = self.writer.lock().await;
        let writer = writer.as_mut().ok_or_else(|| stream_err("closed"))?;
        let write = async {
            writer.write_all(buf).await?;
            if pad > 0 {
                writer.write_all(&[0u8; 3][..pad]).await?;
            }
            writer.flush().await
        };
        let result = tokio::select! {
            _ = self.closed.cancelled() => return Err(stream_err("closed")),
            result = tokio::time::timeout(STREAM_WRITE_TIMEOUT, write) => result,
        };
        match result {
            Ok(Ok(())) => Ok(buf.len()),
            Ok(Err(e)) => {
                self.closed.cancel();
                Err(e.into())
            }
            Err(_) => {
                self.closed.cancel();
                Err(stream_err("write timed out"))
            }
        }
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.closed.cancel();
        let _ = tokio::time::timeout(STREAM_CLOSE_TIMEOUT, async {
            // Take both halves so timeout drops the TLS stream even when
            // poll_shutdown waits forever for an unresponsive peer.
            self.reader.lock().await.take();
            if let Some(mut writer) = self.writer.lock().await.take() {
                let _ = writer.shutdown().await;
            }
        })
        .await;
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turn::client::{Client, ClientConfig};

    const SECRET: &str = "test-secret";
    /// Advertised relay address; any 127/8 address reaches the 0.0.0.0-bound relays.
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

    fn creds(valid_for: i64) -> (String, String) {
        let user = format!("{}:abcdefghij:test", crate::tokens::now() + valid_for);
        let pass = crate::ice::credential(SECRET, &user);
        (user, pass)
    }

    async fn udp_server(ports: (u16, u16)) -> (Relay, SocketAddr) {
        let relay = Relay::for_test(PUBLIC, ports.0, ports.1, SECRET);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        relay.serve_udp(udp).await.unwrap();
        (relay, addr)
    }

    async fn client(server: SocketAddr, conn: Arc<dyn Conn + Send + Sync>, (user, pass): (String, String)) -> Client {
        let c = Client::new(ClientConfig {
            stun_serv_addr: server.to_string(),
            turn_serv_addr: server.to_string(),
            username: user,
            password: pass,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn,
            vnet: None,
        })
        .await
        .unwrap();
        c.listen().await.unwrap();
        c
    }

    async fn udp_client(server: SocketAddr, creds: (String, String)) -> Client {
        client(server, Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), creds).await
    }

    /// Relay a datagram to a plain UDP peer and back.
    async fn round_trip(c: &Client) {
        let relay = c.allocate().await.expect("allocate");
        let relay_addr = relay.local_addr().unwrap();
        assert_eq!(relay_addr.ip(), IpAddr::V4(PUBLIC));
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay.send_to(b"ping", peer.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from.port(), relay_addr.port());
        peer.send_to(b"pong", SocketAddr::from(([127, 0, 0, 1], relay_addr.port()))).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"pong");
        relay.close().await.unwrap();
    }

    /// Models rustls waiting forever to send close_notify to a peer that
    /// never drains its socket. The drop flag verifies transport ownership.
    struct PendingShutdown {
        inner: tokio::io::DuplexStream,
        started: CancellationToken,
        dropped: Arc<AtomicBool>,
    }

    impl AsyncRead for PendingShutdown {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PendingShutdown {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.started.cancel();
            std::task::Poll::Pending
        }
    }

    impl Drop for PendingShutdown {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_shutdown_does_not_block_revocation_and_drops_transport() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
        let (_peer, inner) = tokio::io::duplex(1);
        let started = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let stream = PendingShutdown { inner, started: started.clone(), dropped: dropped.clone() };
        let task = tokio::spawn({
            let relay = relay.clone();
            async move {
                relay.serve_stream(stream, "127.0.0.1:3478".parse().unwrap(), "127.0.0.1:1".parse().unwrap()).await
            }
        });
        started.cancelled().await;
        assert!(!dropped.load(Ordering::Acquire));
        tokio::time::timeout(Duration::from_millis(250), relay.revoke_tunnel("abcdefghij"))
            .await
            .expect("shutdown cannot hold a global command lock");
        tokio::time::timeout(STREAM_CLOSE_TIMEOUT + Duration::from_millis(100), task).await.unwrap().unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
        assert!(relay.shared.stream_ips.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_close_interrupts_pending_io_and_bounds_shutdown() {
        let (_peer, inner) = tokio::io::duplex(1);
        let started = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(StreamConn::new(
            PendingShutdown { inner, started: started.clone(), dropped: dropped.clone() },
            "127.0.0.1:3478".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        ));
        let read = tokio::spawn({
            let conn = conn.clone();
            async move { conn.recv(&mut [0; 64]).await }
        });
        let write = tokio::spawn({
            let conn = conn.clone();
            async move { conn.send(&[0; 64]).await }
        });
        tokio::task::yield_now().await;
        assert!(!read.is_finished());
        assert!(!write.is_finished());
        tokio::time::timeout(STREAM_CLOSE_TIMEOUT + Duration::from_millis(100), conn.close()).await.unwrap().unwrap();
        assert!(started.is_cancelled());
        assert!(dropped.load(Ordering::Acquire));
        assert!(read.await.unwrap().is_err());
        assert!(write.await.unwrap().is_err());
        assert!(conn.reader.lock().await.is_none());
        assert!(conn.writer.lock().await.is_none());
    }

    #[tokio::test]
    async fn forget_validation_drops_cached_expiry() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
        state.install_turn(relay.clone());
        assert!(relay.shared.validate(&creds(600).0).await);
        assert_eq!(relay.shared.cached_validation("abcdefghij"), Some(true));
        let expiry = crate::tokens::now() + 7200;
        state
            .db
            .update_tunnel(
                "abcdefghij".into(),
                crate::db::TunnelPatch { expires_at: Some(expiry), ..Default::default() },
            )
            .await
            .unwrap();
        let epoch = relay.shared.revocation_epoch.load(Ordering::Acquire);
        state.invalidate_tunnel("abcdefghij");
        assert_eq!(relay.shared.revocation_epoch.load(Ordering::Acquire), epoch);
        assert_eq!(relay.shared.cached_validation("abcdefghij"), None);
        assert!(relay.shared.validate(&creds(600).0).await);
        assert_eq!(relay.shared.security.lock().unwrap().validated["abcdefghij"].1, expiry);
    }

    /// Hold the database across a deterministic cancellation/invalidation.
    async fn block_database(
        state: &Arc<crate::state::AppState>,
    ) -> (tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let state = state.clone();
        let task = tokio::spawn(async move {
            state
                .db
                .call(move |_| {
                    let _ = entered_tx.send(());
                    let _ = release_rx.blocking_recv();
                    Ok(())
                })
                .await
                .unwrap();
        });
        entered_rx.await.unwrap();
        (release_tx, task)
    }

    #[tokio::test]
    async fn forget_validation_fences_in_flight_reads() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
        state.install_turn(relay.clone());
        let (release, blocker) = block_database(&state).await;
        let user = creds(600).0;
        let mut validation = Box::pin(relay.shared.validate_stream(&user));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(validation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let _ = release.send(());
        blocker.await.unwrap();
        // Leave the validation future unpolled, then change the expiry and
        // fence any old result before it can be used.
        let expiry = crate::tokens::now() + 7200;
        state
            .db
            .update_tunnel(
                "abcdefghij".into(),
                crate::db::TunnelPatch { expires_at: Some(expiry), ..Default::default() },
            )
            .await
            .unwrap();
        state.invalidate_tunnel("abcdefghij");
        assert!(validation.await);
        assert_eq!(relay.shared.security.lock().unwrap().validated["abcdefghij"].1, expiry);
        assert!(relay.shared.security.lock().unwrap().validation_fenced.is_empty());
    }

    #[tokio::test]
    async fn unrelated_tunnel_invalidation_preserves_in_flight_validation_and_epoch() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
        state.install_turn(relay.clone());
        let (release, blocker) = block_database(&state).await;
        let user = creds(600).0;
        let mut validation = Box::pin(relay.shared.validate_stream(&user));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(validation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let epoch = relay.shared.revocation_epoch.load(Ordering::Acquire);
        // Creation and PATCH both invalidate the affected tunnel id.
        state.invalidate_tunnel("unrelated1");
        state.invalidate_tunnel("unrelated1");
        assert_eq!(relay.shared.revocation_epoch.load(Ordering::Acquire), epoch);
        assert!(relay.shared.security.lock().unwrap().validation_fenced.is_empty());
        let _ = release.send(());
        blocker.await.unwrap();
        assert!(validation.await);
    }

    #[tokio::test]
    async fn cancelled_delete_still_completes_teardown() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
        state.install_turn(relay.clone());
        assert!(relay.shared.validate(&creds(600).0).await);
        let bytes = state.metrics.tunnel_bytes("abcdefghij");
        let (transport, _peer) = tokio::io::duplex(64);
        let session = tunnel_protocol::mux::Session::new_server(transport);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        state.registry.insert(Arc::new(crate::registry::LiveTunnel {
            conn_id: 1,
            tunnel_id: "abcdefghij".into(),
            control: session.control(),
            ports: std::sync::RwLock::new(Default::default()),
            ctrl_tx,
            cancel: CancellationToken::new(),
            connected_at: crate::tokens::now(),
            streams: AtomicUsize::new(0),
            pool: crate::pool::OriginPool::default(),
            token_hash: String::new(),
        }));
        let gate_epoch = state.registry.gate_epoch("abcdefghij");
        let (release, blocker) = block_database(&state).await;
        let mut delete = Box::pin(state.delete_tunnel("abcdefghij", tunnel_protocol::CloseReason::Deleted));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(delete.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(delete);
        let _ = release.send(());
        blocker.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !Arc::ptr_eq(&bytes, &state.metrics.tunnel_bytes("abcdefghij")) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached deletion must finish its in-memory teardown");
        assert!(state.registry.get("abcdefghij").is_none());
        assert!(gate_epoch.is_cancelled());
        assert!(!relay.shared.credential_allowed(&creds(600).0));
        assert!(matches!(
            ctrl_rx.try_recv(),
            Ok(tunnel_protocol::ServerMsg::Close { reason: tunnel_protocol::CloseReason::Deleted })
        ));
        assert!(matches!(state.tunnel("abcdefghij").await.unwrap().as_ref(), crate::db::TunnelLookup::Tombstoned));
    }

    #[tokio::test]
    async fn state_delete_fences_without_waiting_for_relay_commands() {
        let (state, _dir) = state_with_tunnel().await;
        let (relay, _) = udp_server((53200, 53299)).await;
        let relay = Arc::new(relay);
        state.install_turn(relay.clone());
        assert!(relay.shared.validate(&creds(600).0).await);
        let epoch = relay.shared.revocation_epoch.load(Ordering::Acquire);
        let (transport, _peer) = tokio::io::duplex(64);
        let session = tunnel_protocol::mux::Session::new_server(transport);
        let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
        state.registry.insert(Arc::new(crate::registry::LiveTunnel {
            conn_id: 1,
            tunnel_id: "abcdefghij".into(),
            control: session.control(),
            ports: std::sync::RwLock::new(Default::default()),
            ctrl_tx,
            cancel: CancellationToken::new(),
            connected_at: crate::tokens::now(),
            streams: AtomicUsize::new(0),
            pool: crate::pool::OriginPool::default(),
            token_hash: String::new(),
        }));
        let server = relay.udp.lock().unwrap().clone().unwrap();
        let commands = server.commands.lock().await;
        tokio::time::timeout(
            Duration::from_millis(250),
            state.delete_tunnel("abcdefghij", tunnel_protocol::CloseReason::Deleted),
        )
        .await
        .expect("delete must not wait for relay commands")
        .unwrap();
        assert!(!relay.shared.credential_allowed(&creds(600).0));
        assert!(relay.shared.revocation_epoch.load(Ordering::Acquire) > epoch);
        assert!(state.registry.get("abcdefghij").is_none());
        assert!(matches!(
            ctrl_rx.try_recv(),
            Ok(tunnel_protocol::ServerMsg::Close { reason: tunnel_protocol::CloseReason::Deleted })
        ));
        // Both maintenance paths must bound even acquisition of this lock.
        tokio::time::pause();
        tokio::time::timeout(SERVER_COMMAND_TIMEOUT + Duration::from_millis(100), relay.revoke_tunnel("abcdefghij"))
            .await
            .unwrap();
        tokio::time::timeout(SERVER_COMMAND_TIMEOUT + Duration::from_millis(100), sweep_server(&server, &relay.shared))
            .await
            .unwrap();
        drop(commands);
        drop(state);
    }

    #[tokio::test]
    async fn stream_allocate_succeeds_on_first_send_and_refresh_uses_cache_after_31s() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 53300, 53399, SECRET));
        state.install_turn(relay.clone());
        let (stream, peer) = tokio::io::duplex(4096);
        let local = "127.0.0.1:3478".parse().unwrap();
        let remote = "127.0.0.1:1".parse().unwrap();
        let task = tokio::spawn({
            let relay = relay.clone();
            async move { relay.serve_stream(stream, local, remote).await }
        });
        let conn = StreamConn::new(peer, remote, local);
        let mut buf = [0; 2048];
        conn.send(&packet(0x0003, &[(0x0019, &[17, 0, 0, 0])], None)).await.unwrap();
        let n = conn.recv(&mut buf).await.unwrap();
        assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0113);
        // RestAuth inherits turn 0.17.3's MD5-only advertisement in 401.
        assert_eq!(attribute(&buf[..n], 0x8002).unwrap(), &[0, 1, 0, 0]);
        let nonce = attribute(&buf[..n], 0x0015).unwrap().to_vec();
        let (user, password) = creds(600);
        let key = generate_auth_key(&user, "turn.test", &password);
        assert!(relay.shared.security.lock().unwrap().validated.is_empty());
        let allocate = packet(
            0x0003,
            &[(0x0006, user.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce), (0x0019, &[17, 0, 0, 0])],
            Some(&key),
        );
        conn.send(&allocate).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), conn.recv(&mut buf))
            .await
            .expect("reliable transports do not retransmit Allocate")
            .unwrap();
        assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0103);
        let cached_at = relay.shared.security.lock().unwrap().validated["abcdefghij"].0;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(relay.shared.cached_validation("abcdefghij"), Some(true));
        let refresh =
            packet(0x0004, &[(0x0006, user.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce)], Some(&key));
        conn.send(&refresh).await.unwrap();
        let n = conn.recv(&mut buf).await.unwrap();
        assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0104);
        assert_eq!(relay.shared.security.lock().unwrap().validated["abcdefghij"].0, cached_at);
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        conn.close().await.unwrap();
        task.await.unwrap();
        drop(state);
    }

    #[tokio::test]
    async fn stream_validation_waits_for_a_busy_slot_without_losing_request() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
        state.install_turn(relay.clone());
        let slots = relay.shared.validation_slots.clone().acquire_many_owned(VALIDATION_LOOKUPS as u32).await.unwrap();
        let validation = tokio::spawn({
            let shared = relay.shared.clone();
            async move { shared.validate_stream(&creds(600).0).await }
        });
        tokio::task::yield_now().await;
        assert!(!validation.is_finished());
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        drop(slots);
        assert!(validation.await.unwrap());
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
        drop(state);
    }

    #[tokio::test]
    async fn sweep_refreshes_validation_before_expiry() {
        let (state, _dir) = state_with_tunnel().await;
        let (relay, addr) = udp_server((53400, 53499)).await;
        let relay = Arc::new(relay);
        state.install_turn(relay.clone());
        let client = udp_client(addr, creds(600)).await;
        let _allocation = client.allocate().await.unwrap();
        let old = tokio::time::Instant::now() - Duration::from_secs(60);
        relay.shared.security.lock().unwrap().validated.get_mut("abcdefghij").unwrap().0 = old;
        assert_eq!(relay.shared.cached_validation("abcdefghij"), Some(true));
        let server = relay.udp.lock().unwrap().clone().unwrap();
        sweep_server(&server, &relay.shared).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while relay.shared.security.lock().unwrap().validated["abcdefghij"].0 == old {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("sweep must refresh a still-valid cache entry");
        client.close().await.unwrap();
        drop(state);
    }

    #[tokio::test]
    async fn validation_timeout_and_cancellation_release_all_slots_and_identities() {
        // A drop guard unblocks the SQLite worker even if an assertion fails.
        struct Release(Option<std::sync::mpsc::Sender<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
        state.install_turn(relay.clone());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release = Release(Some(release_tx));
        let db = state.db.clone();
        let blocked = tokio::spawn(async move {
            db.call(move |_| {
                let _ = ready_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
            .await
            .unwrap();
        });
        ready_rx.await.unwrap();
        tokio::time::pause();
        for i in 0..VALIDATION_LOOKUPS {
            assert!(!relay.shared.request_validation(&tunnel_creds(&format!("blocked-{i}")).0));
        }
        tokio::task::yield_now().await;
        assert_eq!(relay.shared.validation_slots.available_permits(), 0);
        tokio::time::advance(VALIDATION_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
        let stream = tokio::spawn({
            let shared = relay.shared.clone();
            async move { shared.validate_stream(&creds(600).0).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS - 1);
        tokio::time::advance(STREAM_VALIDATION_TIMEOUT + Duration::from_millis(1)).await;
        assert!(!stream.await.unwrap());
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
        let cancelled = tokio::spawn({
            let shared = relay.shared.clone();
            async move { shared.validate_stream(&creds(600).0).await }
        });
        tokio::task::yield_now().await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
        drop(release);
        blocked.await.unwrap();
        drop(state);
    }

    #[tokio::test]
    async fn binding_and_non_requests_bypass_exhausted_challenge_limits() {
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let guard = GuardConn::new(socket, relay.shared.clone());
        relay.shared.challenges.lock().unwrap().global.tokens = 0.0;
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay.shared.challenges.lock().unwrap().ips.insert(source.local_addr().unwrap().ip(), RequestBucket::new(0.0));
        let mut buf = [0; 2048];
        for kind in [0x0001, 0x0013, 0x0103, 0x0113] {
            for _ in 0..CHALLENGE_IP_BURST as usize + 1 {
                let raw = packet(kind, &[], None);
                source.send_to(&raw, addr).await.unwrap();
                let (n, _) =
                    tokio::time::timeout(Duration::from_millis(250), guard.recv_from(&mut buf)).await.unwrap().unwrap();
                assert_eq!(&buf[..n], raw);
            }
        }
        assert_eq!(relay.shared.challenges.lock().unwrap().global.tokens, 0.0);
    }

    #[tokio::test]
    async fn modern_auth_requests_never_reach_turn() {
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let guard = GuardConn::new(socket, relay.shared.clone());
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (user, password) = creds(600);
        let key = generate_auth_key(&user, "turn.test", &password);
        let mut buf = [0; 2048];
        for typ in [0x001c, 0x001d, 0x8002] {
            for kind in [0x0003, 0x0004, 0x0008, 0x0009] {
                for legacy in [None, Some(key.as_slice())] {
                    let raw = packet(kind, &[(0x0006, user.as_bytes()), (typ, &[0; 32])], legacy);
                    source.send_to(&raw, addr).await.unwrap();
                    source.send_to(&[0x40, 0, 0, 0], addr).await.unwrap();
                    let (n, _) = tokio::time::timeout(Duration::from_millis(250), guard.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(&buf[..n], &[0x40, 0, 0, 0]);
                    assert!(guard.context.lock().unwrap().is_none());
                }
            }
        }
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        assert!(relay.shared.challenges.lock().unwrap().ips.is_empty());
    }

    #[tokio::test]
    async fn stun_binding_and_udp_relay() {
        let (_relay, server) = udp_server((51000, 51099)).await;
        let c = udp_client(server, creds(600)).await;
        let mapped = c.send_binding_request().await.unwrap();
        assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        round_trip(&c).await;
        c.close().await.unwrap();
    }

    async fn wait_allocations(relay: &Relay, want: usize) {
        for _ in 0..50 {
            if relay.shared.allocations.load(Ordering::SeqCst) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("allocations: want {want}, have {}", relay.shared.allocations.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn tcp_relay_and_allocations_end_with_the_connection() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 51100, 51199, SECRET));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        tokio::spawn(relay.clone().accept_tcp(listener));
        let tcp_client = |server| async move {
            let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
            let local = tcp.local_addr().unwrap();
            let conn = Arc::new(StreamConn::new(tcp, local, server));
            (client(server, conn.clone(), creds(600)).await, conn)
        };

        // Relaying works, and closing the relay (refresh with lifetime 0) frees it.
        let (c, _conn) = tcp_client(server).await;
        round_trip(&c).await;
        wait_allocations(&relay, 0).await;

        // An allocation is freed when its TCP connection goes away.
        let (c2, conn2) = tcp_client(server).await;
        let _held = c2.allocate().await.expect("allocate");
        wait_allocations(&relay, 1).await;
        conn2.close().await.unwrap();
        wait_allocations(&relay, 0).await;
    }

    #[tokio::test]
    async fn relay_to_relay_is_delivered_in_process() {
        let (_relay, server) = udp_server((51200, 51299)).await;
        let a = udp_client(server, creds(600)).await;
        let b = udp_client(server, creds(600)).await;
        let ra = a.allocate().await.unwrap();
        let rb = b.allocate().await.unwrap();
        let (aa, ba) = (ra.local_addr().unwrap(), rb.local_addr().unwrap());
        // Each side permits the other, as ICE does.
        rb.send_to(b"hello-a", aa).await.unwrap();
        ra.send_to(b"hello-b", ba).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), rb.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..n], from), (&b"hello-b"[..], aa));
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), ra.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!((&buf[..n], from), (&b"hello-a"[..], ba));
    }

    #[tokio::test]
    async fn bad_and_expired_credentials_are_refused() {
        let (_relay, server) = udp_server((51300, 51399)).await;
        let (user, _) = creds(600);
        let wrong = udp_client(server, (user, "nope".into())).await;
        assert!(wrong.allocate().await.is_err());
        let expired = udp_client(server, creds(-10)).await;
        allocation_refused(&expired).await;
        let garbage = udp_client(server, ("someone".into(), "x".into())).await;
        allocation_refused(&garbage).await;
    }

    async fn allocation_refused(c: &Client) {
        assert!(!matches!(tokio::time::timeout(Duration::from_millis(250), c.allocate()).await, Ok(Ok(_))));
    }

    fn tunnel_creds(tunnel: &str) -> (String, String) {
        let username = format!("{}:{tunnel}:test", crate::tokens::now() + 600);
        let password = crate::ice::credential(SECRET, &username);
        (username, password)
    }

    fn attribute(raw: &[u8], typ: u16) -> Option<&[u8]> {
        let mut pos = 20;
        while pos + 4 <= raw.len() {
            let kind = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            let len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
            pos += 4;
            if kind == typ {
                return raw.get(pos..pos + len);
            }
            pos += (len + 3) & !3;
        }
        None
    }

    fn packet(kind: u16, attrs: &[(u16, &[u8])], key: Option<&[u8]>) -> Vec<u8> {
        use hmac::{Hmac, KeyInit, Mac};
        let mut raw = vec![0; 20];
        raw[..2].copy_from_slice(&kind.to_be_bytes());
        raw[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        raw[8..20].copy_from_slice(&rand::random::<[u8; 12]>());
        for (typ, value) in attrs {
            raw.extend_from_slice(&typ.to_be_bytes());
            raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
            raw.extend_from_slice(value);
            while !raw.len().is_multiple_of(4) {
                raw.push(0);
            }
        }
        let size = raw.len() - 20 + if key.is_some() { 24 } else { 0 };
        raw[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        if let Some(key) = key {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
            mac.update(&raw);
            raw.extend_from_slice(&[0, 8, 0, 20]);
            raw.extend_from_slice(&mac.finalize().into_bytes());
        }
        raw
    }

    async fn raw_allocate(socket: &UdpSocket, server: SocketAddr, username: &str) -> (Vec<u8>, Vec<u8>) {
        let transport = [17, 0, 0, 0];
        socket.send_to(&packet(0x0003, &[(0x0019, &transport)], None), server).await.unwrap();
        let mut buf = [0; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        let nonce = attribute(&buf[..n], 0x0015).unwrap().to_vec();
        let password = crate::ice::credential(SECRET, username);
        let key = generate_auth_key(username, "turn.test", &password);
        let allocate = packet(
            0x0003,
            &[(0x0006, username.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce), (0x0019, &transport)],
            Some(&key),
        );
        socket.send_to(&allocate, server).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0103);
        (nonce, key)
    }

    #[tokio::test]
    async fn expired_cached_key_cannot_refresh_and_sweep_closes_allocation() {
        let (relay, server) = udp_server((51400, 51499)).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (user, _) = creds(60);
        let (nonce, key) = raw_allocate(&socket, server, &user).await;
        let refresh =
            |kind| packet(kind, &[(0x0006, user.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce)], Some(&key));
        let mut buf = [0; 2048];
        // Prove the signed Refresh works before expiry, with the cached key.
        socket.send_to(&refresh(0x0004), server).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0104);
        // Move this relay's Unix clock to the credential's expiry.
        let expiry = credential_parts(&user).unwrap().0;
        relay.shared.clock_skew.store(expiry - crate::tokens::now(), Ordering::SeqCst);
        assert!(relay.shared.now() >= expiry);
        // All four authenticated methods are blocked even before the sweep.
        // The UDP path handles datagrams in order, so the Binding answer
        // arriving first proves the request before it got no reply.
        for kind in [0x0003, 0x0004, 0x0008, 0x0009] {
            socket.send_to(&refresh(kind), server).await.unwrap();
            let binding = packet(0x0001, &[], None);
            socket.send_to(&binding, server).await.unwrap();
            let (n, _) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0101, "reply to expired {kind:#06x}");
            assert_eq!(buf[8..20], binding[8..20]);
        }
        let handle = relay.udp.lock().unwrap().clone().unwrap();
        assert_eq!(handle.get_allocations_info(None).await.unwrap().len(), 1);
        // Exercise the scheduled sweep with virtual time after wall-clock expiry.
        tokio::time::pause();
        tokio::time::advance(SWEEP_INTERVAL).await;
        wait_allocations(&relay, 0).await;
        assert!(handle.get_allocations_info(None).await.unwrap().is_empty());
        assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
    }

    #[tokio::test]
    async fn per_tunnel_quota_and_release() {
        let (relay, server) = udp_server((51500, 51799)).await;
        let mut permits = Vec::new();
        for i in 1..MAX_ALLOCATIONS_PER_TUNNEL {
            permits.push(
                relay
                    .shared
                    .reserve(&Identity {
                        username: tunnel_creds("quota-tunnel").0,
                        source: SocketAddr::from(([192, 0, 2, i as u8], 1)),
                    })
                    .unwrap(),
            );
        }
        let c = udp_client(server, tunnel_creds("quota-tunnel")).await;
        let held = c.allocate().await.unwrap();
        let extra = udp_client(server, tunnel_creds("quota-tunnel")).await;
        let error = extra.allocate().await.err().expect("quota refusal");
        assert!(error.to_string().contains("486"), "quota response must be visible: {error}");
        assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 1);
        held.close().await.unwrap();
        wait_allocations(&relay, 0).await;
        let replacement = extra.allocate().await.unwrap();
        replacement.close().await.unwrap();
        wait_allocations(&relay, 0).await;
        drop(permits);
        let security = relay.shared.security.lock().unwrap();
        assert!(security.tunnels.is_empty() && security.ips.is_empty());
    }

    #[tokio::test]
    async fn relay_bind_failure_close_and_drop_release_quota() {
        let occupied = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let relay = Relay::for_test(PUBLIC, port, port, SECRET);
        let generator = RelayGen {
            shared: relay.shared.clone(),
            refused: Arc::new(AtomicBool::new(false)),
            activity: Arc::new(AllocationActivity::new()),
            context: Arc::new(Mutex::new(Some(Identity {
                username: creds(600).0,
                source: "127.0.0.1:1".parse().unwrap(),
            }))),
        };
        assert!(generator.allocate_conn(true, 0).await.is_err());
        assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
        assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 0);
        drop(occupied);
        let (conn, _) = generator.allocate_conn(true, 0).await.unwrap();
        drop(conn);
        assert!(relay.shared.security.lock().unwrap().ips.is_empty());
        let (conn, _) = generator.allocate_conn(true, 0).await.unwrap();
        conn.close().await.unwrap();
        conn.close().await.unwrap();
        drop(conn);
        assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
        assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(relay.shared.metrics.allocations.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn per_source_ip_quota_across_tunnels_and_release() {
        let (relay, server) = udp_server((51800, 52299)).await;
        let mut permits = Vec::new();
        for i in 1..MAX_ALLOCATIONS_PER_IP {
            permits.push(
                relay
                    .shared
                    .reserve(&Identity {
                        username: tunnel_creds(&format!("ip-tunnel-{i}")).0,
                        source: "127.0.0.1:1".parse().unwrap(),
                    })
                    .unwrap(),
            );
        }
        let c = udp_client(server, tunnel_creds("last-tunnel")).await;
        let held = c.allocate().await.unwrap();
        let extra = udp_client(server, tunnel_creds("another-tunnel")).await;
        let error = extra.allocate().await.err().expect("quota refusal");
        assert!(error.to_string().contains("486"), "quota response must be visible: {error}");
        held.close().await.unwrap();
        wait_allocations(&relay, 0).await;
        let replacement = extra.allocate().await.unwrap();
        replacement.close().await.unwrap();
        wait_allocations(&relay, 0).await;
        drop(permits);
        let security = relay.shared.security.lock().unwrap();
        assert!(security.tunnels.is_empty() && security.ips.is_empty());
    }

    #[test]
    fn ipv6_quota_uses_64_bit_network_and_normalizes_mapped_ipv4() {
        assert_eq!(
            source_network("2001:db8:1:2::1".parse().unwrap()),
            source_network("2001:db8:1:2:ffff::9".parse().unwrap())
        );
        assert_ne!(
            source_network("2001:db8:1:2::1".parse().unwrap()),
            source_network("2001:db8:1:3::1".parse().unwrap())
        );
        assert_eq!(source_network("::ffff:127.0.0.1".parse().unwrap()), "127.0.0.1".parse::<IpAddr>().unwrap());
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        let mut permits = Vec::new();
        for i in 0..MAX_ALLOCATIONS_PER_IP {
            let identity = Identity {
                username: tunnel_creds(&format!("ipv6-{}", i / 32)).0,
                source: format!("[2001:db8:1:2::{:x}]:1234", i + 1).parse().unwrap(),
            };
            permits.push(relay.shared.reserve(&identity).unwrap());
        }
        let identity =
            Identity { username: tunnel_creds("ipv6-extra").0, source: "[2001:db8:1:2::ffff]:1".parse().unwrap() };
        assert!(relay.shared.reserve(&identity).is_err());
        permits.pop();
        assert!(relay.shared.reserve(&identity).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn unauthenticated_stream_deadline_is_absolute_and_releases_slot() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 52300, 52399, SECRET));
        let (mut client, stream) = tokio::io::duplex(4096);
        let local = "127.0.0.1:3478".parse().unwrap();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let task = tokio::spawn({
            let relay = relay.clone();
            async move { relay.serve_stream(stream, local, peer).await }
        });
        tokio::task::yield_now().await;
        assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS - 1);
        // Repeated valid Binding requests do not authenticate the stream.
        for _ in 0..9 {
            client.write_all(&packet(0x0001, &[], None)).await.unwrap();
            let mut head = [0; 4];
            client.read_exact(&mut head).await.unwrap();
            let (len, _) = frame_len(head).unwrap();
            client.read_exact(&mut vec![0; len - 4]).await.unwrap();
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();
        assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_stream_frame_cannot_hold_auth_slot() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 52400, 52499, SECRET));
        let (mut client, stream) = tokio::io::duplex(64);
        let task = tokio::spawn({
            let relay = relay.clone();
            async move {
                relay.serve_stream(stream, "127.0.0.1:3478".parse().unwrap(), "127.0.0.1:1".parse().unwrap()).await;
            }
        });
        client.write_all(&[0, 3]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(STREAM_AUTH_DEADLINE).await;
        task.await.unwrap();
        assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
    }

    #[tokio::test]
    async fn authenticated_stream_survives_auth_deadline() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 52500, 52599, SECRET));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        tokio::spawn(relay.clone().accept_tcp(listener));
        let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
        let conn = Arc::new(StreamConn::new(tcp, "127.0.0.1:1".parse().unwrap(), server));
        let c = client(server, conn.clone(), creds(600)).await;
        let _allocation = c.allocate().await.unwrap();
        tokio::time::pause();
        tokio::time::advance(STREAM_AUTH_DEADLINE + Duration::from_secs(1)).await;
        assert!(!conn.closed.is_cancelled());
        assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 1);
        assert!(c.send_binding_request().await.is_ok());
        conn.close().await.unwrap();
        wait_allocations(&relay, 0).await;
    }

    #[tokio::test]
    async fn refresh_zero_releases_stream_slot_within_auth_deadline() {
        let relay = Arc::new(Relay::for_test(PUBLIC, 53100, 53199, SECRET));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accept = tokio::spawn(relay.clone().accept_tcp(listener));
        let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
        let conn = Arc::new(StreamConn::new(tcp, "127.0.0.1:1".parse().unwrap(), server));
        let c = client(server, conn.clone(), creds(600)).await;
        let allocation = c.allocate().await.unwrap();
        allocation.close().await.unwrap();
        wait_allocations(&relay, 0).await;
        // turn 0.17.3 also closes its transport on allocation teardown. Accept
        // that immediate closure; never permit the stream to retain a slot.
        tokio::time::pause();
        tokio::time::advance(STREAM_AUTH_DEADLINE + Duration::from_secs(1)).await;
        for _ in 0..100 {
            if relay.streams.available_permits() == MAX_STREAM_CONNS {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
        assert!(relay.shared.stream_ips.lock().unwrap().is_empty());
        accept.abort();
    }

    struct TempDir(std::path::PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn temp_dir_guard_removes_sidecars_on_unwind() {
        let path = std::env::temp_dir().join("tunnel-turn-tests").join(crate::tokens::random_tunnel_id());
        let result = std::panic::catch_unwind(|| {
            let _dir = TempDir(path.clone());
            std::fs::create_dir_all(&path).unwrap();
            for file in ["state.db", "state.db-wal", "state.db-shm"] {
                std::fs::write(path.join(file), b"test").unwrap();
            }
            panic!("exercise fixture cleanup");
        });
        assert!(result.is_err());
        assert!(!path.exists());
    }

    async fn state_with_tunnel() -> (Arc<crate::state::AppState>, TempDir) {
        let dir = TempDir(std::env::temp_dir().join("tunnel-turn-tests").join(crate::tokens::random_tunnel_id()));
        std::fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("state.db");
        let db = crate::db::Db::open(&path).unwrap();
        let config: Config = toml::from_str(
            r#"
preview_zone = "previews.example.com"
api_host = "api.example.com"
tunnel_host = "tunnel.example.com"
turn_host = "turn.test"
admin_token_hash = "test-placeholder"
[acme]
email = "admin@example.com"
[dns]
provider = "cloudflare"
zone = "example.com"
"#,
        )
        .unwrap();
        db.create_tunnel(
            crate::db::NewTunnel {
                id: "abcdefghij".into(),
                token_hash: "test-token-hash".into(),
                label: None,
                metadata: None,
                max_ports: 8,
                host_header: crate::db::HostHeaderMode::Rewrite,
                inject_ice: false,
                expires_at: crate::tokens::now() + 3600,
                access: crate::db::Access::default(),
                client_id: None,
            },
            100,
        )
        .await
        .unwrap();
        let certs = crate::tls::CertStore::new(path.with_extension("certs"));
        (crate::state::AppState::new(config, db, certs), dir)
    }

    #[tokio::test]
    async fn state_delete_revokes_new_and_existing_udp_and_stream_allocations() {
        let (state, _dir) = state_with_tunnel().await;
        let (relay, server) = udp_server((52600, 52699)).await;
        let relay = Arc::new(relay);
        state.install_turn(relay.clone());
        let udp = udp_client(server, creds(600)).await;
        let _udp_allocation = udp.allocate().await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream_server = listener.local_addr().unwrap();
        let accept = tokio::spawn(relay.clone().accept_tcp(listener));
        let tcp = tokio::net::TcpStream::connect(stream_server).await.unwrap();
        let conn = Arc::new(StreamConn::new(tcp, "127.0.0.1:1".parse().unwrap(), stream_server));
        let stream_client = client(stream_server, conn, creds(600)).await;
        let _stream_allocation = stream_client.allocate().await.unwrap();
        wait_allocations(&relay, 2).await;
        state.delete_tunnel("abcdefghij", tunnel_protocol::CloseReason::Deleted).await.unwrap();
        wait_allocations(&relay, 0).await;
        let fresh = udp_client(server, creds(600)).await;
        allocation_refused(&fresh).await;
        assert!(!relay.shared.validate(&creds(600).0).await);
        let handle = relay.udp.lock().unwrap().clone().unwrap();
        assert!(handle.get_allocations_info(None).await.unwrap().is_empty());
        assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
        accept.abort();
        drop(state);
    }

    #[tokio::test]
    async fn external_delete_is_detected_by_cached_refresh_validation() {
        let (state, _dir) = state_with_tunnel().await;
        let (relay, server) = udp_server((52700, 52799)).await;
        let relay = Arc::new(relay);
        state.install_turn(relay.clone());
        let c = udp_client(server, creds(600)).await;
        let _allocation = c.allocate().await.unwrap();
        // A second DB connection models the separate CLI process.
        let external = crate::db::Db::open(&_dir.0.join("state.db")).unwrap();
        external.delete_tunnel("abcdefghij".into()).await.unwrap();
        // Age both the AppState cache and the relay's refresh validation cache.
        state.invalidate_tunnel("abcdefghij");
        tokio::time::pause();
        tokio::time::advance(VALIDATION_TTL).await;
        assert!(!relay.shared.validate(&creds(600).0).await);
        let handle = relay.udp.lock().unwrap().clone().unwrap();
        sweep_server(&handle, &relay.shared).await;
        wait_allocations(&relay, 0).await;
        let fresh = udp_client(server, creds(600)).await;
        allocation_refused(&fresh).await;
        drop(external);
        drop(state);
    }

    #[tokio::test]
    async fn external_delete_is_checked_after_allocate_validation_cache_expires() {
        let (state, _dir) = state_with_tunnel().await;
        let (relay, server) = udp_server((52800, 52899)).await;
        let relay = Arc::new(relay);
        state.install_turn(relay.clone());
        assert!(!relay.shared.validate(&tunnel_creds("unknown-tunnel").0).await);
        assert!(relay.shared.security.lock().unwrap().revoked.is_empty());
        let c = udp_client(server, creds(600)).await;
        let _allocation = c.allocate().await.unwrap();
        assert!(relay.shared.security.lock().unwrap().validated.contains_key("abcdefghij"));
        let external = crate::db::Db::open(&_dir.0.join("state.db")).unwrap();
        external.delete_tunnel("abcdefghij".into()).await.unwrap();
        state.invalidate_tunnel("abcdefghij");
        tokio::time::pause();
        tokio::time::advance(VALIDATION_TTL).await;
        let fresh = udp_client(server, creds(600)).await;
        allocation_refused(&fresh).await;
        // The packet queued validation without awaiting it. Wait for the task.
        while relay.shared.security.lock().unwrap().validating.contains("abcdefghij") {
            tokio::task::yield_now().await;
        }
        assert!(!relay.shared.credential_allowed(&creds(600).0));
        let handle = relay.udp.lock().unwrap().clone().unwrap();
        sweep_server(&handle, &relay.shared).await;
        wait_allocations(&relay, 0).await;
        drop(external);
        drop(state);
    }

    #[test]
    fn request_gate_rejects_ambiguous_and_malformed_stun() {
        let user = creds(600).0;
        assert!(stun_packet(&packet(0x0004, &[(0x0006, user.as_bytes())], None)).unwrap().unwrap().username.is_some());
        assert!(stun_packet(&packet(0x0004, &[(0x0006, user.as_bytes()), (0x0006, b"other")], None)).is_err());
        let mut truncated = packet(0x0004, &[(0x0006, user.as_bytes())], None);
        truncated.pop();
        assert!(stun_packet(&truncated).is_err());
        assert!(stun_packet(&[0, 3, 0, 0]).is_err());
        assert!(stun_packet(&packet(0x0003, &[(0x0006, &[b'x'; 514])], None)).is_err());
        assert!(stun_packet(&[0x40, 0, 0, 0]).unwrap().is_none());
        assert!(stun_packet(&packet(0x0003, &[(0x0022, &[0; 8])], None)).unwrap().unwrap().reservation);
    }

    #[tokio::test(start_paused = true)]
    async fn revocation_fences_only_seen_tunnels_are_short_and_never_deny_globally() {
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        for i in 0..SECURITY_ENTRIES + 1 {
            relay.shared.revoke(&format!("unseen-{i}"));
        }
        assert!(relay.shared.security.lock().unwrap().revoked.is_empty());
        assert!(relay.shared.credential_allowed(&creds(600).0));
        {
            let mut security = relay.shared.security.lock().unwrap();
            for i in 0..SECURITY_ENTRIES {
                security.revoked.insert(format!("id-{i}"), tokio::time::Instant::now() + REVOCATION_TTL);
            }
            security.validated.insert("overflow".into(), (tokio::time::Instant::now(), crate::tokens::now() + 600));
        }
        relay.shared.revoke("overflow");
        assert_eq!(relay.shared.security.lock().unwrap().revoked.len(), SECURITY_ENTRIES);
        assert!(!relay.shared.credential_allowed(&tunnel_creds("overflow").0));
        assert!(relay.shared.credential_allowed(&creds(600).0));
        tokio::time::advance(REVOCATION_TTL).await;
        assert!(relay.shared.credential_allowed(&tunnel_creds("overflow").0));
        relay.shared.security.lock().unwrap().revoked.retain(|_, until| *until > tokio::time::Instant::now());
        assert!(relay.shared.security.lock().unwrap().revoked.is_empty());
    }

    #[test]
    fn request_integrity_requires_the_long_term_key_and_authenticated_username() {
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        let (user, password) = creds(600);
        let key = generate_auth_key(&user, "turn.test", &password);
        let raw = packet(0x0003, &[(0x0006, user.as_bytes())], Some(&key));
        assert!(verify_integrity(&raw, &user, &relay.shared));
        let quota = quota_response(&packet(0x0113, &[], None), &user, &relay.shared).unwrap();
        assert_eq!(stun_packet(&quota).unwrap().unwrap().kind, 0x0113);
        assert_eq!(&attribute(&quota, 0x0009).unwrap()[..4], &[0, 0, 4, 86]);
        assert!(verify_integrity(&quota, &user, &relay.shared));
        assert!(!verify_integrity(&packet(0x0003, &[(0x0006, user.as_bytes())], None), &user, &relay.shared));
        assert!(!verify_integrity(&packet(0x0003, &[(0x0006, user.as_bytes())], Some(b"wrong")), &user, &relay.shared));
        let mut tampered = raw.clone();
        tampered[24] ^= 1;
        assert!(!verify_integrity(&tampered, &user, &relay.shared));
        let mut duplicate = raw.clone();
        duplicate.extend_from_slice(&[0, 8, 0, 20]);
        duplicate.extend_from_slice(&[0; 20]);
        let len = (duplicate.len() - 20) as u16;
        duplicate[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(stun_packet(&duplicate).is_err());
        let mut suffix = raw;
        suffix.extend_from_slice(&[0, 6, 0, 4, b'l', b'a', b't', b'e']);
        let len = (suffix.len() - 20) as u16;
        suffix[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(stun_packet(&suffix).is_err());
    }

    #[tokio::test]
    async fn guard_checks_integrity_before_bounded_deduplicated_background_validation() {
        let (state, _dir) = state_with_tunnel().await;
        let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
        state.install_turn(relay.clone());
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let guard = GuardConn::new(socket, relay.shared.clone());
        let (user, password) = creds(600);
        let mut buf = [0; 2048];
        for key in [None, Some(b"wrong".as_slice())] {
            let raw = packet(0x0003, &[(0x0006, user.as_bytes())], key);
            source.send_to(&raw, addr).await.unwrap();
            let (n, _) = guard.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], raw);
            assert!(guard.context.lock().unwrap().is_none());
        }
        assert!(relay.shared.security.lock().unwrap().validating.is_empty());
        assert!(relay.shared.security.lock().unwrap().validated.is_empty());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let db = state.db.clone();
        let blocked = tokio::spawn(async move {
            db.call(move |_| {
                let _ = ready_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
            .unwrap();
        });
        ready_rx.await.unwrap();
        let key = generate_auth_key(&user, "turn.test", &password);
        source.send_to(&packet(0x0003, &[(0x0006, user.as_bytes())], Some(&key)), addr).await.unwrap();
        let binding = packet(0x0001, &[], None);
        source.send_to(&binding, addr).await.unwrap();
        let received = tokio::time::timeout(Duration::from_millis(250), guard.recv_from(&mut buf)).await;
        // Duplicate misses share one lookup; other ids can use at most 8 slots.
        for _ in 0..20 {
            assert!(!relay.shared.request_validation(&user));
        }
        assert_eq!(relay.shared.security.lock().unwrap().validating.len(), 1);
        for i in 0..VALIDATION_LOOKUPS * 2 {
            assert!(!relay.shared.request_validation(&tunnel_creds(&format!("missing-{i}")).0));
        }
        assert_eq!(relay.shared.security.lock().unwrap().validating.len(), VALIDATION_LOOKUPS);
        assert_eq!(relay.shared.validation_slots.available_permits(), 0);
        release_tx.send(()).unwrap();
        blocked.await.unwrap();
        let (n, _) = received.expect("DB cannot stall UDP").unwrap();
        assert_eq!(&buf[..n], binding);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !relay.shared.security.lock().unwrap().validating.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Unknown-id revocations may invalidate a simultaneous positive lookup;
        // an ordinary retransmit queues it again and then uses its cache result.
        if relay.shared.cached_validation("abcdefghij") != Some(true) {
            assert!(!relay.shared.request_validation(&user));
            while relay.shared.security.lock().unwrap().validating.contains("abcdefghij") {
                tokio::task::yield_now().await;
            }
        }
        assert!(relay.shared.request_validation(&user));
        assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
        drop(state);
    }

    #[tokio::test(start_paused = true)]
    async fn challenge_limits_burst_refill_networks_global_cap_and_map_size() {
        let mut limiter = ChallengeLimiter::new();
        let ip = "2001:db8:1:2::1".parse().unwrap();
        for _ in 0..CHALLENGE_IP_BURST as usize {
            assert!(limiter.allow(ip));
        }
        for _ in 0..100 {
            assert!(!limiter.allow("2001:db8:1:2::2".parse().unwrap()));
        }
        assert!(limiter.allow("2001:db8:1:3::1".parse().unwrap()));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
        let mut limiter = ChallengeLimiter::new();
        for i in 0..CHALLENGE_GLOBAL_BURST as usize {
            assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(i as u32 + 1))));
        }
        assert!(!limiter.allow("203.0.113.1".parse().unwrap()));
        tokio::time::advance(Duration::from_millis(5)).await;
        assert!(limiter.allow("203.0.113.1".parse().unwrap()));
        assert!(!limiter.allow("203.0.113.1".parse().unwrap()));
        // Fill the table without exceeding the global rate.
        let mut limiter = ChallengeLimiter::new();
        for i in 0..CHALLENGE_IP_ENTRIES {
            tokio::time::advance(Duration::from_millis(20)).await;
            limiter.ips.insert(IpAddr::V4(Ipv4Addr::from(i as u32 + 1)), RequestBucket::new(CHALLENGE_IP_BURST));
        }
        // Refresh timestamps to model a full active table.
        for bucket in limiter.ips.values_mut() {
            bucket.at = tokio::time::Instant::now();
        }
        let oldest = "198.51.100.1".parse().unwrap();
        limiter.ips.remove(&IpAddr::V4(Ipv4Addr::from(1)));
        limiter.ips.insert(
            oldest,
            RequestBucket { tokens: CHALLENGE_IP_BURST, at: tokio::time::Instant::now() - Duration::from_secs(1) },
        );
        assert!(limiter.allow("203.0.113.2".parse().unwrap()));
        assert!(!limiter.ips.contains_key(&oldest));
        assert_eq!(limiter.ips.len(), CHALLENGE_IP_ENTRIES);
        tokio::time::advance(CHALLENGE_IDLE).await;
        assert!(limiter.allow("203.0.113.2".parse().unwrap()));
        assert_eq!(limiter.ips.len(), 1);
    }

    #[tokio::test]
    async fn guard_drops_excess_challenges_before_turn() {
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let guard = GuardConn::new(socket, relay.shared.clone());
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let challenge = packet(0x0003, &[], None);
        let mut buf = [0; 2048];
        for _ in 0..CHALLENGE_IP_BURST as usize {
            source.send_to(&challenge, addr).await.unwrap();
            guard.recv_from(&mut buf).await.unwrap();
        }
        source.send_to(&challenge, addr).await.unwrap();
        // A ChannelData marker proves recv continued past the dropped request.
        source.send_to(&[0x40, 0, 0, 0], addr).await.unwrap();
        let (n, _) = guard.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x40, 0, 0, 0]);
    }

    #[test]
    fn stream_slots_are_per_network_and_return_on_drop() {
        let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
        let ip = "2001:db8:1:2::1".parse().unwrap();
        let mut held: Vec<_> = (0..MAX_STREAM_CONNS_PER_IP).map(|_| relay.shared.reserve_stream(ip).unwrap()).collect();
        assert!(relay.shared.reserve_stream("2001:db8:1:2::ffff".parse().unwrap()).is_none());
        assert!(relay.shared.reserve_stream("2001:db8:1:3::1".parse().unwrap()).is_some());
        held.pop();
        assert!(relay.shared.reserve_stream(ip).is_some());
        drop(held);
        assert!(relay.shared.stream_ips.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn empty_stream_deadline_restarts_only_after_last_allocation_closes() {
        let activity = Arc::new(AllocationActivity::new());
        let timeout = tokio::spawn({
            let activity = activity.clone();
            async move { activity.empty_timeout().await }
        });
        activity.open();
        activity.open();
        tokio::time::advance(STREAM_AUTH_DEADLINE * 2).await;
        assert!(!timeout.is_finished());
        activity.close();
        tokio::time::advance(STREAM_AUTH_DEADLINE * 2).await;
        assert!(!timeout.is_finished());
        activity.close();
        tokio::task::yield_now().await;
        tokio::time::advance(STREAM_AUTH_DEADLINE - Duration::from_secs(1)).await;
        assert!(!timeout.is_finished());
        activity.open();
        tokio::time::advance(STREAM_AUTH_DEADLINE * 2).await;
        assert!(!timeout.is_finished());
        activity.close();
        tokio::task::yield_now().await;
        tokio::time::advance(STREAM_AUTH_DEADLINE).await;
        timeout.await.unwrap();
    }

    #[tokio::test]
    async fn relay_fast_path_avoids_quota_and_security_locks_and_latches_revocation() {
        let relay = Relay::for_test(PUBLIC, 52900, 52999, SECRET);
        let generator = RelayGen {
            shared: relay.shared.clone(),
            refused: Arc::new(AtomicBool::new(false)),
            activity: Arc::new(AllocationActivity::new()),
            context: Arc::new(Mutex::new(Some(Identity {
                username: creds(600).0,
                source: "127.0.0.1:1".parse().unwrap(),
            }))),
        };
        let (conn, _) = generator.allocate_conn(true, 0).await.unwrap();
        let relay_conn = conn.as_any().downcast_ref::<RelayConn>().unwrap();
        assert!(relay_conn.allow(1));
        let (result, fast) = {
            let _security = relay.shared.security.lock().unwrap();
            let _quota = relay_conn.quota.lock().unwrap();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let fast = std::thread::spawn({
                let conn = conn.clone();
                move || {
                    let allowed = conn.as_any().downcast_ref::<RelayConn>().unwrap().allow(1);
                    let _ = done_tx.send(allowed);
                }
            });
            (done_rx.recv_timeout(Duration::from_millis(250)), fast)
        };
        fast.join().unwrap();
        assert!(result.expect("fast path must not lock either mutex"));
        relay.shared.revoke("abcdefghij");
        assert!(!relay_conn.allow(1));
        relay.shared.security.lock().unwrap().revoked.clear();
        relay.shared.revocation_epoch.fetch_add(1, Ordering::Release);
        assert!(!relay_conn.allow(1));
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn sweep_retries_revoked_allocations_even_without_a_remaining_fence() {
        let (relay, server) = udp_server((53000, 53099)).await;
        let c = udp_client(server, creds(600)).await;
        let _held = c.allocate().await.unwrap();
        // Model a missed broadcast deletion: fence locally but send no command.
        relay.shared.revoke("abcdefghij");
        relay.shared.security.lock().unwrap().revoked.clear();
        let handle = relay.udp.lock().unwrap().clone().unwrap();
        sweep_server(&handle, &relay.shared).await;
        wait_allocations(&relay, 0).await;
        assert!(handle.get_allocations_info(None).await.unwrap().is_empty());
        sweep_server(&handle, &relay.shared).await;
        assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
    }

    #[test]
    fn peer_rules() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "2001:db8::1",
        ] {
            assert!(denied_peer(ip.parse().unwrap(), false), "{ip}");
        }
        for ip in ["8.8.8.8", "203.0.113.9", "100.128.0.1"] {
            assert!(!denied_peer(ip.parse().unwrap(), false), "{ip}");
        }
    }

    #[test]
    fn stream_framing() {
        // STUN binding request header, length 8.
        assert_eq!(frame_len([0x00, 0x01, 0x00, 0x08]), Some((28, 0)));
        // ChannelData 0x4000 with 5 bytes: padded by 3 over streams.
        assert_eq!(frame_len([0x40, 0x00, 0x00, 0x05]), Some((9, 3)));
        assert_eq!(frame_len([0x40, 0x00, 0x00, 0x08]), Some((12, 0)));
        assert_eq!(frame_len([0x80, 0, 0, 0]), None);
        assert_eq!(frame_len([0xC0, 0, 0, 0]), None);
    }
}
