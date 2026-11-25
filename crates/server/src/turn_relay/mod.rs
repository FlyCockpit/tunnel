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
use futures_util::future::BoxFuture;
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
use crate::db::TunnelLookup;
use crate::metrics::{Metrics, TurnMetrics};

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

/// Where the relay reads tunnel lifecycle: the app state in the server.
pub trait TunnelLookups: Send + Sync {
    /// Through the app's short-lived lifecycle cache.
    fn cached<'a>(&'a self, id: &'a str) -> BoxFuture<'a, anyhow::Result<Arc<TunnelLookup>>>;
    /// Straight from the database.
    fn fresh<'a>(&'a self, id: &'a str) -> BoxFuture<'a, anyhow::Result<Arc<TunnelLookup>>>;
}

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
    metrics: Arc<TurnMetrics>,
    /// Peers that tests may relay to despite being non-public (loopback).
    allow_private_peers: bool,
    max_credential_ttl: i64,
    state: OnceLock<Weak<dyn TunnelLookups>>,
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
    pub fn install_state(&self, state: Weak<dyn TunnelLookups>) {
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
            metrics: Arc::new(TurnMetrics::default()),
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
                state.cached(tunnel).await
            } else {
                // A fenced read must reach the database even if it managed to
                // populate AppState's cache before the invalidation arrived.
                state.fresh(tunnel).await
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
        s.metrics.allocation_opened();
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
        self.shared.metrics.allocation_closed();
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

mod auth;
#[cfg(test)]
mod tests;

use auth::*;
