use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use tunnel_protocol::CloseReason;

use crate::config::Config;
use crate::db::{Db, DeleteOutcome, TunnelLookup};
use crate::metrics::Metrics;
use crate::ratelimit::{Limiter, RateLimiter};
use crate::registry::Registry;
use crate::tls::CertStore;

const TUNNEL_CACHE_TTL: Duration = Duration::from_secs(5);
const SESSION_CACHE_TTL: Duration = Duration::from_secs(10);
const CACHE_MAX_ENTRIES: usize = 50_000;
/// Database lookups that visitors can trigger (tunnel by host, session by
/// cookie) in flight at once. Visitors choose hosts and cookie values freely,
/// so cache misses are theirs to make; without a bound each would queue a
/// blocking task on the one SQLite connection.
const VISITOR_LOOKUPS: usize = 32;
/// How long a lookup waits for a slot before the visitor gets a 503.
const VISITOR_LOOKUP_WAIT: Duration = Duration::from_secs(2);

/// Visitor lookups are saturated; answer 503 rather than queue more.
#[derive(Debug, thiserror::Error)]
#[error("too many lookups in progress")]
pub struct LookupsBusy;

/// Unexpired `(tunnel_id, expires_at)` grants of one gate session.
pub type Grants = Arc<Vec<(String, i64)>>;

/// A short-lived cache that never stores a result read before an
/// invalidation. Lookups capture the epoch before querying the database and
/// insert only if no invalidation happened meanwhile, so a slow lookup cannot
/// resurrect a row that a concurrent delete or revoke just removed.
struct Cache<V> {
    ttl: Duration,
    epoch: AtomicU64,
    map: Mutex<HashMap<String, (Instant, V)>>,
}

impl<V: Clone> Cache<V> {
    fn new(ttl: Duration) -> Self {
        Self { ttl, epoch: AtomicU64::new(0), map: Mutex::new(HashMap::new()) }
    }

    fn get(&self, key: &str) -> Option<V> {
        let map = self.map.lock().expect("cache lock");
        map.get(key).filter(|(at, _)| at.elapsed() < self.ttl).map(|(_, v)| v.clone())
    }

    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// The epoch is compared under the map lock, and invalidation bumps it
    /// before taking that lock, so either this insert is skipped or the
    /// invalidation that follows removes it.
    fn insert_if_current(&self, epoch: u64, key: String, value: V) {
        let mut map = self.map.lock().expect("cache lock");
        if self.epoch.load(Ordering::SeqCst) != epoch {
            return;
        }
        if map.len() >= CACHE_MAX_ENTRIES {
            // Drop expired entries first; clear everything only if still full.
            let ttl = self.ttl;
            map.retain(|_, (at, _)| at.elapsed() < ttl);
            if map.len() >= CACHE_MAX_ENTRIES {
                map.clear();
            }
        }
        map.insert(key, (Instant::now(), value));
    }

    fn remove(&self, key: &str) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.map.lock().expect("cache lock").remove(key);
    }

    fn clear(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.map.lock().expect("cache lock").clear();
    }
}

/// Rate limiters and keys of the web UI.
pub struct UiState {
    pub keys: Option<crate::seal::Keys>,
    pub login_ip: RateLimiter,
    /// Per username, with a larger budget than per IP, so one address alone
    /// cannot lock a user out.
    pub login_user: Limiter<String>,
    /// The TOTP step of sign-in, per user (wrong codes also count towards a
    /// persisted lockout).
    pub login_factor: Limiter<String>,
    /// Password and code re-checks inside a session, per user.
    pub reauth: Limiter<String>,
    /// Device user-code lookups, per user (they are guessable only by brute force).
    pub device_lookup: Limiter<String>,
    pub device_code_limiter: RateLimiter,
}

impl UiState {
    pub fn new(config: &Config) -> Self {
        let per_min = config.limits.login_rate_per_min;
        Self {
            keys: config.ui_secret.as_deref().filter(|_| config.ui_host.is_some()).map(crate::seal::Keys::new),
            login_ip: RateLimiter::new(per_min),
            login_user: Limiter::new(per_min.saturating_mul(3)),
            login_factor: Limiter::new(per_min),
            reauth: Limiter::new(per_min),
            device_lookup: Limiter::new(per_min),
            device_code_limiter: RateLimiter::new(per_min),
        }
    }
}

pub struct AppState {
    pub config: Config,
    pub db: Db,
    pub registry: Registry,
    pub certs: Arc<CertStore>,
    pub metrics: Metrics,
    pub traffic: Arc<crate::traffic::Traffic>,
    /// Per-IP limiter for `/__access/*`.
    pub access_limiter: RateLimiter,
    /// Web UI keys and limiters.
    pub ui: UiState,
    tunnel_cache: Cache<Arc<TunnelLookup>>,
    session_cache: Cache<Grants>,
    visitor_lookups: tokio::sync::Semaphore,
    /// The built-in TURN relay, once started (WebRTC enabled).
    pub turn: std::sync::OnceLock<Arc<crate::turn_relay::Relay>>,
    /// Serialize tunnel-token rotation with connection registration (sharded by tunnel id).
    token_locks: Vec<tokio::sync::Mutex<()>>,
}

const TOKEN_LOCK_SHARDS: usize = 64;

impl AppState {
    pub fn new(config: Config, db: Db, certs: Arc<CertStore>) -> Arc<Self> {
        let access_limiter = RateLimiter::new(config.limits.access_rate_per_min);
        db.set_limit_defaults(crate::limits::Defaults::new(&config.limits));
        Arc::new(Self {
            ui: UiState::new(&config),
            config,
            db,
            registry: Registry::default(),
            certs,
            metrics: Metrics::default(),
            traffic: Arc::new(crate::traffic::Traffic::default()),
            access_limiter,
            tunnel_cache: Cache::new(TUNNEL_CACHE_TTL),
            session_cache: Cache::new(SESSION_CACHE_TTL),
            visitor_lookups: tokio::sync::Semaphore::new(VISITOR_LOOKUPS),
            turn: std::sync::OnceLock::new(),
            token_locks: (0..TOKEN_LOCK_SHARDS).map(|_| tokio::sync::Mutex::new(())).collect(),
        })
    }

    /// Held while a tunnel's token is rotated and while a connection checks
    /// its token and registers, so neither can act on a superseded token.
    pub fn token_lock(&self, tunnel_id: &str) -> &tokio::sync::Mutex<()> {
        let h =
            tunnel_id.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
        &self.token_locks[(h % TOKEN_LOCK_SHARDS as u64) as usize]
    }

    /// Attach the TURN lifecycle validator before publishing the relay.
    pub fn install_turn(self: &Arc<Self>, relay: Arc<crate::turn_relay::Relay>) {
        let lookups: std::sync::Weak<dyn crate::turn_relay::TunnelLookups> = Arc::downgrade(self) as _;
        relay.install_state(lookups);
        let _ = self.turn.set(relay);
    }

    /// Tunnel lifecycle state by id (live row, tombstone, or unknown), cached
    /// for a few seconds, negative results included, so probing random hosts
    /// costs one query per id per TTL. Live rows may be expired; callers check
    /// `is_expired()`.
    pub async fn tunnel(&self, id: &str) -> anyhow::Result<Arc<TunnelLookup>> {
        if let Some(found) = self.tunnel_cache.get(id) {
            return Ok(found);
        }
        let _slot = self.admit_lookup().await?;
        // Another request may have filled the cache while this one waited.
        if let Some(found) = self.tunnel_cache.get(id) {
            return Ok(found);
        }
        self.tunnel_for_turn(id).await
    }

    /// TURN admits background lookups with its own semaphore. Reuse lifecycle
    /// caching/invalidation without consuming HTTP visitor lookup permits.
    pub(crate) async fn tunnel_for_turn(&self, id: &str) -> anyhow::Result<Arc<TunnelLookup>> {
        if let Some(found) = self.tunnel_cache.get(id) {
            return Ok(found);
        }
        let epoch = self.tunnel_cache.epoch();
        let found = Arc::new(self.db.lookup_tunnel(id.to_string()).await?);
        self.tunnel_cache.insert_if_current(epoch, id.to_string(), found.clone());
        Ok(found)
    }

    pub fn invalidate_tunnel(&self, id: &str) {
        self.tunnel_cache.remove(id);
        if let Some(relay) = self.turn.get() {
            relay.forget_validation(id);
        }
    }

    /// Cached grants for each of `session_hashes`, plus the hashes that were
    /// not cached. The gate combines cached and loaded grants to select the
    /// longest authorization without reloading cached sessions.
    pub fn cached_session_grants(&self, session_hashes: &[String]) -> (Vec<(String, Grants)>, Vec<String>) {
        let mut hits = Vec::new();
        let mut misses = Vec::new();
        for h in session_hashes {
            match self.session_cache.get(h) {
                Some(g) => hits.push((h.clone(), g)),
                None => misses.push(h.clone()),
            }
        }
        (hits, misses)
    }

    /// Grants for `session_hashes`, fetched in one query. Sessions with
    /// grants are cached; values without any are not, since a client can
    /// vary arbitrary cookie values freely and caching them buys nothing.
    pub async fn load_session_grants(&self, session_hashes: Vec<String>) -> anyhow::Result<Vec<(String, Grants)>> {
        if session_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let _slot = self.admit_lookup().await?;
        let epoch = self.session_cache.epoch();
        let found = self.db.session_grants(session_hashes).await?;
        let mut out = Vec::with_capacity(found.len());
        for (hash, grants) in found {
            let grants: Grants = Arc::new(grants);
            self.session_cache.insert_if_current(epoch, hash.clone(), grants.clone());
            out.push((hash, grants));
        }
        Ok(out)
    }

    async fn admit_lookup(&self) -> anyhow::Result<tokio::sync::SemaphorePermit<'_>> {
        match tokio::time::timeout(VISITOR_LOOKUP_WAIT, self.visitor_lookups.acquire()).await {
            Ok(Ok(permit)) => Ok(permit),
            _ => {
                self.metrics.lookup_shed();
                Err(LookupsBusy.into())
            }
        }
    }

    /// Revocation affects many sessions at once; drop the whole cache.
    pub fn invalidate_sessions(&self) {
        self.session_cache.clear();
    }

    /// Stop a tunnel: DB cascade + tombstone, drop caches, close the live
    /// connection with `reason`. Used by `DELETE /v1/tunnels/{id}` (Deleted)
    /// and the purge job (Expired).
    pub async fn delete_tunnel(self: &Arc<Self>, id: &str, reason: CloseReason) -> anyhow::Result<DeleteOutcome> {
        let state = self.clone();
        let id = id.to_owned();
        // A dropped HTTP request detaches this task instead of interrupting
        // teardown after the blocking database transaction has committed.
        tokio::spawn(async move {
            let outcome = state.db.delete_tunnel(id.clone()).await?;
            if let Some(relay) = state.turn.get() {
                // Fence before spawning: relay I/O must never delay registry
                // removal, and the task must not leave a revocation race window.
                relay.fence_tunnel(&id);
                let relay = relay.clone();
                let id = id.clone();
                tokio::spawn(async move { relay.revoke_tunnel(&id).await });
            }
            state.invalidate_tunnel(&id);
            state.invalidate_sessions();
            if let Some(live) = state.registry.remove(&id) {
                live.close(reason);
            }
            state.traffic.forget_tunnel(&id);
            Ok(outcome)
        })
        .await?
    }

    pub fn preview_host(&self, port: u16, tunnel_id: &str) -> String {
        self.config.preview_host(port, tunnel_id)
    }
}

impl crate::turn_relay::TunnelLookups for AppState {
    fn cached<'a>(&'a self, id: &'a str) -> BoxFuture<'a, anyhow::Result<Arc<TunnelLookup>>> {
        Box::pin(self.tunnel_for_turn(id))
    }

    fn fresh<'a>(&'a self, id: &'a str) -> BoxFuture<'a, anyhow::Result<Arc<TunnelLookup>>> {
        Box::pin(async move { self.db.lookup_tunnel(id.to_owned()).await.map(Arc::new) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn turn_lookup_does_not_wait_for_http_visitor_slots() {
        let path =
            std::env::temp_dir().join("tunnel-state-tests").join(format!("{}.db", crate::tokens::random_tunnel_id()));
        let db = Db::open(&path).unwrap();
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
        let state = AppState::new(config, db, CertStore::new(path.with_extension("certs")));
        let slots = state.visitor_lookups.acquire_many(VISITOR_LOOKUPS as u32).await.unwrap();
        let found = tokio::time::timeout(Duration::from_millis(250), state.tunnel_for_turn("missing"))
            .await
            .expect("TURN must not queue on visitor lookups")
            .unwrap();
        assert!(matches!(found.as_ref(), TunnelLookup::Unknown));
        assert_eq!(state.visitor_lookups.available_permits(), 0);
        drop(slots);
        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
