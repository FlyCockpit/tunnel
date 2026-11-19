//! Visitor gate: the parent-domain session cookie, access-link redemption,
//! and password login. Redemption and login run on the zone host (see
//! `gatehost`), never on a preview origin a preview app could control.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Response, StatusCode};
use tunnel_protocol::{ACCESS_TOKEN_PREFIX, GATE_COOKIE};

use crate::db::Redemption;
use crate::metrics::Metrics;
use crate::pages;
use crate::state::AppState;
use crate::tokens::{hash_token, now};
use crate::util::{Body, empty, text_response};

/// Distinct plausible gate-cookie values considered per request. Preview JS
/// can toss extra same-named cookies (longer paths are sent first), so this
/// must exceed what a browser will store for one site (Chrome keeps 180 per
/// domain) or tossed values could push the real session out. All values are
/// looked up in one query, so the bound only limits query size.
const MAX_GATE_VALUES: usize = 256;

pub struct GateCookies {
    /// Every gate-cookie value the browser sent, in order.
    pub values: Vec<String>,
    /// All other cookies, as one `Cookie` header for the origin.
    pub forward: Option<HeaderValue>,
}

/// Split gate cookies from the rest. HTTP/2 clients may send several
/// `Cookie` headers; all of them are considered and merged.
pub fn split_cookies(headers: &HeaderMap) -> GateCookies {
    let mut values = Vec::new();
    let mut kept: Vec<u8> = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        for pair in value.as_bytes().split(|&b| b == b';') {
            let pair = pair.trim_ascii();
            if pair.is_empty() {
                continue;
            }
            let (name, val) = match pair.iter().position(|&b| b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &pair[pair.len()..]),
            };
            if name.trim_ascii().eq_ignore_ascii_case(GATE_COOKIE.as_bytes()) {
                if let Ok(v) = std::str::from_utf8(val.trim_ascii()) {
                    values.push(v.to_string());
                }
                continue;
            }
            // The web UI's session cookie is host-only on the UI host, so a
            // browser never sends it here; never forward one to an origin anyway.
            if name.trim_ascii().eq_ignore_ascii_case(crate::ui::UI_COOKIE.as_bytes()) {
                continue;
            }
            if !kept.is_empty() {
                kept.extend_from_slice(b"; ");
            }
            kept.extend_from_slice(pair);
        }
    }
    let forward = if kept.is_empty() { None } else { HeaderValue::from_bytes(&kept).ok() };
    GateCookies { values, forward }
}

/// Session ids are 43-char base64url; anything else cannot be a session and
/// is not worth a database lookup.
fn plausible(value: &str) -> bool {
    (16..=128).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Hashes of the distinct plausible cookie values, in order, capped.
fn session_hashes(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values.iter().filter(|v| plausible(v)) {
        if out.len() >= MAX_GATE_VALUES {
            break;
        }
        let hash = hash_token(value);
        if !out.contains(&hash) {
            out.push(hash);
        }
    }
    out
}

/// A gate grant or public access, with the epoch captured before its lookup.
pub struct Authorization {
    /// The session granting access (or, for an upgrade, its original session,
    /// retained if the tunnel becomes public).
    pub session_hash: Option<String>,
    /// Every plausible session the request presented (hashed). A recheck
    /// accepts any of them, so losing one session does not end a request that
    /// another presented session still authorizes. Empty for public access.
    pub candidates: Arc<[String]>,
    /// Public access has no session deadline.
    pub expires_at: Option<i64>,
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Any valid presented session suffices, so tossed cookies cannot lock a
/// visitor out. Ordinary requests accept a cached hit without querying misses;
/// upgraded connections retain the longest matching cached or loaded grant.
pub async fn authorize(
    state: &AppState,
    tunnel_id: &str,
    values: &[String],
    upgrade: bool,
) -> anyhow::Result<Option<Authorization>> {
    let cancel = state.registry.gate_epoch(tunnel_id);
    let hashes: Arc<[String]> = session_hashes(values).into();
    if hashes.is_empty() {
        return Ok(None);
    }
    let (hits, misses) = state.cached_session_grants(&hashes);
    if !upgrade && let Some(cached) = longest_authorization(tunnel_id, hits.iter().cloned(), &hashes, cancel.clone()) {
        return Ok(Some(cached));
    }
    let loaded = state.load_session_grants(misses).await?;
    Ok(longest_authorization(tunnel_id, hits.into_iter().chain(loaded), &hashes, cancel))
}

/// Recheck the current access mode, then the sessions `previous` presented,
/// after a gate epoch rotation or at its expiry. Public access needs no session
/// or expiry. Loading grants directly bypasses cached sessions and captures
/// concurrent rotations.
pub async fn reauthorize(
    state: &AppState,
    tunnel_id: &str,
    previous: &Authorization,
) -> anyhow::Result<Option<Authorization>> {
    let cancel = state.registry.gate_epoch(tunnel_id);
    if cancel.is_cancelled() {
        return Ok(None);
    }
    // Before any database work: blocking a user rotates all their tunnels at once.
    if crate::traffic::tunnel_blocked(state, tunnel_id) {
        return Ok(None);
    }
    let tunnel = state.tunnel(tunnel_id).await?;
    let crate::db::TunnelLookup::Live(tunnel) = tunnel.as_ref() else {
        return Ok(None);
    };
    if tunnel.is_expired() {
        return Ok(None);
    }
    if tunnel.access.mode == crate::db::AccessMode::Public {
        return Ok(Some(Authorization {
            session_hash: previous.session_hash.clone(),
            candidates: previous.candidates.clone(),
            expires_at: None,
            cancel,
        }));
    }
    let grants = state.load_session_grants(previous.candidates.to_vec()).await?;
    Ok(longest_authorization(tunnel_id, grants, &previous.candidates, cancel))
}

/// Whether a [`watch`] has a verdict for its grant. What the watch guards
/// relays nothing while a recheck runs, and already from the moment the
/// grant's gate epoch is rotated (before the watch task gets to run), so a
/// revocation pauses every side at once. Each side registers a waker to
/// resume when the recheck passes or the grant is lost.
#[derive(Default)]
pub struct Rechecking {
    active: AtomicBool,
    lost: AtomicBool,
    /// The epoch of the grant currently in force.
    epoch: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>,
    to_visitor: AtomicWaker,
    to_origin: AtomicWaker,
    driver: AtomicWaker,
}

/// Which part of an exchange waits for a recheck to end. Each is polled by
/// one task at a time.
#[derive(Clone, Copy)]
pub enum Side {
    /// The response body toward the visitor.
    ToVisitor,
    /// The request body toward the origin.
    ToOrigin,
    /// The request itself until the origin answers, then a WebSocket splice.
    Driver,
}

impl Rechecking {
    /// No verdict is pending: no recheck runs and the grant's epoch stands.
    pub(crate) fn is_settled(&self) -> bool {
        if self.active.load(Ordering::Acquire) {
            return false;
        }
        let epoch = self.epoch.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        !epoch.as_ref().is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
    }

    pub(crate) fn start(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// The grant in force now has this epoch.
    pub(crate) fn follow(&self, epoch: &tokio_util::sync::CancellationToken) {
        *self.epoch.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(epoch.clone());
    }

    fn wake_all(&self) {
        self.to_visitor.wake();
        self.to_origin.wake();
        self.driver.wake();
    }

    /// A recheck passed: resume every side.
    pub(crate) fn end(&self) {
        self.active.store(false, Ordering::Release);
        self.wake_all();
    }

    /// Access is lost: release every side (to fail) for good. The caller
    /// marks the loss itself first.
    pub fn finish_lost(&self) {
        self.lost.store(true, Ordering::Release);
        self.active.store(false, Ordering::Release);
        self.wake_all();
    }

    /// Ready when a side may proceed: the grant stands, or it is lost (the
    /// side then fails). `side` is registered on every poll, so it is woken
    /// both when a recheck passes and at a loss.
    pub fn poll_idle(&self, side: Side, cx: &mut Context<'_>) -> Poll<()> {
        match side {
            Side::ToVisitor => self.to_visitor.register(cx.waker()),
            Side::ToOrigin => self.to_origin.register(cx.waker()),
            Side::Driver => self.driver.register(cx.waker()),
        }
        // Checked after registering so a wake in between is not missed.
        if self.lost.load(Ordering::Acquire) || self.is_settled() { Poll::Ready(()) } else { Poll::Pending }
    }
}

/// Upper bound for one recheck; a recheck that cannot finish fails closed.
const RECHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause before retrying a recheck whose lookup was shed.
const RECHECK_RETRY: Duration = Duration::from_millis(50);

/// Resolves once `grant` no longer authorizes its holder: its gate epoch was
/// rotated (a link or session revoked, access changed, the tunnel closed,
/// deleted or replaced) and a recheck of the sessions it presented failed, or
/// its grant expired without the recheck finding a later one. Every proxied
/// request and WebSocket races its stream against this, so revocation and
/// expiry end responses that are already streaming, not only new requests.
///
/// `rechecking` holds the verdict state; what the watch guards must not relay
/// anything until a verdict follows a rotation (see `proxy`), so a revoked
/// visitor receives nothing new after the revocation. On loss it returns with
/// the recheck pending; the caller marks the loss and then calls
/// [`Rechecking::finish_lost`]. The
/// expiry deadline is taken on tokio's clock when a grant is (re)loaded, so
/// paused-time tests reach it deterministically.
pub async fn watch(state: &AppState, tunnel_id: &str, mut grant: Authorization, rechecking: &Rechecking) {
    rechecking.follow(&grant.cancel);
    let mut deadline = expiry_deadline(grant.expires_at);
    loop {
        let expiry = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending::<()>().await,
            }
        };
        let expired = tokio::select! {
            biased;
            _ = grant.cancel.cancelled() => false,
            _ = expiry => true,
        };
        rechecking.start();
        // Lookups shed under load are retried: a busy server must not cut a
        // visitor who is still authorized, and the timeout still fails closed.
        let recheck = async {
            loop {
                match reauthorize(state, tunnel_id, &grant).await {
                    Err(e) if e.is::<crate::state::LookupsBusy>() => {
                        tokio::time::sleep(RECHECK_RETRY).await;
                    }
                    other => return other,
                }
            }
        };
        let current = match tokio::time::timeout(RECHECK_TIMEOUT, recheck).await {
            Ok(Ok(Some(current))) => current,
            Ok(Ok(None)) => return,
            Ok(Err(e)) => {
                tracing::debug!(tunnel = tunnel_id, error = %e, "stream reauthorization failed");
                return;
            }
            Err(_) => {
                tracing::debug!(tunnel = tunnel_id, "stream reauthorization timed out");
                return;
            }
        };
        // At its deadline a grant survives only if its session now lasts longer.
        if expired && !later(current.expires_at, grant.expires_at) {
            return;
        }
        if current.expires_at != grant.expires_at {
            deadline = expiry_deadline(current.expires_at);
        }
        grant = current;
        rechecking.follow(&grant.cancel);
        rechecking.end();
    }
}

fn expiry_deadline(expires_at: Option<i64>) -> Option<tokio::time::Instant> {
    expires_at.map(|at| {
        let remaining = at.saturating_sub(now()).max(0) as u64;
        tokio::time::Instant::now() + Duration::from_secs(remaining)
    })
}

/// `None` (public) outlasts any session expiry.
fn later(current: Option<i64>, previous: Option<i64>) -> bool {
    match (current, previous) {
        (None, Some(_)) => true,
        (Some(c), Some(p)) => c > p,
        (_, None) => false,
    }
}

fn longest_authorization(
    tunnel_id: &str,
    sessions: impl IntoIterator<Item = (String, crate::state::Grants)>,
    candidates: &Arc<[String]>,
    cancel: tokio_util::sync::CancellationToken,
) -> Option<Authorization> {
    let t = now();
    sessions
        .into_iter()
        .filter_map(|(hash, grants)| {
            grants.iter().filter(|(id, expiry)| id == tunnel_id && *expiry > t).map(|(_, expiry)| *expiry).max().map(
                |expires_at| Authorization {
                    session_hash: Some(hash),
                    candidates: candidates.clone(),
                    expires_at: Some(expires_at),
                    cancel: cancel.clone(),
                },
            )
        })
        .max_by_key(|grant| grant.expires_at)
}

/// Access-link redemption: validate, mint a fresh session carrying the new
/// grant and those of any valid presented session, set the cookie, and
/// redirect to `location` so the token never appears in a later URL.
pub async fn redeem(
    state: &AppState,
    peer: IpAddr,
    tunnel_id: &str,
    token: &str,
    cookie_values: &[String],
    location: &str,
) -> Response<Body> {
    if !state.access_limiter.check(peer) {
        return pages::rate_limited();
    }
    if !token.starts_with(ACCESS_TOKEN_PREFIX) || token.len() > 256 {
        Metrics::inc(&state.metrics.access_failures);
        return pages::unauthorized();
    }
    let outcome = match state
        .db
        .redeem_access_link(tunnel_id.to_string(), hash_token(token), session_hashes(cookie_values))
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(tunnel = tunnel_id, error = %e, "access link redemption failed");
            return text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };

    let (session_id, expires_at) = match outcome {
        Redemption::Invalid => {
            Metrics::inc(&state.metrics.access_failures);
            return pages::unauthorized();
        }
        Redemption::Granted { session_id, expires_at } => (session_id, expires_at),
    };
    Metrics::inc(&state.metrics.access_redemptions);

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::SET_COOKIE, gate_cookie(&state.config.preview_zone, &session_id, expires_at - now()))
        .body(empty())
        .expect("valid response")
}

/// Largest login form body accepted.
const LOGIN_BODY_LIMIT: usize = 8 * 1024;
/// A login body must arrive within this long (slow bodies cannot pile up).
const LOGIN_BODY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The fields of a submitted login form.
pub struct LoginForm {
    pub to: String,
    pub username: String,
    pub password: String,
    pub next: String,
}

/// Read a login form body, bounded in size and time. `Err` is the page to show.
pub async fn read_login_form(body: hyper::body::Incoming) -> Result<LoginForm, (StatusCode, &'static str)> {
    use http_body_util::BodyExt;
    let raw =
        match tokio::time::timeout(LOGIN_BODY_DEADLINE, http_body_util::Limited::new(body, LOGIN_BODY_LIMIT).collect())
            .await
        {
            Ok(Ok(b)) => b.to_bytes(),
            Ok(Err(_)) => return Err((StatusCode::PAYLOAD_TOO_LARGE, "The form was too large.")),
            Err(_) => return Err((StatusCode::REQUEST_TIMEOUT, "The form took too long to arrive.")),
        };
    let mut form =
        LoginForm { to: String::new(), username: String::new(), password: String::new(), next: String::new() };
    for (k, v) in url::form_urlencoded::parse(&raw) {
        match &*k {
            "to" => form.to = v.into_owned(),
            "username" => form.username = v.into_owned(),
            "password" => form.password = v.into_owned(),
            "next" => form.next = v.into_owned(),
            _ => {}
        }
    }
    form.next = safe_next(&form.next);
    Ok(form)
}

/// How a password login ended.
pub enum LoginOutcome {
    /// Signed in: the `Set-Cookie` value to send.
    Granted(String),
    /// Show the form again with this status and message.
    Retry(StatusCode, &'static str),
    RateLimited,
    /// The tunnel is not (or no longer) password-protected.
    NotPassword,
    Internal,
}

/// Check a submitted username and password against a password-mode tunnel
/// and mint a session exactly like a link redemption. Attempts share the
/// access-link rate limit.
pub async fn login(
    state: &AppState,
    peer: IpAddr,
    tunnel: &crate::db::TunnelRow,
    form: LoginForm,
    cookie_values: &[String],
) -> LoginOutcome {
    if !state.access_limiter.check(peer) {
        return LoginOutcome::RateLimited;
    }
    let (Some(user), Some(hash)) = (tunnel.access.password_user.clone(), tunnel.access.password_hash.clone()) else {
        return LoginOutcome::NotPassword;
    };
    match crate::password::verify(user, hash.clone(), form.username, form.password).await {
        crate::password::Verdict::Match => {}
        crate::password::Verdict::NoMatch => {
            Metrics::inc(&state.metrics.access_failures);
            return LoginOutcome::Retry(StatusCode::UNAUTHORIZED, "Wrong username or password.");
        }
        crate::password::Verdict::Busy => {
            return LoginOutcome::Retry(StatusCode::SERVICE_UNAVAILABLE, "The server is busy. Try again in a moment.");
        }
    }

    let ttl = state.config.limits.default_session_ttl_s as i64;
    let granted = state.db.login_grant(tunnel.id.clone(), hash, ttl, session_hashes(cookie_values)).await;
    let (session_id, expires_at) = match granted {
        Ok(Some(Redemption::Granted { session_id, expires_at })) => (session_id, expires_at),
        // The password or mode changed while we were checking.
        Ok(_) => return LoginOutcome::Retry(StatusCode::UNAUTHORIZED, "Wrong username or password."),
        Err(e) => {
            tracing::error!(tunnel = %tunnel.id, error = %e, "password login failed");
            return LoginOutcome::Internal;
        }
    };
    Metrics::inc(&state.metrics.access_redemptions);
    tracing::info!(tunnel = %tunnel.id, "password login");
    LoginOutcome::Granted(gate_cookie(&state.config.preview_zone, &session_id, expires_at - now()))
}

/// Same-host path to continue to after signing in; anything else becomes `/`.
pub fn safe_next(next: &str) -> String {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.starts_with("/__")
        && next.len() <= 2048
        && !next.chars().any(|c| c.is_control() || c == '\\');
    if ok { next.to_string() } else { "/".to_string() }
}

fn gate_cookie(zone: &str, value: &str, max_age: i64) -> String {
    format!(
        "{GATE_COOKIE}={value}; Domain={zone}; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age={}",
        max_age.max(0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_state() -> (std::sync::Arc<AppState>, tunnel_protocol::mux::Session) {
        let config = serde_json::from_value(serde_json::json!({
            "preview_zone": "previews.example.com", "api_host": "api.example.com",
            "tunnel_host": "tunnel.example.com", "turn_host": "turn.example.com",
            "admin_token_hash": "test-placeholder",
            "acme": {"email": "test@example.com"},
            "dns": {"provider": "cloudflare", "zone": "example.com"}
        }))
        .unwrap();
        let db = crate::db::Db::open(std::path::Path::new(":memory:")).unwrap();
        db.create_tunnel(
            crate::db::NewTunnel {
                id: "abcdefghij".into(),
                token_hash: "test-placeholder".into(),
                label: None,
                metadata: None,
                max_ports: 8,
                host_header: crate::db::HostHeaderMode::Rewrite,
                inject_ice: false,
                expires_at: now() + 86_400,
                access: crate::db::Access {
                    mode: crate::db::AccessMode::Password,
                    password_user: Some("test".into()),
                    password_hash: Some("test-placeholder".into()),
                },
                client_id: None,
            },
            20,
        )
        .await
        .unwrap();
        // CertStore only retains the path; these tests create no files.
        let certs = crate::tls::CertStore::new(std::env::temp_dir().join("tunnel-gate-tests-certs"));
        let state = AppState::new(config, db, certs);
        let (transport, _peer) = tokio::io::duplex(64);
        let session = tunnel_protocol::mux::Session::new_server(transport);
        let (ctrl_tx, _ctrl_rx) = tokio::sync::mpsc::channel(1);
        state.registry.insert(std::sync::Arc::new(crate::registry::LiveTunnel {
            conn_id: 1,
            tunnel_id: "abcdefghij".into(),
            control: session.control(),
            ports: Default::default(),
            ctrl_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            connected_at: now(),
            streams: Default::default(),
            pool: Default::default(),
            token_hash: String::new(),
        }));
        (state, session)
    }

    /// An authorization that presented only `hash`.
    fn held(hash: &str) -> Authorization {
        Authorization {
            session_hash: Some(hash.to_string()),
            candidates: [hash.to_string()].into(),
            expires_at: None,
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    async fn password_session(state: &AppState, ttl: i64) -> String {
        match state.db.login_grant("abcdefghij".into(), "test-placeholder".into(), ttl, vec![]).await.unwrap() {
            Some(Redemption::Granted { session_id, .. }) => session_id,
            _ => panic!("expected login grant"),
        }
    }

    #[tokio::test]
    async fn authorize_selects_longest_grant_across_cached_and_loaded_sessions() {
        let (state, _session) = test_state().await;
        let short = password_session(&state, 60).await;
        let long = password_session(&state, 3600).await;
        let short_hash = hash_token(&short);
        let long_hash = hash_token(&long);
        state.load_session_grants(vec![short_hash]).await.unwrap();
        let grant = authorize(&state, "abcdefghij", &[short.clone(), long.clone()], true).await.unwrap().unwrap();
        assert_eq!(grant.session_hash.as_deref(), Some(long_hash.as_str()));
        let expires_at = grant.expires_at;
        for values in [vec![long.clone(), short.clone()], vec![short.clone(), long.clone()]] {
            let grant = authorize(&state, "abcdefghij", &values, true).await.unwrap().unwrap();
            assert_eq!(grant.session_hash.as_deref(), Some(long_hash.as_str()));
            assert_eq!(grant.expires_at, expires_at);
        }
    }

    #[tokio::test]
    async fn authorize_cached_hit_skips_database_for_non_upgrade() {
        let (state, _session) = test_state().await;
        let login = password_session(&state, 3600).await;
        let login_hash = hash_token(&login);
        state.load_session_grants(vec![login_hash.clone()]).await.unwrap();
        // Make session queries fail: the cached ordinary request must still
        // succeed even with a plausible uncached cookie in either position.
        state
            .db
            .call(|c| {
                c.execute_batch("ALTER TABLE gate_sessions RENAME TO unavailable_gate_sessions")?;
                Ok(())
            })
            .await
            .unwrap();
        let stale = "stale-cookie-value".to_string();
        for values in [vec![stale.clone(), login.clone()], vec![login.clone(), stale]] {
            let grant = authorize(&state, "abcdefghij", &values, false).await.unwrap().unwrap();
            assert_eq!(grant.session_hash.as_deref(), Some(login_hash.as_str()));
            // Upgrades must query the missing values to find the longest grant.
            assert!(authorize(&state, "abcdefghij", &values, true).await.is_err());
        }
    }

    #[tokio::test]
    async fn reauthorize_keeps_password_session_when_tunnel_becomes_public() {
        let (state, _session) = test_state().await;
        let login = password_session(&state, 3600).await;
        let old = authorize(&state, "abcdefghij", &[login], true).await.unwrap().unwrap();
        // Populate the tunnel cache with the old password mode.
        state.tunnel("abcdefghij").await.unwrap();
        state
            .db
            .update_tunnel(
                "abcdefghij".into(),
                crate::db::TunnelPatch {
                    access: Some(crate::db::Access { mode: crate::db::AccessMode::Public, ..Default::default() }),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        state.invalidate_tunnel("abcdefghij");
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch("abcdefghij");
        assert!(old.cancel.is_cancelled());
        // Leaving password mode revoked this session, but public access wins.
        assert!(state.load_session_grants(vec![old.session_hash.clone().unwrap()]).await.unwrap().is_empty());
        let public = reauthorize(&state, "abcdefghij", &old).await.unwrap().unwrap();
        assert_eq!(public.session_hash, old.session_hash);
        assert_eq!(public.expires_at, None);
        assert!(!public.cancel.is_cancelled());
        state.registry.rotate_gate_epoch("abcdefghij");
        assert!(public.cancel.is_cancelled());
        let current = reauthorize(&state, "abcdefghij", &public).await.unwrap().unwrap();
        assert!(current.expires_at.is_none());
        assert!(!current.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn reauthorize_checks_own_session_without_cache_and_updates_expiry() {
        let (state, _session) = test_state().await;
        let login = password_session(&state, 3600).await;
        let login_hash = hash_token(&login);
        state
            .db
            .create_access_link(crate::db::NewAccessLink {
                id: "test-link".into(),
                tunnel_id: "abcdefghij".into(),
                token_hash: "test-link-placeholder".into(),
                single_use: false,
                label: None,
                session_ttl_s: 60,
                expires_at: now() + 600,
            })
            .await
            .unwrap();
        let Redemption::Granted { session_id: linked, .. } =
            state.db.redeem_access_link("abcdefghij".into(), "test-link-placeholder".into(), vec![]).await.unwrap()
        else {
            panic!("expected link grant");
        };
        let linked_hash = hash_token(&linked);
        let old = authorize(&state, "abcdefghij", &[login], true).await.unwrap().unwrap();
        authorize(&state, "abcdefghij", &[linked], true).await.unwrap().unwrap();
        state.db.delete_access_link("test-link".into()).await.unwrap();
        state.registry.rotate_gate_epoch("abcdefghij");
        assert!(old.cancel.is_cancelled());
        // Deliberately leave the session cache populated to verify the bypass.
        assert!(reauthorize(&state, "abcdefghij", &held(&linked_hash)).await.unwrap().is_none());
        let current = reauthorize(&state, "abcdefghij", &held(&login_hash)).await.unwrap().unwrap();
        assert_eq!(current.session_hash.as_deref(), Some(login_hash.as_str()));
        assert_eq!(current.expires_at, old.expires_at);
        assert!(!current.cancel.is_cancelled());

        let expiry = now() + 30;
        let hash = login_hash.clone();
        state
            .db
            .call(move |c| {
                c.execute(
                    "UPDATE gate_grants SET expires_at = ?2 WHERE session_hash = ?1",
                    rusqlite::params![hash, expiry],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        state.registry.rotate_gate_epoch("abcdefghij");
        assert_eq!(
            reauthorize(&state, "abcdefghij", &held(&login_hash)).await.unwrap().unwrap().expires_at,
            Some(expiry)
        );
        state.registry.remove("abcdefghij");
        assert!(reauthorize(&state, "abcdefghij", &held(&login_hash)).await.unwrap().is_none());
    }

    #[test]
    fn splits_gate_cookies_across_headers() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("a=1; __Secure-tunnel-gate=one"));
        h.append(header::COOKIE, HeaderValue::from_static("__Secure-tunnel-gate=two; b=2"));
        let c = split_cookies(&h);
        assert_eq!(c.values, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(c.forward.unwrap(), "a=1; b=2");
    }

    #[test]
    fn only_gate_cookie_forwards_nothing() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("__Secure-tunnel-gate=one"));
        assert!(split_cookies(&h).forward.is_none());
    }

    #[test]
    fn session_hashes_filter_dedupe_and_cap() {
        let real = "A".repeat(43);
        let values = vec!["garbage!".to_string(), real.clone(), "short".to_string(), real.clone()];
        assert_eq!(session_hashes(&values), vec![hash_token(&real)]);

        let many: Vec<String> = (0..MAX_GATE_VALUES + 10).map(|i| format!("{i:0>43}")).collect();
        assert_eq!(session_hashes(&many).len(), MAX_GATE_VALUES);
    }

    #[test]
    fn next_is_same_host_path_only() {
        assert_eq!(safe_next("/app?x=1"), "/app?x=1");
        for bad in ["", "https://evil.example", "//evil.example", "/\\evil.example", "/__access/x", "/a\\b", "app"] {
            assert_eq!(safe_next(bad), "/", "{bad}");
        }
    }

    #[test]
    fn cookie_attributes() {
        let c = gate_cookie("previews.example.com", "abc", 60);
        assert_eq!(
            c,
            "__Secure-tunnel-gate=abc; Domain=previews.example.com; Path=/; Secure; HttpOnly; SameSite=None; Partitioned; Max-Age=60"
        );
    }
}
