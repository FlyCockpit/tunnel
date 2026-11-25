//! Web UI on `ui_host`: the single-page app, its cookie-authenticated JSON
//! API under `/ui/api/*`, the CLI install scripts, and (on the same host)
//! the bearer API under `/v1/*`.
//!
//! Previews can be same-site with the UI, and members' previews run code
//! anyone wrote, so every `/ui/api/*` request, signed in or not, must:
//! - carry `X-Tunnel-CSRF` (a custom header forces a CORS preflight, which
//!   this server never grants; writes in a session need the session's token);
//! - have `Origin` exactly `https://<ui_host>` (required except on GET/HEAD);
//! - have `Sec-Fetch-Site: same-origin` when the browser sends it.
//!
//! The session cookie is `__Host-tunnel-ui` (host-only, `Secure`, `HttpOnly`,
//! `SameSite=Strict`), never sent to preview hosts. The bearer API ignores it.

pub mod assets;
mod handlers;
pub mod totp;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};

use axum::Router;
use axum::extract::FromRequestParts;
use http::request::Parts;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::accounts::{Session, User};
use crate::api::{self, ApiError, PeerAddr};
use crate::headers::UI_COOKIE;
use crate::state::AppState;
use crate::tokens;
use crate::util::{Body, full};

pub use handlers::{INVITE_PREFIX, OWNER_LINK_TTL_S};

pub const CSRF_HEADER: &str = "x-tunnel-csrf";
/// Sensitive steps (approving a machine) need a password or TOTP check this recent.
pub const REAUTH_S: i64 = 10 * 60;

static ROUTER: LazyLock<Router<Arc<AppState>>> = LazyLock::new(handlers::router);

/// Everything on `ui_host`.
pub async fn handle<B>(state: Arc<AppState>, peer: SocketAddr, mut req: Request<B>) -> Response<Body>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<crate::util::BoxError>,
{
    req.extensions_mut().insert(PeerAddr(peer));
    let path = req.uri().path().to_string();
    if path.starts_with("/v1/") || path == "/healthz" {
        return api::handle(state, req).await;
    }
    if path == "/install.sh" || path == "/install.ps1" {
        return assets::install_script(&state, &path, req.method());
    }
    let mut resp = if path == "/ui/api" || path.starts_with("/ui/api/") {
        ui_api(state, req).await
    } else {
        assets::serve(&path, req.method(), req.headers())
    };
    security_headers(resp.headers_mut());
    resp
}

async fn ui_api<B>(state: Arc<AppState>, req: Request<B>) -> Response<Body>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<crate::util::BoxError>,
{
    let Some(ui_host) = state.config.ui_host.clone() else {
        return error_response(ApiError::not_found("route"));
    };
    if let Err(e) = check_request(req.method(), req.headers(), &ui_host) {
        return error_response(e);
    }
    let router: Router = ROUTER.clone().with_state(state);
    let resp = match router.oneshot(req.map(axum::body::Body::new)).await {
        Ok(resp) => resp,
        Err(never) => match never {},
    };
    let (parts, body) = resp.into_parts();
    let mut resp = match body.collect().await {
        Ok(collected) => Response::from_parts(parts, full(collected.to_bytes())),
        Err(e) => return error_response(ApiError::internal(anyhow::anyhow!("collecting ui response: {e}"))),
    };
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn error_response(e: ApiError) -> Response<Body> {
    use axum::response::IntoResponse;
    let (parts, body) = e.into_response().into_parts();
    let bytes = futures_util::FutureExt::now_or_never(body.collect())
        .and_then(Result::ok)
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let mut resp = Response::from_parts(parts, full(bytes));
    // Cookie-authenticated routes never ask for a bearer token.
    resp.headers_mut().remove(header::WWW_AUTHENTICATE);
    resp
}

fn forbidden(code: &'static str, message: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, code, message)
}

/// The cross-site and same-site defenses every `/ui/api/*` request passes.
pub fn check_request(method: &Method, headers: &HeaderMap, ui_host: &str) -> Result<(), ApiError> {
    let safe = matches!(*method, Method::GET | Method::HEAD);
    if !safe && !matches!(*method, Method::POST | Method::PATCH | Method::DELETE | Method::PUT) {
        return Err(forbidden("method", "method not allowed"));
    }
    if headers.get(CSRF_HEADER).is_none_or(|v| v.is_empty()) {
        return Err(forbidden("csrf", "missing X-Tunnel-CSRF header"));
    }
    match headers.get(header::ORIGIN) {
        Some(origin) => {
            let expected = format!("https://{ui_host}");
            if !origin.as_bytes().eq_ignore_ascii_case(expected.as_bytes()) {
                return Err(forbidden("origin", "cross-origin request refused"));
            }
        }
        None if !safe => return Err(forbidden("origin", "missing Origin header")),
        None => {}
    }
    if let Some(site) = headers.get("sec-fetch-site")
        && site.as_bytes() != b"same-origin"
    {
        return Err(forbidden("origin", "cross-site request refused"));
    }
    Ok(())
}

/// Headers for the SPA and its API: no framing, no inline script, nothing
/// loaded from elsewhere.
fn security_headers(h: &mut HeaderMap) {
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; \
             object-src 'none'",
        ),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=()"));
}

/// Session cookie values the browser sent (a preview cannot set this
/// host-only cookie, but be strict about what counts as plausible).
fn cookie_values(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else { continue };
        for pair in value.split(';') {
            if let Some((name, v)) = pair.trim().split_once('=')
                && name.trim() == UI_COOKIE
            {
                let v = v.trim();
                if v.len() == 43 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                    out.push(v.to_string());
                }
            }
        }
    }
    out.truncate(3);
    out
}

pub fn session_cookie(id: &str, max_age: i64) -> String {
    format!("{UI_COOKIE}={id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}", max_age.max(0))
}

pub fn clear_cookie() -> String {
    format!("{UI_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

fn peer_ip(parts: &Parts) -> Option<IpAddr> {
    parts.extensions.get::<PeerAddr>().map(|p| p.0.ip())
}

/// Request context: client address, user agent, and the session if any.
pub struct Ctx {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    /// `(plaintext id, session)`.
    pub session: Option<(String, Session)>,
    pub method: Method,
    pub csrf_header: Option<String>,
}

impl Ctx {
    pub fn ip_string(&self) -> Option<String> {
        self.ip.map(|i| i.to_string())
    }
}

impl FromRequestParts<Arc<AppState>> for Ctx {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let mut session = None;
        for id in cookie_values(&parts.headers) {
            if let Some(s) = state.db.ui_session(tokens::hash_token(&id)).await? {
                session = Some((id, s));
                break;
            }
        }
        Ok(Self {
            ip: peer_ip(parts),
            user_agent: parts
                .headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.chars().take(200).collect()),
            session,
            method: parts.method.clone(),
            csrf_header: parts.headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string),
        })
    }
}

/// A signed-in (not pending) session; writes carry its CSRF token.
pub struct Signed {
    pub ctx: Ctx,
    pub session: Session,
}

impl Signed {
    pub fn user(&self) -> &User {
        &self.session.user
    }
}

impl FromRequestParts<Arc<AppState>> for Signed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let mut ctx = Ctx::from_request_parts(parts, state).await?;
        let Some((id, session)) = ctx.session.take().filter(|(_, s)| !s.pending) else {
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, "signed_out", "sign in first"));
        };
        if !matches!(ctx.method, Method::GET | Method::HEAD) {
            let keys = state.ui.keys.as_ref().ok_or_else(|| ApiError::not_found("route"))?;
            let expected = keys.csrf_token(&id);
            let ok = ctx.csrf_header.as_deref().is_some_and(|got| tokens::hashes_equal(got, &expected));
            if !ok {
                return Err(forbidden("csrf", "missing or stale CSRF token; reload the page"));
            }
        }
        Ok(Self { ctx, session })
    }
}

/// A signed-in owner or admin.
pub struct AdminSigned(pub Signed);

impl FromRequestParts<Arc<AppState>> for AdminSigned {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let signed = Signed::from_request_parts(parts, state).await?;
        if !signed.user().role.is_admin() {
            return Err(forbidden("admin_only", "only admins can do this"));
        }
        Ok(Self(signed))
    }
}

#[cfg(test)]
mod tests;
