//! Visitor-facing edge for `*.<preview_zone>`.
//!
//! Order: label → reserved `/__access/*` and `/__login` (404) → tunnel lifecycle → gate (with the CORS preflight
//! exception; skipped for public tunnels; pages on password tunnels go to the
//! zone-host login) → `/__tunnel/*` → live port → proxy. Reserved paths are never forwarded, and the origin is
//! never contacted for a request that fails the gate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http::header::{self, HeaderMap};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body::Body as HttpBody;
use hyper::body::Incoming;

use crate::db::{AccessMode, TunnelLookup, TunnelRow};
use crate::gate;
use crate::gatehost;
use crate::headers;
use crate::ice;
use crate::pages;
use crate::proxy;
use crate::state::AppState;
use crate::util::{Body, header_str, json_response, text_response};

const ACCESS_PREFIX: &str = "/__access";
const TUNNEL_PREFIX: &str = "/__tunnel";
const LOGIN_PATH: &str = "/__login";
/// TURN username subject for visitors of a public tunnel (no session).
const PUBLIC_SUBJECT: &str = "public";
const ICE_PATH: &str = "/__tunnel/ice";
/// Gate-session hash prefix used as the TURN username subject (relay log attribution).
const SUBJECT_LEN: usize = 8;
/// The only request headers an unauthenticated preflight carries to the
/// origin. A real preflight has no body and no credentials; anything else a
/// client adds is dropped so the exception cannot carry an ordinary request.
const PREFLIGHT_HEADERS: &[&str] = &[
    "host",
    "origin",
    "referer",
    "user-agent",
    "accept",
    "accept-language",
    "access-control-request-method",
    "access-control-request-headers",
    "access-control-request-private-network",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-dest",
];

/// `label` is the request host minus `.<preview_zone>`, e.g. `3000-ab12cd3efg`.
pub async fn handle(state: Arc<AppState>, peer: SocketAddr, label: &str, req: Request<Incoming>) -> Response<Body> {
    state.metrics.request();
    let started = Instant::now();
    let method = req.method().clone();
    let path = log_path(req.uri().path());
    let resp = route(&state, peer, label, req).await;
    tracing::info!(
        host = %format_args!("{label}.{}", state.config.preview_zone),
        method = %method,
        path = %path,
        status = resp.status().as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "edge request"
    );
    resp
}

async fn route(state: &Arc<AppState>, peer: SocketAddr, label: &str, req: Request<Incoming>) -> Response<Body> {
    let Some((port, id)) = headers::parse_label(label) else {
        return pages::not_found();
    };
    let path = req.uri().path().to_string();
    let cookies = gate::split_cookies(req.headers());

    // Secrets are accepted only on the zone host. Keep the preview paths
    // reserved so neither old links nor login forms reach the sandbox app.
    if is_under(&path, ACCESS_PREFIX) || path == LOGIN_PATH {
        return pages::not_found();
    }

    // Capture before reading the access mode so a concurrent PATCH cannot
    // leave a public request watching an epoch newer than the row it read.
    let public_epoch = state.registry.gate_epoch(id);
    let upgrade = proxy::is_websocket(&req);
    let lookup = match state.tunnel(id).await {
        Ok(l) => l,
        Err(e) => return internal_error(id, e),
    };
    let tunnel = match &*lookup {
        TunnelLookup::Live(t) if !t.is_expired() => t,
        TunnelLookup::Live(_) | TunnelLookup::Tombstoned => return pages::ended(),
        TunnelLookup::Unknown => return pages::not_found(),
    };

    let mode = tunnel.access.mode;
    // Public tunnels have no gate or cookie-granted authority, so presented
    // cookies need no lookup and the authenticated-origin check does not apply.
    let authorization = if mode == AccessMode::Public {
        Some(gate::Authorization {
            session_hash: None,
            candidates: Default::default(),
            expires_at: None,
            cancel: public_epoch,
        })
    } else {
        match gate::authorize(state, id, &cookies.values, upgrade).await {
            Ok(s) => s,
            Err(e) => return internal_error(id, e),
        }
    };
    // Cookie partitioning does not protect WebSockets from an external iframe
    // sharing the preview's top-level site. Require an explicitly trusted origin.
    if mode != AccessMode::Public
        && authorization.is_some()
        && is_forbidden_origin_write(&req, &state.config.preview_zone, id, &state.config.frame_ancestors)
    {
        state.metrics.gate_denied();
        return pages::forbidden_origin();
    }
    let reserved = is_under(&path, TUNNEL_PREFIX);

    let subject = match authorization.as_ref().and_then(|grant| grant.session_hash.as_ref()) {
        Some(hash) => hash[..SUBJECT_LEN].to_string(),
        None if mode == AccessMode::Public => PUBLIC_SUBJECT.to_string(),
        None => {
            let page = wants_page(&req);
            let login_next = (mode == AccessMode::Password && page)
                .then(|| req.uri().path_and_query().map(|p| gate::safe_next(p.as_str())).unwrap_or_default());
            let json = !page && accepts_json(&req);
            if !reserved && is_same_tunnel_preflight(&req, &state.config.preview_zone, id) {
                // Preflights never carry credentials; forward without any cookie.
                // Still watched: any gate epoch rotation (a revoked link, a
                // traffic cap reached) cuts a preflight response in flight.
                if let Some(req) = preflight_only(req) {
                    let watch = gate::Authorization {
                        session_hash: None,
                        candidates: Default::default(),
                        expires_at: None,
                        cancel: state.registry.gate_epoch(id),
                    };
                    return forward_live(state, tunnel, port, req, None, peer, None, Some(watch)).await;
                }
            }
            state.metrics.gate_denied();
            if let Some(next) = login_next {
                return pages::redirect(&gatehost::login_url(&state.config.preview_zone, label, &next));
            }
            if mode == AccessMode::Password {
                // Not a page load, so no redirect: say where a person signs in.
                return pages::password_required(&gatehost::login_url(&state.config.preview_zone, label, "/"), json);
            }
            return pages::unauthorized();
        }
    };

    if reserved {
        let method_ok = *req.method() == Method::GET || *req.method() == Method::HEAD;
        if path == ICE_PATH && method_ok && state.config.webrtc.enabled {
            let ice = ice::mint(&state.config, id, &subject, state.config.webrtc.browser_ttl_s);
            return json_response(StatusCode::OK, &ice);
        }
        return pages::not_found();
    }

    forward_live(state, tunnel, port, req, cookies.forward, peer, Some(subject), authorization).await
}

/// Gate-authenticated WebSocket upgrades and writes require a trusted Origin.
/// Absent origins allow non-browser clients; ordinary reads still use CORS.
fn is_forbidden_origin_write<B>(req: &Request<B>, zone: &str, tunnel_id: &str, parents: &[String]) -> bool {
    let method = req.method();
    let is_ws = req.headers().contains_key(header::UPGRADE) || *method == Method::CONNECT;
    if !is_ws && matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    let mut origins = req.headers().get_all(header::ORIGIN).iter();
    match origins.next() {
        None => false,
        Some(origin) => {
            if origins.next().is_some() {
                return true;
            }
            let Some(origin) = origin.to_str().ok() else { return true };
            if origin_is_allowed(origin, zone, tunnel_id, parents) {
                return false;
            }
            // A top-level form submission from an unrelated site (e.g. an OAuth
            // `form_post` callback) leaves that site, so it cannot be driven from
            // a frame nested in another preview; keep allowing it. Other previews,
            // the zone host and opaque origins stay refused.
            !(!is_ws && is_top_level_navigation(req) && is_external_origin(origin, zone))
        }
    }
}

/// `Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document`: the browser is
/// replacing the top-level page (never an iframe, fetch or subresource).
fn is_top_level_navigation<B>(req: &Request<B>) -> bool {
    header_str(req.headers().get("sec-fetch-mode")) == Some("navigate")
        && header_str(req.headers().get("sec-fetch-dest")) == Some("document")
}

/// A well-formed origin outside the preview zone (not the zone host, not any
/// preview, not `null`).
fn is_external_origin(origin: &str, zone: &str) -> bool {
    let Some(origin) = parse_origin(origin) else { return false };
    let host = origin.host_str().unwrap_or_default().trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.to_ascii_lowercase();
    host != zone && !host.ends_with(&format!(".{zone}"))
}

/// Parse a serialized HTTP(S) origin, rejecting URL credentials, paths and
/// opaque origins instead of treating a malformed header as a missing one.
fn parse_origin(origin: &str) -> Option<url::Url> {
    let (_, authority) = origin.split_once("://")?;
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\'])
        || origin.bytes().any(|b| b.is_ascii_whitespace())
    {
        return None;
    }
    let url = url::Url::parse(origin).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then_some(url)
}

fn origin_is_allowed(origin: &str, zone: &str, tunnel_id: &str, parents: &[String]) -> bool {
    let Some(origin) = parse_origin(origin) else {
        return false;
    };
    let host = origin.host_str().unwrap_or_default().trim_end_matches('.');
    let zone = zone.to_ascii_lowercase();
    let suffix = format!(".{zone}");
    if host.strip_suffix(&suffix).and_then(headers::parse_label).is_some_and(|(_, id)| id == tunnel_id) {
        return true;
    }
    // Parent wildcards must never grant cookie authority to another preview
    // (or to the zone host), even when they cover the entire preview zone.
    if host == zone || host.ends_with(&suffix) {
        return false;
    }
    parents.iter().any(|source| parent_origin_matches(&origin, source))
}

fn parent_origin_matches(origin: &url::Url, source: &str) -> bool {
    // `*` permits arbitrary framing, never arbitrary cookie-authenticated
    // WebSocket origins. Only concrete origins and host wildcards opt in.
    let Some((scheme, authority)) = source.split_once("://") else { return false };
    let wildcard = authority.starts_with("*.");
    let authority = authority.strip_prefix("*.").unwrap_or(authority);
    let any_port = authority.ends_with(":*");
    let authority = authority.strip_suffix(":*").unwrap_or(authority);
    let Some(parent) = parse_origin(&format!("{scheme}://{authority}")) else { return false };
    if origin.scheme() != parent.scheme()
        || (!any_port && origin.port_or_known_default() != parent.port_or_known_default())
    {
        return false;
    }
    let host = origin.host_str().unwrap_or_default();
    let parent_host = parent.host_str().unwrap_or_default();
    if wildcard {
        host.strip_suffix(parent_host).is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
    } else {
        host == parent_host
    }
}

/// A browser loading a page (top level or in an iframe), as opposed to a
/// fetch, script, or image, which should get a plain 401 rather than a form.
fn wants_page(req: &Request<Incoming>) -> bool {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return false;
    }
    match header_str(req.headers().get("sec-fetch-dest")) {
        Some(dest) => matches!(dest, "document" | "iframe" | "frame"),
        None => header_str(req.headers().get(header::ACCEPT)).is_some_and(|a| a.contains("text/html")),
    }
}

/// The client prefers JSON (`Accept: application/json`, not HTML).
fn accepts_json<B>(req: &Request<B>) -> bool {
    header_str(req.headers().get(header::ACCEPT))
        .is_some_and(|a| a.contains("application/json") && !a.contains("text/html"))
}

/// Only ports the connected client declared are routable; anything else is
/// "offline" and never reaches the sandbox.
#[allow(clippy::too_many_arguments)]
async fn forward_live(
    state: &Arc<AppState>,
    tunnel: &TunnelRow,
    port: u16,
    req: Request<Incoming>,
    cookie: Option<HeaderValue>,
    peer: SocketAddr,
    session_subject: Option<String>,
    authorization: Option<gate::Authorization>,
) -> Response<Body> {
    let Some(live) = state.registry.get(&tunnel.id).filter(|l| l.has_port(port)) else {
        return pages::offline();
    };
    // After the gate, so only visitors with access learn of it, and refused
    // requests are never counted.
    let bytes = match state.traffic.counter(&state.db, tunnel).await {
        Ok(bytes) => bytes,
        // Never relayed uncounted: without the owner's usage, no cap could apply.
        Err(e) => {
            tracing::warn!(tunnel = %tunnel.id, error = %format!("{e:#}"), "loading traffic usage failed");
            return pages::server_busy();
        }
    };
    if bytes.blocked() {
        return pages::traffic_limit();
    }
    proxy::forward(state, tunnel, live, port, req, cookie, peer, session_subject, authorization, bytes).await
}

/// CORS preflight from another `{port}-{id}` host of the same tunnel.
fn is_same_tunnel_preflight<B>(req: &Request<B>, zone: &str, tunnel_id: &str) -> bool {
    *req.method() == Method::OPTIONS
        && req.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
        && header_str(req.headers().get(header::ORIGIN))
            .and_then(|o| headers::same_tunnel_origin_port(o, zone, tunnel_id))
            .is_some()
}

/// Reduce a same-tunnel preflight to what a browser preflight carries, or
/// `None` if it has a body (no real preflight does).
fn preflight_only<B: HttpBody>(mut req: Request<B>) -> Option<Request<B>> {
    let declared_body = req.headers().contains_key(header::TRANSFER_ENCODING)
        || header_str(req.headers().get(header::CONTENT_LENGTH)).is_some_and(|l| l.trim() != "0");
    // hyper 1.x `Incoming::is_end_stream()` is true for an h1 request without
    // a body and for an h2 request whose HEADERS frame ended the stream.
    if declared_body || !req.body().is_end_stream() {
        return None;
    }
    let all = std::mem::take(req.headers_mut());
    let mut kept = HeaderMap::new();
    for &name in PREFLIGHT_HEADERS {
        for value in all.get_all(name) {
            kept.append(name, value.clone());
        }
    }
    *req.headers_mut() = kept;
    Some(req)
}

/// `path` is `prefix` itself or below it.
fn is_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Access tokens live in the path; never log them. Long paths are truncated.
fn log_path(path: &str) -> String {
    if is_under(path, ACCESS_PREFIX) {
        return "/__access/[redacted]".to_string();
    }
    path.chars().take(200).collect()
}

fn internal_error(tunnel_id: &str, e: anyhow::Error) -> Response<Body> {
    if e.is::<crate::state::LookupsBusy>() {
        return pages::server_busy();
    }
    tracing::error!(tunnel = tunnel_id, error = %e, "edge lookup failed");
    text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_origins() {
        let z = "tunnel.example.com";
        for origin in [
            "https://3000-abcdefghij.tunnel.example.com",
            "https://5173-abcdefghij.tunnel.example.com:443",
            "https://5173-abcdefghij.tunnel.example.com:8443",
            "http://3000-abcdefghij.tunnel.example.com",
        ] {
            assert!(origin_is_allowed(origin, z, "abcdefghij", &[]), "{origin}");
        }
        for origin in [
            "https://3000-zzzzzzzzzz.tunnel.example.com",
            "https://tunnel.example.com",
            "https://turn.tunnel.example.com",
            "null",
            "https://app.client.com",
            "https://example.com",
            "https://3000-abcdefghij.tunnel.example.com/path",
            "https://user@3000-abcdefghij.tunnel.example.com",
            "https://3000-abcdefghij.tunnel.example.com https://example.com",
        ] {
            assert!(!origin_is_allowed(origin, z, "abcdefghij", &[]), "{origin}");
            assert!(!origin_is_allowed(origin, z, "abcdefghij", &["*".into()]), "{origin}");
        }
    }

    #[test]
    fn parent_patterns_cannot_admit_other_preview_zone_hosts() {
        let zone = "previews.example.com";
        let parents = vec!["https://*.example.com".into(), "https://app.client.com".into()];
        for origin in [
            "https://3000-zzzzzzzzzz.previews.example.com",
            "https://previews.example.com",
            "https://previews.example.com.",
            "https://turn.previews.example.com",
            "https://nested.3000-abcdefghij.previews.example.com",
        ] {
            assert!(!origin_is_allowed(origin, zone, "abcdefghij", &parents), "{origin}");
            let ws = Request::builder()
                .header(header::UPGRADE, "websocket")
                .header(header::ORIGIN, origin)
                .body(())
                .unwrap();
            assert!(is_forbidden_origin_write(&ws, zone, "abcdefghij", &parents), "{origin}");
            assert!(!origin_is_allowed(origin, zone, "abcdefghij", &[origin.into()]), "{origin}");
        }
        for origin in [
            "https://app.example.com",
            "https://app.client.com",
            "https://3000-abcdefghij.previews.example.com",
            "https://5173-abcdefghij.previews.example.com:8443",
            "http://3000-abcdefghij.previews.example.com",
        ] {
            assert!(origin_is_allowed(origin, zone, "abcdefghij", &parents), "{origin}");
        }
    }

    #[test]
    fn configured_origin_matching() {
        let allowed =
            |origin, source: &str| origin_is_allowed(origin, "tunnel.example.com", "abcdefghij", &[source.into()]);
        for (origin, source) in [
            ("https://app.example.com", "https://app.example.com"),
            ("https://APP.example.com:443", "https://app.example.com"),
            ("https://app.example.com", "https://app.example.com:443"),
            ("https://app.example.com:8443", "https://app.example.com:8443"),
            ("https://app.example.com", "https://*.example.com"),
            ("https://nested.app.example.com", "https://*.example.com"),
            ("https://app.example.com:8443", "https://*.example.com:8443"),
            ("https://app.example.com:8443", "https://*.example.com:*"),
        ] {
            assert!(allowed(origin, source), "{origin} / {source}");
        }
        for (origin, source) in [
            ("http://app.example.com", "https://app.example.com"),
            ("https://app.example.com", "http://app.example.com"),
            ("https://app.example.com:8443", "https://app.example.com"),
            ("https://app.example.com", "https://app.example.com:8443"),
            ("https://example.com", "https://*.example.com"),
            ("https://evilexample.com", "https://*.example.com"),
            ("https://app.example.com.evil.com", "https://*.example.com"),
            ("https://app.example.com", "https://app.example.com/path"),
            ("null", "null"),
            ("https://app.example.com", "https:"),
        ] {
            assert!(!allowed(origin, source), "{origin} / {source}");
        }
    }

    #[test]
    fn origin_check_scope() {
        let blocked = |req: &Request<()>| is_forbidden_origin_write(req, "tunnel.example.com", "abcdefghij", &[]);
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            let req = Request::builder().method(method).header(header::ORIGIN, "https://evil.com").body(()).unwrap();
            assert!(!blocked(&req));
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::CONNECT] {
            let req =
                Request::builder().method(method.clone()).header(header::ORIGIN, "https://evil.com").body(()).unwrap();
            assert!(blocked(&req));
            assert!(!blocked(&Request::builder().method(method).body(()).unwrap()));
        }
        let mut ws = Request::builder()
            .header(header::UPGRADE, "websocket")
            .header(header::ORIGIN, "https://evil.com")
            .body(())
            .unwrap();
        assert!(blocked(&ws));
        ws.headers_mut().remove(header::ORIGIN);
        assert!(!blocked(&ws));
        ws.headers_mut().insert(header::ORIGIN, HeaderValue::from_bytes(b"\xff").unwrap());
        assert!(blocked(&ws));
        ws.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://3000-abcdefghij.tunnel.example.com"));
        ws.headers_mut().append(header::ORIGIN, HeaderValue::from_static("https://evil.com"));
        assert!(blocked(&ws));
    }

    #[test]
    fn top_level_form_posts_from_external_sites_pass() {
        let blocked = |origin: &'static str, mode: &'static str, dest: &'static str| {
            let req = Request::builder()
                .method(Method::POST)
                .header(header::ORIGIN, origin)
                .header("sec-fetch-mode", mode)
                .header("sec-fetch-dest", dest)
                .body(())
                .unwrap();
            is_forbidden_origin_write(&req, "tunnel.example.com", "abcdefghij", &[])
        };
        // OAuth-style form_post callback replacing the top-level page.
        assert!(!blocked("https://idp.example.org", "navigate", "document"));
        // The same from a frame, or as a fetch, stays refused.
        assert!(blocked("https://idp.example.org", "navigate", "iframe"));
        assert!(blocked("https://idp.example.org", "cors", "empty"));
        // Other previews, the zone host and opaque origins stay refused even at top level.
        assert!(blocked("https://3000-zzzzzzzzzz.tunnel.example.com", "navigate", "document"));
        assert!(blocked("https://tunnel.example.com", "navigate", "document"));
        assert!(blocked("null", "navigate", "document"));
        // WebSockets never get the exception.
        let ws = Request::builder()
            .header(header::UPGRADE, "websocket")
            .header(header::ORIGIN, "https://idp.example.org")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .body(())
            .unwrap();
        assert!(is_forbidden_origin_write(&ws, "tunnel.example.com", "abcdefghij", &[]));
    }

    #[test]
    fn reserved_prefixes() {
        assert!(is_under("/__access/tnacc_x", ACCESS_PREFIX));
        assert!(is_under("/__access", ACCESS_PREFIX));
        assert!(!is_under("/__accessible", ACCESS_PREFIX));
        assert!(is_under("/__tunnel/ice", TUNNEL_PREFIX));
    }

    #[test]
    fn redacts_tokens() {
        assert_eq!(log_path("/__access/tnacc_secret"), "/__access/[redacted]");
        assert_eq!(log_path("/a/b"), "/a/b");
    }

    #[test]
    fn preflight_detection() {
        let zone = "previews.example.com";
        let req = |origin: &'static str| {
            Request::builder()
                .method(Method::OPTIONS)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ORIGIN, origin)
                .body(())
                .unwrap()
        };
        assert!(is_same_tunnel_preflight(&req("https://3000-abcdefghij.previews.example.com"), zone, "abcdefghij"));
        assert!(!is_same_tunnel_preflight(&req("https://3000-zzzzzzzzzz.previews.example.com"), zone, "abcdefghij"));
    }

    #[test]
    fn preflight_is_reduced() {
        use bytes::Bytes;
        use http_body_util::{Empty, Full};

        let req = Request::builder()
            .method(Method::OPTIONS)
            .header(header::ORIGIN, "https://3000-abcdefghij.previews.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::AUTHORIZATION, "Bearer x")
            .header("x-custom", "1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let out = preflight_only(req).unwrap();
        assert!(out.headers().contains_key(header::ORIGIN));
        assert!(out.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD));
        assert!(!out.headers().contains_key(header::AUTHORIZATION));
        assert!(!out.headers().contains_key("x-custom"));

        let with_body = Request::builder().method(Method::OPTIONS).body(Full::new(Bytes::from_static(b"x"))).unwrap();
        assert!(preflight_only(with_body).is_none());
    }
}
