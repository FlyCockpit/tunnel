//! Sign-in on the zone host (`https://<preview_zone>/`): access-link
//! redemption and the password form.
//!
//! These pages handle secrets (link tokens, passwords), so they never run on a
//! preview origin: a preview app controls its own origin, including service
//! workers that could intercept a form or a link there. The zone host serves
//! no preview content, and the gate cookie is `Domain=<preview_zone>`, so a
//! session set here covers every preview.
//!
//! - `GET /__access/{port}-{id}/{token}` (or `/__access/{id}/{token}`): redeem,
//!   then go to `https://{port}-{id}.<zone>/`. Owner links (the web UI's
//!   Open) only through their own port; a repeat of the same request from
//!   the same address within seconds signs in again instead of failing.
//! - `GET /__login?to={port}-{id}&next=/path`: the form; `POST /__login`: sign in,
//!   then go to `https://{port}-{id}.<zone>/path`.

use std::net::SocketAddr;
use std::sync::Arc;

use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;

use crate::db::{AccessMode, TunnelLookup, TunnelRow};
use crate::edge::gate::{self, LoginOutcome};
use crate::edge::headers;
use crate::edge::pages::{self, LoginTarget};
use crate::state::AppState;
use crate::tokens::is_valid_tunnel_id;
use crate::util::{Body, text_response};

pub const ACCESS_PREFIX: &str = "/__access/";
pub const LOGIN_PATH: &str = "/__login";

/// Paths the zone host answers itself (everything else there is the API, or 404).
pub fn handles(path: &str) -> bool {
    path == LOGIN_PATH || path.starts_with(ACCESS_PREFIX)
}

/// `https://<zone>/__access/{target}/{token}` for a new link. `port` selects
/// which preview host the visitor lands on; without one, redemption picks the
/// lowest connected port.
pub fn access_url(zone: &str, tunnel_id: &str, port: Option<u16>, token: &str) -> String {
    match port {
        Some(p) => format!("https://{zone}{ACCESS_PREFIX}{p}-{tunnel_id}/{token}"),
        None => format!("https://{zone}{ACCESS_PREFIX}{tunnel_id}/{token}"),
    }
}

/// `https://<zone>/__login?to={label}&next={next}`.
pub fn login_url(zone: &str, label: &str, next: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("to", label)
        .append_pair("next", next)
        .finish();
    format!("https://{zone}{LOGIN_PATH}?{query}")
}

pub async fn handle(state: Arc<AppState>, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let resp = if let Some(rest) = path.strip_prefix(ACCESS_PREFIX) {
        access(&state, peer, rest, &req).await
    } else {
        login(&state, peer, req).await
    };
    tracing::info!(
        host = %state.config.preview_zone,
        path = if path == LOGIN_PATH { LOGIN_PATH } else { "/__access/[redacted]" },
        status = resp.status().as_u16(),
        "gate request"
    );
    resp
}

/// `{port}-{id}` or `{id}`.
fn parse_target(target: &str) -> Option<(Option<u16>, &str)> {
    if let Some((port, id)) = headers::parse_label(target) {
        return Some((Some(port), id));
    }
    is_valid_tunnel_id(target).then_some((None, target))
}

fn preview_origin(state: &AppState, port: u16, id: &str) -> String {
    format!("https://{}", state.preview_host(port, id))
}

async fn live_tunnel(state: &AppState, id: &str) -> Option<TunnelRow> {
    match &*state.tunnel(id).await.ok()? {
        TunnelLookup::Live(t) if !t.is_expired() => Some(t.clone()),
        _ => None,
    }
}

async fn access(state: &Arc<AppState>, peer: SocketAddr, rest: &str, req: &Request<Incoming>) -> Response<Body> {
    // Only a navigation redeems: a HEAD (link checkers, previews) must not
    // use up a single-use link.
    if *req.method() != Method::GET {
        return pages::not_found();
    }
    let Some((target, token)) = rest.split_once('/') else {
        return pages::not_found();
    };
    let Some((port, id)) = parse_target(target) else {
        return pages::not_found();
    };
    if token.is_empty() || token.contains('/') {
        return pages::not_found();
    }
    let named_port = port;
    let port = port.or_else(|| state.registry.get(id).and_then(|l| l.ports().first().copied()));
    let location = match port {
        Some(p) => format!("{}/", preview_origin(state, p, id)),
        None => String::new(),
    };
    let cookies = gate::split_cookies(req.headers());
    let resp = gate::redeem(state, peer.ip(), id, named_port, token, &cookies.values, &location).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        // A used or expired link still leads somewhere useful when the tunnel
        // has another way in. Unknown and ended tunnels keep the generic "link not valid" page.
        let mode = live_tunnel(state, id).await.map(|t| t.access.mode);
        return match (mode, port) {
            (Some(AccessMode::Password), Some(p)) => login_form(state, StatusCode::UNAUTHORIZED, p, id, "/", None),
            (Some(AccessMode::Public), Some(p)) => pages::redirect(&format!("{}/", preview_origin(state, p, id))),
            _ => resp,
        };
    }
    if resp.status() == StatusCode::FOUND && port.is_none() {
        return signed_in_offline(resp);
    }
    resp
}

/// Redeemed, but no port to send the visitor to: keep the cookie, explain.
fn signed_in_offline(redirect: Response<Body>) -> Response<Body> {
    let mut page = pages::offline_signed_in();
    if let Some(cookie) = redirect.headers().get(header::SET_COOKIE) {
        page.headers_mut().insert(header::SET_COOKIE, cookie.clone());
    }
    page
}

fn login_form(
    state: &AppState,
    status: StatusCode,
    port: u16,
    id: &str,
    next: &str,
    retry: Option<(&str, &str)>,
) -> Response<Body> {
    let (error, username) = retry.map_or((None, ""), |(message, username)| (Some(message), username));
    let to = format!("{port}-{id}");
    let origin = preview_origin(state, port, id);
    // An empty list restricts the zone-host gate page to its own origin too.
    let frame_sources = headers::frame_sources(&state.config.frame_ancestors);
    pages::login(
        status,
        &LoginTarget { to: &to, next, preview_origin: &origin, frame_sources: &frame_sources },
        error,
        username,
    )
}

async fn login(state: &Arc<AppState>, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    match *req.method() {
        Method::GET | Method::HEAD => {
            let (mut to, mut next) = (String::new(), String::new());
            for (k, v) in url::form_urlencoded::parse(req.uri().query().unwrap_or_default().as_bytes()) {
                match &*k {
                    "to" => to = v.into_owned(),
                    "next" => next = v.into_owned(),
                    _ => {}
                }
            }
            let Some((port, id)) = headers::parse_label(&to) else {
                return pages::not_found();
            };
            match live_tunnel(state, id).await {
                Some(t) if t.access.mode == AccessMode::Password => {
                    login_form(state, StatusCode::OK, port, id, &gate::safe_next(&next), None)
                }
                Some(_) => pages::redirect(&format!("{}{}", preview_origin(state, port, id), gate::safe_next(&next))),
                None => pages::not_found(),
            }
        }
        Method::POST => {
            let cookies = gate::split_cookies(req.headers());
            let form = match gate::read_login_form(req.into_body()).await {
                Ok(f) => f,
                Err((status, msg)) => return pages::bad_form(status, msg),
            };
            let Some((port, id)) = headers::parse_label(&form.to) else {
                return pages::not_found();
            };
            let id = id.to_string();
            let Some(tunnel) = live_tunnel(state, &id).await.filter(|t| t.access.mode == AccessMode::Password) else {
                return pages::not_found();
            };
            let next = form.next.clone();
            let username = form.username.clone();
            match gate::login(state, peer.ip(), &tunnel, form, &cookies.values).await {
                LoginOutcome::Granted(cookie) => {
                    let mut resp = pages::redirect(&format!("{}{next}", preview_origin(state, port, &id)));
                    *resp.status_mut() = StatusCode::SEE_OTHER;
                    if let Ok(v) = HeaderValue::from_str(&cookie) {
                        resp.headers_mut().insert(header::SET_COOKIE, v);
                    }
                    resp
                }
                LoginOutcome::Retry(status, msg) => login_form(state, status, port, &id, &next, Some((msg, &username))),
                LoginOutcome::RateLimited => pages::rate_limited(),
                LoginOutcome::NotPassword => pages::not_found(),
                LoginOutcome::Internal => text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            }
        }
        _ => pages::not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "abcdefghij";

    #[test]
    fn targets() {
        assert_eq!(parse_target("3000-abcdefghij"), Some((Some(3000), ID)));
        assert_eq!(parse_target(ID), Some((None, ID)));
        assert_eq!(parse_target("03000-abcdefghij"), None);
        assert_eq!(parse_target("x"), None);
    }

    #[test]
    fn urls() {
        assert_eq!(
            access_url("z.example", ID, Some(5173), "tnacc_t"),
            "https://z.example/__access/5173-abcdefghij/tnacc_t"
        );
        assert_eq!(access_url("z.example", ID, None, "tnacc_t"), "https://z.example/__access/abcdefghij/tnacc_t");
        assert_eq!(
            login_url("z.example", "3000-abcdefghij", "/a?b=1&c"),
            "https://z.example/__login?to=3000-abcdefghij&next=%2Fa%3Fb%3D1%26c"
        );
    }

    #[test]
    fn routes() {
        assert!(handles("/__login"));
        assert!(handles("/__access/3000-abcdefghij/tnacc_x"));
        assert!(!handles("/__loginx"));
        assert!(!handles("/v1/tunnels"));
    }

    #[tokio::test]
    async fn wrong_password_post_keeps_username_but_never_password() {
        use http_body_util::BodyExt;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let state = crate::listener::tests::test_state(&[]);
        crate::listener::tests::create_tunnel(&state, AccessMode::Password).await;
        let (client, server) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let state = state.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(handle(state, "127.0.0.1:1234".parse().unwrap(), request).await)
                }
            });
            hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(server), service).await.unwrap();
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(connection);
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("to", "3000-abcdefghij")
            .append_pair("next", "/app")
            .append_pair("username", "<\"&")
            .append_pair("password", "never-echo-this-password")
            .finish();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/__login")
            .header(header::HOST, "previews.example.com")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(crate::util::full(form))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("name=\"username\" value=\"&lt;&quot;&amp;\""), "{html}");
        assert!(!html.contains("never-echo-this-password"));
        assert!(html.contains("Wrong username or password"));
    }

    #[test]
    fn gate_form_parent_policy() {
        for (parents, expected) in [
            (vec![], "frame-ancestors 'self'"),
            (vec!["*"], "frame-ancestors *"),
            (vec!["https://app.example.com"], "frame-ancestors 'self' https://app.example.com"),
        ] {
            let state = crate::listener::tests::test_state(&parents);
            let response = login_form(&state, StatusCode::OK, 3000, ID, "/", None);
            assert!(response.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().ends_with(expected));
        }
    }
}
