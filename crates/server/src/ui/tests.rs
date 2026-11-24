//! End-to-end tests of the web UI's JSON API, the device flow and the
//! multi-user rules on `/v1/*`, driven in-process through `ui::handle`.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};

use super::totp;
use crate::accounts::InviteKind;
use crate::role::Role;
use crate::state::AppState;
use crate::tokens::{self, now};

const UI: &str = "ui.example.com";
const ORIGIN: &str = "https://ui.example.com";
const ADMIN_CREDENTIAL: &str = "tnadm_ui-tests-public-placeholder";

fn state() -> Arc<AppState> {
    state_with(|_| {})
}

fn state_with(f: impl FnOnce(&mut crate::config::Config)) -> Arc<AppState> {
    let mut config: crate::config::Config = serde_json::from_value(json!({
        "preview_zone": "previews.example.net", "api_host": "api.example.com",
        "tunnel_host": "tunnel.example.com", "turn_host": "turn.example.com",
        "ui_host": UI, "ui_secret": "ui-tests-public-placeholder-secret-0123456789",
        "admin_token_hash": tokens::hash_token(ADMIN_CREDENTIAL),
        "acme": {"email": "test@example.com"},
        "dns": {"provider": "cloudflare", "zone": "example.com"}
    }))
    .unwrap();
    f(&mut config);
    config.validate().unwrap();
    let db = crate::db::Db::open(std::path::Path::new(":memory:")).unwrap();
    let certs = crate::tls::CertStore::new(std::env::temp_dir().join("tunnel-ui-tests").join("certs"));
    AppState::new(config, db, certs)
}

fn peer(n: u8) -> SocketAddr {
    SocketAddr::from(([203, 0, 113, n], 40000))
}

/// A browser: its cookie, the CSRF token from `/ui/api/session`, and its address.
#[derive(Clone, Default)]
struct Browser {
    cookie: Option<String>,
    csrf: Option<String>,
    ip: u8,
}

struct Resp {
    status: StatusCode,
    body: Value,
    set_cookie: Option<String>,
}

async fn send(state: &Arc<AppState>, req: Request<axum::body::Body>, ip: u8) -> Resp {
    let resp = super::handle(state.clone(), peer(ip), req).await;
    let status = resp.status();
    let set_cookie = resp.headers().get(header::SET_COOKIE).map(|v| v.to_str().unwrap().to_string());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Resp { status, body, set_cookie }
}

impl Browser {
    fn new(ip: u8) -> Self {
        Self { ip, ..Self::default() }
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> http::request::Builder {
        let mut b = Request::builder().method(method).uri(path).header(header::HOST, UI);
        if method != "GET" {
            b = b.header(header::ORIGIN, ORIGIN);
        }
        b = b.header("sec-fetch-site", "same-origin");
        b = b.header(super::CSRF_HEADER, self.csrf.clone().unwrap_or_else(|| "1".into()));
        if let Some(c) = &self.cookie {
            b = b.header(header::COOKIE, c.clone());
        }
        if body.is_some() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b
    }

    async fn call(&mut self, state: &Arc<AppState>, method: &str, path: &str, body: Option<Value>) -> Resp {
        let req = self.request(method, path, body.clone());
        let body = body.map(|b| axum::body::Body::from(b.to_string())).unwrap_or_else(axum::body::Body::empty);
        let resp = send(state, req.body(body).unwrap(), self.ip).await;
        if let Some(c) = &resp.set_cookie {
            let pair = c.split(';').next().unwrap().to_string();
            self.cookie = if pair.ends_with('=') { None } else { Some(pair) };
            self.csrf = resp.body["csrf"].as_str().map(str::to_string);
        }
        resp
    }

    async fn refresh_csrf(&mut self, state: &Arc<AppState>) {
        let r = self.call(state, "GET", "/ui/api/session", None).await;
        self.csrf = r.body["csrf"].as_str().map(str::to_string);
    }
}

/// `/v1/*` with a bearer token, through the UI host.
async fn bearer(state: &Arc<AppState>, method: &str, path: &str, token: &str, body: Option<Value>) -> Resp {
    let mut b = Request::builder().method(method).uri(path).header(header::HOST, UI);
    b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            axum::body::Body::from(v.to_string())
        }
        None => axum::body::Body::empty(),
    };
    send(state, b.body(body).unwrap(), 9).await
}

async fn invite_token(state: &Arc<AppState>, kind: InviteKind, role: Role) -> String {
    let token = tokens::random_token(super::INVITE_PREFIX);
    state
        .db
        .create_invite(
            format!("in{}", tokens::random_tunnel_id()),
            tokens::hash_token(&token),
            kind,
            role,
            None,
            None,
            now() + 600,
        )
        .await
        .unwrap();
    token
}

async fn sign_up(state: &Arc<AppState>, token: &str, username: &str, ip: u8) -> Browser {
    let mut b = Browser::new(ip);
    let r = b
        .call(
            state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": token, "username": username, "password": format!("{username}-password") })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(b.csrf.is_some());
    b
}

async fn owner(state: &Arc<AppState>) -> Browser {
    let token = invite_token(state, InviteKind::OwnerSetup, Role::Owner).await;
    sign_up(state, &token, "olivia", 1).await
}

/// Owner invites a member; returns the member's browser.
async fn member(state: &Arc<AppState>, owner: &mut Browser, name: &str, ip: u8) -> Browser {
    let r = owner.call(state, "POST", "/ui/api/invites", Some(json!({ "role": "member" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let url = r.body["url"].as_str().unwrap();
    let token = url.split_once('#').unwrap().1.to_string();
    assert!(url.starts_with("https://ui.example.com/invite#tninv_"));
    sign_up(state, &token, name, ip).await
}

/// Machine login through the device flow; returns the `tncli_` token.
async fn approve_machine(state: &Arc<AppState>, user: &mut Browser, name: &str) -> String {
    let r = bearer_free(state, "/v1/device/code", json!({ "client_name": name })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let device_code = r.body["device_code"].as_str().unwrap().to_string();
    let user_code = r.body["user_code"].as_str().unwrap().to_string();
    assert_eq!(r.body["verification_uri"], "https://ui.example.com/device");
    let d = user
        .call(state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": true })))
        .await;
    assert_eq!(d.status, StatusCode::OK, "{}", d.body);
    let t = bearer_free(state, "/v1/device/token", json!({ "device_code": device_code })).await;
    assert_eq!(t.status, StatusCode::OK, "{}", t.body);
    t.body["token"].as_str().unwrap().to_string()
}

async fn bearer_free(state: &Arc<AppState>, path: &str, body: Value) -> Resp {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, UI)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    send(state, req, 9).await
}

async fn create_tunnel(state: &Arc<AppState>, token: &str, access: Value) -> Resp {
    bearer(state, "POST", "/v1/tunnels", token, Some(json!({ "ttl_s": 3600, "access": access }))).await
}

#[tokio::test]
async fn owner_setup_link_is_single_use_and_signs_in() {
    let state = state();
    let token = invite_token(&state, InviteKind::OwnerSetup, Role::Owner).await;
    let mut anon = Browser::new(1);
    let info = anon.call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!(info.body["kind"], "owner_setup");
    let mut owner = sign_up(&state, &token, "olivia", 1).await;
    let s = owner.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(s.body["user"]["role"], "owner");
    assert_eq!(s.body["owner_exists"], true);
    let again = Browser::new(2)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": token, "username": "mallory", "password": "mallory-password" })),
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "single use");
    // A second setup link cannot create a second owner.
    let token2 = invite_token(&state, InviteKind::OwnerSetup, Role::Owner).await;
    let r = Browser::new(3)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": token2, "username": "eve", "password": "eve-password1" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // An expired link is refused.
    let expired = tokens::random_token(super::INVITE_PREFIX);
    state
        .db
        .create_invite(
            "inexp".into(),
            tokens::hash_token(&expired),
            InviteKind::Invite,
            Role::Member,
            None,
            None,
            now() - 1,
        )
        .await
        .unwrap();
    let r = Browser::new(4)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": expired, "username": "late", "password": "late-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn owner_reset_link_replaces_password_and_ends_sessions() {
    let state = state();
    let mut owner = owner(&state).await;
    let reset = invite_token(&state, InviteKind::OwnerReset, Role::Owner).await;
    let info = Browser::new(5).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": reset }))).await;
    assert_eq!(info.body["username"], "olivia");
    let mut fresh = Browser::new(5);
    let r = fresh
        .call(&state, "POST", "/ui/api/invite/accept", Some(json!({ "token": reset, "password": "a-new-password" })))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let old = owner.call(&state, "GET", "/ui/api/session", None).await;
    assert!(old.body["user"].is_null(), "the old session ended");
    let mut b = Browser::new(6);
    let r = b
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "a-new-password" })))
        .await;
    assert_eq!(r.body["status"], "ok");
}

#[tokio::test]
async fn request_checks_refuse_cross_origin_same_site_and_stale_csrf() {
    let state = state();
    let mut owner = owner(&state).await;
    let base = |b: &Browser| b.request("POST", "/ui/api/invites", Some(json!({})));
    let body = || axum::body::Body::from(json!({ "role": "member" }).to_string());

    // No custom header (a plain form post from anywhere).
    let mut req = base(&owner).body(body()).unwrap();
    req.headers_mut().remove(super::CSRF_HEADER);
    assert_eq!(send(&state, req, 1).await.body["error"]["code"], "csrf");
    // A preview origin, same-site with the UI.
    let mut req = base(&owner).body(body()).unwrap();
    req.headers_mut().insert(header::ORIGIN, "https://3000-abcdefghij.previews.example.net".parse().unwrap());
    assert_eq!(send(&state, req, 1).await.body["error"]["code"], "origin");
    // Missing Origin on a write.
    let mut req = base(&owner).body(body()).unwrap();
    req.headers_mut().remove(header::ORIGIN);
    assert_eq!(send(&state, req, 1).await.body["error"]["code"], "origin");
    // Sec-Fetch-Site says same-site (a preview), even with a forged-looking Origin.
    let mut req = base(&owner).body(body()).unwrap();
    req.headers_mut().insert("sec-fetch-site", "same-site".parse().unwrap());
    assert_eq!(send(&state, req, 1).await.status, StatusCode::FORBIDDEN);
    // The header present but not the session's token.
    let mut req = base(&owner).body(body()).unwrap();
    req.headers_mut().insert(super::CSRF_HEADER, "1".parse().unwrap());
    let r = send(&state, req, 1).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("csrf")));
    // A CORS preflight is never granted.
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/ui/api/invites")
        .header(header::HOST, UI)
        .header(header::ORIGIN, "https://evil.example")
        .header("access-control-request-headers", "x-tunnel-csrf")
        .body(axum::body::Body::empty())
        .unwrap();
    let r = super::handle(state.clone(), peer(1), req).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(r.headers().get("access-control-allow-origin").is_none());
    // The real thing works.
    let r = owner.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member" }))).await;
    assert_eq!(r.status, StatusCode::OK);
    // The bearer API never accepts the UI cookie.
    let req = Request::builder()
        .uri("/v1/tunnels")
        .header(header::HOST, UI)
        .header(header::COOKIE, owner.cookie.clone().unwrap())
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(send(&state, req, 1).await.status, StatusCode::UNAUTHORIZED);
}

/// Reaches the embedded shell, so CI's `server-ui` job also runs it by name
/// with `--features ui`.
#[tokio::test]
async fn ui_responses_carry_the_strict_headers_and_cookie_attributes() {
    let state = state();
    let mut anon = Browser::new(1);
    let token = invite_token(&state, InviteKind::OwnerSetup, Role::Owner).await;
    let r = anon
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": token, "username": "olivia", "password": "olivia-password" })),
        )
        .await;
    let cookie = r.set_cookie.unwrap();
    assert!(cookie.starts_with("__Host-tunnel-ui="));
    for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(!cookie.contains("Domain"), "host-only");
    let req = anon.request("GET", "/machines", None).body(axum::body::Body::empty()).unwrap();
    let resp = super::handle(state.clone(), peer(1), req).await;
    let csp = resp.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("script-src 'self' 'wasm-unsafe-eval'"));
    assert_eq!(resp.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(resp.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
}

#[tokio::test]
async fn totp_enrolment_login_replay_and_recovery_codes() {
    let state = state();
    let mut owner = owner(&state).await;
    let setup =
        owner.call(&state, "POST", "/ui/api/account/totp/setup", Some(json!({ "password": "olivia-password" }))).await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.body);
    assert!(setup.body["qr"].as_str().unwrap().starts_with("data:image/svg+xml;base64,"));
    let mut codes = Codes::new(base32_decode(setup.body["secret"].as_str().unwrap()));
    let wrong =
        owner.call(&state, "POST", "/ui/api/account/totp/enable", Some(json!({ "code": codes.invalid() }))).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let enrol_code = codes.next();
    let r = owner.call(&state, "POST", "/ui/api/account/totp/enable", Some(json!({ "code": enrol_code }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let recovery: Vec<String> =
        r.body["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert_eq!(recovery.len(), 10);

    let mut b = Browser::new(7);
    let r = b
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" })))
        .await;
    assert_eq!(r.body["status"], "totp_required");
    let s = b.call(&state, "GET", "/ui/api/session", None).await;
    assert!(s.body["user"].is_null() && s.body["pending"] == true, "pending is not signed in");
    let r = b.call(&state, "GET", "/ui/api/machines", None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = b.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": enrol_code }))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "the enrolment code cannot be replayed");
    let code = codes.next();
    let r = b.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": code }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(b.call(&state, "GET", "/ui/api/session", None).await.body["user"]["username"], "olivia");

    // The same code again (another sign-in) is a replay.
    let mut c = Browser::new(8);
    c.call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" }))).await;
    let r = c.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": code }))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // A recovery code works once.
    let r = c.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": recovery[0].to_uppercase() }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["recovery_codes_left"], 9);
    let mut d = Browser::new(9);
    d.call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" }))).await;
    let r = d.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": recovery[0] }))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "recovery codes are single-use");
}

/// A code that is valid for none of the steps the server accepts now.
fn invalid_code(secret: &[u8]) -> String {
    let t = now();
    let valid: Vec<u32> = [-60, -30, 0, 30, 60].iter().map(|d| totp::code_at(secret, t + d)).collect();
    let code = (0..).find(|c| !valid.contains(c)).unwrap();
    format!("{code:06}")
}

fn base32_decode(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0);
    for c in s.bytes() {
        buf = (buf << 5) | ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    out
}

/// Hands out TOTP codes the server is sure to accept when it sees them:
/// each for a step after the last one used, and never the previous step
/// (which a step boundary crossed mid-request could push out of the window).
/// The server accepts the steps around its current one, so a code for the
/// current step stays valid for at least 30 s, and for the next for 60 s.
struct Codes {
    secret: Vec<u8>,
    last: i64,
}

impl Codes {
    fn new(secret: Vec<u8>) -> Self {
        Self { secret, last: i64::MIN }
    }

    fn next(&mut self) -> String {
        loop {
            let s = totp::step_at(now());
            let step = s.max(self.last.saturating_add(1));
            if step <= s + 1 {
                self.last = step;
                return format!("{:06}", totp::code_at(&self.secret, step * totp::STEP_S));
            }
            // Both usable steps are spent: wait for the next one.
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    fn invalid(&self) -> String {
        invalid_code(&self.secret)
    }
}

#[tokio::test]
async fn password_change_ends_other_sessions_and_rotates_this_one() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut other = Browser::new(2);
    other
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" })))
        .await;
    let before = owner.cookie.clone();
    let r = owner
        .call(
            &state,
            "POST",
            "/ui/api/account/password",
            Some(json!({ "current": "olivia-password", "new": "olivia-password-2" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_ne!(owner.cookie, before, "rotated");
    assert_eq!(owner.call(&state, "GET", "/ui/api/session", None).await.body["user"]["username"], "olivia");
    assert!(other.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
}

#[tokio::test]
async fn members_see_and_manage_only_their_own_machines_tunnels_and_links() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let mut bob = member(&state, &mut owner, "bob", 3).await;
    let ann_token = approve_machine(&state, &mut ann, "laptop").await;
    let bob_token = approve_machine(&state, &mut bob, "laptop").await;
    assert!(ann_token.starts_with("tncli_"));

    let machines = ann.call(&state, "GET", "/ui/api/machines", None).await;
    let names: Vec<&str> =
        machines.body["machines"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["laptop"]);
    let bob_machines = bob.call(&state, "GET", "/ui/api/machines", None).await;
    assert_eq!(bob_machines.body["machines"][0]["name"], "laptop-2", "taken names get a suffix");

    let t = create_tunnel(&state, &ann_token, json!({ "mode": "link" })).await;
    assert_eq!(t.status, StatusCode::CREATED, "{}", t.body);
    let id = t.body["id"].as_str().unwrap().to_string();

    let mine = ann.call(&state, "GET", "/ui/api/tunnels", None).await;
    assert_eq!(mine.body["tunnels"].as_array().unwrap().len(), 1);
    assert_eq!(mine.body["tunnels"][0]["owner"], "laptop");
    let theirs = bob.call(&state, "GET", "/ui/api/tunnels", None).await;
    assert!(theirs.body["tunnels"].as_array().unwrap().is_empty());
    assert_eq!(bob.call(&state, "GET", "/ui/api/tunnels?all=true", None).await.status, StatusCode::FORBIDDEN);
    let all = owner.call(&state, "GET", "/ui/api/tunnels?all=true", None).await;
    assert_eq!(all.body["tunnels"][0]["user"], "ann");

    // Bob cannot touch Ann's tunnel, links or machine, through the UI or the API.
    let path = format!("/ui/api/tunnels/{id}/links");
    assert_eq!(bob.call(&state, "GET", &path, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.call(&state, "POST", &path, Some(json!({ "ttl_s": 600 }))).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.call(&state, "DELETE", &format!("/ui/api/tunnels/{id}"), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.call(&state, "DELETE", "/ui/api/machines/laptop", None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &bob_token, None).await.status,
        StatusCode::NOT_FOUND
    );

    // Ann mints, lists and revokes a link.
    let link = ann.call(&state, "POST", &path, Some(json!({ "ttl_s": 600 }))).await;
    assert_eq!(link.status, StatusCode::CREATED, "{}", link.body);
    assert!(link.body["url"].as_str().unwrap().starts_with("https://previews.example.net/__access/"));
    let link_id = link.body["id"].as_str().unwrap().to_string();
    let listed = ann.call(&state, "GET", &path, None).await;
    assert_eq!(listed.body["links"][0]["id"], link_id.as_str());
    let api_listed = bearer(&state, "GET", &format!("/v1/tunnels/{id}/access-links"), &ann_token, None).await;
    assert_eq!(api_listed.body["links"][0]["id"], link_id.as_str());
    assert_eq!(
        bob.call(&state, "DELETE", &format!("/ui/api/links/{link_id}"), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ann.call(&state, "DELETE", &format!("/ui/api/links/{link_id}"), None).await.status,
        StatusCode::NO_CONTENT
    );

    // Ann deletes her tunnel; the API then reports it gone.
    assert_eq!(ann.call(&state, "DELETE", &format!("/ui/api/tunnels/{id}"), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &ann_token, None).await.status,
        StatusCode::NOT_FOUND
    );
    // Removing the machine revokes its token.
    assert_eq!(ann.call(&state, "DELETE", "/ui/api/machines/laptop", None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &ann_token, None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_previews_need_an_admin_or_permission() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let ann_token = approve_machine(&state, &mut ann, "laptop").await;
    let owner_token = approve_machine(&state, &mut owner, "server").await;
    let r = create_tunnel(&state, &ann_token, json!({ "mode": "public" })).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("public_not_allowed")));
    let info = bearer(&state, "GET", "/v1/server", &ann_token, None).await;
    assert_eq!(info.body["limits"]["public_allowed"], false);
    assert_eq!(info.body["ui_origin"], ORIGIN);
    assert_eq!(create_tunnel(&state, &owner_token, json!({ "mode": "public" })).await.status, StatusCode::CREATED);
    // Password mode stays allowed for members.
    let r = create_tunnel(&state, &ann_token, json!({ "mode": "password", "username": "u", "password": "a-password" }))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);

    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = users.body["users"].as_array().unwrap().iter().find(|u| u["username"] == "ann").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "can_public": true }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(create_tunnel(&state, &ann_token, json!({ "mode": "public" })).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn member_quotas_and_ttl_cap() {
    let state = state_with(|c| {
        c.limits.member_max_tunnels = 2;
        c.limits.member_max_clients = 1;
    });
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let token = approve_machine(&state, &mut ann, "laptop").await;
    for _ in 0..2 {
        assert_eq!(create_tunnel(&state, &token, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    }
    let r = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("tunnel_quota")));
    // A second machine is over the machine quota: refused when approving.
    let code = bearer_free(&state, "/v1/device/code", json!({ "client_name": "desktop" })).await;
    let user_code = code.body["user_code"].as_str().unwrap();
    let r = ann
        .call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": true })))
        .await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("client_quota")));
    let r = ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "headless" }))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // Members' tunnel lifetime is capped.
    let r = bearer(&state, "POST", "/v1/tunnels", &token, Some(json!({ "ttl_s": 8 * 86_400 }))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // The owner's machines are not limited by member quotas.
    let owner_token = approve_machine(&state, &mut owner, "server").await;
    for _ in 0..3 {
        assert_eq!(create_tunnel(&state, &owner_token, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    }
}

#[tokio::test]
async fn device_flow_states_and_phishing_resistance() {
    let state = state();
    let mut owner = owner(&state).await;
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "attacker-box" })).await;
    let device_code = r.body["device_code"].as_str().unwrap().to_string();
    let user_code = r.body["user_code"].as_str().unwrap().to_string();
    assert!(!r.body["verification_uri"].as_str().unwrap().contains(&user_code), "no prefilled code");
    let poll = || bearer_free(&state, "/v1/device/token", json!({ "device_code": device_code }));
    assert_eq!(poll().await.body["error"]["code"], "authorization_pending");
    assert_eq!(poll().await.body["error"]["code"], "slow_down", "polled faster than the interval");
    // The approval page shows what is being approved.
    let look = owner
        .call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": user_code.to_lowercase() })))
        .await;
    assert_eq!(look.body["request"]["client_name"], "attacker-box");
    assert_eq!(look.body["request"]["ip"], "203.0.113.9");
    // A wrong code finds nothing.
    let r = owner.call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": "BBBB-BBBB" }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Deny: the CLI hears access_denied, then the code is gone.
    owner
        .call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": false })))
        .await;
    state
        .db
        .call({
            let h = tokens::hash_token(&device_code);
            move |c| {
                c.execute("UPDATE device_logins SET last_poll_at = 0 WHERE device_code_hash = ?1", [h])?;
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(poll().await.body["error"]["code"], "access_denied");
    assert_eq!(poll().await.body["error"]["code"], "invalid_grant");
    // Expiry.
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "slow" })).await;
    let dc = r.body["device_code"].as_str().unwrap().to_string();
    state
        .db
        .call({
            let h = tokens::hash_token(&dc);
            move |c| {
                c.execute("UPDATE device_logins SET expires_at = 0 WHERE device_code_hash = ?1", [h])?;
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(
        bearer_free(&state, "/v1/device/token", json!({ "device_code": dc })).await.body["error"]["code"],
        "expired_token"
    );
    // The token is handed out exactly once.
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "once" })).await;
    let dc = r.body["device_code"].as_str().unwrap().to_string();
    owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": r.body["user_code"], "approve": true })),
        )
        .await;
    let first = bearer_free(&state, "/v1/device/token", json!({ "device_code": dc })).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["api"], "https://api.example.com");
    assert_eq!(
        bearer_free(&state, "/v1/device/token", json!({ "device_code": dc })).await.body["error"]["code"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn approving_a_machine_after_ten_minutes_needs_a_fresh_code() {
    let state = state();
    let mut owner = owner(&state).await;
    let setup =
        owner.call(&state, "POST", "/ui/api/account/totp/setup", Some(json!({ "password": "olivia-password" }))).await;
    let mut codes = Codes::new(base32_decode(setup.body["secret"].as_str().unwrap()));
    assert_eq!(
        owner.call(&state, "POST", "/ui/api/account/totp/enable", Some(json!({ "code": codes.next() }))).await.status,
        StatusCode::OK
    );
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "box" })).await;
    let user_code = r.body["user_code"].as_str().unwrap().to_string();
    let look = owner.call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": user_code }))).await;
    assert_eq!(look.body["needs_code"], true);
    let r = owner
        .call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": true })))
        .await;
    assert_eq!(r.body["error"]["code"], "code_required");
    let code = codes.next();
    let r = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": user_code, "approve": true, "code": code })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn disabling_a_member_ends_sessions_machines_and_tunnels() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let token = approve_machine(&state, &mut ann, "laptop").await;
    let t = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    let id = t.body["id"].as_str().unwrap().to_string();
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = users.body["users"].as_array().unwrap().iter().find(|u| u["username"] == "ann").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "disabled": true }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(ann.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &token, None).await.status, StatusCode::UNAUTHORIZED);
    assert!(matches!(state.db.lookup_tunnel(id).await.unwrap(), crate::db::TunnelLookup::Tombstoned));
    let mut again = Browser::new(2);
    let r = again
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "ann", "password": "ann-password" })))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // An admin token's service is untouched by any of this (services are not users).
    let svc = bearer(
        &state,
        "POST",
        "/v1/services",
        ADMIN_CREDENTIAL,
        Some(json!({ "name": "squadron", "max_tunnels": 50 })),
    )
    .await;
    assert_eq!(svc.status, StatusCode::CREATED, "{}", svc.body);
}

#[tokio::test]
async fn roles_limit_what_admins_and_members_can_do() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    assert_eq!(ann.call(&state, "GET", "/ui/api/users", None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        ann.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member" }))).await.status,
        StatusCode::FORBIDDEN
    );
    let r = owner.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "admin" }))).await;
    let token = r.body["url"].as_str().unwrap().split_once('#').unwrap().1.to_string();
    let mut adam = sign_up(&state, &token, "adam", 4).await;
    let r = adam.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "admin" }))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "only the owner invites admins");
    let users = adam.call(&state, "GET", "/ui/api/users", None).await;
    let id_of = |name: &str| {
        users.body["users"].as_array().unwrap().iter().find(|u| u["username"] == name).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let olivia = id_of("olivia");
    let ann_id = id_of("ann");
    assert_eq!(
        adam.call(&state, "PATCH", &format!("/ui/api/users/{olivia}"), Some(json!({ "disabled": true }))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        adam.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "role": "admin" }))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        adam.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "limits": { "tunnels": 3 } })))
            .await
            .status,
        StatusCode::OK
    );
    // A role change by the owner ends that user's sessions.
    assert_eq!(
        owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "role": "admin" }))).await.status,
        StatusCode::OK
    );
    assert!(ann.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
    let _ = ann.refresh_csrf(&state).await;
}

#[tokio::test]
async fn sign_in_is_rate_limited_before_any_password_check() {
    let state = state_with(|c| c.limits.login_rate_per_min = 3);
    let _owner = owner(&state).await;
    let login = |ip: u8, password: &'static str| {
        let state = state.clone();
        async move {
            Browser::new(ip)
                .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": password })))
                .await
        }
    };
    let mut b = Browser::new(50);
    for _ in 0..3 {
        let r = b
            .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "wrong-password" })))
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let checks = crate::password::CHECKS.with(|c| c.get());
    let r = b
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" })))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "per address");
    assert_eq!(crate::password::CHECKS.with(|c| c.get()), checks, "refused before any password check");
    // The per-username budget is three times the per-address one, so one
    // address alone cannot lock a user out; from many addresses it holds.
    for ip in 51..57 {
        assert_eq!(login(ip, "wrong-password").await.status, StatusCode::UNAUTHORIZED);
    }
    let checks = crate::password::CHECKS.with(|c| c.get());
    assert_eq!(login(57, "olivia-password").await.status, StatusCode::TOO_MANY_REQUESTS, "per username");
    assert_eq!(crate::password::CHECKS.with(|c| c.get()), checks);
    // Unknown users get the same answer as wrong passwords.
    let mut d = Browser::new(58);
    let r = d
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "nobody", "password": "whatever-pass" })))
        .await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::UNAUTHORIZED, json!("invalid_credentials")));
}

#[tokio::test]
async fn audit_log_records_actions() {
    let state = state();
    let mut owner = owner(&state).await;
    let _ann = member(&state, &mut owner, "ann", 2).await;
    let log = owner.call(&state, "GET", "/ui/api/audit", None).await;
    let actions: Vec<&str> =
        log.body["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(
        actions.contains(&"owner_created") && actions.contains(&"invite_created") && actions.contains(&"user_created"),
        "{actions:?}"
    );
}

#[test]
fn config_refuses_ui_on_the_preview_zone() {
    for host in ["previews.example.net", "ui.previews.example.net"] {
        let r = std::panic::catch_unwind(|| state_with(|c| c.ui_host = Some(host.into())));
        assert!(r.is_err(), "{host}");
    }
    let same_site = state_with(|c| c.preview_zone = "previews.example.com".into());
    assert!(same_site.config.ui_same_site_as_previews());
    assert!(!state().config.ui_same_site_as_previews());
    assert_eq!(crate::config::registrable("a.b.example.co.uk"), "example.co.uk");
}

#[test]
fn install_script_is_served_on_the_ui_host_only() {
    let state = state();
    let r = crate::install::response(&state, "/install.sh", &http::Method::GET);
    assert_eq!(r.status(), StatusCode::OK);
    let none = state_with(|c| {
        c.ui_host = None;
    });
    assert_eq!(crate::install::response(&none, "/install.sh", &http::Method::GET).status(), StatusCode::NOT_FOUND);
}

/// Turn TOTP on for `b` (signed in as `username`); returns its code source.
async fn enable_totp(state: &Arc<AppState>, b: &mut Browser, password: &str) -> Codes {
    let setup = b.call(state, "POST", "/ui/api/account/totp/setup", Some(json!({ "password": password }))).await;
    let mut codes = Codes::new(base32_decode(setup.body["secret"].as_str().unwrap()));
    let r = b.call(state, "POST", "/ui/api/account/totp/enable", Some(json!({ "code": codes.next() }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    codes
}

#[tokio::test]
async fn wrong_codes_lock_the_second_factor_across_sign_ins() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut codes = enable_totp(&state, &mut owner, "olivia-password").await;
    for attempt in 0..crate::accounts::FACTOR_FAILURES {
        // A fresh pending sign-in each time does not reset the count.
        let mut b = Browser::new(20 + attempt as u8);
        b.call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" })))
            .await;
        let r = b.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": codes.invalid() }))).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let mut b = Browser::new(30);
    b.call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" }))).await;
    let r = b.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": codes.next() }))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("locked")));
}

#[tokio::test]
async fn sessions_are_not_issued_across_a_credential_change() {
    let state = state();
    let _owner = owner(&state).await;
    let creds = state.db.credentials(Some("olivia".into()), None).await.unwrap().unwrap();
    let bump = |id: String| {
        let state = state.clone();
        async move {
            state
                .db
                .call(move |c| {
                    c.execute("UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?1", [id])?;
                    Ok(())
                })
                .await
                .unwrap()
        }
    };
    // A check passed at this epoch; the credentials change before the session is issued.
    bump(creds.user.id.clone()).await;
    let issued = state
        .db
        .create_ui_session("h1".into(), creds.user.id.clone(), false, creds.auth_epoch, None, None, None)
        .await
        .unwrap();
    assert!(!issued);
    // A pending session from before a change cannot be upgraded either.
    let fresh = state.db.credentials(None, Some(creds.user.id.clone())).await.unwrap().unwrap();
    assert!(
        state
            .db
            .create_ui_session("p1".into(), creds.user.id.clone(), true, fresh.auth_epoch, None, None, None)
            .await
            .unwrap()
    );
    bump(creds.user.id.clone()).await;
    let swapped = state
        .db
        .create_ui_session("h2".into(), creds.user.id.clone(), false, fresh.auth_epoch, Some("p1".into()), None, None)
        .await
        .unwrap();
    assert!(!swapped);
    let now_epoch = fresh.auth_epoch + 1;
    assert!(state.db.create_ui_session("h3".into(), creds.user.id, false, now_epoch, None, None, None).await.unwrap());
}

#[tokio::test]
async fn credential_changes_checked_before_a_recovery_cannot_land_after_it() {
    let state = state();
    let mut owner = owner(&state).await;
    let creds = state.db.credentials(Some("olivia".into()), None).await.unwrap().unwrap();
    let session = state
        .db
        .call(|c| Ok(c.query_row("SELECT id_hash FROM ui_sessions", [], |r| r.get::<_, String>(0))?))
        .await
        .unwrap();
    // The attacker's request verified the old password at this epoch; then the owner recovers.
    let reset = invite_token(&state, InviteKind::OwnerReset, Role::Owner).await;
    let r = Browser::new(5)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": reset, "password": "recovered-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        state
            .db
            .set_password(creds.user.id.clone(), "attacker".into(), creds.auth_epoch, session.clone())
            .await
            .unwrap()
            .is_none()
    );
    assert!(!state.db.disable_totp(creds.user.id.clone(), creds.auth_epoch, session).await.unwrap());
    let mut b = Browser::new(6);
    let r = b
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "recovered-password" })))
        .await;
    assert_eq!(r.body["status"], "ok", "the recovered password stands");
    let _ = owner.refresh_csrf(&state).await;
}

#[tokio::test]
async fn an_owner_reset_drops_logins_approved_before_it() {
    let state = state();
    let mut owner = owner(&state).await;
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "planted" })).await;
    let device_code = r.body["device_code"].as_str().unwrap().to_string();
    let d = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": r.body["user_code"], "approve": true })),
        )
        .await;
    assert_eq!(d.status, StatusCode::OK);
    let reset = invite_token(&state, InviteKind::OwnerReset, Role::Owner).await;
    let r = Browser::new(5)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": reset, "password": "recovered-password", "revoke_machines": true })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let t = bearer_free(&state, "/v1/device/token", json!({ "device_code": device_code })).await;
    assert_eq!(t.body["error"]["code"], "invalid_grant", "no token for a login approved before the reset");
}

#[tokio::test]
async fn adding_a_headless_machine_needs_a_fresh_code_too() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut codes = enable_totp(&state, &mut owner, "olivia-password").await;
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let r = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "ci" }))).await;
    assert_eq!(r.body["error"]["code"], "code_required");
    let code = codes.next();
    let r = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "ci", "code": code }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body["login_code"].as_str().unwrap().starts_with("tnenr_"));
}

#[tokio::test]
async fn demoting_an_admin_resets_member_limits_and_drops_their_invites() {
    let state = state();
    let mut owner = owner(&state).await;
    let r = owner.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "admin" }))).await;
    let token = r.body["url"].as_str().unwrap().split_once('#').unwrap().1.to_string();
    let mut adam = sign_up(&state, &token, "adam", 4).await;
    let r = adam.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member" }))).await;
    let adams_invite = r.body["url"].as_str().unwrap().split_once('#').unwrap().1.to_string();
    let adam_id = state.db.user_by_name("adam".into()).await.unwrap().unwrap().id;
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{adam_id}"), Some(json!({ "role": "member" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["user"]["limits"]["tunnels"]["effective"], state.config.limits.member_max_tunnels);
    assert_eq!(r.body["user"]["can_public"], false);
    let info =
        Browser::new(5).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": adams_invite }))).await;
    assert_eq!(info.status, StatusCode::NOT_FOUND, "their unused invites are gone");
    assert!(adam.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
}

#[tokio::test]
async fn machines_can_belong_to_an_owner_before_anyone_signs_up() {
    let state = state();
    let r = bearer(&state, "POST", "/v1/clients", ADMIN_CREDENTIAL, Some(json!({ "name": "worker" }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let owner = state.db.owner().await.unwrap().unwrap();
    assert!(state.db.owner_without_password().await.unwrap());
    // The password-less owner cannot sign in…
    let r = Browser::new(1)
        .call(
            &state,
            "POST",
            "/ui/api/login",
            Some(json!({ "username": owner.username, "password": "anything-at-all" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // …until the setup link claims it with a name and password.
    let token = invite_token(&state, InviteKind::OwnerSetup, Role::Owner).await;
    let mut olivia = sign_up(&state, &token, "olivia", 2).await;
    let claimed = state.db.owner().await.unwrap().unwrap();
    assert_eq!((claimed.id, claimed.username.as_str()), (owner.id, "olivia"));
    let machines = olivia.call(&state, "GET", "/ui/api/machines", None).await;
    assert_eq!(machines.body["machines"][0]["name"], "worker");
}

#[tokio::test]
async fn owner_reset_can_revoke_the_owners_machines() {
    let state = state();
    let mut owner = owner(&state).await;
    let token = approve_machine(&state, &mut owner, "laptop").await;
    let reset = invite_token(&state, InviteKind::OwnerReset, Role::Owner).await;
    let r = Browser::new(5)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": reset, "password": "a-new-password", "revoke_machines": true })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &token, None).await.status, StatusCode::UNAUTHORIZED);
}

/// Reaches the embedded shell, so CI's `server-ui` job also runs it by name
/// with `--features ui`.
#[tokio::test]
async fn the_app_shell_and_assets_are_served_from_the_binary() {
    let state = state();
    let get = |path: &'static str| {
        let state = state.clone();
        async move {
            let req = Request::builder()
                .uri(path)
                .header(header::HOST, UI)
                .header(header::ACCEPT_ENCODING, "gzip")
                .body(axum::body::Body::empty())
                .unwrap();
            super::handle(state, peer(1), req).await
        }
    };
    let shell = get("/machines").await;
    assert_eq!(shell.status(), StatusCode::OK);
    assert_eq!(shell.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    let missing = get("/assets/app-0000000000000000.js").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND, "a stale script never gets the HTML shell");
    if cfg!(feature = "ui") {
        let html = String::from_utf8(if shell.headers().get(header::CONTENT_ENCODING).is_some() {
            let raw = shell.into_body().collect().await.unwrap().to_bytes();
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut flate2_free_gunzip(&raw), &mut out).unwrap();
            out
        } else {
            shell.into_body().collect().await.unwrap().to_bytes().to_vec()
        })
        .unwrap();
        assert!(html.contains("<script type=\"module\""), "{html}");
        let asset = super::assets::ASSETS.iter().find(|a| a.path.ends_with(".wasm")).expect("embedded wasm");
        let r = get(asset.path).await;
        assert_eq!(r.headers().get(header::CACHE_CONTROL).unwrap(), "public, max-age=31536000, immutable");
        assert_eq!(r.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
    } else {
        let body = shell.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("without the web UI"));
    }
}

/// The embedded gzip files are plain gzip; the test only needs to know the
/// shell came back compressed, so it checks the magic and keeps the raw bytes
/// when no decoder is at hand.
fn flate2_free_gunzip(raw: &[u8]) -> std::io::Cursor<Vec<u8>> {
    assert_eq!(&raw[..2], &[0x1f, 0x8b], "gzip magic");
    // Find the shell's uncompressed twin among the embedded assets.
    let html = super::assets::ASSETS.iter().find(|a| a.path == "/index.html").unwrap();
    assert_eq!(html.gz, Some(raw));
    std::io::Cursor::new(html.raw.to_vec())
}

#[tokio::test]
async fn admin_changes_are_authorized_inside_the_transaction() {
    let state = state();
    let mut owner = owner(&state).await;
    let _ann = member(&state, &mut owner, "ann", 2).await;
    let olivia = state.db.user_by_name("olivia".into()).await.unwrap().unwrap().id;
    let ann = state.db.user_by_name("ann".into()).await.unwrap().unwrap().id;
    let session = state
        .db
        .call(move |c| {
            Ok(c.query_row("SELECT id_hash FROM ui_sessions WHERE user_id = ?1", [olivia], |r| r.get::<_, String>(0))?)
        })
        .await
        .unwrap();
    let olivia = state.db.user_by_name("olivia".into()).await.unwrap().unwrap().id;
    let promote = crate::accounts::UserPatch { role: Some(Role::Admin), ..Default::default() };
    // The session ends (an owner recovery) while the request is in flight.
    state.db.delete_user_sessions(olivia.clone(), None).await.unwrap();
    let r = state.db.admin_update_user(olivia.clone(), session.clone(), ann.clone(), promote, None).await.unwrap();
    assert_eq!(r.unwrap_err(), crate::accounts::AdminError::SignedOut);
    let invite = state
        .db
        .create_invite(
            "inlate".into(),
            "late-hash".into(),
            InviteKind::Invite,
            Role::Admin,
            Some(olivia.clone()),
            Some(session.clone()),
            now() + 600,
        )
        .await
        .unwrap();
    assert!(invite.is_none(), "no invite from an ended session");
    assert_eq!(state.db.user_by_name("ann".into()).await.unwrap().unwrap().role, Role::Member);
}

#[tokio::test]
async fn ui_link_creation_and_session_revocation_recheck_the_session_in_the_transaction() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let token = approve_machine(&state, &mut ann, "laptop").await;
    let t = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    let id = t.body["id"].as_str().unwrap().to_string();
    let olivia = state.db.user_by_name("olivia".into()).await.unwrap().unwrap().id;
    let session = {
        let olivia = olivia.clone();
        state
            .db
            .call(move |c| {
                Ok(c.query_row("SELECT id_hash FROM ui_sessions WHERE user_id = ?1", [olivia], |r| {
                    r.get::<_, String>(0)
                })?)
            })
            .await
            .unwrap()
    };
    let link = || crate::db::NewAccessLink {
        id: crate::tokens::random_link_id(),
        tunnel_id: id.clone(),
        token_hash: crate::tokens::random_secret(),
        single_use: true,
        label: None,
        owner_port: None,
        session_ttl_s: 60,
        expires_at: now() + 60,
    };
    // The owner may mint a link for the member's tunnel while signed in…
    assert!(state.db.create_access_link_for(link(), olivia.clone(), session.clone()).await.unwrap());
    // …but not once that session has ended (e.g. a recovery), even mid-request.
    state.db.delete_user_sessions(olivia.clone(), None).await.unwrap();
    assert!(!state.db.create_access_link_for(link(), olivia.clone(), session.clone()).await.unwrap());
    assert_eq!(state.db.revoke_own_sessions(olivia, session, None).await.unwrap(), None);
    // A member's own session works for their own tunnel only.
    let r = ann.call(&state, "POST", &format!("/ui/api/tunnels/{id}/links"), Some(json!({ "ttl_s": 60 }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
}

#[tokio::test]
async fn an_expired_pending_session_cannot_be_upgraded() {
    let state = state();
    let _owner = owner(&state).await;
    let creds = state.db.credentials(Some("olivia".into()), None).await.unwrap().unwrap();
    let user = creds.user.id.clone();
    assert!(
        state.db.create_ui_session("p1".into(), user.clone(), true, creds.auth_epoch, None, None, None).await.unwrap()
    );
    // Its five minutes ran out while the request carrying the code was in flight.
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET expires_at = 1 WHERE id_hash = 'p1'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let swapped =
        state.db.create_ui_session("h1".into(), user.clone(), false, creds.auth_epoch, Some("p1".into()), None, None);
    assert!(!swapped.await.unwrap());
    // A full session cannot stand in for a pending one either.
    assert!(
        state.db.create_ui_session("f1".into(), user.clone(), false, creds.auth_epoch, None, None, None).await.unwrap()
    );
    let swapped = state.db.create_ui_session("h2".into(), user, false, creds.auth_epoch, Some("f1".into()), None, None);
    assert!(!swapped.await.unwrap());
}

#[tokio::test]
async fn deleting_a_user_from_the_shell_ends_everything_and_frees_the_name() {
    use crate::accounts::DeleteUserError;
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let token = approve_machine(&state, &mut ann, "laptop").await;
    let t = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    let id = t.body["id"].as_str().unwrap().to_string();
    let pending = ann.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member" }))).await;
    assert_eq!(pending.status, StatusCode::FORBIDDEN, "members cannot invite");

    assert_eq!(state.db.delete_user("olivia".into()).await.unwrap(), Err(DeleteUserError::Owner));
    assert_eq!(state.db.delete_user("nobody".into()).await.unwrap(), Err(DeleteUserError::NotFound));
    assert_eq!(state.db.delete_user("ann".into()).await.unwrap(), Ok(vec![id.clone()]));
    assert!(ann.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &token, None).await.status, StatusCode::UNAUTHORIZED);
    // Expired here; the running server's purge loop closes it (as for `client delete`).
    if let crate::db::TunnelLookup::Live(row) = state.db.lookup_tunnel(id).await.unwrap() {
        assert!(row.expires_at < now());
    }
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    assert!(users.body["users"].as_array().unwrap().iter().all(|u| u["username"] != "ann"));
    assert!(owner.call(&state, "GET", "/ui/api/machines", None).await.body.to_string().find("laptop").is_none());

    // A shell invite (no creator) signs up an account with the invite's role, and the name is free again.
    let invite = invite_token(&state, InviteKind::Invite, Role::Admin).await;
    let mut again = sign_up(&state, &invite, "ann", 3).await;
    let me = again.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(me.body["user"]["role"], "admin", "{}", me.body);
}

#[tokio::test]
async fn machines_are_renamed_by_whoever_may_manage_them() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let mut bob = member(&state, &mut owner, "bob", 3).await;
    let r = owner.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "admin" }))).await;
    let token = r.body["url"].as_str().unwrap().split_once('#').unwrap().1.to_string();
    let mut adam = sign_up(&state, &token, "adam", 4).await;
    let ann_token = approve_machine(&state, &mut ann, "laptop").await;
    let _ = approve_machine(&state, &mut bob, "desktop").await;
    let _ = approve_machine(&state, &mut owner, "server").await;
    let _ = approve_machine(&state, &mut adam, "adams-box").await;
    let t = create_tunnel(&state, &ann_token, json!({ "mode": "link" })).await;
    assert_eq!(t.status, StatusCode::CREATED, "{}", t.body);
    let rename = |from: &str, to: &str| (format!("/ui/api/machines/{from}"), Some(json!({ "name": to })));

    // A member renames their own machine; its token and tunnel keep working.
    let (p, b) = rename("laptop", "ann-laptop");
    let r = ann.call(&state, "PATCH", &p, b).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["name"], "ann-laptop");
    let list = bearer(&state, "GET", "/v1/tunnels", &ann_token, None).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.body["tunnels"].as_array().unwrap().len(), 1);
    let mine = ann.call(&state, "GET", "/ui/api/machines", None).await;
    assert_eq!(mine.body["machines"][0]["name"], "ann-laptop", "{}", mine.body);

    // Not someone else's, and not a taken or invalid name.
    for (who, from) in [("ann", "desktop"), ("ann", "server"), ("adam", "server"), ("adam", "laptop")] {
        let (p, b) = rename(from, "x-new");
        let browser = if who == "ann" { &mut ann } else { &mut adam };
        assert_eq!(browser.call(&state, "PATCH", &p, b).await.status, StatusCode::NOT_FOUND, "{who} {from}");
    }
    let (p, b) = rename("ann-laptop", "desktop");
    assert_eq!(ann.call(&state, "PATCH", &p, b).await.status, StatusCode::CONFLICT);
    for bad in ["", "..", ".", "enroll", "a b", "a/b", &"x".repeat(65)] {
        let (p, b) = rename("ann-laptop", bad);
        assert_eq!(ann.call(&state, "PATCH", &p, b).await.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad:?}");
    }
    // Admins rename members' machines; the owner anyone's.
    let (p, b) = rename("desktop", "bobs-desktop");
    assert_eq!(adam.call(&state, "PATCH", &p, b).await.status, StatusCode::OK);
    let (p, b) = rename("adams-box", "admin-box");
    assert_eq!(owner.call(&state, "PATCH", &p, b).await.status, StatusCode::OK);
    // Renaming to the same name is a no-op, not a conflict.
    let (p, b) = rename("admin-box", "admin-box");
    assert_eq!(owner.call(&state, "PATCH", &p, b).await.status, StatusCode::OK);
    // A stale session cannot rename.
    owner.call(&state, "POST", "/ui/api/logout", None).await;
    let (p, b) = rename("server", "srv");
    assert_ne!(owner.call(&state, "PATCH", &p, b).await.status, StatusCode::OK);

    let mut owner2 = Browser::new(1);
    let r = owner2
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "olivia", "password": "olivia-password" })))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let log = owner2.call(&state, "GET", "/ui/api/audit", None).await;
    let renamed: Vec<&str> = log.body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "machine_renamed")
        .map(|e| e["target"].as_str().unwrap())
        .collect();
    assert_eq!(renamed.len(), 3, "{renamed:?}");
    assert!(renamed.contains(&"laptop -> ann-laptop") && renamed.contains(&"desktop -> bobs-desktop"));

    // The admin token renames any machine through /v1 (and the server shell does the same).
    let r = bearer(&state, "PATCH", "/v1/clients/server", ADMIN_CREDENTIAL, Some(json!({ "name": "srv" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = bearer(&state, "PATCH", "/v1/clients/nope", ADMIN_CREDENTIAL, Some(json!({ "name": "srv2" }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = bearer(&state, "PATCH", "/v1/clients/srv", ADMIN_CREDENTIAL, Some(json!({ "name": "admin-box" }))).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    let r = bearer(&state, "PATCH", "/v1/clients/srv", &ann_token, Some(json!({ "name": "mine" }))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "machine tokens cannot manage clients");
}

fn user_id(users: &Value, name: &str) -> String {
    users["users"].as_array().unwrap().iter().find(|u| u["username"] == name).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn listed<'a>(users: &'a Value, name: &str) -> &'a Value {
    users["users"].as_array().unwrap().iter().find(|u| u["username"] == name).unwrap()
}

#[tokio::test]
async fn a_flush_forgets_a_user_nothing_holds_once_their_bytes_are_written() {
    let state = state();
    let mut owner = owner(&state).await;
    let _ann = member(&state, &mut owner, "ann", 2).await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = user_id(&users.body, "ann");
    let usage = state.traffic.usage(&state.db, &ann_id).await.unwrap();
    usage.add(10, false);
    drop(usage);
    // The flush writes the pending bytes and, in the same pass, forgets the
    // unblocked user that no counter holds any more.
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.user_traffic(ann_id.clone(), state.traffic.month()).await.unwrap(), (None, 10));
    assert!(state.traffic.loaded(&ann_id).is_none());
}

#[tokio::test]
async fn traffic_is_counted_capped_cut_reset_and_flushed() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let token = approve_machine(&state, &mut ann, "laptop").await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = user_id(&users.body, "ann");
    // Public, so a recheck needs no session: only the traffic block can refuse it.
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "can_public": true }))).await;
    assert_eq!(r.status, StatusCode::OK);
    let t = create_tunnel(&state, &token, json!({ "mode": "public" })).await;
    let id = t.body["id"].as_str().unwrap().to_string();
    assert_eq!(t.body["traffic_limited"], false);
    let row = state.db.get_tunnel(id.clone()).await.unwrap().unwrap();
    assert_eq!(row.user_id.as_deref(), Some(ann_id.as_str()));

    // Counting: per tunnel and for the user (memory first, then the flush).
    let bytes = crate::traffic::counter(&state, &row).await.unwrap();
    bytes.count(300, false);
    bytes.count(200, true);
    let view = bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &token, None).await;
    assert_eq!((view.body["bytes_in"].clone(), view.body["bytes_out"].clone()), (json!(300), json!(200)));
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    assert_eq!(listed(&users.body, "ann")["traffic_bytes"], 500);
    crate::traffic::flush(&state).await.unwrap();
    let stored = state.db.user_traffic(ann_id.clone(), state.traffic.month()).await.unwrap();
    assert_eq!(stored, (None, 500));
    let row = state.db.get_tunnel(id.clone()).await.unwrap().unwrap();
    assert_eq!((row.bytes_in, row.bytes_out), (300, 200));
    // Nothing new: the next flush writes nothing (and the figures stay).
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.user_traffic(ann_id.clone(), state.traffic.month()).await.unwrap(), (None, 500));
    let view = bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &token, None).await;
    assert_eq!(view.body["bytes_in"], 300);

    // Caps: validated, admins only, never the owner or oneself.
    for bad in [json!(0), json!(999_999), json!(-1), json!("10")] {
        let r = owner
            .call(
                &state,
                "PATCH",
                &format!("/ui/api/users/{ann_id}"),
                Some(json!({ "limits": { "traffic_bytes": bad } })),
            )
            .await;
        assert!(matches!(r.status, StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST), "{bad}: {}", r.status);
    }
    let olivia = user_id(&users.body, "olivia");
    let r = owner
        .call(
            &state,
            "PATCH",
            &format!("/ui/api/users/{olivia}"),
            Some(json!({ "limits": { "traffic_bytes": 2_000_000 } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "nobody caps the owner");
    let r = ann
        .call(
            &state,
            "PATCH",
            &format!("/ui/api/users/{ann_id}"),
            Some(json!({ "limits": { "traffic_bytes": "unlimited" } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "members cannot lift their own cap");
    let r = ann.call(&state, "POST", &format!("/ui/api/users/{ann_id}/traffic/reset"), Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "members cannot reset their own traffic");

    let r = owner
        .call(
            &state,
            "PATCH",
            &format!("/ui/api/users/{ann_id}"),
            Some(json!({ "limits": { "traffic_bytes": 1_000_000 } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["user"]["limits"]["traffic_bytes"]["effective"], 1_000_000);
    assert!(!bytes.blocked());
    let me = ann.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(me.body["traffic"]["used_bytes"], 500);
    assert_eq!(me.body["traffic"]["cap_bytes"], 1_000_000);

    // Crossing the cap blocks at once (`gate::reauthorize` refuses blocked
    // tunnels, which cuts what is in flight once the enforcer rotates the epoch).
    assert!(!crate::traffic::tunnel_blocked(&state, &id));
    bytes.count(999_500, true);
    assert!(bytes.blocked() && crate::traffic::tunnel_blocked(&state, &id));
    let view = bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &token, None).await;
    assert_eq!(view.body["traffic_limited"], true);
    let info = bearer(&state, "GET", "/v1/server", &token, None).await;
    assert_eq!(info.body["limits"]["traffic"]["limited"], true, "{}", info.body);
    assert_eq!(info.body["limits"]["traffic"]["used_bytes"], 1_000_000);
    let t2 = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    assert_eq!((t2.status, t2.body["traffic_limited"].clone()), (StatusCode::CREATED, json!(true)));
    let page = crate::pages::traffic_limit();
    assert_eq!(page.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");

    // Raising (here: removing) the cap unblocks; lowering it below the total blocks again.
    let r = owner
        .call(
            &state,
            "PATCH",
            &format!("/ui/api/users/{ann_id}"),
            Some(json!({ "limits": { "traffic_bytes": "unlimited" } })),
        )
        .await;
    assert_eq!(
        (r.status, r.body["user"]["limits"]["traffic_bytes"]["effective"].clone()),
        (StatusCode::OK, Value::Null)
    );
    assert!(!bytes.blocked());
    let r = owner
        .call(
            &state,
            "PATCH",
            &format!("/ui/api/users/{ann_id}"),
            Some(json!({ "limits": { "traffic_bytes": 1_000_000 } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(bytes.blocked());
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.users_over_cap(state.traffic.month()).await.unwrap(), vec![ann_id.clone()]);

    // A reset starts the month again (stored and in memory); the tunnel's own
    // total is not touched.
    bytes.count(7, false);
    let r = owner.call(&state, "POST", &format!("/ui/api/users/{ann_id}/traffic/reset"), Some(json!({}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["traffic"]["used_bytes"], 0);
    assert!(!bytes.blocked());
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.user_traffic(ann_id.clone(), state.traffic.month()).await.unwrap(), (Some(1_000_000), 0));
    assert!(state.db.users_over_cap(state.traffic.month()).await.unwrap().is_empty());
    let row = state.db.get_tunnel(id.clone()).await.unwrap().unwrap();
    assert_eq!((row.bytes_in, row.bytes_out), (300 + 7, 200 + 999_500));

    // A new month starts from zero for everyone.
    bytes.count(999_999, false);
    assert!(!bytes.blocked());
    bytes.count(1, false);
    assert!(bytes.blocked());
    let next = if state.traffic.month() % 100 == 12 { state.traffic.month() + 89 } else { state.traffic.month() + 1 };
    let old = state.traffic.month();
    crate::traffic::flush_or_roll_over(&state, next).await.unwrap();
    assert!(!bytes.blocked());
    assert_eq!(crate::traffic::view(&state, &ann_id).await.unwrap().used_bytes, 0);
    // The rollover's flush closed the old month with everything counted before it.
    assert_eq!(state.db.user_traffic(ann_id.clone(), old).await.unwrap(), (Some(1_000_000), 1_000_000));

    // A deleted tunnel's last bytes still reach the user's month.
    bytes.count(42, true);
    assert_eq!(
        bearer(&state, "DELETE", &format!("/v1/tunnels/{id}"), &token, None).await.status,
        StatusCode::NO_CONTENT
    );
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.user_traffic(ann_id.clone(), next).await.unwrap(), (Some(1_000_000), 42));

    let log = owner.call(&state, "GET", "/ui/api/audit", None).await;
    let actions: Vec<&str> =
        log.body["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"limit_set") && actions.contains(&"traffic_reset"), "{actions:?}");
}

#[tokio::test]
async fn new_members_get_the_configured_cap_and_admins_none() {
    let state = state_with(|c| c.limits.member_monthly_traffic_gb = Some(5));
    let mut owner = owner(&state).await;
    let _ann = member(&state, &mut owner, "ann", 2).await;
    let r = owner.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "admin" }))).await;
    let token = r.body["url"].as_str().unwrap().split_once('#').unwrap().1.to_string();
    let _adam = sign_up(&state, &token, "adam", 3).await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    assert_eq!(listed(&users.body, "ann")["limits"]["traffic_bytes"]["effective"], 5_000_000_000u64);
    assert_eq!(listed(&users.body, "adam")["limits"]["traffic_bytes"]["effective"], Value::Null);
    assert_eq!(listed(&users.body, "olivia")["limits"]["traffic_bytes"]["effective"], Value::Null);
    assert!(users.body["month"].as_str().unwrap().len() == 7);
    // Demoting an admin gives them the member default.
    let adam = user_id(&users.body, "adam");
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{adam}"), Some(json!({ "role": "member" }))).await;
    assert_eq!(
        (r.status, r.body["user"]["limits"]["traffic_bytes"]["effective"].clone()),
        (StatusCode::OK, json!(5_000_000_000u64))
    );
    let status = owner.call(&state, "GET", "/ui/api/status", None).await;
    assert_eq!(status.body["limits"]["member_monthly_traffic_gb"], 5);
}

#[tokio::test]
async fn services_and_the_owner_are_counted_but_never_capped() {
    let state = state();
    let mut owner = owner(&state).await;
    let owner_token = approve_machine(&state, &mut owner, "server").await;
    let t = create_tunnel(&state, &owner_token, json!({ "mode": "link" })).await;
    let row = state.db.get_tunnel(t.body["id"].as_str().unwrap().to_string()).await.unwrap().unwrap();
    let bytes = crate::traffic::counter(&state, &row).await.unwrap();
    bytes.count(5_000_000_000, true);
    assert!(!bytes.blocked());
    assert_eq!(bytes.owner().unwrap().cap(), None);
    // The owner's month is stored like anyone's and reloads with its total.
    crate::traffic::flush(&state).await.unwrap();
    let owner_id = row.user_id.clone().unwrap();
    assert_eq!(state.db.user_traffic(owner_id, state.traffic.month()).await.unwrap(), (None, 5_000_000_000));
    let svc =
        bearer(&state, "POST", "/v1/services", ADMIN_CREDENTIAL, Some(json!({ "name": "wssp", "max_tunnels": 5 })))
            .await;
    let svc_token = svc.body["token"].as_str().unwrap().to_string();
    let t = create_tunnel(&state, &svc_token, json!({ "mode": "link" })).await;
    let row = state.db.get_tunnel(t.body["id"].as_str().unwrap().to_string()).await.unwrap().unwrap();
    assert!(row.user_id.is_none());
    let bytes = crate::traffic::counter(&state, &row).await.unwrap();
    bytes.count(10, false);
    assert!(bytes.owner().is_none() && !bytes.blocked());
    crate::traffic::flush(&state).await.unwrap();
    let row = state.db.get_tunnel(row.id).await.unwrap().unwrap();
    assert_eq!(row.bytes_in, 10, "services' tunnels are counted per tunnel");
}

#[tokio::test]
async fn sign_in_says_how_to_claim_an_owner_without_a_password() {
    let state = state();
    let s = Browser::new(1).call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(s.body["owner_exists"], false);
    // An owner created for machines before anyone signed up cannot sign in yet.
    state.db.ensure_owner().await.unwrap();
    let s = Browser::new(1).call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(s.body["owner_exists"], false, "the hint stays until the owner is claimed");
    let _owner = owner(&state).await;
    let s = Browser::new(1).call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(s.body["owner_exists"], true);
}

#[tokio::test]
async fn a_deleted_tunnels_counter_in_use_keeps_reaching_the_month() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let token = approve_machine(&state, &mut ann, "laptop").await;
    let t = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    let id = t.body["id"].as_str().unwrap().to_string();
    let row = state.db.get_tunnel(id.clone()).await.unwrap().unwrap();
    let ann_id = row.user_id.clone().unwrap();
    // An exchange in flight holds the counter while the tunnel is deleted.
    let held = crate::traffic::counter(&state, &row).await.unwrap();
    assert_eq!(
        bearer(&state, "DELETE", &format!("/v1/tunnels/{id}"), &token, None).await.status,
        StatusCode::NO_CONTENT
    );
    let month = state.traffic.month();
    held.count(10, true);
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.user_traffic(ann_id.clone(), month).await.unwrap().1, 10);
    held.count(5, false);
    crate::traffic::flush(&state).await.unwrap();
    assert_eq!(state.db.user_traffic(ann_id.clone(), month).await.unwrap().1, 15, "counted while still in use");
    drop(held);
    crate::traffic::flush(&state).await.unwrap();
    assert!(state.metrics.get(&id).is_none(), "a deleted tunnel's counter is gone");
}

/// The Tunnels page's Open button mints a one-time, one-minute link through
/// the same API, so it gets the same checks as any other link.
#[tokio::test]
async fn open_links_follow_the_link_rules_and_are_labelled() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let mut bob = member(&state, &mut owner, "bob", 3).await;
    let ann_token = approve_machine(&state, &mut ann, "laptop").await;
    let t = create_tunnel(&state, &ann_token, json!({ "mode": "link" })).await;
    let id = t.body["id"].as_str().unwrap().to_string();
    let path = format!("/ui/api/tunnels/{id}/links");
    let open = json!({ "port": 3000, "ttl_s": 60, "single_use": true, "label": "Opened from the dashboard" });

    // Another member cannot open (or even see) Ann's tunnel.
    let r = bob.call(&state, "POST", &path, Some(open.clone())).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);
    assert!(r.body.get("url").is_none());
    assert_eq!(bob.call(&state, "GET", &path, None).await.status, StatusCode::NOT_FOUND);

    // Ann can; so can an admin (the owner), as for any link.
    for who in [&mut ann, &mut owner] {
        let r = who.call(&state, "POST", &path, Some(open.clone())).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        let url = r.body["url"].as_str().unwrap();
        assert!(url.starts_with(&format!("https://previews.example.net/__access/3000-{id}/tnacc_")), "{url}");
    }
    let listed = ann.call(&state, "GET", &path, None).await;
    let links = listed.body["links"].as_array().unwrap();
    assert_eq!(links.len(), 2);
    for l in links {
        assert_eq!(l["label"], "Opened from the dashboard");
        assert_eq!(l["single_use"], true);
        assert!(l["used_at"].is_null());
        // Expiry is taken just before the row's creation time (a second boundary may fall between).
        let lifetime = l["expires_at"].as_i64().unwrap() - l["created_at"].as_i64().unwrap();
        assert!((59..=60).contains(&lifetime), "{lifetime}");
        assert!(l.get("url").is_none(), "link URLs are never listed");
    }
    assert!(bob.call(&state, "GET", "/ui/api/tunnels?all=true", None).await.status == StatusCode::FORBIDDEN);
}

/// Pretend tunnel `id` is connected with `ports` (nothing behind them).
/// Keep the returned session alive for as long as the tunnel should be.
fn connect(state: &AppState, id: &str, ports: &[u16]) -> tunnel_protocol::mux::Session {
    let (server_io, client_io) = tokio::io::duplex(1024);
    std::mem::forget(client_io);
    let server = tunnel_protocol::mux::Session::new_server(server_io);
    let (ctrl_tx, _) = tokio::sync::mpsc::channel(1);
    state.registry.insert(Arc::new(crate::registry::LiveTunnel {
        conn_id: 1,
        tunnel_id: id.into(),
        control: server.control(),
        ports: std::sync::RwLock::new(ports.iter().copied().collect()),
        ctrl_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        connected_at: now(),
        streams: std::sync::atomic::AtomicUsize::new(0),
        pool: crate::pool::OriginPool::default(),
        token_hash: String::new(),
    }));
    server
}

/// Open is for the tunnel's own user: a single-use owner link to one
/// connected port, CSRF-protected and audited. Admins (the owner here)
/// viewing a member's tunnel get no Open link: Links makes ordinary ones.
#[tokio::test]
async fn open_mints_a_one_time_owner_link_for_the_tunnels_own_user_only() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let mut bob = member(&state, &mut owner, "bob", 3).await;
    let ann_token = approve_machine(&state, &mut ann, "laptop").await;
    let t = create_tunnel(
        &state,
        &ann_token,
        json!({ "mode": "password", "username": "u", "password": "visitor-password" }),
    )
    .await;
    let id = t.body["id"].as_str().unwrap().to_string();
    let path = format!("/ui/api/tunnels/{id}/open");

    let r = ann.call(&state, "POST", &path, Some(json!({ "port": 3000 }))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::CONFLICT, json!("port_not_connected")));
    let _live = connect(&state, &id, &[3000]);

    // Ann's own tunnel: a link on the preview zone (another site than the
    // UI here), for exactly that port.
    let r = ann.call(&state, "POST", &path, Some(json!({ "port": 3000 }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let url = r.body["url"].as_str().unwrap();
    assert!(url.starts_with(&format!("https://previews.example.net/__access/3000-{id}/tnacc_")), "{url}");
    let r = ann.call(&state, "POST", &path, Some(json!({ "port": 3001 }))).await;
    assert_eq!(r.body["error"]["code"], "port_not_connected");
    // Only the port: the lifetime and kind are the server's.
    let r = ann.call(&state, "POST", &path, Some(json!({ "port": 3000, "ttl_s": 86400 }))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);

    // Another member: not even visible. The owner (an admin): not theirs.
    let r = bob.call(&state, "POST", &path, Some(json!({ "port": 3000 }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(r.body.get("url").is_none());
    let r = owner.call(&state, "POST", &path, Some(json!({ "port": 3000 }))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("not_owner")));
    assert!(r.body.get("url").is_none());

    // A stale CSRF token, or none: refused before anything is minted.
    let mut forged = Browser { csrf: Some("not-the-token".into()), ..ann.clone() };
    let r = forged.call(&state, "POST", &path, Some(json!({ "port": 3000 }))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("csrf")));

    // One owner link, single use, a minute at most, never listed with its URL.
    let links = ann.call(&state, "GET", &format!("/ui/api/tunnels/{id}/links"), None).await;
    let links = links.body["links"].as_array().unwrap().clone();
    assert_eq!(links.len(), 1, "{links:?}");
    let l = &links[0];
    assert_eq!(
        (l["kind"].clone(), l["label"].clone(), l["single_use"].clone()),
        (json!("owner"), json!("Opened from the dashboard"), json!(true))
    );
    let lifetime = l["expires_at"].as_i64().unwrap() - l["created_at"].as_i64().unwrap();
    assert!((59..=60).contains(&lifetime), "{lifetime}");
    assert!(l.get("url").is_none());
    // Audited like any link (no token in the log).
    let audit = owner.call(&state, "GET", "/ui/api/audit", None).await;
    let opened: Vec<_> =
        audit.body["entries"].as_array().unwrap().iter().filter(|e| e["action"] == "tunnel_opened").collect();
    assert_eq!(opened.len(), 1, "{}", audit.body);
    let target = opened[0]["target"].as_str().unwrap();
    assert!(target.contains(&id) && target.ends_with("port 3000") && !target.contains("tnacc_"), "{target}");

    // The list tells the UI whose tunnel it is.
    let mine = ann.call(&state, "GET", "/ui/api/tunnels", None).await;
    assert_eq!(mine.body["tunnels"][0]["mine"], true);
    let all = owner.call(&state, "GET", "/ui/api/tunnels?all=true", None).await;
    let row = all.body["tunnels"].as_array().unwrap().iter().find(|t| t["id"] == id.as_str()).unwrap().clone();
    assert_eq!(row["mine"], false);

    // A tunnel in its last half minute cannot be opened (the link would outlive it).
    state
        .db
        .call({
            let id = id.clone();
            move |c| {
                c.execute("UPDATE tunnels SET expires_at = ?2 WHERE id = ?1", rusqlite::params![id, now() + 20])?;
                Ok(())
            }
        })
        .await
        .unwrap();
    state.invalidate_tunnel(&id);
    let r = ann.call(&state, "POST", &path, Some(json!({ "port": 3000 }))).await;
    assert_eq!(r.body["error"]["code"], "tunnel_ending", "{}", r.body);
}

/// A display name: trimmed, bounded, printable; set on create, renamed by
/// whoever may manage the tunnel, audited, and never touching its URLs.
#[tokio::test]
async fn tunnels_carry_a_display_name_that_whoever_manages_them_can_change() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut ann = member(&state, &mut owner, "ann", 2).await;
    let mut bob = member(&state, &mut owner, "bob", 3).await;
    let ann_token = approve_machine(&state, &mut ann, "laptop").await;
    let make =
        |name: Value| bearer(&state, "POST", "/v1/tunnels", &ann_token, Some(json!({ "ttl_s": 3600, "name": name })));

    for bad in [
        json!("a\u{1b}[2Jb"),
        json!("line\nbreak"),
        json!("x\u{202e}gpj.exe"),
        json!("zero\u{200b}width"),
        json!("arabic\u{61c}mark"),
        json!("\u{3164}"),
        json!("\u{206a}"),
        json!("tag\u{e0041}"),
        json!("é".repeat(81)),
    ] {
        let r = make(bad.clone()).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {}", r.body);
    }
    let r = make(json!("  Checkout redesign  ")).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let id = r.body["id"].as_str().unwrap().to_string();
    let host_template = r.body["host_template"].clone();
    let view = bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &ann_token, None).await;
    assert_eq!(view.body["name"], "Checkout redesign");
    assert_eq!(make(json!("")).await.body["name"], Value::Null, "empty is no name");
    let dup = make(json!("Checkout redesign")).await;
    assert_eq!(dup.status, StatusCode::CREATED, "names need not be unique");

    let path = format!("/ui/api/tunnels/{id}");
    // Stored and returned as typed: HTML is text, escaped where it is shown.
    let r = ann.call(&state, "PATCH", &path, Some(json!({ "name": "<img src=x onerror=alert(1)> & co" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let list = ann.call(&state, "GET", "/ui/api/tunnels", None).await;
    let row = list.body["tunnels"].as_array().unwrap().iter().find(|t| t["id"] == id.as_str()).unwrap().clone();
    assert_eq!(row["name"], "<img src=x onerror=alert(1)> & co");
    assert_eq!(row["host_template"], host_template, "a rename never changes a URL");
    let r = ann.call(&state, "PATCH", &path, Some(json!({ "name": "bad\u{7}" }))).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Bob may not; an admin (the owner) may rename a member's tunnel.
    assert_eq!(
        bob.call(&state, "PATCH", &path, Some(json!({ "name": "mine now" }))).await.status,
        StatusCode::NOT_FOUND
    );
    let r = owner.call(&state, "PATCH", &path, Some(json!({ "name": "Reviewed" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // The machine can rename it too, and "" removes the name.
    let r = bearer(&state, "PATCH", &format!("/v1/tunnels/{id}"), &ann_token, Some(json!({ "name": "" }))).await;
    assert_eq!((r.status, r.body["name"].clone()), (StatusCode::OK, Value::Null));
    assert_eq!(r.body["host_template"], host_template);

    // The write re-checks the session and the right to the tunnel in its own
    // transaction (an admin demoted, or a session revoked, mid-request).
    let session_of = |b: &Browser| tokens::hash_token(b.cookie.as_ref().unwrap().split_once('=').unwrap().1);
    let user_id = |r: &Resp| r.body["user"]["id"].as_str().unwrap().to_string();
    let bob_id = user_id(&bob.call(&state, "GET", "/ui/api/session", None).await);
    let ann_id = user_id(&ann.call(&state, "GET", "/ui/api/session", None).await);
    let db = &state.db;
    let rename = |user: String, session: String| db.rename_tunnel_for(id.clone(), Some("x".into()), user, session);
    assert_eq!(rename(bob_id, session_of(&bob)).await.unwrap(), None, "not bob's");
    assert_eq!(rename(ann_id.clone(), "not-a-live-session".into()).await.unwrap(), None, "signed out");
    assert_eq!(rename(ann_id, session_of(&ann)).await.unwrap(), Some(None));

    let audit = owner.call(&state, "GET", "/ui/api/audit", None).await;
    let renames: Vec<String> = audit.body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "tunnel_renamed")
        .map(|e| e["target"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(renames.len(), 2, "{renames:?}");
    assert!(
        renames.iter().any(|t| t == &format!("{id}: <img src=x onerror=alert(1)> & co -> Reviewed")),
        "{renames:?}"
    );
}

#[path = "limit_tests.rs"]
mod limit_tests;
