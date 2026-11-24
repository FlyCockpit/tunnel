//! `/ui/api/*` handlers. Request checks run before routing (see `ui::check_request`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::Engine;
use http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tunnel_protocol::CloseReason;

use super::store::{AcceptError, Acceptance, DecideError, InviteKind, NewUser, RenameError, Role, User, UserPatch};
use super::{AdminSigned, Ctx, REAUTH_S, Signed, clear_cookie, session_cookie, totp};
use crate::api::{self, ApiError, ApiJson, ApiResult, CreateAccessLinkRequest};
use crate::clients;
use crate::db::{DeleteOutcome, NewClientError, TunnelRow};
use crate::device::normalize_user_code;
use crate::password::{self, Verdict};
use crate::state::AppState;
use crate::tokens::{self, now};

pub const INVITE_PREFIX: &str = "tninv_";
const MIN_ACCOUNT_PASSWORD: usize = 10;
const MAX_USERNAME: usize = 32;
const RECOVERY_CODES: usize = 10;
/// Invites last this long unless the admin picks another lifetime (1 h ..= 30 d).
const INVITE_TTL_S: i64 = 7 * 86_400;
pub const OWNER_LINK_TTL_S: i64 = 15 * 60;
/// Argon2id PHC of a public fixture password, checked when a username is
/// unknown so that answers take as long as for a wrong password.
const DUMMY_PHC: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$cHVibGljLXRlc3Qtc2FsdA$BimFkRyg6Ge8LT3LbudUr7ob0dRYFhuwqMT54saxJvQ";

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ui/api/session", get(session))
        .route("/ui/api/login", post(login))
        .route("/ui/api/login/totp", post(login_totp))
        .route("/ui/api/logout", post(logout))
        .route("/ui/api/invite/info", post(invite_info))
        .route("/ui/api/invite/accept", post(invite_accept))
        .route("/ui/api/cli", get(cli_info))
        .route("/ui/api/account/password", post(change_password))
        .route("/ui/api/account/totp/setup", post(totp_setup))
        .route("/ui/api/account/totp/enable", post(totp_enable))
        .route("/ui/api/account/totp/disable", post(totp_disable))
        .route("/ui/api/account/sessions", get(list_sessions))
        .route("/ui/api/account/sessions/revoke", post(revoke_session))
        .route("/ui/api/machines", get(list_machines).post(add_machine))
        .route("/ui/api/machines/{name}", delete(delete_machine).patch(rename_machine))
        .route("/ui/api/tunnels", get(list_tunnels))
        .route("/ui/api/tunnels/{id}", delete(delete_tunnel))
        .route("/ui/api/tunnels/{id}/links", get(list_links).post(create_link))
        .route("/ui/api/links/{id}", delete(revoke_link))
        .route("/ui/api/device/lookup", post(device_lookup))
        .route("/ui/api/device/decide", post(device_decide))
        .route("/ui/api/users", get(list_users))
        .route("/ui/api/users/{id}", patch(update_user))
        .route("/ui/api/users/{id}/traffic/reset", post(reset_user_traffic))
        .route("/ui/api/invites", get(list_invites).post(create_invite))
        .route("/ui/api/invites/{id}", delete(delete_invite))
        .route("/ui/api/services", get(list_services))
        .route("/ui/api/audit", get(audit_log))
        .route("/ui/api/status", get(status))
        .fallback(|| async { ApiError::not_found("route") })
}

/// The user's sign-in changed (password, two-factor, reset) or this session
/// ended while the request ran.
fn changed_meanwhile() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "signed_out", "your sign-in changed meanwhile; sign in again")
}

fn too_many() -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute")
}

fn busy() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy checking passwords; try again")
}

fn bad_credentials() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "wrong username or password")
}

fn with_cookie(cookie: String, body: Value) -> Response {
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).expect("cookie is ASCII"));
    resp
}

fn keys(state: &AppState) -> ApiResult<&super::seal::Keys> {
    state.ui.keys.as_ref().ok_or_else(|| ApiError::not_found("route"))
}

async fn audit(state: &AppState, user: Option<&str>, action: &'static str, target: Option<String>, ctx: &Ctx) {
    if let Err(e) = state.db.audit(user.map(str::to_string), action, target, ctx.ip_string()).await {
        tracing::warn!(error = %format!("{e:#}"), action, "audit write failed");
    }
}

pub fn validate_username(name: &str) -> ApiResult<String> {
    let name = name.trim().to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= MAX_USERNAME
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(name)
    } else {
        Err(ApiError::validation(format!(
            "username: 1..={MAX_USERNAME} characters: letters, digits, '.', '_', '-', starting with a letter or digit"
        )))
    }
}

fn validate_password(password: &str) -> ApiResult<()> {
    let n = password.chars().count();
    if (MIN_ACCOUNT_PASSWORD..=password::MAX_PASSWORD_LEN).contains(&n) {
        Ok(())
    } else {
        Err(ApiError::validation(format!(
            "password must be {MIN_ACCOUNT_PASSWORD}..={} characters",
            password::MAX_PASSWORD_LEN
        )))
    }
}

/// A fresh signed-in session for `user_id`; returns the cookie and CSRF token.
/// A fresh session for `user_id`, issued only while the user's auth epoch is
/// still `epoch` (see `Db::create_ui_session`); `replace` is a pending
/// session to swap out. Returns the cookie and CSRF token.
async fn start_session(
    state: &AppState,
    user_id: &str,
    pending: bool,
    epoch: i64,
    replace: Option<String>,
    ctx: &Ctx,
) -> ApiResult<(String, String)> {
    let id = tokens::random_secret();
    let issued = state
        .db
        .create_ui_session(
            tokens::hash_token(&id),
            user_id.to_string(),
            pending,
            epoch,
            replace,
            ctx.ip_string(),
            ctx.user_agent.clone(),
        )
        .await?;
    if !issued {
        // The password, second factor, role or status changed meanwhile.
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "signed_out",
            "your sign-in changed meanwhile; sign in again",
        ));
    }
    let max_age = if pending { super::store::PENDING_TTL_S } else { super::store::SESSION_MAX_S };
    Ok((session_cookie(&id, max_age), keys(state)?.csrf_token(&id)))
}

/// Check the current password of `user_id` (rate-limited per user, before Argon2).
/// Check the current password of `user_id` (rate-limited per user, before
/// Argon2). Returns the auth epoch it was checked at.
async fn check_password(state: &AppState, user_id: &str, password: &str) -> ApiResult<i64> {
    if !state.ui.reauth.check_key(user_id.to_string()) {
        return Err(too_many());
    }
    let creds = state.db.credentials(None, Some(user_id.to_string())).await?.ok_or_else(bad_credentials)?;
    match password::verify_phc(creds.password_hash, password.to_string()).await {
        Verdict::Match => Ok(creds.auth_epoch),
        Verdict::NoMatch => {
            Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid_password", "the current password is wrong"))
        }
        Verdict::Busy => Err(busy()),
    }
}

/// Check a TOTP code or recovery code for `user_id` (single use either way).
/// Check a TOTP code or recovery code for `user_id` (single use either
/// way). `limiter` is the pre-session (sign-in) or in-session one. Wrong
/// codes count towards a lockout that survives restarts: five in a row lock
/// the second factor for 15 minutes, doubling up to a day.
async fn check_second_factor(
    state: &AppState,
    limiter: &crate::ratelimit::Limiter<String>,
    user_id: &str,
    code: &str,
) -> ApiResult<()> {
    if !limiter.check_key(user_id.to_string()) {
        return Err(too_many());
    }
    let wrong = || ApiError::new(StatusCode::UNAUTHORIZED, "invalid_code", "wrong or already used code");
    let creds = state.db.credentials(None, Some(user_id.to_string())).await?.ok_or_else(wrong)?;
    if let Some(until) = creds.factor_locked_until.filter(|u| *u > now()) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "locked",
            format!("too many wrong codes; try again in {} minutes", (until - now()) / 60 + 1),
        ));
    }
    let sealed = creds.totp_sealed.ok_or_else(wrong)?;
    let normalized: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    let ok = if normalized.len() == 6 && normalized.bytes().all(|b| b.is_ascii_digit()) {
        let secret = keys(state)?.open(&sealed, &totp_aad(user_id)).ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!("TOTP secret of {user_id} does not open (ui_secret changed?)"))
        })?;
        match totp::verify(&secret, &normalized, now(), creds.totp_last_step) {
            Some(step) => state.db.use_totp_step(user_id.to_string(), step).await?,
            None => false,
        }
    } else if normalized.len() == 10 {
        state.db.use_recovery_code(user_id.to_string(), tokens::hash_token(&normalized)).await?
    } else {
        false
    };
    if ok {
        state.db.factor_ok(user_id.to_string()).await?;
        Ok(())
    } else {
        if state.db.factor_failed(user_id.to_string()).await?.is_some() {
            tracing::warn!(user = %user_id, "second factor locked after repeated wrong codes");
        }
        Err(wrong())
    }
}

/// TOTP users confirm sensitive steps with a code when their last password
/// or code check is older than [`REAUTH_S`].
async fn require_fresh_auth(state: &AppState, s: &Signed, code: Option<&str>) -> ApiResult<()> {
    if !s.user().totp || now() - s.session.auth_at <= REAUTH_S {
        return Ok(());
    }
    let code = code.ok_or_else(|| {
        ApiError::new(StatusCode::UNAUTHORIZED, "code_required", "enter a code from your authenticator app")
    })?;
    check_second_factor(state, &state.ui.reauth, &s.user().id, code).await?;
    state.db.touch_ui_auth(s.session.id_hash.clone()).await?;
    Ok(())
}

fn totp_aad(user_id: &str) -> String {
    format!("totp:{user_id}")
}

// ------------------------------------------------------------------ session

#[derive(Serialize)]
struct ServerSummary {
    version: &'static str,
    ui_origin: String,
    api_origin: String,
    preview_zone: String,
    /// Previews share the UI's registrable domain (see the README).
    same_site: bool,
    abuse_contact: Option<String>,
}

fn server_summary(state: &AppState) -> ServerSummary {
    let cfg = &state.config;
    ServerSummary {
        version: env!("CARGO_PKG_VERSION"),
        ui_origin: format!("https://{}", cfg.ui_host.as_deref().unwrap_or_default()),
        api_origin: format!("https://{}", cfg.api_host),
        preview_zone: cfg.preview_zone.clone(),
        same_site: cfg.ui_same_site_as_previews(),
        abuse_contact: cfg.abuse_contact.clone(),
    }
}

/// A user for the UI API, with their limits: per limit the setting, the
/// server default for the role and the limit in force (`null`: unlimited).
fn user_json(state: &AppState, user: &User) -> Value {
    let mut v = serde_json::to_value(user).unwrap_or_default();
    v["limits"] = state.db.limit_defaults().view(user.role, &user.limits);
    v
}

/// What the user uses of their tunnel and machine limits.
async fn usage_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let (machines, tunnels) = state.db.user_usage(user_id.to_string()).await?;
    Ok(json!({ "tunnels": tunnels, "machines": machines }))
}

async fn session(State(state): State<Arc<AppState>>, ctx: Ctx) -> ApiResult<Json<Value>> {
    // An owner someone can sign in as: one created for machines before anyone
    // signed up has no password yet, and the sign-in page should say how to claim it.
    let owner_exists = state.db.owner_exists().await? && !state.db.owner_without_password().await?;
    let server = server_summary(&state);
    Ok(Json(match &ctx.session {
        Some((id, s)) if !s.pending => json!({
            "user": user_json(&state, &s.user), "pending": false, "csrf": keys(&state)?.csrf_token(id),
            "owner_exists": owner_exists, "server": server,
            "traffic": crate::traffic::view(&state, &s.user.id).await?,
            "usage": usage_json(&state, &s.user.id).await?,
        }),
        Some((_, s)) => {
            json!({ "user": null, "pending": true, "pending_user": s.user.username, "csrf": null, "owner_exists": owner_exists, "server": server })
        }
        None => json!({ "user": null, "pending": false, "csrf": null, "owner_exists": owner_exists, "server": server }),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    ctx: Ctx,
    ApiJson(req): ApiJson<LoginRequest>,
) -> ApiResult<Response> {
    // Limits come first, so a flood never reaches Argon2.
    if ctx.ip.is_some_and(|ip| !state.ui.login_ip.check(ip)) {
        return Err(too_many());
    }
    let username = req.username.trim().to_ascii_lowercase();
    if username.is_empty() || username.len() > MAX_USERNAME || req.password.chars().count() > password::MAX_PASSWORD_LEN
    {
        return Err(bad_credentials());
    }
    if !state.ui.login_user.check_key(username.clone()) {
        return Err(too_many());
    }
    let creds = state.db.credentials(Some(username.clone()), None).await?.filter(|c| c.user.username == username);
    let (phc, known) = match &creds {
        Some(c) if !c.user.disabled => (c.password_hash.clone(), true),
        _ => (DUMMY_PHC.to_string(), false),
    };
    match password::verify_phc(phc, req.password).await {
        Verdict::Busy => return Err(busy()),
        Verdict::Match if known => {}
        _ => {
            audit(&state, creds.as_ref().map(|c| c.user.id.as_str()), "login_failed", Some(username), &ctx).await;
            return Err(bad_credentials());
        }
    }
    let creds = creds.expect("known user");
    if let Some((old, _)) = &ctx.session {
        state.db.delete_ui_session(tokens::hash_token(old)).await?;
    }
    let pending = creds.totp_sealed.is_some();
    // Issued only if nothing changed while Argon2 ran (a reset, TOTP turned on).
    let (cookie, csrf) = start_session(&state, &creds.user.id, pending, creds.auth_epoch, None, &ctx).await?;
    if pending {
        return Ok(with_cookie(cookie, json!({ "status": "totp_required" })));
    }
    audit(&state, Some(&creds.user.id), "login", None, &ctx).await;
    Ok(with_cookie(cookie, json!({ "status": "ok", "csrf": csrf })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeRequest {
    code: String,
}

/// Second step: the pending session plus a TOTP or recovery code gives a new
/// (rotated) signed-in session.
async fn login_totp(
    State(state): State<Arc<AppState>>,
    ctx: Ctx,
    ApiJson(req): ApiJson<CodeRequest>,
) -> ApiResult<Response> {
    let Some((id, s)) = ctx.session.as_ref().filter(|(_, s)| s.pending) else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "signed_out", "sign in with your password first"));
    };
    let user_id = s.user.id.clone();
    if let Err(e) = check_second_factor(&state, &state.ui.login_factor, &user_id, &req.code).await {
        audit(&state, Some(&user_id), "login_failed", Some("second factor".into()), &ctx).await;
        return Err(e);
    }
    // Swaps the pending session for a full one only if it still exists and
    // the user's sign-in has not changed since the password was checked.
    let (cookie, csrf) =
        start_session(&state, &user_id, false, s.auth_epoch, Some(tokens::hash_token(id)), &ctx).await?;
    audit(&state, Some(&user_id), "login", None, &ctx).await;
    let left = state.db.recovery_codes_left(user_id).await?;
    Ok(with_cookie(cookie, json!({ "status": "ok", "csrf": csrf, "recovery_codes_left": left })))
}

async fn logout(State(state): State<Arc<AppState>>, ctx: Ctx) -> ApiResult<Response> {
    // A pending session may sign out too; writes in a full session need the CSRF token.
    if let Some((id, s)) = &ctx.session {
        if !s.pending {
            let expected = keys(&state)?.csrf_token(id);
            if !ctx.csrf_header.as_deref().is_some_and(|got| tokens::hashes_equal(got, &expected)) {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "csrf",
                    "missing or stale CSRF token; reload the page",
                ));
            }
        }
        state.db.delete_ui_session(tokens::hash_token(id)).await?;
        audit(&state, Some(&s.user.id), "logout", None, &ctx).await;
    }
    Ok(with_cookie(clear_cookie(), json!({ "status": "ok" })))
}

// ------------------------------------------------------------------ invites

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    token: String,
}

fn invite_token_hash(token: &str) -> ApiResult<String> {
    let token = token.trim();
    if !token.starts_with(INVITE_PREFIX) || token.len() > 128 {
        return Err(invalid_invite());
    }
    Ok(tokens::hash_token(token))
}

fn invalid_invite() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "invalid_invite", "this link is invalid, used or expired; ask for a new one")
}

async fn invite_info(
    State(state): State<Arc<AppState>>,
    ctx: Ctx,
    ApiJson(req): ApiJson<TokenRequest>,
) -> ApiResult<Json<Value>> {
    if ctx.ip.is_some_and(|ip| !state.ui.login_ip.check(ip)) {
        return Err(too_many());
    }
    let (invite, owner) = state.db.invite_by_token(invite_token_hash(&req.token)?).await?.ok_or_else(invalid_invite)?;
    Ok(Json(json!({
        "kind": invite.kind, "role": invite.role, "expires_at": invite.expires_at,
        "invited_by": invite.created_by, "username": owner,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptRequest {
    token: String,
    /// Ignored for an owner reset (the owner keeps their name).
    #[serde(default)]
    username: Option<String>,
    password: String,
    /// Owner reset only: also remove the owner's machines (their tokens stop working).
    #[serde(default)]
    revoke_machines: bool,
}

async fn invite_accept(
    State(state): State<Arc<AppState>>,
    ctx: Ctx,
    ApiJson(req): ApiJson<AcceptRequest>,
) -> ApiResult<Response> {
    if ctx.ip.is_some_and(|ip| !state.ui.login_ip.check(ip)) {
        return Err(too_many());
    }
    let hash = invite_token_hash(&req.token)?;
    let (invite, _) = state.db.invite_by_token(hash.clone()).await?.ok_or_else(invalid_invite)?;
    validate_password(&req.password)?;
    let password_hash = password::hash(req.password).await.map_err(|_| busy())?;
    let acceptance = if invite.kind == InviteKind::OwnerReset {
        Acceptance::OwnerReset { password_hash, revoke_machines: req.revoke_machines }
    } else {
        let username = validate_username(req.username.as_deref().unwrap_or_default())?;
        // New users start on the server defaults for their role.
        Acceptance::NewUser(NewUser {
            id: format!("us{}", tokens::random_tunnel_id()),
            username,
            password_hash,
            can_public: false,
        })
    };
    let (user_id, epoch, tunnels) = match state.db.accept_invite(hash, acceptance).await? {
        Ok(found) => found,
        Err(AcceptError::UsernameTaken) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "username_taken", "that username is taken"));
        }
        Err(AcceptError::Invalid | AcceptError::OwnerState) => return Err(invalid_invite()),
    };
    let action = match invite.kind {
        InviteKind::Invite => "user_created",
        InviteKind::OwnerSetup => "owner_created",
        InviteKind::OwnerReset => "owner_reset",
    };
    for t in &tunnels {
        state.delete_tunnel(t, CloseReason::Deleted).await?;
    }
    audit(&state, Some(&user_id), action, Some(invite.id), &ctx).await;
    if let Some((old, _)) = &ctx.session {
        state.db.delete_ui_session(tokens::hash_token(old)).await?;
    }
    let (cookie, csrf) = start_session(&state, &user_id, false, epoch, None, &ctx).await?;
    Ok(with_cookie(cookie, json!({ "status": "ok", "csrf": csrf })))
}

async fn cli_info(State(state): State<Arc<AppState>>) -> Json<Value> {
    let ui = state.config.ui_host.clone().unwrap_or_default();
    let version = env!("CARGO_PKG_VERSION");
    Json(json!({
        "version": version,
        "ui_origin": format!("https://{ui}"),
        "repository": "FlyCockpit/tunnel",
        "release_url": format!("https://github.com/FlyCockpit/tunnel/releases/tag/v{version}"),
        "install_sh": format!("curl -fsSL https://{ui}/install.sh | sh"),
        "install_ps1": format!("irm https://{ui}/install.ps1 | iex"),
        "brew": "brew install FlyCockpit/tap/tunnel",
        "login": format!("tunnel login https://{ui}"),
    }))
}

// ------------------------------------------------------------------ account

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChange {
    current: String,
    new: String,
}

/// New password: every session ends, including this one, which is replaced.
async fn change_password(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<PasswordChange>,
) -> ApiResult<Response> {
    validate_password(&req.new)?;
    let user_id = s.user().id.clone();
    let checked_at = check_password(&state, &user_id, &req.current).await?;
    let hash = password::hash(req.new).await.map_err(|_| busy())?;
    // One transaction: the new hash and the end of every session.
    let epoch = state
        .db
        .set_password(user_id.clone(), hash, checked_at, s.session.id_hash.clone())
        .await?
        .ok_or_else(changed_meanwhile)?;
    audit(&state, Some(&user_id), "password_changed", None, &s.ctx).await;
    let (cookie, csrf) = start_session(&state, &user_id, false, epoch, None, &s.ctx).await?;
    Ok(with_cookie(cookie, json!({ "status": "ok", "csrf": csrf })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordConfirm {
    password: String,
}

async fn totp_setup(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<PasswordConfirm>,
) -> ApiResult<Json<Value>> {
    let user = s.user().clone();
    if user.totp {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "totp_enabled",
            "two-factor sign-in is already on; turn it off first",
        ));
    }
    check_password(&state, &user.id, &req.password).await?;
    let mut secret = [0u8; totp::SECRET_LEN];
    {
        use rand::TryRng;
        rand::rngs::SysRng.try_fill_bytes(&mut secret).expect("OS random source failed");
    }
    let sealed = keys(&state)?.seal(&secret, &totp_aad(&user.id));
    if !state.db.set_totp_pending(user.id.clone(), sealed, s.session.id_hash.clone()).await? {
        return Err(changed_meanwhile());
    }
    let issuer = format!("Tunnel {}", state.config.ui_host.as_deref().unwrap_or_default());
    let uri = totp::otpauth_uri(&issuer, &user.username, &secret);
    let qr = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| ApiError::internal(anyhow::anyhow!("qr: {e}")))?;
    let svg = qr.render::<qrcode::render::svg::Color<'_>>().min_dimensions(200, 200).quiet_zone(true).build();
    let data_uri =
        format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg.as_bytes()));
    Ok(Json(json!({ "secret": totp::base32(&secret), "otpauth_uri": uri, "qr": data_uri })))
}

fn new_recovery_codes() -> (Vec<String>, Vec<String>) {
    use rand::TryRng;
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut shown = Vec::new();
    let mut hashes = Vec::new();
    for _ in 0..RECOVERY_CODES {
        let mut bytes = [0u8; 10];
        rand::rngs::SysRng.try_fill_bytes(&mut bytes).expect("OS random source failed");
        let code: String = bytes.iter().map(|b| ALPHABET[(b & 31) as usize] as char).collect();
        hashes.push(tokens::hash_token(&code));
        shown.push(format!("{}-{}", &code[..5], &code[5..]));
    }
    (shown, hashes)
}

async fn totp_enable(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<CodeRequest>,
) -> ApiResult<Json<Value>> {
    let user_id = s.user().id.clone();
    if !state.ui.reauth.check_key(user_id.clone()) {
        return Err(too_many());
    }
    let creds = state.db.credentials(None, Some(user_id.clone())).await?.ok_or_else(|| ApiError::not_found("user"))?;
    let sealed = creds
        .totp_pending_sealed
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no_setup", "start two-factor setup first"))?;
    let secret = keys(&state)?
        .open(&sealed, &totp_aad(&user_id))
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("pending TOTP secret does not open")))?;
    let step = totp::verify(&secret, &req.code, now(), None).ok_or_else(|| {
        ApiError::new(StatusCode::UNAUTHORIZED, "invalid_code", "wrong code; check the time on your device")
    })?;
    let (shown, hashes) = new_recovery_codes();
    if !state.db.enable_totp(user_id.clone(), sealed, step, hashes, creds.auth_epoch, s.session.id_hash.clone()).await?
    {
        return Err(ApiError::new(StatusCode::CONFLICT, "no_setup", "setup was restarted; scan the new code"));
    }
    audit(&state, Some(&user_id), "totp_enabled", None, &s.ctx).await;
    Ok(Json(json!({ "recovery_codes": shown })))
}

async fn totp_disable(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<PasswordConfirm>,
) -> ApiResult<Json<Value>> {
    let user_id = s.user().id.clone();
    let checked_at = check_password(&state, &user_id, &req.password).await?;
    if !state.db.disable_totp(user_id.clone(), checked_at, s.session.id_hash.clone()).await? {
        return Err(changed_meanwhile());
    }
    audit(&state, Some(&user_id), "totp_disabled", None, &s.ctx).await;
    Ok(Json(json!({ "status": "ok" })))
}

async fn list_sessions(State(state): State<Arc<AppState>>, s: Signed) -> ApiResult<Json<Value>> {
    let sessions = state.db.list_user_sessions(s.user().id.clone(), s.session.id_hash.clone()).await?;
    Ok(Json(json!({ "sessions": sessions })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeSession {
    /// A session id from the list, or `others` for every other session.
    id: String,
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<RevokeSession>,
) -> ApiResult<Json<Value>> {
    let user_id = s.user().id.clone();
    let prefix = (req.id != "others").then(|| req.id.clone());
    let n = state
        .db
        .revoke_own_sessions(user_id.clone(), s.session.id_hash.clone(), prefix.clone())
        .await?
        .ok_or_else(changed_meanwhile)?;
    if prefix.is_some() && n == 0 {
        return Err(ApiError::not_found("session"));
    }
    let target = prefix.unwrap_or_else(|| format!("{n} others"));
    audit(&state, Some(&user_id), "sessions_revoked", Some(target), &s.ctx).await;
    Ok(Json(json!({ "revoked": n })))
}

// ----------------------------------------------------------------- machines

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AllQuery {
    #[serde(default)]
    all: Option<bool>,
}

/// `?all=true` (admins): everyone's.
fn scope(s: &Signed, q: &AllQuery) -> ApiResult<Option<String>> {
    match q.all {
        Some(true) if s.user().role.is_admin() => Ok(None),
        Some(true) => Err(ApiError::new(StatusCode::FORBIDDEN, "admin_only", "only admins can list everyone's")),
        _ => Ok(Some(s.user().id.clone())),
    }
}

async fn list_machines(State(state): State<Arc<AppState>>, s: Signed, q: Query<AllQuery>) -> ApiResult<Json<Value>> {
    let machines = state.db.list_machines(scope(&s, &q)?).await?;
    Ok(Json(json!({ "machines": machines })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewMachine {
    name: String,
    /// TOTP or recovery code when the session's last check is stale (as for approval).
    #[serde(default)]
    code: Option<String>,
}

/// A login code for a machine without a browser (`tunnel login <code>`).
async fn add_machine(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<NewMachine>,
) -> ApiResult<Json<Value>> {
    let user_id = s.user().id.clone();
    require_fresh_auth(&state, &s, req.code.as_deref()).await?;
    match clients::add(&state.db, &state.config, &req.name, &user_id, Some(s.session.id_hash.clone())).await {
        Ok(e) => {
            audit(&state, Some(&user_id), "machine_added", Some(e.name.clone()), &s.ctx).await;
            Ok(Json(json!({ "name": e.name, "login_code": e.login_code, "expires_at": e.expires_at })))
        }
        Err(clients::AddError::Invalid(m)) => Err(ApiError::validation(m)),
        Err(clients::AddError::Taken) => {
            Err(ApiError::new(StatusCode::CONFLICT, "client_exists", "a machine with this name exists; pick another"))
        }
        Err(clients::AddError::Quota { limit, role }) => Err(client_quota(limit, role)),
        Err(clients::AddError::NoUser) => Err(ApiError::new(StatusCode::FORBIDDEN, "disabled", "account disabled")),
        Err(clients::AddError::Other(e)) => Err(e.into()),
    }
}

fn client_quota(limit: u64, role: Role) -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "client_quota", crate::limits::machine_limit_message(limit, role))
}

/// May `actor` act on what `target_user_id` owns? Their own things, admins
/// on members', the owner on everyone's.
async fn may_manage(state: &AppState, actor: &User, target_user_id: &str) -> ApiResult<bool> {
    if actor.id == target_user_id || actor.role == Role::Owner {
        return Ok(true);
    }
    if actor.role != Role::Admin {
        return Ok(false);
    }
    let target = state.db.credentials(None, Some(target_user_id.to_string())).await?;
    Ok(target.is_some_and(|t| t.user.role == Role::Member))
}

async fn delete_machine(
    State(state): State<Arc<AppState>>,
    s: Signed,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let tunnels = state
        .db
        .delete_client_for(name.clone(), s.user().id.clone())
        .await?
        .ok_or_else(|| ApiError::not_found("machine"))?;
    for id in &tunnels {
        state.delete_tunnel(id, CloseReason::Deleted).await?;
    }
    audit(&state, Some(&s.user().id), "machine_deleted", Some(name), &s.ctx).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameMachine {
    name: String,
}

/// Rename a machine: one's own, admins also members', the owner anyone's.
async fn rename_machine(
    State(state): State<Arc<AppState>>,
    s: Signed,
    Path(name): Path<String>,
    ApiJson(req): ApiJson<RenameMachine>,
) -> ApiResult<Json<Value>> {
    clients::validate_new_name(&req.name).map_err(ApiError::validation)?;
    let actor = Some((s.user().id.clone(), s.session.id_hash.clone()));
    match state.db.rename_client(name.clone(), req.name.clone(), actor).await? {
        Ok(()) => {}
        Err(RenameError::NotFound) => return Err(ApiError::not_found("machine")),
        Err(RenameError::Taken) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "client_exists",
                "a machine with this name exists; pick another",
            ));
        }
        Err(RenameError::SignedOut) => return Err(changed_meanwhile()),
    }
    if name != req.name {
        audit(&state, Some(&s.user().id), "machine_renamed", Some(format!("{name} -> {}", req.name)), &s.ctx).await;
    }
    Ok(Json(json!({ "name": req.name })))
}

// ------------------------------------------------------------------ tunnels

#[derive(Serialize)]
struct UiTunnel {
    #[serde(flatten)]
    view: api::TunnelView,
    /// The machine (or service) that created it.
    owner: Option<String>,
    user: Option<String>,
}

async fn list_tunnels(State(state): State<Arc<AppState>>, s: Signed, q: Query<AllQuery>) -> ApiResult<Json<Value>> {
    // Stored bytes and unflushed ones from the same side of any flush.
    let _reading = state.traffic.reading().await;
    let rows = state.db.list_user_tunnels(scope(&s, &q)?).await?;
    let tunnels: Vec<UiTunnel> = rows
        .into_iter()
        .map(|(row, owner, user)| UiTunnel { view: api::tunnel_view(&state, &row), owner, user })
        .collect();
    Ok(Json(json!({ "tunnels": tunnels })))
}

/// A tunnel the signed-in user may manage; anything else is "not found".
async fn ui_tunnel(state: &AppState, s: &Signed, id: &str) -> ApiResult<TunnelRow> {
    if !tokens::is_valid_tunnel_id(id) {
        return Err(ApiError::not_found("tunnel"));
    }
    let row = state.db.get_tunnel(id.to_string()).await?.ok_or_else(|| ApiError::not_found("tunnel"))?;
    let allowed = match state.db.tunnel_user(id.to_string()).await? {
        Some(owner) => may_manage(state, s.user(), &owner).await?,
        // Service and admin-token tunnels: admins only.
        None => s.user().role.is_admin(),
    };
    if !allowed {
        return Err(ApiError::not_found("tunnel"));
    }
    Ok(row)
}

async fn delete_tunnel(State(state): State<Arc<AppState>>, s: Signed, Path(id): Path<String>) -> ApiResult<StatusCode> {
    ui_tunnel(&state, &s, &id).await?;
    match state.delete_tunnel(&id, CloseReason::Deleted).await? {
        DeleteOutcome::Deleted | DeleteOutcome::AlreadyTombstoned => {
            audit(&state, Some(&s.user().id), "tunnel_deleted", Some(id), &s.ctx).await;
            Ok(StatusCode::NO_CONTENT)
        }
        DeleteOutcome::NotFound => Err(ApiError::not_found("tunnel")),
    }
}

async fn list_links(
    State(state): State<Arc<AppState>>,
    s: Signed,
    Path(id): Path<String>,
) -> ApiResult<Json<api::AccessLinkList>> {
    let row = ui_tunnel(&state, &s, &id).await?;
    Ok(Json(api::access_link_list(&state, &row.id).await?))
}

async fn create_link(
    State(state): State<Arc<AppState>>,
    s: Signed,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<CreateAccessLinkRequest>,
) -> ApiResult<(StatusCode, Json<api::AccessLinkResponse>)> {
    let row = ui_tunnel(&state, &s, &id).await?;
    if row.is_expired() {
        return Err(ApiError::expired());
    }
    let ui = Some((s.user().id.clone(), s.session.id_hash.clone()));
    let link = api::mint_access_link(&state, &row, req, ui).await?;
    audit(&state, Some(&s.user().id), "link_created", Some(format!("{} {}", row.id, link.id)), &s.ctx).await;
    Ok((StatusCode::CREATED, Json(link)))
}

async fn revoke_link(State(state): State<Arc<AppState>>, s: Signed, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let tunnel = state.db.access_link_tunnel(id.clone()).await?.ok_or_else(|| ApiError::not_found("access link"))?;
    if ui_tunnel(&state, &s, &tunnel).await.is_err() {
        return Err(ApiError::not_found("access link"));
    }
    api::revoke_access_link(&state, &id, &tunnel).await?;
    audit(&state, Some(&s.user().id), "link_revoked", Some(format!("{tunnel} {id}")), &s.ctx).await;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------- device

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserCode {
    user_code: String,
}

fn unknown_code() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "unknown_code", "no pending login with this code; check it, or start again")
}

async fn device_lookup(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<UserCode>,
) -> ApiResult<Json<Value>> {
    if !state.ui.device_lookup.check_key(s.user().id.clone()) {
        return Err(too_many());
    }
    let code = normalize_user_code(&req.user_code).ok_or_else(unknown_code)?;
    let found = state.db.device_request(code).await?.ok_or_else(unknown_code)?;
    let needs_code = s.user().totp && now() - s.session.auth_at > REAUTH_S;
    Ok(Json(json!({ "request": found, "needs_code": needs_code })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decide {
    user_code: String,
    approve: bool,
    /// TOTP or recovery code, required to approve when the session's last
    /// check is older than ten minutes and the user has two-factor sign-in.
    #[serde(default)]
    code: Option<String>,
}

async fn device_decide(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<Decide>,
) -> ApiResult<Json<Value>> {
    if !state.ui.device_lookup.check_key(s.user().id.clone()) {
        return Err(too_many());
    }
    let user_id = s.user().id.clone();
    let code = normalize_user_code(&req.user_code).ok_or_else(unknown_code)?;
    if req.approve {
        require_fresh_auth(&state, &s, req.code.as_deref()).await?;
    }
    match state.db.decide_device(code, user_id.clone(), req.approve, s.session.id_hash.clone()).await? {
        Ok(name) => {
            let action = if req.approve { "device_approved" } else { "device_denied" };
            audit(&state, Some(&user_id), action, Some(name.clone()), &s.ctx).await;
            Ok(Json(json!({ "status": if req.approve { "approved" } else { "denied" }, "client_name": name })))
        }
        Err(DecideError::NotFound) => Err(unknown_code()),
        Err(DecideError::Client(NewClientError::Quota { limit, role })) => Err(client_quota(limit, role)),
        Err(DecideError::Client(NewClientError::NoUser)) => {
            Err(ApiError::new(StatusCode::FORBIDDEN, "disabled", "account disabled"))
        }
        Err(DecideError::Client(NewClientError::NameTaken)) => {
            Err(ApiError::new(StatusCode::CONFLICT, "client_exists", "no free machine name"))
        }
    }
}

// -------------------------------------------------------------------- admin

async fn list_users(State(state): State<Arc<AppState>>, _a: AdminSigned) -> ApiResult<Json<Value>> {
    let mut users = state.db.list_users(state.traffic.month()).await?;
    for u in &mut users {
        u.traffic_bytes = crate::traffic::used_or(&state, &u.user.id, u.traffic_bytes);
    }
    let users: Vec<Value> = users
        .iter()
        .map(|u| {
            let mut v = serde_json::to_value(u).unwrap_or_default();
            v["limits"] = user_json(&state, &u.user)["limits"].take();
            v
        })
        .collect();
    Ok(Json(json!({ "users": users, "month": crate::traffic::month_label(state.traffic.month()) })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserUpdate {
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    can_public: Option<bool>,
    /// Any of `tunnels`, `machines`, `tunnel_ttl_s` (seconds) and
    /// `traffic_bytes` (per month): `"default"`, `"unlimited"` or a number.
    #[serde(default)]
    limits: Option<crate::limits::SettingsPatch>,
    #[serde(default)]
    disabled: Option<bool>,
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    AdminSigned(s): AdminSigned,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<UserUpdate>,
) -> ApiResult<Json<Value>> {
    let actor = s.user().clone();
    let target = state.db.credentials(None, Some(id.clone())).await?.ok_or_else(|| ApiError::not_found("user"))?.user;
    if target.role == Role::Owner || target.id == actor.id {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "you cannot change the owner or yourself here"));
    }
    if !may_manage(&state, &actor, &target.id).await? {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "only the owner can change admins"));
    }
    if req.role.is_some() && actor.role != Role::Owner {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "only the owner can change roles"));
    }
    if req.role == Some(Role::Owner) {
        return Err(ApiError::validation("there is exactly one owner"));
    }
    let limits = req.limits.unwrap_or_default();
    limits.validate().map_err(ApiError::validation)?;
    if req.role.is_some() && limits != crate::limits::SettingsPatch::default() {
        return Err(ApiError::validation(
            "change the role and the limits in separate requests: a role change resets the limits to the server default",
        ));
    }
    let patch = UserPatch { role: req.role, can_public: req.can_public, limits };
    // The checks above give clear errors; this transaction is the authority
    // (the session may have ended, or roles changed, since they ran).
    // The new cap takes effect in memory in the same task as the commit, so
    // a cancelled request cannot leave the old one enforced.
    // The traffic lock is held from the commit until the cap is applied, so
    // two changes apply in commit order; the limits' audit entries are
    // written in the same task.
    let task = {
        let (state, actor, session, id, disabled, ip) =
            (state.clone(), actor.id.clone(), s.session.id_hash.clone(), id.clone(), req.disabled, s.ctx.ip_string());
        let username = target.username.clone();
        tokio::spawn(async move {
            let changes = state.traffic.changes().await;
            let updated = state.db.admin_update_user(actor.clone(), session, id, patch, disabled).await?;
            if let Ok((user, update)) = &updated {
                let defaults = state.db.limit_defaults();
                // Always the committed row's cap: a role or limit change by a
                // concurrent request may have committed just before this one.
                let cap = defaults.resolve(crate::limits::Kind::Traffic, user.role, user.limits.traffic_bytes);
                crate::traffic::set_cap(&state, &changes, &user.id, cap).await?;
                for t in &update.shortened {
                    state.invalidate_tunnel(t);
                }
                let mut entries: Vec<(&'static str, String)> = update
                    .limits
                    .iter()
                    .map(|c| {
                        let (old, new) = (
                            defaults.describe(c.kind, c.old_role, c.old),
                            defaults.describe(c.kind, c.new_role, c.new),
                        );
                        ("limit_set", format!("{username}: {} {old} → {new}", c.kind.label()))
                    })
                    .collect();
                if !update.shortened.is_empty() {
                    let limit = defaults
                        .resolve(crate::limits::Kind::TunnelTtl, user.role, user.limits.tunnel_ttl_s)
                        .map_or_else(String::new, crate::limits::duration_text);
                    let n = update.shortened.len();
                    entries.push(("tunnels_shortened", format!("{username}: {n} tunnel(s) now end within {limit}")));
                }
                for (action, entry) in entries {
                    if let Err(e) = state.db.audit(Some(actor.clone()), action, Some(entry), ip.clone()).await {
                        tracing::warn!(error = %format!("{e:#}"), "audit write failed");
                    }
                }
            }
            anyhow::Ok(updated)
        })
    };
    let (user, update) = match task.await.map_err(|e| ApiError::internal(e.into()))?? {
        Ok(found) => found,
        Err(super::store::AdminError::NotFound) => return Err(ApiError::not_found("user")),
        Err(super::store::AdminError::Forbidden) => {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "you may not change this user"));
        }
        Err(super::store::AdminError::SignedOut) => return Err(changed_meanwhile()),
    };
    for t in &update.closed {
        state.delete_tunnel(t, CloseReason::Deleted).await?;
    }
    audit(&state, Some(&actor.id), "user_updated", Some(target.username.clone()), &s.ctx).await;
    if let Some(disabled) = req.disabled {
        let action = if disabled { "user_disabled" } else { "user_enabled" };
        audit(&state, Some(&actor.id), action, Some(target.username.clone()), &s.ctx).await;
    }
    Ok(Json(json!({ "user": user_json(&state, &user), "shortened_tunnels": update.shortened.len() })))
}

/// Start the user's traffic for this month again from zero (audited).
async fn reset_user_traffic(
    State(state): State<Arc<AppState>>,
    AdminSigned(s): AdminSigned,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let actor = s.user().clone();
    let reset = crate::traffic::reset_month(
        state.clone(),
        id.clone(),
        actor.id.clone(),
        s.session.id_hash.clone(),
        s.ctx.ip_string(),
    )
    .await?;
    match reset {
        Ok(_) => Ok(Json(json!({ "traffic": crate::traffic::view(&state, &id).await? }))),
        Err(super::store::AdminError::NotFound) => Err(ApiError::not_found("user")),
        Err(super::store::AdminError::Forbidden) => {
            Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "you may not change this user"))
        }
        Err(super::store::AdminError::SignedOut) => Err(changed_meanwhile()),
    }
}

async fn list_invites(State(state): State<Arc<AppState>>, _a: AdminSigned) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "invites": state.db.list_invites().await? })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewInvite {
    role: Role,
    #[serde(default)]
    ttl_s: Option<i64>,
}

async fn create_invite(
    State(state): State<Arc<AppState>>,
    AdminSigned(s): AdminSigned,
    ApiJson(req): ApiJson<NewInvite>,
) -> ApiResult<Json<Value>> {
    match req.role {
        Role::Owner => return Err(ApiError::validation("there is exactly one owner")),
        Role::Admin if s.user().role != Role::Owner => {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "only the owner can invite admins"));
        }
        _ => {}
    }
    let ttl = req.ttl_s.unwrap_or(INVITE_TTL_S);
    if !(3600..=30 * 86_400).contains(&ttl) {
        return Err(ApiError::validation("ttl_s must be within 3600..=2592000"));
    }
    let ui = state.config.ui_host.clone().ok_or_else(|| ApiError::not_found("route"))?;
    let token = tokens::random_token(INVITE_PREFIX);
    let invite = state
        .db
        .create_invite(
            format!("in{}", tokens::random_tunnel_id()),
            tokens::hash_token(&token),
            InviteKind::Invite,
            req.role,
            Some(s.user().id.clone()),
            Some(s.session.id_hash.clone()),
            now() + ttl,
        )
        .await?
        .ok_or_else(changed_meanwhile)?;
    audit(&state, Some(&s.user().id), "invite_created", Some(format!("{} {}", invite.id, req.role.as_str())), &s.ctx)
        .await;
    // The token goes in the fragment: it never reaches a server log or a Referer.
    Ok(Json(json!({ "url": format!("https://{ui}/invite#{token}"), "invite": invite })))
}

async fn delete_invite(
    State(state): State<Arc<AppState>>,
    AdminSigned(s): AdminSigned,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.db.delete_invite(id.clone(), s.user().id.clone(), s.session.id_hash.clone()).await? {
        return Err(ApiError::not_found("invite"));
    }
    audit(&state, Some(&s.user().id), "invite_revoked", Some(id), &s.ctx).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_services(State(state): State<Arc<AppState>>, _a: AdminSigned) -> ApiResult<Json<Value>> {
    let services: Vec<Value> = state
        .db
        .list_services(None, None)
        .await?
        .into_iter()
        .map(|s| {
            json!({ "name": s.name, "max_tunnels": s.max_tunnels, "created_at": s.created_at,
                    "last_used_at": s.last_used_at, "tunnels": s.tunnels })
        })
        .collect();
    Ok(Json(json!({ "services": services })))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct AuditQuery {
    #[serde(default)]
    before: Option<i64>,
}

async fn audit_log(
    State(state): State<Arc<AppState>>,
    _a: AdminSigned,
    q: Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "entries": state.db.list_audit(q.before, 100).await? })))
}

async fn status(State(state): State<Arc<AppState>>, _a: AdminSigned) -> ApiResult<Json<Value>> {
    let cfg = &state.config;
    let (tunnels, tombstones, links, sessions) = state.db.counts().await?;
    let limits = &cfg.limits;
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "hosts": { "ui": cfg.ui_host, "api": cfg.api_host, "tunnel": cfg.tunnel_host, "preview_zone": cfg.preview_zone },
        "same_site": cfg.ui_same_site_as_previews(),
        "certificate_not_after": state.certs.not_after(),
        "connected_tunnels": state.registry.len(),
        "password_checks_running": password::slots_in_use(),
        "counts": { "tunnels": tunnels, "tombstones": tombstones, "access_links": links, "gate_sessions": sessions },
        "webrtc": cfg.webrtc.enabled,
        "limits": {
            "max_tunnels_per_client": limits.max_tunnels_per_client,
            "member_max_tunnels": limits.member_max_tunnels,
            "member_max_clients": limits.member_max_clients,
            "member_max_tunnel_ttl_s": limits.member_max_tunnel_ttl_s,
            "max_tunnel_ttl_s": limits.max_tunnel_ttl_s,
            "allow_public_for_clients": limits.allow_public_for_clients,
            "member_monthly_traffic_gb": limits.member_monthly_traffic_gb,
        },
        "traffic_month": crate::traffic::month_label(state.traffic.month()),
        "abuse_contact": cfg.abuse_contact,
    })))
}
