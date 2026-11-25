//! Mail flows of the web UI (only with mail on; otherwise these routes are
//! "not found" and the UI shows nothing about email): "Forgot password?",
//! an account's own address (add, change, confirm, remove) and security
//! notices.
//!
//! - "Forgot password?" answers the same, at once, whatever was asked for:
//!   the lookup and the mail happen in the background, so neither the
//!   answer nor its timing (nor a mail server failure) tells whether an
//!   account or address exists.
//! - Links are mailed only to confirmed addresses, are single use, short
//!   and stop working when the account's sign-in changes. A mailed password
//!   reset keeps two-factor sign-in (the page asks for a code): an address
//!   is never a second factor.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use super::checks::{
    audit, changed_meanwhile, check_password, invalid_invite, invite_token_hash, require_fresh_auth, too_many,
};
use super::{Ctx, INVITE_PREFIX, PeerIp, Signed};
use crate::addresses::{EmailChange, EmailError, VerifyError};
use crate::api::{ApiError, ApiJson, ApiResult};
use crate::config::smtp::parse_address;
use crate::mail::{Mailer, Notice};
use crate::state::AppState;
use crate::tokens::{self, now};

/// A "Forgot password?" link works this long…
pub const PASSWORD_RESET_TTL_S: i64 = 30 * 60;
/// An address confirmation link works this long.
pub const EMAIL_VERIFY_TTL_S: i64 = 3600;

/// The mailer, or "not found" with mail off.
pub fn mailer(state: &AppState) -> ApiResult<&Arc<Mailer>> {
    state.ui.mail.as_ref().ok_or_else(|| ApiError::not_found("route"))
}

/// `https://<ui_host>/invite#<token>`: from the configured host only.
pub fn link(state: &AppState, token: &str) -> String {
    format!("https://{}/invite#{token}", state.config.ui_host.as_deref().unwrap_or_default())
}

/// Mail `notice` to the account's confirmed address, if it has one.
pub async fn notify(state: &AppState, user_id: &str, notice: Notice, ctx: &Ctx) {
    notify_user(state, user_id, notice, ctx.ip_string().as_deref()).await;
}

/// As `notify`, for requests outside the web UI (the admin API); `ip` is shown when known.
pub async fn notify_user(state: &AppState, user_id: &str, notice: Notice, ip: Option<&str>) {
    let Some(mailer) = state.ui.mail.as_ref() else { return };
    match state.db.contact(user_id.to_string()).await {
        Ok(Some((username, email))) => notify_address(mailer, &username, email, &notice, ip),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %format!("{e:#}"), "looking up an address for a notice failed"),
    }
}

fn notify_address(mailer: &Arc<Mailer>, username: &str, email: String, notice: &Notice, ip: Option<&str>) {
    let mail = mailer.texts().notice(notice, username, now(), ip);
    mailer.send_notice_later(email, mail);
}

// ------------------------------------------------------------- forgot

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgotRequest {
    /// Username or email address.
    login: String,
}

/// "Forgot password?": always the same answer; a link goes out in the
/// background only to an enabled account's confirmed address.
pub async fn forgot_password(
    State(state): State<Arc<AppState>>,
    PeerIp(peer): PeerIp,
    ApiJson(req): ApiJson<ForgotRequest>,
) -> ApiResult<Json<Value>> {
    let mailer = mailer(&state)?.clone();
    // Per address, then server-wide, both before any lookup (not even of a
    // session cookie): a refusal depends on the load alone, never on whether
    // an account exists, and a refused flood costs no database work.
    if peer.is_some_and(|ip| !state.ui.forgot_ip.check(ip)) || !state.ui.forgot_budget.check_key(()) {
        return Err(too_many());
    }
    let login = req.login.trim().to_ascii_lowercase();
    if login.is_empty() || login.len() > 254 {
        return Err(ApiError::validation("enter your username or email address"));
    }
    let (worker, ip) = (state.clone(), peer.map(|ip| ip.to_string()));
    mailer.clone().run_later(async move {
        let state = worker;
        if !state.ui.forgot_login.check_key(login.clone()) {
            tracing::info!("password reset mail skipped (rate limit)");
            return;
        }
        let token = tokens::random_token(INVITE_PREFIX);
        let made = state
            .db
            .create_password_reset(
                login,
                format!("in{}", tokens::random_tunnel_id()),
                tokens::hash_token(&token),
                now() + PASSWORD_RESET_TTL_S,
            )
            .await;
        match made {
            Ok(Some(target)) => {
                let mail = mailer.texts().password_reset(
                    &link(&state, &token),
                    &target.username,
                    target.totp,
                    PASSWORD_RESET_TTL_S,
                );
                // Answered already; a drop (full queue) is logged and looks like any other request.
                let _ = mailer.send_later("password_reset", target.email, mail);
                let _ = state.db.audit(Some(target.user_id), "password_reset_mailed", None, ip).await;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "making a password reset link failed"),
        }
    });
    Ok(Json(json!({ "status": "ok" })))
}

// ------------------------------------------------------- own address

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailRequest {
    email: String,
    /// The current password.
    password: String,
    /// TOTP or recovery code when the session's last check is stale (as for adding a machine).
    #[serde(default)]
    code: Option<String>,
}

/// Add or change the account's address: a confirmation link goes to it; the
/// change happens when it is opened. The same answer if another account has
/// the address (then nothing is mailed).
pub async fn set_email(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<EmailRequest>,
) -> ApiResult<Json<Value>> {
    let mailer = mailer(&state)?.clone();
    let email = parse_address(&req.email).map_err(ApiError::validation)?;
    let user_id = s.user().id.clone();
    if !state.ui.address_change.check_key(user_id.clone()) || !state.ui.address_change_hourly.check_key(user_id.clone())
    {
        return Err(too_many());
    }
    let epoch = check_password(&state, &user_id, &req.password).await?;
    // Where password resets go is a sign-in setting: two-factor users confirm it.
    require_fresh_auth(&state, &s, req.code.as_deref()).await?;
    // One address gets only a few confirmation mails an hour, whoever asks.
    // Over that, the answer is the same and nothing changes (no link, no mail),
    // so it says nothing about who else asked.
    if !state.ui.confirmations_to.check_key(email.to_ascii_lowercase()) {
        tracing::info!("address confirmation skipped (that address had its share this hour)");
        return Ok(Json(json!({ "status": "sent", "pending": email, "expires_in_s": EMAIL_VERIFY_TTL_S })));
    }
    let token = tokens::random_token(INVITE_PREFIX);
    let made = state
        .db
        .create_email_verify(
            user_id.clone(),
            s.session.id_hash.clone(),
            epoch,
            format!("in{}", tokens::random_tunnel_id()),
            tokens::hash_token(&token),
            email.clone(),
            now() + EMAIL_VERIFY_TTL_S,
        )
        .await?;
    match made {
        Ok(EmailChange::Send { username }) => {
            let mail = mailer.texts().verify_address(&link(&state, &token), &username, EMAIL_VERIFY_TTL_S);
            // The same answer if a full queue drops it (it depends on load only); asking again sends a new link.
            let _ = mailer.send_later("email_verify", email.clone(), mail);
        }
        Ok(EmailChange::Taken) => {}
        Err(EmailError::SignedOut) => return Err(changed_meanwhile()),
        Err(EmailError::Unchanged) => {
            return Err(ApiError::new(StatusCode::CONFLICT, "unchanged", "this is already your address"));
        }
    }
    audit(&state, Some(&user_id), "email_change_requested", None, &s.ctx).await;
    Ok(Json(json!({ "status": "sent", "pending": email, "expires_in_s": EMAIL_VERIFY_TTL_S })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfirm {
    password: String,
}

/// Remove the account's address; a notice goes to it.
pub async fn remove_email(
    State(state): State<Arc<AppState>>,
    s: Signed,
    ApiJson(req): ApiJson<PasswordConfirm>,
) -> ApiResult<Json<Value>> {
    let mailer = mailer(&state)?.clone();
    let user = s.user().clone();
    let epoch = check_password(&state, &user.id, &req.password).await?;
    let old = state
        .db
        .remove_email(user.id.clone(), epoch, s.session.id_hash.clone())
        .await?
        .ok_or_else(changed_meanwhile)?;
    if let Some(old) = old {
        notify_address(&mailer, &user.username, old, &Notice::AddressRemoved, s.ctx.ip_string().as_deref());
        audit(&state, Some(&user.id), "email_removed", None, &s.ctx).await;
    }
    Ok(Json(json!({ "status": "ok" })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    token: String,
}

/// Confirm an address with the mailed link (no session needed: the link
/// may be opened on another device). The old address gets a notice.
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    ctx: Ctx,
    ApiJson(req): ApiJson<TokenRequest>,
) -> ApiResult<Json<Value>> {
    let mailer = mailer(&state)?.clone();
    if ctx.ip.is_some_and(|ip| !state.ui.login_ip.check(ip)) {
        return Err(too_many());
    }
    let hash = invite_token_hash(&req.token)?;
    let verified = match state.db.verify_email(hash).await? {
        Ok(v) => v,
        Err(VerifyError::AddressTaken) => {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "email_taken",
                "another account uses this address now; add a different one",
            ));
        }
        Err(_) => return Err(invalid_invite()),
    };
    if let Some(old) = verified.old.clone() {
        notify_address(
            &mailer,
            &verified.username,
            old,
            &Notice::AddressChanged { new: verified.new.clone() },
            ctx.ip_string().as_deref(),
        );
    }
    audit(&state, Some(&verified.user_id), "email_verified", None, &ctx).await;
    Ok(Json(json!({ "status": "ok", "email": verified.new, "username": verified.username })))
}

/// The UI's view of mail for a signed-in user: their pending address.
pub async fn pending(state: &AppState, user_id: &str) -> ApiResult<Option<String>> {
    if state.ui.mail.as_ref().is_none() {
        return Ok(None);
    }
    Ok(state.db.pending_email(user_id.to_string()).await?)
}

/// For `/ui/api/status`: whether mail is on and through what (no credentials).
/// How the mail commands are run on this server: with sudo for a system
/// install, as the server's own user for a rootless one (sudo would pick
/// root's config there), and with `--config` when the server was started
/// with a config file other than the install's default.
pub(super) fn command(config: &crate::config::Config, config_path: Option<&std::path::Path>, args: &str) -> String {
    use crate::config::mode::{Mode, SYSTEM_CONFIG_PATH, SYSTEM_DATA_DIR};
    let system = config.data_dir == std::path::Path::new(SYSTEM_DATA_DIR);
    let default = if system { Some(SYSTEM_CONFIG_PATH.into()) } else { Mode::User.config_path().ok() };
    let flag = config_path
        .filter(|p| default.as_deref() != Some(*p))
        .map(|p| format!(" --config {}", shell_quote(&p.to_string_lossy())))
        .unwrap_or_default();
    format!("{}tunnel-server{flag} mail {args}", if system { "sudo " } else { "" })
}

/// `value` as one POSIX shell word.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn status(state: &AppState) -> Value {
    match (&state.config.smtp, state.ui.mail.as_ref().is_some()) {
        (Some(s), true) => json!({
            "enabled": true, "host": s.host, "port": s.port, "security": s.security().label(), "from": s.from,
            "signs_in": s.user.is_some(), "test": command(&state.config, state.ui.config_path.get().map(|p| p.as_path()), "test you@example.com"),
        }),
        _ => json!({
            "enabled": false, "setup": command(&state.config, state.ui.config_path.get().map(|p| p.as_path()), "setup"), "detail": state.config.mail_status(),
        }),
    }
}
