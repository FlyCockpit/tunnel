//! Checks and answers the UI handlers share: passwords, second factors and
//! fresh re-authentication, invite-style link tokens, the audit log, and the
//! common error answers.

use http::StatusCode;

use super::{Ctx, REAUTH_S, Signed, totp};
use crate::api::{ApiError, ApiResult};
use crate::password::{self, Verdict};
use crate::state::AppState;
use crate::tokens::{self, now};

pub const INVITE_PREFIX: &str = "tninv_";

/// The user's sign-in changed (password, two-factor, reset) or this session
/// ended while the request ran.
pub(super) fn changed_meanwhile() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "signed_out", "your sign-in changed meanwhile; sign in again")
}

pub(super) fn too_many() -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many attempts; wait a minute")
}

pub(super) fn busy() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy checking passwords; try again")
}

pub(super) fn bad_credentials() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "wrong username or password")
}

/// A refused sign-in on the sign-in page, with what to do about a forgotten
/// password: the mailed reset (its button is under the form) when the server
/// sends mail, else whoever can reset it.
pub(super) fn bad_sign_in(state: &AppState) -> ApiError {
    let next = if state.ui.mail.is_some() {
        "Forgot your password? Choose Forgot password? below, or ask an admin of this server to reset your sign-in."
    } else {
        "Forgot your password? Ask an admin of this server to reset your sign-in. \
         Only if you are the owner: run tunnel-server admin link on the server."
    };
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", format!("wrong username or password. {next}"))
}

pub(super) fn keys(state: &AppState) -> ApiResult<&crate::seal::Keys> {
    state.ui.keys.as_ref().ok_or_else(|| ApiError::not_found("route"))
}

pub(super) async fn audit(
    state: &AppState,
    user: Option<&str>,
    action: &'static str,
    target: Option<String>,
    ctx: &Ctx,
) {
    if let Err(e) = state.db.audit(user.map(str::to_string), action, target, ctx.ip_string()).await {
        tracing::warn!(error = %format!("{e:#}"), action, "audit write failed");
    }
}

/// Check the current password of `user_id` (rate-limited per user, before Argon2).
/// Check the current password of `user_id` (rate-limited per user, before
/// Argon2). Returns the auth epoch it was checked at.
pub(super) async fn check_password(state: &AppState, user_id: &str, password: &str) -> ApiResult<i64> {
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
pub(super) async fn check_second_factor(
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
pub(super) async fn require_fresh_auth(state: &AppState, s: &Signed, code: Option<&str>) -> ApiResult<()> {
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

pub(super) fn totp_aad(user_id: &str) -> String {
    format!("totp:{user_id}")
}

pub(super) fn invite_token_hash(token: &str) -> ApiResult<String> {
    let token = token.trim();
    if !token.starts_with(INVITE_PREFIX) || token.len() > 128 {
        return Err(invalid_invite());
    }
    Ok(tokens::hash_token(token))
}

pub(super) fn invalid_invite() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "invalid_invite",
        "this link is invalid, used or expired; ask whoever sent it for a new one",
    )
}
