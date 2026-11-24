//! Browser-approved machine login (RFC 8628 device authorization grant).
//!
//! `tunnel login https://<ui host>` asks for a code here, prints the code and
//! the approval page, and polls. The user types the code on the page (it is
//! never part of a URL, so nobody can send a victim a link that approves an
//! attacker's machine), sees the machine's name and address, and approves.
//! The new client belongs to the approving user.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tunnel_protocol::CLIENT_TOKEN_PREFIX;
use utoipa::ToSchema;

use crate::api::{ApiError, ApiJson, ApiResult, ErrorBody, PeerAddr};
use crate::clients::validate_new_name;
use crate::db::NewClientError;
use crate::state::AppState;
use crate::tokens::{self, now};
use crate::ui::store::Poll;

pub const DEVICE_CODE_PREFIX: &str = "tndev_";
pub const DEVICE_TTL_S: i64 = 15 * 60;
pub const POLL_INTERVAL_S: i64 = 5;
/// 20 consonants without look-alikes; 8 of them give about 34 bits.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceCodeRequest {
    /// Name for the new machine (letters, digits, `.`, `_`, `-`); a suffix
    /// is added if the name is taken.
    pub client_name: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DeviceCodeResponse {
    /// Secret: only the CLI holds it, to poll with.
    pub device_code: String,
    /// Shown to the user, typed on the approval page, e.g. `WDJB-MJHT`.
    pub user_code: String,
    /// The approval page (no code in it).
    pub verification_uri: String,
    pub interval: i64,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceTokenRequest {
    pub device_code: String,
}

/// `XXXXXXXX` → `XXXX-XXXX`.
fn random_user_code() -> String {
    use rand::TryRng;
    let mut bytes = [0u8; USER_CODE_LEN];
    rand::rngs::SysRng.try_fill_bytes(&mut bytes).expect("OS random source failed");
    // 256 % 20 != 0: reject bytes ≥ 240 to avoid bias.
    let mut out = String::with_capacity(USER_CODE_LEN + 1);
    let mut i = 0;
    let mut extra = [0u8; 1];
    while out.len() < USER_CODE_LEN + 1 {
        if out.len() == USER_CODE_LEN / 2 {
            out.push('-');
            continue;
        }
        let b = if i < bytes.len() {
            i += 1;
            bytes[i - 1]
        } else {
            rand::rngs::SysRng.try_fill_bytes(&mut extra).expect("OS random source failed");
            extra[0]
        };
        if b < 240 {
            out.push(USER_CODE_ALPHABET[(b % 20) as usize] as char);
        }
    }
    out
}

/// Normalize what a user typed: case, spaces and the dash do not matter.
pub fn normalize_user_code(input: &str) -> Option<String> {
    let letters: String = input.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect();
    if letters.len() != USER_CODE_LEN || !letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)) {
        return None;
    }
    Some(format!("{}-{}", &letters[..USER_CODE_LEN / 2], &letters[USER_CODE_LEN / 2..]))
}

fn ui_host(state: &AppState) -> ApiResult<&str> {
    state.config.ui_host.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "device_login_unavailable",
            "this server has no web UI; ask the admin for a login code (`tunnel-server client add`)",
        )
    })
}

/// RFC 8628 error codes, in the API's error shape (`error.code`), status 400.
fn oauth_error(code: &'static str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, code, code)
}

#[utoipa::path(
    post,
    path = "/v1/device/code",
    security(()),
    request_body = DeviceCodeRequest,
    responses((status = 200, body = DeviceCodeResponse), (status = 404, body = ErrorBody), (status = 422, body = ErrorBody), (status = 429, body = ErrorBody))
)]
pub async fn device_code(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::Extension<PeerAddr>>,
    ApiJson(req): ApiJson<DeviceCodeRequest>,
) -> ApiResult<Json<DeviceCodeResponse>> {
    let ui = ui_host(&state)?.to_string();
    let ip = peer.map(|axum::Extension(PeerAddr(a))| a.ip());
    if let Some(ip) = ip
        && !state.ui.device_code_limiter.check(ip)
    {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many login requests; wait a minute",
        ));
    }
    validate_new_name(&req.client_name).map_err(ApiError::validation)?;
    for _ in 0..8 {
        let device_code = tokens::random_token(DEVICE_CODE_PREFIX);
        let user_code = random_user_code();
        if state
            .db
            .create_device_login(
                tokens::hash_token(&device_code),
                user_code.clone(),
                req.client_name.clone(),
                ip.map(|i| i.to_string()),
                now() + DEVICE_TTL_S,
                POLL_INTERVAL_S,
            )
            .await?
        {
            tracing::info!(client = %req.client_name, "device login requested");
            return Ok(Json(DeviceCodeResponse {
                device_code,
                user_code,
                verification_uri: format!("https://{ui}/device"),
                interval: POLL_INTERVAL_S,
                expires_in: DEVICE_TTL_S,
            }));
        }
    }
    Err(ApiError::internal(anyhow::anyhow!("could not allocate a unique user code")))
}

/// Polled by the CLI; the final answer is the same shape as `/v1/clients/enroll`.
#[utoipa::path(
    post,
    path = "/v1/device/token",
    security(()),
    request_body = DeviceTokenRequest,
    responses(
        (status = 200, body = crate::api::EnrollResponse),
        (status = 400, description = "`authorization_pending`, `slow_down`, `expired_token`, `access_denied` (RFC 8628) or `invalid_grant`", body = ErrorBody),
        (status = 409, description = "Approved, but the machine could not be created (quota)", body = ErrorBody),
    )
)]
pub async fn device_token(
    State(state): State<Arc<AppState>>,
    ApiJson(req): ApiJson<DeviceTokenRequest>,
) -> ApiResult<Json<crate::api::EnrollResponse>> {
    ui_host(&state)?;
    let code = req.device_code.trim();
    if !code.starts_with(DEVICE_CODE_PREFIX) || code.len() > 256 {
        return Err(oauth_error("invalid_grant"));
    }
    let token = tokens::random_token(CLIENT_TOKEN_PREFIX);
    let client_id = format!("cl{}", tokens::random_tunnel_id());
    let poll = state.db.poll_device(tokens::hash_token(code), client_id, tokens::hash_token(&token)).await?;
    match poll {
        None => Err(oauth_error("invalid_grant")),
        Some(Poll::Pending) => Err(oauth_error("authorization_pending")),
        Some(Poll::SlowDown) => Err(oauth_error("slow_down")),
        Some(Poll::Expired) => Err(oauth_error("expired_token")),
        Some(Poll::Denied) => Err(oauth_error("access_denied")),
        Some(Poll::Failed(e)) => Err(ApiError::new(
            StatusCode::CONFLICT,
            "client_refused",
            match e {
                NewClientError::Quota { limit, role } => {
                    format!("approved, but {}", crate::limits::machine_limit_message(limit, role))
                }
                NewClientError::NoUser => "approved, but the approving account was disabled".to_string(),
                NewClientError::NameTaken => "approved, but no free machine name was left".to_string(),
            },
        )),
        Some(Poll::Approved { name }) => {
            tracing::info!(client = %name, "client enrolled by browser approval");
            Ok(Json(crate::api::EnrollResponse {
                name,
                token,
                api: format!("https://{}", state.config.api_host),
                server: format!("wss://{}", state.config.tunnel_host),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_are_well_formed_and_normalize() {
        for _ in 0..200 {
            let c = random_user_code();
            assert_eq!(c.len(), 9);
            assert_eq!(c.as_bytes()[4], b'-');
            assert_eq!(normalize_user_code(&c).as_deref(), Some(c.as_str()));
            assert_eq!(normalize_user_code(&c.to_lowercase().replace('-', " ")).as_deref(), Some(c.as_str()));
        }
        assert_eq!(normalize_user_code("WDJB-MJH"), None);
        assert_eq!(normalize_user_code("WDJB-MJHA"), None, "vowels are not in the alphabet");
        assert_eq!(normalize_user_code("https://x/device?code=WDJBMJHT"), None);
    }
}
