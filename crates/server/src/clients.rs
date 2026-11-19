//! Client enrollment shared by the `client` subcommands and the admin API.

use tunnel_protocol::ENROLL_CODE_PREFIX;

use crate::config::Config;
use crate::db::{Db, NewClientError};
use crate::tokens::{self, now};

/// How long a `client add` login code works.
pub const ENROLL_TTL_S: i64 = 15 * 60;
pub const MAX_NAME_LEN: usize = 64;

pub struct Enrollment {
    pub name: String,
    /// `<code>@<host>`, pasted at the `tunnel login` prompt.
    pub login_code: String,
    /// The same as one command; the code is then visible in process listings
    /// and shell history, so the prompt is preferred.
    pub login_command: String,
    pub expires_at: i64,
}

pub enum AddError {
    Invalid(String),
    Taken,
    /// The owning user already has as many machines as allowed.
    Quota,
    /// The owning user is unknown or disabled.
    NoUser,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for AddError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok { Ok(()) } else { Err(format!("name must be 1..={MAX_NAME_LEN} characters: letters, digits, '.', '_', '-'")) }
}

/// Create client `name` owned by `user_id`, and its one-time login command.
/// From the web UI, `session` is the requesting session's id hash, which must
/// still be valid when the client is created.
pub async fn add(
    db: &Db,
    cfg: &Config,
    name: &str,
    user_id: &str,
    session: Option<String>,
) -> Result<Enrollment, AddError> {
    validate_name(name).map_err(AddError::Invalid)?;
    let code = tokens::random_token(ENROLL_CODE_PREFIX);
    let expires_at = now() + ENROLL_TTL_S;
    let id = format!("cl{}", tokens::random_tunnel_id());
    match db
        .create_client(id, name.to_string(), user_id.to_string(), tokens::hash_token(&code), expires_at, session)
        .await?
    {
        Ok(_) => {
            let login_code = format!("{code}@{}", cfg.api_host);
            Ok(Enrollment {
                name: name.to_string(),
                login_command: format!("tunnel login '{login_code}'"),
                login_code,
                expires_at,
            })
        }
        Err(NewClientError::NameTaken) => Err(AddError::Taken),
        Err(NewClientError::Quota) => Err(AddError::Quota),
        Err(NewClientError::NoUser) => Err(AddError::NoUser),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn names() {
        assert!(super::validate_name("laptop").is_ok());
        assert!(super::validate_name("ci.runner-2_a").is_ok());
        for bad in ["", "has space", "slash/x", "ünï", &"x".repeat(65)] {
            assert!(super::validate_name(bad).is_err(), "{bad}");
        }
    }
}
