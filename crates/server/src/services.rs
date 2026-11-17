//! Service credentials, shared by the `service` subcommands and the admin API.
//!
//! A service (for example a sandbox platform) is an API-only caller: with its
//! `tnsvc_` token it creates, lists and deletes its own tunnels and their
//! access links, within its own live-tunnel quota. It cannot manage clients
//! or services and never sees other owners' tunnels.

use tunnel_protocol::SERVICE_TOKEN_PREFIX;

use crate::clients::validate_name;
use crate::db::{Db, ServiceRow};
use crate::tokens;

/// Bounds of a service's live-tunnel quota.
pub const MAX_TUNNELS_RANGE: std::ops::RangeInclusive<u32> = 1..=10_000;

pub enum Error {
    Invalid(String),
    Taken,
    NotFound,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

pub fn validate_quota(max_tunnels: u32) -> Result<(), Error> {
    if MAX_TUNNELS_RANGE.contains(&max_tunnels) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "max_tunnels must be within {}..={}",
            MAX_TUNNELS_RANGE.start(),
            MAX_TUNNELS_RANGE.end()
        )))
    }
}

/// A new service token. Callers hand it out (or store it) before committing
/// its hash with [`add`] or [`rotate`], so a failed hand-out never leaves a
/// credential nobody holds.
pub fn new_token() -> String {
    tokens::random_token(SERVICE_TOKEN_PREFIX)
}

pub fn validate_new(name: &str, max_tunnels: u32) -> Result<(), Error> {
    validate_name(name).map_err(Error::Invalid)?;
    validate_quota(max_tunnels)
}

/// Create service `name` holding `token`.
pub async fn add(db: &Db, name: &str, max_tunnels: u32, token: &str) -> Result<ServiceRow, Error> {
    validate_new(name, max_tunnels)?;
    let id = format!("sv{}", tokens::random_tunnel_id());
    db.create_service(id, name.to_string(), tokens::hash_token(token), max_tunnels).await?.ok_or(Error::Taken)
}

/// Replace service `name`'s token with `token`; the old one stops working at once.
pub async fn rotate(db: &Db, name: &str, token: &str) -> Result<(), Error> {
    if db.rotate_service_token(name.to_string(), tokens::hash_token(token)).await? {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

pub async fn set_quota(db: &Db, name: &str, max_tunnels: u32) -> Result<(), Error> {
    validate_quota(max_tunnels)?;
    if db.set_service_quota(name.to_string(), max_tunnels).await? { Ok(()) } else { Err(Error::NotFound) }
}
