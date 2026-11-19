//! Tunnel passwords: argon2id (PHC strings), hashed and verified off the async
//! runtime because each takes tens of milliseconds by design.

use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use std::sync::LazyLock;
use std::time::Duration;

use argon2::Argon2;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub const MIN_PASSWORD_LEN: usize = 8;
pub const MAX_PASSWORD_LEN: usize = 256;
pub const MAX_USERNAME_LEN: usize = 64;

/// Argon2 runs at most this many at once (each takes ~19 MiB and tens of ms).
const MAX_CONCURRENT: usize = 2;
/// A caller waits this long for a slot, then gives up (`Busy`), so a flood
/// cannot queue unbounded work.
const SLOT_WAIT: Duration = Duration::from_secs(3);
static SLOTS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MAX_CONCURRENT));

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Match,
    NoMatch,
    /// Too many password checks are already running.
    Busy,
}

/// The hasher for new hashes: Argon2id with the crate's default (OWASP)
/// parameters. Test builds use tiny parameters so that the many tests that
/// sign in do not queue on the two hashing slots; verification always uses
/// the parameters recorded in the PHC string.
fn hasher() -> Argon2<'static> {
    #[cfg(not(test))]
    {
        Argon2::default()
    }
    #[cfg(test)]
    {
        let params = argon2::Params::new(64, 1, 1, None).expect("valid test parameters");
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
    }
}

#[cfg(test)]
thread_local! {
    /// Password checks started on this thread (tests run one per thread).
    pub static CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub async fn hash(password: String) -> anyhow::Result<String> {
    let slot = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire())
        .await
        .map_err(|_| anyhow::anyhow!("password hashing is busy; try again"))??;
    // The permit lives in the blocking task: a cancelled request (h2 reset)
    // must not free the slot while Argon2 is still running.
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        hasher()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
    })
    .await?
}

/// True if `username` matches and `password` verifies against `phc`. The
/// password is always checked, so a wrong username takes as long as a wrong password.
pub async fn verify(expected_user: String, phc: String, username: String, password: String) -> Verdict {
    let Ok(Ok(slot)) = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire()).await else {
        return Verdict::Busy;
    };
    // See `hash`: the slot is held until Argon2 finishes, even if cancelled.
    let ok = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let user_ok: bool = expected_user.as_bytes().ct_eq(username.as_bytes()).into();
        let pass_ok = Argon2::default().verify_password(password.as_bytes(), phc.as_str()).is_ok();
        user_ok && pass_ok
    })
    .await
    .unwrap_or(false);
    if ok { Verdict::Match } else { Verdict::NoMatch }
}

/// `password` against `phc` alone (web UI accounts look the user up first).
pub async fn verify_phc(phc: String, password: String) -> Verdict {
    #[cfg(test)]
    CHECKS.with(|c| c.set(c.get() + 1));
    let Ok(Ok(slot)) = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire()).await else {
        return Verdict::Busy;
    };
    let ok = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        Argon2::default().verify_password(password.as_bytes(), phc.as_str()).is_ok()
    })
    .await
    .unwrap_or(false);
    if ok { Verdict::Match } else { Verdict::NoMatch }
}

/// Argon2 checks running or waiting right now (for the status page and tests).
pub fn slots_in_use() -> usize {
    MAX_CONCURRENT - SLOTS.available_permits()
}

#[cfg(test)]
mod tests {
    /// Known-answer Argon2id PHC string (default parameters); public fixture data.
    #[tokio::test]
    async fn verifies_known_argon2id_phc() {
        let phc = "$argon2id$v=19$m=19456,t=2,p=1$cHVibGljLXRlc3Qtc2FsdA$BimFkRyg6Ge8LT3LbudUr7ob0dRYFhuwqMT54saxJvQ";
        assert_eq!(
            super::verify("ann".into(), phc.into(), "ann".into(), "legacy-argon2-fixture".into()).await,
            super::Verdict::Match
        );
        assert_eq!(
            super::verify("ann".into(), phc.into(), "ann".into(), "wrong".into()).await,
            super::Verdict::NoMatch
        );
    }

    #[tokio::test]
    async fn hash_and_verify() {
        let phc = super::hash("correct horse".into()).await.unwrap();
        assert!(phc.starts_with("$argon2id$"));
        use super::Verdict::*;
        assert_eq!(super::verify("ann".into(), phc.clone(), "ann".into(), "correct horse".into()).await, Match);
        assert_eq!(super::verify("ann".into(), phc.clone(), "bob".into(), "correct horse".into()).await, NoMatch);
        assert_eq!(super::verify("ann".into(), phc.clone(), "ann".into(), "wrong".into()).await, NoMatch);
        assert_eq!(super::verify("ann".into(), "not a hash".into(), "ann".into(), "x".into()).await, NoMatch);
    }
}
