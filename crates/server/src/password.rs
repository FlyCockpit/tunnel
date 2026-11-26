//! Account and tunnel passwords: Argon2id, hashed and verified off the async
//! runtime because each takes tens of milliseconds by design.

use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use std::sync::LazyLock;
use std::time::Duration;

use argon2::Argon2;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

use crate::pepper::{Pepper, Purpose};

/// Public fixture used for a full Argon2 check when a stored hash cannot open.
pub(crate) const DUMMY_PHC: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$cHVibGljLXRlc3Qtc2FsdA$BimFkRyg6Ge8LT3LbudUr7ob0dRYFhuwqMT54saxJvQ";

pub(crate) fn valid_phc(phc: &str) -> bool {
    argon2::password_hash::phc::PasswordHash::new(phc).is_ok_and(|hash| {
        hash.algorithm.as_str() == "argon2id"
            && hash.salt.is_some()
            && hash.hash.is_some()
            && hash.version.is_none_or(|version| argon2::Version::try_from(version).is_ok())
            && argon2::Params::try_from(&hash).is_ok()
    })
}

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
    /// Make `hash` on this thread answer as if every slot were busy.
    pub static HASH_BUSY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Raw PHC; wrap it once the destination row id is known.
pub async fn hash(password: String) -> anyhow::Result<String> {
    #[cfg(test)]
    anyhow::ensure!(!HASH_BUSY.get(), "password hashing is busy; try again");
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

/// Check both credentials, always spending a full password check.
pub async fn verify(
    pepper: Pepper,
    stored: String,
    purpose: Purpose,
    row_id: String,
    expected_user: String,
    username: String,
    password: String,
) -> Verdict {
    verify_inner(pepper, stored, purpose, row_id, Some((expected_user, username)), password).await
}

/// Check an account password after looking up its row.
pub async fn verify_password(
    pepper: Pepper,
    stored: String,
    purpose: Purpose,
    row_id: String,
    password: String,
) -> Verdict {
    verify_inner(pepper, stored, purpose, row_id, None, password).await
}

/// Return the PHC actually checked, even when opening or parsing fails.
fn verify_sync(
    pepper: &Pepper,
    stored: &str,
    purpose: Purpose,
    row_id: &str,
    users: Option<(String, String)>,
    password: &str,
) -> (String, bool) {
    let user_ok = users.is_none_or(|(expected, actual)| expected.as_bytes().ct_eq(actual.as_bytes()).into());
    let opened = pepper.unwrap(stored, purpose, row_id).filter(|phc| valid_phc(phc));
    let phc = opened.as_deref().unwrap_or(DUMMY_PHC);
    let pass_ok = Argon2::default().verify_password(password.as_bytes(), phc).is_ok();
    (phc.to_string(), opened.is_some() && user_ok && pass_ok)
}

async fn verify_inner(
    pepper: Pepper,
    stored: String,
    purpose: Purpose,
    row_id: String,
    users: Option<(String, String)>,
    password: String,
) -> Verdict {
    let Ok(Ok(slot)) = tokio::time::timeout(SLOT_WAIT, SLOTS.acquire()).await else {
        return Verdict::Busy;
    };
    // Cancellation must not release the slot while Argon2 is still running.
    let ok = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        verify_sync(&pepper, &stored, purpose, &row_id, users, &password).1
    })
    .await;
    #[cfg(test)]
    if ok.is_ok() {
        CHECKS.with(|c| c.set(c.get() + 1));
    }
    if ok.unwrap_or(false) { Verdict::Match } else { Verdict::NoMatch }
}

/// Argon2 checks running or waiting right now (for the status page and tests).
pub fn slots_in_use() -> usize {
    MAX_CONCURRENT - SLOTS.available_permits()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wrapped_passwords_verify_for_both_purposes() {
        let pepper = Pepper::new("public fixture secret");
        let phc = hash("correct horse".into()).await.unwrap();
        assert!(phc.starts_with("$argon2id$"));
        for purpose in [Purpose::User, Purpose::Tunnel] {
            let stored = pepper.wrap(&phc, purpose, "row1");
            for (user, password, expected) in [
                ("ann", "correct horse", Verdict::Match),
                ("bob", "correct horse", Verdict::NoMatch),
                ("ann", "wrong", Verdict::NoMatch),
            ] {
                assert_eq!(
                    verify(
                        pepper.clone(),
                        stored.clone(),
                        purpose,
                        "row1".into(),
                        "ann".into(),
                        user.into(),
                        password.into()
                    )
                    .await,
                    expected
                );
            }
            assert_eq!(
                verify_password(pepper.clone(), stored, purpose, "row1".into(), "correct horse".into()).await,
                Verdict::Match
            );
        }
    }

    #[tokio::test]
    async fn unwrappable_values_do_a_full_check_and_never_match() {
        let pepper = Pepper::new("public fixture secret");
        let other = Pepper::new("other public fixture");
        let dummy = argon2::password_hash::phc::PasswordHash::new(DUMMY_PHC).unwrap();
        assert_eq!(dummy.algorithm.as_str(), "argon2id");
        assert_eq!(dummy.params.get_decimal("m"), Some(19456));
        assert_eq!(dummy.params.get_decimal("t"), Some(2));
        assert_eq!(dummy.params.get_decimal("p"), Some(1));
        let (params, default) = (argon2::Params::try_from(&dummy).unwrap(), argon2::Params::default());
        assert_eq!(
            (params.m_cost(), params.t_cost(), params.p_cost()),
            (default.m_cost(), default.t_cost(), default.p_cost())
        );
        assert!(Argon2::default().verify_password(b"legacy-argon2-fixture", DUMMY_PHC).is_ok());
        for purpose in [Purpose::User, Purpose::Tunnel] {
            let wrong_key = other.wrap(DUMMY_PHC, purpose, "row1");
            let wrong_row = pepper.wrap(DUMMY_PHC, purpose, "row2");
            let wrong_purpose = pepper.wrap(DUMMY_PHC, Purpose::Tunnel, "row1");
            let invalid = pepper.wrap("invalid PHC", purpose, "row1");
            let incomplete = pepper.wrap("$argon2id$fixture", purpose, "row1");
            let wrong_algorithm = pepper.wrap(&DUMMY_PHC.replace("argon2id", "argon2i"), purpose, "row1");
            let invalid_phcs = [
                DUMMY_PHC.replace("m=19456", "m=0"),
                DUMMY_PHC.replace("v=19", "v=99"),
                DUMMY_PHC.rsplit_once('$').unwrap().0.to_string() + "$AA",
            ];
            for invalid_phc in invalid_phcs {
                assert!(!valid_phc(&invalid_phc));
                let stored = pepper.wrap(&invalid_phc, purpose, "row1");
                assert_eq!(
                    verify_sync(&pepper, &stored, purpose, "row1", None, "legacy-argon2-fixture"),
                    (DUMMY_PHC.into(), false)
                );
                let before = CHECKS.get();
                assert_eq!(
                    verify_password(pepper.clone(), stored, purpose, "row1".into(), "legacy-argon2-fixture".into())
                        .await,
                    Verdict::NoMatch
                );
                assert_eq!(CHECKS.get(), before + 1);
            }
            let damaged = format!("pw1:{}:AA", pepper.id());
            for stored in [
                "!",
                "",
                "garbage",
                DUMMY_PHC,
                &wrong_key,
                &wrong_row,
                &invalid,
                &incomplete,
                &wrong_algorithm,
                &damaged,
            ] {
                let (checked, matched) = verify_sync(&pepper, stored, purpose, "row1", None, "legacy-argon2-fixture");
                assert_eq!(checked, DUMMY_PHC);
                assert!(!matched);
                let before = CHECKS.get();
                assert_eq!(
                    verify_password(
                        pepper.clone(),
                        stored.into(),
                        purpose,
                        "row1".into(),
                        "legacy-argon2-fixture".into()
                    )
                    .await,
                    Verdict::NoMatch
                );
                assert_eq!(CHECKS.get(), before + 1, "a blocking Argon2 check completed");
            }
            if matches!(purpose, Purpose::User) {
                assert_eq!(
                    verify_sync(&pepper, &wrong_purpose, purpose, "row1", None, "legacy-argon2-fixture"),
                    (DUMMY_PHC.into(), false)
                );
            }
            let phc = hash("known password".into()).await.unwrap();
            let stored = pepper.wrap(&phc, purpose, "row1");
            assert_eq!(verify_sync(&pepper, &stored, purpose, "row1", None, "known password"), (phc.clone(), true));
            assert_eq!(
                verify_sync(&pepper, &stored, purpose, "row1", Some(("ann".into(), "bob".into())), "known password"),
                (phc, false)
            );
        }
    }

    #[tokio::test]
    async fn verifies_known_argon2id_after_wrapping() {
        let pepper = Pepper::new("public fixture secret");
        let stored = pepper.wrap(DUMMY_PHC, Purpose::User, "u1");
        assert_eq!(
            verify_password(pepper, stored, Purpose::User, "u1".into(), "legacy-argon2-fixture".into()).await,
            Verdict::Match
        );
    }
}
