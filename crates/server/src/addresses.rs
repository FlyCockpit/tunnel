//! Accounts' email addresses and the links mailed to them (only with mail
//! on): "Forgot password?" links, address confirmations, binding a mailed
//! sign-in reset to its address, and who gets a notice. `accounts` calls
//! the few helpers it needs while redeeming links.

use crate::db::{Db, authorized};
use crate::tokens::now;
use rusqlite::{OptionalExtension, params};

/// An account "Forgot password?" mails a link to.
#[derive(Debug, Clone)]
pub struct ResetTarget {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub totp: bool,
}

/// What a request for a new address leads to (the caller answers the same either way).
#[derive(Debug, PartialEq, Eq)]
pub enum EmailChange {
    /// Mail the confirmation link.
    Send { username: String },
    /// Another account has the address: nothing is mailed.
    Taken,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EmailError {
    SignedOut,
    /// It is already the account's address.
    Unchanged,
}

/// Why an address confirmation link was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Unknown, used or expired, or the sign-in changed since it was made.
    Invalid,
    /// Another account confirmed this address meanwhile.
    AddressTaken,
}

/// A confirmed address change.
#[derive(Debug, Clone)]
pub struct Verified {
    pub user_id: String,
    pub username: String,
    /// The address it replaced.
    pub old: Option<String>,
    pub new: String,
}

/// At most one "Forgot password?" link is mailed per account this often
/// (cleanup keeps a used link at least this long, as the marker).
pub const PASSWORD_RESET_COOLDOWN_S: i64 = 120;

impl Db {
    /// "Forgot password?": a `password_reset` link for the enabled account
    /// whose username or confirmed address is `login`, replacing its earlier
    /// unused ones, unless one was made less than `PASSWORD_RESET_COOLDOWN_S` ago. `None`:
    /// no mail to send (no such account, no address, disabled, too soon).
    pub async fn create_password_reset(
        &self,
        login: String,
        id: String,
        token_hash: String,
        expires_at: i64,
    ) -> anyhow::Result<Option<ResetTarget>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let found: Option<(String, String, String, bool)> = tx
                .query_row(
                    "SELECT id, username, email, totp_secret_sealed IS NOT NULL FROM users
                     WHERE (username = ?1 OR email = ?1) AND email IS NOT NULL AND disabled_at IS NULL",
                    params![login],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let Some((user_id, username, email, totp)) = found else {
                return Ok(None);
            };
            let recent: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM invites WHERE kind = 'password_reset' AND user_id = ?1 AND created_at > ?2)",
                params![user_id, t - PASSWORD_RESET_COOLDOWN_S],
                |r| r.get(0),
            )?;
            if recent {
                return Ok(None);
            }
            tx.execute("DELETE FROM invites WHERE kind = 'password_reset' AND user_id = ?1 AND used_at IS NULL", params![
                user_id
            ])?;
            tx.execute(
                "INSERT INTO invites (id, token_hash, kind, role, created_at, expires_at, user_id, auth_epoch, email)
                 SELECT ?1, ?2, 'password_reset', role, ?3, ?4, id, auth_epoch, email FROM users WHERE id = ?5",
                params![id, token_hash, t, expires_at, user_id],
            )?;
            tx.commit()?;
            Ok(Some(ResetTarget { user_id, username, email, totp }))
        })
        .await
    }

    /// A link that confirms `email` as the address of `user_id`, replacing
    /// the user's earlier unconfirmed one; only while `session` is live and
    /// the sign-in is still at `epoch` (the password was checked there).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_email_verify(
        &self,
        user_id: String,
        session: String,
        epoch: i64,
        id: String,
        token_hash: String,
        email: String,
        expires_at: i64,
    ) -> anyhow::Result<Result<EmailChange, EmailError>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, Some(epoch), &session)? {
                return Ok(Err(EmailError::SignedOut));
            }
            let (username, current): (String, Option<String>) =
                tx.query_row("SELECT username, email FROM users WHERE id = ?1", params![user_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            if current.as_deref() == Some(email.as_str()) {
                return Ok(Err(EmailError::Unchanged));
            }
            tx.execute("DELETE FROM invites WHERE kind = 'email_verify' AND user_id = ?1 AND used_at IS NULL", params![
                user_id
            ])?;
            tx.execute(
                "INSERT INTO invites (id, token_hash, kind, role, created_by, created_at, expires_at, user_id, auth_epoch, email)
                 SELECT ?1, ?2, 'email_verify', role, id, ?3, ?4, id, auth_epoch, ?5 FROM users WHERE id = ?6",
                params![id, token_hash, t, expires_at, email, user_id],
            )?;
            // Another account's address: the same answer, but nothing is mailed.
            let taken: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1 AND id != ?2)",
                params![email, user_id],
                |r| r.get(0),
            )?;
            tx.commit()?;
            Ok(Ok(if taken { EmailChange::Taken } else { EmailChange::Send { username } }))
        })
        .await
    }

    /// Confirm an address with its `email_verify` link: valid while unused,
    /// unexpired, the account is enabled and its sign-in unchanged since the
    /// link was made, and no other account has the address.
    pub async fn verify_email(&self, token_hash: String) -> anyhow::Result<Result<Verified, VerifyError>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let found: Option<(String, String, String, Option<String>, String)> = tx
                .query_row(
                    "SELECT i.id, u.id, u.username, u.email, i.email FROM invites i JOIN users u ON u.id = i.user_id
                     WHERE i.token_hash = ?1 AND i.kind = 'email_verify' AND i.used_at IS NULL AND i.expires_at > ?2
                       AND u.disabled_at IS NULL AND u.auth_epoch IS i.auth_epoch AND i.email IS NOT NULL",
                    params![token_hash, t],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((invite_id, user_id, username, old, new)) = found else {
                return Ok(Err(VerifyError::Invalid));
            };
            let taken: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1 AND id != ?2)",
                params![new, user_id],
                |r| r.get(0),
            )?;
            if taken {
                return Ok(Err(VerifyError::AddressTaken));
            }
            tx.execute("UPDATE users SET email = ?2, email_verified_at = ?3 WHERE id = ?1", params![user_id, new, t])?;
            tx.execute("UPDATE invites SET used_at = ?2, used_by = ?3 WHERE id = ?1", params![invite_id, t, user_id])?;
            // Links mailed to the old address are for an address the account no longer has.
            drop_mailed_links(&tx, &user_id)?;
            tx.commit()?;
            Ok(Ok(Verified { user_id, username, old: old.filter(|o| *o != new), new }))
        })
        .await
    }

    /// Remove the account's address (and its pending links), while `session`
    /// is live at `epoch`. `None`: signed out meanwhile; else the old address.
    pub async fn remove_email(
        &self,
        user_id: String,
        epoch: i64,
        session: String,
    ) -> anyhow::Result<Option<Option<String>>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, Some(epoch), &session)? {
                return Ok(None);
            }
            let old: Option<String> =
                tx.query_row("SELECT email FROM users WHERE id = ?1", params![user_id], |r| r.get(0))?;
            tx.execute("UPDATE users SET email = NULL, email_verified_at = NULL WHERE id = ?1", params![user_id])?;
            drop_mailed_links(&tx, &user_id)?;
            tx.commit()?;
            Ok(Some(old))
        })
        .await
    }

    /// Bind sign-in reset link `id` to the account's confirmed address, to
    /// mail it there: it then works only while the account keeps that
    /// address. Returns the address; `None` if the account has none.
    pub async fn bind_reset_to_address(&self, id: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            Ok(c.query_row(
                "UPDATE invites SET email = (SELECT email FROM users WHERE users.id = invites.user_id)
                 WHERE id = ?1 AND kind = 'account_reset' AND used_at IS NULL
                   AND EXISTS (SELECT 1 FROM users WHERE users.id = invites.user_id AND users.email IS NOT NULL)
                 RETURNING email",
                params![id],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await
    }

    /// The account a `password_reset` link may still reset, and whether it
    /// has two-factor sign-in: the link is unused and unexpired, the account
    /// is enabled, and its sign-in and address are those the link was made for.
    pub async fn password_reset_target(&self, token_hash: String) -> anyhow::Result<Option<(String, bool)>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT u.id, u.totp_secret_sealed IS NOT NULL FROM invites i JOIN users u ON u.id = i.user_id
                 WHERE i.token_hash = ?1 AND i.kind = 'password_reset' AND i.used_at IS NULL AND i.expires_at > ?2
                   AND u.disabled_at IS NULL AND u.auth_epoch IS i.auth_epoch AND u.email = i.email",
                params![token_hash, now()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })
        .await
    }

    /// Whether an address confirmation link would still be honoured (unused,
    /// unexpired, the account enabled and its sign-in unchanged since).
    pub async fn email_verify_valid(&self, token_hash: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM invites i JOIN users u ON u.id = i.user_id
                   WHERE i.token_hash = ?1 AND i.kind = 'email_verify' AND i.used_at IS NULL AND i.expires_at > ?2
                     AND u.disabled_at IS NULL AND u.auth_epoch IS i.auth_epoch AND i.email IS NOT NULL)",
                params![token_hash, now()],
                |r| r.get(0),
            )?)
        })
        .await
    }

    /// The address waiting for confirmation, if any (a link still valid: the
    /// sign-in unchanged since it was made).
    pub async fn pending_email(&self, user_id: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT i.email FROM invites i JOIN users u ON u.id = i.user_id
                 WHERE i.kind = 'email_verify' AND i.user_id = ?1 AND i.used_at IS NULL AND i.expires_at > ?2
                   AND u.auth_epoch IS i.auth_epoch AND u.disabled_at IS NULL ORDER BY i.created_at DESC LIMIT 1",
                params![user_id, now()],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await
    }

    /// Username and confirmed address of an enabled account, for a notice.
    pub async fn contact(&self, user_id: String) -> anyhow::Result<Option<(String, String)>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT username, email FROM users WHERE id = ?1 AND email IS NOT NULL AND disabled_at IS NULL",
                params![user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })
        .await
    }

    /// Whether an account has confirmed `email`.
    pub async fn email_in_use(&self, email: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.query_row("SELECT EXISTS (SELECT 1 FROM users WHERE email = ?1)", params![email], |r| r.get(0))?)
        })
        .await
    }
}

/// Redeem a "Forgot password?" link for `target`: only for the sign-in
/// (`epoch`) and the address (`email`) it was mailed for, and an enabled
/// account. Returns the account, `None` if the link no longer applies.
#[allow(clippy::too_many_arguments)]
pub(crate) fn redeem_password_reset(
    tx: &rusqlite::Transaction<'_>,
    target: Option<String>,
    epoch: Option<i64>,
    email: Option<String>,
    password_hash: &str,
    revoke_machines: bool,
    tunnels: &mut Vec<String>,
) -> anyhow::Result<Option<String>> {
    let (Some(target), Some(email)) = (target, email) else {
        return Ok(None);
    };
    let current: bool = tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1 AND disabled_at IS NULL AND auth_epoch IS ?2 AND email = ?3)",
        params![target, epoch, email],
        |r| r.get(0),
    )?;
    if !current {
        return Ok(None);
    }
    new_password(tx, &target, password_hash, revoke_machines, tunnels)?;
    Ok(Some(target))
}

/// Signing up through a mailed invite confirms its address for `user_id`,
/// unless another account has confirmed it meanwhile.
pub(crate) fn confirm_invited_address(
    tx: &rusqlite::Transaction<'_>,
    user_id: &str,
    email: Option<&str>,
    t: i64,
) -> anyhow::Result<()> {
    if let Some(email) = email {
        tx.execute(
            "UPDATE users SET email = ?2, email_verified_at = ?3
             WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM users WHERE email = ?2)",
            params![user_id, email, t],
        )?;
    }
    Ok(())
}

/// A sign-in reset mailed to `email` works only while the account still has
/// that address; one handed over by hand (`None`) is not bound.
pub(crate) fn still_at_address(c: &rusqlite::Connection, target: &str, email: Option<&str>) -> anyhow::Result<bool> {
    let Some(email) = email else {
        return Ok(true);
    };
    Ok(c.query_row("SELECT EXISTS (SELECT 1 FROM users WHERE id = ?1 AND email = ?2)", params![target, email], |r| {
        r.get(0)
    })?)
}

/// A new password for `user_id` that keeps its second factor and recovery
/// codes (a mailed reset: the address is not a second factor). Sessions and
/// pending machine logins end and the auth epoch moves on; with
/// `revoke_machines` its machines go too.
fn new_password(
    tx: &rusqlite::Transaction<'_>,
    user_id: &str,
    password_hash: &str,
    revoke_machines: bool,
    tunnels: &mut Vec<String>,
) -> anyhow::Result<()> {
    tx.execute(
        "UPDATE users SET password_hash = ?2, auth_epoch = auth_epoch + 1 WHERE id = ?1",
        params![user_id, password_hash],
    )?;
    tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1", params![user_id])?;
    tx.execute("DELETE FROM device_logins WHERE user_id = ?1", params![user_id])?;
    if revoke_machines {
        crate::db::revoke_machines(tx, user_id, tunnels)?;
    }
    Ok(())
}

/// Delete the account's unused links that went to (or wait for) an address:
/// address confirmations, mailed password resets, and sign-in resets an
/// admin mailed. Called when the address changes or goes, so none of them
/// works again even if the old address comes back.
fn drop_mailed_links(tx: &rusqlite::Transaction<'_>, user_id: &str) -> anyhow::Result<()> {
    tx.execute(
        "DELETE FROM invites WHERE user_id = ?1 AND used_at IS NULL
           AND (kind IN ('email_verify', 'password_reset') OR (kind = 'account_reset' AND email IS NOT NULL))",
        params![user_id],
    )?;
    Ok(())
}

/// Purge: mailed self-service links hold an address, so they go as soon as
/// they are used or expired (they are not kept for the invite list), but
/// not within the reset cooldown: a used reset still marks it.
pub(crate) fn purge_mailed_links(tx: &rusqlite::Transaction<'_>, t: i64) -> anyhow::Result<usize> {
    Ok(tx.execute(
        "DELETE FROM invites WHERE kind IN ('password_reset', 'email_verify') AND (used_at IS NOT NULL OR expires_at <= ?1)
           AND created_at <= ?2",
        params![t, t - PASSWORD_RESET_COOLDOWN_S],
    )?)
}
