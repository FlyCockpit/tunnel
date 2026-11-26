//! Accounts: users, sessions, invites, recovery codes and the audit log.

use crate::pepper::{Pepper, Purpose};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::addresses;
use crate::db::{Db, authorized, expire_owner_tunnels};
use crate::limits::{Kind, Setting, Settings, SettingsPatch};
use crate::role::Role;
use crate::tokens::now;

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub disabled: bool,
    pub can_public: bool,
    pub totp: bool,
    pub created_at: i64,
    /// Confirmed email address (mail on only).
    pub email: Option<String>,
    /// As set; the API shows them with what they resolve to (`limits.rs`).
    #[serde(skip)]
    pub limits: Settings,
}

/// A user with the secrets needed to sign them in.
#[derive(Clone)]
pub struct Credentials {
    pub user: User,
    /// Row-bound password seal, or `NO_PASSWORD`.
    pub password_hash: String,
    pub totp_sealed: Option<String>,
    pub totp_pending_sealed: Option<String>,
    pub totp_last_step: Option<i64>,
    pub auth_epoch: i64,
    /// Second-factor checks are refused until then.
    pub factor_locked_until: Option<i64>,
}

/// Password hash of an account that has no password yet (an owner created
/// without the UI); it never verifies.
pub const NO_PASSWORD: &str = "!";

/// Lockout after this many wrong second-factor codes in a row…
pub const FACTOR_FAILURES: i64 = 5;
/// …for this long, doubling with every further run of failures (at most a day).
pub const FACTOR_LOCK_S: i64 = 15 * 60;

/// A user in the admin list, with usage.
#[derive(Debug, Clone, Serialize)]
pub struct UserSummary {
    #[serde(flatten)]
    pub user: User,
    pub clients: i64,
    pub tunnels: i64,
    /// Bytes this calendar month (UTC), both directions.
    pub traffic_bytes: u64,
}

pub struct NewUser {
    pub id: String,
    pub username: String,
    /// Raw PHC, wrapped inside the insertion transaction.
    pub password_hash: String,
    pub can_public: bool,
}

#[derive(Debug, Default, Clone)]
pub struct UserPatch {
    pub role: Option<Role>,
    pub can_public: Option<bool>,
    pub limits: SettingsPatch,
}

/// One limit an admin's change set to another value (for the audit log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitChange {
    pub kind: Kind,
    pub old: Setting,
    pub old_role: Role,
    pub new: Setting,
    pub new_role: Role,
}

/// What [`Db::admin_update_user`] changed besides the row itself.
#[derive(Debug, Clone, Default)]
pub struct AdminUpdate {
    /// Tunnels to close (the user was disabled).
    pub closed: Vec<String>,
    pub limits: Vec<LimitChange>,
    /// Tunnels whose expiry moved earlier to fit a lower lifetime limit.
    pub shortened: Vec<String>,
}

/// A signed-in (or half signed-in) UI session.
#[derive(Clone)]
pub struct Session {
    pub id_hash: String,
    pub user: User,
    /// Password checked, TOTP code still due.
    pub pending: bool,
    pub auth_at: i64,
    pub auth_epoch: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    /// First 12 hex chars of the id hash: enough to name it, useless as a credential.
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub current: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteKind {
    Invite,
    OwnerSetup,
    OwnerReset,
    /// A new password for one account other than the owner's.
    AccountReset,
    /// "Forgot password?": a new password, mailed to the account's address.
    PasswordReset,
    /// Confirms a new email address of an account.
    EmailVerify,
}

impl InviteKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Invite => "invite",
            Self::OwnerSetup => "owner_setup",
            Self::OwnerReset => "owner_reset",
            Self::AccountReset => "account_reset",
            Self::PasswordReset => "password_reset",
            Self::EmailVerify => "email_verify",
        }
    }
    /// `None` for a kind this build does not know: never read as an invite.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "invite" => Some(Self::Invite),
            "owner_setup" => Some(Self::OwnerSetup),
            "owner_reset" => Some(Self::OwnerReset),
            "account_reset" => Some(Self::AccountReset),
            "password_reset" => Some(Self::PasswordReset),
            "email_verify" => Some(Self::EmailVerify),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Invite {
    pub id: String,
    pub kind: InviteKind,
    pub role: Role,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
    /// The account an `owner_reset` or `account_reset` is for.
    pub user: Option<String>,
    /// That account's role now.
    #[serde(skip)]
    pub user_role: Option<Role>,
    /// Where an emailed invite went, or the address to confirm.
    pub email: Option<String>,
}

/// What redeeming an invite needs: a new account, or a reset.
pub enum Acceptance {
    NewUser(NewUser),
    /// Owner or account reset: new password; TOTP, recovery codes, sessions
    /// and pending machine logins are cleared, and with `revoke_machines` the
    /// account's machines too.
    Reset {
        password_hash: String,
        revoke_machines: bool,
    },
}

/// Why a sign-in reset link was not made.
#[derive(Debug, PartialEq, Eq)]
pub enum ResetLinkError {
    NotFound,
    /// The owner (use `admin link`), oneself, or an admin for an admin.
    Forbidden,
    Disabled,
    /// The actor's session ended meanwhile.
    SignedOut,
    /// To be mailed, but the account has no confirmed address.
    NoEmail,
    /// To be mailed, but a recovery mail went to the account this many seconds too recently.
    MailCooldown(i64),
}

/// Why a machine rename was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum RenameError {
    /// No such machine, or not one the actor may manage.
    NotFound,
    Taken,
    /// The UI session ended or the actor was disabled meanwhile.
    SignedOut,
}

/// Why `user delete` refused.
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteUserError {
    NotFound,
    Owner,
}

/// Why an admin's change to a user was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum AdminError {
    NotFound,
    Forbidden,
    /// The admin's session ended meanwhile.
    SignedOut,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AcceptError {
    /// Unknown, used or expired.
    Invalid,
    UsernameTaken,
    /// `owner_setup` while an owner exists, or `owner_reset` with none.
    OwnerState,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub at: i64,
    pub user: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub ip: Option<String>,
}

/// A machine as the UI lists it.
#[derive(Debug, Clone, Serialize)]
pub struct Machine {
    pub name: String,
    pub user: String,
    pub enrolled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub tunnels: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkSummary {
    pub id: String,
    pub label: Option<String>,
    pub single_use: bool,
    pub used_at: Option<i64>,
    pub session_ttl_s: i64,
    pub created_at: i64,
    pub expires_at: i64,
    /// `visitor` or `owner` (Open in the web UI).
    pub kind: String,
}

const USER_COLUMNS: &str = "u.id, u.username, u.role, u.disabled_at IS NOT NULL, u.can_public, \
     u.totp_secret_sealed IS NOT NULL, u.created_at, u.limit_tunnels, u.limit_clients, u.limit_tunnel_ttl_s, \
     u.limit_traffic_bytes, u.email";
/// Columns `user_from_row` reads; queries add theirs after these.
const USER_COLS: usize = 12;

fn user_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        role: Role::parse(&r.get::<_, String>(2)?),
        disabled: r.get(3)?,
        can_public: r.get(4)?,
        totp: r.get(5)?,
        created_at: r.get(6)?,
        limits: Settings {
            tunnels: Setting::from_column(r.get(7)?),
            machines: Setting::from_column(r.get(8)?),
            tunnel_ttl_s: Setting::from_column(r.get(9)?),
            traffic_bytes: Setting::from_column(r.get(10)?),
        },
        email: r.get(11)?,
    })
}

fn invite_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Invite> {
    Ok(Invite {
        id: r.get(0)?,
        kind: InviteKind::parse(&r.get::<_, String>(1)?).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, "unknown link kind".into())
        })?,
        role: Role::parse(&r.get::<_, String>(2)?),
        created_by: r.get(3)?,
        created_at: r.get(4)?,
        expires_at: r.get(5)?,
        used_at: r.get(6)?,
        used_by: r.get(7)?,
        user: r.get(8)?,
        user_role: r.get::<_, Option<String>>(9)?.as_deref().map(Role::parse),
        email: r.get(10)?,
    })
}

/// Sessions end after this long without a request…
pub const SESSION_IDLE_S: i64 = 12 * 3600;
/// …and at the latest this long after sign-in.
pub const SESSION_MAX_S: i64 = 7 * 86_400;
/// A password-checked session has this long to present its TOTP code.
pub const PENDING_TTL_S: i64 = 5 * 60;
/// `last_seen_at` is written at most this often per session.
const TOUCH_EVERY_S: i64 = 60;

impl Db {
    // ------------------------------------------------------------------ users

    pub async fn owner_exists(&self) -> anyhow::Result<bool> {
        self.call(|c| Ok(c.query_row("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner')", [], |r| r.get(0))?))
            .await
    }

    pub async fn owner(&self) -> anyhow::Result<Option<User>> {
        self.call(|c| {
            Ok(c.query_row(&format!("SELECT {USER_COLUMNS} FROM users u WHERE u.role = 'owner'"), [], user_from_row)
                .optional()?)
        })
        .await
    }

    pub async fn user_by_name(&self, username: String) -> anyhow::Result<Option<User>> {
        self.call(move |c| {
            Ok(c.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users u WHERE u.username = ?1"),
                params![username],
                user_from_row,
            )
            .optional()?)
        })
        .await
    }

    /// Credentials by username (sign-in) or id.
    pub async fn credentials(
        &self,
        username: Option<String>,
        id: Option<String>,
    ) -> anyhow::Result<Option<Credentials>> {
        self.call(move |c| {
            let sql = format!(
                "SELECT {USER_COLUMNS}, u.password_hash, u.totp_secret_sealed, u.totp_pending_sealed, u.totp_last_step,
                        u.auth_epoch, u.factor_locked_until
                 FROM users u WHERE u.username = ?1 OR u.id = ?2"
            );
            Ok(c.query_row(&sql, params![username, id], |r| {
                Ok(Credentials {
                    user: user_from_row(r)?,
                    password_hash: r.get(USER_COLS)?,
                    totp_sealed: r.get(USER_COLS + 1)?,
                    totp_pending_sealed: r.get(USER_COLS + 2)?,
                    totp_last_step: r.get(USER_COLS + 3)?,
                    auth_epoch: r.get(USER_COLS + 4)?,
                    factor_locked_until: r.get(USER_COLS + 5)?,
                })
            })
            .optional()?)
        })
        .await
    }

    /// Every user, with machines, live tunnels and the stored traffic of `month`.
    pub async fn list_users(&self, month: u32) -> anyhow::Result<Vec<UserSummary>> {
        self.call(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {USER_COLUMNS},
                        (SELECT COUNT(*) FROM clients c WHERE c.user_id = u.id),
                        (SELECT COUNT(*) FROM tunnels t JOIN clients c ON c.id = t.client_id
                         WHERE c.user_id = u.id AND t.expires_at > ?1),
                        COALESCE((SELECT bytes_in + bytes_out FROM traffic WHERE user_id = u.id AND month = ?2), 0)
                 FROM users u ORDER BY u.username"
            ))?;
            Ok(stmt
                .query_map(params![now(), month], |r| {
                    Ok(UserSummary {
                        user: user_from_row(r)?,
                        clients: r.get(USER_COLS)?,
                        tunnels: r.get(USER_COLS + 1)?,
                        traffic_bytes: r.get::<_, i64>(USER_COLS + 2)?.max(0) as u64,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// An admin's change to another user, authorized inside the same
    /// transaction: `actor` must still be signed in with `session`, be the
    /// owner or an admin, the target must not be the owner or the actor, an
    /// admin may change members only, and only the owner changes roles.
    /// A role change ends the user's sessions and resets the four limits to
    /// the server default; becoming a member also resets public previews and
    /// drops the unused invites they made. A lower lifetime limit (a changed
    /// lifetime or role) moves the expiry of the user's tunnels that would
    /// outlive it to that long from now. Disabling ends sessions and logins
    /// and deletes machines; the tunnels in `closed` must be closed by the
    /// caller.
    pub async fn admin_update_user(
        &self,
        actor: String,
        session: String,
        id: String,
        patch: UserPatch,
        disabled: Option<bool>,
    ) -> anyhow::Result<Result<(User, AdminUpdate), AdminError>> {
        let defaults = self.limit_defaults();
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &actor, None, &session)? {
                return Ok(Err(AdminError::SignedOut));
            }
            let actor_role = Role::parse(&tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor], |r| {
                r.get::<_, String>(0)
            })?);
            let role: Option<String> =
                tx.query_row("SELECT role FROM users WHERE id = ?1", params![id], |r| r.get(0)).optional()?;
            let Some(role) = role.map(|r| Role::parse(&r)) else {
                return Ok(Err(AdminError::NotFound));
            };
            let allowed = id != actor
                && role != Role::Owner
                && (actor_role == Role::Owner || (actor_role == Role::Admin && role == Role::Member))
                && (patch.role.is_none() || actor_role == Role::Owner)
                && patch.role != Some(Role::Owner);
            if !allowed {
                return Ok(Err(AdminError::Forbidden));
            }
            let before = tx.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users u WHERE u.id = ?1"),
                params![id],
                user_from_row,
            )?;
            let mut settings = before.limits;
            let mut new_role = role;
            if let Some(changed) = patch.role.filter(|r| *r != role) {
                new_role = changed;
                tx.execute(
                    "UPDATE users SET role = ?2, auth_epoch = auth_epoch + 1 WHERE id = ?1",
                    params![id, changed.as_str()],
                )?;
                tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1", params![id])?;
                settings = Settings::default();
                if changed == Role::Member {
                    tx.execute("UPDATE users SET can_public = 0 WHERE id = ?1", params![id])?;
                    tx.execute("DELETE FROM invites WHERE created_by = ?1 AND used_at IS NULL", params![id])?;
                }
            }
            if let Some(v) = patch.can_public {
                tx.execute("UPDATE users SET can_public = ?2 WHERE id = ?1", params![id, v])?;
            }
            for kind in Kind::ALL {
                if let Some(v) = patch.limits.get(kind) {
                    settings.set(kind, v);
                }
            }
            let mut update = AdminUpdate::default();
            for kind in Kind::ALL {
                let (old, new) = (before.limits.get(kind), settings.get(kind));
                if old != new {
                    tx.execute(
                        &format!("UPDATE users SET {} = ?2 WHERE id = ?1", kind.column()),
                        params![id, new.to_column()],
                    )?;
                }
                // Also a limit a role change moved (e.g. Server default for
                // an admin → for a member).
                if old != new || defaults.resolve(kind, role, old) != defaults.resolve(kind, new_role, new) {
                    update.limits.push(LimitChange { kind, old, old_role: role, new, new_role });
                }
            }
            let lifetime_changed = new_role != role || before.limits.tunnel_ttl_s != settings.tunnel_ttl_s;
            if lifetime_changed
                && let Some(limit) = defaults.resolve(Kind::TunnelTtl, new_role, settings.tunnel_ttl_s)
            {
                let latest = now().saturating_add(i64::try_from(limit).unwrap_or(i64::MAX));
                let mut stmt = tx.prepare(
                    "UPDATE tunnels SET expires_at = ?2
                     WHERE expires_at > ?2 AND client_id IN (SELECT id FROM clients WHERE user_id = ?1)
                     RETURNING id",
                )?;
                update.shortened =
                    stmt.query_map(params![id, latest], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
            }
            let mut tunnels = Vec::new();
            match disabled {
                Some(true) => {
                    tx.execute(
                        "UPDATE users SET disabled_at = COALESCE(disabled_at, ?2), auth_epoch = auth_epoch + 1 WHERE id = ?1",
                        params![id, now()],
                    )?;
                    tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1", params![id])?;
                    tx.execute("DELETE FROM invites WHERE created_by = ?1 AND used_at IS NULL", params![id])?;
                    tx.execute("DELETE FROM device_logins WHERE user_id = ?1", params![id])?;
                    let clients: Vec<String> = {
                        let mut stmt = tx.prepare("SELECT id FROM clients WHERE user_id = ?1")?;
                        stmt.query_map(params![id], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?
                    };
                    for client in clients {
                        tunnels.extend(expire_owner_tunnels(&tx, &client)?);
                        tx.execute("DELETE FROM clients WHERE id = ?1", params![client])?;
                    }
                }
                Some(false) => {
                    tx.execute("UPDATE users SET disabled_at = NULL WHERE id = ?1", params![id])?;
                }
                None => {}
            }
            let user = tx.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users u WHERE u.id = ?1"),
                params![id],
                user_from_row,
            )?;
            tx.commit()?;
            update.closed = tunnels;
            Ok(Ok((user, update)))
        })
        .await
    }

    /// New password, and every session of the user ends, in one
    /// transaction; only while `session` still exists and the user's auth
    /// epoch is still `epoch` (the one the current password was checked at),
    /// so a change cannot land after a recovery. Returns the new epoch.
    pub async fn set_password(
        &self,
        user_id: String,
        password_hash: String,
        epoch: i64,
        session: String,
        pepper: Pepper,
    ) -> anyhow::Result<Option<i64>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, Some(epoch), &session)? {
                return Ok(None);
            }
            let epoch: i64 = tx.query_row(
                "UPDATE users SET password_hash = ?2, auth_epoch = auth_epoch + 1 WHERE id = ?1 RETURNING auth_epoch",
                params![user_id, pepper.wrap(&password_hash, Purpose::User, &user_id)],
                |r| r.get(0),
            )?;
            tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1", params![user_id])?;
            tx.commit()?;
            Ok(Some(epoch))
        })
        .await
    }

    /// Store a pending TOTP secret while `session` is still a live session of the user.
    pub async fn set_totp_pending(&self, user_id: String, sealed: String, session: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, None, &session)? {
                return Ok(false);
            }
            tx.execute("UPDATE users SET totp_pending_sealed = ?2 WHERE id = ?1", params![user_id, sealed])?;
            tx.commit()?;
            Ok(true)
        })
        .await
    }

    /// The user ends their own sessions: all others, or the one whose id hash
    /// starts with `prefix`; only while `current` is still live. Returns how
    /// many ended, `None` if `current` has ended meanwhile.
    pub async fn revoke_own_sessions(
        &self,
        user_id: String,
        current: String,
        prefix: Option<String>,
    ) -> anyhow::Result<Option<usize>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, None, &current)? {
                return Ok(None);
            }
            let n = match prefix {
                None => tx.execute(
                    "DELETE FROM ui_sessions WHERE user_id = ?1 AND id_hash != ?2",
                    params![user_id, current],
                )?,
                Some(p) if p.len() == 12 && p.bytes().all(|b| b.is_ascii_hexdigit()) => tx.execute(
                    "DELETE FROM ui_sessions WHERE user_id = ?1 AND substr(id_hash, 1, 12) = ?2",
                    params![user_id, p],
                )?,
                Some(_) => 0,
            };
            tx.commit()?;
            Ok(Some(n))
        })
        .await
    }

    /// Turn TOTP on with the pending secret `sealed` (checked unchanged, so a
    /// concurrent restart of enrolment cannot swap it), first used at `step`,
    /// with fresh recovery codes; the user's other sessions end (all but `keep`).
    pub async fn enable_totp(
        &self,
        user_id: String,
        sealed: String,
        step: i64,
        recovery_hashes: Vec<String>,
        epoch: i64,
        keep: String,
    ) -> anyhow::Result<bool> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, Some(epoch), &keep)? {
                return Ok(false);
            }
            let n = tx.execute(
                "UPDATE users SET totp_secret_sealed = totp_pending_sealed, totp_pending_sealed = NULL, totp_last_step = ?3,
                        auth_epoch = auth_epoch + 1, factor_failures = 0, factor_locked_until = NULL
                 WHERE id = ?1 AND totp_pending_sealed = ?2",
                params![user_id, sealed, step],
            )?;
            if n != 1 {
                return Ok(false);
            }
            tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1 AND id_hash != ?2", params![user_id, keep])?;
            tx.execute("UPDATE ui_sessions SET auth_at = ?2 WHERE id_hash = ?1", params![keep, now()])?;
            tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", params![user_id])?;
            for h in recovery_hashes {
                tx.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)", params![user_id, h])?;
            }
            tx.commit()?;
            Ok(true)
        })
        .await
    }

    /// Turn TOTP off; the user's other sessions end (all but `keep`). Only
    /// while `keep` exists and the epoch is still `epoch` (see `set_password`).
    pub async fn disable_totp(&self, user_id: String, epoch: i64, keep: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &user_id, Some(epoch), &keep)? {
                return Ok(false);
            }
            tx.execute(
                "UPDATE users SET totp_secret_sealed = NULL, totp_pending_sealed = NULL, totp_last_step = NULL,
                        auth_epoch = auth_epoch + 1 WHERE id = ?1",
                params![user_id],
            )?;
            tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1 AND id_hash != ?2", params![user_id, keep])?;
            tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", params![user_id])?;
            tx.commit()?;
            Ok(true)
        })
        .await
    }

    /// Record a used TOTP step; `false` if that step (or a later one) was
    /// already used, so a code cannot be replayed even by concurrent requests.
    pub async fn use_totp_step(&self, user_id: String, step: i64) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.execute(
                "UPDATE users SET totp_last_step = ?2
                 WHERE id = ?1 AND totp_secret_sealed IS NOT NULL AND (totp_last_step IS NULL OR totp_last_step < ?2)",
                params![user_id, step],
            )? == 1)
        })
        .await
    }

    /// Count a wrong second-factor code; returns the lockout end if this
    /// failure started one.
    pub async fn factor_failed(&self, user_id: String) -> anyhow::Result<Option<i64>> {
        self.call(move |c| {
            let t = now();
            let failures: i64 = c.query_row(
                "UPDATE users SET factor_failures = factor_failures + 1 WHERE id = ?1 RETURNING factor_failures",
                params![user_id],
                |r| r.get(0),
            )?;
            if failures % FACTOR_FAILURES != 0 {
                return Ok(None);
            }
            let runs = (failures / FACTOR_FAILURES - 1).min(7) as u32;
            let until = t + (FACTOR_LOCK_S << runs).min(86_400);
            c.execute("UPDATE users SET factor_locked_until = ?2 WHERE id = ?1", params![user_id, until])?;
            Ok(Some(until))
        })
        .await
    }

    pub async fn factor_ok(&self, user_id: String) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute(
                "UPDATE users SET factor_failures = 0, factor_locked_until = NULL WHERE id = ?1",
                params![user_id],
            )?;
            Ok(())
        })
        .await
    }

    /// Consume a recovery code (single use).
    pub async fn use_recovery_code(&self, user_id: String, code_hash: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.execute(
                "UPDATE recovery_codes SET used_at = ?3 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
                params![user_id, code_hash, now()],
            )? == 1)
        })
        .await
    }

    pub async fn recovery_codes_left(&self, user_id: String) -> anyhow::Result<i64> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                params![user_id],
                |r| r.get(0),
            )?)
        })
        .await
    }

    // --------------------------------------------------------------- sessions

    /// Issue a session for `user_id`, only if the user is enabled and their
    /// auth epoch is still `epoch` (nothing about how they sign in changed
    /// since it was checked). With `replace`, that (pending) session must
    /// still exist with the same epoch and is removed in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_ui_session(
        &self,
        id_hash: String,
        user_id: String,
        pending: bool,
        epoch: i64,
        replace: Option<String>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> anyhow::Result<bool> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some(old) = &replace {
                // Only a live, still-pending session can be swapped: one that
                // expired while its request was in flight is not.
                let n = tx.execute(
                    "DELETE FROM ui_sessions WHERE id_hash = ?1 AND user_id = ?2 AND auth_epoch = ?3
                       AND pending = 1 AND expires_at > ?4",
                    params![old, user_id, epoch, t],
                )?;
                if n != 1 {
                    return Ok(false);
                }
            }
            let expires = t + if pending { PENDING_TTL_S } else { SESSION_MAX_S };
            let n = tx.execute(
                "INSERT INTO ui_sessions (id_hash, user_id, pending, created_at, last_seen_at, auth_at, expires_at, auth_epoch, ip, user_agent)
                 SELECT ?1, ?2, ?3, ?4, ?4, ?4, ?5, ?6, ?7, ?8
                 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND disabled_at IS NULL AND auth_epoch = ?6)",
                params![id_hash, user_id, pending, t, expires, epoch, ip, user_agent],
            )?;
            if n != 1 {
                return Ok(false);
            }
            tx.commit()?;
            Ok(true)
        })
        .await
    }

    /// The live session with `id_hash` whose user is enabled, refreshing
    /// `last_seen_at` at most once a minute. Idle or expired sessions are deleted.
    pub async fn ui_session(&self, id_hash: String) -> anyhow::Result<Option<Session>> {
        self.call(move |c| {
            let t = now();
            let found = c
                .query_row(
                    &format!(
                        "SELECT {USER_COLUMNS}, s.pending, s.created_at, s.auth_at, s.last_seen_at, s.expires_at, s.auth_epoch
                         FROM ui_sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?1"
                    ),
                    params![id_hash],
                    |r| {
                        Ok((
                            Session {
                                id_hash: id_hash.clone(),
                                user: user_from_row(r)?,
                                pending: r.get(USER_COLS)?,
                                auth_at: r.get(USER_COLS + 2)?,
                                auth_epoch: r.get(USER_COLS + 5)?,
                            },
                            r.get::<_, i64>(USER_COLS + 3)?,
                            r.get::<_, i64>(USER_COLS + 4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((session, last_seen, expires)) = found else {
                return Ok(None);
            };
            if expires <= t || last_seen + SESSION_IDLE_S <= t || session.user.disabled {
                c.execute("DELETE FROM ui_sessions WHERE id_hash = ?1", params![id_hash])?;
                return Ok(None);
            }
            if last_seen + TOUCH_EVERY_S <= t {
                c.execute("UPDATE ui_sessions SET last_seen_at = ?2 WHERE id_hash = ?1", params![id_hash, t])?;
            }
            Ok(Some(session))
        })
        .await
    }

    pub async fn touch_ui_auth(&self, id_hash: String) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute("UPDATE ui_sessions SET auth_at = ?2 WHERE id_hash = ?1", params![id_hash, now()])?;
            Ok(())
        })
        .await
    }

    pub async fn delete_ui_session(&self, id_hash: String) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute("DELETE FROM ui_sessions WHERE id_hash = ?1", params![id_hash])?;
            Ok(())
        })
        .await
    }

    /// End all of a user's sessions except `keep`.
    #[cfg(test)]
    pub async fn delete_user_sessions(&self, user_id: String, keep: Option<String>) -> anyhow::Result<usize> {
        self.call(move |c| {
            Ok(c.execute(
                "DELETE FROM ui_sessions WHERE user_id = ?1 AND (?2 IS NULL OR id_hash != ?2)",
                params![user_id, keep],
            )?)
        })
        .await
    }

    pub async fn list_user_sessions(&self, user_id: String, current: String) -> anyhow::Result<Vec<SessionSummary>> {
        self.call(move |c| {
            let t = now();
            let mut stmt = c.prepare(
                "SELECT id_hash, created_at, last_seen_at, ip, user_agent FROM ui_sessions
                 WHERE user_id = ?1 AND pending = 0 AND expires_at > ?2 AND last_seen_at > ?3 ORDER BY last_seen_at DESC",
            )?;
            Ok(stmt
                .query_map(params![user_id, t, t - SESSION_IDLE_S], |r| {
                    let hash: String = r.get(0)?;
                    Ok(SessionSummary {
                        id: hash[..12].to_string(),
                        current: hash == current,
                        created_at: r.get(1)?,
                        last_seen_at: r.get(2)?,
                        ip: r.get(3)?,
                        user_agent: r.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    // ---------------------------------------------------------------- invites

    /// A new invite. From the web UI (`session` set), `created_by` must still
    /// be signed in with that session and be the owner or an admin (the
    /// owner, for an admin invite), checked in the same transaction; `None`
    /// otherwise. The CLI's owner links pass no session.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_invite(
        &self,
        id: String,
        token_hash: String,
        kind: InviteKind,
        role: Role,
        created_by: Option<String>,
        session: Option<String>,
        expires_at: i64,
        email: Option<String>,
    ) -> anyhow::Result<Option<Invite>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if let Some(session) = &session {
                let actor = created_by.clone().unwrap_or_default();
                if !authorized(&tx, &actor, None, session)? {
                    return Ok(None);
                }
                let actor_role =
                    Role::parse(&tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor], |r| {
                        r.get::<_, String>(0)
                    })?);
                let ok = kind == InviteKind::Invite
                    && match role {
                        Role::Member => actor_role.is_admin(),
                        Role::Admin => actor_role == Role::Owner,
                        Role::Owner => false,
                    };
                if !ok {
                    return Ok(None);
                }
            }
            // Sign-in resets for other accounts are made by `create_reset_link`.
            anyhow::ensure!(kind != InviteKind::AccountReset, "account resets are made by create_reset_link");
            // A new owner link replaces any earlier unused one.
            if kind != InviteKind::Invite {
                tx.execute("DELETE FROM invites WHERE kind IN ('owner_setup', 'owner_reset') AND used_at IS NULL", [])?;
            }
            let email = email.filter(|_| kind == InviteKind::Invite);
            tx.execute(
                "INSERT INTO invites (id, token_hash, kind, role, created_by, created_at, expires_at, email)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![id, token_hash, kind.as_str(), role.as_str(), created_by, t, expires_at, email],
            )?;
            tx.commit()?;
            Ok(Some(Invite {
                id,
                kind,
                role,
                created_by,
                created_at: t,
                expires_at,
                used_at: None,
                used_by: None,
                user: None,
                user_role: None,
                email,
            }))
        })
        .await
    }

    /// A sign-in reset link for `target` (a user id), replacing its earlier
    /// unused one. From the web UI, `actor` is `(user id, session)`: still
    /// signed in, and the owner (for an admin or member) or an admin (for a
    /// member), checked in the same transaction. `None` is the server shell.
    /// Nobody resets the owner here (`admin link` does) or themselves.
    /// With `mail`, the link is bound to the account's confirmed address (it
    /// works only while the account keeps it; `Invite::email`) and takes the
    /// account's recovery-mail slot (`addresses::claim_recovery_mail`).
    pub async fn create_reset_link(
        &self,
        id: String,
        token_hash: String,
        target: String,
        actor: Option<(String, String)>,
        expires_at: i64,
        mail: bool,
    ) -> anyhow::Result<Result<Invite, ResetLinkError>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let found: Option<(String, String, bool, i64, Option<String>)> = tx
                .query_row(
                    "SELECT username, role, disabled_at IS NOT NULL, auth_epoch, email FROM users WHERE id = ?1",
                    params![target],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((username, role, disabled, epoch, address)) = found else {
                return Ok(Err(ResetLinkError::NotFound));
            };
            let role = Role::parse(&role);
            let mut issuer_epoch = None;
            if let Some((actor, session)) = &actor {
                if !authorized(&tx, actor, None, session)? {
                    return Ok(Err(ResetLinkError::SignedOut));
                }
                let (actor_role, actor_epoch): (String, i64) =
                    tx.query_row("SELECT role, auth_epoch FROM users WHERE id = ?1", params![actor], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })?;
                if *actor == target || !may_reset(Role::parse(&actor_role), role) {
                    return Ok(Err(ResetLinkError::Forbidden));
                }
                issuer_epoch = Some(actor_epoch);
            }
            if role == Role::Owner {
                return Ok(Err(ResetLinkError::Forbidden));
            }
            if disabled {
                return Ok(Err(ResetLinkError::Disabled));
            }
            let email = if mail {
                let Some(address) = address else {
                    return Ok(Err(ResetLinkError::NoEmail));
                };
                if let Err(wait) = addresses::claim_recovery_mail(&tx, &target, t)? {
                    return Ok(Err(ResetLinkError::MailCooldown(wait)));
                }
                Some(address)
            } else {
                None
            };
            tx.execute("DELETE FROM invites WHERE kind = 'account_reset' AND user_id = ?1 AND used_at IS NULL", params![
                target
            ])?;
            let created_by = actor.map(|(a, _)| a);
            tx.execute(
                "INSERT INTO invites (id, token_hash, kind, role, created_by, created_at, expires_at, user_id, auth_epoch,
                                      issuer_epoch, email)
                 VALUES (?1, ?2, 'account_reset', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![id, token_hash, role.as_str(), created_by, t, expires_at, target, epoch, issuer_epoch, email],
            )?;
            tx.commit()?;
            Ok(Ok(Invite {
                id,
                kind: InviteKind::AccountReset,
                role,
                created_by,
                created_at: t,
                expires_at,
                used_at: None,
                used_by: None,
                user: Some(username),
                user_role: Some(role),
                email,
            }))
        })
        .await
    }

    /// Delete a user other than the owner, with their sessions, unused
    /// invites, device logins and machines; returns the machines' tunnels
    /// (expired here, closed by the purge loop).
    pub async fn delete_user(&self, username: String) -> anyhow::Result<Result<Vec<String>, DeleteUserError>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let found: Option<(String, String)> = tx
                .query_row("SELECT id, role FROM users WHERE username = ?1", params![username], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let Some((id, role)) = found else {
                return Ok(Err(DeleteUserError::NotFound));
            };
            if Role::parse(&role) == Role::Owner {
                return Ok(Err(DeleteUserError::Owner));
            }
            tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1", params![id])?;
            tx.execute("DELETE FROM invites WHERE created_by = ?1 AND used_at IS NULL", params![id])?;
            tx.execute("DELETE FROM device_logins WHERE user_id = ?1", params![id])?;
            tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", params![id])?;
            let clients: Vec<String> = {
                let mut stmt = tx.prepare("SELECT id FROM clients WHERE user_id = ?1")?;
                stmt.query_map(params![id], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?
            };
            let mut tunnels = Vec::new();
            for client in clients {
                tunnels.extend(expire_owner_tunnels(&tx, &client)?);
                tx.execute("DELETE FROM clients WHERE id = ?1", params![client])?;
            }
            tx.execute("DELETE FROM users WHERE id = ?1", params![id])?;
            tx.commit()?;
            Ok(Ok(tunnels))
        })
        .await
    }

    /// An unused, unexpired invite (with the account's name for a reset).
    pub async fn invite_by_token(&self, token_hash: String) -> anyhow::Result<Option<Invite>> {
        self.call(move |c| {
            let found = c
                .query_row(
                    "SELECT i.id, i.kind, i.role, cu.username, i.created_at, i.expires_at, i.used_at, i.used_by,
                            CASE i.kind WHEN 'owner_reset' THEN (SELECT username FROM users WHERE role = 'owner')
                                        ELSE tu.username END,
                            CASE i.kind WHEN 'owner_reset' THEN 'owner' ELSE tu.role END, i.email,
                            i.user_id, i.auth_epoch, i.created_by, i.issuer_epoch
                     FROM invites i LEFT JOIN users cu ON cu.id = i.created_by LEFT JOIN users tu ON tu.id = i.user_id
                     WHERE i.token_hash = ?1 AND i.used_at IS NULL AND i.expires_at > ?2",
                    params![token_hash, now()],
                    |r| {
                        let issuer: Option<String> = r.get(13)?;
                        Ok((invite_from_row(r)?, r.get::<_, Option<String>>(11)?, r.get(12)?, issuer, r.get(14)?))
                    },
                )
                .optional()?;
            let Some((invite, target, epoch, issuer, issuer_epoch)) = found else {
                return Ok(None);
            };
            // A reset link that redeeming would refuse says nothing about its account.
            if invite.kind == InviteKind::AccountReset {
                let role = invite.role.as_str();
                let issuer = issuer.as_deref().map(|i| (i, issuer_epoch));
                let valid = |t: &str| {
                    Ok::<_, anyhow::Error>(
                        reset_still_allowed(c, t, role, epoch, issuer)?
                            && addresses::still_at_address(c, t, invite.email.as_deref())?,
                    )
                };
                if !target.is_some_and(|t| valid(&t).unwrap_or(false)) {
                    return Ok(None);
                }
            }
            Ok(Some(invite))
        })
        .await
    }

    pub async fn list_invites(&self) -> anyhow::Result<Vec<Invite>> {
        self.call(|c| {
            let mut stmt = c.prepare(
                "SELECT i.id, i.kind, i.role, cu.username, i.created_at, i.expires_at, i.used_at, uu.username,
                        tu.username, tu.role, i.email
                 FROM invites i LEFT JOIN users cu ON cu.id = i.created_by LEFT JOIN users uu ON uu.id = i.used_by
                 LEFT JOIN users tu ON tu.id = i.user_id
                 WHERE i.kind IN ('invite', 'account_reset') ORDER BY i.created_at DESC LIMIT 200",
            )?;
            Ok(stmt.query_map([], invite_from_row)?.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// Revoke an unused invite, or a sign-in reset link for an account
    /// `actor` may reset, while `actor` (an admin) is still signed in with `session`.
    pub async fn delete_invite(&self, id: String, actor: String, session: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let role: Option<String> =
                tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor], |r| r.get(0)).optional()?;
            let role = role.as_deref().map(Role::parse);
            if !role.is_some_and(Role::is_admin) || !authorized(&tx, &actor, None, &session)? {
                return Ok(false);
            }
            let n = tx.execute(
                "DELETE FROM invites WHERE id = ?1 AND used_at IS NULL
                   AND (kind = 'invite' OR (kind = 'account_reset' AND
                        (?2 = 'owner' OR (SELECT role FROM users WHERE id = invites.user_id) = 'member')))",
                params![id, role.map(Role::as_str)],
            )?;
            tx.commit()?;
            Ok(n == 1)
        })
        .await
    }

    /// Redeem an invite in one transaction: mark it used and create the user
    /// (or reset the owner). Returns the user id.
    pub async fn accept_invite(
        &self,
        token_hash: String,
        acceptance: Acceptance,
        pepper: Pepper,
    ) -> anyhow::Result<Result<(String, i64, Vec<String>), AcceptError>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            /// Who made a reset link, the account and auth epoch it is for,
            /// and the address it (or an invite) was mailed to.
            struct Reset {
                created_by: Option<String>,
                target: Option<String>,
                epoch: Option<i64>,
                issuer_epoch: Option<i64>,
                email: Option<String>,
            }
            let invite: Option<(String, String, String, Reset)> = tx
                .query_row(
                    "SELECT id, kind, role, created_by, user_id, auth_epoch, issuer_epoch, email FROM invites
                     WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                    params![token_hash, t],
                    |r| {
                        let reset = Reset {
                            created_by: r.get(3)?,
                            target: r.get(4)?,
                            epoch: r.get(5)?,
                            issuer_epoch: r.get(6)?,
                            email: r.get(7)?,
                        };
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, reset))
                    },
                )
                .optional()?;
            let Some((invite_id, kind, role, reset)) = invite else {
                return Ok(Err(AcceptError::Invalid));
            };
            let Some(kind) = InviteKind::parse(&kind) else {
                return Ok(Err(AcceptError::Invalid));
            };
            // The owner, and whether it still lacks a password (created for
            // machines before anyone signed up).
            let owner: Option<(String, bool)> = tx
                .query_row("SELECT id, password_hash = ?1 FROM users WHERE role = 'owner'", params![NO_PASSWORD], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let mut tunnels = Vec::new();
            let user_id = match (kind, acceptance) {
                (InviteKind::OwnerReset, Acceptance::Reset { password_hash, revoke_machines }) => {
                    let Some((owner, _)) = owner else {
                        return Ok(Err(AcceptError::OwnerState));
                    };
                    tx.execute("UPDATE users SET disabled_at = NULL WHERE id = ?1", params![owner])?;
                    reset_sign_in(&tx, &owner, &pepper.wrap(&password_hash, Purpose::User, &owner), revoke_machines, &mut tunnels)?;
                    owner
                }
                (InviteKind::AccountReset, Acceptance::Reset { password_hash, revoke_machines }) => {
                    let Some(target) = reset.target else {
                        return Ok(Err(AcceptError::Invalid));
                    };
                    let issuer = reset.created_by.as_deref().map(|id| (id, reset.issuer_epoch));
                    if !reset_still_allowed(&tx, &target, &role, reset.epoch, issuer)? {
                        return Ok(Err(AcceptError::Invalid));
                    }
                    if !addresses::still_at_address(&tx, &target, reset.email.as_deref())? {
                        return Ok(Err(AcceptError::Invalid));
                    }
                    reset_sign_in(&tx, &target, &pepper.wrap(&password_hash, Purpose::User, &target), revoke_machines, &mut tunnels)?;
                    target
                }
                (InviteKind::PasswordReset, Acceptance::Reset { password_hash, revoke_machines }) => {
                    let found = addresses::redeem_password_reset(
                        &tx,
                        reset.target,
                        reset.epoch,
                        reset.email,
                        &password_hash,
                        &pepper,
                        revoke_machines,
                        &mut tunnels,
                    )?;
                    match found {
                        Some(target) => target,
                        None => return Ok(Err(AcceptError::Invalid)),
                    }
                }
                (InviteKind::OwnerSetup, Acceptance::NewUser(u)) => match owner {
                    Some((_, false)) => return Ok(Err(AcceptError::OwnerState)),
                    // The password-less owner signs up: it takes the chosen name.
                    Some((owner, true)) => {
                        let taken: bool = tx.query_row(
                            "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?1 AND id != ?2)",
                            params![u.username, owner],
                            |r| r.get(0),
                        )?;
                        if taken {
                            return Ok(Err(AcceptError::UsernameTaken));
                        }
                        tx.execute(
                            "UPDATE users SET username = ?2, password_hash = ?3, auth_epoch = auth_epoch + 1 WHERE id = ?1",
                            params![owner, u.username, pepper.wrap(&u.password_hash, Purpose::User, &owner)],
                        )?;
                        owner
                    }
                    None => match insert_user(&tx, u, Role::Owner, t, &pepper)? {
                        Some(id) => id,
                        None => return Ok(Err(AcceptError::UsernameTaken)),
                    },
                },
                (InviteKind::Invite, Acceptance::NewUser(u)) => {
                    // The invite decides the role, never the invitee.
                    let role = match Role::parse(&role) {
                        Role::Owner => Role::Member,
                        r => r,
                    };
                    let id = match insert_user(&tx, u, role, t, &pepper)? {
                        Some(id) => id,
                        None => return Ok(Err(AcceptError::UsernameTaken)),
                    };
                    addresses::confirm_invited_address(&tx, &id, reset.email.as_deref(), t)?;
                    id
                }
                _ => return Ok(Err(AcceptError::Invalid)),
            };
            tx.execute(
                "UPDATE invites SET used_at = ?2, used_by = ?3 WHERE id = ?1",
                params![invite_id, t, user_id],
            )?;
            let epoch: i64 = tx.query_row("SELECT auth_epoch FROM users WHERE id = ?1", params![user_id], |r| r.get(0))?;
            tx.commit()?;
            Ok(Ok((user_id, epoch, tunnels)))
        })
        .await
    }

    /// The owner, created without a password if there is none yet, so
    /// machines can belong to someone on a server used without the web UI.
    /// `admin link` later lets them pick a name and password.
    pub async fn ensure_owner(&self) -> anyhow::Result<User> {
        self.call(|c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let found = tx
                .query_row(&format!("SELECT {USER_COLUMNS} FROM users u WHERE u.role = 'owner'"), [], user_from_row)
                .optional()?;
            let user = match found {
                Some(u) => u,
                None => {
                    let id = format!("us{}", crate::tokens::random_tunnel_id());
                    let mut name = "owner".to_string();
                    let mut n = 2;
                    while tx.query_row(
                        "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?1)",
                        params![name],
                        |r| r.get::<_, bool>(0),
                    )? {
                        name = format!("owner-{n}");
                        n += 1;
                    }
                    tx.execute(
                        "INSERT INTO users (id, username, password_hash, role, can_public, created_at)
                         VALUES (?1, ?2, ?3, 'owner', 1, ?4)",
                        params![id, name, NO_PASSWORD, now()],
                    )?;
                    tx.query_row(
                        &format!("SELECT {USER_COLUMNS} FROM users u WHERE u.id = ?1"),
                        params![id],
                        user_from_row,
                    )?
                }
            };
            tx.commit()?;
            Ok(user)
        })
        .await
    }

    /// Whether the owner exists and still has no password.
    pub async fn owner_without_password(&self) -> anyhow::Result<bool> {
        self.call(|c| {
            Ok(c.query_row(
                "SELECT EXISTS (SELECT 1 FROM users WHERE role = 'owner' AND password_hash = ?1)",
                params![NO_PASSWORD],
                |r| r.get(0),
            )?)
        })
        .await
    }

    // ------------------------------------------------------------------ audit

    pub async fn audit(
        &self,
        user_id: Option<String>,
        action: &'static str,
        target: Option<String>,
        ip: Option<String>,
    ) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO audit (at, user_id, action, target, ip) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![now(), user_id, action, target, ip],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn list_audit(&self, before: Option<i64>, limit: u32) -> anyhow::Result<Vec<AuditEntry>> {
        self.call(move |c| {
            let mut stmt = c.prepare(
                "SELECT a.id, a.at, u.username, a.action, a.target, a.ip FROM audit a LEFT JOIN users u ON u.id = a.user_id
                 WHERE ?1 IS NULL OR a.id < ?1 ORDER BY a.id DESC LIMIT ?2",
            )?;
            Ok(stmt
                .query_map(params![before, limit], |r| {
                    Ok(AuditEntry {
                        id: r.get(0)?,
                        at: r.get(1)?,
                        user: r.get(2)?,
                        action: r.get(3)?,
                        target: r.get(4)?,
                        ip: r.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    // -------------------------------------------------------- machines, links

    /// Rename machine `old` to `new` (validated by the caller). From the web
    /// UI, `actor` is `(user id, session id hash)`: the session must still be
    /// valid and the user may rename their own machines, admins members'
    /// machines, the owner everyone's (checked here, in the transaction). The
    /// server shell and the admin token pass `None`.
    pub async fn rename_client(
        &self,
        old: String,
        new: String,
        actor: Option<(String, String)>,
    ) -> anyhow::Result<Result<(), RenameError>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // The session first, so a signed-out caller learns nothing about which names exist.
            if let Some((actor_id, session)) = &actor
                && !authorized(&tx, actor_id, None, session)?
            {
                return Ok(Err(RenameError::SignedOut));
            }
            let found: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT c.id, c.user_id, u.role FROM clients c JOIN users u ON u.id = c.user_id WHERE c.name = ?1",
                    params![old],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((client_id, owner_id, owner_role)) = found else {
                return Ok(Err(RenameError::NotFound));
            };
            if let Some((actor_id, _)) = &actor {
                let actor_role =
                    Role::parse(&tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor_id], |r| {
                        r.get::<_, String>(0)
                    })?);
                let allowed = owner_id == *actor_id
                    || actor_role == Role::Owner
                    || (actor_role == Role::Admin && Role::parse(&owner_role) == Role::Member);
                if !allowed {
                    return Ok(Err(RenameError::NotFound));
                }
            }
            if old == new {
                return Ok(Ok(()));
            }
            let renamed = tx.execute(
                "UPDATE clients SET name = ?2 WHERE id = ?1 AND NOT EXISTS (SELECT 1 FROM clients WHERE name = ?2)",
                params![client_id, new],
            )?;
            if renamed == 0 {
                return Ok(Err(RenameError::Taken));
            }
            tx.commit()?;
            Ok(Ok(()))
        })
        .await
    }

    /// Rename live tunnel `id` from the web UI: the session must still be
    /// valid and `actor` may manage the tunnel (their own; admins members';
    /// the owner anyone's; service and admin-token tunnels admins only),
    /// checked here, in the transaction. `Ok(Some(old name))` when renamed,
    /// `Ok(None)` when not found (or not theirs, or signed out meanwhile).
    pub async fn rename_tunnel_for(
        &self,
        id: String,
        name: Option<String>,
        actor: String,
        session: String,
    ) -> anyhow::Result<Option<Option<String>>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &actor, None, &session)? {
                return Ok(None);
            }
            let actor_role =
                Role::parse(
                    &tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor], |r| r.get::<_, String>(0))?,
                );
            let found: Option<(Option<String>, Option<String>, Option<String>)> = tx
                .query_row(
                    "SELECT t.name, c.user_id, u.role FROM tunnels t
                     LEFT JOIN clients c ON c.id = t.client_id LEFT JOIN users u ON u.id = c.user_id
                     WHERE t.id = ?1 AND t.expires_at > ?2",
                    params![id, now()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((old, owner, owner_role)) = found else {
                return Ok(None);
            };
            let allowed = match owner {
                Some(owner) => {
                    owner == actor
                        || actor_role == Role::Owner
                        || (actor_role == Role::Admin && owner_role.as_deref() == Some("member"))
                }
                None => actor_role.is_admin(),
            };
            if !allowed {
                return Ok(None);
            }
            tx.execute("UPDATE tunnels SET name = ?2 WHERE id = ?1", params![id, name])?;
            tx.commit()?;
            Ok(Some(old))
        })
        .await
    }

    /// Machines of `user_id`, or of everyone when `None`.
    pub async fn list_machines(&self, user_id: Option<String>) -> anyhow::Result<Vec<Machine>> {
        self.call(move |c| {
            let mut stmt = c.prepare(
                "SELECT c.name, u.username, c.token_hash IS NOT NULL, c.created_at, c.last_used_at,
                        (SELECT COUNT(*) FROM tunnels t WHERE t.client_id = c.id AND t.expires_at > ?2)
                 FROM clients c JOIN users u ON u.id = c.user_id
                 WHERE ?1 IS NULL OR c.user_id = ?1 ORDER BY u.username, c.name",
            )?;
            Ok(stmt
                .query_map(params![user_id, now()], |r| {
                    Ok(Machine {
                        name: r.get(0)?,
                        user: r.get(1)?,
                        enrolled: r.get(2)?,
                        created_at: r.get(3)?,
                        last_used_at: r.get(4)?,
                        tunnels: r.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// Delete machine `name` if `actor_id` may: their own, an admin on a
    /// member's, the owner on anyone's. Checked and deleted in one
    /// transaction (names can be reused). Returns the tunnels to close;
    /// `None` if there is no such machine or the actor may not delete it.
    pub async fn delete_client_for(&self, name: String, actor_id: String) -> anyhow::Result<Option<Vec<String>>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let found: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT c.id, c.user_id, u.role FROM clients c JOIN users u ON u.id = c.user_id WHERE c.name = ?1",
                    params![name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let actor: Option<String> = tx
                .query_row("SELECT role FROM users WHERE id = ?1 AND disabled_at IS NULL", params![actor_id], |r| {
                    r.get(0)
                })
                .optional()?;
            let (Some((client_id, owner_id, owner_role)), Some(actor_role)) = (found, actor) else {
                return Ok(None);
            };
            let allowed =
                owner_id == actor_id || actor_role == "owner" || (actor_role == "admin" && owner_role == "member");
            if !allowed {
                return Ok(None);
            }
            let tunnels = expire_owner_tunnels(&tx, &client_id)?;
            tx.execute("DELETE FROM clients WHERE id = ?1", params![client_id])?;
            tx.commit()?;
            Ok(Some(tunnels))
        })
        .await
    }

    /// Unexpired tunnels of `user_id`'s machines (everyone's when `None`,
    /// including service and admin-token tunnels), with the machine and user names.
    pub async fn list_user_tunnels(
        &self,
        user_id: Option<String>,
    ) -> anyhow::Result<Vec<(crate::db::TunnelRow, Option<String>, Option<String>)>> {
        self.call(move |c| {
            let sql = "SELECT t.id, t.label, t.metadata, t.max_ports, t.host_header, t.inject_ice, t.created_at, t.expires_at,
                        t.last_seen_at, t.access_mode, t.password_user, t.password_hash, t.client_id,
                        t.bytes_in, t.bytes_out, c.user_id, t.name, COALESCE(c.name, s.name), u.username
                 FROM tunnels t
                 LEFT JOIN clients c ON c.id = t.client_id
                 LEFT JOIN users u ON u.id = c.user_id
                 LEFT JOIN services s ON s.id = t.client_id
                 WHERE t.expires_at > ?2 AND (?1 IS NULL OR c.user_id = ?1)
                 ORDER BY t.created_at DESC LIMIT 1000";
            let mut stmt = c.prepare(sql)?;
            Ok(stmt
                .query_map(params![user_id, now()], |r| {
                    let n = crate::db::TUNNEL_COLUMNS;
                    Ok((crate::db::tunnel_from_row(r)?, r.get(n)?, r.get(n + 1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// The user owning tunnel `id` through one of their machines.
    pub async fn tunnel_user(&self, id: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT c.user_id FROM tunnels t JOIN clients c ON c.id = t.client_id WHERE t.id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?)
        })
        .await
    }

    /// Store a link minted in the web UI, only if, in this transaction,
    /// `actor` is still signed in with `session`, may manage the tunnel (their
    /// own, an admin on a member's or on a service's, the owner on any) and
    /// the tunnel is unexpired.
    pub async fn create_access_link_for(
        &self,
        l: crate::db::NewAccessLink,
        actor: String,
        session: String,
    ) -> anyhow::Result<bool> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !authorized(&tx, &actor, None, &session)? {
                return Ok(false);
            }
            let actor_role = Role::parse(&tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor], |r| {
                r.get::<_, String>(0)
            })?);
            let owner: Option<(Option<String>, Option<String>)> = tx
                .query_row(
                    "SELECT c.user_id, u.role FROM tunnels t
                     LEFT JOIN clients c ON c.id = t.client_id LEFT JOIN users u ON u.id = c.user_id
                     WHERE t.id = ?1 AND t.expires_at > ?2",
                    params![l.tunnel_id, t],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((owner, owner_role)) = owner else {
                return Ok(false);
            };
            let allowed = match owner {
                // An owner link (Open) is only ever for the tunnel's own user.
                Some(owner) if l.owner_port.is_some() => owner == actor,
                None if l.owner_port.is_some() => false,
                Some(owner) => {
                    owner == actor
                        || actor_role == Role::Owner
                        || (actor_role == Role::Admin && owner_role.as_deref() == Some("member"))
                }
                None => actor_role.is_admin(),
            };
            if !allowed {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO access_links (id, tunnel_id, token_hash, single_use, label, session_ttl_s, created_at, expires_at, kind, port)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    l.id,
                    l.tunnel_id,
                    l.token_hash,
                    l.single_use,
                    l.label,
                    l.session_ttl_s,
                    t,
                    l.expires_at,
                    if l.owner_port.is_some() { "owner" } else { "visitor" },
                    l.owner_port,
                ],
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await
    }

    pub async fn list_access_links(&self, tunnel_id: String) -> anyhow::Result<Vec<LinkSummary>> {
        self.call(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, label, single_use, used_at, session_ttl_s, created_at, expires_at, kind FROM access_links
                 WHERE tunnel_id = ?1 ORDER BY created_at DESC LIMIT 500",
            )?;
            Ok(stmt
                .query_map(params![tunnel_id], |r| {
                    Ok(LinkSummary {
                        id: r.get(0)?,
                        label: r.get(1)?,
                        single_use: r.get(2)?,
                        used_at: r.get(3)?,
                        session_ttl_s: r.get(4)?,
                        created_at: r.get(5)?,
                        expires_at: r.get(6)?,
                        kind: r.get(7)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// Hourly cleanup of expired account rows; audit entries are kept 90 days.
    pub async fn purge_accounts(&self) -> anyhow::Result<usize> {
        self.call(|c| {
            let t = now();
            let tx = c.transaction()?;
            let mut n = tx.execute(
                "DELETE FROM ui_sessions WHERE expires_at <= ?1 OR last_seen_at <= ?2",
                params![t, t - SESSION_IDLE_S],
            )?;
            n += tx.execute("DELETE FROM device_logins WHERE expires_at <= ?1", params![t])?;
            n += tx.execute(
                "DELETE FROM invites WHERE (used_at IS NOT NULL OR expires_at <= ?1) AND created_at <= ?2",
                params![t, t - 30 * 86_400],
            )?;
            n += addresses::purge_mailed_links(&tx, t)?;
            n += tx.execute("DELETE FROM audit WHERE at <= ?1", params![t - 90 * 86_400])?;
            tx.commit()?;
            Ok(n)
        })
        .await
    }
}

#[cfg(test)]
impl Db {
    /// A user row for tests outside the UI module.
    pub async fn insert_test_user(&self, id: &str, username: &str, role: Role) {
        let (id, username) = (id.to_string(), username.to_string());
        self.call(move |c| {
            c.execute(
                "INSERT OR IGNORE INTO users (id, username, password_hash, role, limit_tunnels, limit_clients, created_at)
                 VALUES (?1, ?2, 'x', ?3, 1000, 1000, 0)",
                params![id, username, role.as_str()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }
}

/// Insert `u` with `role`; `None` if the username is taken.
/// Whether an `actor_role` may reset the sign-in of an account with `target_role`.
fn may_reset(actor_role: Role, target_role: Role) -> bool {
    match target_role {
        Role::Member => actor_role.is_admin(),
        Role::Admin => actor_role == Role::Owner,
        Role::Owner => false,
    }
}

/// An `account_reset` link is honoured only while its account is enabled and
/// has the role and sign-in (auth epoch) it had when the link was made, and
/// the admin who made it (none: the server shell) still may reset it with
/// the sign-in it had then: any change to the maker's sign-in, role or status
/// since (a recovery from a stolen session, a demotion, even one undone)
/// voids the links it made.
fn reset_still_allowed(
    tx: &rusqlite::Connection,
    target: &str,
    role: &str,
    epoch: Option<i64>,
    issuer: Option<(&str, Option<i64>)>,
) -> anyhow::Result<bool> {
    let current: Option<(String, i64)> = tx
        .query_row("SELECT role, auth_epoch FROM users WHERE id = ?1 AND disabled_at IS NULL", params![target], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let Some((current_role, current_epoch)) = current else {
        return Ok(false);
    };
    if current_role != role || Some(current_epoch) != epoch || Role::parse(role) == Role::Owner {
        return Ok(false);
    }
    let Some((issuer, issuer_epoch)) = issuer else {
        return Ok(true);
    };
    let found: Option<(String, i64)> = tx
        .query_row("SELECT role, auth_epoch FROM users WHERE id = ?1 AND disabled_at IS NULL", params![issuer], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    Ok(issuer != target
        && found.is_some_and(|(r, e)| Some(e) == issuer_epoch && may_reset(Role::parse(&r), Role::parse(role))))
}

/// A new password for `user_id`; its second factor, recovery codes, factor
/// lockout, sessions and pending machine logins go, and its auth epoch moves
/// on (voiding anything issued for the old sign-in). With `revoke_machines`
/// its machines go too; their tunnels are added to `tunnels`.
fn reset_sign_in(
    tx: &rusqlite::Transaction<'_>,
    user_id: &str,
    password_hash: &str,
    revoke_machines: bool,
    tunnels: &mut Vec<String>,
) -> anyhow::Result<()> {
    tx.execute(
        "UPDATE users SET password_hash = ?2, totp_secret_sealed = NULL, totp_pending_sealed = NULL,
                totp_last_step = NULL, auth_epoch = auth_epoch + 1,
                factor_failures = 0, factor_locked_until = NULL WHERE id = ?1",
        params![user_id, password_hash],
    )?;
    tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", params![user_id])?;
    tx.execute("DELETE FROM ui_sessions WHERE user_id = ?1", params![user_id])?;
    // Logins approved before the reset (maybe by whoever forced it) are not honoured.
    tx.execute("DELETE FROM device_logins WHERE user_id = ?1", params![user_id])?;
    if revoke_machines {
        crate::db::revoke_machines(tx, user_id, tunnels)?;
    }
    Ok(())
}

fn insert_user(
    tx: &rusqlite::Transaction<'_>,
    u: NewUser,
    role: Role,
    t: i64,
    pepper: &Pepper,
) -> anyhow::Result<Option<String>> {
    let inserted = tx.execute(
        "INSERT INTO users (id, username, password_hash, role, can_public, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(username) DO NOTHING",
        params![u.id, u.username, pepper.wrap(&u.password_hash, Purpose::User, &u.id), role.as_str(), u.can_public, t],
    )?;
    Ok((inserted == 1).then_some(u.id))
}
