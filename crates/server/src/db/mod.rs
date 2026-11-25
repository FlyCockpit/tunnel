//! SQLite persistence. All access goes through [`Db::call`], which runs the
//! closure on a blocking thread holding the single connection.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};

use crate::role::Role;
use crate::tokens::now;

/// Moved on whenever the schema does, so that an older build refuses the
/// database rather than misreading it (2: sign-in reset links).
pub const SCHEMA_VERSION: i32 = 2;

/// `expires_at` of a tunnel that never expires (9999-12-31T23:59:59Z): every
/// expiry check (`expires_at > now`, the sweep) keeps working unchanged.
pub const NEVER_EXPIRES: i64 = 253_402_300_799;

const SCHEMA: &str = r#"
CREATE TABLE tunnels (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT,
    metadata     TEXT,
    max_ports    INTEGER NOT NULL,
    host_header  TEXT NOT NULL,
    inject_ice   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER,
    access_mode  TEXT NOT NULL DEFAULT 'link',
    password_user TEXT,
    password_hash TEXT,
    -- The owner: the client (`cl…`) or service (`sv…`) that created the
    -- tunnel; NULL for the admin token.
    client_id    TEXT,
    -- Proxied body and WebSocket bytes (visitor -> app, app -> visitor),
    -- flushed from memory about once a minute.
    bytes_in     INTEGER NOT NULL DEFAULT 0,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    -- Display name (`tunnel share --name`, renamed in the web UI): a label
    -- only, never part of a URL, not unique. Trimmed, 1..=80 characters, no
    -- control or bidi-override characters; NULL when unnamed.
    name         TEXT
);
CREATE INDEX tunnels_expires_at ON tunnels(expires_at);
CREATE INDEX tunnels_client ON tunnels(client_id, expires_at);
CREATE INDEX tunnels_client_id ON tunnels(client_id, id);
CREATE TABLE tombstones (
    id         TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL
);
CREATE INDEX tombstones_deleted_at ON tombstones(deleted_at);
CREATE TABLE access_links (
    id            TEXT PRIMARY KEY,
    tunnel_id     TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    single_use    INTEGER NOT NULL,
    used_at       INTEGER,
    label         TEXT,
    session_ttl_s INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    -- `owner`: minted by the web UI's Open button for the tunnel's owner,
    -- bound to `port`, and redeemable again from the address that used it
    -- for a few seconds (a browser's repeated request must not land on the
    -- sign-in form). `visitor`: every other link.
    kind          TEXT NOT NULL DEFAULT 'visitor' CHECK (kind IN ('visitor', 'owner')),
    -- The only port an owner link lands on; NULL for visitor links.
    port          INTEGER,
    -- Hash of the address that redeemed a single-use owner link.
    used_from     TEXT
);
CREATE INDEX access_links_tunnel ON access_links(tunnel_id);
CREATE TABLE gate_sessions (
    id_hash    TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE gate_grants (
    session_hash TEXT NOT NULL REFERENCES gate_sessions(id_hash) ON DELETE CASCADE,
    tunnel_id    TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (session_hash, tunnel_id)
);
CREATE INDEX gate_grants_tunnel ON gate_grants(tunnel_id);
-- Every link a grant came from, so revoking any of them revokes the grant.
-- Deleting a link cascades here only; the grant itself is removed explicitly
-- by revocation, never by routine link expiry.
CREATE TABLE gate_grant_links (
    session_hash TEXT NOT NULL,
    tunnel_id    TEXT NOT NULL,
    link_id      TEXT NOT NULL REFERENCES access_links(id) ON DELETE CASCADE,
    -- When the access this link gave runs out.
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (session_hash, tunnel_id, link_id),
    FOREIGN KEY (session_hash, tunnel_id) REFERENCES gate_grants(session_hash, tunnel_id) ON DELETE CASCADE
);
CREATE INDEX gate_grant_links_link ON gate_grant_links(link_id);
-- Grants that came from a password login, so changing the password (or
-- leaving password mode) revokes exactly those.
CREATE TABLE gate_grant_logins (
    session_hash TEXT NOT NULL,
    tunnel_id    TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (session_hash, tunnel_id),
    FOREIGN KEY (session_hash, tunnel_id) REFERENCES gate_grants(session_hash, tunnel_id) ON DELETE CASCADE
);
-- Machines enrolled with `client add` + `tunnel login`, or approved in the
-- browser (`tunnel login <url>`). Each belongs to a user.
CREATE TABLE clients (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    user_id      TEXT NOT NULL REFERENCES users(id)
);
CREATE INDEX clients_user ON clients(user_id);
-- People who sign in to the web UI. Exactly one owner (setup); admins manage
-- users and see everything; members manage only their own machines.
CREATE TABLE users (
    id                 TEXT PRIMARY KEY,
    username           TEXT NOT NULL UNIQUE,
    password_hash      TEXT NOT NULL,
    -- Sealed with a key derived from `ui_secret`; the pending one waits for
    -- the first code during enrolment.
    totp_secret_sealed TEXT,
    totp_pending_sealed TEXT,
    totp_last_step     INTEGER,
    role               TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    disabled_at        INTEGER,
    can_public         INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    -- Bumped by every change to how the user signs in (password, TOTP, role,
    -- disabling): a session is issued only if it is unchanged since the check.
    auth_epoch         INTEGER NOT NULL DEFAULT 0,
    -- Wrong TOTP or recovery codes in a row, and the lockout they caused.
    factor_failures    INTEGER NOT NULL DEFAULT 0,
    factor_locked_until INTEGER,
    -- Per-user limits (see `limits.rs`): NULL follows the server default for
    -- the role, -1 is unlimited. Live tunnels across the user's machines,
    -- machines, longest tunnel lifetime (seconds) and monthly traffic (bytes,
    -- both directions).
    limit_tunnels       INTEGER CHECK (limit_tunnels >= -1),
    limit_clients       INTEGER CHECK (limit_clients >= -1),
    limit_tunnel_ttl_s  INTEGER CHECK (limit_tunnel_ttl_s >= -1),
    limit_traffic_bytes INTEGER CHECK (limit_traffic_bytes >= -1),
    -- The account's email address once confirmed (lowercased; mail on only):
    -- password resets and notices go there. A new address waits in an
    -- `email_verify` link until it is confirmed.
    email TEXT,
    email_verified_at INTEGER
);
CREATE UNIQUE INDEX users_one_owner ON users(role) WHERE role = 'owner';
CREATE UNIQUE INDEX users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE recovery_codes (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at   INTEGER,
    PRIMARY KEY (user_id, code_hash)
);
-- Single-use links: `invite` (role admin or member), the owner's
-- `owner_setup` / `owner_reset` from `tunnel-server admin link`, and
-- `account_reset` (a new password for `user_id`, made by an admin or `user
-- reset`; `role` and `auth_epoch` are the account's when it was made,
-- `issuer_epoch` the maker's).
-- With mail on: `password_reset` ("Forgot password?", mailed to `email`, the
-- account's address then) and `email_verify` (confirms `email` as the
-- address of `user_id`); an emailed `invite` was sent to `email`.
CREATE TABLE invites (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('invite', 'owner_setup', 'owner_reset', 'account_reset',
                                             'password_reset', 'email_verify')),
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_by TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    used_by    TEXT,
    user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
    auth_epoch INTEGER,
    issuer_epoch INTEGER,
    email      TEXT
);
CREATE INDEX invites_user ON invites(user_id);
-- Web UI sessions (`__Host-tunnel-ui` cookie; only the hash is stored).
-- `pending` sessions have passed the password and wait for the TOTP code.
CREATE TABLE ui_sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pending      INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    -- Last password or TOTP check, for re-authentication on sensitive steps.
    auth_at      INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    -- The user's auth_epoch when the session was issued.
    auth_epoch   INTEGER NOT NULL,
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX ui_sessions_user ON ui_sessions(user_id);
-- Browser-approved machine logins (RFC 8628 device flow).
CREATE TABLE device_logins (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    client_name      TEXT NOT NULL,
    ip               TEXT,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    interval_s       INTEGER NOT NULL,
    last_poll_at     INTEGER,
    status           TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    user_id          TEXT REFERENCES users(id) ON DELETE CASCADE
);
-- Traffic per user and calendar month (UTC, `YYYYMM`), from their machines' tunnels.
CREATE TABLE traffic (
    user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    month     INTEGER NOT NULL,
    bytes_in  INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, month)
);
CREATE TABLE audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      INTEGER NOT NULL,
    user_id TEXT,
    action  TEXT NOT NULL,
    target  TEXT,
    ip      TEXT
);
CREATE INDEX audit_at ON audit(at);
-- Service credentials (`service add`): API-only callers such as a sandbox
-- platform. They manage only their own tunnels, within `max_tunnels`.
CREATE TABLE services (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    max_tunnels  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
-- One-time enrollment codes; only the hash is stored.
CREATE TABLE client_enrollments (
    code_hash  TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HostHeaderMode {
    Rewrite,
    Preserve,
}

impl HostHeaderMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rewrite => "rewrite",
            Self::Preserve => "preserve",
        }
    }
    pub fn parse(s: &str) -> Self {
        if s == "preserve" { Self::Preserve } else { Self::Rewrite }
    }
}

/// Who may open a tunnel's previews. Access links work in every mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Access links only.
    Link,
    /// Access links, or a username and password on the login page.
    Password,
    /// Anyone with the URL; no gate.
    Public,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Password => "password",
            Self::Public => "public",
        }
    }
    /// Unknown values fall back to the strictest mode.
    pub fn parse(s: &str) -> Self {
        match s {
            "password" => Self::Password,
            "public" => Self::Public,
            _ => Self::Link,
        }
    }
}

/// A tunnel's access setting as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub mode: AccessMode,
    /// Set in password mode only.
    pub password_user: Option<String>,
    /// PHC-format argon2 hash; set in password mode only.
    pub password_hash: Option<String>,
}

impl Default for Access {
    fn default() -> Self {
        Self { mode: AccessMode::Link, password_user: None, password_hash: None }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelRow {
    pub id: String,
    pub label: Option<String>,
    /// Display name (see the schema); `None` when unnamed.
    pub name: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub max_ports: u16,
    pub host_header: HostHeaderMode,
    pub inject_ice: bool,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: Option<i64>,
    pub access: Access,
    /// Owner: the creating client's or service's id; `None` for tunnels
    /// created with the admin token.
    pub client_id: Option<String>,
    /// The user whose machine created it (`None` for services and the admin token).
    pub user_id: Option<String>,
    /// Flushed traffic (see `traffic`); add the unflushed part for a current figure.
    pub bytes_in: i64,
    pub bytes_out: i64,
}

impl TunnelRow {
    pub fn is_expired(&self) -> bool {
        self.expires_at <= now()
    }
}

#[derive(Debug, Clone)]
pub struct NewTunnel {
    pub id: String,
    pub token_hash: String,
    pub label: Option<String>,
    pub name: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub max_ports: u16,
    pub host_header: HostHeaderMode,
    pub inject_ice: bool,
    pub expires_at: i64,
    pub access: Access,
    /// Owner id (client or service); `None` for the admin token.
    pub client_id: Option<String>,
}

/// Which live-tunnel limit refused a new tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TunnelQuotaExceeded {
    /// The user's limit across all their machines.
    #[error("live-tunnel limit of the account reached")]
    Account { limit: u64, role: Role },
    /// `limits.max_tunnels_per_client`.
    #[error("live-tunnel limit of the machine reached")]
    Machine { limit: u32 },
    /// The service's own quota.
    #[error("live-tunnel quota of the service reached")]
    Service { limit: u32 },
}

#[derive(Debug, Clone, Default)]
pub struct TunnelPatch {
    pub expires_at: Option<i64>,
    pub label: Option<String>,
    /// `Some(None)` removes the name.
    pub name: Option<Option<String>>,
    pub host_header: Option<HostHeaderMode>,
    pub inject_ice: Option<bool>,
    /// Replaces the access setting, subject to `keep_password_hash`.
    pub access: Option<Access>,
    /// Resolve an omitted password from the row in the update transaction.
    pub keep_password_hash: bool,
    /// The caller's owner id (client or service) and the server's rules for
    /// it, applied with the owner's *current* role and permissions inside the
    /// update transaction: a switch into public access needs permission (a
    /// tunnel that is already public may stay public), and members' expiry is
    /// capped. `None` for the admin token.
    pub owner_policy: Option<(String, Policy)>,
}

/// Server rules evaluated against an owner's current permissions in the
/// same transaction as a tunnel write.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// `limits.allow_public_for_clients`.
    pub allow_all_public: bool,
    /// What "Server default" means for per-user limits.
    pub defaults: crate::limits::Defaults,
}

/// A lifetime longer than the owner's limit, or "never expires" with a limit.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("the tunnel lifetime is longer than this caller may set")]
pub struct TtlTooLong {
    /// Seconds.
    pub limit: u64,
    /// The machine's user's role; `None` for a service.
    pub account: Option<Role>,
}

/// The current rules for tunnel owner `owner` (a client or service id).
#[derive(Debug, Clone, Copy)]
struct OwnerRules {
    /// May create public previews.
    public: bool,
    /// Longest lifetime in seconds; `None`: unlimited (may never expire).
    ttl_s: Option<u64>,
    /// A service's own live-tunnel quota.
    service_max: Option<u32>,
    /// A machine's user: role and live-tunnel limit across their machines.
    account: Option<(Role, Option<u64>)>,
}

impl OwnerRules {
    /// Whether `expires_at`, set at `at`, is within the lifetime limit.
    fn check_expiry(&self, expires_at: i64, at: i64) -> Result<(), TtlTooLong> {
        let Some(limit) = self.ttl_s else { return Ok(()) };
        if expires_at == NEVER_EXPIRES || expires_at.saturating_sub(at) > i64::try_from(limit).unwrap_or(i64::MAX) {
            return Err(TtlTooLong { limit, account: self.account.map(|(role, _)| role) });
        }
        Ok(())
    }
}

/// `None` if the owner is gone or its user is disabled.
fn owner_rules(tx: &rusqlite::Transaction<'_>, owner: &str, policy: Policy) -> anyhow::Result<Option<OwnerRules>> {
    use crate::limits::{Kind, Setting};
    let service: Option<u32> =
        tx.query_row("SELECT max_tunnels FROM services WHERE id = ?1", params![owner], |r| r.get(0)).optional()?;
    if let Some(max) = service {
        return Ok(Some(OwnerRules {
            public: policy.allow_all_public,
            ttl_s: Some(policy.defaults.max_tunnel_ttl_s),
            service_max: Some(max),
            account: None,
        }));
    }
    let user: Option<(String, bool, Option<i64>, Option<i64>)> = tx
        .query_row(
            "SELECT u.role, u.can_public, u.limit_tunnels, u.limit_tunnel_ttl_s FROM clients c
             JOIN users u ON u.id = c.user_id
             WHERE c.id = ?1 AND u.disabled_at IS NULL",
            params![owner],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    Ok(user.map(|(role, can_public, tunnels, ttl)| {
        let role = Role::parse(&role);
        let d = policy.defaults;
        OwnerRules {
            public: role.is_admin() || can_public || policy.allow_all_public,
            ttl_s: d.resolve(Kind::TunnelTtl, role, Setting::from_column(ttl)),
            service_max: None,
            account: Some((role, d.resolve(Kind::Tunnels, role, Setting::from_column(tunnels)))),
        }
    }))
}

#[derive(Debug, thiserror::Error)]
#[error("access.password is required for password mode")]
pub struct PasswordRequired;

#[derive(Debug, thiserror::Error)]
#[error("public access is not allowed for this caller")]
pub struct PublicNotAllowed;

pub struct TunnelUpdate {
    pub row: TunnelRow,
    pub access_changed: bool,
    pub grants_changed: bool,
}

#[derive(Debug, Clone)]
pub struct NewAccessLink {
    pub id: String,
    pub tunnel_id: String,
    pub token_hash: String,
    pub single_use: bool,
    pub label: Option<String>,
    pub session_ttl_s: i64,
    pub expires_at: i64,
    /// `Some(port)`: an owner link (Open in the web UI) bound to that port.
    pub owner_port: Option<u16>,
}

/// How long after its first use a single-use owner link may be redeemed
/// again, from the same address only. Browsers can send one navigation
/// twice (a retry on a new connection, a duplicated navigation); without
/// this the tab shows the second answer, the sign-in form.
pub const OWNER_LINK_RETRY_S: i64 = 10;

/// A service credential.
#[derive(Debug, Clone)]
pub struct ServiceRow {
    pub name: String,
    pub max_tunnels: u32,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Unexpired tunnels it created.
    pub tunnels: i64,
}

/// An enrolled machine.
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub name: String,
    /// The owning user's name.
    pub user: String,
    /// False until the enrollment code has been redeemed.
    pub enrolled: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Unexpired tunnels it created.
    pub tunnels: i64,
}

/// The machine client behind a `tncli_` token, and its owner.
#[derive(Debug, Clone)]
pub struct ClientAuth {
    pub id: String,
    pub name: String,
    pub user_id: String,
    pub role: Role,
    pub can_public: bool,
    pub limits: crate::limits::Settings,
}

/// Why a new client was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewClientError {
    NameTaken,
    /// The owner is unknown or disabled.
    NoUser,
    /// The user already has as many machines as their limit allows.
    Quota {
        limit: u64,
        role: Role,
    },
}

/// Outcome of redeeming an access link.
#[derive(Debug, Clone)]
pub enum Redemption {
    /// A fresh gate session holding the new grant (plus the grants of any
    /// live session the browser presented). The caller sets the cookie to
    /// `session_id`, the plaintext; only its hash is stored.
    Granted { session_id: String, expires_at: i64 },
    /// Unknown, expired, revoked, already-used, or for another tunnel.
    Invalid,
}

/// A tunnel id's lifecycle state, resolved in one database call.
#[derive(Debug, Clone)]
// Held in an `Arc` by the tunnel cache, so the live row's size costs one
// allocation either way.
#[allow(clippy::large_enum_variant)]
pub enum TunnelLookup {
    Live(TunnelRow),
    Tombstoned,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    AlreadyTombstoned,
    NotFound,
}

#[derive(Debug, Clone, Default)]
pub struct PurgeStats {
    pub tombstones: usize,
    pub access_links: usize,
    pub sessions: usize,
    pub grants: usize,
}

/// Switch to WAL. SQLite does not wait on the busy handler for this switch,
/// so it fails with `SQLITE_BUSY` while another connection opening the same
/// new file holds a lock; retry for up to 5 seconds.
fn enable_wal(conn: &Connection) -> rusqlite::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DatabaseBusy && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            result => return result,
        }
    }
}

/// Every table, index and trigger with its SQL, comments and whitespace
/// dropped (SQLite keeps the text of each `CREATE`, extended by `ALTER TABLE
/// … ADD COLUMN`).
fn schema_shape(c: &Connection) -> rusqlite::Result<Vec<(String, String, String)>> {
    let mut q = c.prepare(
        "SELECT type, name, sql FROM sqlite_schema WHERE substr(name, 1, 7) != 'sqlite_' ORDER BY type, name",
    )?;
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, Option<String>>(2)?)))?;
    rows.map(|r| {
        r.map(|(t, n, sql)| {
            let sql = sql.unwrap_or_default();
            let text: String = sql.lines().map(|l| l.split_once("--").map_or(l, |(code, _)| code)).collect();
            (t, n, text.chars().filter(|c| !c.is_whitespace()).collect())
        })
    })
    .collect()
}

/// The database has exactly the schema this build creates. The version alone
/// would let a build open a database made (or left un-upgraded) by another
/// build with the same version, and read its rows with other meanings.
pub(crate) fn check_schema(c: &Connection) -> anyhow::Result<()> {
    let fresh = Connection::open_in_memory()?;
    fresh.execute_batch(SCHEMA)?;
    let (want, got) = (schema_shape(&fresh)?, schema_shape(c)?);
    if want == got {
        return Ok(());
    }
    let mut differ: Vec<&str> = want.iter().filter(|w| !got.contains(w)).map(|w| w.1.as_str()).collect();
    differ.extend(got.iter().filter(|g| !want.contains(g)).map(|g| g.1.as_str()));
    differ.sort_unstable();
    differ.dedup();
    anyhow::bail!(
        "the database schema differs from this build's ({}): it was made or left by another build; \
         restore a backup made by this build, or upgrade the database as the release notes say",
        differ.join(", ")
    )
}

/// SQLite (bundled with URI support) reads a name starting with `file:` as a
/// URI naming another file than the one this code prepares and checks.
pub(crate) fn ensure_plain_path(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        !path.as_os_str().as_encoded_bytes().starts_with(b"file:"),
        "database path {} must not be a SQLite URI",
        path.display()
    );
    Ok(())
}

/// The database must be a regular file at its path, not a symlink: root CLI
/// commands open it in a data dir the service account owns, and must not be
/// pointed at, or change the mode of, another file.
pub(crate) fn ensure_not_symlink(path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => anyhow::bail!("database path {} must not be a symlink", path.display()),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

/// The database holds token hashes and session ids: create it 0600 before
/// SQLite opens it (SQLite would use the umask) and tighten a looser existing
/// file. SQLite gives new `-wal`/`-shm` files the database's mode, but ones left
/// from a looser database keep theirs, so tighten those too. A user who does
/// not own them cannot; the owner (the server, at start) does.
///
/// Closing a descriptor of the database drops every POSIX lock this process
/// holds on it, including another connection's. The only one opened here is
/// for a file that did not exist (O_EXCL, which also never follows a symlink),
/// closed before any other `Db::open` in this process can reach SQLite
/// (`CREATING`); existing files are changed through O_PATH, which drops no
/// locks, and never through a symlink.
fn make_private(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    static CREATING: Mutex<()> = Mutex::new(());
    ensure_not_symlink(path)?;
    {
        let _creating = CREATING.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
            Ok(file) => file.set_permissions(std::fs::Permissions::from_mode(0o600))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(anyhow::Error::new(e).context(format!("creating {}", path.display()))),
        }
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let file = std::path::PathBuf::from(file);
        match crate::files::set_mode_nofollow(&file, 0o600) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => return Err(anyhow::Error::new(e).context(format!("making {} private", file.display()))),
        }
    }
    Ok(())
}

/// `path` with its directory resolved, so the only symlink SQLite could meet
/// opening it is the file itself, which `open_nofollow` refuses.
fn with_canonical_parent(path: &Path) -> anyhow::Result<std::path::PathBuf> {
    let name = path.file_name().with_context(|| format!("database path {} names no file", path.display()))?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).with_context(|| format!("resolving {}", parent.display()))?;
    Ok(parent.join(name))
}

/// SQLite refuses the database if it is a symlink, so one swapped in after
/// `make_private` checked the path is refused too.
fn open_nofollow(path: &Path) -> anyhow::Result<Connection> {
    let flags = rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Connection::open_with_flags(path, flags).with_context(|| format!("opening {}", path.display()))
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    /// What "Server default" means for per-user limits (from the config).
    defaults: Arc<std::sync::RwLock<crate::limits::Defaults>>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        ensure_plain_path(path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = if path == Path::new(":memory:") {
            Connection::open(path)?
        } else {
            let path = with_canonical_parent(path)?;
            make_private(&path)?;
            open_nofollow(&path)?
        };
        enable_wal(&conn)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let objects: i64 = tx.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if objects == 0 {
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        } else {
            let version: i32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            anyhow::ensure!(
                version == SCHEMA_VERSION,
                "unsupported database schema version {version}; this build needs schema version {SCHEMA_VERSION}"
            );
            check_schema(&tx)?;
        }
        tx.commit()?;
        let defaults = crate::limits::Defaults::new(&crate::config::Limits::default());
        Ok(Self { conn: Arc::new(Mutex::new(conn)), defaults: Arc::new(std::sync::RwLock::new(defaults)) })
    }

    /// Open the configured database, with the configured limit defaults.
    pub fn open_configured(cfg: &crate::config::Config) -> anyhow::Result<Self> {
        let db = Self::open(&cfg.db_path())?;
        db.set_limit_defaults(crate::limits::Defaults::new(&cfg.limits));
        Ok(db)
    }

    pub fn set_limit_defaults(&self, defaults: crate::limits::Defaults) {
        *self.defaults.write().unwrap_or_else(std::sync::PoisonError::into_inner) = defaults;
    }

    pub fn limit_defaults(&self) -> crate::limits::Defaults {
        *self.defaults.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Run `f` with the connection on a blocking thread.
    pub async fn call<F, R>(&self, f: F) -> anyhow::Result<R>
    where
        F: FnOnce(&mut Connection) -> anyhow::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
            f(&mut guard)
        })
        .await?
    }

    // ---------------------------------------------------------------- tunnels

    /// True if `id` is used by a live tunnel or a tombstone (ids are never reused).
    pub async fn id_taken(&self, id: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let n: i64 = c.query_row(
                "SELECT (SELECT COUNT(*) FROM tunnels WHERE id = ?1) + (SELECT COUNT(*) FROM tombstones WHERE id = ?1)",
                params![id],
                |r| r.get(0),
            )?;
            Ok(n > 0)
        })
        .await
    }

    /// `None` if `t.client_id` names an owner (client or service) that no
    /// longer exists (deleted after the request authenticated). The owner
    /// existence and live-tunnel quota checks share the INSERT's write
    /// transaction, including across connections. Clients are limited by
    /// `max_tunnels_per_client` and their user's limit across all their
    /// machines, services by their own `max_tunnels`; admin-owned tunnels are
    /// not limited.
    #[cfg(test)]
    pub async fn create_tunnel(&self, t: NewTunnel, max_tunnels_per_client: u32) -> anyhow::Result<Option<TunnelRow>> {
        let defaults = crate::limits::Defaults::new(&crate::config::Limits {
            max_tunnel_ttl_s: crate::limits::MAX_TTL_S,
            member_max_tunnel_ttl_s: crate::limits::MAX_TTL_S,
            ..Default::default()
        });
        let unrestricted = Policy { allow_all_public: true, defaults };
        self.create_tunnel_with(t, max_tunnels_per_client, unrestricted).await
    }

    /// [`Db::create_tunnel`], with the owner's current public and lifetime
    /// rules checked in the same transaction (errors `PublicNotAllowed`,
    /// `TtlTooLong`).
    pub async fn create_tunnel_with(
        &self,
        t: NewTunnel,
        max_tunnels_per_client: u32,
        policy: Policy,
    ) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let created = now();
            let mut user_id = None;
            if let Some(owner) = &t.client_id {
                // The owner was deleted (or its user disabled) meanwhile.
                let Some(rules) = owner_rules(&tx, owner, policy)? else { return Ok(None) };
                if t.access.mode == AccessMode::Public && !rules.public {
                    return Err(PublicNotAllowed.into());
                }
                rules.check_expiry(t.expires_at, created)?;
                let live: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE client_id = ?1 AND expires_at > ?2",
                    params![owner, created],
                    |r| r.get(0),
                )?;
                match rules.service_max {
                    Some(limit) if live >= i64::from(limit) => {
                        return Err(TunnelQuotaExceeded::Service { limit }.into());
                    }
                    None if live >= i64::from(max_tunnels_per_client) => {
                        return Err(TunnelQuotaExceeded::Machine { limit: max_tunnels_per_client }.into());
                    }
                    _ => {}
                }
                if rules.account.is_some() {
                    user_id = Some(
                        tx.query_row("SELECT user_id FROM clients WHERE id = ?1", params![owner], |r| {
                            r.get::<_, String>(0)
                        })?,
                    );
                }
                // The user's limit covers the tunnels of all their machines.
                if let (Some((role, Some(limit))), Some(user)) = (rules.account, &user_id) {
                    let across: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM tunnels t JOIN clients c ON c.id = t.client_id
                         WHERE c.user_id = ?1 AND t.expires_at > ?2",
                        params![user, created],
                        |r| r.get(0),
                    )?;
                    if across.max(0) as u64 >= limit {
                        return Err(TunnelQuotaExceeded::Account { limit, role }.into());
                    }
                }
            }
            let metadata = t.metadata.as_ref().map(|m| m.to_string());
            tx.execute(
                "INSERT INTO tunnels (id, token_hash, label, metadata, max_ports, host_header, inject_ice, created_at, expires_at,
                                      access_mode, password_user, password_hash, client_id, name)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    t.id,
                    t.token_hash,
                    t.label,
                    metadata,
                    t.max_ports,
                    t.host_header.as_str(),
                    t.inject_ice,
                    created,
                    t.expires_at,
                    t.access.mode.as_str(),
                    t.access.password_user,
                    t.access.password_hash,
                    t.client_id,
                    t.name,
                ],
            )?;
            tx.commit()?;
            Ok(Some(TunnelRow {
                id: t.id,
                label: t.label,
                name: t.name,
                metadata: t.metadata,
                max_ports: t.max_ports,
                host_header: t.host_header,
                inject_ice: t.inject_ice,
                created_at: created,
                expires_at: t.expires_at,
                last_seen_at: None,
                access: t.access,
                client_id: t.client_id,
                user_id,
                bytes_in: 0,
                bytes_out: 0,
            }))
        })
        .await
    }

    pub async fn get_tunnel(&self, id: String) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            Ok(c.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?)
        })
        .await
    }

    /// Live row (possibly expired; callers check `is_expired()`), tombstone, or neither.
    pub async fn lookup_tunnel(&self, id: String) -> anyhow::Result<TunnelLookup> {
        self.call(move |c| {
            let row =
                c.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?;
            if let Some(row) = row {
                return Ok(TunnelLookup::Live(row));
            }
            let tomb: i64 = c.query_row("SELECT COUNT(*) FROM tombstones WHERE id = ?1", params![id], |r| r.get(0))?;
            Ok(if tomb > 0 { TunnelLookup::Tombstoned } else { TunnelLookup::Unknown })
        })
        .await
    }

    pub async fn find_tunnel_by_token_hash(&self, hash: String) -> anyhow::Result<Option<TunnelRow>> {
        self.call(move |c| {
            Ok(c.query_row(&format!("{TUNNEL_SELECT} WHERE token_hash = ?1"), params![hash], tunnel_from_row)
                .optional()?)
        })
        .await
    }

    /// Ascending id keyset page; owner-scoped pages use tunnels_client_id.
    /// `label` matches exactly. Fetch one extra row so the API can detect
    /// whether another page exists.
    pub async fn list_tunnels_page(
        &self,
        client_id: Option<String>,
        label: Option<String>,
        cursor: Option<String>,
        limit: u32,
    ) -> anyhow::Result<Vec<TunnelRow>> {
        self.call(move |c| {
            let mut sql = TUNNEL_SELECT.to_string();
            let mut values = Vec::<Value>::new();
            let mut predicates = Vec::new();
            if let Some(id) = client_id {
                values.push(Value::Text(id));
                predicates.push(format!("client_id = ?{}", values.len()));
            }
            if let Some(label) = label {
                values.push(Value::Text(label));
                predicates.push(format!("label = ?{}", values.len()));
            }
            if let Some(cursor) = cursor {
                values.push(Value::Text(cursor));
                predicates.push(format!("id > ?{}", values.len()));
            }
            if !predicates.is_empty() {
                sql.push_str(&format!(" WHERE {}", predicates.join(" AND ")));
            }
            values.push(Value::Integer(i64::from(limit) + 1));
            sql.push_str(&format!(" ORDER BY id LIMIT ?{}", values.len()));
            let mut stmt = c.prepare(&sql)?;
            Ok(stmt.query_map(params_from_iter(values), tunnel_from_row)?.collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    pub async fn update_tunnel(&self, id: String, patch: TunnelPatch) -> anyhow::Result<Option<TunnelUpdate>> {
        self.call(move |c| {
            let tx = c.transaction()?;
            // Re-checked inside the transaction: the caller's expiry check can
            // race the sweep or a client delete, and expiry is revocation.
            let current =
                tx.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?;
            let Some(current) = current.filter(|row| !row.is_expired()) else { return Ok(None) };
            let mut access_changed = false;
            let mut grants_changed = false;
            let rules = match &patch.owner_policy {
                Some((owner, policy)) => match owner_rules(&tx, owner, *policy)? {
                    Some(rules) => Some(rules),
                    // The machine was removed or its user disabled meanwhile.
                    None => return Ok(None),
                },
                None => None,
            };
            if let Some(v) = patch.expires_at {
                if let Some(rules) = &rules {
                    rules.check_expiry(v, now())?;
                }
                tx.execute("UPDATE tunnels SET expires_at = ?2 WHERE id = ?1", params![id, v])?;
            }
            if let Some(v) = &patch.label {
                tx.execute("UPDATE tunnels SET label = ?2 WHERE id = ?1", params![id, v])?;
            }
            if let Some(v) = &patch.name {
                tx.execute("UPDATE tunnels SET name = ?2 WHERE id = ?1", params![id, v])?;
            }
            if let Some(v) = patch.host_header {
                tx.execute("UPDATE tunnels SET host_header = ?2 WHERE id = ?1", params![id, v.as_str()])?;
            }
            if let Some(v) = patch.inject_ice {
                tx.execute("UPDATE tunnels SET inject_ice = ?2 WHERE id = ?1", params![id, v])?;
            }
            if let Some(mut access) = patch.access {
                let may_public = rules.is_none_or(|r| r.public);
                if !may_public && access.mode == AccessMode::Public && current.access.mode != AccessMode::Public {
                    return Err(PublicNotAllowed.into());
                }
                if patch.keep_password_hash && access.mode == AccessMode::Password {
                    access.password_hash = Some(current.access.password_hash.clone().ok_or(PasswordRequired)?);
                }
                access_changed = access != current.access;
                grants_changed =
                    access.mode != current.access.mode || access.password_hash != current.access.password_hash;
                tx.execute(
                    "UPDATE tunnels SET access_mode = ?2, password_user = ?3, password_hash = ?4 WHERE id = ?1",
                    params![id, access.mode.as_str(), access.password_user, access.password_hash],
                )?;
                // A new password (or none) ends every session the old one opened.
                if current.access.password_hash != access.password_hash {
                    revoke_login_grants(&tx, &id)?;
                }
            }
            let row =
                tx.query_row(&format!("{TUNNEL_SELECT} WHERE id = ?1"), params![id], tunnel_from_row).optional()?;
            tx.commit()?;
            Ok(row.map(|row| TunnelUpdate { row, access_changed, grants_changed }))
        })
        .await
    }

    pub async fn touch_last_seen(&self, id: String) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute("UPDATE tunnels SET last_seen_at = ?2 WHERE id = ?1", params![id, now()])?;
            Ok(())
        })
        .await
    }

    pub async fn is_tombstoned(&self, id: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let n: i64 = c.query_row("SELECT COUNT(*) FROM tombstones WHERE id = ?1", params![id], |r| r.get(0))?;
            Ok(n > 0)
        })
        .await
    }

    /// Hard-delete the tunnel, its token, links, and grants (FK cascades),
    /// delete gate sessions left without grants, insert a tombstone. One transaction.
    pub async fn delete_tunnel(&self, id: String) -> anyhow::Result<DeleteOutcome> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let n = tx.execute("DELETE FROM tunnels WHERE id = ?1", params![id])?;
            if n == 0 {
                let tomb: i64 =
                    tx.query_row("SELECT COUNT(*) FROM tombstones WHERE id = ?1", params![id], |r| r.get(0))?;
                tx.commit()?;
                return Ok(if tomb > 0 { DeleteOutcome::AlreadyTombstoned } else { DeleteOutcome::NotFound });
            }
            tx.execute("INSERT OR REPLACE INTO tombstones (id, deleted_at) VALUES (?1, ?2)", params![id, now()])?;
            tx.execute("DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)", [])?;
            tx.commit()?;
            Ok(DeleteOutcome::Deleted)
        })
        .await
    }

    /// Ids of tunnels whose TTL has elapsed (the purge job deletes them via the
    /// same path as the API so live connections are closed too).
    pub async fn expired_tunnel_ids(&self) -> anyhow::Result<Vec<String>> {
        self.call(|c| {
            let mut stmt = c.prepare("SELECT id FROM tunnels WHERE expires_at <= ?1")?;
            let ids = stmt.query_map(params![now()], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
            Ok(ids)
        })
        .await
    }

    // ----------------------------------------------------------- access links

    pub async fn create_access_link(&self, l: NewAccessLink) -> anyhow::Result<()> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO access_links (id, tunnel_id, token_hash, single_use, label, session_ttl_s, created_at, expires_at, kind, port)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    l.id,
                    l.tunnel_id,
                    l.token_hash,
                    l.single_use,
                    l.label,
                    l.session_ttl_s,
                    now(),
                    l.expires_at,
                    if l.owner_port.is_some() { "owner" } else { "visitor" },
                    l.owner_port,
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Revoke a link: delete every grant it contributed to, the link, and
    /// sessions left without grants. Returns `false` if no such link.
    pub async fn delete_access_link(&self, id: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            let tx = c.transaction()?;
            tx.execute(
                "DELETE FROM gate_grants WHERE EXISTS (
                     SELECT 1 FROM gate_grant_links l
                     WHERE l.link_id = ?1 AND l.session_hash = gate_grants.session_hash
                       AND l.tunnel_id = gate_grants.tunnel_id)",
                params![id],
            )?;
            let n = tx.execute("DELETE FROM access_links WHERE id = ?1", params![id])?;
            tx.execute("DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)", [])?;
            tx.commit()?;
            Ok(n > 0)
        })
        .await
    }

    /// Redeem `token_hash` for `tunnel_id`. Always mints a fresh session: a
    /// presented cookie value may have been tossed by preview JS, so the new
    /// grant is never attached to it. The unexpired grants of every live
    /// session in `presented_session_hashes` are copied into the new session
    /// (tossing could already give the browser those), which keeps one cookie
    /// covering every tunnel the visitor holds. Single-use links are consumed
    /// in the same transaction as the grant.
    /// Redeem an access link reached through `port` (`None`: the URL named
    /// no port) by a visitor whose address hashes to `peer`. Owner links work
    /// only through their own port and, once used, again only from the same
    /// address within [`OWNER_LINK_RETRY_S`].
    pub async fn redeem_access_link(
        &self,
        tunnel_id: String,
        token_hash: String,
        presented_session_hashes: Vec<String>,
        port: Option<u16>,
        peer: String,
    ) -> anyhow::Result<Redemption> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            type LinkRow = (String, bool, Option<i64>, i64, i64, String, Option<u16>, Option<String>);
            let link: Option<LinkRow> = tx
                .query_row(
                    "SELECT id, single_use, used_at, session_ttl_s, expires_at, kind, port, used_from FROM access_links
                     WHERE token_hash = ?1 AND tunnel_id = ?2",
                    params![token_hash, tunnel_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
                )
                .optional()?;
            let Some((link_id, single_use, used_at, session_ttl_s, link_expires, kind, link_port, used_from)) = link
            else {
                return Ok(Redemption::Invalid);
            };
            let owner = kind == "owner";
            if link_expires <= t || (owner && (link_port.is_none() || link_port != port)) {
                return Ok(Redemption::Invalid);
            }
            let repeat = match used_at {
                Some(_) if !single_use => false,
                None => false,
                Some(used) => {
                    let retry = owner && used_from.as_deref() == Some(peer.as_str()) && t - used <= OWNER_LINK_RETRY_S;
                    if !retry {
                        return Ok(Redemption::Invalid);
                    }
                    true
                }
            };
            let tunnel_expires: Option<i64> = tx
                .query_row("SELECT expires_at FROM tunnels WHERE id = ?1", params![tunnel_id], |r| r.get(0))
                .optional()?;
            if tunnel_expires.is_none_or(|e| e <= t) {
                return Ok(Redemption::Invalid);
            }
            if single_use && !repeat {
                let n = tx.execute(
                    "UPDATE access_links SET used_at = ?2, used_from = ?3 WHERE id = ?1 AND used_at IS NULL",
                    params![link_id, t, owner.then_some(&peer)],
                )?;
                if n != 1 {
                    return Ok(Redemption::Invalid);
                }
            }
            // Not capped by the tunnel's expiry: the edge enforces that live,
            // so a later `PATCH` extending the tunnel keeps visitors signed in.
            let (session_id, session_hash) =
                mint_session(&tx, &tunnel_id, &presented_session_hashes, t, t + session_ttl_s)?;
            tx.execute(
                "INSERT INTO gate_grant_links (session_hash, tunnel_id, link_id, expires_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_hash, tunnel_id, link_id) DO UPDATE SET
                   expires_at = MAX(gate_grant_links.expires_at, excluded.expires_at)",
                params![session_hash, tunnel_id, link_id, t + session_ttl_s],
            )?;
            let expires_at = finish_session(&tx, &session_hash)?;
            tx.commit()?;
            Ok(Redemption::Granted { session_id, expires_at })
        })
        .await
    }

    /// A successful password login: a fresh session (carrying the presented
    /// sessions' grants, like a link redemption) with a grant for `tunnel_id`
    /// recorded as login-derived. `None` if the tunnel is gone, expired, or no
    /// longer in password mode with exactly `password_hash` (a concurrent
    /// password change wins over a login checked against the old one).
    pub async fn login_grant(
        &self,
        tunnel_id: String,
        password_hash: String,
        session_ttl_s: i64,
        presented_session_hashes: Vec<String>,
    ) -> anyhow::Result<Option<Redemption>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let current: Option<(i64, String, Option<String>)> = tx
                .query_row(
                    "SELECT expires_at, access_mode, password_hash FROM tunnels WHERE id = ?1",
                    params![tunnel_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match current {
                Some((expires, mode, Some(hash)))
                    if expires > t && AccessMode::parse(&mode) == AccessMode::Password && hash == password_hash => {}
                _ => return Ok(None),
            }
            let (session_id, session_hash) =
                mint_session(&tx, &tunnel_id, &presented_session_hashes, t, t + session_ttl_s)?;
            tx.execute(
                "INSERT OR IGNORE INTO gate_grant_logins (session_hash, tunnel_id, expires_at) VALUES (?1, ?2, ?3)",
                params![session_hash, tunnel_id, t + session_ttl_s],
            )?;
            let expires_at = finish_session(&tx, &session_hash)?;
            tx.commit()?;
            Ok(Some(Redemption::Granted { session_id, expires_at }))
        })
        .await
    }

    /// Unexpired `(tunnel_id, grant_expires_at)` pairs for each of
    /// `session_hashes` that is a live session with at least one grant, in
    /// one query. Hashes with nothing live are absent from the map.
    pub async fn session_grants(
        &self,
        session_hashes: Vec<String>,
    ) -> anyhow::Result<HashMap<String, Vec<(String, i64)>>> {
        if session_hashes.is_empty() {
            return Ok(HashMap::new());
        }
        self.call(move |c| {
            let placeholders = (0..session_hashes.len()).map(|i| format!("?{}", i + 2)).collect::<Vec<_>>().join(",");
            let mut stmt = c.prepare(&format!(
                "SELECT g.session_hash, g.tunnel_id, g.expires_at FROM gate_grants g
                 JOIN gate_sessions s ON s.id_hash = g.session_hash
                 WHERE g.session_hash IN ({placeholders}) AND s.expires_at > ?1 AND g.expires_at > ?1"
            ))?;
            let mut values = Vec::with_capacity(session_hashes.len() + 1);
            values.push(Value::Integer(now()));
            values.extend(session_hashes.into_iter().map(Value::Text));
            let mut out: HashMap<String, Vec<(String, i64)>> = HashMap::new();
            let mut rows = stmt.query(params_from_iter(values.iter()))?;
            while let Some(r) = rows.next()? {
                out.entry(r.get(0)?).or_default().push((r.get(1)?, r.get(2)?));
            }
            Ok(out)
        })
        .await
    }

    // ---------------------------------------------------------------- clients

    /// New client `name` owned by `user_id`, with a one-time enrollment code
    /// (hash stored) valid until `code_expires_at`.
    pub async fn create_client(
        &self,
        id: String,
        name: String,
        user_id: String,
        code_hash: String,
        code_expires_at: i64,
        session: Option<String>,
    ) -> anyhow::Result<Result<ClientRow, NewClientError>> {
        let defaults = self.limit_defaults();
        self.call(move |c| {
            let t = now();
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // From the web UI: only while the requesting session is still valid.
            if let Some(session) = &session
                && !authorized(&tx, &user_id, None, session)?
            {
                return Ok(Err(NewClientError::NoUser));
            }
            if let Err(e) = client_admissible(&tx, &name, &user_id, defaults)? {
                return Ok(Err(e));
            }
            tx.execute(
                "INSERT INTO clients (id, name, created_at, user_id) VALUES (?1, ?2, ?3, ?4)",
                params![id, name, t, user_id],
            )?;
            tx.execute(
                "INSERT INTO client_enrollments (code_hash, client_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![code_hash, id, t, code_expires_at],
            )?;
            let user: String =
                tx.query_row("SELECT username FROM users WHERE id = ?1", params![user_id], |r| r.get(0))?;
            tx.commit()?;
            Ok(Ok(ClientRow { name, user, enrolled: false, created_at: t, last_used_at: None, tunnels: 0 }))
        })
        .await
    }

    /// Redeem an enrollment code: single use, unexpired. Sets the client's token
    /// hash (replacing any earlier token) and returns the client's name.
    pub async fn enroll_client(&self, code_hash: String, token_hash: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let found: Option<(String, String)> = tx
                .query_row(
                    "SELECT e.client_id, c.name FROM client_enrollments e JOIN clients c ON c.id = e.client_id
                     WHERE e.code_hash = ?1 AND e.used_at IS NULL AND e.expires_at > ?2",
                    params![code_hash, t],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((client_id, name)) = found else {
                return Ok(None);
            };
            let n = tx.execute(
                "UPDATE client_enrollments SET used_at = ?2 WHERE code_hash = ?1 AND used_at IS NULL",
                params![code_hash, t],
            )?;
            if n != 1 {
                return Ok(None);
            }
            tx.execute(
                "UPDATE clients SET token_hash = ?2, last_used_at = ?3 WHERE id = ?1",
                params![client_id, token_hash, t],
            )?;
            tx.commit()?;
            Ok(Some(name))
        })
        .await
    }

    /// The client holding `token_hash` (its owner enabled), recording use at
    /// most once a minute.
    /// A user's machines and live tunnels across them.
    pub async fn user_usage(&self, user_id: String) -> anyhow::Result<(u64, u64)> {
        self.call(move |c| {
            let (machines, tunnels): (i64, i64) = c.query_row(
                "SELECT (SELECT COUNT(*) FROM clients WHERE user_id = ?1),
                        (SELECT COUNT(*) FROM tunnels t JOIN clients c ON c.id = t.client_id
                         WHERE c.user_id = ?1 AND t.expires_at > ?2)",
                params![user_id, now()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok((machines.max(0) as u64, tunnels.max(0) as u64))
        })
        .await
    }

    pub async fn client_by_token_hash(&self, token_hash: String) -> anyhow::Result<Option<ClientAuth>> {
        self.call(move |c| {
            let t = now();
            let found = c
                .query_row(
                    "SELECT c.id, c.name, u.id, u.role, u.can_public,
                            u.limit_tunnels, u.limit_clients, u.limit_tunnel_ttl_s, u.limit_traffic_bytes
                     FROM clients c JOIN users u ON u.id = c.user_id
                     WHERE c.token_hash = ?1 AND u.disabled_at IS NULL",
                    params![token_hash],
                    |r| {
                        use crate::limits::Setting;
                        Ok(ClientAuth {
                            id: r.get(0)?,
                            name: r.get(1)?,
                            user_id: r.get(2)?,
                            role: Role::parse(&r.get::<_, String>(3)?),
                            can_public: r.get(4)?,
                            limits: crate::limits::Settings {
                                tunnels: Setting::from_column(r.get(5)?),
                                machines: Setting::from_column(r.get(6)?),
                                tunnel_ttl_s: Setting::from_column(r.get(7)?),
                                traffic_bytes: Setting::from_column(r.get(8)?),
                            },
                        })
                    },
                )
                .optional()?;
            if let Some(found) = &found {
                c.execute(
                    "UPDATE clients SET last_used_at = ?2 WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 60)",
                    params![found.id, t],
                )?;
            }
            Ok(found)
        })
        .await
    }

    /// Ascending name keyset page, using clients' unique name index.
    pub async fn list_clients_page(&self, cursor: Option<String>, limit: u32) -> anyhow::Result<Vec<ClientRow>> {
        self.call(move |c| {
            let predicate = if cursor.is_some() { "WHERE c.name > ?3" } else { "" };
            let mut stmt = c.prepare(&format!(
                "SELECT c.name, c.token_hash IS NOT NULL, c.created_at, c.last_used_at,
                        (SELECT COUNT(*) FROM tunnels t WHERE t.client_id = c.id AND t.expires_at > ?1), u.username
                 FROM clients c JOIN users u ON u.id = c.user_id {predicate} ORDER BY c.name LIMIT ?2"
            ))?;
            let mut values = vec![Value::Integer(now()), Value::Integer(i64::from(limit) + 1)];
            if let Some(cursor) = cursor {
                values.push(Value::Text(cursor));
            }
            Ok(stmt
                .query_map(params_from_iter(values), |r| {
                    Ok(ClientRow {
                        name: r.get(0)?,
                        enrolled: r.get(1)?,
                        created_at: r.get(2)?,
                        last_used_at: r.get(3)?,
                        tunnels: r.get(4)?,
                        user: r.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    pub async fn list_clients(&self) -> anyhow::Result<Vec<ClientRow>> {
        self.call(|c| {
            let mut stmt = c.prepare(
                "SELECT c.name, c.token_hash IS NOT NULL, c.created_at, c.last_used_at,
                        (SELECT COUNT(*) FROM tunnels t WHERE t.client_id = c.id AND t.expires_at > ?1), u.username
                 FROM clients c JOIN users u ON u.id = c.user_id ORDER BY c.name",
            )?;
            let rows = stmt
                .query_map(params![now()], |r| {
                    Ok(ClientRow {
                        name: r.get(0)?,
                        enrolled: r.get(1)?,
                        created_at: r.get(2)?,
                        last_used_at: r.get(3)?,
                        tunnels: r.get(4)?,
                        user: r.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
    }

    /// Delete client `name` (its token and pending codes go with it) and
    /// expire its tunnels so they stop serving at once. Returns the tunnel
    /// ids so a running server can close them right away; otherwise the
    /// expiry sweep does. `None` if there is no such client.
    pub async fn delete_client(&self, name: String) -> anyhow::Result<Option<Vec<String>>> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let id: Option<String> =
                tx.query_row("SELECT id FROM clients WHERE name = ?1", params![name], |r| r.get(0)).optional()?;
            let Some(id) = id else {
                return Ok(None);
            };
            let tunnels = expire_owner_tunnels(&tx, &id)?;
            tx.execute("DELETE FROM clients WHERE id = ?1", params![id])?;
            tx.commit()?;
            Ok(Some(tunnels))
        })
        .await
    }

    // --------------------------------------------------------------- services

    /// New service `name` holding `token_hash`. `None` if the name is taken.
    pub async fn create_service(
        &self,
        id: String,
        name: String,
        token_hash: String,
        max_tunnels: u32,
    ) -> anyhow::Result<Option<ServiceRow>> {
        self.call(move |c| {
            let t = now();
            let inserted = c.execute(
                "INSERT INTO services (id, name, token_hash, max_tunnels, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(name) DO NOTHING",
                params![id, name, token_hash, max_tunnels, t],
            )?;
            Ok((inserted == 1).then_some(ServiceRow {
                name,
                max_tunnels,
                created_at: t,
                last_used_at: None,
                tunnels: 0,
            }))
        })
        .await
    }

    /// The service holding `token_hash`, recording use at most once a minute.
    pub async fn service_by_token_hash(&self, token_hash: String) -> anyhow::Result<Option<(String, String)>> {
        self.call(move |c| {
            let t = now();
            let found: Option<(String, String)> = c
                .query_row("SELECT id, name FROM services WHERE token_hash = ?1", params![token_hash], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            if let Some((id, _)) = &found {
                c.execute(
                    "UPDATE services SET last_used_at = ?2 WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 60)",
                    params![id, t],
                )?;
            }
            Ok(found)
        })
        .await
    }

    /// Ascending name keyset page (all services when `limit` is `None`).
    pub async fn list_services(&self, cursor: Option<String>, limit: Option<u32>) -> anyhow::Result<Vec<ServiceRow>> {
        self.call(move |c| {
            let mut values = vec![Value::Integer(now())];
            let mut sql = "SELECT s.name, s.max_tunnels, s.created_at, s.last_used_at,
                        (SELECT COUNT(*) FROM tunnels t WHERE t.client_id = s.id AND t.expires_at > ?1)
                 FROM services s"
                .to_string();
            if let Some(cursor) = cursor {
                values.push(Value::Text(cursor));
                sql.push_str(&format!(" WHERE s.name > ?{}", values.len()));
            }
            sql.push_str(" ORDER BY s.name");
            if let Some(limit) = limit {
                values.push(Value::Integer(i64::from(limit) + 1));
                sql.push_str(&format!(" LIMIT ?{}", values.len()));
            }
            let mut stmt = c.prepare(&sql)?;
            Ok(stmt
                .query_map(params_from_iter(values), |r| {
                    Ok(ServiceRow {
                        name: r.get(0)?,
                        max_tunnels: r.get(1)?,
                        created_at: r.get(2)?,
                        last_used_at: r.get(3)?,
                        tunnels: r.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
    }

    /// Set a service's live-tunnel quota. Tunnels above a lowered quota keep
    /// running; new ones are refused until the count drops below it.
    pub async fn set_service_quota(&self, name: String, max_tunnels: u32) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.execute("UPDATE services SET max_tunnels = ?2 WHERE name = ?1", params![name, max_tunnels])? == 1)
        })
        .await
    }

    /// Replace a service's token; the old one stops working at once.
    pub async fn rotate_service_token(&self, name: String, token_hash: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.execute("UPDATE services SET token_hash = ?2 WHERE name = ?1", params![name, token_hash])? == 1)
        })
        .await
    }

    /// Delete service `name` and expire its tunnels (see [`Db::delete_client`]).
    pub async fn delete_service(&self, name: String) -> anyhow::Result<Option<Vec<String>>> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let id: Option<String> =
                tx.query_row("SELECT id FROM services WHERE name = ?1", params![name], |r| r.get(0)).optional()?;
            let Some(id) = id else {
                return Ok(None);
            };
            let tunnels = expire_owner_tunnels(&tx, &id)?;
            tx.execute("DELETE FROM services WHERE id = ?1", params![id])?;
            tx.commit()?;
            Ok(Some(tunnels))
        })
        .await
    }

    /// Current token hash and expiry of tunnel `id`; `None` once it is deleted.
    pub async fn tunnel_token_state(&self, id: String) -> anyhow::Result<Option<(String, i64)>> {
        self.call(move |c| {
            Ok(c.query_row("SELECT token_hash, expires_at FROM tunnels WHERE id = ?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
        })
        .await
    }

    /// Replace an unexpired tunnel's token. `false` if the tunnel is missing or expired.
    pub async fn rotate_tunnel_token(&self, id: String, token_hash: String) -> anyhow::Result<bool> {
        self.call(move |c| {
            Ok(c.execute(
                "UPDATE tunnels SET token_hash = ?2 WHERE id = ?1 AND expires_at > ?3",
                params![id, token_hash, now()],
            )? == 1)
        })
        .await
    }

    /// The tunnel an access link belongs to.
    pub async fn access_link_tunnel(&self, link_id: String) -> anyhow::Result<Option<String>> {
        self.call(move |c| {
            Ok(c.query_row("SELECT tunnel_id FROM access_links WHERE id = ?1", params![link_id], |r| r.get(0))
                .optional()?)
        })
        .await
    }

    // ------------------------------------------------------------------ purge

    /// Remove tombstones older than `tombstone_retention_s`, expired grants,
    /// expired or grant-less sessions, and expired access links that no live
    /// grant came from. A link outlives its expiry while its grants live, so
    /// revoking it still revokes them and routine expiry never logs anyone out.
    pub async fn purge(&self, tombstone_retention_s: i64) -> anyhow::Result<PurgeStats> {
        self.call(move |c| {
            let t = now();
            let tx = c.transaction()?;
            let tombstones =
                tx.execute("DELETE FROM tombstones WHERE deleted_at <= ?1", params![t - tombstone_retention_s])?;
            let grants = tx.execute("DELETE FROM gate_grants WHERE expires_at <= ?1", params![t])?;
            let sessions = tx.execute(
                "DELETE FROM gate_sessions WHERE expires_at <= ?1
                   OR id_hash NOT IN (SELECT session_hash FROM gate_grants)",
                params![t],
            )?;
            let access_links = tx.execute(
                "DELETE FROM access_links WHERE expires_at <= ?1
                   AND NOT EXISTS (SELECT 1 FROM gate_grant_links l WHERE l.link_id = access_links.id)",
                params![t],
            )?;
            tx.commit()?;
            Ok(PurgeStats { tombstones, access_links, sessions, grants })
        })
        .await
    }

    // ----------------------------------------------------------------- admin

    pub async fn backup_to(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        ensure_plain_path(&path)?;
        self.call(move |c| {
            c.execute("VACUUM INTO ?1", params![path.to_string_lossy()])?;
            Ok(())
        })
        .await
    }

    /// `(tunnels, tombstones, access_links, gate_sessions)` counts for `status`.
    pub async fn counts(&self) -> anyhow::Result<(i64, i64, i64, i64)> {
        self.call(|c| {
            Ok(c.query_row(
                "SELECT (SELECT COUNT(*) FROM tunnels), (SELECT COUNT(*) FROM tombstones),
                        (SELECT COUNT(*) FROM access_links), (SELECT COUNT(*) FROM gate_sessions)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?)
        })
        .await
    }
}

pub(crate) const TUNNEL_SELECT: &str = "SELECT id, label, metadata, max_ports, host_header, inject_ice, created_at, expires_at, last_seen_at, access_mode, password_user, password_hash, client_id, bytes_in, bytes_out, (SELECT user_id FROM clients WHERE clients.id = tunnels.client_id), name FROM tunnels";
/// Columns `tunnel_from_row` reads (others may follow).
pub(crate) const TUNNEL_COLUMNS: usize = 17;

/// Fresh session for a new grant on `tunnel_id`, carrying the unexpired grants
/// (and their provenance) of every live presented session. Returns the
/// plaintext session id and its hash; the caller records the new grant's
/// provenance and then calls [`finish_session`].
fn mint_session(
    tx: &rusqlite::Transaction<'_>,
    tunnel_id: &str,
    presented_session_hashes: &[String],
    t: i64,
    grant_expires: i64,
) -> anyhow::Result<(String, String)> {
    let session_id = crate::tokens::random_secret();
    let session_hash = crate::tokens::hash_token(&session_id);
    tx.execute(
        "INSERT INTO gate_sessions (id_hash, created_at, expires_at) VALUES (?1, ?2, ?3)",
        params![session_hash, t, grant_expires],
    )?;
    {
        let mut copy_grants = tx.prepare(
            "INSERT INTO gate_grants (session_hash, tunnel_id, expires_at)
             SELECT ?1, g.tunnel_id, g.expires_at FROM gate_grants g
             JOIN gate_sessions s ON s.id_hash = g.session_hash
             WHERE g.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3
             ON CONFLICT(session_hash, tunnel_id) DO UPDATE SET
               expires_at = MAX(gate_grants.expires_at, excluded.expires_at)",
        )?;
        // Provenance follows the copy so revoking the original link (or
        // changing the password) also revokes the carried-over grant.
        let mut copy_links = tx.prepare(
            "INSERT INTO gate_grant_links (session_hash, tunnel_id, link_id, expires_at)
             SELECT ?1, l.tunnel_id, l.link_id, l.expires_at FROM gate_grant_links l
             JOIN gate_grants g ON g.session_hash = l.session_hash AND g.tunnel_id = l.tunnel_id
             JOIN gate_sessions s ON s.id_hash = l.session_hash
             WHERE l.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3
             ON CONFLICT(session_hash, tunnel_id, link_id) DO UPDATE SET
               expires_at = MAX(gate_grant_links.expires_at, excluded.expires_at)",
        )?;
        let mut copy_logins = tx.prepare(
            "INSERT INTO gate_grant_logins (session_hash, tunnel_id, expires_at)
             SELECT ?1, l.tunnel_id, l.expires_at FROM gate_grant_logins l
             JOIN gate_grants g ON g.session_hash = l.session_hash AND g.tunnel_id = l.tunnel_id
             JOIN gate_sessions s ON s.id_hash = l.session_hash
             WHERE l.session_hash = ?2 AND s.expires_at > ?3 AND g.expires_at > ?3
             ON CONFLICT(session_hash, tunnel_id) DO UPDATE SET
               expires_at = MAX(gate_grant_logins.expires_at, excluded.expires_at)",
        )?;
        let mut seen: Vec<&String> = Vec::new();
        for h in presented_session_hashes {
            if seen.contains(&h) || *h == session_hash {
                continue;
            }
            seen.push(h);
            copy_grants.execute(params![session_hash, h, t])?;
            copy_links.execute(params![session_hash, h, t])?;
            copy_logins.execute(params![session_hash, h, t])?;
        }
    }
    tx.execute(
        "INSERT INTO gate_grants (session_hash, tunnel_id, expires_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(session_hash, tunnel_id) DO UPDATE SET
           expires_at = MAX(gate_grants.expires_at, excluded.expires_at)",
        params![session_hash, tunnel_id, grant_expires],
    )?;
    Ok((session_id, session_hash))
}

/// Set the session's expiry to its longest grant; returns it.
fn finish_session(tx: &rusqlite::Transaction<'_>, session_hash: &str) -> anyhow::Result<i64> {
    Ok(tx.query_row(
        "UPDATE gate_sessions SET expires_at =
           (SELECT MAX(expires_at) FROM gate_grants WHERE session_hash = ?1)
         WHERE id_hash = ?1 RETURNING expires_at",
        params![session_hash],
        |r| r.get(0),
    )?)
}

/// End what password logins granted on `tunnel_id`. A grant that a still-live
/// access link also vouches for stays, but only until that link's own
/// expiry (a longer login must not outlive the password); the rest go, then
/// sessions left empty.
fn revoke_login_grants(tx: &rusqlite::Transaction<'_>, tunnel_id: &str) -> anyhow::Result<()> {
    let t = now();
    let has_login = "EXISTS (SELECT 1 FROM gate_grant_logins l
                     WHERE l.session_hash = gate_grants.session_hash AND l.tunnel_id = ?1)";
    let live_link = "FROM gate_grant_links k
                     WHERE k.session_hash = gate_grants.session_hash AND k.tunnel_id = ?1
                       AND k.expires_at > ?2";
    tx.execute(
        &format!("DELETE FROM gate_grants WHERE tunnel_id = ?1 AND {has_login} AND NOT EXISTS (SELECT 1 {live_link})"),
        params![tunnel_id, t],
    )?;
    tx.execute(
        &format!(
            "UPDATE gate_grants SET expires_at = MIN(expires_at,
               (SELECT MAX(k.expires_at) {live_link}))
             WHERE tunnel_id = ?1 AND {has_login}"
        ),
        params![tunnel_id, t],
    )?;
    tx.execute("DELETE FROM gate_grant_logins WHERE tunnel_id = ?1", params![tunnel_id])?;
    tx.execute("DELETE FROM gate_sessions WHERE id_hash NOT IN (SELECT session_hash FROM gate_grants)", [])?;
    Ok(())
}

/// Expire every tunnel owned by `owner_id` so it stops serving at once;
/// returns their ids.
/// Checks shared by every way a client is created: a free name and an
/// enabled owner below their machine quota (members only).
pub(crate) fn client_admissible(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
    user_id: &str,
    defaults: crate::limits::Defaults,
) -> anyhow::Result<Result<(), NewClientError>> {
    let taken: i64 = tx.query_row("SELECT COUNT(*) FROM clients WHERE name = ?1", params![name], |r| r.get(0))?;
    if taken > 0 {
        return Ok(Err(NewClientError::NameTaken));
    }
    let user: Option<(String, Option<i64>, i64)> = tx
        .query_row(
            "SELECT u.role, u.limit_clients, (SELECT COUNT(*) FROM clients c WHERE c.user_id = u.id)
             FROM users u WHERE u.id = ?1 AND u.disabled_at IS NULL",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((role, setting, have)) = user else { return Ok(Err(NewClientError::NoUser)) };
    let role = Role::parse(&role);
    let limit = defaults.resolve(crate::limits::Kind::Machines, role, crate::limits::Setting::from_column(setting));
    Ok(match limit {
        Some(limit) if have.max(0) as u64 >= limit => Err(NewClientError::Quota { limit, role }),
        _ => Ok(()),
    })
}

/// Delete every machine of `user_id`, expiring their tunnels (added to `tunnels`, for the caller to close).
pub(crate) fn revoke_machines(
    tx: &rusqlite::Transaction<'_>,
    user_id: &str,
    tunnels: &mut Vec<String>,
) -> anyhow::Result<()> {
    let clients: Vec<String> = {
        let mut stmt = tx.prepare("SELECT id FROM clients WHERE user_id = ?1")?;
        stmt.query_map(params![user_id], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?
    };
    for client in clients {
        tunnels.extend(expire_owner_tunnels(tx, client.as_str())?);
        tx.execute("DELETE FROM clients WHERE id = ?1", params![client])?;
    }
    Ok(())
}

pub(crate) fn expire_owner_tunnels(tx: &rusqlite::Transaction<'_>, owner_id: &str) -> anyhow::Result<Vec<String>> {
    let tunnels: Vec<String> = {
        let mut stmt = tx.prepare("SELECT id FROM tunnels WHERE client_id = ?1")?;
        stmt.query_map(params![owner_id], |r| r.get(0))?.collect::<Result<Vec<_>, _>>()?
    };
    tx.execute(
        "UPDATE tunnels SET expires_at = MIN(expires_at, ?2) WHERE client_id = ?1",
        params![owner_id, now() - 1],
    )?;
    Ok(tunnels)
}

pub(crate) fn tunnel_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelRow> {
    let metadata: Option<String> = r.get(2)?;
    let host_header: String = r.get(4)?;
    Ok(TunnelRow {
        id: r.get(0)?,
        label: r.get(1)?,
        metadata: metadata.and_then(|m| serde_json::from_str(&m).ok()),
        max_ports: r.get(3)?,
        host_header: HostHeaderMode::parse(&host_header),
        inject_ice: r.get(5)?,
        created_at: r.get(6)?,
        expires_at: r.get(7)?,
        last_seen_at: r.get(8)?,
        access: Access {
            mode: AccessMode::parse(&r.get::<_, String>(9)?),
            password_user: r.get(10)?,
            password_hash: r.get(11)?,
        },
        client_id: r.get(12)?,
        bytes_in: r.get(13)?,
        bytes_out: r.get(14)?,
        user_id: r.get(15)?,
        name: r.get(16)?,
    })
}

/// Whether `session` is a live, signed-in session of the enabled `user_id`,
/// and (with `epoch`) the user's credentials are unchanged since then.
pub(crate) fn authorized(
    tx: &rusqlite::Transaction<'_>,
    user_id: &str,
    epoch: Option<i64>,
    session: &str,
) -> anyhow::Result<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM users u JOIN ui_sessions s ON s.user_id = u.id
                        WHERE u.id = ?1 AND u.disabled_at IS NULL AND (?2 IS NULL OR u.auth_epoch = ?2)
                          AND s.id_hash = ?3 AND s.pending = 0 AND s.expires_at > ?4)",
        params![user_id, epoch, session, now()],
        |r| r.get(0),
    )?)
}

#[cfg(test)]
mod tests;
