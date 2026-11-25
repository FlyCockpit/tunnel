//! JSON shapes of `/ui/api/*` (see crates/server/src/ui/handlers.rs).
//! Fields default when absent so an older or newer server degrades gracefully.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub role: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub can_public: bool,
    #[serde(default)]
    pub totp: bool,
    #[serde(default)]
    pub created_at: i64,
    /// Confirmed email address (servers that send mail).
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub limits: Limits,
}

/// A user's four limits (see crates/server/src/limits.rs).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Limits {
    #[serde(default)]
    pub tunnels: Limit,
    #[serde(default)]
    pub machines: Limit,
    #[serde(default)]
    pub tunnel_ttl_s: Limit,
    #[serde(default)]
    pub traffic_bytes: Limit,
}

/// One limit: how it is set (`"default"`, `"unlimited"` or a number), what
/// the server default is for the user's role and what is in force
/// (`None`: unlimited).
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Limit {
    #[serde(default)]
    pub setting: serde_json::Value,
    #[serde(default)]
    pub default: Option<u64>,
    #[serde(default)]
    pub effective: Option<u64>,
}

impl Limit {
    /// `"default"`, `"unlimited"` or `"number"`.
    pub fn mode(&self) -> &'static str {
        if self.setting.is_u64() {
            "number"
        } else if self.setting.as_str() == Some("unlimited") {
            "unlimited"
        } else {
            "default"
        }
    }
}

/// What a user uses of their tunnel and machine limits.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Usage {
    #[serde(default)]
    pub tunnels: u64,
    #[serde(default)]
    pub machines: u64,
}

/// A user's traffic this month.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Traffic {
    #[serde(default)]
    pub month: String,
    #[serde(default)]
    pub used_bytes: u64,
    #[serde(default)]
    pub cap_bytes: Option<u64>,
    #[serde(default)]
    pub limited: bool,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "owner" || self.role == "admin"
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Server {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub ui_origin: String,
    #[serde(default)]
    pub api_origin: String,
    #[serde(default)]
    pub preview_zone: String,
    #[serde(default)]
    pub same_site: bool,
    #[serde(default)]
    pub abuse_contact: Option<String>,
    /// The server sends mail (invites, password resets, notices).
    #[serde(default)]
    pub mail: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SessionInfo {
    pub user: Option<User>,
    #[serde(default)]
    pub pending: bool,
    #[serde(default)]
    pub pending_user: Option<String>,
    pub csrf: Option<String>,
    #[serde(default)]
    pub owner_exists: bool,
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub traffic: Option<Traffic>,
    #[serde(default)]
    pub usage: Option<Usage>,
    /// A new address waiting to be confirmed from its mail.
    #[serde(default)]
    pub email_pending: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Port {
    pub port: u16,
    pub host: String,
    #[serde(default)]
    pub connected: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Access {
    pub mode: String,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Tunnel {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    /// Display name (a label only; URLs never change).
    #[serde(default)]
    pub name: Option<String>,
    /// One of the signed-in user's own machines made it (Open skips its sign-in).
    #[serde(default)]
    pub mine: bool,
    pub access: Access,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub never_expires: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub bytes_in: u64,
    #[serde(default)]
    pub bytes_out: u64,
    #[serde(default)]
    pub traffic_limited: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Link {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    /// `visitor`, or `owner` (made by Open for the tunnel's own user).
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub single_use: bool,
    #[serde(default)]
    pub used_at: Option<i64>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Machine {
    pub name: String,
    pub user: String,
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub tunnels: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct UserRow {
    #[serde(flatten)]
    pub user: User,
    #[serde(default)]
    pub clients: i64,
    #[serde(default)]
    pub tunnels: i64,
    /// Bytes this month.
    #[serde(default)]
    pub traffic_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Invite {
    pub id: String,
    /// `invite` or `account_reset`.
    #[serde(default)]
    pub kind: String,
    /// Where an emailed invite went.
    #[serde(default)]
    pub email: Option<String>,
    pub role: String,
    /// The account an `account_reset` is for.
    #[serde(default)]
    pub user: Option<String>,
    /// Whether this admin may revoke it (the server decides).
    #[serde(default)]
    pub revocable: bool,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub used_at: Option<i64>,
    #[serde(default)]
    pub used_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SessionRow {
    pub id: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub last_seen_at: i64,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub current: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AuditEntry {
    pub id: i64,
    pub at: i64,
    #[serde(default)]
    pub user: Option<String>,
    pub action: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DeviceRequest {
    pub user_code: String,
    pub client_name: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub created_at: i64,
}
