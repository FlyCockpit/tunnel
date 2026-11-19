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
    pub max_tunnels: u32,
    #[serde(default)]
    pub max_clients: u32,
    #[serde(default)]
    pub totp: bool,
    #[serde(default)]
    pub created_at: i64,
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
    pub access: Access,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Link {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Invite {
    pub id: String,
    pub role: String,
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
