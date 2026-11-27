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
    pub recovery_codes_left: u64,
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
#[serde(try_from = "serde_json::Value")]
pub struct UserRow {
    pub user: User,
    pub clients: i64,
    pub tunnels: i64,
    /// Bytes this month.
    pub traffic_bytes: u64,
}

impl TryFrom<serde_json::Value> for UserRow {
    type Error = serde_json::Error;

    fn try_from(mut row: serde_json::Value) -> Result<Self, Self::Error> {
        fn count<T: serde::de::DeserializeOwned + Default>(
            row: &mut serde_json::Value,
            key: &str,
        ) -> Result<T, serde_json::Error> {
            row.get_mut(key).map(|v| serde_json::from_value(v.take())).unwrap_or_else(|| Ok(T::default()))
        }

        let clients = count(&mut row, "clients")?;
        let tunnels = count(&mut row, "tunnels")?;
        let traffic_bytes = count(&mut row, "traffic_bytes")?;
        // Reuse User's Value decoder instead of serde's flatten content buffer.
        let user = serde_json::from_value(row)?;
        Ok(Self { user, clients, tunnels, traffic_bytes })
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// Keep the old wire decoder as an oracle, without shipping its content buffer.
    #[derive(Deserialize)]
    struct FlattenedRow {
        #[serde(flatten)]
        user: User,
        #[serde(default)]
        clients: i64,
        #[serde(default)]
        tunnels: i64,
        #[serde(default)]
        traffic_bytes: u64,
    }

    #[test]
    fn the_session_keeps_the_remaining_recovery_count() {
        for (extra, expected) in
            [(json!({}), 0), (json!({ "recovery_codes_left": 1 }), 1), (json!({ "recovery_codes_left": 9 }), 9)]
        {
            let mut user = json!({ "id": "u1", "username": "alice", "role": "member", "totp": true });
            user.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            let session: SessionInfo = serde_json::from_value(json!({ "user": user })).unwrap();
            assert_eq!(session.user.unwrap().recovery_codes_left, expected);
        }
    }

    #[test]
    fn sessions_keep_decoding_through_json_values() {
        for session in [
            json!({}),
            json!({ "user": null, "csrf": null }),
            json!({ "user": { "id": "u1", "username": "alice", "role": "owner" }, "csrf": "token" }),
            json!({ "pending": true, "pending_user": "alice", "server": { "mail": true } }),
            json!({ "usage": { "tunnels": u64::MAX }, "traffic": { "cap_bytes": null } }),
            json!({ "user": { "id": "u1" } }),
            json!({ "server": null }),
            Value::Null,
        ] {
            let text = serde_json::to_string(&session).unwrap();
            let expected = serde_json::from_str::<SessionInfo>(&text).ok();
            let actual = serde_json::from_value::<SessionInfo>(session).ok();
            assert_eq!(actual, expected, "{text}");
        }
    }

    #[test]
    fn user_rows_keep_the_flattened_wire_shape() {
        let base = json!({ "id": "u1", "username": "alice", "role": "member" });
        let mut cases = vec![base.clone(), Value::Null, json!([]), json!({})];
        for (key, value) in [
            ("clients", json!(i64::MAX)),
            ("tunnels", json!(-1)),
            ("traffic_bytes", json!(u64::MAX)),
            ("traffic_bytes", json!(-1)),
            ("clients", Value::Null),
            ("tunnels", json!("3")),
            ("clients", json!(1.5)),
            ("disabled", json!(true)),
            ("email", json!("alice@example.org")),
            ("limits", json!({ "machines": { "setting": 3, "effective": 3 } })),
            ("limits", Value::Null),
            ("id", Value::Null),
            ("extra", json!({ "future": true })),
        ] {
            let mut row = base.clone();
            row[key] = value;
            cases.push(row);
        }
        for row in cases {
            let expected = serde_json::from_value::<FlattenedRow>(row.clone())
                .map(|r| UserRow {
                    user: r.user,
                    clients: r.clients,
                    tunnels: r.tunnels,
                    traffic_bytes: r.traffic_bytes,
                })
                .ok();
            let actual = serde_json::from_value::<UserRow>(row.clone()).ok();
            assert_eq!(actual, expected, "{row}");
        }
    }
}
