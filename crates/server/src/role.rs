//! Account roles: the server's owner, admins, and members.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }
    /// Unknown values fall back to the least privileged role.
    pub fn parse(s: &str) -> Self {
        match s {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            _ => Self::Member,
        }
    }
    /// Server-wide permission also lets members keep and create public tunnels.
    pub fn may_public(self, can_public: bool, allow_all_public: bool) -> bool {
        self.is_admin() || can_public || allow_all_public
    }

    pub fn is_admin(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}
