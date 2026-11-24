//! Per-user limits: live tunnels across the user's machines, machines,
//! longest tunnel lifetime and monthly traffic. Each is stored as one
//! nullable `users.limit_*` column: NULL follows the server's configuration
//! for the user's role ("Server default", read live), `-1` is Unlimited and
//! any other value is the limit. The owner is always unlimited.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ui::store::Role;

/// Stored value of an Unlimited setting.
pub const UNLIMITED: i64 = -1;

/// Longest explicit tunnel lifetime (100 years); longer than that is "never expires".
pub const MAX_TTL_S: u64 = 100 * 365 * 86_400;

/// How one limit is set for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Setting {
    /// Follows the server's configuration for the user's role.
    #[default]
    Default,
    Unlimited,
    Value(u64),
}

impl Setting {
    pub fn from_column(v: Option<i64>) -> Self {
        match v {
            None => Self::Default,
            Some(n) if n < 0 => Self::Unlimited,
            Some(n) => Self::Value(n as u64),
        }
    }

    pub fn to_column(self) -> Option<i64> {
        match self {
            Self::Default => None,
            Self::Unlimited => Some(UNLIMITED),
            Self::Value(n) => Some(i64::try_from(n).unwrap_or(i64::MAX)),
        }
    }
}

/// JSON: `"default"`, `"unlimited"` or a number.
impl Serialize for Setting {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Default => s.serialize_str("default"),
            Self::Unlimited => s.serialize_str("unlimited"),
            Self::Value(n) => s.serialize_u64(*n),
        }
    }
}

impl<'de> Deserialize<'de> for Setting {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u64),
            Word(String),
        }
        match Raw::deserialize(d)? {
            Raw::Number(n) => Ok(Self::Value(n)),
            Raw::Word(w) if w == "default" => Ok(Self::Default),
            Raw::Word(w) if w == "unlimited" => Ok(Self::Unlimited),
            Raw::Word(_) => {
                Err(serde::de::Error::custom("a limit is \"default\", \"unlimited\" or a non-negative whole number"))
            }
        }
    }
}

/// The four limits as set for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    pub tunnels: Setting,
    pub machines: Setting,
    pub tunnel_ttl_s: Setting,
    pub traffic_bytes: Setting,
}

impl Settings {
    pub fn get(&self, kind: Kind) -> Setting {
        match kind {
            Kind::Tunnels => self.tunnels,
            Kind::Machines => self.machines,
            Kind::TunnelTtl => self.tunnel_ttl_s,
            Kind::Traffic => self.traffic_bytes,
        }
    }

    pub fn set(&mut self, kind: Kind, setting: Setting) {
        match kind {
            Kind::Tunnels => self.tunnels = setting,
            Kind::Machines => self.machines = setting,
            Kind::TunnelTtl => self.tunnel_ttl_s = setting,
            Kind::Traffic => self.traffic_bytes = setting,
        }
    }
}

/// Changes to some of the four (absent: unchanged).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    #[serde(default)]
    pub tunnels: Option<Setting>,
    #[serde(default)]
    pub machines: Option<Setting>,
    #[serde(default)]
    pub tunnel_ttl_s: Option<Setting>,
    #[serde(default)]
    pub traffic_bytes: Option<Setting>,
}

impl SettingsPatch {
    pub fn get(&self, kind: Kind) -> Option<Setting> {
        match kind {
            Kind::Tunnels => self.tunnels,
            Kind::Machines => self.machines,
            Kind::TunnelTtl => self.tunnel_ttl_s,
            Kind::Traffic => self.traffic_bytes,
        }
    }

    /// Range checks for explicit numbers.
    pub fn validate(&self) -> Result<(), String> {
        for kind in Kind::ALL {
            if let Some(Setting::Value(n)) = self.get(kind) {
                let (min, max) = kind.range();
                if !(min..=max).contains(&n) {
                    return Err(format!(
                        "limits.{} must be \"default\", \"unlimited\" or within {min}..={max}{}",
                        kind.key(),
                        kind.unit_hint()
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tunnels,
    Machines,
    TunnelTtl,
    Traffic,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Tunnels, Kind::Machines, Kind::TunnelTtl, Kind::Traffic];

    /// JSON key.
    pub fn key(self) -> &'static str {
        match self {
            Self::Tunnels => "tunnels",
            Self::Machines => "machines",
            Self::TunnelTtl => "tunnel_ttl_s",
            Self::Traffic => "traffic_bytes",
        }
    }

    /// For people (messages, audit).
    pub fn label(self) -> &'static str {
        match self {
            Self::Tunnels => "live tunnels",
            Self::Machines => "machines",
            Self::TunnelTtl => "tunnel lifetime",
            Self::Traffic => "monthly traffic",
        }
    }

    pub fn column(self) -> &'static str {
        match self {
            Self::Tunnels => "limit_tunnels",
            Self::Machines => "limit_clients",
            Self::TunnelTtl => "limit_tunnel_ttl_s",
            Self::Traffic => "limit_traffic_bytes",
        }
    }

    fn range(self) -> (u64, u64) {
        match self {
            Self::Tunnels => (0, 10_000),
            Self::Machines => (0, 1000),
            Self::TunnelTtl => (crate::api::MIN_TUNNEL_TTL_S, MAX_TTL_S),
            Self::Traffic => (crate::traffic::MIN_CAP, crate::traffic::MAX_CAP),
        }
    }

    fn unit_hint(self) -> &'static str {
        match self {
            Self::TunnelTtl => " seconds",
            Self::Traffic => " bytes",
            _ => "",
        }
    }

    /// `n` as people read it.
    pub fn amount(self, n: u64) -> String {
        match self {
            Self::TunnelTtl => duration_text(n),
            Self::Traffic => bytes_text(n),
            _ => n.to_string(),
        }
    }
}

/// What "Server default" means, from the configuration (read live, so a
/// changed config applies to everyone on the default after a restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Defaults {
    pub max_tunnel_ttl_s: u64,
    pub member_tunnels: u64,
    pub member_machines: u64,
    pub member_tunnel_ttl_s: u64,
    pub member_traffic_bytes: Option<u64>,
}

impl Defaults {
    pub fn new(limits: &crate::config::Limits) -> Self {
        Self {
            max_tunnel_ttl_s: limits.max_tunnel_ttl_s,
            member_tunnels: limits.member_max_tunnels.into(),
            member_machines: limits.member_max_clients.into(),
            member_tunnel_ttl_s: limits.max_tunnel_ttl_s.min(limits.member_max_tunnel_ttl_s),
            member_traffic_bytes: limits.member_monthly_traffic_gb.map(|gb| gb.saturating_mul(1_000_000_000)),
        }
    }

    /// The server default of `kind` for `role`; `None`: unlimited.
    pub fn of(&self, kind: Kind, role: Role) -> Option<u64> {
        match (role, kind) {
            (Role::Owner, _) => None,
            (Role::Admin, Kind::TunnelTtl) => Some(self.max_tunnel_ttl_s),
            (Role::Admin, _) => None,
            (Role::Member, Kind::Tunnels) => Some(self.member_tunnels),
            (Role::Member, Kind::Machines) => Some(self.member_machines),
            (Role::Member, Kind::TunnelTtl) => Some(self.member_tunnel_ttl_s),
            (Role::Member, Kind::Traffic) => self.member_traffic_bytes,
        }
    }

    /// The limit in force; `None`: unlimited. The owner is never limited.
    pub fn resolve(&self, kind: Kind, role: Role, setting: Setting) -> Option<u64> {
        if role == Role::Owner {
            return None;
        }
        match setting {
            Setting::Default => self.of(kind, role),
            Setting::Unlimited => None,
            Setting::Value(n) => Some(n),
        }
    }

    pub fn effective(&self, role: Role, s: &Settings) -> Effective {
        Effective {
            tunnels: self.resolve(Kind::Tunnels, role, s.tunnels),
            machines: self.resolve(Kind::Machines, role, s.machines),
            tunnel_ttl_s: self.resolve(Kind::TunnelTtl, role, s.tunnel_ttl_s),
            traffic_bytes: self.resolve(Kind::Traffic, role, s.traffic_bytes),
        }
    }

    /// For the audit log: `Server default (10)`, `Unlimited`, `3`.
    pub fn describe(&self, kind: Kind, role: Role, setting: Setting) -> String {
        let amount = |v: Option<u64>| v.map_or_else(|| "unlimited".to_string(), |n| kind.amount(n));
        match setting {
            Setting::Default => format!("Server default ({})", amount(self.of(kind, role))),
            Setting::Unlimited => "Unlimited".to_string(),
            Setting::Value(n) => kind.amount(n),
        }
    }

    /// The user's limits for the API and the UI: per limit its setting, what
    /// the server default is for the role, and the limit in force (`null`:
    /// unlimited).
    pub fn view(&self, role: Role, s: &Settings) -> Value {
        let mut out = serde_json::Map::new();
        for kind in Kind::ALL {
            let setting = if role == Role::Owner { Setting::Unlimited } else { s.get(kind) };
            out.insert(
                kind.key().to_string(),
                json!({
                    "setting": setting,
                    "default": self.of(kind, role),
                    "effective": self.resolve(kind, role, setting),
                }),
            );
        }
        Value::Object(out)
    }
}

/// Limits in force; `None`: unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub tunnels: Option<u64>,
    pub machines: Option<u64>,
    pub tunnel_ttl_s: Option<u64>,
    pub traffic_bytes: Option<u64>,
}

/// Who can raise a limit of a user with `role`.
pub fn raiser(role: Role) -> &'static str {
    match role {
        Role::Member => "an admin",
        _ => "the server's owner",
    }
}

/// A refused new machine.
pub fn machine_limit_message(limit: u64, role: Role) -> String {
    format!(
        "this account's machine limit ({limit}) is reached; remove a machine on the Machines page, \
         or ask {} to raise the limit",
        raiser(role)
    )
}

/// A refused new tunnel (the user's limit across all their machines).
pub fn tunnel_limit_message(limit: u64, role: Role) -> String {
    format!(
        "this account's live-tunnel limit ({limit}, across all its machines) is reached; delete a tunnel \
         (`tunnel unshare`, or the Tunnels page), or ask {} to raise the limit",
        raiser(role)
    )
}

/// A refused lifetime: too long, or "never expires" while a limit applies.
/// `account`: the machine's user's role (`None`: a service or the admin token).
pub fn ttl_limit_message(limit: u64, account: Option<Role>, never: bool) -> String {
    let whose = if account.is_some() { "this account's" } else { "this caller's" };
    let asked = if never { "a tunnel that never expires" } else { "a lifetime that long" };
    let raise = match account {
        Some(role) => format!("; ask {} to raise the limit", raiser(role)),
        None => " (limits.max_tunnel_ttl_s)".to_string(),
    };
    format!("{whose} tunnel lifetime limit is {}, so {asked} is not allowed{raise}", duration_text(limit))
}

/// `90s`, `30m`, `8h`, `7d`, or a combination (`1d 12h`).
pub fn duration_text(s: u64) -> String {
    let mut parts = Vec::new();
    let mut left = s;
    for (unit, size) in [("d", 86_400), ("h", 3600), ("m", 60), ("s", 1)] {
        if left >= size {
            parts.push(format!("{}{unit}", left / size));
            left %= size;
        }
    }
    if parts.is_empty() { "0s".to_string() } else { parts.join(" ") }
}

/// Exact: `5 GB` when whole in a decimal unit, else the bytes with a rounded
/// hint (`1040000000 bytes (1.0 GB)`), `999 bytes`.
pub fn bytes_text(b: u64) -> String {
    for (unit, size) in [("TB", 1_000_000_000_000u64), ("GB", 1_000_000_000), ("MB", 1_000_000), ("kB", 1000)] {
        if b >= size {
            return if b.is_multiple_of(size) {
                format!("{} {unit}", b / size)
            } else {
                format!("{b} bytes ({:.1} {unit})", b as f64 / size as f64)
            };
        }
    }
    format!("{b} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Defaults {
        Defaults::new(&crate::config::Limits { member_monthly_traffic_gb: Some(5), ..Default::default() })
    }

    #[test]
    fn settings_round_trip_through_columns_and_json() {
        for s in [Setting::Default, Setting::Unlimited, Setting::Value(0), Setting::Value(7)] {
            assert_eq!(Setting::from_column(s.to_column()), s);
            assert_eq!(serde_json::from_value::<Setting>(serde_json::to_value(s).unwrap()).unwrap(), s);
        }
        assert_eq!(Setting::Unlimited.to_column(), Some(-1));
        assert_eq!(Setting::Default.to_column(), None);
        assert_eq!(serde_json::to_value(Setting::Unlimited).unwrap(), json!("unlimited"));
        for bad in [json!("none"), json!(-1), json!(1.5), json!(null), json!(true)] {
            assert!(serde_json::from_value::<Setting>(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_limit_resolves_by_role_and_setting() {
        let d = defaults();
        let cases: [(Kind, Option<u64>, Option<u64>); 4] = [
            (Kind::Tunnels, Some(10), None),
            (Kind::Machines, Some(5), None),
            (Kind::TunnelTtl, Some(7 * 86_400), Some(30 * 86_400)),
            (Kind::Traffic, Some(5_000_000_000), None),
        ];
        for (kind, member_default, admin_default) in cases {
            assert_eq!(d.resolve(kind, Role::Member, Setting::Default), member_default, "{kind:?}");
            assert_eq!(d.resolve(kind, Role::Admin, Setting::Default), admin_default, "{kind:?}");
            for role in [Role::Member, Role::Admin] {
                assert_eq!(d.resolve(kind, role, Setting::Value(3)), Some(3), "{kind:?}");
                assert_eq!(d.resolve(kind, role, Setting::Unlimited), None, "{kind:?}");
            }
            for setting in [Setting::Default, Setting::Value(3), Setting::Unlimited] {
                assert_eq!(d.resolve(kind, Role::Owner, setting), None, "the owner is never limited");
            }
        }
    }

    #[test]
    fn patch_ranges_and_descriptions() {
        let ok = SettingsPatch {
            tunnels: Some(Setting::Value(0)),
            machines: Some(Setting::Unlimited),
            tunnel_ttl_s: Some(Setting::Value(60)),
            traffic_bytes: Some(Setting::Default),
        };
        assert!(ok.validate().is_ok());
        for bad in [
            SettingsPatch { tunnels: Some(Setting::Value(10_001)), ..Default::default() },
            SettingsPatch { machines: Some(Setting::Value(1001)), ..Default::default() },
            SettingsPatch { tunnel_ttl_s: Some(Setting::Value(59)), ..Default::default() },
            SettingsPatch { tunnel_ttl_s: Some(Setting::Value(MAX_TTL_S + 1)), ..Default::default() },
            SettingsPatch { traffic_bytes: Some(Setting::Value(999_999)), ..Default::default() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        let d = defaults();
        assert_eq!(d.describe(Kind::Tunnels, Role::Member, Setting::Default), "Server default (10)");
        assert_eq!(d.describe(Kind::Traffic, Role::Admin, Setting::Default), "Server default (unlimited)");
        assert_eq!(d.describe(Kind::TunnelTtl, Role::Member, Setting::Default), "Server default (7d)");
        assert_eq!(d.describe(Kind::TunnelTtl, Role::Member, Setting::Value(90_000)), "1d 1h");
        assert_eq!(d.describe(Kind::Traffic, Role::Member, Setting::Value(1_500_000)), "1500000 bytes (1.5 MB)");
        assert_ne!(bytes_text(1_040_000_000), bytes_text(1_030_000_000), "the audit keeps exact values");
        assert_eq!(bytes_text(2_000_000_000), "2 GB");
        assert_eq!(d.describe(Kind::Machines, Role::Member, Setting::Unlimited), "Unlimited");
    }

    #[test]
    fn the_view_reports_setting_default_and_effective() {
        let d = defaults();
        let s = Settings { tunnels: Setting::Value(3), tunnel_ttl_s: Setting::Unlimited, ..Default::default() };
        let v = d.view(Role::Member, &s);
        assert_eq!(v["tunnels"], json!({"setting": 3, "default": 10, "effective": 3}));
        assert_eq!(v["machines"], json!({"setting": "default", "default": 5, "effective": 5}));
        assert_eq!(v["tunnel_ttl_s"], json!({"setting": "unlimited", "default": 604_800, "effective": null}));
        let owner = d.view(Role::Owner, &s);
        for kind in Kind::ALL {
            assert_eq!(owner[kind.key()], json!({"setting": "unlimited", "default": null, "effective": null}));
        }
    }
}
