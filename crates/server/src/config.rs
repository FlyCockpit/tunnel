use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub const DEFAULT_DATA_DIR: &str = "/var/lib/tunnel";
pub const SERVICE_USER: &str = "tunnel-server";
pub const SERVICE_NAME: &str = "tunnel-server";

/// System config: root:tunnel-server, mode 0640; rootless config: mode 0600.
/// Contains secrets (TURN secret, DNS token); the admin token is stored only as a hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Wildcard preview zone, e.g. `previews.example.com`.
    pub preview_zone: String,
    pub api_host: String,
    pub tunnel_host: String,
    pub turn_host: String,
    /// Sites allowed to show previews in an iframe: CSP `frame-ancestors` sources
    /// (`https://app.example.com`, `https://*.example.com`), or `*` for any site.
    /// The preview's own origin is always allowed; an empty list allows only it.
    #[serde(default)]
    pub frame_ancestors: Vec<String>,

    #[serde(default = "default_https")]
    pub listen_https: SocketAddr,
    #[serde(default = "default_http")]
    pub listen_http: SocketAddr,
    #[serde(default = "default_metrics")]
    pub metrics_listen: SocketAddr,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Hex SHA-256 of the admin API token.
    pub admin_token_hash: String,

    /// Hex SHA-256 of the optional `/healthz` token (`health-token set`).
    /// When set, `/healthz` answers only callers that present it (the admin
    /// token is not accepted there) and is a plain 404 to everyone else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_token_hash: Option<String>,

    #[serde(default)]
    pub public_ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    pub public_ipv6: Option<Ipv6Addr>,

    pub acme: AcmeConfig,
    pub dns: DnsConfig,
    #[serde(default)]
    pub webrtc: WebrtcConfig,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AcmeConfig {
    pub email: String,
    /// Use the Let's Encrypt staging directory.
    #[serde(default)]
    pub staging: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsProviderKind {
    Cloudflare,
    Hetzner,
    Digitalocean,
    Route53,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsConfig {
    pub provider: DnsProviderKind,
    /// DNS zone name managed at the provider, e.g. `example.com`.
    pub zone: String,
    /// Cloudflare / Hetzner / DigitalOcean API token.
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub aws_access_key_id: Option<String>,
    #[serde(default)]
    pub aws_secret_access_key: Option<String>,
    #[serde(default)]
    pub route53_hosted_zone_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebrtcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub static_auth_secret: String,
    /// Treat TLS connections on 443 without SNI as TURN over TLS.
    #[serde(default = "default_true")]
    pub passthrough_no_sni: bool,
    #[serde(default = "default_browser_ttl")]
    pub browser_ttl_s: u64,
    #[serde(default = "default_sandbox_ttl")]
    pub sandbox_ttl_s: u64,
    #[serde(default = "default_stun_port")]
    pub stun_port: u16,
    #[serde(default = "default_relay_min")]
    pub relay_min_port: u16,
    #[serde(default = "default_relay_max")]
    pub relay_max_port: u16,
}

impl Default for WebrtcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            static_auth_secret: String::new(),
            passthrough_no_sni: true,
            browser_ttl_s: default_browser_ttl(),
            sandbox_ttl_s: default_sandbox_ttl(),
            stun_port: default_stun_port(),
            relay_min_port: default_relay_min(),
            relay_max_port: default_relay_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Limits {
    /// Live tunnels one client token may own; the admin token is not limited.
    #[serde(default = "default_max_tunnels_per_client")]
    pub max_tunnels_per_client: u32,
    #[serde(default = "default_max_ports")]
    pub default_max_ports: u16,
    #[serde(default = "default_hard_max_ports")]
    pub hard_max_ports: u16,
    /// `/__access/*` attempts per IP per minute.
    #[serde(default = "default_access_rate")]
    pub access_rate_per_min: u32,
    #[serde(default = "default_session_ttl")]
    pub default_session_ttl_s: u64,
    #[serde(default = "default_max_tunnel_ttl")]
    pub max_tunnel_ttl_s: u64,
    #[serde(default = "default_tombstone_retention")]
    pub tombstone_retention_s: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tunnels_per_client: default_max_tunnels_per_client(),
            default_max_ports: default_max_ports(),
            hard_max_ports: default_hard_max_ports(),
            access_rate_per_min: default_access_rate(),
            default_session_ttl_s: default_session_ttl(),
            max_tunnel_ttl_s: default_max_tunnel_ttl(),
            tombstone_retention_s: default_tombstone_retention(),
        }
    }
}

fn default_https() -> SocketAddr {
    "[::]:443".parse().unwrap()
}
fn default_http() -> SocketAddr {
    "[::]:80".parse().unwrap()
}
fn default_metrics() -> SocketAddr {
    "127.0.0.1:9464".parse().unwrap()
}
fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}
fn default_true() -> bool {
    true
}
fn default_browser_ttl() -> u64 {
    3600
}
fn default_sandbox_ttl() -> u64 {
    86_400
}
fn default_stun_port() -> u16 {
    3478
}
fn default_relay_min() -> u16 {
    49160
}
fn default_relay_max() -> u16 {
    49999
}
fn default_max_tunnels_per_client() -> u32 {
    20
}
fn default_max_ports() -> u16 {
    8
}
fn default_hard_max_ports() -> u16 {
    32
}
fn default_access_rate() -> u32 {
    30
}
fn default_session_ttl() -> u64 {
    12 * 3600
}
fn default_max_tunnel_ttl() -> u64 {
    30 * 86_400
}
fn default_tombstone_retention() -> u64 {
    30 * 86_400
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        cfg.normalize_frame_ancestors();
        Ok(cfg)
    }

    /// Trim and deduplicate sources without broadening an empty policy.
    pub fn normalize_frame_ancestors(&mut self) {
        let mut sources = Vec::new();
        for source in &self.frame_ancestors {
            let source = source.trim();
            if !source.is_empty() && !sources.iter().any(|s| s == source) {
                sources.push(source.to_string());
            }
        }
        self.frame_ancestors = sources;
    }

    pub fn to_toml(&self) -> anyhow::Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Atomic write with mode 0600. Returns `true` if the file content changed.
    pub fn save(&self, path: &Path) -> anyhow::Result<bool> {
        let content = self.to_toml()?;
        crate::util::write_if_changed(path, content.as_bytes(), 0o600)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("tunnel.db")
    }

    pub fn cert_dir(&self) -> PathBuf {
        self.data_dir.join("certs")
    }

    pub fn acme_account_path(&self) -> PathBuf {
        self.data_dir.join("acme-account.json")
    }

    /// Every name on the single DNS-01 certificate.
    pub fn cert_names(&self) -> Vec<String> {
        // The zone apex serves sign-in (`gatehost`); usually it is also the API host.
        let mut names = vec![
            format!("*.{}", self.preview_zone),
            self.preview_zone.clone(),
            self.api_host.clone(),
            self.tunnel_host.clone(),
        ];
        if self.webrtc.enabled && !self.covered_by_wildcard(&self.turn_host) {
            names.push(self.turn_host.clone());
        }
        names.sort();
        names.dedup();
        names
    }

    /// `host` is one label below the preview zone, so `*.<zone>` (certificate
    /// and DNS) already covers it.
    pub fn covered_by_wildcard(&self, host: &str) -> bool {
        host.strip_suffix(&format!(".{}", self.preview_zone))
            .is_some_and(|label| !label.is_empty() && !label.contains('.'))
    }

    /// `{port}-<id>.<zone>` host for a tunnel port.
    pub fn preview_host(&self, port: u16, tunnel_id: &str) -> String {
        format!("{port}-{tunnel_id}.{}", self.preview_zone)
    }

    pub fn host_template(&self, tunnel_id: &str) -> String {
        format!("{{port}}-{tunnel_id}.{}", self.preview_zone)
    }
}

/// Ensure a path has exactly `mode` permissions.
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: &str = r#"
preview_zone = "previews.example.com"
api_host = "api.example.com"
tunnel_host = "tunnel.example.com"
turn_host = "turn.example.com"
admin_token_hash = "public-test-placeholder"
frame_ancestors = ["https://app.example.com", "https://*.example.com"]
data_dir = "/var/lib/tunnel"
[acme]
email = "admin@example.com"
staging = true
[dns]
provider = "cloudflare"
zone = "example.com"
api_token = "public-test-placeholder"
"#;

    #[test]
    fn config_round_trip() {
        let cfg: Config = toml::from_str(CURRENT).unwrap();
        let written = cfg.to_toml().unwrap();
        let reloaded: Config = toml::from_str(&written).unwrap();
        assert_eq!(cfg, reloaded);
        assert_eq!(cfg.cert_names(), reloaded.cert_names());
        assert_eq!(written, reloaded.to_toml().unwrap());
    }
    #[test]
    fn config_defaults_are_restrictive_and_unknown_fields_are_ignored() {
        let raw = CURRENT.replace(
            "frame_ancestors = [\"https://app.example.com\", \"https://*.example.com\"]",
            "future_option = true",
        );
        let cfg: Config = toml::from_str(&raw).unwrap();
        assert!(cfg.frame_ancestors.is_empty());
        assert_eq!(cfg.limits.max_tunnels_per_client, 20);
        let limits: Limits = toml::from_str("max_tunnels_per_client = 7").unwrap();
        assert_eq!(limits.max_tunnels_per_client, 7);
    }

    #[test]
    fn config_load_normalizes_sources_without_allowing_any_site() {
        let dir = std::env::temp_dir().join(format!("tunnel-config-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut cfg: Config = toml::from_str(CURRENT).unwrap();
        cfg.frame_ancestors = vec!["  ".into()];
        cfg.save(&path).unwrap();
        assert!(Config::load(&path).unwrap().frame_ancestors.is_empty());
        cfg.frame_ancestors = vec![" https://app.example.com ".into(), "https://app.example.com".into(), "*".into()];
        cfg.save(&path).unwrap();
        assert_eq!(Config::load(&path).unwrap().frame_ancestors, vec!["https://app.example.com", "*"]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
