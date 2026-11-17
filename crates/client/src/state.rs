//! Persisted daemon state and server URL resolution.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::paths::ENV_SERVER;

/// Written on every change so a killed daemon restarts with the same tunnel
/// and ports. Holds the tunnel token, hence 0600 in a 0700 directory.
/// Deliberately not `Debug`, so the token cannot end up in a log line.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Persisted {
    pub server: String,
    pub token: String,
    pub ports: Vec<u16>,
    pub revoked: bool,
    /// Another client took over the tunnel; commands do not restart the daemon
    /// on their own, so two sandboxes never fight over one token.
    pub replaced: bool,
    pub tunnel_id: Option<String>,
    pub host_template: Option<String>,
    /// Where exposed ports are dialled (`TUNNEL_TARGET_HOST` / `--target`);
    /// `None`: loopback.
    #[serde(default)]
    pub target: Option<std::net::IpAddr>,
}

impl Persisted {
    /// A missing or unreadable file is treated as no state (commands); the
    /// daemon uses [`Persisted::load_strict`].
    pub fn load(path: &Path) -> Option<Self> {
        Self::load_strict(path).unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %format!("{e:#}"), "ignoring unreadable state file");
            None
        })
    }

    /// `Ok(None)` only if there is no file; unreadable or malformed state
    /// (including an invalid target) is an error.
    pub fn load_strict(path: &Path) -> anyhow::Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow!("cannot read state file: {e}")),
        };
        let mut state: Self = serde_json::from_slice(&bytes).map_err(|e| anyhow!("malformed state file: {e}"))?;
        state.target = state.target.map(crate::paths::validate_target).transpose()?;
        Ok(Some(state))
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_atomic(path, &json, 0o600)
    }
}

/// Write to a sibling temp file and rename over `path`, so readers never see a
/// partial file.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut tmp_name = path.file_name().map(OsString::from).unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut f =
            OpenOptions::new().write(true).create_new(true).custom_flags(libc::O_NOFOLLOW).mode(mode).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Server base URL as `wss://host[:port]` (or `ws://` for local testing).
pub fn normalize_server(raw: &str) -> anyhow::Result<String> {
    let s = raw.trim().trim_end_matches('/');
    let url = if let Some(rest) = s.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = s.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if s.starts_with("wss://") || s.starts_with("ws://") {
        s.to_string()
    } else if s.contains("://") {
        bail!("unsupported tunnel server URL scheme: {s}");
    } else {
        format!("wss://{s}")
    };
    if url.ends_with("://") {
        bail!("empty tunnel server URL");
    }
    Ok(url)
}

/// `$TUNNEL_SERVER`, else the persisted server, else the default baked
/// in at build time via `TUNNEL_DEFAULT_SERVER`.
pub fn resolve_server(env: Option<&str>, persisted: Option<&str>) -> anyhow::Result<String> {
    let raw = env
        .or(persisted.filter(|s| !s.is_empty()))
        .or(option_env!("TUNNEL_DEFAULT_SERVER").filter(|s| !s.is_empty()))
        .ok_or_else(|| anyhow!("no tunnel server configured: set {ENV_SERVER}"))?;
    normalize_server(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn terminal_flags_are_required_in_persisted_state() {
        let value = serde_json::to_value(Persisted::default()).unwrap();
        assert!(serde_json::from_value::<Persisted>(value.clone()).is_ok());
        for field in ["revoked", "replaced"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Persisted>(missing).is_err());
        }
    }

    #[test]
    fn write_atomic_does_not_follow_planted_temp_symlink() {
        let dir = std::env::temp_dir().join(format!("tunnel-write-atomic-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        let victim = dir.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, dir.join("state.json.tmp")).unwrap();
        write_atomic(&path, b"replacement", 0o600).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert_eq!(fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!dir.join("state.json.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn target_round_trips_and_defaults_to_loopback() {
        let p = Persisted { target: Some("fd00::2".parse().unwrap()), ..Persisted::default() };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["target"], "fd00::2");
        assert_eq!(serde_json::from_value::<Persisted>(json.clone()).unwrap().target, p.target);
        let mut without = json;
        without.as_object_mut().unwrap().remove("target");
        assert_eq!(serde_json::from_value::<Persisted>(without).unwrap().target, None);
    }

    #[test]
    fn strict_load_refuses_malformed_or_invalid_targets() {
        let dir = std::env::temp_dir().join(format!("tunnel-state-strict-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("state.json");
        assert!(Persisted::load_strict(&path).unwrap().is_none());
        let mut value = serde_json::to_value(Persisted::default()).unwrap();
        value.as_object_mut().unwrap().remove("target");
        fs::write(&path, value.to_string()).unwrap();
        assert_eq!(Persisted::load_strict(&path).unwrap().unwrap().target, None, "no target: loopback");
        for bad in [serde_json::json!("vm.internal"), serde_json::json!("0.0.0.0"), serde_json::json!(42)] {
            value["target"] = bad.clone();
            fs::write(&path, value.to_string()).unwrap();
            assert!(Persisted::load_strict(&path).is_err(), "{bad}");
            assert!(Persisted::load(&path).is_none(), "commands still treat it as no state");
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
