//! Filesystem locations and environment shared by commands and the daemon.

use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use tunnel_protocol::TUNNEL_TOKEN_PREFIX;

pub const ENV_TOKEN: &str = "TUNNEL_TOKEN";
pub const ENV_SERVER: &str = "TUNNEL_SERVER";
pub const ENV_ICE_FILE: &str = "TUNNEL_ICE_FILE";
pub const ENV_ICE_PORT: &str = "TUNNEL_ICE_PORT";
pub const DEFAULT_ICE_PORT: u16 = 47801;
const RUN_ICE_DIR: &str = "/run/tunnel";

pub struct Paths {
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub log_file: PathBuf,
    pub lock_file: PathBuf,
}

impl Paths {
    /// Resolve and create (0700) the per-user state directory.
    pub fn resolve() -> anyhow::Result<Self> {
        let dir = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            Some(xdg) if xdg.is_absolute() && xdg.is_dir() => xdg.join("tunnel"),
            _ => PathBuf::from(format!("/tmp/tunnel-{}", uid())),
        };
        ensure_private_dir(&dir)?;
        Ok(Self {
            socket: dir.join("daemon.sock"),
            state_file: dir.join("state.json"),
            log_file: dir.join("daemon.log"),
            lock_file: dir.join("daemon.lock"),
            dir,
        })
    }
}

/// Make server-controlled text safe to display on a terminal.
pub fn terminal_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_control() {
            escaped.extend(c.escape_unicode());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub fn validate_tunnel_token(token: &str) -> anyhow::Result<()> {
    if !token.starts_with(TUNNEL_TOKEN_PREFIX) {
        bail!(
            "not a Tunnel token (expected a {TUNNEL_TOKEN_PREFIX}… value); \
             it may belong to another tool, e.g. cloudflared"
        );
    }
    Ok(())
}

pub fn env_token() -> anyhow::Result<Option<String>> {
    parse_env_token(std::env::var_os(ENV_TOKEN))
}

fn parse_env_token(value: Option<OsString>) -> anyhow::Result<Option<String>> {
    let token = match value {
        None => return Ok(None),
        Some(value) => value.into_string().map_err(|_| {
            anyhow::anyhow!("{ENV_TOKEN} is set but is not valid UTF-8 (expected a {TUNNEL_TOKEN_PREFIX}… value)")
        })?,
    };
    if token.trim().is_empty() {
        return Ok(None);
    }
    validate_tunnel_token(&token).map_err(|e| anyhow::anyhow!("{ENV_TOKEN} is set but is {e}"))?;
    Ok(Some(token))
}

fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    // Checked after creation so a directory or symlink planted in /tmp by
    // another user is refused rather than trusted.
    let meta = fs::symlink_metadata(dir).with_context(|| format!("inspecting {}", dir.display()))?;
    if !meta.file_type().is_dir() {
        bail!("{} is not a directory; refusing to use it", dir.display());
    }
    if meta.uid() != uid() {
        bail!("{} is owned by uid {}, not {}; refusing to use it", dir.display(), meta.uid(), uid());
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    Ok(())
}

/// `$TUNNEL_ICE_FILE`, else `/run/tunnel/ice.json` when writable,
/// else `<state dir>/ice.json`.
pub fn ice_file(state_dir: &Path) -> PathBuf {
    if let Some(path) = env_nonempty(ENV_ICE_FILE) {
        return PathBuf::from(path);
    }
    let run = Path::new(RUN_ICE_DIR);
    if fs::create_dir_all(run).is_ok() && is_writable(run) {
        return run.join("ice.json");
    }
    state_dir.join("ice.json")
}

fn is_writable(dir: &Path) -> bool {
    let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

pub fn ice_port() -> u16 {
    match env_nonempty(ENV_ICE_PORT) {
        None => DEFAULT_ICE_PORT,
        Some(raw) => raw.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(value = %raw, "invalid {ENV_ICE_PORT}; using {DEFAULT_ICE_PORT}");
            DEFAULT_ICE_PORT
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_text_escapes_controls_and_preserves_printable_unicode() {
        assert_eq!(terminal_text("hello café 🦀"), "hello café 🦀");
        assert_eq!(terminal_text("\x1b[31m\r\n\t\0\x7f\u{85}"), r"\u{1b}[31m\u{d}\u{a}\u{9}\u{0}\u{7f}\u{85}");
    }

    #[test]
    fn tunnel_token_prefix_is_accepted() {
        assert!(validate_tunnel_token(&format!("{TUNNEL_TOKEN_PREFIX}test")).is_ok());
    }

    #[test]
    fn other_token_prefixes_are_rejected_without_disclosing_the_value() {
        for token in ["foreign-credential", "tncli_test", "tnadm_test", "TNTUN_test", " tntun_test"] {
            let message = validate_tunnel_token(token).unwrap_err().to_string();
            assert!(message.contains(TUNNEL_TOKEN_PREFIX));
            assert!(message.contains("cloudflared"));
            assert!(!message.contains(token));
        }
    }

    #[test]
    fn empty_or_blank_tunnel_tokens_are_rejected() {
        for token in ["", " ", "\t\n"] {
            assert!(validate_tunnel_token(token).is_err());
        }
    }

    #[test]
    fn unset_empty_or_blank_env_tokens_are_ignored() {
        assert!(parse_env_token(None).unwrap().is_none());
        for value in ["", " ", "\t\n", "\u{2003}"] {
            assert!(parse_env_token(Some(value.into())).unwrap().is_none());
        }
    }

    #[test]
    fn valid_env_token_is_preserved() {
        let token = format!("{TUNNEL_TOKEN_PREFIX}test");
        assert!(parse_env_token(Some(token.clone().into())).unwrap().as_deref() == Some(token.as_str()));
    }

    #[test]
    fn foreign_env_token_is_rejected_without_disclosing_the_value() {
        let token = "foreign-credential";
        let message = parse_env_token(Some(token.into())).unwrap_err().to_string();
        assert!(message.contains(ENV_TOKEN));
        assert!(message.contains("cloudflared"));
        assert!(!message.contains(token));
    }

    #[test]
    fn non_unicode_env_token_is_rejected_without_disclosing_the_value() {
        use std::os::unix::ffi::OsStringExt;

        let value = OsString::from_vec(b"foreign-credential\xff".to_vec());
        let message = parse_env_token(Some(value)).unwrap_err().to_string();
        assert!(message.contains("not valid UTF-8"));
        assert!(!message.contains("foreign-credential"));
    }
}
