//! Install mode: a root (system) install or a rootless (user) install.
//!
//! The mode follows the effective user: root manages `/etc`, `/var/lib`, a
//! dedicated service user, and a system unit; anyone else gets XDG paths
//! under their home and a systemd *user* unit. A rootless install needs two
//! one-time root changes (unprivileged ports from 80, lingering), which setup
//! checks and prints as a single command.

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::Context;

use crate::config::SERVICE_NAME;

pub const SYSTEM_CONFIG_DIR: &str = "/etc/tunnel-server";
pub const SYSTEM_CONFIG_PATH: &str = "/etc/tunnel-server/config.toml";
pub const SYSTEM_DATA_DIR: &str = "/var/lib/tunnel";
pub const SYSTEM_BINARY_PATH: &str = "/usr/local/bin/tunnel-server";
/// Directory name of the rootless config under `$XDG_CONFIG_HOME` (same name as the system one).
pub const USER_CONFIG_DIR_NAME: &str = "tunnel-server";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    System,
    User,
}

impl Mode {
    pub fn current() -> Self {
        if uid() == 0 { Self::System } else { Self::User }
    }

    pub fn is_user(self) -> bool {
        self == Self::User
    }

    pub fn config_path(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from(SYSTEM_CONFIG_PATH),
            Self::User => user_config_path(&xdg("XDG_CONFIG_HOME", ".config")?),
        })
    }

    pub fn data_dir(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from(SYSTEM_DATA_DIR),
            Self::User => xdg("XDG_DATA_HOME", ".local/share")?.join("tunnel"),
        })
    }

    pub fn binary_path(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from(SYSTEM_BINARY_PATH),
            Self::User => home()?.join(".local/bin/tunnel-server"),
        })
    }

    pub fn unit_dir(self) -> anyhow::Result<PathBuf> {
        Ok(match self {
            Self::System => PathBuf::from("/etc/systemd/system"),
            Self::User => xdg("XDG_CONFIG_HOME", ".config")?.join("systemd/user"),
        })
    }

    /// `systemctl` (or `systemctl --user`) with the environment a user
    /// manager needs even when no login session set it (e.g. a remote runner).
    pub fn systemctl(self) -> Command {
        let mut cmd = Command::new("systemctl");
        if self.is_user() {
            cmd.arg("--user");
            if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
                let runtime = format!("/run/user/{}", uid());
                cmd.env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={runtime}/bus"));
                cmd.env("XDG_RUNTIME_DIR", runtime);
            }
        }
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Run `systemctl`; `Err` carries its stderr.
    pub fn systemctl_run(self, args: &[&str]) -> anyhow::Result<()> {
        let out =
            self.systemctl().args(args).output().with_context(|| format!("running systemctl {}", args.join(" ")))?;
        anyhow::ensure!(
            out.status.success(),
            "systemctl {}{} failed: {}",
            if self.is_user() { "--user " } else { "" },
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        Ok(())
    }

    pub fn systemctl_ok(self, args: &[&str]) -> bool {
        self.systemctl().args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
    }

    /// `systemctl is-active` prints the state even when it exits non-zero.
    pub fn service_state(self, unit: &str) -> String {
        match self.systemctl().args(["is-active", unit]).output() {
            Ok(out) => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() { "unknown".to_string() } else { s }
            }
            Err(_) => "unknown (systemctl unavailable)".to_string(),
        }
    }

    /// How to read the service log in this mode.
    pub fn journal_hint(self) -> String {
        match self {
            Self::System => format!("journalctl -u {SERVICE_NAME}"),
            Self::User => format!("journalctl --user -u {SERVICE_NAME}"),
        }
    }
}

pub fn uid() -> u32 {
    std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(u32::MAX)
}

pub fn username() -> anyhow::Result<String> {
    if let Ok(u) = std::env::var("USER")
        && !u.is_empty()
    {
        return Ok(u);
    }
    let out = Command::new("id").arg("-un").output().context("running id -un")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Rootless config file under `$XDG_CONFIG_HOME`, named like `/etc/tunnel-server`
/// (the client keeps its own `$XDG_CONFIG_HOME/tunnel`).
fn user_config_path(config_home: &std::path::Path) -> PathBuf {
    config_home.join(USER_CONFIG_DIR_NAME).join("config.toml")
}

fn home() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).context("HOME is not set")?;
    Ok(PathBuf::from(home))
}

fn xdg(var: &str, fallback: &str) -> anyhow::Result<PathBuf> {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(v) if PathBuf::from(&v).is_absolute() => Ok(PathBuf::from(v)),
        _ => Ok(home()?.join(fallback)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_config_path_is_inside_system_config_dir() {
        assert_eq!(std::path::Path::new(SYSTEM_CONFIG_PATH).parent(), Some(std::path::Path::new(SYSTEM_CONFIG_DIR)));
        assert_eq!(SYSTEM_CONFIG_DIR, "/etc/tunnel-server");
        assert_eq!(SYSTEM_DATA_DIR, "/var/lib/tunnel");
    }

    #[test]
    fn user_config_path_matches_system_config_dir_name() {
        assert_eq!(
            user_config_path(std::path::Path::new("/home/test/.config")),
            PathBuf::from("/home/test/.config/tunnel-server/config.toml")
        );
        assert_eq!(
            Some(std::ffi::OsStr::new(USER_CONFIG_DIR_NAME)),
            std::path::Path::new(SYSTEM_CONFIG_DIR).file_name()
        );
    }
}
