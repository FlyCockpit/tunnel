//! Install mode: a root (system) install or a rootless (user) install.
//!
//! The mode follows the effective user: root manages `/etc`, `/var/lib`, a
//! dedicated service user, and a system unit; anyone else gets XDG paths
//! under their home and a systemd *user* unit. A rootless install needs two
//! one-time root changes (unprivileged ports from 80, lingering), which setup
//! checks and prints as a single command.

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;

use crate::config::{DEFAULT_DATA_DIR, SERVICE_NAME, SERVICE_USER};
use crate::files;

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

/// Reject unsafe data paths before setup or privileged CLI work. System installs
/// deliberately support ONLY the default data directory: a config file cannot
/// authorize root to change ownership of a different tree. All existing path
/// components must be real directories; system parents must be root-owned and
/// not writable by another account. Rootless installs may use a dedicated path.
pub fn check_data_dir(path: &Path, privileged: bool) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let raw = path.as_os_str().as_bytes();
    anyhow::ensure!(path.is_absolute(), "data_dir must be absolute");
    anyhow::ensure!(
        raw[1..].split(|b| *b == b'/').all(|p| !p.is_empty() && p != b"." && p != b".."),
        "data_dir must be normalized, without empty, . or .. components"
    );
    let system_dirs = [
        "/",
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/var",
        "/var/lib",
        "/var/log",
        "/var/cache",
        "/var/tmp",
        "/home",
        "/root",
        "/run",
        "/tmp",
        "/opt",
        "/srv",
        "/mnt",
        "/media",
        "/lost+found",
    ];
    anyhow::ensure!(!system_dirs.iter().any(|p| path == Path::new(p)), "data_dir cannot be a system directory");
    for forbidden in
        ["/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot", "/dev", "/proc", "/sys"]
    {
        anyhow::ensure!(!path.starts_with(forbidden), "data_dir cannot be inside {forbidden}");
    }
    if privileged {
        anyhow::ensure!(path == Path::new(DEFAULT_DATA_DIR), "root installs require data_dir = {}", DEFAULT_DATA_DIR);
    }
    for component in path.ancestors() {
        match std::fs::symlink_metadata(component) {
            Ok(meta) => {
                anyhow::ensure!(
                    !meta.file_type().is_symlink() && meta.is_dir(),
                    "data_dir component {} must be a directory, not a symlink",
                    component.display()
                );
                if privileged && component != path {
                    anyhow::ensure!(
                        meta.uid() == 0 && meta.mode() & 0o022 == 0,
                        "data_dir parent {} must be root-owned and not group/world writable",
                        component.display()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Restore the system config's root:service ownership after an atomic write.
/// The containing directory is root:service 0750, so the service cannot replace
/// either the config or its directory entry. Never operate through a symlink.
pub fn secure_system_config(path: &Path) -> anyhow::Result<()> {
    check_system_config_dir(path)?;
    let file = std::fs::OpenOptions::new().read(true).custom_flags(files::O_NOFOLLOW).open(path)?; // O_NOFOLLOW
    anyhow::ensure!(file.metadata()?.is_file(), "config must be a regular file");
    files::set_owner_fd(&file, 0, files::group_id(SERVICE_USER)?)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    Ok(())
}

/// Check before creating/replacing a system config, not only after writing it.
/// Missing directories may be created by root; existing parents must be trusted.
pub fn check_system_config_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(path.is_absolute(), "system config path must be absolute");
    anyhow::ensure!(
        !path.components().any(|c| c == std::path::Component::ParentDir),
        "system config path must not contain .."
    );
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("config has no parent"))?;
    for component in parent.ancestors() {
        let meta = match std::fs::symlink_metadata(component) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        anyhow::ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "config directory must not contain symlinks");
        anyhow::ensure!(
            meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "config directory {} must be root-owned and not group/world writable",
            component.display()
        );
    }
    Ok(())
}

/// Recursively restore service ownership, without following symlinks or crossing
/// filesystems. The guard is inside the entry point so no privileged caller can
/// forget it. Directory descriptors prevent rename/symlink races during descent.
pub fn chown_recursive(path: &Path, owner: &str) -> anyhow::Result<()> {
    check_data_dir(path, uid() == 0)?;
    files::chown_tree_ids(path, files::account_id(owner, "-u")?, files::group_id(owner)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tunnel-util-{name}-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    #[test]
    fn data_dir_guard_rejects_system_relative_and_non_normal_paths() {
        for path in [
            "/",
            "/etc",
            "/etc/tunnel-server",
            "relative/tunnel",
            "/var/lib/../tunnel",
            "/var/lib/./tunnel",
            "/var//lib/tunnel",
            "/var/lib",
            "/home",
            "/tmp",
            "/proc/self",
        ] {
            assert!(check_data_dir(Path::new(path), false).is_err(), "accepted {path}");
        }
        #[cfg(target_os = "linux")]
        check_data_dir(Path::new(DEFAULT_DATA_DIR), true).unwrap();
        assert!(check_data_dir(Path::new("/var/lib/other-tunnel"), true).is_err());
    }

    #[test]
    fn data_dir_guard_rejects_symlink_and_symlinked_ancestor() {
        let dir = test_dir("guard");
        std::fs::create_dir(dir.join("real")).unwrap();
        symlink(dir.join("real"), dir.join("link")).unwrap();
        assert!(check_data_dir(&dir.join("link"), false).is_err());
        assert!(check_data_dir(&dir.join("link/child"), false).is_err());
        check_data_dir(&dir.join("real"), false).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
