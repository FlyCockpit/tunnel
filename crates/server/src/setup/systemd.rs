//! systemd units for system and rootless installs. System installs run as the
//! service account with kernel, filesystem, process and syscall restrictions.
//! User units use restrictions that work without privileged mount namespaces.

use std::path::Path;

use anyhow::Context;

use crate::config::{Config, SERVICE_NAME, SERVICE_USER};
use crate::mode::Mode;
use crate::util::write_if_changed;

/// Quote a systemd word (systemd.syntax), including specifier escaping. ExecStart
/// uses the ':' prefix to disable environment substitution, preserving literal '$'.
fn unit_path(path: &Path) -> String {
    let mut quoted = String::from("\"");
    for c in path.to_string_lossy().chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '%' => quoted.push_str("%%"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() => quoted.push_str(&format!("\\x{:02x}", c as u32)),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

fn user_service_unit(bin: &Path, config_path: &Path) -> String {
    format!(
        "[Unit]
Description=Tunnel preview relay

[Service]
Type=simple
ExecStart=:{bin} serve --config {config}
NoNewPrivileges=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=default.target
",
        bin = unit_path(bin),
        config = unit_path(config_path),
    )
}

// ring uses compiled crypto code and bundled SQLite does not JIT, so neither
// needs writable executable mappings. The server uses Tokio sockets and DNS,
// not interface enumeration, so AF_NETLINK is unnecessary. ACME and SQLite
// retain write access to the data directory; serve never rewrites config.toml.
fn service_unit(cfg: &Config, bin: &Path, config_path: &Path) -> String {
    format!(
        "[Unit]
Description=Tunnel preview relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
ExecStart=:{bin} serve --config {config}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
PrivateDevices=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadOnlyPaths={config_dir}
ReadWritePaths={data}
ProtectProc=invisible
ProcSubset=pid
KeyringMode=private
RemoveIPC=true
UMask=0027
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
",
        user = SERVICE_USER,
        bin = unit_path(bin),
        config = unit_path(config_path),
        data = unit_path(&cfg.data_dir),
        config_dir = unit_path(config_path.parent().expect("config path has a parent")),
    )
}

/// Copy the running binary to the service path when it differs (write to a
/// temporary file and rename, so a running server keeps its old inode).
/// Returns `true` if the installed binary changed.
fn install_binary(target: &Path) -> anyhow::Result<bool> {
    let current = std::env::current_exe().context("locating the running binary")?;
    let current = current.canonicalize().unwrap_or(current);
    if target.canonicalize().ok().as_deref() == Some(current.as_path()) {
        return Ok(false);
    }
    let new = std::fs::read(&current).with_context(|| format!("reading {}", current.display()))?;
    if std::fs::read(target).ok().as_deref() == Some(new.as_slice()) {
        return Ok(false);
    }
    let dir = target.parent().context("binary path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = target.with_extension("new");
    std::fs::write(&tmp, &new).with_context(|| format!("writing {}", tmp.display()))?;
    crate::config::set_mode(&tmp, 0o755)?;
    std::fs::rename(&tmp, target).with_context(|| format!("installing {}", target.display()))?;
    println!("Installed {}", target.display());
    Ok(true)
}

fn running_binary_changed(exe: &str, bin: &Path) -> bool {
    exe.ends_with(" (deleted)") || Path::new(exe) != bin
}

/// The installer may already have replaced the binary before execing setup.
/// In that case install_binary sees no change, but the service has the old inode.
fn service_binary_changed(mode: Mode, unit: &str, bin: &Path) -> anyhow::Result<bool> {
    let out = mode
        .systemctl()
        .args(["show", "-p", "MainPID", "--value", unit])
        .output()
        .context("reading service MainPID")?;
    anyhow::ensure!(out.status.success(), "could not read MainPID for {unit}");
    let pid = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>().context("parsing service MainPID")?;
    // The process may have exited since is-active; restart to ensure it runs the installed binary.
    if pid == 0 {
        return Ok(true);
    }
    let exe = match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(exe) => exe,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e).context("reading service executable"),
    };
    let bin = bin.canonicalize().unwrap_or_else(|_| bin.to_path_buf());
    Ok(running_binary_changed(&exe.to_string_lossy(), &bin))
}

/// Identify the executable on an ExecStart line, not mentions in comments or
/// other directives. Accept systemd command prefixes and quoted paths.
pub(super) fn is_tunnel_unit(unit: &str) -> bool {
    unit.lines().any(|line| {
        let Some((key, command)) = line.trim().split_once('=') else { return false };
        if key.trim() != "ExecStart" {
            return false;
        }
        let command = command.trim().trim_start_matches(['-', '@', ':', '+', '!']);
        let executable = if let Some(command) = command.strip_prefix('"') {
            command.split('"').next()
        } else if let Some(command) = command.strip_prefix('\'') {
            command.split('\'').next()
        } else {
            command.split_whitespace().next()
        };
        executable.is_some_and(|exe| Path::new(exe).file_name().is_some_and(|name| name == "tunnel-server"))
    })
}

pub(super) fn check_existing_unit(path: &Path, unit: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_tunnel_unit(unit),
        "an unrelated {SERVICE_NAME}.service exists at {}; refusing to overwrite",
        path.display()
    );
    Ok(())
}

/// Install the binary and units, reload systemd if any changed, and make sure
/// the server runs. It restarts only when the binary, unit, or `config.toml` changed.
pub fn install(cfg: &Config, config_path: &Path, config_changed: bool, mode: Mode) -> anyhow::Result<()> {
    let unit_dir = mode.unit_dir()?;
    let service_file = format!("{SERVICE_NAME}.service");
    let unit_path = unit_dir.join(&service_file);
    match std::fs::read_to_string(&unit_path) {
        Ok(unit) => check_existing_unit(&unit_path, &unit)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", unit_path.display())),
    }
    let bin = mode.binary_path()?;
    let binary_changed = install_binary(&bin)?;
    std::fs::create_dir_all(&unit_dir).with_context(|| format!("creating {}", unit_dir.display()))?;

    let unit = match mode {
        Mode::System => service_unit(cfg, &bin, config_path),
        Mode::User => user_service_unit(&bin, config_path),
    };
    let service_changed = write_if_changed(&unit_path, unit.as_bytes(), 0o644)?;
    if service_changed {
        mode.systemctl_run(&["daemon-reload"])?;
    }

    let was_active = mode.systemctl_ok(&["is-active", "--quiet", &service_file]);
    let binary_changed = binary_changed || (was_active && service_binary_changed(mode, &service_file, &bin)?);
    mode.systemctl_run(&["enable", &service_file])?;
    if !was_active {
        println!("Starting {service_file}");
        mode.systemctl_run(&["start", &service_file])?;
    } else if service_changed || config_changed || binary_changed {
        println!("Restarting {service_file}");
        mode.systemctl_run(&["restart", &service_file])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_binary_detects_replaced_or_different_executables() {
        for bin in ["/usr/local/bin/tunnel-server", "/home/test/.local/bin/tunnel-server"] {
            let path = Path::new(bin);
            assert!(!running_binary_changed(bin, path));
            assert!(running_binary_changed(&format!("{bin} (deleted)"), path));
            assert!(running_binary_changed("/tmp/tunnel-server", path));
        }
    }

    #[test]
    fn unit_identity_requires_tunnel_server_exec_start() {
        for unit in [
            "[Service]\nExecStart=/usr/local/bin/tunnel-server serve\n",
            "  ExecStart = :\"/home/test user/bin/tunnel-server\" serve --config config.toml\n",
            "ExecStart=-/usr/bin/tunnel-server serve",
            "ExecStart=tunnel-server serve",
            "ExecStart='/usr/local/bin/tunnel-server' serve",
        ] {
            assert!(is_tunnel_unit(unit));
        }
        for unit in [
            "",
            "[Service]\nExecStart=/usr/bin/autossh -N example.com\n",
            "# ExecStart=/usr/local/bin/tunnel-server serve\n",
            "; ExecStart=/usr/local/bin/tunnel-server serve\n",
            "Description=tunnel-server\nExecStart=/usr/bin/ssh -N example.com\n",
            "ExecStartPre=/usr/local/bin/tunnel-server check\nExecStart=/usr/bin/ssh\n",
            "ExecStart=/usr/bin/echo tunnel-server\n",
            "ExecStart=/usr/bin/other-tunnel-server\n",
        ] {
            assert!(!is_tunnel_unit(unit));
        }
    }

    #[test]
    fn unrelated_system_and_user_units_are_refused() {
        for path in
            ["/etc/systemd/system/tunnel-server.service", "/home/test/.config/systemd/user/tunnel-server.service"]
        {
            let error = check_existing_unit(Path::new(path), "[Service]\nExecStart=/usr/bin/autossh -N host\n")
                .unwrap_err()
                .to_string();
            assert_eq!(error, format!("an unrelated tunnel-server.service exists at {path}; refusing to overwrite"));
            let unit =
                user_service_unit(Path::new("/home/test/bin/tunnel-server"), Path::new("/home/test/config.toml"));
            check_existing_unit(Path::new(path), &unit).unwrap();
        }
        let cfg = super::super::fresh_config().unwrap();
        let unit =
            service_unit(&cfg, Path::new("/usr/local/bin/tunnel-server"), Path::new("/etc/tunnel-server/config.toml"));
        check_existing_unit(Path::new("/etc/systemd/system/tunnel-server.service"), &unit).unwrap();
    }

    #[test]
    fn system_unit_preserves_network_and_data_access_with_hardening() {
        let cfg = super::super::fresh_config().unwrap();
        let unit =
            service_unit(&cfg, Path::new("/usr/local/bin/tunnel-server"), Path::new("/etc/tunnel-server/config.toml"));
        for directive in [
            "User=tunnel-server",
            "Group=tunnel-server",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "PrivateTmp=true",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectKernelLogs=true",
            "ProtectControlGroups=true",
            "ProtectClock=true",
            "ProtectHostname=true",
            "PrivateDevices=true",
            "RestrictNamespaces=true",
            "RestrictRealtime=true",
            "RestrictSUIDSGID=true",
            "LockPersonality=true",
            "MemoryDenyWriteExecute=true",
            "SystemCallArchitectures=native",
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~@privileged @resources",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "ReadOnlyPaths=\"/etc/tunnel-server\"",
            "ReadWritePaths=\"/var/lib/tunnel\"",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "KeyringMode=private",
            "RemoveIPC=true",
        ] {
            assert!(unit.lines().any(|line| line == directive), "missing {directive}");
        }
        assert!(!unit.contains("AF_NETLINK"));
    }

    #[test]
    fn rootless_unit_uses_unprivileged_restrictions() {
        let unit = user_service_unit(Path::new("/home/test/bin/server"), Path::new("/home/test/config.toml"));
        assert!(unit.contains("NoNewPrivileges=true"));
        assert!(unit.contains("MemoryDenyWriteExecute=true"));
        assert!(unit.contains("SystemCallFilter=@system-service"));
        for privileged in [
            "User=",
            "Group=",
            "ProtectSystem=",
            "ProtectHome=",
            "PrivateDevices=",
            "ProtectProc=",
            "AmbientCapabilities=",
            "ReadWritePaths=",
        ] {
            assert!(!unit.contains(privileged), "rootless unit contains {privileged}");
        }
    }

    #[test]
    fn unit_paths_quote_spaces_quotes_backslashes_specifiers_and_controls() {
        assert_eq!(unit_path(Path::new("/a b/\"c\\d%h$HOME\n\t")), "\"/a b/\\\"c\\\\d%%h$HOME\\n\\t\"");
        let bin = Path::new("/a b/bin");
        let config = Path::new("/a b/config %h $HOME.toml");
        let expected = "ExecStart=:\"/a b/bin\" serve --config \"/a b/config %%h $HOME.toml\"";
        assert!(user_service_unit(bin, config).lines().any(|line| line == expected));
        let mut cfg = super::super::fresh_config().unwrap();
        cfg.data_dir = "/a b/data".into();
        let system = service_unit(&cfg, bin, config);
        assert!(system.lines().any(|line| line == expected));
        assert!(system.contains("ReadWritePaths=\"/a b/data\""));
        assert!(system.contains("ReadOnlyPaths=\"/a b\""));
    }
}
