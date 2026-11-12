//! Non-interactive subcommands: `serve`, `token rotate`, `status`, `backup`, `cert renew`.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use tunnel_protocol::{ADMIN_TOKEN_PREFIX, CloseReason};

use crate::config::{Config, SERVICE_NAME, SERVICE_USER};
use crate::db::Db;
use crate::mode::{self, Mode};
use crate::state::AppState;
use crate::tls::{self, CertStatus};
use crate::tokens;
use crate::{acme, listener, metrics, purge, util};

const HEALTH_TOKEN_PREFIX: &str = "tnhlt_";

/// Time for `Close { Shutdown }` to reach clients before the process exits.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

pub async fn serve(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open(&cfg.db_path())?;
    let certs = tls::CertStore::new(cfg.cert_dir());
    certs.reload().with_context(|| {
        format!(
            "no usable certificate in {}; run `tunnel-server setup` or `tunnel-server cert renew`",
            cfg.cert_dir().display()
        )
    })?;
    let state = AppState::new(cfg, db, certs.clone());
    tracing::info!(not_after = certs.not_after(), "certificate loaded");

    if state.config.webrtc.enabled {
        match crate::turn_relay::Relay::start(&state.config, &state.metrics).await {
            Ok(relay) => {
                state.install_turn(relay);
            }
            // Previews matter more than WebRTC; keep serving and say why.
            Err(e) => tracing::error!(error = %format!("{e:#}"), "TURN relay failed to start; WebRTC is unavailable"),
        }
    }
    tokio::spawn(tls::watch(certs));
    tokio::spawn(acme::renew_loop(state.clone()));
    tokio::spawn(purge::run(state.clone()));
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(state).await {
                // Metrics are loopback-only diagnostics; serving previews matters more.
                tracing::error!(error = %format!("{e:#}"), "metrics listener failed");
            }
        });
    }

    tokio::select! {
        r = listener::run_https(state.clone()) => r.context("https listener")?,
        r = listener::run_http_redirect(state.clone()) => r.context("http redirect listener")?,
        r = shutdown_signal() => {
            r?;
            tracing::info!(tunnels = state.registry.len(), "shutting down");
            for live in state.registry.all() {
                live.close(CloseReason::Shutdown);
            }
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = term.recv() => {}
    }
    Ok(())
}

pub async fn token_rotate(config_path: &Path) -> anyhow::Result<()> {
    ensure_can_write(config_path, "token rotate")?;
    let mode = install_mode(config_path);
    let mut cfg = Config::load(config_path)?;
    let token = tokens::random_token(ADMIN_TOKEN_PREFIX);
    cfg.admin_token_hash = tokens::hash_token(&token);
    if mode == Mode::System {
        util::check_system_config_dir(config_path)?;
    }
    cfg.save(config_path)?;
    if mode == Mode::System {
        util::secure_system_config(config_path)?;
    }

    // The server reads the hash at startup; the old token stays valid until it restarts.
    if mode.systemctl_ok(&["try-restart", SERVICE_NAME]) {
        println!("Restarted {SERVICE_NAME} (if it was running); the old token no longer works.");
    } else {
        eprintln!("warning: restarting {SERVICE_NAME} failed; restart the service so the new token takes effect");
    }

    println!("New admin API token (shown once):");
    println!();
    println!("  {token}");
    println!();
    println!("Environment for API clients:");
    println!("  TUNNEL_API=https://{}", cfg.api_host);
    println!("  TUNNEL_ADMIN_TOKEN={token}");
    Ok(())
}

/// `health-token set`: a new `/healthz` token (shown once); `clear` reopens it.
pub async fn health_token(config_path: &Path, set: bool) -> anyhow::Result<()> {
    ensure_can_write(config_path, "health-token")?;
    let mode = install_mode(config_path);
    let mut cfg = Config::load(config_path)?;
    let token = set.then(|| tokens::random_token(HEALTH_TOKEN_PREFIX));
    cfg.health_token_hash = token.as_deref().map(tokens::hash_token);
    if mode == Mode::System {
        util::check_system_config_dir(config_path)?;
    }
    cfg.save(config_path)?;
    if mode == Mode::System {
        util::secure_system_config(config_path)?;
    }
    if !mode.systemctl_ok(&["try-restart", SERVICE_NAME]) {
        eprintln!("warning: restarting {SERVICE_NAME} failed; restart the service so the change takes effect");
    }
    match token {
        Some(token) => {
            println!("New health token (shown once). /healthz now answers only with it:");
            println!();
            println!("  curl -H 'Authorization: Bearer {token}' https://{}/healthz", cfg.api_host);
            println!("  https://{}/healthz?token={token}   (for monitors that cannot send headers)", cfg.api_host);
            println!();
            println!("It returns 200 when healthy, 503 when the database does not answer or the");
            println!("certificate is missing or expires within 7 days.");
        }
        None => println!("Health token removed; /healthz is open to anyone again."),
    }
    Ok(())
}

pub async fn status(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;

    println!("config:      {}", config_path.display());
    println!("api:         https://{}", cfg.api_host);
    println!("tunnel:      wss://{}", cfg.tunnel_host);
    println!("previews:    *.{}", cfg.preview_zone);
    let mode = install_mode(config_path);
    let kind = if mode == Mode::System { "root install" } else { "rootless install" };
    println!("service:     {} ({kind})", mode.service_state(SERVICE_NAME));
    if cfg.webrtc.enabled {
        let w = &cfg.webrtc;
        println!(
            "webrtc:      built-in relay, turn host {} (udp/tcp {}, tls 443, relays udp {}-{})",
            cfg.turn_host, w.stun_port, w.relay_min_port, w.relay_max_port
        );
    } else {
        println!("webrtc:      disabled");
    }

    println!("certificate: {}", cfg.cert_names().join(", "));
    match tls::cert_status(&cfg) {
        CertStatus::Valid { not_after } => println!("  valid until {}", describe_time(not_after)),
        CertStatus::NeedsRenewal => println!("  due for renewal (the server renews automatically; or `cert renew`)"),
        CertStatus::NamesChanged => println!("  does not cover the configured names; run `cert renew`"),
        CertStatus::Missing => println!("  missing; run `setup` or `cert renew`"),
    }

    let db_path = cfg.db_path();
    if db_path.exists() {
        let db = Db::open(&db_path)?;
        let (tunnels, tombstones, links, sessions) = db.counts().await?;
        drop(db);
        restore_ownership(config_path, &cfg)?;
        println!("database:    {}", db_path.display());
        println!("  tunnels {tunnels}, tombstones {tombstones}, access links {links}, gate sessions {sessions}");
    } else {
        println!("database:    {} (not created yet)", db_path.display());
    }
    Ok(())
}

pub async fn backup(config_path: &Path, out: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!out.exists(), "{} already exists; refusing to overwrite", out.display());
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db_path = cfg.db_path();
    anyhow::ensure!(db_path.exists(), "no database at {}", db_path.display());
    let db = Db::open(&db_path)?;
    // Holds token hashes and session ids: create it private (and atomically
    // refuse an existing file) before SQLite writes into it.
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)
            .with_context(|| format!("creating {}", out.display()))?;
    }
    if let Err(e) = db.backup_to(out.to_path_buf()).await {
        let _ = std::fs::remove_file(out);
        return Err(e);
    }
    drop(db);
    restore_ownership(config_path, &cfg)?;
    crate::config::set_mode(out, 0o600)?;
    println!("Wrote {}", out.display());
    Ok(())
}

/// Tables a restorable backup must have.
const REQUIRED_TABLES: &[&str] = &["tunnels", "access_links", "gate_sessions", "clients"];

/// Check that `path` is an intact Tunnel database.
fn check_backup(path: &Path) -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {}", path.display()))?;
    let version: i32 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).context("reading backup schema version")?;
    anyhow::ensure!(
        version != 0,
        "this backup was written by a pre-1.0.0 build (schema version 0) and cannot be restored"
    );
    anyhow::ensure!(
        version <= crate::db::SCHEMA_VERSION,
        "this backup is newer than this binary (schema version {version}; expected {})",
        crate::db::SCHEMA_VERSION
    );
    anyhow::ensure!(
        version == crate::db::SCHEMA_VERSION,
        "unsupported backup schema version {version}; expected {}",
        crate::db::SCHEMA_VERSION
    );
    let integrity: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).context("integrity check")?;
    anyhow::ensure!(integrity == "ok", "{} failed the integrity check: {integrity}", path.display());
    for table in REQUIRED_TABLES {
        let n: i64 =
            c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |r| {
                r.get(0)
            })?;
        anyhow::ensure!(n == 1, "{} is not a Tunnel database (no {table} table)", path.display());
    }
    Ok(())
}

/// Copy into a fresh private inode, never through a leftover restoring symlink.
fn restore_backup_file(backup: &Path, db_path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut source = std::fs::File::open(backup).with_context(|| format!("opening {}", backup.display()))?;
    let tmp = db_path.with_extension("db.restoring");
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut dest = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(util::O_NOFOLLOW | util::O_CLOEXEC)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let result = (|| -> anyhow::Result<()> {
        std::io::copy(&mut source, &mut dest).with_context(|| format!("copying {}", backup.display()))?;
        dest.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        dest.sync_all()?;
        std::fs::rename(&tmp, db_path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

pub async fn restore(config_path: &Path, backup: &Path) -> anyhow::Result<()> {
    ensure_can_write(config_path, "restore")?;
    let mode = install_mode(config_path);
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    check_backup(backup)?;
    let db_path = cfg.db_path();

    let was_running = mode.service_state(SERVICE_NAME) == "active";
    if was_running {
        anyhow::ensure!(mode.systemctl_ok(&["stop", SERVICE_NAME]), "stopping {SERVICE_NAME} failed");
    }
    let result = (|| -> anyhow::Result<Option<std::path::PathBuf>> {
        let kept = if db_path.exists() {
            let aside = db_path.with_extension(format!("db.before-restore-{}", tokens::now()));
            std::fs::rename(&db_path, &aside).with_context(|| format!("moving {} aside", db_path.display()))?;
            Some(aside)
        } else {
            None
        };
        // Stale WAL files belong to the old database and must not be replayed into the new one.
        for ext in ["db-wal", "db-shm"] {
            let _ = std::fs::remove_file(db_path.with_extension(ext));
        }
        restore_backup_file(backup, &db_path)?;
        restore_ownership(config_path, &cfg)?;
        Ok(kept)
    })();
    // Start again even if the swap failed, so a failed restore never leaves the server down.
    if was_running && !mode.systemctl_ok(&["start", SERVICE_NAME]) {
        eprintln!("warning: starting {SERVICE_NAME} failed; check `{}`", mode.journal_hint());
    }
    let kept = result?;
    println!("Restored {} from {}.", db_path.display(), backup.display());
    if let Some(k) = kept {
        println!("The previous database is kept at {}.", k.display());
    }
    if was_running {
        println!("Restarted {SERVICE_NAME}. Connected sandboxes reconnect on their own.");
    }
    Ok(())
}

pub async fn cert_renew(config_path: &Path, force: bool) -> anyhow::Result<()> {
    ensure_can_write(config_path, "cert renew")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let status = tls::cert_status(&cfg);
    if let (false, CertStatus::Valid { not_after }) = (force, status) {
        println!(
            "Certificate is valid until {}; nothing to do (use --force to renew anyway).",
            describe_time(not_after)
        );
        return Ok(());
    }
    println!("Issuing a certificate for {} ...", cfg.cert_names().join(", "));
    acme::issue(&cfg).await?;
    restore_ownership(config_path, &cfg)?;
    println!("Certificate written to {}.", cfg.cert_dir().display());
    println!("A running server loads it within a minute; no restart needed.");
    Ok(())
}

pub async fn client_add(config_path: &Path, name: &str) -> anyhow::Result<()> {
    ensure_can_write(config_path, "client add")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open(&cfg.db_path())?;
    let result = crate::clients::add(&db, &cfg, name).await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    match result {
        Ok(e) => {
            println!(
                "On {name}, run `tunnel login` and paste this when asked (works once, within {} minutes):\n",
                crate::clients::ENROLL_TTL_S / 60
            );
            println!("  {}\n", e.login_code);
            Ok(())
        }
        Err(crate::clients::AddError::Invalid(m)) => anyhow::bail!(m),
        Err(crate::clients::AddError::Taken) => {
            anyhow::bail!("client {name} exists; `client delete {name}` first to re-register it")
        }
        Err(crate::clients::AddError::Other(e)) => Err(e),
    }
}

pub async fn client_list(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open(&cfg.db_path())?;
    let clients = db.list_clients().await?;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    if clients.is_empty() {
        println!("No clients. Add one with `tunnel-server client add <name>`.");
        return Ok(());
    }
    println!("{:<24} {:<12} {:<22} {:>7}", "NAME", "STATUS", "LAST USED", "TUNNELS");
    for c in clients {
        let status = if c.enrolled { "active" } else { "not logged in" };
        let last = c.last_used_at.map(describe_ago).unwrap_or_else(|| "never".to_string());
        println!("{:<24} {:<12} {:<22} {:>7}", c.name, status, last, c.tunnels);
    }
    Ok(())
}

pub async fn client_delete(config_path: &Path, name: &str) -> anyhow::Result<()> {
    ensure_can_write(config_path, "client delete")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open(&cfg.db_path())?;
    let deleted = db.delete_client(name.to_string()).await?;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    match deleted {
        Some(tunnels) => {
            println!("Deleted client {name}; its token no longer works.");
            if !tunnels.is_empty() {
                println!("Its {} tunnel(s) stopped serving and close within 15 seconds.", tunnels.len());
            }
            Ok(())
        }
        None => anyhow::bail!("no client named {name}"),
    }
}

fn describe_ago(unix: i64) -> String {
    let s = (tokens::now() - unix).max(0);
    match s {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86_400),
    }
}

/// Root commands and configs in `/etc` belong to system installs.
fn install_mode(config_path: &Path) -> Mode {
    if mode::uid() == 0 || config_path.starts_with("/etc") { Mode::System } else { Mode::User }
}

/// Commands that write a root install's files must run as root.
fn ensure_can_write(config_path: &Path, what: &str) -> anyhow::Result<()> {
    if install_mode(config_path) == Mode::System {
        anyhow::ensure!(
            mode::uid() == 0,
            "`{what}` changes a root install ({}); run it with sudo",
            config_path.display()
        );
    }
    Ok(())
}

/// Root CLI operations use the same fixed data directory policy as setup.
fn check_privileged_data_dir(cfg: &Config) -> anyhow::Result<()> {
    if mode::uid() == 0 {
        util::check_data_dir(&cfg.data_dir, true)?;
    }
    Ok(())
}

/// Opening SQLite as root can leave root-owned files (the db, `-wal`, `-shm`)
/// that the service user cannot write; hand the data dir back.
fn restore_ownership(_config_path: &Path, cfg: &Config) -> anyhow::Result<()> {
    if mode::uid() == 0 {
        util::chown_recursive(&cfg.data_dir, SERVICE_USER)?;
    }
    Ok(())
}

fn describe_time(unix: i64) -> String {
    let days = (unix - tokens::now()) / 86_400;
    match time::OffsetDateTime::from_unix_timestamp(unix) {
        Ok(t) => format!("{} UTC ({days} days)", t.date()),
        Err(_) => format!("{unix} ({days} days)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tunnel-{name}-{}-{}", std::process::id(), rand::random::<u64>()))
    }

    #[test]
    fn restore_backup_file_does_not_follow_planted_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = test_dir("restore-symlink");
        std::fs::create_dir_all(&dir).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let backup = dir.join("backup.db");
        let db = dir.join("tunnel.db");
        let target = dir.join("untouched");
        std::fs::write(&backup, b"restored database").unwrap();
        std::fs::write(&db, b"old database").unwrap();
        std::fs::write(&target, b"keep me").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, db.with_extension("db.restoring")).unwrap();

        restore_backup_file(&backup, &db).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(std::fs::read(&db).unwrap(), b"restored database");
        assert_eq!(std::fs::metadata(&db).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!std::fs::symlink_metadata(&db).unwrap().file_type().is_symlink());
        assert!(!db.with_extension("db.restoring").exists());
    }

    #[test]
    fn restore_requires_current_schema_version() {
        let dir = test_dir("schema");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("backup.db");
        let db = rusqlite::Connection::open(&path).unwrap();
        for table in REQUIRED_TABLES {
            db.execute_batch(&format!("CREATE TABLE {table} (id INTEGER)")).unwrap();
        }
        assert!(check_backup(&path).unwrap_err().to_string().contains("pre-1.0.0"));
        db.pragma_update(None, "user_version", 1).unwrap();
        check_backup(&path).unwrap();
        db.pragma_update(None, "user_version", crate::db::SCHEMA_VERSION + 1).unwrap();
        assert!(check_backup(&path).unwrap_err().to_string().contains("newer than this binary"));
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn backups_pass_the_restore_check_and_junk_does_not() {
        let dir = test_dir("restore");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("live.db")).unwrap();
        db.backup_to(dir.join("backup.db")).await.unwrap();
        check_backup(&dir.join("backup.db")).unwrap();

        std::fs::write(dir.join("junk.db"), b"not a database").unwrap();
        assert!(check_backup(&dir.join("junk.db")).is_err());
        let other = rusqlite::Connection::open(dir.join("other.db")).unwrap();
        other.execute_batch("CREATE TABLE t (x)").unwrap();
        drop(other);
        assert!(check_backup(&dir.join("other.db")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `backup` pre-creates the target 0600 and empty; SQLite must accept it.
    #[tokio::test]
    async fn backup_into_precreated_private_file() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = test_dir("backup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(&dir.join("live.db")).unwrap();
        let out = dir.join("backup.db");
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&out).unwrap();
        db.backup_to(out.clone()).await.unwrap();
        check_backup(&out).unwrap();
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
