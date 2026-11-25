//! Non-interactive subcommands: `serve`, `token rotate`, `status`, `backup`,
//! `cert renew`, `client …`, `service …`.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use tunnel_protocol::{ADMIN_TOKEN_PREFIX, CloseReason};

use crate::config::mode::{self, Mode};
use crate::config::{Config, SERVICE_NAME, SERVICE_USER};
use crate::db::Db;
use crate::state::AppState;
use crate::tls::{self, CertStatus};
use crate::tokens;
use crate::{jobs::acme, jobs::purge, listener, metrics};

pub mod setup;

const HEALTH_TOKEN_PREFIX: &str = "tnhlt_";

/// Time for `Close { Shutdown }` to reach clients before the process exits.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

pub async fn serve(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
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
    if let Err(e) = state.traffic.preload(&state.db).await {
        tracing::warn!(error = %format!("{e:#}"), "loading users over their traffic cap failed");
    }
    {
        let state = state.clone();
        tokio::spawn(async move { state.traffic.run(&state.db, &state.registry).await });
    }
    {
        let state = state.clone();
        tokio::spawn(async move { state.traffic.enforce(&state.registry).await });
    }
    {
        let state = state.clone();
        tokio::spawn(async move {
            let listen = state.config.metrics_listen;
            let render =
                move || state.metrics.render(state.registry.len(), state.certs.not_after(), &state.traffic.snapshot());
            if let Err(e) = metrics::serve(listen, render).await {
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
            // Keep the last minute of traffic counts.
            match tokio::time::timeout(Duration::from_secs(5), state.traffic.flush(&state.db, &state.registry)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %format!("{e:#}"), "final traffic flush failed"),
                Err(_) => tracing::warn!("final traffic flush timed out"),
            }
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
        mode::check_system_config_dir(config_path)?;
    }
    cfg.save(config_path)?;
    if mode == Mode::System {
        mode::secure_system_config(config_path)?;
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
        mode::check_system_config_dir(config_path)?;
    }
    cfg.save(config_path)?;
    if mode == Mode::System {
        mode::secure_system_config(config_path)?;
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
        CertStatus::Expired => println!("  expired; replace your own certificate"),
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
    crate::files::set_mode(out, 0o600)?;
    println!("Wrote {}", out.display());
    Ok(())
}

/// Tables a restorable backup must have.
const REQUIRED_TABLES: &[&str] = &["tunnels", "access_links", "gate_sessions", "clients"];

/// Check that `path` is an intact Tunnel database.
fn check_backup(path: &Path) -> anyhow::Result<()> {
    use rusqlite::{Connection, OpenFlags};
    crate::db::ensure_plain_path(path)?;
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening {}", path.display()))?;
    let version: i32 = c.query_row("PRAGMA user_version", [], |r| r.get(0)).context("reading backup schema version")?;
    anyhow::ensure!(
        version == crate::db::SCHEMA_VERSION,
        "unsupported backup schema version {version}; this build needs schema version {}",
        crate::db::SCHEMA_VERSION
    );
    let integrity: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).context("integrity check")?;
    anyhow::ensure!(integrity == "ok", "{} failed the integrity check: {integrity}", path.display());
    crate::db::check_schema(&c).with_context(|| format!("checking {}", path.display()))?;
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
        .custom_flags(crate::files::O_NOFOLLOW | crate::files::O_CLOEXEC)
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

/// Keep the current database as `<db>.before-restore-<time>`, private even
/// when an older build created it looser than 0600.
fn move_aside(db_path: &Path) -> anyhow::Result<std::path::PathBuf> {
    // Before the rename, so a failure leaves the database where it was.
    crate::db::ensure_not_symlink(db_path)?;
    crate::files::set_mode_nofollow(db_path, 0o600).with_context(|| format!("making {} private", db_path.display()))?;
    let aside = db_path.with_extension(format!("db.before-restore-{}", tokens::now()));
    std::fs::rename(db_path, &aside).with_context(|| format!("moving {} aside", db_path.display()))?;
    Ok(aside)
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
        let kept = if db_path.exists() { Some(move_aside(&db_path)?) } else { None };
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

pub async fn client_add(config_path: &Path, name: &str, user: Option<&str>) -> anyhow::Result<()> {
    ensure_can_write(config_path, "client add")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    // Without --user the machine is the owner's; on a server used without the
    // web UI that account is created here, without a password.
    let owner = match user {
        Some(u) => db.user_by_name(u.to_ascii_lowercase()).await,
        None => db.ensure_owner().await.map(Some),
    };
    let owner = match owner {
        Ok(Some(o)) => o,
        other => {
            drop(db);
            restore_ownership(config_path, &cfg)?;
            other?;
            anyhow::bail!("no user {}; see `tunnel-server user list`", user.unwrap_or_default());
        }
    };
    let result = crate::clients::add(&db, &cfg, name, &owner.id, None).await;
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
        Err(crate::clients::AddError::Quota { limit, .. }) => {
            anyhow::bail!(
                "{} has reached their machine limit ({limit}); raise it in the web UI's Users page",
                owner.username
            )
        }
        Err(crate::clients::AddError::NoUser) => anyhow::bail!("{} is disabled", owner.username),
        Err(crate::clients::AddError::Other(e)) => Err(e),
    }
}

/// One-time owner link: sign up as the owner (first run) or reset the
/// owner's password and two-factor sign-in (recovery). Anyone with a shell
/// here as the service user can already do anything, so this is the
/// recovery path too.
/// With `first_run`, nothing happens once the owner has signed up (setup
/// calls it so a fresh install ends with the owner's link).
pub async fn admin_link(config_path: &Path, first_run: bool) -> anyhow::Result<()> {
    use crate::accounts::InviteKind;
    use crate::role::Role;
    ensure_can_write(config_path, "admin link")?;
    let cfg = Config::load(config_path)?;
    let Some(ui) = cfg.ui_host.clone() else {
        anyhow::bail!("the web UI is off: turn it on with `tunnel-server setup --ui-host <name>`");
    };
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let owner = db.owner().await?;
    // An owner created for machines without the UI has no password yet: it signs up.
    let unclaimed = db.owner_without_password().await?;
    if first_run && owner.is_some() && !unclaimed {
        return Ok(());
    }
    let kind = if owner.is_some() && !unclaimed { InviteKind::OwnerReset } else { InviteKind::OwnerSetup };
    let token = crate::tokens::random_token(crate::ui::INVITE_PREFIX);
    let ttl = crate::ui::OWNER_LINK_TTL_S;
    let result = db
        .create_invite(
            format!("in{}", crate::tokens::random_tunnel_id()),
            crate::tokens::hash_token(&token),
            kind,
            Role::Owner,
            None,
            None,
            crate::tokens::now() + ttl,
        )
        .await;
    if result.is_ok() {
        let _ = db.audit(None, if owner.is_some() { "owner_reset_link" } else { "owner_setup_link" }, None, None).await;
    }
    drop(db);
    restore_ownership(config_path, &cfg)?;
    result?;
    match owner.filter(|_| !unclaimed) {
        Some(o) => println!(
            "Open this link within {} minutes to set a new password for the owner {} \
             (two-factor sign-in is turned off; turn it on again afterwards). It works once:\n",
            ttl / 60,
            o.username
        ),
        None => println!("Open this link within {} minutes to create the owner account. It works once:\n", ttl / 60),
    }
    println!("  https://{ui}/invite#{token}\n");
    Ok(())
}

pub async fn user_list(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let users = db.list_users(crate::traffic::month_of(crate::tokens::now())).await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    let users = users?;
    if users.is_empty() {
        println!("No users yet; `tunnel-server admin link` creates the owner.");
        return Ok(());
    }
    println!("{:<24} {:<8} {:<9} {:>8} {:>8} {:>4}", "USERNAME", "ROLE", "STATUS", "MACHINES", "TUNNELS", "2FA");
    let defaults = crate::limits::Defaults::new(&cfg.limits);
    let of = |n: Option<u64>| n.map_or_else(|| "-".to_string(), |n| n.to_string());
    for u in users {
        let limits = defaults.effective(u.user.role, &u.user.limits);
        println!(
            "{:<24} {:<8} {:<9} {:>8} {:>8} {:>4}",
            u.user.username,
            u.user.role.as_str(),
            if u.user.disabled { "disabled" } else { "active" },
            format!("{}/{}", u.clients, of(limits.machines)),
            format!("{}/{}", u.tunnels, of(limits.tunnels)),
            if u.user.totp { "on" } else { "off" }
        );
    }
    println!("(\"-\": unlimited; admins and the owner set per-user limits in the web UI's Users page)");
    Ok(())
}

/// `user invite`: a sign-up link made from the server's shell (as the owner would).
pub async fn user_invite(config_path: &Path, role: crate::role::Role, hours: u32) -> anyhow::Result<()> {
    use crate::accounts::InviteKind;
    ensure_can_write(config_path, "user invite")?;
    let cfg = Config::load(config_path)?;
    let Some(ui) = cfg.ui_host.clone() else {
        anyhow::bail!("the web UI is off: turn it on with `tunnel-server setup --ui-host <name>`");
    };
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let token = crate::tokens::random_token(crate::ui::INVITE_PREFIX);
    let id = format!("in{}", crate::tokens::random_tunnel_id());
    let expires_at = crate::tokens::now() + i64::from(hours) * 3600;
    let result = db
        .create_invite(id.clone(), crate::tokens::hash_token(&token), InviteKind::Invite, role, None, None, expires_at)
        .await;
    if result.is_ok() {
        let _ = db.audit(None, "invite_created", Some(format!("{id} {} (server shell)", role.as_str())), None).await;
    }
    drop(db);
    restore_ownership(config_path, &cfg)?;
    result?;
    println!(
        "Send this link to the new {}; it works once, within {hours} hour(s), and is a credential:\n",
        role.as_str()
    );
    println!("  https://{ui}/invite#{token}\n");
    println!("Withdraw it in the web UI (Users) if it is not needed any more.");
    Ok(())
}

/// `user reset`: a sign-in reset link for an account other than the owner's.
pub async fn user_reset(config_path: &Path, username: &str, hours: u32) -> anyhow::Result<()> {
    use crate::accounts::ResetLinkError;
    ensure_can_write(config_path, "user reset")?;
    let cfg = Config::load(config_path)?;
    let Some(ui) = cfg.ui_host.clone() else {
        anyhow::bail!("the web UI is off: turn it on with `tunnel-server setup --ui-host <name>`");
    };
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let username = username.to_ascii_lowercase();
    let token = crate::tokens::random_token(crate::ui::INVITE_PREFIX);
    let result = async {
        let Some(user) = db.user_by_name(username.clone()).await? else {
            return Ok(Err(ResetLinkError::NotFound));
        };
        let made = db
            .create_reset_link(
                format!("in{}", crate::tokens::random_tunnel_id()),
                crate::tokens::hash_token(&token),
                user.id,
                None,
                crate::tokens::now() + i64::from(hours) * 3600,
            )
            .await?;
        if made.is_ok() {
            let _ = db.audit(None, "reset_link_created", Some(format!("{username} (server shell)")), None).await;
        }
        anyhow::Ok(made)
    }
    .await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    match result? {
        Ok(_) => {}
        Err(ResetLinkError::NotFound) => anyhow::bail!("no user {username}; see `tunnel-server user list`"),
        Err(ResetLinkError::Forbidden | ResetLinkError::SignedOut) => {
            anyhow::bail!("{username} is the owner: `tunnel-server admin link` resets the owner")
        }
        Err(ResetLinkError::Disabled) => {
            anyhow::bail!("{username} is disabled; enable the account in the web UI (Users) first")
        }
    }
    println!(
        "Send this link to {username}; it works once, within {hours} hour(s), and is a credential.\n\
         It sets a new password, turns two-factor sign-in off and ends {username}'s sessions:\n"
    );
    println!("  https://{ui}/invite#{token}\n");
    println!("Withdraw it in the web UI (Users → Invites) if it is not needed any more.");
    Ok(())
}

/// `user delete`: remove an account other than the owner, with its machines.
pub async fn user_delete(config_path: &Path, username: &str) -> anyhow::Result<()> {
    ensure_can_write(config_path, "user delete")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let result = db.delete_user(username.to_ascii_lowercase()).await;
    if let Ok(Ok(_)) = &result {
        let _ = db.audit(None, "user_deleted", Some(format!("{username} (server shell)")), None).await;
    }
    drop(db);
    restore_ownership(config_path, &cfg)?;
    match result? {
        Ok(tunnels) => {
            println!("Deleted {username}: signed out, machine tokens revoked.");
            if !tunnels.is_empty() {
                println!("Their {} tunnel(s) stopped serving and close within 15 seconds.", tunnels.len());
            }
            Ok(())
        }
        Err(crate::accounts::DeleteUserError::NotFound) => {
            anyhow::bail!("no user {username}; see `tunnel-server user list`")
        }
        Err(crate::accounts::DeleteUserError::Owner) => {
            anyhow::bail!("{username} is the owner and cannot be deleted (`admin link` resets its password instead)")
        }
    }
}

pub async fn client_list(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let clients = db.list_clients().await?;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    if clients.is_empty() {
        println!("No clients. Add one with `tunnel-server client add <name>`.");
        return Ok(());
    }
    println!("{:<24} {:<16} {:<12} {:<22} {:>7}", "NAME", "USER", "STATUS", "LAST USED", "TUNNELS");
    for c in clients {
        let status = if c.enrolled { "active" } else { "not logged in" };
        let last = c.last_used_at.map(describe_ago).unwrap_or_else(|| "never".to_string());
        println!("{:<24} {:<16} {:<12} {:<22} {:>7}", c.name, c.user, status, last, c.tunnels);
    }
    Ok(())
}

pub async fn client_delete(config_path: &Path, name: &str) -> anyhow::Result<()> {
    ensure_can_write(config_path, "client delete")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
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

pub async fn client_rename(config_path: &Path, name: &str, new_name: &str) -> anyhow::Result<()> {
    crate::clients::validate_new_name(new_name).map_err(anyhow::Error::msg)?;
    ensure_can_write(config_path, "client rename")?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let result = db.rename_client(name.to_string(), new_name.to_string(), None).await;
    if let Ok(Ok(())) = &result
        && name != new_name
    {
        let _ = db.audit(None, "machine_renamed", Some(format!("{name} -> {new_name} (server shell)")), None).await;
    }
    drop(db);
    restore_ownership(config_path, &cfg)?;
    match result? {
        Ok(()) => {
            println!("Renamed {name} to {new_name}; its login and tunnels are unchanged.");
            Ok(())
        }
        Err(crate::accounts::RenameError::Taken) => anyhow::bail!("a client named {new_name} exists"),
        Err(_) => anyhow::bail!("no client named {name}"),
    }
}

/// Write a new service token to a new file (0600, never overwritten), synced
/// before the token's hash is committed.
fn write_token_file(path: &Path, token: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    let written = f.write_all(format!("{token}\n").as_bytes()).and_then(|()| f.sync_all());
    if let Err(e) = written {
        let _ = std::fs::remove_file(path);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

/// Hand out a new service token: written to `token_file` first, then `commit`
/// stores its hash; if that fails the file is removed again. Without a file the
/// token is printed once after the commit.
async fn issue_service_token<F>(
    cfg: &Config,
    name: &str,
    token_file: Option<&Path>,
    commit: impl FnOnce(String) -> F,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let token = crate::services::new_token();
    if let Some(path) = token_file {
        write_token_file(path, &token)?;
        if let Err(e) = commit(token).await {
            let _ = std::fs::remove_file(path);
            return Err(e);
        }
        println!("Wrote the token for service {name} to {} (mode 0600).", path.display());
    } else {
        commit(token.clone()).await?;
        println!("Token for service {name} (shown once):");
        println!();
        println!("  {token}");
        println!();
    }
    println!("Use it as the bearer token for the management API:");
    println!("  TUNNEL_API=https://{}", cfg.api_host);
    println!("  TUNNEL_SERVER=wss://{}", cfg.tunnel_host);
    Ok(())
}

fn service_error(name: &str, e: crate::services::Error) -> anyhow::Error {
    match e {
        crate::services::Error::Invalid(m) => anyhow::anyhow!(m),
        crate::services::Error::Taken => {
            anyhow::anyhow!("service {name} exists; `service rotate {name}` for a new token, or delete it first")
        }
        crate::services::Error::NotFound => anyhow::anyhow!("no service named {name}"),
        crate::services::Error::Other(e) => e,
    }
}

/// Config and database for a subcommand that writes the database; call
/// `restore_ownership` after dropping the database.
fn open_for_write(config_path: &Path, what: &str) -> anyhow::Result<(Config, Db)> {
    ensure_can_write(config_path, what)?;
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    Ok((cfg, db))
}

pub async fn service_add(
    config_path: &Path,
    name: &str,
    max_tunnels: u32,
    token_file: Option<&Path>,
) -> anyhow::Result<()> {
    crate::services::validate_new(name, max_tunnels).map_err(|e| service_error(name, e))?;
    let (cfg, db) = open_for_write(config_path, "service add")?;
    let result = issue_service_token(&cfg, name, token_file, |token| {
        let db = &db;
        async move {
            crate::services::add(db, name, max_tunnels, &token).await.map(drop).map_err(|e| service_error(name, e))
        }
    })
    .await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    result?;
    println!("Service {name} may own up to {max_tunnels} live tunnels.");
    Ok(())
}

pub async fn service_rotate(config_path: &Path, name: &str, token_file: Option<&Path>) -> anyhow::Result<()> {
    let (cfg, db) = open_for_write(config_path, "service rotate")?;
    let result = issue_service_token(&cfg, name, token_file, |token| {
        let db = &db;
        async move { crate::services::rotate(db, name, &token).await.map_err(|e| service_error(name, e)) }
    })
    .await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    result?;
    println!("The previous token of service {name} no longer works.");
    Ok(())
}

pub async fn service_set(config_path: &Path, name: &str, max_tunnels: u32) -> anyhow::Result<()> {
    let (cfg, db) = open_for_write(config_path, "service set")?;
    let result = crate::services::set_quota(&db, name, max_tunnels).await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    result.map_err(|e| service_error(name, e))?;
    println!("Service {name} may now own up to {max_tunnels} live tunnels.");
    Ok(())
}

pub async fn service_list(config_path: &Path) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    check_privileged_data_dir(&cfg)?;
    let db = Db::open_configured(&cfg)?;
    let services = db.list_services(None, None).await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    let services = services?;
    if services.is_empty() {
        println!("No services. Add one with `tunnel-server service add <name> --max-tunnels <n>`.");
        return Ok(());
    }
    println!("{:<24} {:<22} {:>7} {:>11}", "NAME", "LAST USED", "TUNNELS", "MAX TUNNELS");
    for s in services {
        let last = s.last_used_at.map(describe_ago).unwrap_or_else(|| "never".to_string());
        println!("{:<24} {:<22} {:>7} {:>11}", s.name, last, s.tunnels, s.max_tunnels);
    }
    Ok(())
}

pub async fn service_delete(config_path: &Path, name: &str) -> anyhow::Result<()> {
    let (cfg, db) = open_for_write(config_path, "service delete")?;
    let result = db.delete_service(name.to_string()).await;
    drop(db);
    restore_ownership(config_path, &cfg)?;
    let tunnels = result?.ok_or_else(|| anyhow::anyhow!("no service named {name}"))?;
    println!("Deleted service {name}; its token no longer works.");
    if !tunnels.is_empty() {
        // The running server's control sessions re-check their tunnel every minute.
        println!("Its {} tunnel(s) stopped serving and close within a minute.", tunnels.len());
    }
    Ok(())
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
        mode::check_data_dir(&cfg.data_dir, true)?;
    }
    Ok(())
}

/// Opening SQLite as root can leave root-owned files (the db, `-wal`, `-shm`)
/// that the service user cannot write; hand the data dir back.
fn restore_ownership(_config_path: &Path, cfg: &Config) -> anyhow::Result<()> {
    if mode::uid() == 0 {
        mode::chown_recursive(&cfg.data_dir, SERVICE_USER)?;
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

    #[tokio::test]
    async fn service_token_file_is_written_before_commit_and_removed_on_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("svc-token");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "preview_zone": "previews.example.com", "api_host": "api.example.com",
            "tunnel_host": "tunnel.example.com", "turn_host": "turn.example.com",
            "admin_token_hash": "x", "acme": {"email": "test@example.com"},
            "dns": {"provider": "cloudflare", "zone": "example.com"}
        }))
        .unwrap();
        let file = dir.join("svc");
        let committed = std::sync::Mutex::new(None::<String>);
        issue_service_token(&cfg, "wssp", Some(&file), |token| {
            // The file is complete before the hash is committed.
            assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{token}\n"));
            *committed.lock().unwrap() = Some(token);
            async { Ok(()) }
        })
        .await
        .unwrap();
        let token = committed.lock().unwrap().clone().unwrap();
        assert!(token.starts_with(tunnel_protocol::SERVICE_TOKEN_PREFIX));
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);

        // An existing file is never overwritten, and nothing is committed.
        let mut called = false;
        let existing = issue_service_token(&cfg, "wssp", Some(&file), |_| {
            called = true;
            async { Ok(()) }
        })
        .await;
        assert!(existing.is_err() && !called);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{token}\n"));

        // An unwritable path fails before the commit (the old credential stays valid).
        let mut called = false;
        let missing = issue_service_token(&cfg, "wssp", Some(&dir.join("missing").join("svc")), |_| {
            called = true;
            async { Ok(()) }
        })
        .await;
        assert!(missing.is_err() && !called);

        // A failed commit removes the file again.
        let other = dir.join("other");
        let failed = issue_service_token(&cfg, "wssp", Some(&other), |_| async { anyhow::bail!("name taken") }).await;
        assert!(failed.is_err());
        assert!(!other.exists());
        std::fs::remove_dir_all(&dir).unwrap();
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
    fn database_moved_aside_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("aside");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("tunnel.db");
        std::fs::write(&db, b"old database").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        let aside = move_aside(&db).unwrap();
        assert!(!db.exists());
        assert!(aside.file_name().unwrap().to_str().unwrap().starts_with("tunnel.db.before-restore-"));
        assert_eq!(std::fs::read(&aside).unwrap(), b"old database");
        assert_eq!(std::fs::metadata(&aside).unwrap().permissions().mode() & 0o777, 0o600);

        // A database symlink is refused and left where it is, its target untouched.
        let target = dir.join("elsewhere.db");
        std::fs::write(&target, b"elsewhere").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, &db).unwrap();
        assert!(move_aside(&db).unwrap_err().to_string().contains("must not be a symlink"));
        assert!(std::fs::symlink_metadata(&db).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o644);
        std::fs::remove_dir_all(dir).unwrap();
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
        for version in [0, crate::db::SCHEMA_VERSION + 1] {
            db.pragma_update(None, "user_version", version).unwrap();
            assert_eq!(
                check_backup(&path).unwrap_err().to_string(),
                format!(
                    "unsupported backup schema version {version}; this build needs schema version {}",
                    crate::db::SCHEMA_VERSION
                )
            );
        }
        db.pragma_update(None, "user_version", crate::db::SCHEMA_VERSION).unwrap();
        // The right version but not this build's schema.
        let err = format!("{:#}", check_backup(&path).unwrap_err());
        assert!(err.contains("schema differs from this build's"), "{err}");
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

        // A URI would name another file than the one checked, copied or written.
        let uri = Path::new("file:tunnel-uri-test.db");
        assert!(check_backup(uri).unwrap_err().to_string().contains("must not be a SQLite URI"));
        assert!(db.backup_to(uri.to_path_buf()).await.unwrap_err().to_string().contains("must not be a SQLite URI"));
        assert!(!uri.exists() && !Path::new("tunnel-uri-test.db").exists());

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
