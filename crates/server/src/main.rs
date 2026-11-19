mod acme;
mod api;
mod clients;
mod commands;
mod config;
mod control;
mod db;
mod device;
mod dns;
mod edge;
mod gate;
mod gatehost;
mod headers;
mod ice;
mod inject;
mod install;
mod listener;
mod metrics;
mod mode;
mod pages;
mod password;
mod pool;
mod proxy;
mod purge;
mod ratelimit;
mod registry;
mod services;
mod setup;
mod sni;
mod state;
mod tls;
mod tokens;
mod turn_relay;
mod ui;
mod util;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tunnel-server", version, about = "Preview relay for sandboxed apps")]
struct Cli {
    /// Config file (default: /etc/tunnel-server/config.toml as root,
    /// ~/.config/tunnel-server/config.toml otherwise, honoring $XDG_CONFIG_HOME).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (used by the systemd unit).
    Serve,
    /// Install or reconfigure (as root: system install; as another user: rootless install).
    Setup(Box<setup::SetupArgs>),
    /// Admin token management.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Protect /healthz with an optional token (for uptime monitors).
    HealthToken {
        #[command(subcommand)]
        cmd: HealthTokenCmd,
    },
    /// Show service, database, and certificate status.
    Status,
    /// Write a consistent SQLite backup (`VACUUM INTO`).
    Backup { path: PathBuf },
    /// Replace the database with a backup: checks it, stops the service, keeps
    /// the current database as `<db>.before-restore-<time>`, starts again.
    Restore { path: PathBuf },
    /// Certificate management.
    Cert {
        #[command(subcommand)]
        cmd: CertCmd,
    },
    /// Web UI owner account: `admin link` prints a one-time link to create
    /// the owner (first run) or reset the owner's password and two-factor sign-in.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// Web UI accounts.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Machines that may create tunnels with their own token (`tunnel login`).
    Client {
        #[command(subcommand)]
        cmd: ClientCmd,
    },
    /// API-only credentials for other services (e.g. a sandbox platform): they
    /// create and delete their own tunnels and access links within a quota.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Create a service and print its token once (or write it to --token-file).
    Add {
        name: String,
        /// Live tunnels it may own at once (1..=10000).
        #[arg(long)]
        max_tunnels: u32,
        /// Write the token to this new file (mode 0600) instead of printing it.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// List services, when they were last used, and their open tunnels.
    List,
    /// Change a service's live-tunnel quota.
    Set {
        name: String,
        #[arg(long)]
        max_tunnels: u32,
    },
    /// Replace a service's token; the old one stops working at once.
    Rotate {
        name: String,
        /// Write the token to this new file (mode 0600) instead of printing it.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// Remove a service: its token stops working and its tunnels close.
    Delete { name: String },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Print a one-time link (15 minutes) to create or recover the owner account.
    Link,
}

#[derive(Subcommand)]
enum UserCmd {
    /// List accounts, their roles, machines and tunnels.
    List,
    /// Print a one-time sign-up link for a new account (like an invite from the web UI).
    Invite {
        /// The new account's role.
        #[arg(long, value_enum, default_value_t = InviteRole::Member)]
        role: InviteRole,
        /// Hours the link works (1..=720).
        #[arg(long, default_value_t = 168, value_parser = clap::value_parser!(u32).range(1..=720))]
        hours: u32,
    },
    /// Delete an account (not the owner): its sessions end, its machines'
    /// tokens stop working and their tunnels close.
    Delete { username: String },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum InviteRole {
    Member,
    Admin,
}

#[derive(Subcommand)]
enum ClientCmd {
    /// Register a machine and print the one-time login command to run on it.
    Add {
        name: String,
        /// The account that owns the machine (default: the owner).
        #[arg(long)]
        user: Option<String>,
    },
    /// List machines, when they were last used, and their open tunnels.
    List,
    /// Remove a machine: its token stops working and its tunnels close.
    Delete { name: String },
    /// Rename a machine; its login, token and tunnels stay as they are.
    Rename { name: String, new_name: String },
}

#[derive(Subcommand)]
enum HealthTokenCmd {
    /// Require a token for /healthz: generate one, print it once, restart.
    Set,
    /// Make /healthz open again.
    Clear,
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Generate a new admin API token, print it once, restart the service.
    Rotate,
}

#[derive(Subcommand)]
enum CertCmd {
    /// Renew the certificate if due (or always with --force).
    Renew {
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // No ANSI colors in the journal or when piped.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = match cli.config {
        Some(p) => p,
        None => mode::Mode::current().config_path()?,
    };
    match cli.cmd {
        Cmd::Serve => commands::serve(&config).await,
        Cmd::Setup(args) => setup::run(&config, *args).await,
        Cmd::Token { cmd: TokenCmd::Rotate } => commands::token_rotate(&config).await,
        Cmd::HealthToken { cmd } => commands::health_token(&config, matches!(cmd, HealthTokenCmd::Set)).await,
        Cmd::Status => commands::status(&config).await,
        Cmd::Backup { path } => commands::backup(&config, &path).await,
        Cmd::Restore { path } => commands::restore(&config, &path).await,
        Cmd::Cert { cmd: CertCmd::Renew { force } } => commands::cert_renew(&config, force).await,
        Cmd::Admin { cmd: AdminCmd::Link } => commands::admin_link(&config, false).await,
        Cmd::User { cmd: UserCmd::List } => commands::user_list(&config).await,
        Cmd::User { cmd: UserCmd::Invite { role, hours } } => {
            let role = match role {
                InviteRole::Member => ui::store::Role::Member,
                InviteRole::Admin => ui::store::Role::Admin,
            };
            commands::user_invite(&config, role, hours).await
        }
        Cmd::User { cmd: UserCmd::Delete { username } } => commands::user_delete(&config, &username).await,
        Cmd::Client { cmd: ClientCmd::Add { name, user } } => {
            commands::client_add(&config, &name, user.as_deref()).await
        }
        Cmd::Client { cmd: ClientCmd::List } => commands::client_list(&config).await,
        Cmd::Client { cmd: ClientCmd::Delete { name } } => commands::client_delete(&config, &name).await,
        Cmd::Client { cmd: ClientCmd::Rename { name, new_name } } => {
            commands::client_rename(&config, &name, &new_name).await
        }
        Cmd::Service { cmd: ServiceCmd::Add { name, max_tunnels, token_file } } => {
            commands::service_add(&config, &name, max_tunnels, token_file.as_deref()).await
        }
        Cmd::Service { cmd: ServiceCmd::List } => commands::service_list(&config).await,
        Cmd::Service { cmd: ServiceCmd::Set { name, max_tunnels } } => {
            commands::service_set(&config, &name, max_tunnels).await
        }
        Cmd::Service { cmd: ServiceCmd::Rotate { name, token_file } } => {
            commands::service_rotate(&config, &name, token_file.as_deref()).await
        }
        Cmd::Service { cmd: ServiceCmd::Delete { name } } => commands::service_delete(&config, &name).await,
    }
}
