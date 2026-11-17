//! `tunnel`: the sandbox side of Tunnel.
//!
//! Commands talk to one background daemon over a Unix socket. The daemon owns
//! the single control connection to the tunnel server and splices
//! server-opened streams to loopback ports.

#[cfg(not(unix))]
compile_error!("the tunnel client supports only Unix targets (Linux and macOS)");

mod commands;
mod daemon;
mod ice;
mod ipc;
mod login;
mod paths;
mod session;
mod share;
mod state;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tunnel", version, about = "Expose sandbox ports through Tunnel")]
struct Cli {
    /// State directory (absolute): one daemon and one tunnel per directory.
    /// Default `$TUNNEL_STATE_DIR`, else `$XDG_RUNTIME_DIR/tunnel`, else `/tmp/tunnel-<uid>`.
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<std::path::PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Expose local ports (starts the daemon if needed). Token from TUNNEL_TOKEN.
    Expose {
        #[arg(required = true, num_args = 1.., value_parser = clap::value_parser!(u16).range(1..))]
        ports: Vec<u16>,
        /// Dial the ports on this IP address instead of loopback (default $TUNNEL_TARGET_HOST; no hostnames).
        #[arg(long, value_name = "IP")]
        target: Option<String>,
    },
    /// Stop exposing a port.
    Unexpose {
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        port: u16,
    },
    /// Show tunnel and per-port status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Print the current ICE (STUN/TURN) config, or run a command with it in the environment.
    Ice {
        #[arg(long, value_enum, default_value_t = IceFormat::Json)]
        format: IceFormat,
        /// Ask the server for a new credential even if the cached one is fresh.
        #[arg(long)]
        fresh: bool,
        /// Exec the command after `--` with TURN_* / ICE_* variables set.
        #[arg(long, requires = "command")]
        exec: bool,
        #[arg(last = true, requires = "exec", value_name = "CMD")]
        command: Vec<String>,
    },
    /// Stop the daemon and forget exposed ports (deletes a tunnel `share` created).
    Stop,
    /// Log this machine in with the code `tunnel-server client add` printed
    /// (prompted for, so it stays out of process listings and shell history).
    Login {
        /// `<code>@<host>`; omit (or `-`) to be prompted / read it from stdin.
        code: Option<String>,
    },
    /// Forget this machine's login.
    Logout,
    /// Share local ports from a logged-in machine. Default access: a one-time link per port.
    Share {
        #[arg(required = true, num_args = 1.., value_parser = clap::value_parser!(u16).range(1..))]
        ports: Vec<u16>,
        /// Anyone with the URL can open it (servers allow this only if `allow_public_for_clients` is set).
        #[arg(long, conflicts_with_all = ["password", "link"])]
        public: bool,
        /// Visitors sign in with a username and password (password from $TUNNEL_SHARE_PASSWORD or a prompt).
        #[arg(long, conflicts_with = "link")]
        password: bool,
        /// Access links only (the default for a new share; switches an existing one back).
        #[arg(long)]
        link: bool,
        /// Username for --password (default "preview").
        #[arg(long, requires = "password")]
        username: Option<String>,
        /// How long the tunnel lives, e.g. 30m, 8h, 2d.
        #[arg(long, default_value = "8h", value_parser = login::parse_duration)]
        ttl: u64,
        #[arg(long)]
        label: Option<String>,
        /// Dial the ports on this IP address instead of loopback (default $TUNNEL_TARGET_HOST; no hostnames).
        #[arg(long, value_name = "IP")]
        target: Option<String>,
    },
    /// Print a new access link for what this machine is sharing.
    Link {
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        /// Usable more than once until it expires.
        #[arg(long)]
        reusable: bool,
        /// How long the link works, e.g. 10m, 1h.
        #[arg(long, default_value = "10m", value_parser = login::parse_duration)]
        ttl: u64,
    },
    /// Run the daemon in the foreground, e.g. under systemd. Token, server and
    /// target come from TUNNEL_TOKEN, TUNNEL_SERVER and TUNNEL_TARGET_HOST (or the
    /// state dir's saved tunnel); ports from `expose` over the state dir's socket.
    /// Exits 3 when the tunnel is gone or its token rejected, 4 when replaced.
    Daemon,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum IceFormat {
    /// `export K='v'` lines for `eval "$(...)"`.
    Env,
    /// The ICE config JSON.
    Json,
    /// The path of the ICE file the daemon keeps fresh.
    File,
}

fn main() {
    let cli = Cli::parse();
    let is_daemon = matches!(cli.cmd, Cmd::Daemon);
    init_tracing(is_daemon);
    // Fails only if a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(dir) = cli.state_dir
        && let Err(e) = paths::set_state_dir(dir)
    {
        eprintln!("tunnel: {e:#}");
        std::process::exit(2);
    }

    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tunnel: starting runtime: {e}");
            std::process::exit(1);
        }
    };
    let code = match runtime.block_on(run(cli.cmd)) {
        Ok(code) => code,
        Err(e) => {
            if is_daemon {
                tracing::error!("{e:#}");
            } else {
                eprintln!("tunnel: {}", paths::terminal_text(&format!("{e:#}")));
            }
            1
        }
    };
    std::process::exit(code);
}

async fn run(cmd: Cmd) -> anyhow::Result<i32> {
    match cmd {
        Cmd::Expose { ports, target } => commands::expose(ports, target).await,
        Cmd::Unexpose { port } => commands::unexpose(port).await,
        Cmd::Status { json } => commands::status(json).await,
        Cmd::Ice { format, fresh, exec: _, command } => commands::ice(format, fresh, command).await,
        Cmd::Stop => commands::stop().await,
        Cmd::Login { code } => share::login(code.as_deref()).await,
        Cmd::Logout => share::logout(),
        Cmd::Share { ports, public, password, link, username, ttl, label, target } => {
            share::share(ports, share::ShareAccess { public, password, link, username }, ttl, label, target).await
        }
        Cmd::Link { port, reusable, ttl } => share::link(port, reusable, ttl).await,
        Cmd::Daemon => daemon::run().await.map(|()| 0),
    }
}

fn init_tracing(daemon: bool) {
    let default = if daemon { "info" } else { "warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    // The client handshake traces the full request, including Authorization.
    let filter = protect_log_filter(filter);
    // No ANSI colors when stderr is a file (daemon.log) or a pipe.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).with_ansi(ansi);
    if daemon {
        builder.init();
    } else {
        builder.without_time().init();
    }
}

fn protect_log_filter(filter: EnvFilter) -> EnvFilter {
    filter.add_directive("tungstenite::handshake::client=off".parse().expect("valid log directive"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_logging_is_disabled_even_when_trace_is_requested() {
        for directives in ["trace", "trace,tungstenite::handshake::client=trace"] {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(protect_log_filter(EnvFilter::new(directives)))
                .with_writer(std::io::sink)
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                assert!(!tracing::enabled!(target: "tungstenite::handshake::client", tracing::Level::TRACE));
                assert!(!tracing::enabled!(target: "tungstenite::handshake::client", tracing::Level::DEBUG));
                assert!(tracing::enabled!(target: "tunnel_client", tracing::Level::TRACE));
            });
        }
    }
}
