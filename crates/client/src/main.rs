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
#[command(name = "tunnel", version, about = "Expose sandbox ports through Tunnel", disable_help_subcommand = true)]
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
    /// Log this machine in: `tunnel login https://<server>` asks you to approve
    /// it in the browser; `tunnel login` with the code `tunnel-server client add`
    /// printed works without one (prompted for, so it stays out of process
    /// listings and shell history).
    Login {
        /// `https://<server>`, or `<code>@<host>`; omit (or `-`) to be prompted / read it from stdin.
        code: Option<String>,
        /// Machine name for browser approval (default: this host's name).
        #[arg(long)]
        name: Option<String>,
        /// Do not try to open the approval page in a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Forget this machine's login.
    Logout,
    /// Share local ports from a logged-in machine. Default access: a one-time link per port.
    #[command(after_long_help = SHARE_NOTES)]
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
        /// How long the tunnel lives, e.g. 30m, 8h, 2d, or `never` (only if your
        /// account's tunnel lifetime is Unlimited); the daemon keeps it up after
        /// this command ends, until `tunnel unshare`. Not with --for.
        #[arg(long, default_value = "8h", value_parser = login::parse_ttl)]
        ttl: login::Ttl,
        /// Stay in the foreground, then unshare: `--for` (1h) or `--for=30m`;
        /// Ctrl-C (or SIGTERM) unshares sooner. Always makes a new tunnel. Not with --ttl.
        #[arg(long = "for", value_name = "DURATION", num_args = 0..=1, require_equals = true,
              default_missing_value = "1h", value_parser = login::parse_duration, conflicts_with = "ttl")]
        for_s: Option<u64>,
        #[arg(long)]
        label: Option<String>,
        /// Dial the ports on this IP address instead of loopback (default $TUNNEL_TARGET_HOST; no hostnames).
        #[arg(long, value_name = "IP")]
        target: Option<String>,
        /// Print one JSON object: {"tunnel","mode","expires_at","links":[{"port","url","connected",…}]};
        /// password mode adds "username" and each link's "login_url".
        #[arg(long)]
        json: bool,
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
        /// A note shown by `tunnel links` and the web UI, e.g. who got the link.
        #[arg(long)]
        label: Option<String>,
        /// Print one JSON object, shaped like `share --json`.
        #[arg(long)]
        json: bool,
    },
    /// List the access links of what this machine is sharing (their URLs are not stored).
    Links {
        #[arg(long)]
        json: bool,
    },
    /// Revoke one access link (see `tunnel links`) and end the visits it allowed.
    Unlink {
        /// The link id.
        id: String,
    },
    /// Stop sharing: delete the shared tunnel and stop its daemon. With
    /// ports, stop sharing only those (the tunnel goes once none are left).
    Unshare {
        #[arg(value_parser = clap::value_parser!(u16).range(1..))]
        ports: Vec<u16>,
    },
    /// Help for a command, or `tunnel help agent`: how AI agents should share apps with tunnel.
    Help {
        /// A command name, or `agent`.
        topic: Option<String>,
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

/// `tunnel share --help` notes on how visitors get in.
const SHARE_NOTES: &str = "\
Visitors' browsers get the sign-in page: a link, or the password form. Only page loads
(`Sec-Fetch-Dest: document`, `iframe` or `frame`; without that header, `Accept: text/html`)
are redirected to it. Anything else (curl, fetch, an agent) gets 401, in password mode too.
In password mode, give people the `login_url` from --json (or the \"sign in\" line), not `url`.

To leave a share up for a while, use `--for=8h --json` (in the background): it makes its own
tunnel and ends by itself. --ttl and --for are exclusive; --ttl is for a share the daemon
keeps until `tunnel unshare`. A machine has one daemon: if `tunnel status --json` shows a
running tunnel someone else started, a new share takes the daemon over, so ask first; never
unshare a tunnel someone else started: check
`tunnel status --json` first.

AI agents: `tunnel help agent`.";

/// The agent skill (docs/agent/SKILL.md), for `tunnel help agent`.
const AGENT_SKILL: &str = include_str!("../../../docs/agent/SKILL.md");

fn help(topic: Option<&str>) -> anyhow::Result<i32> {
    use clap::CommandFactory;
    let mut cli = Cli::command();
    match topic {
        Some("agent") => print!("{AGENT_SKILL}"),
        Some(name) => match cli.find_subcommand_mut(name) {
            Some(sub) => sub.print_long_help()?,
            None => anyhow::bail!("no help topic '{name}'; try `tunnel help` or `tunnel help agent`"),
        },
        None => {
            cli.print_long_help()?;
            println!("\nAI agents: `tunnel help agent` explains how to share an app safely.");
        }
    }
    Ok(0)
}

async fn run(cmd: Cmd) -> anyhow::Result<i32> {
    match cmd {
        Cmd::Help { topic } => help(topic.as_deref()),
        Cmd::Expose { ports, target } => commands::expose(ports, target).await,
        Cmd::Unexpose { port } => commands::unexpose(port).await,
        Cmd::Status { json } => commands::status(json).await,
        Cmd::Ice { format, fresh, exec: _, command } => commands::ice(format, fresh, command).await,
        Cmd::Stop => commands::stop().await,
        Cmd::Login { code, name, no_browser } => share::login(code.as_deref(), name.as_deref(), !no_browser).await,
        Cmd::Logout => share::logout(),
        Cmd::Share { ports, public, password, link, username, ttl, for_s, label, target, json } => {
            let access = share::ShareAccess { public, password, link, username };
            let foreground = for_s.map(|duration_s| share::Foreground { duration_s });
            share::share(ports, access, ttl, label, target, share::Output { json }, foreground).await
        }
        Cmd::Link { port, reusable, ttl, label, json } => {
            share::link(port, reusable, ttl, label, share::Output { json }).await
        }
        Cmd::Links { json } => share::links(json).await,
        Cmd::Unlink { id } => share::unlink(&id).await,
        Cmd::Unshare { ports } => share::unshare(ports).await,
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
    fn share_for_defaults_to_an_hour_and_excludes_ttl() {
        let for_s = |args: &[&str]| match Cli::try_parse_from(args).map(|c| c.cmd) {
            Ok(Cmd::Share { for_s, ports, .. }) => Ok((for_s, ports)),
            Ok(_) => panic!("not share"),
            Err(e) => Err(e.kind()),
        };
        assert_eq!(for_s(&["tunnel", "share", "3000"]), Ok((None, vec![3000])));
        assert_eq!(for_s(&["tunnel", "share", "3000", "--for"]), Ok((Some(3600), vec![3000])));
        assert_eq!(for_s(&["tunnel", "share", "3000", "--for=30m"]), Ok((Some(1800), vec![3000])));
        assert_eq!(for_s(&["tunnel", "share", "--for=2h", "3000", "5173"]), Ok((Some(7200), vec![3000, 5173])));
        // A bare `--for` never takes a port as its duration.
        assert_eq!(for_s(&["tunnel", "share", "--for", "3000"]), Ok((Some(3600), vec![3000])));
        assert_eq!(for_s(&["tunnel", "share", "3000", "--for", "5173"]), Ok((Some(3600), vec![3000, 5173])));
        assert!(for_s(&["tunnel", "share", "3000", "--for", "30m"]).is_err());
        assert_eq!(
            for_s(&["tunnel", "share", "3000", "--for", "--ttl", "1h"]),
            Err(clap::error::ErrorKind::ArgumentConflict)
        );
    }

    #[test]
    fn agent_skill_and_share_help_cover_password_mode_and_unshare_safety() {
        for needle in [
            "login_url",
            "`Sec-Fetch-Dest: document`",
            "`Accept: text/html`",
            "gets **401**, in\n  password mode too",
            "--for=8h --json",
            "`--ttl` and `--for` are exclusive",
            "**Never unshare a tunnel you did not create in this session.**",
            "a new share (including `--for`) would take the daemon\n  over",
            "check `tunnel status --json`",
            "ask the human",
        ] {
            assert!(AGENT_SKILL.contains(needle), "skill lacks {needle:?}");
        }
        let help = <Cli as clap::CommandFactory>::command()
            .find_subcommand_mut("share")
            .expect("share")
            .render_long_help()
            .to_string();
        for needle in [
            "Sec-Fetch-Dest: document",
            "Accept: text/html",
            "gets 401, in password mode too",
            "`login_url`",
            "--for=8h --json",
            "--ttl and --for are exclusive",
            "check\n`tunnel status --json` first",
            "a new share takes the daemon over",
            "Not with --for",
            "Not with --ttl",
        ] {
            assert!(help.contains(needle), "share --help lacks {needle:?}:\n{help}");
        }
    }

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
