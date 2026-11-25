//! `tunnel-server setup`: the install/reconfigure wizard.
//!
//! One question matters: the server hostname. The API, the sandbox tunnel,
//! and `*.<host>` previews all live on it (TURN on `turn.<host>`), so two DNS
//! records cover everything. Every input is checked as soon as it is given
//! (DNS token, zone, records) so mistakes fail early with a reason.
//!
//! Every step is idempotent. Existing config values are the defaults,
//! secrets are never regenerated, files are only rewritten when their content
//! changes, and services only restart when something changed, so re-running
//! with the same answers changes nothing.
//!
//! Run as root for a system install; as any other user for a rootless one
//! (see `crate::mode`).

mod firewall;
mod os;
mod prompt;
mod systemd;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use tunnel_protocol::ADMIN_TOKEN_PREFIX;

use crate::config::{Config, DnsConfig, DnsProviderKind, SERVICE_NAME, SERVICE_USER};
use crate::mode::{self, Mode};
use crate::{acme, dns, tls, tokens};

#[allow(unused_imports)] // part of the module contract; no caller outside setup yet
#[derive(clap::Args, Debug, Default)]
pub struct SetupArgs {
    /// Server hostname, e.g. tunnel.example.com. The API and sandbox tunnel use it,
    /// previews are *.<host>, TURN is turn.<host>.
    #[arg(long)]
    pub host: Option<String>,
    /// Override the preview zone (default: the server hostname).
    #[arg(long)]
    pub preview_zone: Option<String>,
    /// Override the TURN hostname (default: turn.<host>).
    #[arg(long)]
    pub turn_host: Option<String>,
    /// Web UI hostname (sign-in, machines, users), or `none` for no web UI.
    /// Never the preview zone or a name under it.
    #[arg(long)]
    pub ui_host: Option<String>,
    /// Whether people other than you will use this server (true or false).
    /// Then previews must be on a separate registrable domain from the UI.
    #[arg(long)]
    pub multi_user: Option<bool>,
    /// DNS provider of the preview zone, when it is not in the server's DNS zone.
    #[arg(long)]
    pub preview_dns_provider: Option<String>,
    /// DNS zone holding the preview zone (detected automatically for Cloudflare).
    #[arg(long)]
    pub preview_dns_zone: Option<String>,
    /// File holding the API token for the preview zone's DNS provider.
    #[arg(long)]
    pub preview_dns_token_file: Option<PathBuf>,
    /// Bring your own certificate (true or false): setup and the server never
    /// issue or renew one; put fullchain.pem and privkey.pem covering every
    /// name into the data directory's certs/ (combine with --skip-dns for a
    /// fully manual DNS setup).
    #[arg(long)]
    pub own_certificate: Option<bool>,
    /// ACME (Let's Encrypt) contact email.
    #[arg(long)]
    pub email: Option<String>,
    /// DNS provider: cloudflare, hetzner, digitalocean, or route53.
    #[arg(long)]
    pub dns_provider: Option<String>,
    /// DNS zone at the provider (detected automatically for Cloudflare).
    #[arg(long)]
    pub dns_zone: Option<String>,
    /// File holding the DNS provider API token (keeps it out of argv and shell history).
    #[arg(long)]
    pub dns_token_file: Option<PathBuf>,
    /// Sites allowed to show previews in an iframe, comma-separated:
    /// https://app.example.com,https://*.example.com — * for any site, none (default) for own origin only.
    #[arg(long)]
    pub frame_ancestors: Option<String>,
    /// Enable WebRTC (built-in STUN/TURN relay): true or false.
    #[arg(long)]
    pub webrtc: Option<bool>,
    /// Never prompt: use flags and current values, fail if something required is missing.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Use the Let's Encrypt staging directory (untrusted certs, generous rate limits).
    #[arg(long)]
    pub staging: bool,
    /// Do not create DNS records (they must already point here; they are still verified).
    #[arg(long)]
    pub skip_dns: bool,
    /// Skip the HTTPS checks against the running service.
    #[arg(long)]
    pub skip_self_test: bool,
}

const DNS_POLL: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(30);

const PROVIDERS: [(DnsProviderKind, &str); 4] = [
    (DnsProviderKind::Cloudflare, "cloudflare"),
    (DnsProviderKind::Hetzner, "hetzner"),
    (DnsProviderKind::Digitalocean, "digitalocean"),
    (DnsProviderKind::Route53, "route53"),
];

pub async fn run(config_path: &Path, args: SetupArgs) -> anyhow::Result<()> {
    let mode = Mode::current();
    if mode.is_user() {
        println!("Rootless install for user {} (run with sudo for a system install).", mode::username()?);
        user_preflight(config_path)?;
    }

    let existing = if config_path.exists() { Some(Config::load(config_path)?) } else { None };
    if existing.is_some() {
        println!("Reconfiguring from {} (Enter keeps each current value).", config_path.display());
    }
    let ask = Ask { yes: args.yes };
    let mut cfg = ask_config(&ask, existing.as_ref(), &args, mode).await?;

    // Set only once the config holding its hash is on disk, so a failure
    // after that point still shows the token instead of losing it.
    let mut new_token: Option<String> = None;
    let result = configure(config_path, existing.as_ref(), &mut cfg, &args, mode, &mut new_token).await;
    if let Err(e) = result {
        if let Some(token) = &new_token {
            eprintln!("\nSetup failed, but a new admin token was already saved. Keep it:");
            print_token_box(&cfg, token);
        }
        return Err(e);
    }
    finish(&cfg, mode, new_token.as_deref());
    if cfg.ui_host.is_some() {
        // First run with the UI: the one-time link that creates the owner account.
        if let Err(e) = crate::commands::admin_link(config_path, true).await {
            eprintln!("Could not create the owner sign-up link ({e:#}); run `tunnel-server admin link`.");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn configure(
    config_path: &Path,
    existing: Option<&Config>,
    cfg: &mut Config,
    args: &SetupArgs,
    mode: Mode,
    new_token: &mut Option<String>,
) -> anyhow::Result<()> {
    if mode == Mode::System {
        system_preflight(config_path, &mode.unit_dir()?.join(format!("{SERVICE_NAME}.service")))?;
    }
    mode::check_data_dir(&cfg.data_dir, mode == Mode::System)?;
    if mode == Mode::System {
        mode::check_system_config_dir(config_path)?;
    }
    if cfg.webrtc.enabled {
        check_stun_port(cfg.webrtc.stun_port, mode.systemctl_ok(&["is-active", "--quiet", SERVICE_NAME]))?;
    }
    step("Detecting public IP addresses");
    let (v4, v6) = detect_public_ips(existing, args.yes).await?;
    cfg.public_ipv4 = Some(v4);
    cfg.public_ipv6 = v6;
    if v6.is_none() && existing.and_then(|c| c.public_ipv6).is_some() {
        println!("Note: no IPv6 detected any more; remove stale AAAA records at the DNS provider by hand.");
    }

    step("Checking DNS provider access");
    if !args.skip_dns || !cfg.acme.own_certificate {
        for zone in std::iter::once(&cfg.dns).chain(&cfg.extra_dns) {
            dns::Provider::from_dns(zone)?.check_write(&zone.zone).await.with_context(|| {
                format!("the DNS token cannot create records in {} (it needs DNS edit permission)", zone.zone)
            })?;
            println!("Token can edit records in {}", zone.zone);
        }
    } else {
        println!("Not checking DNS provider access (--skip-dns and an own certificate)");
    }

    // Before DNS so the answers are persisted even if DNS verification times out.
    step("Creating directories");
    if mode == Mode::System {
        ensure_service_user(cfg)?;
    }
    ensure_dirs(cfg, config_path, mode)?;

    step("Generating secrets");
    let token = generate_secrets(cfg);
    let config_changed = cfg.save(config_path)?;
    if mode == Mode::System {
        mode::secure_system_config(config_path)?;
    }
    *new_token = token;
    println!("{} {}", if config_changed { "Wrote" } else { "Unchanged:" }, config_path.display());

    if args.skip_dns {
        println!("Not creating DNS records (--skip-dns)");
    } else {
        step("Configuring DNS");
        configure_dns(cfg).await?;
    }
    verify_dns(cfg, v4, v6).await?;

    step("Certificate");
    ensure_certificate(cfg).await?;
    if mode == Mode::System {
        mode::chown_recursive(&cfg.data_dir, SERVICE_USER)?;
    }

    step("Firewall");
    if mode == Mode::System {
        firewall::configure(cfg)?;
    } else {
        println!(
            "Rootless install: not touching the host firewall. Inbound {} must be open",
            firewall::required_ports(cfg)
                .iter()
                .map(|(p, proto)| format!("{p}/{proto}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("(host firewall and any cloud provider firewall).");
        if let Some(cmd) = firewall::rootless_command(cfg) {
            println!("A host firewall is running. If these ports are not open yet, run once:\n\n  {cmd}\n");
        }
    }

    step("Service");
    systemd::install(cfg, config_path, config_changed, mode)?;

    if args.skip_self_test {
        println!("Skipping self-test (--skip-self-test)");
    } else {
        step("Self-test");
        self_test(cfg, mode).await?;
    }
    Ok(())
}

fn step(title: &str) {
    println!("\n==> {title}");
}

/// Refuse collisions before setup changes local files or remote DNS records.
fn system_preflight(config_path: &Path, unit_path: &Path) -> anyhow::Result<()> {
    match std::fs::read_to_string(unit_path) {
        Ok(unit) => systemd::check_existing_unit(unit_path, &unit)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", unit_path.display())),
    }
    let dir = config_path.parent().context("config path has no parent directory")?;
    let config_loadable = Config::load(config_path).is_ok();
    let has_entries = if config_loadable {
        false
    } else {
        match std::fs::read_dir(dir) {
            Ok(mut entries) => entries.next().transpose()?.is_some(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        }
    };
    check_config_dir_takeover(dir, config_loadable, has_entries)
}

fn check_config_dir_takeover(dir: &Path, config_loadable: bool, has_entries: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        config_loadable || !has_entries,
        "{} exists and holds no Tunnel config; refusing to take it over",
        dir.display()
    );
    Ok(())
}

/// A rootless server needs two root-owned settings. Check both (and whether a
/// root install is still around) and print one command that fixes everything.
fn user_preflight(config_path: &Path) -> anyhow::Result<()> {
    let user = mode::username()?;
    let port_start = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1024);
    let ports_ok = port_start <= 80;
    let linger_ok = Path::new("/var/lib/systemd/linger").join(&user).exists();
    let system_config = Path::new(mode::SYSTEM_CONFIG_PATH);
    let system_unit = Mode::System.unit_dir()?.join(format!("{SERVICE_NAME}.service"));
    let system_install = is_system_install(system_config, &system_unit);
    if std::fs::read_to_string(&system_unit).is_ok_and(|unit| !systemd::is_tunnel_unit(&unit)) {
        eprintln!("Warning: the unit at {} is not Tunnel's; nothing is migrated.", system_unit.display());
    } else if !system_install && system_config.parent().is_some_and(Path::exists) {
        eprintln!("Warning: {} is not a Tunnel install; it is left alone.", mode::SYSTEM_CONFIG_DIR);
    }

    if ports_ok && linger_ok && !system_install {
        return Ok(());
    }

    let data = Mode::User.data_dir()?;
    let script = rootless_setup_script(&user, config_path, &data, !ports_ok, !linger_ok, system_install)?;

    eprintln!("A rootless install needs a one-time change as root:");
    if !ports_ok {
        eprintln!("  - allow unprivileged programs to use ports 80 and up (now {port_start})");
    }
    if !linger_ok {
        eprintln!("  - keep {user}'s services running after logout (lingering)");
    }
    if system_install {
        eprintln!("  - move the existing root install (config, certificate, database) to {user}");
    }
    // One line joined with `&&`: it survives copy/paste and runners that fold newlines,
    // and stops at the first failing step.
    eprintln!("\nRun this once, then run setup again:\n");
    eprintln!("sudo sh -c {}", shell_quote(&script));
    bail!("one-time root setup needed (see above)")
}

fn is_system_install(config_path: &Path, unit_path: &Path) -> bool {
    system_install_from_config(Config::load(config_path), unit_path)
}

fn system_install_from_config(config: anyhow::Result<Config>, unit_path: &Path) -> bool {
    let our_unit = match std::fs::read_to_string(unit_path) {
        Ok(unit) if systemd::is_tunnel_unit(&unit) => true,
        Ok(_) => return false,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return false,
    };
    match config {
        Ok(_) => true,
        // System configs are normally root:tunnel-server 0640. Only an unreadable
        // config can use our unit as evidence; invalid or missing configs cannot.
        Err(e)
            if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            our_unit
        }
        Err(_) => false,
    }
}

/// POSIX shell word quoting, including embedded apostrophes. Apply this to the
/// complete script as well as each interpolated argument in it.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn rootless_setup_script(
    user: &str,
    config: &Path,
    data: &Path,
    need_ports: bool,
    need_linger: bool,
    migrate: bool,
) -> anyhow::Result<String> {
    let config = std::path::absolute(config).context("resolving config path")?;
    let config_dir = config.parent().filter(|dir| !dir.as_os_str().is_empty()).context("config path has no parent")?;
    let qpath = |path: &Path| shell_quote(&path.to_string_lossy());
    let user = shell_quote(user);
    let mut lines = Vec::new();
    if need_ports {
        lines.push(
            "echo net.ipv4.ip_unprivileged_port_start=80 > /etc/sysctl.d/60-tunnel-server.conf && sysctl -q --system"
                .to_string(),
        );
    }
    if need_linger {
        lines.push(format!("loginctl enable-linger {user}"));
    }
    if migrate {
        lines.push(format!("(systemctl disable --now {SERVICE_NAME}.service 2>/dev/null || true)"));
        lines.push(format!("runuser -u {user} -- mkdir -p -- {} {}", qpath(config_dir), qpath(data)));
        // Extract as the destination user: no root chown or root writes into
        // user-controlled paths. pipefail also checks the producer's exit code.
        let copy_data = format!(
            "tar -C {} -cf - . | runuser -u {user} -- tar --no-same-owner -C {} -xf -",
            shell_quote(mode::SYSTEM_DATA_DIR),
            qpath(data)
        );
        lines.push(format!("bash -o pipefail -c {}", shell_quote(&copy_data)));
        let write_config = shell_quote(&format!("umask 077; cat > {}", qpath(&config)));
        lines.push(format!("runuser -u {user} -- sh -c {write_config} < {}", shell_quote(mode::SYSTEM_CONFIG_PATH)));
        lines.push(format!(
            "mv {} {} && mv {} {}",
            shell_quote(mode::SYSTEM_CONFIG_DIR),
            shell_quote(&format!("{}.migrated", mode::SYSTEM_CONFIG_DIR)),
            shell_quote(mode::SYSTEM_DATA_DIR),
            shell_quote(&format!("{}.migrated", mode::SYSTEM_DATA_DIR))
        ));
        lines.push(format!("rm -f /etc/systemd/system/{SERVICE_NAME}.service && systemctl daemon-reload"));
    }
    Ok(lines.join(" && "))
}

/// Probe both transports and address families unless our running service may
/// already own the port. Reconfiguring an active install must remain possible.
fn check_stun_port(port: u16, service_active: bool) -> anyhow::Result<()> {
    if service_active {
        return Ok(());
    }
    for host in [std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED)] {
        let addr = std::net::SocketAddr::new(host, port);
        for result in [std::net::UdpSocket::bind(addr).map(drop), std::net::TcpListener::bind(addr).map(drop)] {
            if let Err(e) = result {
                // IPv6 can be disabled on the host.
                if host.is_ipv6() && (e.kind() == std::io::ErrorKind::AddrNotAvailable || e.raw_os_error() == Some(97))
                {
                    continue;
                }
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    bail!(
                        "port {port} is in use by another process (for example a coturn service); stop it and run setup again"
                    );
                }
                return Err(e).with_context(|| format!("checking STUN/TURN port {addr}"));
            }
        }
    }
    Ok(())
}

/// A config with only defaults, so `config.rs` stays the single source of
/// default values.
fn fresh_config() -> anyhow::Result<Config> {
    Ok(serde_json::from_value(serde_json::json!({
        "preview_zone": "",
        "api_host": "",
        "tunnel_host": "",
        "turn_host": "",
        "admin_token_hash": "",
        "acme": { "email": "" },
        "dns": { "provider": "cloudflare", "zone": "" },
    }))?)
}

/// Answers come from a flag, else a prompt, else (with `--yes`) the default.
struct Ask {
    yes: bool,
}

impl Ask {
    fn text<T>(
        &self,
        flag: Option<&str>,
        flag_name: &str,
        question: &str,
        default: &str,
        parse: impl Fn(&str) -> Result<T, String>,
    ) -> anyhow::Result<T> {
        if let Some(v) = flag {
            return parse(v).map_err(|e| anyhow::anyhow!("--{flag_name}: {e}"));
        }
        if self.yes {
            anyhow::ensure!(!default.is_empty(), "--{flag_name} is required with --yes");
            return parse(default).map_err(|e| anyhow::anyhow!("current {flag_name}: {e}"));
        }
        prompt::ask_with(question, default, parse)
    }

    fn bool(&self, flag: Option<bool>, question: &str, default: bool) -> anyhow::Result<bool> {
        match flag {
            Some(v) => Ok(v),
            None if self.yes => Ok(default),
            None => prompt::ask_bool(question, default),
        }
    }

    fn confirm(&self, question: &str) -> anyhow::Result<bool> {
        if self.yes { Ok(true) } else { prompt::ask_bool(question, true) }
    }

    fn secret(
        &self,
        file: Option<&Path>,
        flag_name: &str,
        question: &str,
        current: Option<&str>,
    ) -> anyhow::Result<String> {
        if let Some(path) = file {
            let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            let v = raw.trim().to_string();
            anyhow::ensure!(!v.is_empty(), "{} is empty", path.display());
            return Ok(v);
        }
        if self.yes {
            return current
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .with_context(|| format!("--{flag_name} is required with --yes"));
        }
        prompt::ask_secret(question, current)
    }
}

async fn ask_config(ask: &Ask, existing: Option<&Config>, args: &SetupArgs, mode: Mode) -> anyhow::Result<Config> {
    let mut cfg = match existing {
        Some(c) => c.clone(),
        None => fresh_config()?,
    };
    if mode.is_user() {
        // A migrated root config still points at /var/lib.
        cfg.data_dir = mode.data_dir()?;
    }

    // 1. The server hostname; the rest of the layout follows from it.
    let host = ask.text(
        args.host.as_deref(),
        "host",
        "Server hostname (API, sandbox tunnel, and *.<host> previews), e.g. tunnel.example.com",
        &cfg.tunnel_host,
        parse_host,
    )?;
    // 1b. Who uses it. With others, previews (code anyone wrote) must not be
    //     same-site with the UI, so they need their own registrable domain.
    let multi_user = ask.bool(
        args.multi_user,
        "Will people other than you use this server (invited friends or colleagues)?",
        existing.is_some_and(|c| c.ui_host.is_some() && !c.ui_same_site_as_previews()),
    )?;
    let preview_zone = match &args.preview_zone {
        Some(z) => parse_host(z).map_err(|e| anyhow::anyhow!("--preview-zone: {e}"))?,
        None if existing.is_some_and(|c| c.tunnel_host == host)
            && !(multi_user && crate::config::registrable(&cfg.preview_zone) == crate::config::registrable(&host)) =>
        {
            cfg.preview_zone.clone()
        }
        None if multi_user => ask.text(
            None,
            "preview-zone",
            "Preview domain on a separate registrable domain (previews are *.<this>), e.g. previews.example-previews.com",
            "",
            parse_host,
        )?,
        None => host.clone(),
    };
    let turn_host = match &args.turn_host {
        Some(t) => parse_host(t).map_err(|e| anyhow::anyhow!("--turn-host: {e}"))?,
        None if existing.is_some_and(|c| c.tunnel_host == host) => cfg.turn_host.clone(),
        None => format!("turn.{host}"),
    };
    let before = existing.map(layout);
    cfg.api_host = host.clone();
    cfg.tunnel_host = host.clone();
    cfg.preview_zone = preview_zone;
    cfg.turn_host = turn_host;

    // 1c. The web UI's own host (never under the preview zone).
    let ui_default = match (&cfg.ui_host, existing) {
        (Some(h), _) => h.clone(),
        // Re-running setup keeps a server without the UI that way unless asked.
        (None, Some(_)) if !multi_user => "none".to_string(),
        _ => default_ui_host(&cfg.tunnel_host, &cfg.preview_zone),
    };
    cfg.ui_host = ask.text(
        args.ui_host.as_deref(),
        "ui-host",
        "Web UI hostname (sign-in, machines, users; not under the preview zone), or none",
        &ui_default,
        parse_ui_host,
    )?;
    check_hosts(&cfg, multi_user)?;

    // 2. Who may frame previews.
    cfg.normalize_frame_ancestors();
    let current = if cfg.frame_ancestors.is_empty() { "none".to_string() } else { cfg.frame_ancestors.join(",") };
    cfg.frame_ancestors = ask.text(
        args.frame_ancestors.as_deref(),
        "frame-ancestors",
        "Sites that may show previews in an iframe (comma-separated, e.g. https://app.example.com,https://*.example.com; none for own origin only, * for any)",
        &current,
        parse_frame_ancestors,
    )?;

    // 3. Let's Encrypt contact.
    cfg.acme.email = ask.text(args.email.as_deref(), "email", "ACME contact email", &cfg.acme.email, parse_email)?;
    cfg.acme.staging = args.staging;

    // A provider setup does not support: records by hand (--skip-dns) and the
    // operator's own certificate. Then no DNS credentials are needed at all.
    let own_certificate = args.own_certificate.unwrap_or(cfg.acme.own_certificate);
    let manual_dns = args.skip_dns && own_certificate;
    if manual_dns {
        if cfg.dns.zone.is_empty() {
            cfg.dns.zone = parent_domain(&cfg.tunnel_host);
        }
        println!("Manual DNS and your own certificate: no DNS provider settings are needed.");
    } else {
        // 4. DNS provider, credentials, and zone (checked right away).
        let current = PROVIDERS.iter().position(|(k, _)| *k == cfg.dns.provider).unwrap_or(0);
        let provider = match args.dns_provider.as_deref() {
            Some(name) => PROVIDERS
                .iter()
                .find(|(_, n)| n.eq_ignore_ascii_case(name.trim()))
                .map(|(k, _)| *k)
                .with_context(|| format!("--dns-provider: unknown provider '{name}'"))?,
            None if ask.yes => PROVIDERS[current].0,
            None => {
                let names: Vec<&str> = PROVIDERS.iter().map(|(_, n)| *n).collect();
                PROVIDERS[prompt::ask_choice("DNS provider", &names, current)?].0
            }
        };
        // Credentials of a different provider are dropped, not carried over.
        if existing.map(|c| c.dns.provider) != Some(provider) {
            cfg.dns.api_token = None;
            cfg.dns.aws_access_key_id = None;
            cfg.dns.aws_secret_access_key = None;
            cfg.dns.route53_hosted_zone_id = None;
        }
        cfg.dns.provider = provider;
        match provider {
            DnsProviderKind::Route53 => {
                let key_id = cfg.dns.aws_access_key_id.clone().unwrap_or_default();
                cfg.dns.aws_access_key_id =
                    Some(ask.text(None, "aws-access-key-id (config)", "AWS access key id", &key_id, non_empty)?);
                cfg.dns.aws_secret_access_key = Some(ask.secret(
                    args.dns_token_file.as_deref(),
                    "dns-token-file",
                    "AWS secret access key",
                    cfg.dns.aws_secret_access_key.as_deref(),
                )?);
                let zone_id = cfg.dns.route53_hosted_zone_id.clone().unwrap_or_default();
                cfg.dns.route53_hosted_zone_id = Some(ask.text(
                    None,
                    "route53-hosted-zone-id (config)",
                    "Route53 hosted zone id",
                    &zone_id,
                    non_empty,
                )?);
                cfg.dns.api_token = None;
            }
            _ => {
                let hint = match provider {
                    DnsProviderKind::Cloudflare => {
                        "Cloudflare API token (Zone → DNS → Edit AND Zone → Zone → Read, limited to this zone)"
                    }
                    DnsProviderKind::Hetzner => "Hetzner DNS API token",
                    _ => "DigitalOcean API token (domain read/write)",
                };
                cfg.dns.api_token = Some(ask.secret(
                    args.dns_token_file.as_deref(),
                    "dns-token-file",
                    hint,
                    cfg.dns.api_token.as_deref(),
                )?);
                cfg.dns.aws_access_key_id = None;
                cfg.dns.aws_secret_access_key = None;
                cfg.dns.route53_hosted_zone_id = None;
            }
        }
        cfg.dns.zone = choose_zone(ask, &cfg, args).await?;
        // 4b. Names outside that zone (a separate preview domain) need their own zone.
        //     Explicit --preview-dns-* flags replace the settings of an existing one.
        let hosts = record_hosts(&cfg);
        cfg.extra_dns.retain(|d| hosts.iter().any(|h| in_zone(h, &d.zone)));
        let overrides = args.preview_dns_provider.is_some()
            || args.preview_dns_zone.is_some()
            || args.preview_dns_token_file.is_some();
        let outside = hosts.iter().map(|h| h.trim_start_matches("*.")).find(|h| !in_zone(h, &cfg.dns.zone));
        if let Some(outside) = outside {
            let current = cfg.extra_dns.iter().position(|d| in_zone(outside, &d.zone));
            if current.is_none() || overrides {
                let zone = ask_extra_zone(ask, &cfg, args, outside, current.map(|i| &cfg.extra_dns[i])).await?;
                if let Some(i) = current {
                    cfg.extra_dns.remove(i);
                }
                cfg.extra_dns.push(zone);
            }
        }
    }
    cfg.acme.own_certificate = own_certificate;

    // 5. WebRTC.
    cfg.webrtc.enabled = ask.bool(args.webrtc, "Enable WebRTC (built-in STUN/TURN relay)?", cfg.webrtc.enabled)?;

    if !manual_dns {
        check_names(&cfg)?;
    }
    print_layout(&cfg, before.as_ref());
    anyhow::ensure!(ask.confirm("Continue with this layout?")?, "stopped; nothing was changed");
    Ok(cfg)
}

/// `host` is the zone or inside it.
fn in_zone(host: &str, zone: &str) -> bool {
    let host = host.trim_start_matches("*.");
    host == zone || host.ends_with(&format!(".{zone}"))
}

/// The UI next to the API when previews have their own domain; otherwise a
/// sibling of the server name (`tunnel.example.com` → `tunnel-ui.example.com`),
/// since names under the preview zone are previews.
fn default_ui_host(host: &str, preview_zone: &str) -> String {
    if host != preview_zone && !host.ends_with(&format!(".{preview_zone}")) {
        return host.to_string();
    }
    match host.split_once('.') {
        Some((first, rest)) if rest.contains('.') => format!("{first}-ui.{rest}"),
        _ => format!("tunnel-ui.{host}"),
    }
}

fn parse_ui_host(input: &str) -> Result<Option<String>, String> {
    if input.trim().eq_ignore_ascii_case("none") { Ok(None) } else { parse_host(input).map(Some) }
}

/// The UI never under the preview zone; with other users, previews never
/// same-site with it (a separate registrable domain); alone, only a warning.
fn check_hosts(cfg: &Config, multi_user: bool) -> anyhow::Result<()> {
    if let Some(ui) = &cfg.ui_host {
        anyhow::ensure!(
            ui != &cfg.preview_zone && !ui.ends_with(&format!(".{}", cfg.preview_zone)),
            "the web UI ({ui}) must not be the preview zone or a name under it: previews there could read or forge its requests"
        );
    }
    if multi_user {
        let ui = cfg.ui_host.as_deref().context("a server for several people needs the web UI (invites, sign-in)")?;
        anyhow::ensure!(
            crate::config::registrable(ui) != crate::config::registrable(&cfg.preview_zone),
            "with other users, previews must be on a separate registrable domain from the UI ({ui}): their \
             code would otherwise be same-site with it. Use e.g. --preview-zone previews.example-previews.com"
        );
    }
    Ok(())
}

/// DNS settings for the zone holding `host` when it is outside the server's
/// zone (typically a separate preview domain), possibly at another provider.
async fn ask_extra_zone(
    ask: &Ask,
    cfg: &Config,
    args: &SetupArgs,
    host: &str,
    existing: Option<&DnsConfig>,
) -> anyhow::Result<DnsConfig> {
    println!("{host} is not in the DNS zone {}; it needs its own zone settings.", cfg.dns.zone);
    let provider = match args.preview_dns_provider.as_deref() {
        Some(name) => PROVIDERS
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name.trim()))
            .map(|(k, _)| *k)
            .with_context(|| format!("--preview-dns-provider: unknown provider '{name}'"))?,
        None if existing.is_some() => existing.map(|e| e.provider).expect("checked"),
        None if ask.yes => bail!("--preview-dns-provider is required with --yes for {host}"),
        None => {
            let names: Vec<&str> = PROVIDERS.iter().map(|(_, n)| *n).collect();
            PROVIDERS[prompt::ask_choice(&format!("DNS provider for {host}"), &names, 0)?].0
        }
    };
    anyhow::ensure!(
        provider != DnsProviderKind::Route53,
        "Route53 is supported for the server's main zone only; use another provider for {host} or put it in that zone"
    );
    // A different provider's token never carries over.
    let same_provider = existing.filter(|e| e.provider == provider);
    let token = ask.secret(
        args.preview_dns_token_file.as_deref(),
        "preview-dns-token-file",
        &format!("API token for the DNS zone of {host}"),
        same_provider.and_then(|e| e.api_token.as_deref()),
    )?;
    let zone = match &args.preview_dns_zone {
        Some(z) => parse_host(z).map_err(|e| anyhow::anyhow!("--preview-dns-zone: {e}"))?,
        None if same_provider.is_some() => same_provider.map(|e| e.zone.clone()).expect("checked"),
        None if provider == DnsProviderKind::Cloudflare => {
            let zones =
                dns::cloudflare_zones(&token).await.context("checking the Cloudflare token for the preview zone")?;
            dns::pick_zone(host, &zones)
                .with_context(|| format!("that Cloudflare token cannot see a zone holding {host}"))?
        }
        None => {
            ask.text(None, "preview-dns-zone", &format!("DNS zone holding {host}"), &parent_domain(host), parse_host)?
        }
    };
    anyhow::ensure!(in_zone(host, &zone), "{host} is not inside the DNS zone {zone}");
    Ok(DnsConfig {
        provider,
        zone,
        api_token: Some(token),
        aws_access_key_id: None,
        aws_secret_access_key: None,
        route53_hosted_zone_id: None,
    })
}

/// Cloudflare: the zones the token can see decide (the token is checked here).
/// Other providers: ask, defaulting to the host's parent domain.
async fn choose_zone(ask: &Ask, cfg: &Config, args: &SetupArgs) -> anyhow::Result<String> {
    let host = cfg.tunnel_host.as_str();
    if cfg.dns.provider == DnsProviderKind::Cloudflare {
        let token = cfg.dns.api_token.as_deref().unwrap_or_default();
        let zones = dns::cloudflare_zones(token).await.context(
            "checking the Cloudflare token (requires Zone → DNS → Edit AND Zone → Zone → Read for the zone)",
        )?;
        let zone = match &args.dns_zone {
            Some(z) => parse_host(z).map_err(|e| anyhow::anyhow!("--dns-zone: {e}"))?,
            None => match dns::pick_zone(host, &zones) {
                Some(z) => z,
                None if zones.is_empty() => {
                    bail!(
                        "the Cloudflare token cannot see any zone; grant Zone → DNS → Edit AND Zone → Zone → Read for the zone that holds {host}"
                    )
                }
                None => bail!(
                    "{host} is not in any zone this Cloudflare token can see ({}); give it access to the right zone",
                    zones.join(", ")
                ),
            },
        };
        anyhow::ensure!(
            zones.contains(&zone),
            "the Cloudflare token cannot see zone {zone} (it sees: {})",
            if zones.is_empty() { "nothing".to_string() } else { zones.join(", ") }
        );
        println!("Cloudflare token OK; DNS zone {zone}");
        return Ok(zone);
    }
    let guess = if !cfg.dns.zone.is_empty() && (host == cfg.dns.zone || host.ends_with(&format!(".{}", cfg.dns.zone))) {
        cfg.dns.zone.clone()
    } else {
        parent_domain(host)
    };
    ask.text(args.dns_zone.as_deref(), "dns-zone", "DNS zone managed at the provider", &guess, parse_host)
}

/// `a.b.example.com` → `example.com` (a guess; public suffixes like co.uk need the flag).
fn parent_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

type Layout = Vec<(&'static str, String)>;

fn layout(cfg: &Config) -> Layout {
    let mut rows = vec![
        ("Web UI", cfg.ui_host.as_ref().map(|h| format!("https://{h}")).unwrap_or_else(|| "none".into())),
        ("API", format!("https://{}", cfg.api_host)),
        ("Sandbox tunnel", format!("wss://{}", cfg.tunnel_host)),
        ("Previews", format!("https://{{port}}-{{id}}.{}", cfg.preview_zone)),
    ];
    if cfg.webrtc.enabled {
        rows.push(("TURN", cfg.turn_host.clone()));
    }
    rows.push(("DNS zone", format!("{} ({:?})", cfg.dns.zone, cfg.dns.provider).to_lowercase()));
    for extra in &cfg.extra_dns {
        rows.push(("DNS zone", format!("{} ({:?})", extra.zone, extra.provider).to_lowercase()));
    }
    if cfg.acme.own_certificate {
        rows.push(("Certificate", "your own (not issued or renewed)".into()));
    }
    let parents = if cfg.frame_ancestors.iter().any(|s| s == "*") {
        "any site".to_string()
    } else if cfg.frame_ancestors.is_empty() {
        "own origin only".to_string()
    } else {
        cfg.frame_ancestors.join(", ")
    };
    rows.push(("Iframe parents", parents));
    rows
}

fn print_layout(cfg: &Config, before: Option<&Layout>) {
    println!("\nLayout:");
    for (name, value) in layout(cfg) {
        let old = before.and_then(|b| b.iter().find(|(n, _)| *n == name)).map(|(_, v)| v);
        match old {
            Some(old) if *old != value => println!("  {name:<15} {value}   (was {old})"),
            _ => println!("  {name:<15} {value}"),
        }
    }
    if cfg.ui_same_site_as_previews() {
        println!(
            "\nNote: previews share the web UI's registrable domain ({}). Fine for a server only you use; \
             for others, use a separate preview domain (see the README's \"Hosts and domains\").",
            crate::config::registrable(&cfg.preview_zone)
        );
    }
    println!("\nDNS records (each pointing at this server; setup creates them unless --skip-dns):");
    for host in record_hosts(cfg) {
        println!("  {host}");
    }
    if cfg.preview_zone == cfg.dns.zone && cfg.preview_zone != cfg.tunnel_host && cfg.preview_zone != cfg.api_host {
        println!(
            "Note: the preview zone is the DNS zone apex ({}). It must point here for access links and password sign-in; setup will verify it but will not replace its records.",
            cfg.preview_zone
        );
    }
    println!();
}

/// Every record setup creates must live inside a configured zone.
fn check_names(cfg: &Config) -> anyhow::Result<()> {
    let mut hosts = vec![&cfg.preview_zone, &cfg.api_host, &cfg.tunnel_host];
    if cfg.webrtc.enabled {
        hosts.push(&cfg.turn_host);
    }
    if let Some(ui) = &cfg.ui_host {
        hosts.push(ui);
    }
    for host in hosts {
        anyhow::ensure!(cfg.dns_for(host).is_some(), "{host} is not inside the DNS zone {}", cfg.dns.zone);
    }
    Ok(())
}

/// `*`, or a comma-separated list of `https://host[:port]` origins whose host
/// may start with a `*.` wildcard label (CSP source syntax).
fn parse_frame_ancestors(input: &str) -> Result<Vec<String>, String> {
    let items: Vec<&str> = input.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if items.is_empty() || (items.len() == 1 && items[0].eq_ignore_ascii_case("none")) {
        return Ok(Vec::new());
    }
    if items == ["*"] {
        return Ok(vec!["*".to_string()]);
    }
    let mut out = Vec::new();
    for item in items {
        if item == "*" {
            return Err("use * alone (any site) or list specific sites".to_string());
        }
        let parsed = match item.strip_prefix("https://*.") {
            Some(rest) => parse_origin(&format!("https://{rest}")).map(|o| o.replacen("https://", "https://*.", 1)),
            None => parse_origin(item),
        }?;
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
    Ok(out)
}

fn parse_host(input: &str) -> Result<String, String> {
    let host = input.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if host.len() > 253 || !host.contains('.') || !host.split('.').all(valid_label) {
        return Err(format!("'{input}' is not a valid DNS name"));
    }
    Ok(host)
}

fn parse_origin(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('/');
    let rest = trimmed.strip_prefix("https://").ok_or_else(|| "the origin must start with https://".to_string())?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(p) = port {
        p.parse::<u16>().map_err(|_| format!("bad port in '{input}'"))?;
    }
    let host = parse_host(host).map_err(|_| format!("'{input}' is not https://<host>[:port] (no path)"))?;
    Ok(match port {
        Some(p) => format!("https://{host}:{p}"),
        None => format!("https://{host}"),
    })
}

fn parse_email(input: &str) -> Result<String, String> {
    let email = input.trim();
    match email.split_once('@') {
        Some((local, domain)) if !local.is_empty() && domain.contains('.') && !email.contains(' ') => {
            Ok(email.to_string())
        }
        _ => Err(format!("'{input}' is not an email address")),
    }
}

fn non_empty(input: &str) -> Result<String, String> {
    let v = input.trim();
    if v.is_empty() { Err("a value is required".to_string()) } else { Ok(v.to_string()) }
}

async fn detect_public_ips(existing: Option<&Config>, yes: bool) -> anyhow::Result<(Ipv4Addr, Option<Ipv6Addr>)> {
    let v4 = match fetch_ip("https://api.ipify.org", IpAddr::V4(Ipv4Addr::UNSPECIFIED)).await {
        Ok(IpAddr::V4(ip)) => ip,
        other => {
            if let Err(e) = &other {
                println!("Could not detect the public IPv4 address: {e:#}");
            }
            public_ipv4_fallback(existing, yes)?
        }
    };
    let v6 = match fetch_ip("https://api6.ipify.org", IpAddr::V6(Ipv6Addr::UNSPECIFIED)).await {
        Ok(IpAddr::V6(ip)) => Some(ip),
        _ => None,
    };
    println!("Public IPv4: {v4}");
    match v6 {
        Some(ip) => println!("Public IPv6: {ip}"),
        None => println!("Public IPv6: none"),
    }
    Ok((v4, v6))
}

fn public_ipv4_fallback(existing: Option<&Config>, yes: bool) -> anyhow::Result<Ipv4Addr> {
    let current = existing.and_then(|c| c.public_ipv4);
    if yes {
        let ip = current.context("could not detect the public IPv4 address; re-run setup interactively")?;
        println!("Note: reusing the configured public IPv4 address {ip} (--yes).");
        return Ok(ip);
    }
    let default = current.map(|ip| ip.to_string()).unwrap_or_default();
    prompt::ask_with("Public IPv4 address of this VM", &default, |s| {
        s.trim().parse::<Ipv4Addr>().map_err(|_| format!("'{s}' is not an IPv4 address"))
    })
}

/// Bind the request to one address family so the echo service sees that family.
async fn fetch_ip(url: &str, local: IpAddr) -> anyhow::Result<IpAddr> {
    let client = reqwest::Client::builder()
        // Preserve bundled Mozilla roots even when the host has no CA bundle.
        .tls_certs_only(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| reqwest::Certificate::from_der(der).expect("bundled Mozilla root is valid DER")),
        )
        .timeout(Duration::from_secs(10))
        .local_address(local)
        .build()?;
    let text = client.get(url).send().await?.error_for_status()?.text().await?;
    Ok(text.trim().parse()?)
}

fn ensure_service_user(cfg: &Config) -> anyhow::Result<()> {
    if os::succeeds("id", &["-u", SERVICE_USER]) {
        let passwd = os::output("getent", &["passwd", SERVICE_USER])?;
        return check_service_account(&passwd, &cfg.data_dir);
    }
    println!("Creating system user {SERVICE_USER}");
    let home = cfg.data_dir.to_string_lossy();
    let mut args = vec!["--system", "--home-dir", &*home, "--no-create-home", "--shell", "/usr/sbin/nologin"];
    if os::succeeds("getent", &["group", SERVICE_USER]) {
        args.extend(["--gid", SERVICE_USER]);
    } else {
        args.push("--user-group");
    }
    args.push(SERVICE_USER);
    os::run("useradd", &args)
}

fn check_service_account(passwd: &str, data_dir: &Path) -> anyhow::Result<()> {
    let fields: Vec<_> = passwd.trim_end().split(':').collect();
    anyhow::ensure!(
        fields.len() == 7
            && fields[0] == SERVICE_USER
            && (fields[6].ends_with("/nologin") || fields[6].ends_with("/false")),
        "account {SERVICE_USER} exists and is not a Tunnel service account; remove/rename it or set its home to {} and its shell to /usr/sbin/nologin",
        data_dir.display()
    );
    anyhow::ensure!(
        Path::new(fields[5]) == data_dir,
        "account {SERVICE_USER} exists with home {}, expected {}; remove/rename it or set its home to {}",
        fields[5],
        data_dir.display(),
        data_dir.display()
    );
    Ok(())
}

fn is_dedicated_config_dir(dir: &Path) -> bool {
    dir.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "tunnel" || name.starts_with("tunnel-") || name.starts_with("tunnel."))
}

fn ensure_dirs(cfg: &Config, config_path: &Path, mode: Mode) -> anyhow::Result<()> {
    let data = &cfg.data_dir;
    mode::check_data_dir(data, mode == Mode::System)?;
    if mode == Mode::System {
        mode::check_system_config_dir(config_path)?;
    }
    std::fs::create_dir_all(data).with_context(|| format!("creating {}", data.display()))?;
    let etc = config_path.parent().context("config path has no parent directory")?;
    std::fs::create_dir_all(etc).with_context(|| format!("creating {}", etc.display()))?;
    let dedicated = is_dedicated_config_dir(etc);

    if mode.is_user() {
        crate::files::set_mode(data, 0o700)?;
        if dedicated {
            crate::files::set_mode(etc, 0o700)?;
        }
        return Ok(());
    }
    crate::files::set_mode(data, 0o750)?;
    mode::chown_recursive(data, SERVICE_USER)?;
    anyhow::ensure!(dedicated, "root config must be in a dedicated tunnel directory");
    for component in etc.ancestors() {
        let meta = std::fs::symlink_metadata(component)?;
        anyhow::ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "config directory must not contain symlinks");
    }
    // Do not give the service write permission to the directory or its config.
    os::run("chown", &["--no-dereference", &format!("root:{SERVICE_USER}"), "--", &etc.to_string_lossy()])?;
    crate::files::set_mode(etc, 0o750)?;
    Ok(())
}

/// Fill in missing secrets; returns the plaintext admin token if one was minted.
fn generate_secrets(cfg: &mut Config) -> Option<String> {
    let mut minted = None;
    if cfg.admin_token_hash.is_empty() {
        let token = tokens::random_token(ADMIN_TOKEN_PREFIX);
        cfg.admin_token_hash = tokens::hash_token(&token);
        minted = Some(token);
        println!("Generated a new admin API token (shown at the end)");
    }
    if cfg.ui_host.is_some() && cfg.ui_secret.as_deref().is_none_or(|s| s.len() < 32) {
        cfg.ui_secret = Some(tokens::random_secret());
        println!("Generated the web UI secret");
    }
    if cfg.webrtc.enabled && cfg.webrtc.static_auth_secret.is_empty() {
        cfg.webrtc.static_auth_secret = tokens::random_secret();
        println!("Generated the TURN static auth secret");
    }
    minted
}

fn record_hosts(cfg: &Config) -> Vec<String> {
    let mut hosts = vec![
        format!("*.{}", cfg.preview_zone),
        cfg.preview_zone.clone(),
        cfg.api_host.clone(),
        cfg.tunnel_host.clone(),
    ];
    if let Some(ui) = &cfg.ui_host {
        hosts.push(ui.clone());
    }
    if cfg.webrtc.enabled && !cfg.covered_by_wildcard(&cfg.turn_host) {
        hosts.push(cfg.turn_host.clone());
    }
    if cfg.preview_zone == cfg.dns.zone && cfg.preview_zone != cfg.tunnel_host && cfg.preview_zone != cfg.api_host {
        hosts.retain(|host| host != &cfg.preview_zone);
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

async fn configure_dns(cfg: &Config) -> anyhow::Result<()> {
    let v4 = cfg.public_ipv4.context("no public IPv4 address")?;
    for host in record_hosts(cfg) {
        let provider = dns::Provider::for_host(cfg, &host)?;
        println!("  {host} A {v4}");
        provider.upsert(&host, "A", &v4.to_string()).await?;
        if let Some(v6) = cfg.public_ipv6 {
            println!("  {host} AAAA {v6}");
            provider.upsert(&host, "AAAA", &v6.to_string()).await?;
        }
    }
    Ok(())
}

fn dns_verification_names(cfg: &Config, probe: String) -> Vec<String> {
    let mut names = vec![cfg.api_host.clone(), cfg.tunnel_host.clone(), cfg.preview_zone.clone(), probe];
    names.extend(cfg.ui_host.clone());
    names.sort();
    names.dedup();
    names
}

/// Wait until public resolvers return this VM for the server host and a fresh
/// (never-queried, so never negatively cached) preview name. Runs even with
/// `--skip-dns`: issuing a certificate for names that point elsewhere fails later
/// with a far less useful error.
async fn verify_dns(cfg: &Config, v4: Ipv4Addr, v6: Option<Ipv6Addr>) -> anyhow::Result<()> {
    step("Verifying DNS");
    let probe = format!("1-{}.{}", tokens::random_tunnel_id(), cfg.preview_zone);
    let names = dns_verification_names(cfg, probe);
    let mut checks: Vec<(String, &str, IpAddr)> = Vec::new();
    for name in names {
        checks.push((name.clone(), "A", IpAddr::V4(v4)));
        if let Some(v6) = v6 {
            checks.push((name, "AAAA", IpAddr::V6(v6)));
        }
    }
    println!(
        "Waiting for public DNS (polling every {}s, up to {} min)",
        DNS_POLL.as_secs(),
        DNS_TIMEOUT.as_secs() / 60
    );
    let deadline = Instant::now() + DNS_TIMEOUT;
    let mut warned_proxy = false;
    loop {
        let mut pending = Vec::new();
        for (name, rtype, want) in &checks {
            let seen = match dns::resolve_public(name, rtype).await {
                Ok(values) => values,
                Err(e) => vec![format!("lookup error: {e:#}")],
            };
            if !seen.iter().any(|v| v.parse::<IpAddr>().ok() == Some(*want)) {
                pending.push((name, rtype, want, seen));
            }
        }
        if pending.is_empty() {
            println!("DNS resolves to this VM");
            return Ok(());
        }
        let proxied: Vec<&String> = pending
            .iter()
            .filter(|(_, _, _, seen)| seen.iter().any(|v| v.parse().is_ok_and(is_cloudflare_proxy)))
            .map(|(name, ..)| *name)
            .collect();
        if !proxied.is_empty() && !warned_proxy {
            warned_proxy = true;
            eprintln!(
                "{} resolve to Cloudflare's proxy, not this server. Set those records to \"DNS only\" \
                 (grey cloud) in Cloudflare; TLS must end on this server.",
                proxied.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        if Instant::now() >= deadline {
            eprintln!("DNS did not converge:");
            for (name, rtype, want, seen) in &pending {
                let seen = if seen.is_empty() { "nothing".to_string() } else { seen.join(", ") };
                eprintln!("  {name} {rtype}: expected {want}, saw {seen}");
            }
            bail!("DNS records do not resolve to this VM; fix them (or wait) and re-run setup");
        }
        tokio::time::sleep(DNS_POLL).await;
    }
}

/// Cloudflare's published proxy ranges (an orange-cloud record answers with these).
fn is_cloudflare_proxy(ip: IpAddr) -> bool {
    const V4: [(u32, u32); 7] = [
        (0x6810_0000, 13), // 104.16.0.0/13
        (0x6818_0000, 14), // 104.24.0.0/14
        (0xAC40_0000, 13), // 172.64.0.0/13
        (0xA29E_0000, 15), // 162.158.0.0/15
        (0xBC72_6000, 20), // 188.114.96.0/20
        (0xC629_8000, 17), // 198.41.128.0/17
        (0x6715_F400, 22), // 103.21.244.0/22
    ];
    match ip {
        IpAddr::V4(v4) => {
            let n = u32::from(v4);
            V4.iter().any(|(net, len)| n >> (32 - len) == net >> (32 - len))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] == 0x2606 && s[1] == 0x4700) || (s[0] == 0x2a06 && s[1] & 0xfe00 == 0x9800)
        }
    }
}

async fn ensure_certificate(cfg: &Config) -> anyhow::Result<()> {
    let status = tls::cert_status(cfg);
    if cfg.acme.own_certificate {
        return match status {
            tls::CertStatus::Valid { not_after } => {
                println!("Own certificate is valid until {} and covers every name", format_unix(not_after));
                Ok(())
            }
            // Still usable: say so, and carry on.
            tls::CertStatus::NeedsRenewal => {
                println!(
                    "Warning: your certificate is in its last third of validity; replace fullchain.pem and privkey.pem in {} soon",
                    cfg.cert_dir().display()
                );
                Ok(())
            }
            other => bail!(
                "own certificate: {other:?}. Put fullchain.pem and privkey.pem covering {} into {} and re-run setup",
                cfg.cert_names().join(", "),
                cfg.cert_dir().display()
            ),
        };
    }
    // A staging leftover is "valid" by dates and names but untrusted.
    let staging_leftover = !cfg.acme.staging && cert_is_staging(cfg);
    match status {
        tls::CertStatus::Valid { not_after } if !staging_leftover => {
            println!("Certificate is valid until {} (unix {not_after}); not reissuing", format_unix(not_after));
            return Ok(());
        }
        _ if staging_leftover => println!("Replacing the Let's Encrypt staging certificate with a production one"),
        other => println!("Certificate status: {other:?}; issuing via DNS-01 for {}", cfg.cert_names().join(", ")),
    }
    acme::issue(cfg).await.context("issuing the certificate")?;
    println!("Certificate issued");
    Ok(())
}

/// Let's Encrypt staging intermediates are named "(STAGING) ...".
fn cert_is_staging(cfg: &Config) -> bool {
    let Ok(pem) = std::fs::read(cfg.cert_dir().join("fullchain.pem")) else {
        return false;
    };
    match x509_parser::pem::parse_x509_pem(&pem) {
        Ok((_, block)) => block.parse_x509().map(|cert| cert.issuer().to_string().contains("STAGING")).unwrap_or(false),
        Err(_) => false,
    }
}

fn format_unix(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .map(|t| format!("{} {:02}:{:02} UTC", t.date(), t.hour(), t.minute()))
        .unwrap_or_else(|_| secs.to_string())
}

async fn self_test(cfg: &Config, mode: Mode) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        // Preserve bundled Mozilla roots even when the host has no CA bundle.
        .tls_certs_only(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| reqwest::Certificate::from_der(der).expect("bundled Mozilla root is valid DER")),
        )
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .tls_danger_accept_invalid_certs(cfg.acme.staging)
        .build()?;
    let health = format!("https://{}/healthz", cfg.api_host);
    // A protected /healthz is a 404 without its token, which still proves TLS and routing.
    let want = if cfg.health_token_hash.is_some() { 404 } else { 200 };
    expect_status(&client, &health, want, mode).await?;
    // Unknown tunnel id → 404 proves the wildcard cert and preview routing.
    let probe = format!("https://1-{}.{}/", tokens::random_tunnel_id(), cfg.preview_zone);
    expect_status(&client, &probe, 404, mode).await?;
    println!("Self-test passed");
    Ok(())
}

/// Retries for a short while: the service may have just (re)started.
async fn expect_status(client: &reqwest::Client, url: &str, want: u16, mode: Mode) -> anyhow::Result<()> {
    let deadline = Instant::now() + SELF_TEST_TIMEOUT;
    loop {
        let (outcome, timed_out) = match client.get(url).send().await {
            Ok(resp) if resp.status().as_u16() == want => {
                println!("  GET {url} -> {want}");
                return Ok(());
            }
            Ok(resp) => (format!("HTTP {}", resp.status()), false),
            Err(e) => (format!("{:#}", anyhow::Error::from(e)), true),
        };
        if Instant::now() >= deadline {
            let hint = if timed_out && mode.service_state(&format!("{SERVICE_NAME}.service")) == "active" {
                "the service is running, so a firewall is probably dropping inbound 443 \
                 (check the cloud provider's firewall)"
                    .to_string()
            } else {
                format!("check `{}`", mode.journal_hint())
            };
            bail!(
                "self-test GET {url}: expected HTTP {want}, got {outcome}; {hint} \
                 (re-run with --skip-self-test to bypass)"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn print_token_box(cfg: &Config, token: &str) {
    let lines = [
        "Admin API token (shown once; only its hash is stored):".to_string(),
        String::new(),
        format!("TUNNEL_API=https://{}", cfg.api_host),
        format!("TUNNEL_ADMIN_TOKEN={token}"),
    ];
    let width = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let rule = "-".repeat(width + 2);
    println!("+{rule}+");
    for line in &lines {
        println!("| {line:<width$} |");
    }
    println!("+{rule}+");
}

fn finish(cfg: &Config, mode: Mode, new_token: Option<&str>) {
    println!("\nSetup complete.\n");
    if let Some(ui) = &cfg.ui_host {
        println!("  Web UI          https://{ui}");
    }
    println!("  API             https://{}", cfg.api_host);
    println!("  Sandbox server  TUNNEL_SERVER=wss://{}", cfg.tunnel_host);
    println!("  Previews        https://{{port}}-{{id}}.{}", cfg.preview_zone);
    println!("  Logs            {}", mode.journal_hint());
    println!();
    match new_token {
        Some(token) => {
            print_token_box(cfg, token);
            println!("Give these to the backend that calls the management API. They will not be shown again.");
        }
        None => {
            println!("The existing admin token was kept. Environment for API clients:");
            println!("  TUNNEL_API=https://{}", cfg.api_host);
            println!("  TUNNEL_ADMIN_TOKEN=<existing token>  (lost it? run `tunnel-server token rotate`)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_directory_takeover_requires_a_config_or_no_entries() {
        let dir = Path::new("/etc/tunnel-server");
        check_config_dir_takeover(dir, false, false).unwrap();
        check_config_dir_takeover(dir, true, false).unwrap();
        check_config_dir_takeover(dir, true, true).unwrap();
        assert_eq!(
            check_config_dir_takeover(dir, false, true).unwrap_err().to_string(),
            "/etc/tunnel-server exists and holds no Tunnel config; refusing to take it over"
        );
    }

    #[test]
    fn system_preflight_checks_existing_unit_and_config_directory() {
        let dir =
            std::env::temp_dir().join(format!("tunnel-preflight-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let config_dir = dir.join("tunnel-server");
        let config = config_dir.join("config.toml");
        let unit = dir.join("tunnel-server.service");
        // Missing and empty config directories are both safe for a fresh install.
        system_preflight(&config, &unit).unwrap();
        std::fs::create_dir(&config_dir).unwrap();
        system_preflight(&config, &unit).unwrap();
        let unrelated = config_dir.join("autossh.conf");
        std::fs::write(&unrelated, "foreign settings").unwrap();
        assert!(system_preflight(&config, &unit).unwrap_err().to_string().contains("holds no Tunnel config"));
        std::fs::write(&config, "[ssh]\nport = 22\n").unwrap();
        assert!(system_preflight(&config, &unit).is_err());
        fresh_config().unwrap().save(&config).unwrap();
        system_preflight(&config, &unit).unwrap();
        std::fs::write(&unit, "[Service]\nExecStart=/usr/local/bin/tunnel-server serve\n").unwrap();
        system_preflight(&config, &unit).unwrap();
        std::fs::write(&unit, "[Service]\nExecStart=/usr/bin/autossh -N example.com\n").unwrap();
        assert!(system_preflight(&config, &unit).unwrap_err().to_string().contains("refusing to overwrite"));
        std::fs::remove_file(&config).unwrap();
        // A foreign unit is refused before checking its populated config directory.
        assert!(system_preflight(&config, &unit).unwrap_err().to_string().contains("refusing to overwrite"));
        assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "foreign settings");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn system_install_requires_a_valid_config() {
        let dir =
            std::env::temp_dir().join(format!("tunnel-preflight-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let config = dir.join("config.toml");
        let unit = dir.join("tunnel-server.service");
        assert!(!is_system_install(&config, &unit));
        std::fs::write(&unit, "[Service]\nExecStart=/usr/local/bin/tunnel-server serve\n").unwrap();
        assert!(!is_system_install(&config, &unit));
        for unrelated in ["[ssh]\nport = 22\n", "not valid TOML", ""] {
            std::fs::write(&config, unrelated).unwrap();
            assert!(!is_system_install(&config, &unit));
        }
        fresh_config().unwrap().save(&config).unwrap();
        assert!(is_system_install(&config, &unit));
        std::fs::remove_file(&unit).unwrap();
        assert!(is_system_install(&config, &unit));
        std::fs::write(&unit, "[Service]\nExecStart=/usr/bin/autossh -N example.com\n").unwrap();
        let migrate = is_system_install(&config, &unit);
        assert!(!migrate);
        let script = rootless_setup_script(
            "test",
            Path::new("/home/test/.config/tunnel-server/config.toml"),
            Path::new("/home/test/.local/share/tunnel"),
            true,
            true,
            migrate,
        )
        .unwrap();
        for destructive in ["systemctl", "tar ", "mv ", "rm ", "/etc/tunnel-server", "/var/lib/tunnel"] {
            assert!(!script.contains(destructive));
        }
        // An unreadable unit cannot establish that it is safe to migrate either.
        std::fs::write(&unit, [0xff]).unwrap();
        assert!(!is_system_install(&config, &unit));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unreadable_system_config_requires_our_unit() {
        let dir =
            std::env::temp_dir().join(format!("tunnel-preflight-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let unit = dir.join("tunnel-server.service");
        // Inject the wrapped I/O error so this also tests the fallback as root.
        let denied = || -> anyhow::Result<Config> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)).context("reading config")
        };
        assert!(!system_install_from_config(denied(), &unit));
        std::fs::write(&unit, "[Service]\nExecStart=/usr/bin/autossh -N example.com\n").unwrap();
        assert!(!system_install_from_config(denied(), &unit));
        std::fs::write(&unit, "[Service]\nExecStart=:\"/usr/local/bin/tunnel-server\" serve\n").unwrap();
        assert!(system_install_from_config(denied(), &unit));
        let missing = Err(std::io::Error::from(std::io::ErrorKind::NotFound)).context("reading config");
        assert!(!system_install_from_config(missing, &unit));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rootless_setup_without_migration_leaves_system_install_alone() {
        let script = rootless_setup_script(
            "test",
            Path::new("/home/test/.config/tunnel-server/config.toml"),
            Path::new("/home/test/.local/share/tunnel"),
            true,
            true,
            false,
        )
        .unwrap();
        assert!(script.contains(
            "echo net.ipv4.ip_unprivileged_port_start=80 > /etc/sysctl.d/60-tunnel-server.conf && sysctl -q --system"
        ));
        assert!(script.contains("loginctl enable-linger"));
        for destructive in ["systemctl", "tar ", "mv ", "rm ", "/etc/tunnel-server", "/var/lib/tunnel"] {
            assert!(!script.contains(destructive));
        }
    }

    #[test]
    fn rootless_setup_migrates_new_system_names_and_preserves_user_paths() {
        let script = rootless_setup_script(
            "test",
            Path::new("/home/test/.config/tunnel-server/config.toml"),
            Path::new("/home/test/.local/share/tunnel"),
            true,
            true,
            true,
        )
        .unwrap();
        for command in [
            "systemctl disable --now tunnel-server.service",
            "/etc/sysctl.d/60-tunnel-server.conf",
            "runuser -u 'test' -- mkdir -p -- '/home/test/.config/tunnel-server' '/home/test/.local/share/tunnel'",
            "< '/etc/tunnel-server/config.toml'",
            "mv '/etc/tunnel-server' '/etc/tunnel-server.migrated' && mv '/var/lib/tunnel' '/var/lib/tunnel.migrated'",
            "rm -f /etc/systemd/system/tunnel-server.service && systemctl daemon-reload",
        ] {
            assert!(script.contains(command), "missing {command}");
        }
    }

    #[test]
    fn rootless_setup_migrates_to_explicit_config_path() {
        let config = Path::new("/home/test/custom config/relay.toml");
        let script =
            rootless_setup_script("test", config, Path::new("/home/test/.local/share/tunnel"), false, false, true)
                .unwrap();
        assert!(script.contains("mkdir -p -- '/home/test/custom config' '/home/test/.local/share/tunnel'"));
        let write_config = shell_quote(&format!("umask 077; cat > {}", shell_quote(&config.to_string_lossy())));
        assert!(
            script.contains(&format!("runuser -u 'test' -- sh -c {write_config} < '/etc/tunnel-server/config.toml'"))
        );
        assert!(!script.contains("/home/test/.config/tunnel-server"));
    }

    #[test]
    fn rootless_setup_resolves_relative_config_paths_before_migration() {
        let cwd = std::env::current_dir().unwrap();
        let data = Path::new("/home/test/.local/share/tunnel");
        for relative in ["config.toml", "custom config/relay.toml"] {
            let config = cwd.join(relative);
            let script = rootless_setup_script("test", Path::new(relative), data, false, false, true).unwrap();
            assert!(script.contains(&format!(
                "runuser -u 'test' -- mkdir -p -- {} {}",
                shell_quote(&config.parent().unwrap().to_string_lossy()),
                shell_quote(&data.to_string_lossy())
            )));
            let write_config = shell_quote(&format!("umask 077; cat > {}", shell_quote(&config.to_string_lossy())));
            assert!(
                script
                    .contains(&format!("runuser -u 'test' -- sh -c {write_config} < '/etc/tunnel-server/config.toml'"))
            );
            assert!(!script.contains("mkdir -p -- ''"));
        }
    }

    #[test]
    fn rootless_setup_rejects_config_paths_without_a_parent() {
        let data = Path::new("/home/test/.local/share/tunnel");
        assert!(rootless_setup_script("test", Path::new(""), data, false, false, true).is_err());
        assert_eq!(
            rootless_setup_script("test", Path::new("/"), data, false, false, true).unwrap_err().to_string(),
            "config path has no parent"
        );
    }

    #[test]
    fn existing_service_account_requires_matching_home_and_no_login_shell() {
        let home = Path::new("/var/lib/tunnel");
        for shell in ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"] {
            let passwd = format!("tunnel-server:x:123:123::/var/lib/tunnel:{shell}\n");
            check_service_account(&passwd, home).unwrap();
        }
        for passwd in [
            "tunnel-server:x:123:123::/var/lib/tunnel:/bin/bash\n",
            "tunnel-server:x:123:123::/home/tunnel:/bin/bash\n",
            "tunnel-server:x:123:123::/var/lib/tunnel:/bin/not-nologin\n",
            "tunnel-server:x:123:123::/var/lib/tunnel:\n",
            "other:x:123:123::/var/lib/tunnel:/bin/false\n",
            "tunnel-server:x:123:123::/var/lib/tunnel:/bin/false:extra\n",
            "tunnel-server:x:123:123\n",
            "",
        ] {
            let error = check_service_account(passwd, home).unwrap_err().to_string();
            assert!(error.contains("account tunnel-server exists and is not a Tunnel service account"));
            assert!(error.contains("remove/rename"));
        }
        check_service_account("tunnel-server:x:123:123::/srv/tunnel:/bin/false\n", Path::new("/srv/tunnel")).unwrap();
    }

    #[test]
    fn service_account_home_mismatch_reports_actual_and_expected_paths() {
        for shell in ["/usr/sbin/nologin", "/bin/false"] {
            let passwd = format!("tunnel-server:x:123:123::/home/tunnel:{shell}\n");
            assert_eq!(
                check_service_account(&passwd, Path::new("/var/lib/tunnel")).unwrap_err().to_string(),
                "account tunnel-server exists with home /home/tunnel, expected /var/lib/tunnel; remove/rename it or set its home to /var/lib/tunnel"
            );
        }
    }

    #[test]
    fn dedicated_config_dir_requires_a_tunnel_name_boundary() {
        for dir in ["/etc/tunnel-server", "/etc/tunnel", "/etc/tunnel-staging", "/etc/tunnel.dev"] {
            assert!(is_dedicated_config_dir(Path::new(dir)), "{dir}");
        }
        for dir in ["/etc/stunnel", "/etc", "/etc/tunnelbackup", "/etc/my-tunnel", "/"] {
            assert!(!is_dedicated_config_dir(Path::new(dir)), "{dir}");
        }
    }

    #[test]
    fn empty_frame_default_works_with_yes_and_layout_explains_it() {
        let ask = Ask { yes: true };
        assert!(ask.text(None, "frame-ancestors", "parents", "none", parse_frame_ancestors).unwrap().is_empty());
        assert!(ask.text(Some(""), "frame-ancestors", "parents", "none", parse_frame_ancestors).unwrap().is_empty());
        assert!(layout(&fresh_config().unwrap()).iter().any(|(k, v)| *k == "Iframe parents" && v == "own origin only"));
    }

    #[test]
    fn stun_preflight_rejects_busy_udp_and_tcp_ports() {
        let udp = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        assert!(
            check_stun_port(port, false)
                .unwrap_err()
                .to_string()
                .contains(&format!("port {port} is in use by another process"))
        );
        let tcp = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        assert!(
            check_stun_port(port, false)
                .unwrap_err()
                .to_string()
                .contains(&format!("port {port} is in use by another process"))
        );
        check_stun_port(0, false).unwrap();
    }

    #[test]
    fn stun_preflight_skips_busy_ports_for_active_service() {
        let udp = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        check_stun_port(udp.local_addr().unwrap().port(), true).unwrap();
        let tcp = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        check_stun_port(tcp.local_addr().unwrap().port(), true).unwrap();
    }

    #[test]
    fn shell_quoting_preserves_special_characters_in_nested_scripts() {
        let value = "/home/O'Neil/a b/$HOME/`id`/$(id)\nnext";
        let script = format!("printf '%s' {}", shell_quote(value));
        let out =
            std::process::Command::new("sh").args(["-c", &format!("sh -c {}", shell_quote(&script))]).output().unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, value.as_bytes());
        let script = rootless_setup_script(
            "O'Neil",
            Path::new(value).join("config.toml").as_path(),
            Path::new(value),
            true,
            true,
            true,
        )
        .unwrap();
        let syntax = std::process::Command::new("sh")
            .args(["-n", "-c", &format!("sh -c {}", shell_quote(&script))])
            .status()
            .unwrap();
        assert!(syntax.success());
        assert!(script.contains(&format!("mkdir -p -- {} {}", shell_quote(value), shell_quote(value))));
        assert!(!script.contains("chown -R"));
    }

    #[test]
    fn host_parsing() {
        assert_eq!(parse_host(" Example.COM. ").unwrap(), "example.com");
        assert!(parse_host("localhost").is_err());
        assert!(parse_host("-bad.example.com").is_err());
        assert!(parse_host("a_b.example.com").is_err());
    }

    #[test]
    fn origin_parsing() {
        assert_eq!(parse_origin("https://App.example.com/").unwrap(), "https://app.example.com");
        assert_eq!(parse_origin("https://app.example.com:8443").unwrap(), "https://app.example.com:8443");
        assert!(parse_origin("http://app.example.com").is_err());
        assert!(parse_origin("https://app.example.com/path").is_err());
        assert_eq!(parse_frame_ancestors("*").unwrap(), vec!["*"]);
        assert!(parse_frame_ancestors("").unwrap().is_empty());
        assert!(parse_frame_ancestors(" none ").unwrap().is_empty());
        assert_eq!(
            parse_frame_ancestors("https://App.example.com/, https://*.Example.com").unwrap(),
            vec!["https://app.example.com", "https://*.example.com"]
        );
        assert!(parse_frame_ancestors("*, https://a.example.com").is_err());
        assert!(parse_frame_ancestors("http://a.example.com").is_err());
    }

    #[test]
    fn fresh_config_has_defaults() {
        let cfg = fresh_config().unwrap();
        assert_eq!(cfg.data_dir, Path::new(crate::config::DEFAULT_DATA_DIR));
        assert!(!cfg.webrtc.enabled);
        assert!(cfg.frame_ancestors.is_empty());
    }

    #[test]
    fn secrets_are_not_regenerated() {
        let mut cfg = fresh_config().unwrap();
        cfg.webrtc.enabled = true;
        let token = generate_secrets(&mut cfg).unwrap();
        assert!(token.starts_with(ADMIN_TOKEN_PREFIX));
        assert_eq!(cfg.admin_token_hash, tokens::hash_token(&token));
        let (hash, secret) = (cfg.admin_token_hash.clone(), cfg.webrtc.static_auth_secret.clone());
        assert!(generate_secrets(&mut cfg).is_none());
        assert_eq!(cfg.admin_token_hash, hash);
        assert_eq!(cfg.webrtc.static_auth_secret, secret);
    }

    #[test]
    fn record_hosts_dedupe() {
        let mut cfg = fresh_config().unwrap();
        cfg.preview_zone = "tunnel.example.com".into();
        cfg.api_host = "tunnel.example.com".into();
        cfg.tunnel_host = "tunnel.example.com".into();
        cfg.turn_host = "turn.tunnel.example.com".into();
        assert_eq!(record_hosts(&cfg), vec!["*.tunnel.example.com", "tunnel.example.com"]);
        cfg.webrtc.enabled = true;
        // turn.<zone> is covered by the *.<zone> record (and certificate).
        assert_eq!(record_hosts(&cfg).len(), 2);
        assert!(!cfg.cert_names().contains(&cfg.turn_host));
        cfg.turn_host = "turn.example.com".into();
        assert_eq!(record_hosts(&cfg).len(), 3);
        assert!(cfg.cert_names().contains(&cfg.turn_host));
    }

    #[test]
    fn record_hosts_include_separate_preview_sign_in_host() {
        let mut cfg = fresh_config().unwrap();
        cfg.preview_zone = "previews.example.com".into();
        cfg.api_host = "api.example.com".into();
        cfg.tunnel_host = "tunnel.example.com".into();
        cfg.dns.zone = "example.com".into();
        assert_eq!(
            record_hosts(&cfg),
            vec!["*.previews.example.com", "api.example.com", "previews.example.com", "tunnel.example.com"]
        );
        let names = dns_verification_names(&cfg, "1-probe.previews.example.com".into());
        assert!(names.contains(&cfg.preview_zone));
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn record_hosts_preserve_preview_zone_apex_but_verify_it() {
        let mut cfg = fresh_config().unwrap();
        cfg.preview_zone = "example.com".into();
        cfg.dns.zone = "example.com".into();
        cfg.api_host = "api.example.com".into();
        cfg.tunnel_host = "tunnel.example.com".into();
        assert_eq!(record_hosts(&cfg), vec!["*.example.com", "api.example.com", "tunnel.example.com"]);
        assert!(dns_verification_names(&cfg, "1-probe.example.com".into()).contains(&cfg.preview_zone));
        cfg.api_host = cfg.preview_zone.clone();
        cfg.tunnel_host = cfg.preview_zone.clone();
        assert_eq!(record_hosts(&cfg), vec!["*.example.com", "example.com"]);
        assert_eq!(dns_verification_names(&cfg, "1-probe.example.com".into()).len(), 2);
    }

    #[test]
    fn record_hosts_include_zone_apex_for_api_or_tunnel_host() {
        let mut cfg = fresh_config().unwrap();
        cfg.preview_zone = "example.com".into();
        cfg.dns.zone = "example.com".into();
        cfg.api_host = "example.com".into();
        cfg.tunnel_host = "tunnel.example.com".into();
        assert_eq!(record_hosts(&cfg), vec!["*.example.com", "example.com", "tunnel.example.com"]);
        cfg.api_host = "api.example.com".into();
        cfg.tunnel_host = "example.com".into();
        assert_eq!(record_hosts(&cfg), vec!["*.example.com", "api.example.com", "example.com"]);
    }

    #[tokio::test]
    async fn ask_config_preserves_custom_hosts_until_server_host_changes() {
        let mut cfg = fresh_config().unwrap();
        cfg.tunnel_host = "tunnel.example.com".into();
        cfg.api_host = cfg.tunnel_host.clone();
        cfg.preview_zone = "previews.example.com".into();
        cfg.turn_host = "relay.example.com".into();
        cfg.acme.email = "test@example.com".into();
        // This provider needs no network lookup when choosing a zone.
        cfg.dns.provider = DnsProviderKind::Hetzner;
        cfg.dns.zone = "example.com".into();
        cfg.dns.api_token = Some("test-token".into());
        let ask = Ask { yes: true };
        for host in [None, Some("Tunnel.Example.com.".into())] {
            let args = SetupArgs { yes: true, host, ..Default::default() };
            let kept = ask_config(&ask, Some(&cfg), &args, Mode::System).await.unwrap();
            assert_eq!(kept.preview_zone, cfg.preview_zone);
            assert_eq!(kept.turn_host, cfg.turn_host);
        }
        let args = SetupArgs { yes: true, host: Some("new.example.com".into()), ..Default::default() };
        let changed = ask_config(&ask, Some(&cfg), &args, Mode::System).await.unwrap();
        assert_eq!(changed.preview_zone, "new.example.com");
        assert_eq!(changed.turn_host, "turn.new.example.com");
        let args = SetupArgs {
            yes: true,
            preview_zone: Some("other.example.com".into()),
            turn_host: Some("turn.other.example.com".into()),
            ..Default::default()
        };
        let overridden = ask_config(&ask, Some(&cfg), &args, Mode::System).await.unwrap();
        assert_eq!(overridden.preview_zone, "other.example.com");
        assert_eq!(overridden.turn_host, "turn.other.example.com");
    }

    #[test]
    fn public_ipv4_fallback_with_yes_reuses_existing_or_fails() {
        let mut cfg = fresh_config().unwrap();
        for existing in [None, Some(&cfg)] {
            assert_eq!(
                public_ipv4_fallback(existing, true).unwrap_err().to_string(),
                "could not detect the public IPv4 address; re-run setup interactively"
            );
        }
        let ip = "203.0.113.7".parse::<Ipv4Addr>().unwrap();
        cfg.public_ipv4 = Some(ip);
        assert_eq!(public_ipv4_fallback(Some(&cfg), true).unwrap(), ip);
    }

    #[test]
    fn parent_domain_guess() {
        assert_eq!(parent_domain("tunnel.example.com"), "example.com");
        assert_eq!(parent_domain("a.b.example.com"), "example.com");
        assert_eq!(parent_domain("example.com"), "example.com");
    }

    #[test]
    fn cloudflare_proxy_ranges() {
        assert!(is_cloudflare_proxy("104.21.93.176".parse().unwrap()));
        assert!(is_cloudflare_proxy("172.67.213.73".parse().unwrap()));
        assert!(is_cloudflare_proxy("2606:4700:3030::ac43:d549".parse().unwrap()));
        assert!(!is_cloudflare_proxy("203.0.113.10".parse().unwrap()));
    }

    fn hosts_config() -> Config {
        let mut cfg = fresh_config().unwrap();
        cfg.tunnel_host = "tunnel.example.com".into();
        cfg.api_host = cfg.tunnel_host.clone();
        cfg.preview_zone = "tunnel.example.com".into();
        cfg.turn_host = "turn.tunnel.example.com".into();
        cfg.acme.email = "test@example.com".into();
        cfg.dns.provider = DnsProviderKind::Hetzner;
        cfg.dns.zone = "example.com".into();
        cfg.dns.api_token = Some("test-token".into());
        cfg
    }

    #[test]
    fn default_ui_host_is_never_a_preview_name() {
        assert_eq!(default_ui_host("tunnel.example.com", "tunnel.example.com"), "tunnel-ui.example.com");
        assert_eq!(default_ui_host("tunnel.example.com", "previews.example-previews.com"), "tunnel.example.com");
        assert_eq!(default_ui_host("example.com", "example.com"), "tunnel-ui.example.com");
        assert_eq!(parse_ui_host("None").unwrap(), None);
        assert_eq!(parse_ui_host("UI.Example.com").unwrap().as_deref(), Some("ui.example.com"));
    }

    #[test]
    fn hosts_refuse_the_ui_under_previews_and_same_site_previews_for_several_people() {
        let mut cfg = hosts_config();
        cfg.ui_host = Some("ui.tunnel.example.com".into());
        assert!(check_hosts(&cfg, false).unwrap_err().to_string().contains("must not be the preview zone"));
        cfg.ui_host = Some("tunnel-ui.example.com".into());
        check_hosts(&cfg, false).unwrap();
        assert!(check_hosts(&cfg, true).unwrap_err().to_string().contains("separate registrable domain"));
        cfg.preview_zone = "previews.example-previews.com".into();
        check_hosts(&cfg, true).unwrap();
        cfg.ui_host = None;
        assert!(check_hosts(&cfg, true).unwrap_err().to_string().contains("needs the web UI"));
    }

    #[tokio::test]
    async fn ask_config_sets_up_the_ui_and_a_separate_preview_zone() {
        let token_file =
            std::env::temp_dir().join(format!("tunnel-preview-token-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::write(&token_file, "preview-test-token\n").unwrap();
        let ask = Ask { yes: true };
        // Fresh single-user layout: the UI gets a sibling name, previews stay on the host.
        let args = SetupArgs {
            yes: true,
            host: Some("tunnel.example.com".into()),
            email: Some("test@example.com".into()),
            dns_provider: Some("hetzner".into()),
            dns_zone: Some("example.com".into()),
            dns_token_file: Some(token_file.clone()),
            webrtc: Some(false),
            ..Default::default()
        };
        let cfg = ask_config(&ask, None, &args, Mode::System).await.unwrap();
        assert_eq!(cfg.ui_host.as_deref(), Some("tunnel-ui.example.com"));
        assert!(cfg.ui_same_site_as_previews());
        assert!(record_hosts(&cfg).contains(&"tunnel-ui.example.com".to_string()));
        // Several people: previews on another domain at another provider.
        let args = SetupArgs {
            multi_user: Some(true),
            preview_zone: Some("previews.example-previews.com".into()),
            preview_dns_provider: Some("digitalocean".into()),
            preview_dns_zone: Some("example-previews.com".into()),
            preview_dns_token_file: Some(token_file.clone()),
            ..args
        };
        let cfg = ask_config(&ask, None, &args, Mode::System).await.unwrap();
        assert_eq!(cfg.ui_host.as_deref(), Some("tunnel.example.com"));
        assert_eq!(cfg.extra_dns.len(), 1);
        assert_eq!(cfg.extra_dns[0].zone, "example-previews.com");
        assert_eq!(
            cfg.dns_for("3000-abc.previews.example-previews.com").unwrap().provider,
            DnsProviderKind::Digitalocean
        );
        assert_eq!(cfg.dns_for("tunnel.example.com").unwrap().zone, "example.com");
        check_names(&cfg).unwrap();
        // Several people without a separate preview domain: refused.
        let args = SetupArgs { preview_zone: Some("previews.example.com".into()), ..args };
        let err = ask_config(&ask, None, &args, Mode::System).await.unwrap_err().to_string();
        assert!(err.contains("separate registrable domain"), "{err}");
        // An existing server without the UI keeps it off on a plain re-run.
        let existing = hosts_config();
        let args = SetupArgs { yes: true, ..Default::default() };
        assert_eq!(ask_config(&ask, Some(&existing), &args, Mode::System).await.unwrap().ui_host, None);
        std::fs::remove_file(token_file).unwrap();
    }

    #[test]
    fn the_ui_secret_is_generated_with_the_ui() {
        let mut cfg = hosts_config();
        cfg.admin_token_hash = "set".into();
        generate_secrets(&mut cfg);
        assert!(cfg.ui_secret.is_none());
        cfg.ui_host = Some("tunnel-ui.example.com".into());
        generate_secrets(&mut cfg);
        let secret = cfg.ui_secret.clone().unwrap();
        assert!(secret.len() >= 32);
        cfg.validate().unwrap();
        generate_secrets(&mut cfg);
        assert_eq!(cfg.ui_secret.as_deref(), Some(secret.as_str()), "kept on re-runs");
    }

    #[tokio::test]
    async fn an_own_certificate_must_cover_every_name_and_is_never_issued() {
        let dir =
            std::env::temp_dir().join(format!("tunnel-own-cert-{}-{}", std::process::id(), rand::random::<u64>()));
        let mut cfg = hosts_config();
        cfg.data_dir = dir.clone();
        cfg.acme.own_certificate = true;
        cfg.ui_host = Some("tunnel-ui.example.com".into());
        std::fs::create_dir_all(cfg.cert_dir()).unwrap();
        let write = |names: &[&str]| {
            let key = rcgen::KeyPair::generate().unwrap();
            let params =
                rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
            let cert = params.self_signed(&key).unwrap();
            std::fs::write(cfg.cert_dir().join("fullchain.pem"), cert.pem()).unwrap();
            std::fs::write(cfg.cert_dir().join("privkey.pem"), key.serialize_pem()).unwrap();
        };
        write(&["*.tunnel.example.com", "tunnel.example.com"]);
        let err = ensure_certificate(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("tunnel-ui.example.com"), "{err}");
        write(&["*.tunnel.example.com", "tunnel.example.com", "tunnel-ui.example.com"]);
        ensure_certificate(&cfg).await.unwrap();
        assert!(crate::acme::issue(&cfg).await.unwrap_err().to_string().contains("own certificate"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn manual_dns_with_an_own_certificate_needs_no_provider_settings() {
        let ask = Ask { yes: true };
        let args = SetupArgs {
            yes: true,
            host: Some("tunnel.example.org".into()),
            email: Some("test@example.org".into()),
            skip_dns: true,
            own_certificate: Some(true),
            webrtc: Some(false),
            ..Default::default()
        };
        let cfg = ask_config(&ask, None, &args, Mode::System).await.unwrap();
        assert!(cfg.acme.own_certificate);
        assert_eq!(cfg.dns.zone, "example.org");
        assert_eq!(cfg.dns.api_token, None);
        assert!(cfg.extra_dns.is_empty());
    }

    #[tokio::test]
    async fn preview_dns_flags_replace_an_existing_zone_on_reruns() {
        let token_file = std::env::temp_dir().join(format!(
            "tunnel-preview-token2-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&token_file, "renewed-token\n").unwrap();
        let mut existing = hosts_config();
        existing.preview_zone = "previews.example-previews.com".into();
        existing.ui_host = Some("tunnel.example.com".into());
        existing.extra_dns.push(DnsConfig {
            provider: DnsProviderKind::Digitalocean,
            zone: "example-previews.com".into(),
            api_token: Some("expired-token".into()),
            aws_access_key_id: None,
            aws_secret_access_key: None,
            route53_hosted_zone_id: None,
        });
        let ask = Ask { yes: true };
        // A plain re-run keeps the zone as it is.
        let kept = ask_config(&ask, Some(&existing), &SetupArgs { yes: true, ..Default::default() }, Mode::System)
            .await
            .unwrap();
        assert_eq!(kept.extra_dns[0].api_token.as_deref(), Some("expired-token"));
        // An explicit token file replaces just the token.
        let args = SetupArgs { yes: true, preview_dns_token_file: Some(token_file.clone()), ..Default::default() };
        let renewed = ask_config(&ask, Some(&existing), &args, Mode::System).await.unwrap();
        assert_eq!(renewed.extra_dns.len(), 1);
        assert_eq!(renewed.extra_dns[0].api_token.as_deref(), Some("renewed-token"));
        assert_eq!(renewed.extra_dns[0].provider, DnsProviderKind::Digitalocean);
        assert_eq!(renewed.extra_dns[0].zone, "example-previews.com");
        std::fs::remove_file(token_file).unwrap();
    }

    #[tokio::test]
    async fn an_own_certificate_due_for_replacement_still_lets_setup_continue() {
        let dir =
            std::env::temp_dir().join(format!("tunnel-own-cert2-{}-{}", std::process::id(), rand::random::<u64>()));
        let mut cfg = hosts_config();
        cfg.data_dir = dir.clone();
        cfg.acme.own_certificate = true;
        std::fs::create_dir_all(cfg.cert_dir()).unwrap();
        let write = |days_left: i64, days_total: i64| {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![
                "*.tunnel.example.com".to_string(),
                "tunnel.example.com".to_string(),
            ])
            .unwrap();
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::days(days_total - days_left);
            params.not_after = now + time::Duration::days(days_left);
            let cert = params.self_signed(&key).unwrap();
            std::fs::write(cfg.cert_dir().join("fullchain.pem"), cert.pem()).unwrap();
            std::fs::write(cfg.cert_dir().join("privkey.pem"), key.serialize_pem()).unwrap();
        };
        write(20, 90);
        assert_eq!(tls::cert_status(&cfg), tls::CertStatus::NeedsRenewal);
        ensure_certificate(&cfg).await.unwrap();
        write(-1, 90);
        assert_eq!(tls::cert_status(&cfg), tls::CertStatus::Expired);
        assert!(ensure_certificate(&cfg).await.is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
