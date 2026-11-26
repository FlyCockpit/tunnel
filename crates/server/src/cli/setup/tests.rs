use super::*;

#[test]
fn the_admin_lock_alone_does_not_count_as_a_foreign_entry() {
    let dir = std::env::temp_dir().join(format!("tunnel-setup-lock-{}-{}", std::process::id(), rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    assert!(!foreign_entries(&dir, &config).unwrap());
    let lock = crate::cli::admin_lock(&config).unwrap().expect("directory exists");
    assert!(!foreign_entries(&dir, &config).unwrap(), "only our own lock");
    std::fs::write(dir.join("other"), b"x").unwrap();
    assert!(foreign_entries(&dir, &config).unwrap());
    drop(lock);
    std::fs::remove_dir_all(&dir).unwrap();
}

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
    let dir = std::env::temp_dir().join(format!("tunnel-preflight-{}-{}", std::process::id(), rand::random::<u64>()));
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
    let dir = std::env::temp_dir().join(format!("tunnel-preflight-{}-{}", std::process::id(), rand::random::<u64>()));
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
    let dir = std::env::temp_dir().join(format!("tunnel-preflight-{}-{}", std::process::id(), rand::random::<u64>()));
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
        rootless_setup_script("test", config, Path::new("/home/test/.local/share/tunnel"), false, false, true).unwrap();
    assert!(script.contains("mkdir -p -- '/home/test/custom config' '/home/test/.local/share/tunnel'"));
    let write_config = shell_quote(&format!("umask 077; cat > {}", shell_quote(&config.to_string_lossy())));
    assert!(script.contains(&format!("runuser -u 'test' -- sh -c {write_config} < '/etc/tunnel-server/config.toml'")));
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
            script.contains(&format!("runuser -u 'test' -- sh -c {write_config} < '/etc/tunnel-server/config.toml'"))
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
    assert_eq!(cfg.dns_for("3000-abc.previews.example-previews.com").unwrap().provider, DnsProviderKind::Digitalocean);
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
fn the_ui_secret_is_generated_with_or_without_the_ui() {
    let mut cfg = hosts_config();
    cfg.admin_token_hash = "set".into();
    generate_secrets(&mut cfg);
    assert!(cfg.ui_secret.as_ref().unwrap().len() >= 32);
    let original = cfg.ui_secret.clone();
    cfg.ui_host = Some("tunnel-ui.example.com".into());
    generate_secrets(&mut cfg);
    let secret = cfg.ui_secret.clone().unwrap();
    assert_eq!(cfg.ui_secret, original);
    assert!(secret.len() >= 32);
    cfg.validate().unwrap();
    generate_secrets(&mut cfg);
    assert_eq!(cfg.ui_secret.as_deref(), Some(secret.as_str()), "kept on re-runs");
    cfg.ui_secret = Some("é".repeat(16));
    generate_secrets(&mut cfg);
    assert_eq!(cfg.ui_secret.as_deref(), Some("é".repeat(16).as_str()));
    cfg.ui_secret = Some("é".repeat(15));
    generate_secrets(&mut cfg);
    assert!(cfg.ui_secret.as_ref().unwrap().len() >= 32);
}

#[tokio::test]
async fn an_own_certificate_must_cover_every_name_and_is_never_issued() {
    let dir = std::env::temp_dir().join(format!("tunnel-own-cert-{}-{}", std::process::id(), rand::random::<u64>()));
    let mut cfg = hosts_config();
    cfg.data_dir = dir.clone();
    cfg.acme.own_certificate = true;
    cfg.ui_host = Some("tunnel-ui.example.com".into());
    std::fs::create_dir_all(cfg.cert_dir()).unwrap();
    let write = |names: &[&str]| {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(cfg.cert_dir().join("fullchain.pem"), cert.pem()).unwrap();
        std::fs::write(cfg.cert_dir().join("privkey.pem"), key.serialize_pem()).unwrap();
    };
    write(&["*.tunnel.example.com", "tunnel.example.com"]);
    let err = ensure_certificate(&cfg).await.unwrap_err().to_string();
    assert!(err.contains("tunnel-ui.example.com"), "{err}");
    write(&["*.tunnel.example.com", "tunnel.example.com", "tunnel-ui.example.com"]);
    ensure_certificate(&cfg).await.unwrap();
    assert!(crate::jobs::acme::issue(&cfg).await.unwrap_err().to_string().contains("own certificate"));
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
    let token_file =
        std::env::temp_dir().join(format!("tunnel-preview-token2-{}-{}", std::process::id(), rand::random::<u64>()));
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
    let kept =
        ask_config(&ask, Some(&existing), &SetupArgs { yes: true, ..Default::default() }, Mode::System).await.unwrap();
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
    let dir = std::env::temp_dir().join(format!("tunnel-own-cert2-{}-{}", std::process::id(), rand::random::<u64>()));
    let mut cfg = hosts_config();
    cfg.data_dir = dir.clone();
    cfg.acme.own_certificate = true;
    std::fs::create_dir_all(cfg.cert_dir()).unwrap();
    let write = |days_left: i64, days_total: i64| {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["*.tunnel.example.com".to_string(), "tunnel.example.com".to_string()])
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
