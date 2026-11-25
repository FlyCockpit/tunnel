//! Email (SMTP): the optional step of `setup`, and `mail setup`, `mail off`
//! and `mail test` for a running server. Nothing here is needed for the
//! server to work: without `[smtp]` every link is handed over by hand.

use std::path::Path;

use anyhow::bail;

use super::{Ask, prompt};
use crate::config::smtp::{self, DEFAULT_PORT, SmtpConfig};
use crate::config::{Config, SERVICE_NAME};
use crate::mail::{Mail, Mailer, SendError, Step};

/// The SMTP password comes from this variable or a prompt, never from argv.
pub const PASS_ENV: &str = "SMTP_PASS";

#[derive(clap::Args, Debug, Default, Clone)]
pub struct SmtpArgs {
    /// Mail server for invites, password resets and security notices, e.g.
    /// smtp.example.com, or `none` for no email. Its password is read from
    /// $SMTP_PASS or asked for (never a flag).
    #[arg(long)]
    pub smtp_host: Option<String>,
    /// Mail server port: 587 (STARTTLS, the default) or 465 (TLS).
    #[arg(long)]
    pub smtp_port: Option<u16>,
    /// User name at the mail server, or `none` to send without signing in.
    #[arg(long)]
    pub smtp_user: Option<String>,
    /// Sender: tunnel@example.com or "Tunnel <tunnel@example.com>".
    #[arg(long)]
    pub smtp_from: Option<String>,
    /// Send a test mail to this address before anything is saved; stop if it fails.
    #[arg(long)]
    pub smtp_test_to: Option<String>,
}

impl SmtpArgs {
    fn any(&self) -> bool {
        self.smtp_host.is_some()
            || self.smtp_port.is_some()
            || self.smtp_user.is_some()
            || self.smtp_from.is_some()
            || self.smtp_test_to.is_some()
    }
}

fn parse_host_or_none(input: &str) -> Result<Option<String>, String> {
    if input.trim().eq_ignore_ascii_case("none") { Ok(None) } else { smtp::parse_host(input).map(Some) }
}

fn parse_port(input: &str) -> Result<u16, String> {
    input.trim().parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| "a port is 1..=65535 (587 or 465)".into())
}

fn parse_user(input: &str) -> Result<Option<String>, String> {
    let user = input.trim();
    if user.is_empty() || user.eq_ignore_ascii_case("none") {
        Ok(None)
    } else if user.chars().any(char::is_control) || user.len() > 256 {
        Err("not a user name".into())
    } else {
        Ok(Some(user.to_string()))
    }
}

fn parse_from(input: &str) -> Result<String, String> {
    let from = input.trim().to_string();
    let probe = SmtpConfig { host: "localhost".into(), port: DEFAULT_PORT, user: None, pass: None, from };
    probe.sender().map(|_| probe.from)
}

/// The password: $SMTP_PASS, else the prompt (Enter keeps `current`).
fn password(ask: &Ask, current: Option<&str>) -> anyhow::Result<String> {
    if let Ok(p) = std::env::var(PASS_ENV)
        && !p.is_empty()
    {
        println!("Using the mail server password from ${PASS_ENV}.");
        return Ok(p);
    }
    if ask.yes {
        return current
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("--smtp-user needs the password in ${PASS_ENV} with --yes"));
    }
    prompt::ask_password("Password at the mail server (not shown)", current)
}

/// Ask for the `[smtp]` settings (each from its flag, else a prompt, else the
/// current value with `--yes`), send a test mail and return what to save;
/// `None` is no email. In `setup` (`explicit` false) the step is skipped
/// unless asked for; `mail setup` asks straight away.
pub async fn ask_smtp(
    yes: bool,
    current: Option<&SmtpConfig>,
    args: &SmtpArgs,
    ui_host: Option<&str>,
    suggested_to: &str,
    explicit: bool,
) -> anyhow::Result<Option<SmtpConfig>> {
    // Removing the settings needs nothing else (not even a web UI).
    if args.smtp_host.as_deref().is_some_and(|h| h.trim().eq_ignore_ascii_case("none")) {
        return Ok(None);
    }
    let Some(ui_host) = ui_host else {
        if args.any() || explicit {
            bail!("email needs the web UI (its links point there); set it up first with `setup --ui-host <name>`");
        }
        return Ok(current.cloned());
    };
    let ask = Ask { yes };
    if !explicit && !args.any() {
        if yes {
            return Ok(current.cloned());
        }
        let question = match current {
            Some(c) => {
                println!("\nEmail: on via {} from {}.", c.describe(), c.from);
                "Change the email (SMTP) settings?"
            }
            None => {
                println!(
                    "\nEmail (optional): with an SMTP server the web UI can send invites, password resets and \
                     security notices.\nWithout it everything works and links are handed over by hand."
                );
                "Set up email now?"
            }
        };
        if !prompt::ask_bool(question, false)? {
            return Ok(current.cloned());
        }
    }
    let mut args = args.clone();
    // After a failed test, the answers just given are the defaults of the next round.
    let mut tried: Option<SmtpConfig> = None;
    loop {
        let base = tried.clone().or_else(|| current.cloned());
        let current = base.as_ref();
        let host_default = current.map(|c| c.host.clone()).unwrap_or_default();
        let Some(host) = ask.text(
            args.smtp_host.as_deref(),
            "smtp-host",
            "SMTP server, e.g. smtp.example.com (none: no email)",
            &host_default,
            parse_host_or_none,
        )?
        else {
            return Ok(None);
        };
        let port_default = current.map_or(DEFAULT_PORT, |c| c.port).to_string();
        let port_flag = args.smtp_port.map(|p| p.to_string());
        let port =
            ask.text(port_flag.as_deref(), "smtp-port", "Port (587: STARTTLS, 465: TLS)", &port_default, parse_port)?;
        let user_default = current.and_then(|c| c.user.clone()).unwrap_or_else(|| "none".into());
        let user = ask.text(
            args.smtp_user.as_deref(),
            "smtp-user",
            "User name at the mail server (none: send without signing in)",
            &user_default,
            parse_user,
        )?;
        let pass = match &user {
            Some(u) => {
                // The stored password only goes with the same server and user.
                let keep =
                    current.filter(|c| c.host == host && c.user.as_deref() == Some(u)).and_then(|c| c.pass.as_deref());
                Some(password(&ask, keep)?)
            }
            None => None,
        };
        let from_default = current.map(|c| c.from.clone()).unwrap_or_default();
        let from = ask.text(
            args.smtp_from.as_deref(),
            "smtp-from",
            "Sender, e.g. Tunnel <tunnel@example.com> (an address the mail server may send from)",
            &from_default,
            parse_from,
        )?;
        let smtp = SmtpConfig { host, port, user, pass, from };
        if let Err(e) = smtp.validate() {
            bail!("email settings: {e}");
        }
        let to = match &args.smtp_test_to {
            Some(to) => Some(smtp::parse_address(to).map_err(|e| anyhow::anyhow!("--smtp-test-to: {e}"))?),
            None if yes => None,
            None => ask.text(
                None,
                "smtp-test-to",
                "Send a test mail to (none: skip the test)",
                if suggested_to.is_empty() { "none" } else { suggested_to },
                |s| if s.trim().eq_ignore_ascii_case("none") { Ok(None) } else { smtp::parse_address(s).map(Some) },
            )?,
        };
        let Some(to) = to else {
            return Ok(Some(smtp));
        };
        match send_test(&smtp, ui_host, &to).await {
            Ok(()) => {
                println!("Test mail sent to {to}; check that it arrived (and the spam folder).");
                return Ok(Some(smtp));
            }
            // `--smtp-test-to` (or `--yes`) promises nothing is saved after a failed test.
            Err(e) if yes || args.smtp_test_to.is_some() => {
                bail!("the test mail failed: {e}; nothing was changed");
            }
            Err(_) => match prompt::ask_choice(
                "The test mail failed",
                &["change the settings", "save them anyway", "no email"],
                0,
            )? {
                0 => {
                    args = SmtpArgs::default();
                    tried = Some(smtp);
                }
                1 => return Ok(Some(smtp)),
                _ => return Ok(None),
            },
        }
    }
}

/// Send the test mail now, printing every step.
pub async fn send_test(smtp: &SmtpConfig, ui_host: &str, to: &str) -> Result<(), SendError> {
    println!("Sending a test mail to {to} via {} from {}:", smtp.describe(), smtp.from);
    let mailer = Mailer::new(smtp.clone(), ui_host.to_string());
    let mail: Mail = mailer.texts().test();
    let result = mailer.send_now(to, mail, &mut |s: Step| println!("  ok      {}", s.label())).await;
    if let Err(e) = &result {
        println!("  FAILED  {e}");
        if let Some(reply) = &e.reply {
            // Masked before shortening, so no piece of the password survives a cut.
            println!("          the server said: {}", crate::mail::transport::one_line(&masked(reply, smtp)));
        }
    }
    result
}

/// `reply` with the password, and the forms AUTH sends it in, masked (a
/// relay may echo what it was sent).
fn masked(reply: &str, smtp: &SmtpConfig) -> String {
    use base64::Engine;
    let (Some(user), Some(pass)) = (&smtp.user, &smtp.pass) else {
        return reply.to_string();
    };
    let b64 = |s: String| base64::engine::general_purpose::STANDARD.encode(s);
    let secrets = [pass.clone(), b64(format!("\0{user}\0{pass}")), b64(pass.clone())];
    // Every occurrence of every form, found in the original text (they may
    // overlap: the password can sit inside an encoded form), then merged.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        let mut from = 0;
        while let Some(i) = reply[from..].find(secret.as_str()) {
            spans.push((from + i, from + i + secret.len()));
            from += i + reply[from + i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    spans.sort_unstable();
    let mut out = String::new();
    let mut at = 0;
    for (start, end) in spans {
        if end <= at {
            continue;
        }
        if start > at {
            out.push_str(&reply[at..start]);
            out.push_str("***");
        } else if out.is_empty() && at == 0 {
            out.push_str("***");
        }
        at = end;
    }
    out.push_str(&reply[at..]);
    out
}

// ----------------------------------------------------------------- commands

fn save(config_path: &Path, cfg: &Config, what: &str) -> anyhow::Result<()> {
    use crate::config::mode::{self, Mode};
    let mode = crate::cli::install_mode(config_path);
    if mode == Mode::System {
        mode::check_system_config_dir(config_path)?;
    }
    cfg.validate()?;
    let changed = cfg.save(config_path)?;
    // Always: `save` makes the file 0600 even when nothing changed, and the
    // service account must still read a root install's config.
    if mode == Mode::System {
        mode::secure_system_config(config_path)?;
    }
    if !changed {
        // No restart (it would drop every tunnel for nothing), and no claim
        // that the running server uses these settings: an earlier restart
        // may have failed.
        println!("{}", unchanged(mode));
        return Ok(());
    }
    let restarted = mode.systemctl_ok(&["try-restart", SERVICE_NAME]);
    let installed = restarted || mode.unit_loaded(SERVICE_NAME);
    println!("{}", applied(what, mode, restarted, installed)?);
    Ok(())
}

fn restart_command(mode: crate::config::mode::Mode) -> String {
    format!("systemctl{} restart {SERVICE_NAME}", if mode.is_user() { " --user" } else { "" })
}

/// Nothing to save: say so, and how to apply the saved settings if an
/// earlier restart failed.
fn unchanged(mode: crate::config::mode::Mode) -> String {
    format!(
        "The config file already has these settings. If an earlier restart failed, run `{}` to apply them.",
        restart_command(mode)
    )
}

/// The outcome of saving and restarting. A failed restart of an installed
/// service is an error (the running server still uses the old settings),
/// naming the command that applies the saved change.
fn applied(what: &str, mode: crate::config::mode::Mode, restarted: bool, installed: bool) -> anyhow::Result<String> {
    if restarted {
        return Ok(format!("{what}; restarted {SERVICE_NAME} (if it was running)."));
    }
    if !installed {
        return Ok(format!(
            "{what}. No {SERVICE_NAME} service is installed here; restart the server yourself if one runs."
        ));
    }
    bail!(
        "{what}, but restarting {SERVICE_NAME} failed, so the running server still uses the old settings; \
         run `{}` to apply them",
        restart_command(mode)
    )
}

/// `mail setup`: add or change the `[smtp]` settings of an installed server.
pub async fn setup_command(config_path: &Path, args: &SmtpArgs, yes: bool) -> anyhow::Result<()> {
    crate::cli::ensure_can_write(config_path, "mail setup")?;
    let mut cfg = Config::load(config_path)?;
    let smtp = ask_smtp(yes, cfg.smtp.as_ref(), args, cfg.ui_host.as_deref(), &cfg.acme.email, true).await?;
    let what = if smtp.is_some() { "Email settings saved" } else { "Email turned off" };
    cfg.smtp = smtp;
    save(config_path, &cfg, what)?;
    println!("Mail: {}", cfg.mail_status());
    Ok(())
}

/// `mail off`: remove the `[smtp]` settings.
pub async fn off_command(config_path: &Path) -> anyhow::Result<()> {
    crate::cli::ensure_can_write(config_path, "mail off")?;
    let mut cfg = Config::load(config_path)?;
    if cfg.smtp.take().is_none() {
        println!("Email is already off in the config file.");
        println!("{}", unchanged(crate::cli::install_mode(config_path)));
        return Ok(());
    }
    save(config_path, &cfg, "Email turned off")
}

/// `mail test <address>`: send a test mail now with the saved settings.
pub async fn test_command(config_path: &Path, to: &str) -> anyhow::Result<()> {
    let cfg = Config::load(config_path)?;
    let Some(smtp) = &cfg.smtp else {
        bail!("email is off: set it up with `tunnel-server mail setup`");
    };
    let to = smtp::parse_address(to).map_err(anyhow::Error::msg)?;
    let hello = cfg.ui_host.as_deref().unwrap_or(&cfg.api_host);
    match send_test(smtp, hello, &to).await {
        Ok(()) => {
            println!(
                "Sent. If it does not arrive, check the spam folder and the sender's domain settings (SPF, DKIM)."
            );
            if !cfg.mail_enabled() {
                println!("Note: {}", cfg.mail_status());
            }
            Ok(())
        }
        Err(e) => bail!("the test mail was not sent: {} failed", e.step.label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_restart_is_an_error_that_says_how_to_apply_the_change() {
        use crate::config::mode::Mode;
        assert!(
            applied("Email turned off", Mode::System, true, true).unwrap().starts_with("Email turned off; restarted")
        );
        let e = applied("Email turned off", Mode::System, false, true).unwrap_err().to_string();
        assert!(e.contains("still uses the old settings") && e.contains("`systemctl restart tunnel-server`"), "{e}");
        let e = applied("Email settings saved", Mode::User, false, true).unwrap_err().to_string();
        assert!(e.contains("`systemctl --user restart tunnel-server`"), "{e}");
        // Unchanged: no claim that it is applied, and the way to apply it.
        let same = unchanged(Mode::System);
        assert!(same.contains("If an earlier restart failed, run `systemctl restart tunnel-server`"), "{same}");
        // No service installed (a server run by hand): saved, with a note.
        let note = applied("Email turned off", Mode::User, false, false).unwrap();
        assert!(note.contains("No tunnel-server service is installed here"), "{note}");
    }

    #[test]
    fn a_reply_echoing_the_password_is_masked() {
        use base64::Engine;
        let smtp = SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            user: Some("bob".into()),
            pass: Some("public-test-pass".into()),
            from: "t@example.com".into(),
        };
        let plain = base64::engine::general_purpose::STANDARD.encode("\0bob\0public-test-pass");
        let login = base64::engine::general_purpose::STANDARD.encode("public-test-pass");
        let reply = format!("535 bad: public-test-pass {plain} {login}");
        let shown = masked(&reply, &smtp);
        assert_eq!(shown, "535 bad: *** *** ***");
        // A password with repeated spaces, and one that a 300-character cut would split.
        let spaced = SmtpConfig { pass: Some("two  spaces  pass".into()), ..smtp.clone() };
        let shown = crate::mail::transport::one_line(&masked("535 two  spaces  pass rejected", &spaced));
        assert_eq!(shown, "535 *** rejected");
        // The password inside its own encoded form (user `xxsecret`, password `c2VjcmV0`).
        let tricky = SmtpConfig { user: Some("xxsecret".into()), pass: Some("c2VjcmV0".into()), ..smtp.clone() };
        let plain = base64::engine::general_purpose::STANDARD.encode("\0xxsecret\0c2VjcmV0");
        assert_eq!(plain, "AHh4c2VjcmV0AGMyVmpjbVYw");
        assert_eq!(masked(&format!("535 {plain} c2VjcmV0"), &tricky), "535 *** ***");
        assert_eq!(masked("c2VjcmV0 at the start", &tricky), "*** at the start");
        let long = format!("{} public-test-pass", "x".repeat(290));
        let shown = crate::mail::transport::one_line(&masked(&long, &smtp));
        assert!(!shown.contains("public") && shown.ends_with("***"), "{shown}");
    }

    #[tokio::test]
    async fn smtp_host_none_removes_the_settings_even_without_a_web_ui() {
        let current = SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            user: None,
            pass: None,
            from: "t@example.com".into(),
        };
        let none = SmtpArgs { smtp_host: Some("none".into()), ..Default::default() };
        for ui in [None, Some("ui.example.com")] {
            assert_eq!(ask_smtp(true, Some(&current), &none, ui, "", false).await.unwrap(), None);
        }
        // Without a web UI and without flags, setup keeps what is there.
        let kept = ask_smtp(true, Some(&current), &SmtpArgs::default(), None, "", false).await.unwrap();
        assert_eq!(kept, Some(current.clone()));
        let on = SmtpArgs { smtp_host: Some("smtp.example.com".into()), ..Default::default() };
        assert!(ask_smtp(true, None, &on, None, "", false).await.is_err(), "email needs the web UI");
        let test_only = SmtpArgs { smtp_test_to: Some("you@example.com".into()), ..Default::default() };
        assert!(ask_smtp(true, Some(&current), &test_only, None, "", false).await.is_err(), "no flag is ignored");
    }

    #[test]
    fn answers_parse_strictly() {
        assert_eq!(parse_host_or_none("None").unwrap(), None);
        assert_eq!(parse_host_or_none("Smtp.Example.com").unwrap().as_deref(), Some("smtp.example.com"));
        assert!(parse_port("0").is_err() && parse_port("x").is_err());
        assert_eq!(parse_port(" 465 ").unwrap(), 465);
        assert_eq!(parse_user("none").unwrap(), None);
        assert!(parse_user("a\nb").is_err());
        assert!(parse_from("Tunnel <t@example.com>").is_ok() && parse_from("nope").is_err());
        assert!(parse_from("Tunnel <用户@example.com>").is_err(), "ASCII senders only");
    }
}
