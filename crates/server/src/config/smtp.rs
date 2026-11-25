//! The optional `[smtp]` table: where the server sends its mail (invites,
//! password resets, address checks and security notices). Without it the
//! server sends no mail and every link is handed over by hand.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 587;
/// The port of implicit TLS ("SMTPS", RFC 8314).
pub const IMPLICIT_TLS_PORT: u16 = 465;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SmtpConfig {
    /// Mail server (relay) name or address.
    pub host: String,
    /// 587 (STARTTLS) unless set; 465 is implicit TLS.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Sign-in at the mail server; `user` and `pass` are set together or not at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
    /// Sender: `tunnel@example.com` or `Tunnel <tunnel@example.com>`.
    pub from: String,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("pass", &self.pass.as_ref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .finish()
    }
}

/// How the connection is protected, from the port and the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// TLS from the first byte (port 465).
    ImplicitTls,
    /// Plain greeting, then STARTTLS; refused if the server does not offer it.
    StartTls,
    /// No TLS: only for a relay on this machine (nothing crosses the network).
    Plain,
}

impl Security {
    pub fn label(self) -> &'static str {
        match self {
            Self::ImplicitTls => "TLS",
            Self::StartTls => "STARTTLS",
            Self::Plain => "plain, local relay",
        }
    }
}

impl SmtpConfig {
    pub fn security(&self) -> Security {
        if self.port == IMPLICIT_TLS_PORT {
            Security::ImplicitTls
        } else if is_loopback(&self.host) {
            Security::Plain
        } else {
            Security::StartTls
        }
    }

    /// The sender as a mailbox (display name optional; an ASCII address, see `parse_address`).
    pub fn sender(&self) -> Result<lettre::message::Mailbox, String> {
        let mailbox: lettre::message::Mailbox =
            self.from.trim().parse().map_err(|_| format!("from {:?} is not an email address", self.from))?;
        parse_address(mailbox.email.as_ref()).map_err(|e| format!("from: {e}"))?;
        Ok(mailbox)
    }

    pub fn validate(&self) -> Result<(), String> {
        parse_host(&self.host)?;
        if self.port == 0 {
            return Err("port must be 1..=65535".into());
        }
        self.sender()?;
        match (&self.user, &self.pass) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Ok(()),
            (None, None) => Ok(()),
            _ => Err("user and pass are set together (sign-in at the mail server) or not at all".into()),
        }
    }

    /// `host:port (security)` for status lines; never the credentials.
    pub fn describe(&self) -> String {
        format!("{}:{} ({})", self.host, self.port, self.security().label())
    }
}

/// A host name or IP address (no scheme, port or path).
pub fn parse_host(input: &str) -> Result<String, String> {
    let host = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return Ok(host);
    }
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if ok { Ok(host) } else { Err(format!("{input:?} is not a host name or IP address")) }
}

/// A relay on this machine: `localhost` or a loopback address.
pub fn is_loopback(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// An email address, lowercased (as stored and compared). ASCII only: the
/// server does not negotiate SMTPUTF8 (write an international domain in its
/// `xn--` form).
pub fn parse_address(input: &str) -> Result<String, String> {
    let s = input.trim();
    if !s.is_ascii() {
        return Err(format!("{s:?}: only ASCII addresses are supported (international domains in their xn-- form)"));
    }
    let ok = s.len() <= 254 && s.parse::<lettre::Address>().is_ok();
    if ok { Ok(s.to_ascii_lowercase()) } else { Err(format!("{s:?} is not an email address")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(host: &str, port: u16) -> SmtpConfig {
        SmtpConfig { host: host.into(), port, user: None, pass: None, from: "Tunnel <t@example.com>".into() }
    }

    #[test]
    fn security_follows_the_port_and_the_host() {
        assert_eq!(cfg("smtp.example.com", 587).security(), Security::StartTls);
        assert_eq!(cfg("smtp.example.com", 25).security(), Security::StartTls);
        assert_eq!(cfg("smtp.example.com", 465).security(), Security::ImplicitTls);
        assert_eq!(cfg("localhost", 465).security(), Security::ImplicitTls);
        for local in ["localhost", "127.0.0.1", "127.0.0.53", "::1", "LOCALHOST."] {
            assert_eq!(cfg(local, 1025).security(), Security::Plain, "{local}");
        }
        // Names that only look local still need TLS.
        for remote in ["localhost.example.com", "10.0.0.5", "mailpit", "0.0.0.0"] {
            assert_eq!(cfg(remote, 1025).security(), Security::StartTls, "{remote}");
        }
    }

    #[test]
    fn validation_names_the_problem_and_debug_hides_the_password() {
        assert!(cfg("smtp.example.com", 587).validate().is_ok());
        assert!(cfg("smtp example", 587).validate().unwrap_err().contains("host"));
        assert!(cfg("smtp.example.com", 0).validate().unwrap_err().contains("port"));
        let mut c = cfg("smtp.example.com", 587);
        c.from = "not an address".into();
        assert!(c.validate().unwrap_err().contains("from"));
        c.from = "t@example.com".into();
        c.user = Some("u".into());
        assert!(c.validate().unwrap_err().contains("together"));
        c.pass = Some("public-test-placeholder".into());
        assert!(c.validate().is_ok());
        let shown = format!("{c:?}");
        assert!(!shown.contains("public-test-placeholder") && shown.contains("redacted"), "{shown}");
        assert_eq!(c.describe(), "smtp.example.com:587 (STARTTLS)");
    }

    #[test]
    fn addresses_are_checked_and_lowercased() {
        assert_eq!(parse_address(" Bob@Example.COM ").unwrap(), "bob@example.com");
        for bad in [
            "",
            "bob",
            "bob@",
            "@example.com",
            "a b@example.com",
            "bob@example.com\r\nBcc: x@y.z",
            "用户@example.com",
            "bob@bücher.example",
        ] {
            assert!(parse_address(bad).is_err(), "{bad:?}");
        }
    }
}
