//! What the server's mails say. Plain text only. Links are built from the
//! configured `ui_host`, never from a request; no mail carries a TOTP
//! secret, a recovery code or a machine token.

use super::Mail;

/// Something that changed how an account signs in or what it can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    PasswordChanged,
    /// "Forgot password?" was used (two-factor sign-in, if on, stays on).
    PasswordReset,
    /// An admin's sign-in reset link was used: new password, two-factor sign-in off.
    SignInReset,
    TotpEnabled,
    TotpDisabled,
    MachineAdded(String),
    MachineApproved(String),
    RoleChanged {
        from: String,
        to: String,
    },
    /// Sent to the old address.
    AddressChanged {
        new: String,
    },
    AddressRemoved,
}

impl Notice {
    fn what(&self) -> String {
        match self {
            Self::PasswordChanged => "The password of your account was changed.".into(),
            Self::PasswordReset => {
                "The password of your account was reset with a link sent to this address. Two-factor sign-in, if \
                 it was on, is still on."
                    .into()
            }
            Self::SignInReset => {
                "Your account's sign-in was reset with a link from an admin: it has a new password and two-factor \
                 sign-in is off."
                    .into()
            }
            Self::TotpEnabled => "Two-factor sign-in was turned on for your account.".into(),
            Self::TotpDisabled => "Two-factor sign-in was turned off for your account.".into(),
            Self::MachineAdded(name) => format!("A login code for a new machine, {name}, was made for your account."),
            Self::MachineApproved(name) => format!("A new machine, {name}, was approved to use your account."),
            Self::RoleChanged { from, to } => format!("Your account's role changed from {from} to {to}."),
            Self::AddressChanged { new } => {
                format!("Your account's email address was changed from this address to {}.", mask(new))
            }
            Self::AddressRemoved => "This email address was removed from your account.".into(),
        }
    }

    fn subject(&self) -> &'static str {
        match self {
            Self::PasswordChanged | Self::PasswordReset => "Your password was changed",
            Self::SignInReset => "Your sign-in was reset",
            Self::TotpEnabled | Self::TotpDisabled => "Two-factor sign-in changed",
            Self::MachineAdded(_) | Self::MachineApproved(_) => "A machine was added to your account",
            Self::RoleChanged { .. } => "Your role changed",
            Self::AddressChanged { .. } | Self::AddressRemoved => "Your email address changed",
        }
    }
}

/// `b***@example.com`: enough to recognise an address, not to harvest it.
pub fn mask(address: &str) -> String {
    match address.split_once('@') {
        Some((local, domain)) => format!("{}***@{domain}", local.chars().next().unwrap_or('*')),
        None => "***".into(),
    }
}

fn when(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| {
            format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", t.year(), u8::from(t.month()), t.day(), t.hour(), t.minute())
        })
        .unwrap_or_else(|_| unix.to_string())
}

fn minutes(ttl_s: i64) -> String {
    match ttl_s {
        s if s >= 2 * 86_400 => format!("{} days", s / 86_400),
        s if s >= 2 * 3600 => format!("{} hours", s / 3600),
        s if s >= 3600 => "1 hour".into(),
        s => format!("{} minutes", (s / 60).max(1)),
    }
}

pub struct Texts<'a> {
    ui: &'a str,
}

impl<'a> Texts<'a> {
    pub fn new(ui_host: &'a str) -> Self {
        Self { ui: ui_host }
    }

    fn footer(&self) -> String {
        format!("\n\n-- \nTunnel at https://{}/\nThis mail was sent automatically; replies are not read.\n", self.ui)
    }

    fn mail(&self, subject: String, body: String) -> Mail {
        Mail { subject, body: format!("{body}{}", self.footer()), expires_at: None }
    }

    /// A mail carrying a link that works for `ttl_s` from now.
    fn link_mail(&self, subject: String, body: String, ttl_s: i64) -> Mail {
        Mail { expires_at: Some(crate::tokens::now() + ttl_s), ..self.mail(subject, body) }
    }

    pub fn invite(&self, url: &str, role: &str, invited_by: Option<&str>, ttl_s: i64) -> Mail {
        let by = invited_by.map(|b| format!("{b} invited you")).unwrap_or_else(|| "You are invited".into());
        self.link_mail(
            format!("You are invited to Tunnel at {}", self.ui),
            format!(
                "{by} to an account ({role}) on the Tunnel server at https://{ui}/.\n\nChoose a username and \
                 password here (the link works once, for {ttl}):\n\n  {url}\n\nSigning up with this link also \
                 confirms this email address for your account. If you did not expect this, ignore this mail.",
                ui = self.ui,
                ttl = minutes(ttl_s),
            ),
            ttl_s,
        )
    }

    pub fn password_reset(&self, url: &str, username: &str, totp: bool, ttl_s: i64) -> Mail {
        let factor = if totp {
            "\n\nTwo-factor sign-in stays on: the page also asks for a code from your authenticator app or a \
             recovery code."
        } else {
            ""
        };
        self.link_mail(
            "Reset your Tunnel password".into(),
            format!(
                "Someone (hopefully you) asked to reset the password of the account {username} at https://{ui}/.\n\n\
                 Choose a new password here (the link works once, for {ttl}):\n\n  {url}{factor}\n\nIf this was \
                 not you, ignore this mail: your password stays as it is.",
                ui = self.ui,
                ttl = minutes(ttl_s),
            ),
            ttl_s,
        )
    }

    pub fn verify_address(&self, url: &str, username: &str, ttl_s: i64) -> Mail {
        self.link_mail(
            "Confirm your email address".into(),
            format!(
                "Confirm that this address belongs to the account {username} at https://{ui}/ (the link works \
                 once, for {ttl}):\n\n  {url}\n\nIf this was not you, ignore this mail: the address is not added.",
                ui = self.ui,
                ttl = minutes(ttl_s),
            ),
            ttl_s,
        )
    }

    pub fn sign_in_reset(&self, url: &str, username: &str, by: &str, ttl_s: i64) -> Mail {
        self.link_mail(
            "Reset your Tunnel sign-in".into(),
            format!(
                "{by} made a link that resets the sign-in of your account {username} at https://{ui}/: it sets a \
                 new password, turns two-factor sign-in off and ends your sessions. It works once, for {ttl}:\n\n  \
                 {url}\n\nIf you did not ask for this, ignore this mail and tell {by}.",
                ui = self.ui,
                ttl = minutes(ttl_s),
            ),
            ttl_s,
        )
    }

    /// A security notice; `ip` is the address the change came from, if known.
    pub fn notice(&self, n: &Notice, username: &str, at: i64, ip: Option<&str>) -> Mail {
        let from = ip.map(|ip| format!(" from {ip}")).unwrap_or_default();
        self.mail(
            n.subject().into(),
            format!(
                "Account {username} at https://{ui}/:\n\n{what}\n\nWhen: {when}{from}\n\nIf this was not you, sign \
                 in and change your password, or ask an admin of this server for help.",
                ui = self.ui,
                what = n.what(),
                when = when(at),
            ),
        )
    }

    pub fn test(&self) -> Mail {
        self.mail(
            "Tunnel test mail".into(),
            format!(
                "This is a test mail from the Tunnel server at https://{}/. Mail works: invites, password resets \
                 and security notices can be sent.",
                self.ui
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_durations() {
        assert_eq!(mask("bob@example.com"), "b***@example.com");
        assert_eq!(minutes(30 * 60), "30 minutes");
        assert_eq!(minutes(3600), "1 hour");
        assert_eq!(minutes(7 * 86_400), "7 days");
        assert_eq!(when(0), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn every_notice_names_the_account_and_the_server() {
        let t = Texts::new("ui.example.com");
        for n in [
            Notice::PasswordChanged,
            Notice::PasswordReset,
            Notice::SignInReset,
            Notice::TotpEnabled,
            Notice::TotpDisabled,
            Notice::MachineAdded("laptop".into()),
            Notice::MachineApproved("laptop".into()),
            Notice::RoleChanged { from: "member".into(), to: "admin".into() },
            Notice::AddressChanged { new: "new@example.com".into() },
            Notice::AddressRemoved,
        ] {
            let m = t.notice(&n, "bob", 0, Some("192.0.2.1"));
            assert!(m.body.contains("bob") && m.body.contains("https://ui.example.com/"), "{}", m.body);
            assert!(m.body.contains("192.0.2.1"));
            assert!(!m.body.contains("new@example.com"), "the new address is masked");
        }
    }
}
