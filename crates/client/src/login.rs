//! `tunnel login`: the machine's client token and server, plus a
//! small management-API client for `share`, `link`, `links`, `unlink`, `unshare` and `stop`.
//!
//! Saved at `$XDG_CONFIG_HOME/tunnel/login.json` (else
//! `~/.config/...`), mode 0600 in a 0700 directory. Deliberately not `Debug`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::paths::terminal_text;
use crate::state::write_atomic;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize)]
pub struct Login {
    /// Client name on the server.
    pub name: String,
    /// `https://<api host>`
    pub api: String,
    /// `wss://<tunnel host>`
    pub server: String,
    /// `tncli_…`
    pub token: String,
}

pub fn path() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("tunnel").join("login.json"))
}

impl Login {
    pub fn load() -> anyhow::Result<Option<Self>> {
        let p = path()?;
        match std::fs::read(&p) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", p.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    pub fn require() -> anyhow::Result<Self> {
        Self::load()?.context(
            "not logged in: run `tunnel login https://<server>` and approve this machine in the browser, \
             or ask the server admin for a login code (`tunnel-server client add <name>`)",
        )
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let p = path()?;
        if let Some(dir) = p.parent() {
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
            }
        }
        write_atomic(&p, &serde_json::to_vec_pretty(self)?, 0o600).with_context(|| format!("writing {}", p.display()))
    }
}

fn http() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        // Preserve bundled Mozilla roots even when the host has no CA bundle.
        .tls_certs_only(
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| reqwest::Certificate::from_der(der).expect("bundled Mozilla root is valid DER")),
        )
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("tunnel/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Body of an API response, or its `error.message` as the error.
async fn decode<T: DeserializeOwned>(resp: reqwest::Response, what: &str) -> anyhow::Result<T> {
    let status = resp.status();
    let text = resp.text().await.with_context(|| what.to_string())?;
    if status == reqwest::StatusCode::UNAUTHORIZED && what != "login" {
        bail!(
            "the server no longer accepts this machine's login (the client was deleted or logged in elsewhere); \
             ask the admin for a new `tunnel login` command"
        );
    }
    if !status.is_success() {
        let message = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["error"]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| text.chars().take(300).collect());
        bail!("{what}: HTTP {}: {}", status.as_u16(), terminal_text(&message));
    }
    if text.trim().is_empty() {
        return Ok(serde_json::from_value(Value::Null)?);
    }
    serde_json::from_str(&text).with_context(|| format!("{what}: unexpected response"))
}

/// `<code>@<host>` from `client add`.
pub fn parse_login_arg(arg: &str) -> anyhow::Result<(String, String)> {
    let arg = arg.trim().trim_matches('\'').trim_matches('"');
    let Some((code, host)) = arg.rsplit_once('@') else {
        bail!("expected <code>@<host>, as printed by `tunnel-server client add`");
    };
    let host = host.trim().trim_start_matches("https://").trim_end_matches('/');
    if !code.starts_with(tunnel_protocol::ENROLL_CODE_PREFIX) || host.is_empty() || host.contains('/') {
        bail!("expected <code>@<host>, as printed by `tunnel-server client add`");
    }
    Ok((code.to_string(), host.to_string()))
}

#[derive(Deserialize)]
struct Enrolled {
    name: String,
    token: String,
    api: String,
    server: String,
}

pub async fn enroll(code: &str, host: &str) -> anyhow::Result<Login> {
    let resp = http()?
        .post(format!("https://{host}/v1/clients/enroll"))
        .json(&json!({ "code": code }))
        .send()
        .await
        .with_context(|| format!("contacting https://{host}"))?;
    let e: Enrolled = decode(resp, "login").await?;
    Ok(Login { name: e.name, api: e.api, server: e.server, token: e.token })
}

/// What `tunnel login <arg>` was given.
pub enum LoginTarget {
    /// `<code>@<host>` from `tunnel-server client add` (no browser needed).
    Code { code: String, host: String },
    /// `https://<ui host>`: approve this machine in the browser.
    Browser { origin: String },
}

pub fn parse_login_target(arg: &str) -> anyhow::Result<LoginTarget> {
    let trimmed = arg.trim().trim_matches('\'').trim_matches('"');
    if trimmed.contains('@') {
        let (code, host) = parse_login_arg(trimmed)?;
        return Ok(LoginTarget::Code { code, host });
    }
    let host = trimmed.strip_prefix("https://").unwrap_or(trimmed).trim_end_matches('/');
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':');
    if trimmed.starts_with("http://") || !valid {
        bail!("expected https://<server> (browser approval) or <code>@<host> (from `tunnel-server client add`)");
    }
    Ok(LoginTarget::Browser { origin: format!("https://{}", host.to_ascii_lowercase()) })
}

/// This machine's name for the server: the hostname, reduced to the
/// characters the server accepts.
pub fn default_machine_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
    // within it or truncates, and the last byte is kept 0.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) } == 0;
    let raw = if ok {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        String::new()
    };
    let name: String = raw
        .split('.')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '-' })
        .take(48)
        .collect();
    let name = name.trim_matches('-').to_string();
    if name.is_empty() { "machine".to_string() } else { name }
}

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    interval: u64,
    expires_in: u64,
}

/// Browser-approved login (RFC 8628): print the code and the page, open the
/// page if there is a desktop, and poll until someone approves or denies.
pub async fn device_login(origin: &str, name: &str, open_browser: bool) -> anyhow::Result<Login> {
    let http = http()?;
    let resp = http
        .post(format!("{origin}/v1/device/code"))
        .json(&json!({ "client_name": name }))
        .send()
        .await
        .with_context(|| format!("contacting {origin}"))?;
    let code: DeviceCode = decode(resp, "login").await?;
    let page = terminal_text(&code.verification_uri);
    let user_code = terminal_text(&code.user_code);
    eprintln!(
        "To approve this machine ({}), open\n\n  {page}\n\nsign in, and enter the code\n\n  {user_code}\n",
        terminal_text(name)
    );
    // Open only a page on the server we asked: never a server-chosen scheme
    // or something `open` could read as an option.
    if open_browser && code.verification_uri.starts_with(&format!("{origin}/")) {
        open_url(&code.verification_uri);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(code.expires_in.min(3600));
    let mut interval = code.interval.clamp(1, 60);
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if std::time::Instant::now() >= deadline {
            bail!("the code expired before it was approved; run `tunnel login {origin}` again");
        }
        let resp = match http
            .post(format!("{origin}/v1/device/token"))
            .json(&json!({ "device_code": code.device_code }))
            .send()
            .await
        {
            Ok(r) => r,
            // A network blip while waiting is not fatal.
            Err(_) => continue,
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            let e: Enrolled = serde_json::from_str(&text).context("login: unexpected response")?;
            return Ok(Login { name: e.name, api: e.api, server: e.server, token: e.token });
        }
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let err = body["error"]["code"].as_str().unwrap_or("");
        match err {
            "authorization_pending" => {}
            "slow_down" => interval += 5,
            "expired_token" => bail!("the code expired before it was approved; run `tunnel login {origin}` again"),
            "access_denied" => bail!("the login was denied in the browser"),
            _ => {
                let message = body["error"]["message"].as_str().map(str::to_string).unwrap_or(text);
                bail!("login: HTTP {}: {}", status.as_u16(), terminal_text(&message));
            }
        }
    }
}

/// Best effort: open `url` in the desktop's browser; nothing on a headless box.
fn open_url(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        Some("open")
    } else if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        Some("xdg-open")
    } else {
        None
    };
    if let Some(cmd) = opener {
        let _ = std::process::Command::new(cmd)
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// Management API calls made with this machine's client token.
pub struct Api<'a> {
    login: &'a Login,
    http: reqwest::Client,
}

#[derive(Deserialize)]
pub struct Created {
    pub id: String,
    pub expires_at: i64,
    pub tunnel_token: String,
    /// The account reached its monthly traffic cap.
    #[serde(default)]
    pub traffic_limited: bool,
}

#[derive(Deserialize)]
pub struct TunnelInfo {
    pub expired: bool,
    pub expires_at: i64,
    pub access: AccessInfo,
    #[serde(default)]
    pub traffic_limited: bool,
}

#[derive(Deserialize)]
pub struct NewLink {
    pub id: String,
    pub url: String,
    pub expires_at: i64,
}

/// A listed access link (`GET /v1/tunnels/{id}/access-links`; no URL).
#[derive(Deserialize, Serialize)]
pub struct LinkInfo {
    pub id: String,
    pub label: Option<String>,
    pub single_use: bool,
    pub used_at: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct AccessInfo {
    pub mode: String,
    #[serde(default)]
    pub username: Option<String>,
}

impl<'a> Api<'a> {
    pub fn new(login: &'a Login) -> anyhow::Result<Self> {
        Ok(Self { login, http: http()? })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http.request(method, format!("{}{path}", self.login.api)).bearer_auth(&self.login.token)
    }

    pub async fn create_tunnel(&self, label: &str, ttl_s: u64, access: &Value) -> anyhow::Result<Created> {
        let body = json!({ "label": label, "ttl_s": ttl_s, "access": access });
        decode(self.req(reqwest::Method::POST, "/v1/tunnels").json(&body).send().await?, "creating tunnel").await
    }

    /// `None` if the tunnel is gone (deleted, or not this client's).
    pub async fn tunnel(&self, id: &str) -> anyhow::Result<Option<TunnelInfo>> {
        let resp = self.req(reqwest::Method::GET, &format!("/v1/tunnels/{id}")).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND || resp.status() == reqwest::StatusCode::CONFLICT {
            return Ok(None);
        }
        decode(resp, "reading tunnel").await.map(Some)
    }

    pub async fn set_access(&self, id: &str, access: &Value) -> anyhow::Result<()> {
        let resp = self
            .req(reqwest::Method::PATCH, &format!("/v1/tunnels/{id}"))
            .json(&json!({ "access": access }))
            .send()
            .await?;
        decode::<Value>(resp, "changing access").await.map(|_| ())
    }

    /// A new access link that opens `port`'s preview.
    pub async fn access_link(
        &self,
        id: &str,
        port: u16,
        ttl_s: u64,
        single_use: bool,
        label: Option<&str>,
    ) -> anyhow::Result<NewLink> {
        let mut body = json!({ "ttl_s": ttl_s, "single_use": single_use, "port": port });
        if let Some(label) = label {
            body["label"] = json!(label);
        }
        let resp =
            self.req(reqwest::Method::POST, &format!("/v1/tunnels/{id}/access-links")).json(&body).send().await?;
        decode(resp, "creating access link").await
    }

    /// The tunnel's access links, newest first; `None` if the tunnel is gone.
    pub async fn access_links(&self, id: &str) -> anyhow::Result<Option<Vec<LinkInfo>>> {
        #[derive(Deserialize)]
        struct List {
            links: Vec<LinkInfo>,
        }
        let resp = self.req(reqwest::Method::GET, &format!("/v1/tunnels/{id}/access-links")).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        decode::<List>(resp, "listing access links").await.map(|l| Some(l.links))
    }

    pub async fn delete_access_link(&self, id: &str) -> anyhow::Result<()> {
        let resp = self.req(reqwest::Method::DELETE, &format!("/v1/access-links/{id}")).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("access link {} not found (already revoked?)", terminal_text(id));
        }
        decode::<Value>(resp, "revoking access link").await.map(|_| ())
    }

    pub async fn delete_tunnel(&self, id: &str) -> anyhow::Result<()> {
        let resp = self.req(reqwest::Method::DELETE, &format!("/v1/tunnels/{id}")).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        decode::<Value>(resp, "deleting tunnel").await.map(|_| ())
    }
}

/// `90`, `30m`, `8h`, `2d` → seconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("'{s}' is not a duration like 90s, 30m, 8h, or 2d"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_arg() {
        assert_eq!(
            parse_login_arg("'tnenr_abc@tunnel.example.com'").unwrap(),
            ("tnenr_abc".to_string(), "tunnel.example.com".to_string())
        );
        assert!(parse_login_arg("tnenr_abc").is_err());
        assert!(parse_login_arg("other_abc@host").is_err());
        assert!(parse_login_arg("tnenr_abc@host/path").is_err());
    }

    #[test]
    fn login_targets() {
        assert!(matches!(
            parse_login_target("https://tunnel.example.com/").unwrap(),
            LoginTarget::Browser { origin } if origin == "https://tunnel.example.com"
        ));
        assert!(matches!(
            parse_login_target("Tunnel.Example.com").unwrap(),
            LoginTarget::Browser { origin } if origin == "https://tunnel.example.com"
        ));
        assert!(matches!(parse_login_target("tnenr_abc@host").unwrap(), LoginTarget::Code { .. }));
        assert!(parse_login_target("http://tunnel.example.com").is_err());
        assert!(parse_login_target("https://tunnel.example.com/device?x=1").is_err());
        assert!(parse_login_target("").is_err());
        let name = default_machine_name();
        assert!(!name.is_empty() && name.len() <= 48);
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("8h").unwrap(), 28_800);
        assert_eq!(parse_duration("2d").unwrap(), 172_800);
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
