//! A small SMTP server on loopback for tests: scripted answers, optional
//! STARTTLS or implicit TLS with a throwaway certificate, and every message
//! it accepts kept for inspection. No network beyond 127.0.0.1.

use std::sync::{Arc, Mutex};

use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// How the fake server behaves.
#[derive(Clone, Default)]
pub struct Script {
    /// Offer STARTTLS (with `tls`).
    pub starttls: bool,
    /// TLS from the first byte (with `tls`).
    pub implicit_tls: bool,
    /// Offer AUTH PLAIN LOGIN and accept exactly this `user:pass`.
    pub auth: Option<String>,
    pub refuse_sender: bool,
    pub refuse_recipient: bool,
    /// Answer DATA with 250 instead of 354 (a broken relay).
    pub data_250: bool,
    /// Accept connections and never say anything.
    pub silent: bool,
    /// Answer AUTH with 354 (neither a challenge nor a completion).
    pub auth_354: bool,
    /// Wait this long before every reply (tests with a paused clock).
    pub delay_s: u64,
    /// Never answer QUIT.
    pub quit_silent: bool,
}

/// A message the server accepted.
#[derive(Debug, Clone)]
pub struct Received {
    pub from: String,
    pub to: String,
    pub data: String,
    /// Whether it came over TLS.
    pub tls: bool,
}

impl Received {
    /// The body, with quoted-printable soft line breaks undone (enough to find links).
    pub fn text(&self) -> String {
        let body = self.data.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&self.data);
        body.replace("=\r\n", "").replace("=3D", "=")
    }

    pub fn subject(&self) -> String {
        self.data.lines().find_map(|l| l.strip_prefix("Subject: ")).unwrap_or_default().to_string()
    }

    /// The first `https://…#tninv_…` link in the body.
    pub fn link(&self) -> Option<String> {
        let text = self.text();
        let token_at = text.find("#tninv_")?;
        let start = text[..token_at].rfind("https://")?;
        let rest = &text[start..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }

    /// The token in the link's fragment.
    pub fn token(&self) -> Option<String> {
        self.link()?.split_once('#').map(|(_, t)| t.to_string())
    }
}

pub struct FakeSmtp {
    pub port: u16,
    /// The certificate clients must trust for TLS (`localhost`).
    pub root: CertificateDer<'static>,
    received: Arc<Mutex<Vec<Received>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeSmtp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeSmtp {
    pub async fn start(script: Script) -> Self {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root = CertificateDer::from(generated.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()));
        let tls = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![root.clone()], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let store = received.clone();
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (script, store, tls) = (script.clone(), store.clone(), tls.clone());
                tokio::spawn(async move {
                    let _ = session(tcp, &script, &store, tls).await;
                });
            }
        });
        Self { port, root, received, task }
    }

    pub fn received(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }

    /// Mails to `to`, oldest first.
    pub fn to(&self, to: &str) -> Vec<Received> {
        self.received().into_iter().filter(|m| m.to == to).collect()
    }
}

async fn session(
    tcp: TcpStream,
    script: &Script,
    store: &Mutex<Vec<Received>>,
    tls: Arc<rustls::ServerConfig>,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    if script.silent {
        // Hold the connection open and say nothing.
        // (`tcp` stays alive in this frame while it waits.)
        std::future::pending::<()>().await;
        return Ok(());
    }
    if script.implicit_tls {
        let stream = acceptor.accept(tcp).await?;
        run(stream, script, store, true, true).await?;
        return Ok(());
    }
    if let Some(tcp) = run(tcp, script, store, false, true).await? {
        let stream = acceptor.accept(tcp).await?;
        run(stream, script, store, true, false).await?;
    }
    Ok(())
}

/// Serve one connection; returns the stream when the client asked for STARTTLS.
async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    script: &Script,
    store: &Mutex<Vec<Received>>,
    tls: bool,
    greet: bool,
) -> std::io::Result<Option<S>> {
    let mut io = BufReader::new(stream);
    let pause = || tokio::time::sleep(std::time::Duration::from_secs(script.delay_s));
    if greet {
        pause().await;
        io.write_all(b"220 fake.test ESMTP\r\n").await?;
    }
    let (mut from, mut to) = (String::new(), String::new());
    let mut line = String::new();
    loop {
        line.clear();
        if io.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        let cmd = line.trim_end().to_string();
        let upper = cmd.to_ascii_uppercase();
        let reply: String = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let mut r = String::from("250-fake.test\r\n");
            if script.starttls && !tls {
                r.push_str("250-STARTTLS\r\n");
            }
            if script.auth.is_some() {
                r.push_str("250-AUTH PLAIN LOGIN\r\n");
            }
            r.push_str("250 8BITMIME\r\n");
            r
        } else if upper == "STARTTLS" && script.starttls && !tls {
            io.write_all(b"220 2.0.0 go ahead\r\n").await?;
            return Ok(Some(io.into_inner()));
        } else if upper.starts_with("AUTH") && script.auth_354 {
            "354 go on\r\n".into()
        } else if upper.starts_with("AUTH PLAIN") {
            let mut b64 = cmd[10..].trim().to_string();
            if b64.is_empty() {
                io.write_all(b"334 \r\n").await?;
                line.clear();
                io.read_line(&mut line).await?;
                b64 = line.trim().to_string();
            }
            let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default();
            let parts: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
            let given = match parts.as_slice() {
                [_, user, pass] => format!("{}:{}", String::from_utf8_lossy(user), String::from_utf8_lossy(pass)),
                _ => String::new(),
            };
            if script.auth.as_deref() == Some(given.as_str()) {
                "235 2.7.0 accepted\r\n".into()
            } else {
                "535 5.7.8 authentication credentials invalid\r\n".into()
            }
        } else if upper.starts_with("MAIL FROM:") {
            from = addr(&cmd[10..]);
            if script.refuse_sender { "550 5.7.1 sender not allowed\r\n".into() } else { "250 2.1.0 ok\r\n".into() }
        } else if upper.starts_with("RCPT TO:") {
            to = addr(&cmd[8..]);
            if script.refuse_recipient { "550 5.1.1 no such user\r\n".into() } else { "250 2.1.5 ok\r\n".into() }
        } else if upper == "DATA" && script.data_250 {
            "250 2.0.0 ok\r\n".into()
        } else if upper == "DATA" {
            pause().await;
            io.write_all(b"354 end with <CRLF>.<CRLF>\r\n").await?;
            let mut data = String::new();
            loop {
                line.clear();
                if io.read_line(&mut line).await? == 0 {
                    return Ok(None);
                }
                if line == ".\r\n" {
                    break;
                }
                data.push_str(line.strip_prefix('.').filter(|_| line.starts_with("..")).unwrap_or(&line));
            }
            store.lock().unwrap().push(Received { from: from.clone(), to: to.clone(), data, tls });
            "250 2.0.0 queued\r\n".into()
        } else if upper == "QUIT" && script.quit_silent {
            std::future::pending::<()>().await;
            return Ok(None);
        } else if upper == "QUIT" {
            io.write_all(b"221 2.0.0 bye\r\n").await?;
            return Ok(None);
        } else if upper == "RSET" || upper == "NOOP" {
            "250 2.0.0 ok\r\n".into()
        } else {
            "502 5.5.2 not implemented\r\n".into()
        };
        pause().await;
        io.write_all(reply.as_bytes()).await?;
    }
}

fn addr(s: &str) -> String {
    s.trim().trim_start_matches('<').split('>').next().unwrap_or_default().to_ascii_lowercase()
}
