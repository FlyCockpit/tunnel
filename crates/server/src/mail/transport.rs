//! One SMTP delivery, step by step, so a failure names the step that failed
//! (lettre's pooled transport cannot tell a TLS failure from a refused
//! connection, or a refused sign-in from a refused sender).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::{
    AsyncSmtpConnection, AsyncTokioStream, Certificate, CertificateStore, TlsParameters,
};
use lettre::transport::smtp::commands::{Data, Mail, Rcpt};
use lettre::transport::smtp::extension::ClientId;
use lettre::transport::smtp::response::{Response, Severity};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;

use crate::config::smtp::Security;

/// Connecting may take this long for all addresses together…
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// …and this long for each, so one that never answers (a broken IPv6
/// route) leaves time for the next.
const CONNECT_PER_ADDRESS: Duration = Duration::from_secs(5);
/// …every other step this long…
const STEP_TIMEOUT: Duration = Duration::from_secs(20);
/// …and the whole delivery this long.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// The steps of a delivery, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Dns,
    Connect,
    Tls,
    Greeting,
    Auth,
    Sender,
    Recipient,
    Data,
}

impl Step {
    const ALL: [Step; 8] =
        [Self::Dns, Self::Connect, Self::Tls, Self::Greeting, Self::Auth, Self::Sender, Self::Recipient, Self::Data];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "DNS lookup",
            Self::Connect => "connect",
            Self::Tls => "TLS",
            Self::Greeting => "greeting",
            Self::Auth => "sign-in (AUTH)",
            Self::Sender => "sender (MAIL FROM)",
            Self::Recipient => "recipient (RCPT TO)",
            Self::Data => "message (DATA)",
        }
    }
}

/// A failed delivery: the step, the SMTP reply code if the server gave one,
/// and what happened. Never holds the message (it carries tokens).
#[derive(Debug, Clone)]
pub struct SendError {
    pub step: Step,
    pub code: Option<u16>,
    /// What happened, in this program's words: safe to log.
    pub detail: String,
    /// The server's own words as they came, if it said something: shown by
    /// `mail test` (password masked first, then shortened), never logged,
    /// since a relay may echo what it was sent.
    pub reply: Option<String>,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.step.label(), self.detail)?;
        if let Some(hint) = self.hint() {
            write!(f, " ({hint})")?;
        }
        Ok(())
    }
}

impl SendError {
    pub(crate) fn new(step: Step, detail: impl Into<String>) -> Self {
        Self { step, code: None, detail: one_line(&detail.into()), reply: None }
    }

    /// A lettre error: a reply from the server keeps its text out of `detail`.
    fn smtp(step: Step, e: &lettre::transport::smtp::Error) -> Self {
        let code = e.status().map(|c| c.to_string().parse().unwrap_or(0));
        if code.is_some() || e.is_response() {
            let detail = match code {
                Some(c) => format!("the server refused it ({c})"),
                None => "the server's reply was not understood".to_string(),
            };
            return Self { step, code, detail, reply: Some(e.to_string()) };
        }
        Self::new(step, e.to_string())
    }

    /// A positive reply of the wrong kind (e.g. 250 where 354 belongs).
    fn unexpected(step: Step, r: &Response) -> Self {
        let code = r.code().to_string().parse().ok();
        Self {
            step,
            code,
            detail: format!("unexpected reply {} from the server", r.code()),
            reply: Some(r.message().collect::<Vec<_>>().join("\n")),
        }
    }

    /// What to check for the usual causes.
    fn hint(&self) -> Option<&'static str> {
        Some(match self.step {
            Step::Dns => "check the host name",
            Step::Connect => {
                "check the host and port, and that outbound mail is not blocked by a firewall or the VM provider"
            }
            Step::Tls => "port 465 is TLS from the start, other ports need STARTTLS; check the port",
            Step::Auth => "check the user and password (some providers need an app password or API key)",
            Step::Sender => "the server refuses this sender: use an address of a verified domain or sender",
            Step::Recipient => "the server refuses this recipient",
            Step::Greeting | Step::Data => return None,
        })
    }
}

/// `s` on one line, at most 300 characters.
pub(crate) fn one_line(s: &str) -> String {
    let s: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    s.chars().take(300).collect()
}

/// Where and how to deliver.
pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub security: Security,
    pub credentials: Option<(&'a str, &'a str)>,
    /// EHLO name: the web UI's host.
    pub hello: &'a str,
    /// Trusted roots (the public web roots; tests add their own).
    pub roots: &'a [CertificateDer<'static>],
}

pub static PUBLIC_ROOTS: LazyLock<Vec<CertificateDer<'static>>> =
    LazyLock::new(|| webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec());

/// Deliver `message` (a formatted RFC 5322 message) from `from` to `to`.
/// `done` is called after each step that succeeded.
pub async fn deliver(
    t: &Target<'_>,
    from: &lettre::Address,
    to: &lettre::Address,
    message: &[u8],
    done: &mut (dyn FnMut(Step) + Send),
) -> Result<(), SendError> {
    // The step under way (set as each starts), so running out of the overall time names it.
    let current = AtomicUsize::new(0);
    match tokio::time::timeout(SEND_TIMEOUT, deliver_inner(t, from, to, message, done, &current)).await {
        Ok(Ok(mut conn)) => {
            // Delivered once DATA is accepted: QUIT is a courtesy outside the deadline.
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.quit()).await;
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(SendError::new(
            Step::ALL[current.load(Ordering::Relaxed)],
            format!("gave up after {} s in all", SEND_TIMEOUT.as_secs()),
        )),
    }
}

/// A completed command: a 2xx reply.
fn completed(step: Step, r: Response) -> Result<Response, SendError> {
    if r.code().severity == Severity::PositiveCompletion { Ok(r) } else { Err(SendError::unexpected(step, &r)) }
}

async fn step<T>(
    current: &AtomicUsize,
    step: Step,
    limit: Duration,
    f: impl Future<Output = Result<T, SendError>>,
) -> Result<T, SendError> {
    current.store(Step::ALL.iter().position(|s| *s == step).unwrap_or(0), Ordering::Relaxed);
    tokio::time::timeout(limit, f)
        .await
        .unwrap_or_else(|_| Err(SendError::new(step, format!("no answer within {} s", limit.as_secs()))))
}

async fn deliver_inner(
    t: &Target<'_>,
    from: &lettre::Address,
    to: &lettre::Address,
    message: &[u8],
    done: &mut (dyn FnMut(Step) + Send),
    current: &AtomicUsize,
) -> Result<AsyncSmtpConnection, SendError> {
    let host = t.host.trim_matches(['[', ']']);
    let addrs: Vec<SocketAddr> = step(current, Step::Dns, STEP_TIMEOUT, async {
        let found = tokio::net::lookup_host((host, t.port))
            .await
            .map_err(|e| SendError::new(Step::Dns, format!("{host}: {e}")))?
            .collect::<Vec<_>>();
        if found.is_empty() { Err(SendError::new(Step::Dns, format!("{host} has no address"))) } else { Ok(found) }
    })
    .await?;
    // Plain SMTP is only for a relay on this machine: whatever the name
    // resolved to, never connect elsewhere without TLS.
    let addrs = if t.security == Security::Plain {
        let local: Vec<SocketAddr> = addrs.into_iter().filter(|a| a.ip().to_canonical().is_loopback()).collect();
        if local.is_empty() {
            return Err(SendError::new(
                Step::Connect,
                format!("{host} is not a loopback address, and mail goes unencrypted only to this machine"),
            ));
        }
        local
    } else {
        addrs
    };
    done(Step::Dns);

    let tcp =
        step(current, Step::Connect, CONNECT_TIMEOUT, connect_any(&addrs, CONNECT_PER_ADDRESS, TcpStream::connect))
            .await?;
    let _ = tcp.set_nodelay(true);
    done(Step::Connect);

    let stream: Box<dyn AsyncTokioStream> = if t.security == Security::ImplicitTls {
        let tls = step(current, Step::Tls, STEP_TIMEOUT, async {
            let name = ServerName::try_from(host.to_string())
                .map_err(|_| SendError::new(Step::Tls, format!("{host} is not a valid TLS server name")))?;
            tokio_rustls::TlsConnector::from(client_config(t.roots))
                .connect(name, tcp)
                .await
                .map_err(|e| SendError::new(Step::Tls, e.to_string()))
        })
        .await?;
        done(Step::Tls);
        Box::new(TlsStream(tls))
    } else {
        Box::new(tcp)
    };

    let hello = ClientId::Domain(t.hello.to_string());
    let mut conn = step(current, Step::Greeting, STEP_TIMEOUT, async {
        AsyncSmtpConnection::connect_with_transport(stream, &hello)
            .await
            .map_err(|e| SendError::smtp(Step::Greeting, &e))
    })
    .await?;
    done(Step::Greeting);

    if t.security == Security::StartTls {
        step(current, Step::Tls, STEP_TIMEOUT, async {
            if !conn.can_starttls() {
                return Err(SendError::new(
                    Step::Tls,
                    "the server does not offer STARTTLS, and mail is never sent unencrypted over the network",
                ));
            }
            conn.starttls(tls_parameters(host, t.roots)?, &hello).await.map_err(|e| SendError::smtp(Step::Tls, &e))
        })
        .await?;
        done(Step::Tls);
    }

    if let Some((user, pass)) = t.credentials {
        step(current, Step::Auth, STEP_TIMEOUT, async {
            let creds = Credentials::new(user.to_string(), pass.to_string());
            let r = conn
                .auth(&[Mechanism::Plain, Mechanism::Login], &creds)
                .await
                .map_err(|e| SendError::smtp(Step::Auth, &e))?;
            completed(Step::Auth, r)
        })
        .await?;
        done(Step::Auth);
    }

    step(current, Step::Sender, STEP_TIMEOUT, async {
        let r =
            conn.command(Mail::new(Some(from.clone()), vec![])).await.map_err(|e| SendError::smtp(Step::Sender, &e))?;
        completed(Step::Sender, r)
    })
    .await?;
    done(Step::Sender);
    step(current, Step::Recipient, STEP_TIMEOUT, async {
        let r = conn.command(Rcpt::new(to.clone(), vec![])).await.map_err(|e| SendError::smtp(Step::Recipient, &e))?;
        completed(Step::Recipient, r)
    })
    .await?;
    done(Step::Recipient);
    step(current, Step::Data, STEP_TIMEOUT, async {
        // The body goes only after "354 go ahead", or it would be read as commands.
        let r = conn.command(Data).await.map_err(|e| SendError::smtp(Step::Data, &e))?;
        if !r.has_code(354) {
            return Err(SendError::unexpected(Step::Data, &r));
        }
        let r = conn.message(message).await.map_err(|e| SendError::smtp(Step::Data, &e))?;
        completed(Step::Data, r)
    })
    .await?;
    done(Step::Data);
    Ok(conn)
}

/// The first address that accepts a connection within `per_address`, in order.
pub(crate) async fn connect_any<T, F, Fut>(
    addrs: &[SocketAddr],
    per_address: Duration,
    connect: F,
) -> Result<T, SendError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let mut last = None;
    for addr in addrs {
        match tokio::time::timeout(per_address, connect(*addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(format!("{addr}: {e}")),
            Err(_) => last = Some(format!("{addr}: no answer within {} s", per_address.as_secs())),
        }
    }
    Err(SendError::new(Step::Connect, last.unwrap_or_default()))
}

fn client_config(roots: &[CertificateDer<'static>]) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(roots.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

/// lettre's STARTTLS settings with the same roots (no system store, no OpenSSL).
fn tls_parameters(host: &str, roots: &[CertificateDer<'static>]) -> Result<TlsParameters, SendError> {
    let mut b = TlsParameters::builder(host.to_string()).certificate_store(CertificateStore::None);
    for root in roots {
        if let Ok(cert) = Certificate::from_der(root.to_vec()) {
            b = b.add_root_certificate(cert);
        }
    }
    b.build_rustls().map_err(|e| SendError::smtp(Step::Tls, &e))
}

/// An implicit-TLS stream lettre can drive.
#[derive(Debug)]
struct TlsStream(tokio_rustls::client::TlsStream<TcpStream>);

impl AsyncTokioStream for TlsStream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.get_ref().0.peer_addr()
    }
}

impl tokio::io::AsyncRead for TlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
