//! Outgoing mail, when `[smtp]` is configured (see `config::smtp`).
//!
//! Requests never wait for the mail server: they queue a mail and answer,
//! so neither the time taken nor a delivery failure tells a caller anything
//! (e.g. whether an address belongs to an account). Deliveries run a few
//! at a time, are bounded in time and never retried. Logs name the kind of
//! mail and the failing step, never the message (it carries tokens).

mod texts;
pub mod transport;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub use texts::{Notice, Texts};
pub use transport::{SendError, Step};

use crate::config::Config;
use crate::config::smtp::SmtpConfig;

/// Deliveries at the same time…
const PARALLEL: usize = 4;
/// …and waiting; more are dropped (with a warning) rather than queued without bound.
const MAX_QUEUED: usize = 200;
/// Notices may use only this much of the queue (the rest is kept for
/// password resets, invites and address checks)…
const NOTICE_QUEUE: usize = MAX_QUEUED / 2;
/// …and go to one address at most this often per minute.
const NOTICES_PER_MIN: u32 = 5;
/// Background jobs (e.g. "Forgot password?" lookups) waiting for the one
/// worker that runs them; more are dropped, whatever they would have found.
const MAX_JOBS: usize = 64;

type Job = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// A mail to send: subject and plain-text body.
pub struct Mail {
    pub subject: String,
    pub body: String,
    /// When the link it carries stops working (unix seconds): a mail that
    /// waited in the queue until then is dropped, not sent.
    pub expires_at: Option<i64>,
}

/// A link mail goes out only with at least this long left to use it.
const LINK_MIN_LEFT_S: i64 = 60;

pub struct Mailer {
    smtp: SmtpConfig,
    ui_host: String,
    slots: tokio::sync::Semaphore,
    /// Deliveries queued or under way.
    deliveries: AtomicUsize,
    /// Jobs queued or running (counted apart, so they never take delivery places).
    jobs: Arc<AtomicUsize>,
    /// Notices per address (a burst of machine changes cannot flood a mailbox or the queue).
    notices: crate::ratelimit::Limiter<String>,
    /// The job queue, made with its worker on first use (inside the runtime).
    job_queue: std::sync::OnceLock<tokio::sync::mpsc::Sender<Job>>,
    #[cfg(test)]
    roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Mailer {
    /// A mailer when mail is on (`[smtp]` and a web UI); `None` otherwise.
    pub fn from_config(cfg: &Config) -> Option<Arc<Self>> {
        if !cfg.mail_enabled() {
            return None;
        }
        Some(Arc::new(Self::new(cfg.smtp.clone()?, cfg.ui_host.clone()?)))
    }

    pub fn new(smtp: SmtpConfig, ui_host: String) -> Self {
        Self {
            smtp,
            ui_host,
            slots: tokio::sync::Semaphore::new(PARALLEL),
            deliveries: AtomicUsize::new(0),
            jobs: Arc::new(AtomicUsize::new(0)),
            notices: crate::ratelimit::Limiter::new(NOTICES_PER_MIN),
            job_queue: std::sync::OnceLock::new(),
            #[cfg(test)]
            roots: Vec::new(),
        }
    }

    /// Trust `root` too (tests: a local TLS server).
    #[cfg(test)]
    pub fn with_root(mut self, root: rustls::pki_types::CertificateDer<'static>) -> Self {
        self.roots.push(root);
        self
    }

    pub fn texts(&self) -> Texts<'_> {
        Texts::new(&self.ui_host)
    }

    /// Send `mail` to `to` in the background. `kind` names it in the log.
    /// `false` if the queue was full and it was dropped.
    #[must_use = "say whether it was mailed (or ignore a drop on purpose)"]
    pub fn send_later(self: &Arc<Self>, kind: &'static str, to: String, mail: Mail) -> bool {
        self.queue(kind, to, mail, MAX_QUEUED)
    }

    /// Queue a delivery while fewer than `limit` are queued (the place is
    /// taken atomically, so concurrent callers never pass the limit).
    fn queue(self: &Arc<Self>, kind: &'static str, to: String, mail: Mail, limit: usize) -> bool {
        if self.deliveries.fetch_add(1, Ordering::SeqCst) >= limit {
            self.deliveries.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(kind, "mail queue full; dropped a mail");
            return false;
        }
        let me = self.clone();
        tokio::spawn(async move {
            match me.slots.acquire().await {
                Ok(_) if mail.expires_at.is_some_and(|e| e - crate::tokens::now() < LINK_MIN_LEFT_S) => {
                    tracing::warn!(kind, "mail dropped: its link expired while it waited in the queue");
                }
                Ok(_slot) => match me.send_now(&to, mail, &mut |_| {}).await {
                    Ok(()) => tracing::info!(kind, "mail sent"),
                    // `detail` is this program's text; the server's reply is never logged.
                    Err(e) => {
                        tracing::warn!(kind, step = e.step.label(), code = e.code, error = %e.detail, "mail not sent")
                    }
                },
                Err(_) => tracing::warn!(kind, "mailer closed; dropped a mail"),
            }
            me.deliveries.fetch_sub(1, Ordering::SeqCst);
        });
        true
    }

    /// Send a security notice in the background, unless that address had
    /// its share this minute or the queue is half full (reset mails first).
    pub fn send_notice_later(self: &Arc<Self>, to: String, mail: Mail) {
        if !self.notices.check_key(to.clone()) {
            tracing::info!("security notice skipped (rate limit)");
            return;
        }
        self.queue("notice", to, mail, NOTICE_QUEUE);
    }

    /// Queue `job` for the background worker (one at a time; it may queue
    /// mails). A full queue drops it before it runs, so whether a job is
    /// dropped never depends on what it would have found.
    pub fn run_later(&self, job: impl Future<Output = ()> + Send + 'static) {
        let queue = self.job_queue.get_or_init(|| {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<Job>(MAX_JOBS);
            let jobs = self.jobs.clone();
            tokio::spawn(async move {
                while let Some(job) = rx.recv().await {
                    job.await;
                    jobs.fetch_sub(1, Ordering::SeqCst);
                }
            });
            tx
        });
        self.jobs.fetch_add(1, Ordering::SeqCst);
        if queue.try_send(Box::pin(job)).is_err() {
            self.jobs.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!("mail job queue full; dropped a background job");
        }
    }

    /// Wait until no job and no delivery is queued or under way.
    #[cfg(test)]
    pub async fn idle(&self) {
        while self.jobs.load(Ordering::SeqCst) + self.deliveries.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Send now and report how it went; `done` is called after every step that worked.
    pub async fn send_now(&self, to: &str, mail: Mail, done: &mut (dyn FnMut(Step) + Send)) -> Result<(), SendError> {
        let bad = |what: String| SendError::new(Step::Recipient, what);
        let sender = self.smtp.sender().map_err(|e| SendError::new(Step::Sender, e))?;
        let recipient: lettre::message::Mailbox =
            to.parse().map_err(|_| bad(format!("{to:?} is not an email address")))?;
        let message = lettre::Message::builder()
            .from(sender.clone())
            .to(recipient.clone())
            .subject(mail.subject)
            .message_id(Some(format!("<{}@{}>", crate::tokens::random_tunnel_id(), self.ui_host)))
            .header(AutoSubmitted)
            // A single part (not `.body`): it adds `MIME-Version`, needed with the transfer encoding.
            .singlepart(lettre::message::SinglePart::plain(mail.body))
            .map_err(|e| bad(e.to_string()))?;
        #[cfg(test)]
        let all: Vec<_> = transport::PUBLIC_ROOTS.iter().cloned().chain(self.roots.iter().cloned()).collect();
        #[cfg(test)]
        let roots: &[_] = &all;
        #[cfg(not(test))]
        let roots: &[_] = &transport::PUBLIC_ROOTS;
        let target = transport::Target {
            host: &self.smtp.host,
            port: self.smtp.port,
            security: self.smtp.security(),
            credentials: self.smtp.user.as_deref().zip(self.smtp.pass.as_deref()),
            hello: &self.ui_host,
            roots,
        };
        transport::deliver(&target, &sender.email, &recipient.email, &message.formatted(), done).await
    }
}

/// `Auto-Submitted: auto-generated` (RFC 3834): no out-of-office replies.
#[derive(Clone)]
struct AutoSubmitted;

impl lettre::message::header::Header for AutoSubmitted {
    fn name() -> lettre::message::header::HeaderName {
        lettre::message::header::HeaderName::new_from_ascii_str("Auto-Submitted")
    }
    fn parse(_: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self)
    }
    fn display(&self) -> lettre::message::header::HeaderValue {
        lettre::message::header::HeaderValue::new(Self::name(), "auto-generated".into())
    }
}

#[cfg(test)]
pub mod fake;
#[cfg(test)]
mod tests;
