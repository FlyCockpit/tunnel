//! Let's Encrypt DNS-01 issuance for the single certificate, and the renewal task.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use futures_util::future::BoxFuture;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderStatus,
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::config::dns::{self, RecordRef};
use crate::state::AppState;
use crate::tls::{self, CertStatus};

const TXT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(300);
const ORDER_TIMEOUT: Duration = Duration::from_secs(300);
const ISSUANCE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(120);
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);

/// `acme-account.json`: the credentials plus the directory they belong to, so
/// toggling `acme.staging` doesn't reuse an account from the other directory.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    directory: String,
    credentials: AccountCredentials,
}

/// Run a full DNS-01 order for `cfg.cert_names()` and write the result to
/// `cfg.cert_dir()`. Challenge TXT cleanup is attempted afterwards, including on timeout.
pub async fn issue(cfg: &Config) -> anyhow::Result<()> {
    anyhow::ensure!(
        !cfg.acme.own_certificate,
        "this server uses its own certificate (acme.own_certificate): replace fullchain.pem and privkey.pem in {}",
        cfg.cert_dir().display()
    );
    // Every name must be in a configured zone before anything is ordered.
    for name in cfg.cert_names() {
        dns::Provider::for_host(cfg, &name)?;
    }
    issue_with_cleanup(
        cfg,
        |cfg, created| Box::pin(run_order(cfg, created)),
        // A challenge record lives in the zone of the name it is for.
        |cfg, rec| Box::pin(async move { dns::Provider::for_host(cfg, &rec.name)?.delete(rec).await }),
    )
    .await
}

async fn issue_with_cleanup<C>(
    context: &C,
    run: impl for<'a> FnOnce(&'a C, &'a mut Vec<RecordRef>) -> BoxFuture<'a, anyhow::Result<()>>,
    delete: impl for<'a> Fn(&'a C, &'a RecordRef) -> BoxFuture<'a, anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let mut created = Vec::new();
    // Bound every network await, including account loading and order creation.
    // Keep cleanup outside this timeout so cancellation still removes known TXT records.
    let result = tokio::time::timeout(ISSUANCE_TIMEOUT, run(context, &mut created))
        .await
        .context("ACME issuance timed out")
        .and_then(|result| result);
    for rec in &created {
        let cleanup = tokio::time::timeout(CLEANUP_TIMEOUT, delete(context, rec))
            .await
            .context("ACME challenge cleanup timed out")
            .and_then(|result| result);
        if let Err(e) = cleanup {
            tracing::warn!(error = %format!("{e:#}"), name = %rec.name, "failed to remove ACME challenge record");
        }
    }
    result
}

async fn run_order(cfg: &Config, created: &mut Vec<RecordRef>) -> anyhow::Result<()> {
    let names = cfg.cert_names();
    let account = load_or_create_account(cfg).await?;

    let identifiers: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await.context("creating ACME order")?;
    tracing::info!(names = ?names, "ACME order created");

    let pending = {
        let mut authorizations = order.authorizations();
        let mut pending = Vec::new();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.context("fetching ACME authorizations")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                // Already validated recently (e.g. a retried order); nothing to do.
                AuthorizationStatus::Valid => continue,
                ref other => bail!("ACME authorization for {:?} is {other:?}", authz.identifier()),
            }
            #[allow(unreachable_patterns)]
            let domain = match authz.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                other => bail!("unsupported ACME identifier {other:?}"),
            };
            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .with_context(|| format!("no dns-01 challenge offered for {domain}"))?;
            // Wildcard authorizations already carry the base name; strip defensively.
            let txt_name = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
            let value = challenge.key_authorization().dns_value();
            // Create, never replace: two authorizations could share a TXT name.
            let rec = dns::Provider::for_host(cfg, &txt_name)?.create_txt(&txt_name, &value).await?;
            created.push(rec);
            pending.push((txt_name, value));
        }

        pending
    };

    // Public resolvers are only a propagation hint; Let's Encrypt queries the
    // authoritative servers itself, so a slow resolver should not fail issuance.
    let waits = pending.iter().map(|(name, value)| dns::wait_for_txt(name, value, TXT_PROPAGATION_TIMEOUT));
    for (res, (name, _)) in futures_util::future::join_all(waits).await.into_iter().zip(&pending) {
        if let Err(e) = res {
            tracing::warn!(error = %format!("{e:#}"), %name, "continuing without public-resolver confirmation");
        }
    }

    {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.context("fetching ACME authorizations")?;
            if authz.status == AuthorizationStatus::Pending {
                authz
                    .challenge(ChallengeType::Dns01)
                    .context("no dns-01 challenge offered")?
                    .set_ready()
                    .await
                    .context("marking ACME challenge ready")?;
            }
        }
    }

    wait_until_ready(&mut order).await?;

    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(names.clone())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key)?;
    let csr_der: &[u8] = csr.der();
    order.finalize_csr(csr_der).await.context("finalizing ACME order")?;

    let chain = wait_for_certificate(&mut order).await?;
    tls::write_cert_files(&cfg.cert_dir(), &chain, &key.serialize_pem(), &names)?;
    tracing::info!(names = ?names, "certificate issued");
    Ok(())
}

async fn load_or_create_account(cfg: &Config) -> anyhow::Result<Account> {
    let directory = if cfg.acme.staging { LetsEncrypt::Staging.url() } else { LetsEncrypt::Production.url() };
    let path = cfg.acme_account_path();

    if let Ok(raw) = std::fs::read(&path) {
        match serde_json::from_slice::<StoredAccount>(&raw) {
            Ok(stored) if stored.directory == directory => {
                return Account::builder()?.from_credentials(stored.credentials).await.context("loading ACME account");
            }
            Ok(_) => tracing::info!("ACME directory changed; registering a new account"),
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "unreadable ACME account file; registering a new account")
            }
        }
    }

    let contact = format!("mailto:{}", cfg.acme.email);
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount { contact: &[contact.as_str()], terms_of_service_agreed: true, only_return_existing: false },
            directory.to_string(),
            None,
        )
        .await
        .context("registering ACME account")?;

    let stored = StoredAccount { directory: directory.to_string(), credentials };
    crate::files::write_atomic(&path, &serde_json::to_vec(&stored)?, 0o600)?;
    Ok(account)
}

/// Exponential backoff 1s → 15s, bounded by `ORDER_TIMEOUT`.
struct Backoff {
    delay: Duration,
    deadline: tokio::time::Instant,
}

impl Backoff {
    fn new() -> Self {
        Self { delay: Duration::from_secs(1), deadline: tokio::time::Instant::now() + ORDER_TIMEOUT }
    }

    async fn wait(&mut self, what: &str) -> anyhow::Result<()> {
        if tokio::time::Instant::now() + self.delay > self.deadline {
            bail!("timed out waiting for {what}");
        }
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(Duration::from_secs(15));
        Ok(())
    }
}

async fn wait_until_ready(order: &mut Order) -> anyhow::Result<()> {
    let mut backoff = Backoff::new();
    loop {
        let status = &order.refresh().await.context("polling ACME order")?.status;
        // Valid before finalize cannot happen for a fresh order; let finalize report it.
        if matches!(status, OrderStatus::Ready | OrderStatus::Valid) {
            return Ok(());
        }
        if matches!(status, OrderStatus::Invalid) {
            bail!("ACME order invalid: {}", challenge_errors(order).await);
        }
        backoff.wait("ACME challenge validation").await?;
    }
}

async fn wait_for_certificate(order: &mut Order) -> anyhow::Result<String> {
    let mut backoff = Backoff::new();
    loop {
        // certificate() refreshes the order while it is Processing.
        if let Some(chain) = order.certificate().await.context("downloading certificate")? {
            return Ok(chain);
        }
        if order.state().status == OrderStatus::Invalid {
            bail!("ACME order became invalid after finalize");
        }
        backoff.wait("certificate issuance").await?;
    }
}

/// Best-effort summary of why an order failed, for the log.
async fn challenge_errors(order: &mut Order) -> String {
    let mut authorizations = order.authorizations();
    let mut out = Vec::new();
    while let Some(authz) = authorizations.next().await {
        let authz = match authz {
            Ok(authz) => authz,
            Err(e) => return format!("(could not fetch authorizations: {e})"),
        };
        for ch in &authz.challenges {
            if let Some(err) = &ch.error {
                out.push(format!(
                    "{:?}: {}",
                    authz.identifier(),
                    err.detail.as_deref().or(err.r#type.as_deref()).unwrap_or("unknown error")
                ));
            }
        }
    }
    if out.is_empty() { "no challenge error reported".to_string() } else { out.join("; ") }
}

/// Background renewal: first check shortly after start, then every 12 hours
/// (hourly while failing). Issuance writes the files; reloading here (and the
/// 60s watcher) swaps the cert in. The TURN relay uses the same store.
pub async fn renew_loop(state: Arc<AppState>) {
    tokio::time::sleep(FIRST_CHECK_DELAY).await;
    loop {
        let next = match renew_if_needed(&state).await {
            Ok(()) => CHECK_INTERVAL,
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "certificate renewal failed; retrying in 1h");
                RETRY_AFTER_FAILURE
            }
        };
        tokio::time::sleep(next).await;
    }
}

async fn renew_if_needed(state: &AppState) -> anyhow::Result<()> {
    let status = tls::cert_status(&state.config);
    if let CertStatus::Valid { .. } = status {
        return Ok(());
    }
    if state.config.acme.own_certificate {
        // Not ours to renew; say so while there is time to act.
        tracing::warn!(?status, dir = %state.config.cert_dir().display(), "own certificate needs replacing");
        return Ok(());
    }
    tracing::info!(?status, "certificate needs (re)issuance");
    issue(&state.config).await?;
    if state.certs.reload()? {
        tracing::info!(not_after = state.certs.not_after(), "renewed certificate loaded");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn challenge(name: &str) -> RecordRef {
        RecordRef { name: name.into(), rtype: "TXT".into(), value: "test".into(), id: None }
    }

    #[tokio::test(start_paused = true)]
    async fn issuance_timeout_still_cleans_up() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Cancelled<'a>(&'a AtomicBool);
        impl Drop for Cancelled<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let context = (AtomicBool::new(false), AtomicBool::new(false));
        let started = tokio::time::Instant::now();
        let result = issue_with_cleanup(
            &context,
            |(cancelled, _), created| {
                Box::pin(async move {
                    created.push(challenge("_acme-challenge.example.com"));
                    let _cancelled = Cancelled(cancelled);
                    std::future::pending().await
                })
            },
            |(cancelled, cleaned), rec| {
                Box::pin(async move {
                    assert!(cancelled.load(Ordering::Relaxed), "order must be cancelled before cleanup");
                    assert_eq!(rec.name, "_acme-challenge.example.com");
                    cleaned.store(true, Ordering::Relaxed);
                    Ok(())
                })
            },
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("ACME issuance timed out"));
        assert!(context.1.load(Ordering::Relaxed));
        assert_eq!(started.elapsed(), ISSUANCE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_timeout_and_errors_do_not_skip_remaining_records() {
        use std::sync::Mutex;
        let attempted = Mutex::new(Vec::new());
        let started = tokio::time::Instant::now();
        let result = issue_with_cleanup(
            &attempted,
            |_, created| {
                Box::pin(async move {
                    created.extend([challenge("stalled"), challenge("failed"), challenge("ok")]);
                    bail!("issuance failed");
                })
            },
            |attempted, rec| {
                Box::pin(async move {
                    attempted.lock().unwrap().push(rec.name.clone());
                    match rec.name.as_str() {
                        "stalled" => std::future::pending().await,
                        "failed" => bail!("cleanup failed"),
                        _ => Ok(()),
                    }
                })
            },
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "issuance failed");
        assert_eq!(*attempted.lock().unwrap(), ["stalled", "failed", "ok"]);
        assert_eq!(started.elapsed(), CLEANUP_TIMEOUT);
    }

    #[test]
    fn account_credentials_round_trip() {
        let key = rcgen::KeyPair::generate().unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.serialize_der());
        let directory = LetsEncrypt::Staging.url();
        let stored_json = serde_json::json!({
            "directory": directory,
            "credentials": {
                "id": "https://acme.example.com/acct/1",
                "key_pkcs8": encoded,
                "directory": directory
            }
        });
        let stored: StoredAccount = serde_json::from_value(stored_json.clone()).unwrap();
        assert_eq!(stored.directory, directory);
        assert!(stored.credentials.private_key().secret_pkcs8_der() == key.serialize_der());
        assert!(serde_json::to_value(stored).unwrap() == stored_json);
    }
}
