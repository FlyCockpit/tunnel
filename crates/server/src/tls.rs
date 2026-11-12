use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config::Config;

const FULLCHAIN: &str = "fullchain.pem";
const PRIVKEY: &str = "privkey.pem";
const NAMES: &str = "names.json";
const WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// The single DNS-01 certificate, swapped atomically when the files on disk
/// change so renewal never needs a restart.
pub struct CertStore {
    cert_dir: PathBuf,
    current: RwLock<Option<Arc<CertifiedKey>>>,
    /// mtime of `fullchain.pem` at the last successful load. It is written
    /// after the key; their consistency is checked before swapping them in.
    loaded_mtime: Mutex<Option<SystemTime>>,
    /// Unix seconds; 0 = nothing loaded.
    not_after: AtomicI64,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("cert_dir", &self.cert_dir)
            .field("not_after", &self.not_after())
            .finish_non_exhaustive()
    }
}

impl CertStore {
    pub fn new(cert_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            cert_dir,
            current: RwLock::new(None),
            loaded_mtime: Mutex::new(None),
            not_after: AtomicI64::new(0),
        })
    }

    /// Load `fullchain.pem` + `privkey.pem` if `fullchain.pem` changed since the
    /// last load. Returns `Ok(true)` when a new certificate was swapped in.
    pub fn reload(&self) -> anyhow::Result<bool> {
        let chain_path = self.cert_dir.join(FULLCHAIN);
        let mtime = std::fs::metadata(&chain_path)
            .and_then(|m| m.modified())
            .with_context(|| format!("stat {}", chain_path.display()))?;
        if self.is_loaded() && *self.loaded_mtime.lock().expect("mtime lock") == Some(mtime) {
            return Ok(false);
        }

        let loaded = load_files(&self.cert_dir)?;
        *self.current.write().expect("cert lock") = Some(Arc::new(loaded.certified));
        *self.loaded_mtime.lock().expect("mtime lock") = Some(mtime);
        self.not_after.store(loaded.not_after, Ordering::Relaxed);
        Ok(true)
    }

    pub fn not_after(&self) -> Option<i64> {
        match self.not_after.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.current.read().map(|c| c.is_some()).unwrap_or(false)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // One cert covers every name we serve; routing is by Host, not SNI.
        self.current.read().ok().and_then(|c| c.clone())
    }
}

pub fn server_config(store: Arc<CertStore>) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(store);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

/// For TURN over TLS: the same certificate, no ALPN.
pub fn turn_server_config(store: Arc<CertStore>) -> rustls::ServerConfig {
    rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(store)
}

/// Pick up renewals written by the renewal task or `cert renew` (another process).
pub async fn watch(store: Arc<CertStore>) {
    loop {
        tokio::time::sleep(WATCH_INTERVAL).await;
        match store.reload() {
            Ok(true) => tracing::info!(not_after = store.not_after(), "certificate reloaded"),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "certificate reload failed"),
        }
    }
}

/// Write a freshly issued certificate. Key first, then chain (the store keys
/// reloads on the chain's mtime), then the name list used by `cert_status`.
/// Files are group-readable by the service group.
pub fn write_cert_files(cert_dir: &Path, fullchain_pem: &str, key_pem: &str, names: &[String]) -> anyhow::Result<()> {
    std::fs::create_dir_all(cert_dir).with_context(|| format!("creating {}", cert_dir.display()))?;
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::util::O_DIRECTORY | crate::util::O_NOFOLLOW | crate::util::O_CLOEXEC)
        .open(cert_dir)
        .with_context(|| format!("opening certificate directory {} without following symlinks", cert_dir.display()))?;
    dir.set_permissions(std::fs::Permissions::from_mode(0o750))?;
    crate::util::write_atomic_in_dir(&dir, PRIVKEY, key_pem.as_bytes(), 0o640)?;
    crate::util::write_atomic_in_dir(&dir, FULLCHAIN, fullchain_pem.as_bytes(), 0o640)?;
    let names_json = serde_json::to_vec_pretty(names)?;
    crate::util::write_atomic_in_dir(&dir, NAMES, &names_json, 0o640)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Missing,
    NamesChanged,
    NeedsRenewal,
    Valid { not_after: i64 },
}

/// Whether the certificate on disk is usable for `cfg` as-is.
///
/// Renews once a third of the lifetime remains, derived from the cert itself
/// (no hardcoded 90 days). ARI is not used.
pub fn cert_status(cfg: &Config) -> CertStatus {
    let dir = cfg.cert_dir();
    let loaded = match load_files(&dir) {
        Ok(l) => l,
        Err(_) => return CertStatus::Missing,
    };
    let on_disk: Option<Vec<String>> =
        std::fs::read(dir.join(NAMES)).ok().and_then(|raw| serde_json::from_slice(&raw).ok());
    let mut on_disk = match on_disk {
        Some(n) => n,
        None => return CertStatus::NamesChanged,
    };
    on_disk.sort();
    on_disk.dedup();
    if on_disk != cfg.cert_names() {
        return CertStatus::NamesChanged;
    }

    let lifetime = (loaded.not_after - loaded.not_before).max(0);
    let remaining = loaded.not_after - crate::tokens::now();
    if remaining < lifetime / 3 { CertStatus::NeedsRenewal } else { CertStatus::Valid { not_after: loaded.not_after } }
}

struct LoadedFiles {
    certified: CertifiedKey,
    not_before: i64,
    not_after: i64,
}

fn load_files(dir: &Path) -> anyhow::Result<LoadedFiles> {
    let chain_path = dir.join(FULLCHAIN);
    let key_path = dir.join(PRIVKEY);

    let chain_pem = std::fs::read(&chain_path).with_context(|| format!("reading {}", chain_path.display()))?;
    let chain = CertificateDer::pem_slice_iter(&chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", chain_path.display()))?;
    anyhow::ensure!(!chain.is_empty(), "{} contains no certificates", chain_path.display());

    let key_pem = std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| match e {
        pem::Error::NoItemsFound => anyhow::anyhow!("{} contains no private key", key_path.display()),
        e => anyhow::Error::new(e).context(format!("parsing {}", key_path.display())),
    })?;

    let (_, leaf) = x509_parser::parse_x509_certificate(&chain[0])
        .map_err(|e| anyhow::anyhow!("parsing leaf certificate in {}: {e}", chain_path.display()))?;
    let validity = leaf.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();

    let key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported private key in {}: {e}", dir.display()))?;
    let certified = CertifiedKey::new(chain, key);
    match certified.keys_match() {
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
        Err(e) => return Err(e).context("certificate and private key are inconsistent"),
    }

    Ok(LoadedFiles { certified, not_before, not_after })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("tunnel-tls-{}-{}", std::process::id(), rand::random::<u64>()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn mismatched_key_is_missing_and_reload_keeps_current_certificate() {
        let dir = TestDir::new();
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "preview_zone": "localhost",
            "api_host": "localhost",
            "tunnel_host": "localhost",
            "turn_host": "localhost",
            "admin_token_hash": "public-test-placeholder",
            "data_dir": dir.0,
            "acme": { "email": "admin@example.com" },
            "dns": { "provider": "cloudflare", "zone": "example.com" }
        }))
        .unwrap();
        let cert_dir = cfg.cert_dir();
        let first = rcgen::generate_simple_self_signed(cfg.cert_names()).unwrap();
        let second = rcgen::generate_simple_self_signed(cfg.cert_names()).unwrap();
        write_cert_files(&cert_dir, &first.cert.pem(), &first.signing_key.serialize_pem(), &cfg.cert_names()).unwrap();
        assert!(matches!(cert_status(&cfg), CertStatus::Valid { .. }));
        let store = CertStore::new(cert_dir.clone());
        assert!(store.reload().unwrap());
        let previous = store.current.read().unwrap().as_ref().unwrap().clone();
        let previous_expiry = store.not_after();
        let previous_mtime = store.loaded_mtime.lock().unwrap().unwrap();

        write_cert_files(&cert_dir, &first.cert.pem(), &second.signing_key.serialize_pem(), &cfg.cert_names()).unwrap();
        // Force a distinct mtime even on coarse-resolution filesystems.
        std::fs::File::open(cert_dir.join(FULLCHAIN))
            .unwrap()
            .set_modified(previous_mtime + Duration::from_secs(1))
            .unwrap();
        let err = load_files(&cert_dir).err().expect("mismatched key must fail");
        assert!(matches!(
            err.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch))
        ));
        assert_eq!(cert_status(&cfg), CertStatus::Missing);
        assert!(store.reload().is_err());
        assert!(Arc::ptr_eq(store.current.read().unwrap().as_ref().unwrap(), &previous));
        assert_eq!(store.not_after(), previous_expiry);
        assert_eq!(*store.loaded_mtime.lock().unwrap(), Some(previous_mtime));
        let cold = CertStore::new(cert_dir.clone());
        assert!(cold.reload().is_err());
        assert!(!cold.is_loaded());

        write_cert_files(&cert_dir, &second.cert.pem(), &second.signing_key.serialize_pem(), &cfg.cert_names())
            .unwrap();
        std::fs::File::open(cert_dir.join(FULLCHAIN))
            .unwrap()
            .set_modified(previous_mtime + Duration::from_secs(2))
            .unwrap();
        assert!(store.reload().unwrap());
        assert!(!Arc::ptr_eq(store.current.read().unwrap().as_ref().unwrap(), &previous));
        assert!(matches!(cert_status(&cfg), CertStatus::Valid { .. }));
    }

    #[test]
    fn write_cert_files_refuses_symlinked_directory() {
        let dir = TestDir::new();
        let target = dir.0.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in [PRIVKEY, FULLCHAIN, NAMES] {
            std::fs::write(target.join(name), b"untouched").unwrap();
        }
        let link = dir.0.join("certs");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_cert_files(&link, "new chain", "new key", &["localhost".into()]).is_err());
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o700);
        for name in [PRIVKEY, FULLCHAIN, NAMES] {
            assert_eq!(std::fs::read(target.join(name)).unwrap(), b"untouched");
        }
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 3);
    }

    #[test]
    fn write_cert_files_writes_contents_and_modes() {
        let dir = TestDir::new();
        let cert_dir = dir.0.join("certs");
        let names = vec!["localhost".into()];
        write_cert_files(&cert_dir, "chain", "key", &names).unwrap();
        assert_eq!(std::fs::read(cert_dir.join(PRIVKEY)).unwrap(), b"key");
        assert_eq!(std::fs::read(cert_dir.join(FULLCHAIN)).unwrap(), b"chain");
        let loaded_names: Vec<String> = serde_json::from_slice(&std::fs::read(cert_dir.join(NAMES)).unwrap()).unwrap();
        assert_eq!(loaded_names, names);
        assert_eq!(std::fs::metadata(&cert_dir).unwrap().permissions().mode() & 0o777, 0o750);
        for name in [PRIVKEY, FULLCHAIN, NAMES] {
            assert_eq!(std::fs::metadata(cert_dir.join(name)).unwrap().permissions().mode() & 0o777, 0o640);
        }
        assert_eq!(std::fs::read_dir(&cert_dir).unwrap().count(), 3);
    }

    #[test]
    fn loads_generated_pem_and_preserves_errors() {
        let dir = std::env::temp_dir().join("tunnel-test-tls").join(format!(
            "{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = generated.cert.pem();
        std::fs::write(dir.join(FULLCHAIN), &cert_pem).unwrap();
        std::fs::write(dir.join(PRIVKEY), generated.signing_key.serialize_pem()).unwrap();
        let loaded = load_files(&dir).unwrap();
        assert_eq!(loaded.certified.cert, vec![generated.cert.der().clone()]);
        assert!(loaded.not_after > loaded.not_before);
        loaded.certified.keys_match().unwrap();

        // A PEM certificate in the key file is not a private key.
        std::fs::write(dir.join(PRIVKEY), &cert_pem).unwrap();
        let err = load_files(&dir).err().expect("certificate is not a key");
        assert_eq!(err.to_string(), format!("{} contains no private key", dir.join(PRIVKEY).display()));
        std::fs::remove_file(dir.join(PRIVKEY)).unwrap();
        let err = load_files(&dir).err().expect("missing key file");
        assert_eq!(err.to_string(), format!("reading {}", dir.join(PRIVKEY).display()));
        std::fs::write(dir.join(FULLCHAIN), "").unwrap();
        let err = load_files(&dir).err().expect("missing certificate");
        assert_eq!(err.to_string(), format!("{} contains no certificates", dir.join(FULLCHAIN).display()));
    }
}
