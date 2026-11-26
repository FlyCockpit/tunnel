//! Row-bound encryption of password PHC strings and recovery-code hashes
//! with keys derived from the server secret.
//!
//! Passwords: `pw1:<key id>:<b64url(nonce || AES-256-GCM(K_pw, PHC) || tag)>`,
//! AAD `password-v1|user|<user id>` or `password-v1|tunnel|<tunnel id>`.
//!
//! Recovery codes: `rc1:<key id>:<b64url(nonce || AES-256-GCM(K_rc, H) || tag)>`
//! with `H = hex(SHA-256(normalized code))` (64 lowercase hex characters, the
//! value older versions stored as is) and AAD `recovery-v1|<user id>`. Legacy
//! rows therefore convert without the codes (seal the stored `H`), and a
//! rotation re-seals them like passwords. A sign-in computes `H` from the
//! typed code, opens each of the user's unused rows and compares in constant
//! time.
//!
//! `K_pw = HKDF-SHA256(ui_secret, "tunnel password pepper v1")`,
//! `K_rc = HKDF-SHA256(ui_secret, "tunnel recovery codes v1")`, and the public
//! key id is the first 8 bytes (hex) of
//! `HKDF-SHA256(ui_secret, "tunnel password pepper id v1")`; both kinds of
//! value carry that one id, which names the `ui_secret` they were sealed with.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use rand::rngs::SysRng;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;

#[derive(Clone, Copy, Debug)]
pub enum Purpose {
    User,
    Tunnel,
    /// A recovery code's SHA-256 hex; the row id is the user id.
    Recovery,
}

impl Purpose {
    fn aad(self, row_id: &str) -> String {
        match self {
            Self::User => format!("password-v1|user|{row_id}"),
            Self::Tunnel => format!("password-v1|tunnel|{row_id}"),
            Self::Recovery => format!("recovery-v1|{row_id}"),
        }
    }

    pub fn prefix(self) -> &'static str {
        match self {
            Self::User | Self::Tunnel => "pw1:",
            Self::Recovery => "rc1:",
        }
    }
}

#[derive(Clone)]
pub struct Pepper {
    key: Arc<LessSafeKey>,
    recovery: Arc<LessSafeKey>,
    id: String,
}

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pepper").field("id", &self.id).finish_non_exhaustive()
    }
}

fn derive(secret: &str, info: &[u8]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(secret.as_bytes());
    let info = [info];
    let mut out = [0; 32];
    prk.expand(&info, hkdf::HKDF_SHA256).expect("valid HKDF length").fill(&mut out).expect("32-byte output");
    out
}

impl Pepper {
    pub fn new(ui_secret: &str) -> Self {
        let key = derive(ui_secret, b"tunnel password pepper v1");
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).expect("32-byte AES key"));
        let recovery = derive(ui_secret, b"tunnel recovery codes v1");
        let recovery = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &recovery).expect("32-byte AES key"));
        let id = derive(ui_secret, b"tunnel password pepper id v1");
        let id = id[..8].iter().map(|b| format!("{b:02x}")).collect();
        Self { key: Arc::new(key), recovery: Arc::new(recovery), id }
    }

    fn key(&self, purpose: Purpose) -> &LessSafeKey {
        match purpose {
            Purpose::User | Purpose::Tunnel => &self.key,
            Purpose::Recovery => &self.recovery,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn wrap(&self, phc: &str, purpose: Purpose, row_id: &str) -> String {
        let mut nonce = [0; NONCE_LEN];
        SysRng.try_fill_bytes(&mut nonce).expect("OS random source failed");
        let mut buf = phc.as_bytes().to_vec();
        self.key(purpose)
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(purpose.aad(row_id).as_bytes()),
                &mut buf,
            )
            .expect("AES-GCM sealing cannot fail for small inputs");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        format!("{}{}:{}", purpose.prefix(), self.id, URL_SAFE_NO_PAD.encode(out))
    }

    pub fn unwrap(&self, stored: &str, purpose: Purpose, row_id: &str) -> Option<String> {
        let (id, sealed) = stored.strip_prefix(purpose.prefix())?.split_once(':')?;
        if id != self.id {
            return None;
        }
        let raw = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if raw.len() < NONCE_LEN {
            return None;
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = rest.to_vec();
        let plain = self.key(purpose).open_in_place(nonce, Aad::from(purpose.aad(row_id).as_bytes()), &mut buf).ok()?;
        String::from_utf8(plain.to_vec()).ok()
    }
}

#[derive(Clone, Debug)]
pub struct PepperSet {
    pub current: Pepper,
    pub previous: Option<Pepper>,
}

impl PepperSet {
    pub fn new(current: &str, previous: Option<&str>) -> Self {
        Self { current: Pepper::new(current), previous: previous.map(Pepper::new) }
    }

    pub fn unwrap(&self, stored: &str, purpose: Purpose, row_id: &str) -> Option<String> {
        let id = stored.strip_prefix(purpose.prefix())?.split_once(':')?.0;
        let key =
            if id == self.current.id() { &self.current } else { self.previous.as_ref().filter(|p| p.id() == id)? };
        key.unwrap(stored, purpose, row_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_are_bound_to_key_purpose_and_row() {
        let key = Pepper::new("public test fixture one");
        let other = Pepper::new("public test fixture two");
        let phc = crate::password::DUMMY_PHC;
        let stored = key.wrap(phc, Purpose::User, "u1");
        assert_eq!(key.id().len(), 16);
        assert!(key.id().bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(key.id(), Pepper::new("public test fixture one").id());
        assert_eq!(key.unwrap(&stored, Purpose::User, "u1").as_deref(), Some(phc));
        assert_eq!(key.unwrap(&stored, Purpose::User, "u2"), None);
        assert_eq!(key.unwrap(&stored, Purpose::Tunnel, "u1"), None);
        assert_eq!(other.unwrap(&stored, Purpose::User, "u1"), None);
        assert_ne!(stored, key.wrap(phc, Purpose::User, "u1"));
        assert_eq!(key.unwrap(&stored.replace(key.id(), other.id()), Purpose::User, "u1"), None);
        let mut raw = URL_SAFE_NO_PAD.decode(stored.rsplit(':').next().unwrap()).unwrap();
        raw[NONCE_LEN] ^= 1;
        let tampered = format!("pw1:{}:{}", key.id(), URL_SAFE_NO_PAD.encode(raw));
        assert_eq!(key.unwrap(&tampered, Purpose::User, "u1"), None);
        for bad in [phc, "garbage", &format!("pw1:{}:!", key.id()), &format!("pw1:{}:AA", key.id())] {
            assert_eq!(key.unwrap(bad, Purpose::User, "u1"), None);
        }
        assert_eq!(format!("{key:?}"), format!("Pepper {{ id: {:?}, .. }}", key.id()));
        let set = PepperSet { current: other.clone(), previous: Some(key.clone()) };
        assert_eq!(set.unwrap(&stored, Purpose::User, "u1").as_deref(), Some(phc));

        let hash = crate::tokens::hash_token("abcde23456");
        let code = key.wrap(&hash, Purpose::Recovery, "u1");
        assert!(code.starts_with(&format!("rc1:{}:", key.id())));
        assert_eq!(key.unwrap(&code, Purpose::Recovery, "u1").as_deref(), Some(hash.as_str()));
        assert_eq!(key.unwrap(&code, Purpose::Recovery, "u2"), None);
        assert_eq!(other.unwrap(&code, Purpose::Recovery, "u1"), None);
        // A distinct key and AAD: a password seal never opens as a code and back.
        assert_eq!(key.unwrap(&code.replacen("rc1:", "pw1:", 1), Purpose::User, "u1"), None);
        assert_eq!(key.unwrap(&stored.replacen("pw1:", "rc1:", 1), Purpose::Recovery, "u1"), None);
        assert_eq!(set.unwrap(&code, Purpose::Recovery, "u1").as_deref(), Some(hash.as_str()));
    }
}
