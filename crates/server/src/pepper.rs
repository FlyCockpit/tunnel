//! Row-bound encryption of password PHC strings with a server-derived key.

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
}

impl Purpose {
    fn aad(self, row_id: &str) -> String {
        let purpose = match self {
            Self::User => "user",
            Self::Tunnel => "tunnel",
        };
        format!("password-v1|{purpose}|{row_id}")
    }
}

#[derive(Clone)]
pub struct Pepper {
    key: Arc<LessSafeKey>,
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
        let id = derive(ui_secret, b"tunnel password pepper id v1");
        let id = id[..8].iter().map(|b| format!("{b:02x}")).collect();
        Self { key: Arc::new(key), id }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn wrap(&self, phc: &str, purpose: Purpose, row_id: &str) -> String {
        let mut nonce = [0; NONCE_LEN];
        SysRng.try_fill_bytes(&mut nonce).expect("OS random source failed");
        let mut buf = phc.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(purpose.aad(row_id).as_bytes()),
                &mut buf,
            )
            .expect("AES-GCM sealing cannot fail for small inputs");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        format!("pw1:{}:{}", self.id, URL_SAFE_NO_PAD.encode(out))
    }

    pub fn unwrap(&self, stored: &str, purpose: Purpose, row_id: &str) -> Option<String> {
        let (id, sealed) = stored.strip_prefix("pw1:")?.split_once(':')?;
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
        let plain = self.key.open_in_place(nonce, Aad::from(purpose.aad(row_id).as_bytes()), &mut buf).ok()?;
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
        let id = stored.strip_prefix("pw1:")?.split_once(':')?.0;
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
        let set = PepperSet { current: other, previous: Some(key) };
        assert_eq!(set.unwrap(&stored, Purpose::User, "u1").as_deref(), Some(phc));
    }
}
