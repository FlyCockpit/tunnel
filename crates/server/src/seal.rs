//! Keys derived from the server's `ui_secret`: AES-256-GCM sealing of TOTP
//! secrets at rest (a database copy alone does not reveal them) and the
//! per-session CSRF token.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::TryRng;
use rand::rngs::SysRng;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use sha2::Sha256;

pub fn totp_aad(user_id: &str) -> String {
    format!("totp:{user_id}")
}

pub struct Keys {
    seal: LessSafeKey,
    csrf: [u8; 32],
}

fn derive(secret: &str, purpose: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(purpose.as_bytes());
    mac.finalize().into_bytes().into()
}

impl Keys {
    pub fn new(ui_secret: &str) -> Self {
        let seal = derive(ui_secret, "tunnel-ui seal v1");
        let seal = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &seal).expect("32-byte AES key"));
        Self { seal, csrf: derive(ui_secret, "tunnel-ui csrf v1") }
    }

    /// `base64url(nonce || ciphertext || tag)`; `aad` binds it to its row.
    pub fn seal(&self, plain: &[u8], aad: &str) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        SysRng.try_fill_bytes(&mut nonce).expect("OS random source failed");
        let mut buf = plain.to_vec();
        self.seal
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad.as_bytes()), &mut buf)
            .expect("AES-GCM sealing cannot fail for small inputs");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        URL_SAFE_NO_PAD.encode(out)
    }

    pub fn open(&self, sealed: &str, aad: &str) -> Option<Vec<u8>> {
        let raw = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if raw.len() < NONCE_LEN {
            return None;
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = rest.to_vec();
        let plain = self.seal.open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf).ok()?;
        Some(plain.to_vec())
    }

    /// CSRF token for a UI session: an HMAC of its id, so nothing extra is
    /// stored and it changes whenever the session id rotates.
    pub fn csrf_token(&self, session_id: &str) -> String {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.csrf).expect("HMAC accepts any key length");
        mac.update(session_id.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip_is_bound_to_key_and_aad() {
        let keys = Keys::new("test-secret-one");
        let sealed = keys.seal(b"JBSWY3DPEHPK3PXP", "user:u1");
        assert_eq!(keys.open(&sealed, "user:u1").as_deref(), Some(&b"JBSWY3DPEHPK3PXP"[..]));
        assert_eq!(keys.open(&sealed, "user:u2"), None);
        assert_eq!(Keys::new("test-secret-two").open(&sealed, "user:u1"), None);
        assert_ne!(sealed, keys.seal(b"JBSWY3DPEHPK3PXP", "user:u1"), "fresh nonce each time");
        assert_eq!(keys.open("garbage", "user:u1"), None);
    }

    #[test]
    fn csrf_depends_on_session_and_secret() {
        let a = Keys::new("s1");
        assert_eq!(a.csrf_token("sess"), a.csrf_token("sess"));
        assert_ne!(a.csrf_token("sess"), a.csrf_token("sess2"));
        assert_ne!(a.csrf_token("sess"), Keys::new("s2").csrf_token("sess"));
    }
}
