use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const ID_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
pub const TUNNEL_ID_LEN: usize = 10;

/// `<prefix><43 chars base64url>` (256 bits).
pub fn random_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).expect("OS random source failed");
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Opaque random value without prefix (gate session ids, secrets).
pub fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).expect("OS random source failed");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hex SHA-256. Tokens are high-entropy, so no password KDF is needed.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Constant-time comparison of two hex hashes.
pub fn hashes_equal(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// 10 lowercase base32 chars (50 bits). DNS-safe, contains no `-`.
pub fn random_tunnel_id() -> String {
    let mut bytes = [0u8; TUNNEL_ID_LEN];
    SysRng.try_fill_bytes(&mut bytes).expect("OS random source failed");
    bytes.iter().map(|b| ID_ALPHABET[(b & 31) as usize] as char).collect()
}

pub fn is_valid_tunnel_id(id: &str) -> bool {
    id.len() == TUNNEL_ID_LEN && id.bytes().all(|b| ID_ALPHABET.contains(&b))
}

/// Access link ids: `al_<16 hex>`.
pub fn random_link_id() -> String {
    let mut bytes = [0u8; 8];
    SysRng.try_fill_bytes(&mut bytes).expect("OS random source failed");
    format!("al_{}", hex::encode(bytes))
}

/// Unix seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
