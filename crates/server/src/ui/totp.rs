//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s steps), the profile every
//! authenticator app supports. Built on the `hmac`/`sha1` crates the server
//! already uses rather than a TOTP crate with its own copies of them.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const STEP_S: i64 = 30;
pub const DIGITS: u32 = 6;
pub const SECRET_LEN: usize = 20;
/// Codes from one step before or after the current one are accepted (clock skew).
const SKEW_STEPS: i64 = 1;

/// HOTP value (RFC 4226) for `counter`.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([digest[offset] & 0x7f, digest[offset + 1], digest[offset + 2], digest[offset + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The 6-digit code at `unix` (tests and fixtures).
#[cfg(test)]
pub fn code_at(secret: &[u8], unix: i64) -> u32 {
    hotp(secret, step_at(unix) as u64)
}

pub fn step_at(unix: i64) -> i64 {
    unix.div_euclid(STEP_S)
}

/// The step `code` belongs to, if it is valid at `unix` (within the skew) and
/// newer than `last_step`, so a code can be used only once.
pub fn verify(secret: &[u8], code: &str, unix: i64, last_step: Option<i64>) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = step_at(unix);
    let mut found = None;
    // Check every candidate step without stopping early, so timing does not
    // reveal which step matched.
    for step in (current - SKEW_STEPS)..=(current + SKEW_STEPS) {
        if step < 0 {
            continue;
        }
        let expected = format!("{:0width$}", hotp(secret, step as u64), width = DIGITS as usize);
        let matches: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
        if matches && last_step.is_none_or(|last| step > last) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// RFC 4648 base32 without padding, as authenticator apps expect.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `otpauth://` URI for the QR code (issuer and account are URL-encoded).
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>().replace('+', "%20");
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_S}",
        enc(issuer),
        enc(account),
        base32(secret),
        enc(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B vectors (SHA-1 secret, 8 digits there; the last 6 here).
    #[test]
    fn rfc6238_vectors() {
        let secret = b"12345678901234567890";
        for (t, code8) in [
            (59_i64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ] {
            let six = &code8[2..];
            assert_eq!(format!("{:06}", hotp(secret, step_at(t) as u64)), six, "t={t}");
            assert_eq!(verify(secret, six, t, None), Some(step_at(t)));
        }
    }

    #[test]
    fn skew_replay_and_format() {
        let secret = b"12345678901234567890";
        let t = 1_234_567_890;
        let code = format!("{:06}", hotp(secret, step_at(t) as u64));
        assert_eq!(verify(secret, &code, t + STEP_S, None), Some(step_at(t)));
        assert_eq!(verify(secret, &code, t + 2 * STEP_S, None), None);
        assert_eq!(verify(secret, &code, t, Some(step_at(t))), None, "replay of the same step");
        assert_eq!(verify(secret, &format!("{} {}", &code[..3], &code[3..]), t, None), Some(step_at(t)));
        assert_eq!(verify(secret, "12345", t, None), None);
        assert_eq!(verify(secret, "abcdef", t, None), None);
    }

    #[test]
    fn base32_and_uri() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        let uri = otpauth_uri("Tunnel tunnel.example.com", "ann", b"12345678901234567890");
        assert!(uri.starts_with("otpauth://totp/Tunnel%20tunnel.example.com:ann?secret=GEZD"));
    }
}
