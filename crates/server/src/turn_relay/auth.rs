//! TURN REST credentials, STUN message checks and the challenge rate limits.

use super::*;

pub(super) struct RestAuth {
    pub(super) shared: Arc<Shared>,
}

impl AuthHandler for RestAuth {
    fn auth_handle(&self, username: &str, realm: &str, _src: SocketAddr) -> Result<Vec<u8>, turn::Error> {
        if !self.shared.credential_allowed(username) {
            return Err(turn::Error::Other("invalid or revoked credential".into()));
        }
        let password = crate::ice::credential(&self.shared.secret, username);
        Ok(generate_auth_key(username, realm, &password))
    }
}

/// The credential format is unchanged; reject malformed identities before any lookup.
pub(super) fn credential_parts(username: &str) -> Option<(i64, &str)> {
    // RFC 5389 USERNAME bound also limits memory used by identity tables.
    if username.len() > 513 {
        return None;
    }
    let mut parts = username.splitn(3, ':');
    let expiry = parts.next()?.parse().ok()?;
    let tunnel = parts.next()?;
    let subject = parts.next()?;
    if tunnel.is_empty() || subject.is_empty() {
        return None;
    }
    Some((expiry, tunnel))
}

/// Minimal strict STUN envelope/attribute reader. The server crate does not expose
/// its STUN decoder. Duplicate usernames/integrity and identities outside the
/// authenticated prefix are rejected rather than parsed differently.
#[derive(Debug)]
pub(super) struct StunPacket<'a> {
    pub(super) kind: u16,
    pub(super) username: Option<&'a str>,
    pub(super) reservation: bool,
    pub(super) modern_auth: bool,
}

pub(super) fn stun_packet(raw: &[u8]) -> Result<Option<StunPacket<'_>>, ()> {
    if raw.first().is_none_or(|b| b & 0xc0 != 0) {
        return Ok(None);
    }
    if raw.len() < 20 || raw[4..8] != [0x21, 0x12, 0xa4, 0x42] {
        return Err(());
    }
    let len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if !len.is_multiple_of(4) || raw.len() != 20 + len {
        return Err(());
    }
    let mut packet = StunPacket {
        kind: u16::from_be_bytes([raw[0], raw[1]]),
        username: None,
        reservation: false,
        modern_auth: false,
    };
    let mut integrity = false;
    let mut pos = 20;
    while pos < raw.len() {
        let head = raw.get(pos..pos + 4).ok_or(())?;
        let typ = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[2], head[3]]) as usize;
        pos += 4;
        let value = raw.get(pos..pos + len).ok_or(())?;
        packet.modern_auth |= matches!(typ, 0x001c | 0x001d | 0x8002);
        if typ == 0x0008 {
            if integrity || len != 20 {
                return Err(());
            }
            integrity = true;
        }
        if typ == 0x0006 {
            if integrity || packet.username.is_some() || len > 513 {
                return Err(());
            }
            packet.username = Some(std::str::from_utf8(value).map_err(|_| ())?);
        }
        // Optional even-port/reservation-token allocations can move a relay socket
        // between usernames, bypassing ownership quotas. ICE does not need them.
        packet.reservation |= matches!(typ, 0x0018 | 0x0022);
        pos += (len + 3) & !3;
        if pos > raw.len() {
            return Err(());
        }
    }
    Ok(Some(packet))
}

pub(super) fn integrity(username: &str, shared: &Shared) -> MessageIntegrity {
    MessageIntegrity::new_long_term_integrity(
        username.to_owned(),
        shared.realm.clone(),
        crate::ice::credential(&shared.secret, username),
    )
}

pub(super) fn verify_integrity(raw: &[u8], username: &str, shared: &Shared) -> bool {
    let mut message = Message { raw: raw.to_vec(), ..Default::default() };
    message.decode().is_ok() && integrity(username, shared).check(&mut message).is_ok()
}

pub(super) fn quota_response(raw: &[u8], username: &str, shared: &Shared) -> Result<Vec<u8>, stun::Error> {
    use stun::error_code::CODE_ALLOC_QUOTA_REACHED;
    use stun::message::{CLASS_ERROR_RESPONSE, METHOD_ALLOCATE, MessageType};
    let mut original = Message { raw: raw.to_vec(), ..Default::default() };
    original.decode()?;
    let mut response = Message::default();
    response.build(&[
        Box::new(original.transaction_id),
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)),
        Box::new(CODE_ALLOC_QUOTA_REACHED),
    ])?;
    integrity(username, shared).add_to(&mut response)?;
    Ok(response.raw)
}

pub(super) struct RequestBucket {
    pub(super) tokens: f64,
    pub(super) at: tokio::time::Instant,
}

impl RequestBucket {
    pub(super) fn new(burst: f64) -> Self {
        Self { tokens: burst, at: tokio::time::Instant::now() }
    }

    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let now = tokio::time::Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

pub(super) struct ChallengeLimiter {
    pub(super) global: RequestBucket,
    pub(super) ips: HashMap<IpAddr, RequestBucket>,
    pub(super) pruned: tokio::time::Instant,
}

impl ChallengeLimiter {
    pub(super) fn new() -> Self {
        Self {
            global: RequestBucket::new(CHALLENGE_GLOBAL_BURST),
            ips: HashMap::new(),
            pruned: tokio::time::Instant::now(),
        }
    }

    pub(super) fn allow(&mut self, ip: IpAddr) -> bool {
        // turn 0.17.3 scans its hour-long nonce table for every challenge.
        // This bounds unauthenticated challenge growth/work; residual O(N)
        // pruning remains at the admitted rate (~720k nonces/hour). A holder
        // of valid credentials can also provoke authenticated stale-nonce
        // challenges; this guard does not replace upstream nonce-table fixes.
        let now = tokio::time::Instant::now();
        if now.duration_since(self.pruned) >= SWEEP_INTERVAL {
            self.ips.retain(|_, bucket| now.duration_since(bucket.at) < CHALLENGE_IDLE);
            self.pruned = now;
        }
        let ip = source_network(ip);
        if self.ips.len() >= CHALLENGE_IP_ENTRIES
            && !self.ips.contains_key(&ip)
            && let Some(oldest) = self.ips.iter().min_by_key(|(_, bucket)| bucket.at).map(|(ip, _)| *ip)
        {
            self.ips.remove(&oldest);
        }
        self.ips
            .entry(ip)
            .or_insert_with(|| RequestBucket::new(CHALLENGE_IP_BURST))
            .take(CHALLENGE_IP_RATE, CHALLENGE_IP_BURST)
            && self.global.take(CHALLENGE_GLOBAL_RATE, CHALLENGE_GLOBAL_BURST)
    }
}
