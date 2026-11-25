//! Fixed-window rate limiters, per IP or per any key (e.g. a username).

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
/// Above this many tracked addresses, stale windows are dropped, at most once per `PRUNE_EVERY`.
const PRUNE_ABOVE: usize = 10_000;
const PRUNE_EVERY: Duration = Duration::from_secs(10);
/// Hard cap on tracked addresses. When it is full of live windows, new
/// addresses are refused (fail closed) rather than growing without bound.
const MAX_TRACKED: usize = 100_000;

/// Per-IP limiter (IPv6 per /64).
pub type RateLimiter = Limiter<IpAddr>;

pub struct Limiter<K> {
    per_min: u32,
    /// How long one budget lasts (a minute unless made with `per_hour`).
    window: Duration,
    windows: Mutex<Windows<K>>,
}

struct Windows<K> {
    map: HashMap<K, (Instant, u32)>,
    last_prune: Instant,
}

impl RateLimiter {
    /// Count one attempt from `ip`; `false` if it exceeds the per-minute budget.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_key(bucket(ip))
    }
}

impl<K: Hash + Eq> Limiter<K> {
    /// `per_min == 0` disables limiting.
    pub fn new(per_min: u32) -> Self {
        Self {
            per_min,
            window: WINDOW,
            windows: Mutex::new(Windows { map: HashMap::new(), last_prune: Instant::now() }),
        }
    }

    /// At most `per_hour` per key in an hour (sustained budgets, e.g. mail to one address).
    pub fn per_hour(per_hour: u32) -> Self {
        Self { window: Duration::from_secs(3600), ..Self::new(per_hour) }
    }

    /// Count one attempt for `key`; `false` if it exceeds the per-minute budget.
    pub fn check_key(&self, key: K) -> bool {
        if self.per_min == 0 {
            return true;
        }
        let now = Instant::now();
        let mut guard = self.windows.lock().expect("ratelimit lock");
        let w = &mut *guard;
        if w.map.len() > PRUNE_ABOVE && now.duration_since(w.last_prune) >= PRUNE_EVERY {
            w.map.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            w.last_prune = now;
        }
        if w.map.len() >= MAX_TRACKED && !w.map.contains_key(&key) {
            return false;
        }
        let entry = w.map.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 >= self.per_min {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// IPv4-mapped addresses count as IPv4 (the listener binds `[::]`), and IPv6
/// clients are bucketed per /64 since one host typically owns the whole prefix.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut seg = v6.segments();
            seg[4..].fill(0);
            IpAddr::V6(seg.into())
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_window() {
        let rl = RateLimiter::new(2);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip));
        assert!(rl.check("203.0.113.6".parse().unwrap()));
    }

    #[test]
    fn an_hourly_budget_outlasts_a_minute() {
        let rl = Limiter::<&str>::per_hour(1);
        assert!(rl.check_key("a"));
        assert!(!rl.check_key("a"));
        assert_eq!(rl.window, Duration::from_secs(3600));
    }

    #[test]
    fn zero_is_unlimited() {
        let rl = RateLimiter::new(0);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..1000 {
            assert!(rl.check(ip));
        }
    }

    #[test]
    fn ipv6_shares_a_64() {
        let rl = RateLimiter::new(1);
        assert!(rl.check("2001:db8::1".parse().unwrap()));
        assert!(!rl.check("2001:db8::2".parse().unwrap()));
        assert!(rl.check("2001:db8:0:1::1".parse().unwrap()));
    }
}
