//! Traffic counters per tunnel and per user, and monthly per-user caps.
//!
//! Proxied body bytes and WebSocket bytes are counted in memory: per tunnel
//! (`metrics::TunnelBytes`, lifetime totals) and, for tunnels of a user's
//! machine, into that user's [`UserUsage`] for the current calendar month
//! (UTC). A flush about once a minute writes both to the database in one
//! transaction (nothing when idle). A user's pending bytes are taken with
//! an atomic swap, which is the one cutoff for a flush, a new month and an
//! admin's reset; every such change (and a user's first load and an admin's
//! cap change with its commit) runs under one lock, so only the hot path's
//! atomic adds run beside them. A user whose monthly total reaches their cap is
//! blocked at once: new requests to their tunnels get a "traffic limit
//! reached" page, and the gate epoch of their live tunnels is rotated so
//! in-flight responses, uploads and WebSockets are cut (`gate::reauthorize`
//! refuses blocked tunnels). Raising or removing the cap, resetting the
//! month, or a new month unblocks. Services and admin-token tunnels are
//! counted per tunnel only and never capped; the owner has no cap.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use tokio::sync::Notify;
use utoipa::ToSchema;

use crate::accounts::AdminError;
use crate::db::{Db, TunnelRow};
use crate::metrics::TunnelBytes;
use crate::role::Role;
use crate::state::AppState;

/// How often counters are written to the database.
pub const FLUSH_EVERY: Duration = Duration::from_secs(60);

/// `YYYYMM` of a Unix time, in UTC.
pub fn month_of(unix: i64) -> u32 {
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year * 100 + month) as u32
}

/// `2026-11` for `202611`.
pub fn month_label(month: u32) -> String {
    format!("{:04}-{:02}", month / 100, month % 100)
}

fn now_month() -> u32 {
    month_of(crate::tokens::now())
}

/// One user's traffic this month, kept current on the hot path.
pub struct UserUsage {
    pub user_id: String,
    /// This month's bytes, stored and pending: the one figure enforcement
    /// reads. Counting adds to it; only a new period subtracts from it.
    total: AtomicU64,
    /// Counted since the last flush, per direction: what the next flush
    /// writes (taken with atomic swaps, the cutoff).
    pending_in: AtomicU64,
    pending_out: AtomicU64,
    /// This month's bytes written by flushes (or loaded); changed only with
    /// [`Traffic::changes`] held. `total` = `stored` + pending, apart from
    /// a byte being counted right now.
    stored: AtomicU64,
    /// Cap in bytes; 0: none.
    cap: AtomicU64,
    blocked: AtomicBool,
    /// Serializes changes of `blocked` (with fresh reads of cap and total).
    transitions: Mutex<()>,
    notify: Arc<Notify>,
}

impl UserUsage {
    fn new(user_id: &str, stored: u64, cap: u64, notify: Arc<Notify>) -> Self {
        Self {
            user_id: user_id.to_string(),
            total: AtomicU64::new(stored),
            pending_in: AtomicU64::new(0),
            pending_out: AtomicU64::new(0),
            stored: AtomicU64::new(stored),
            cap: AtomicU64::new(cap),
            blocked: AtomicBool::new(cap != 0 && stored >= cap),
            transitions: Mutex::new(()),
            notify,
        }
    }

    fn transition(&self) -> std::sync::MutexGuard<'_, ()> {
        self.transitions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count `n` bytes (`outbound`: app → visitor); crossing the cap blocks
    /// the user and wakes the enforcer.
    ///
    /// Sequentially consistent with [`Self::settle`]: this writes the total,
    /// then reads `blocked`; an unblock writes `blocked`, then reads the
    /// total. So either this sees the unblock and re-evaluates, or the unblock
    /// sees these bytes and blocks again; a crossing is never missed.
    pub fn add(&self, n: u64, outbound: bool) {
        let total = self.count_total(n);
        self.count_pending(n, outbound);
        let cap = self.cap.load(Ordering::SeqCst);
        if cap != 0 && total >= cap && !self.blocked.load(Ordering::SeqCst) {
            let _t = self.transition();
            self.settle();
        }
    }

    /// First the total: a byte a cutoff can take from pending is then always
    /// already in the total it subtracts from (no phantom usage). A byte in
    /// the total but not yet pending at a cutoff belongs to the new period
    /// on both sides.
    fn count_total(&self, n: u64) -> u64 {
        self.total.fetch_add(n, Ordering::SeqCst) + n
    }

    fn count_pending(&self, n: u64, outbound: bool) {
        let pending = if outbound { &self.pending_out } else { &self.pending_in };
        pending.fetch_add(n, Ordering::SeqCst);
    }

    pub fn blocked(&self) -> bool {
        self.blocked.load(Ordering::SeqCst)
    }

    /// This month's bytes, stored and pending.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }

    pub fn cap(&self) -> Option<u64> {
        Some(self.cap.load(Ordering::SeqCst)).filter(|c| *c != 0)
    }

    fn over(&self) -> bool {
        let cap = self.cap.load(Ordering::SeqCst);
        cap != 0 && self.total() >= cap
    }

    /// Bring `blocked` in line with the current cap and total; under
    /// `transitions`. A block is never lifted while still over the cap, so
    /// readers never see a passing "unblocked"; an unblock re-checks after
    /// publishing (see [`Self::add`]). Notifies the enforcer on every new block.
    fn settle(&self) {
        if self.over() {
            if !self.blocked.swap(true, Ordering::SeqCst) {
                self.notify.notify_one();
            }
        } else if self.blocked.load(Ordering::SeqCst) {
            self.blocked.store(false, Ordering::SeqCst);
            if self.over() {
                self.blocked.store(true, Ordering::SeqCst);
                self.notify.notify_one();
            }
        }
    }

    fn set_cap(&self, cap: Option<u64>) {
        let _t = self.transition();
        self.cap.store(cap.unwrap_or(0), Ordering::SeqCst);
        self.settle();
    }

    /// Take the pending bytes for a flush or a reset (the cutoff). `total` is untouched.
    fn cut_off(&self) -> Cutoff<'_> {
        Cutoff {
            user: self,
            taken: (self.pending_in.swap(0, Ordering::SeqCst), self.pending_out.swap(0, Ordering::SeqCst)),
        }
    }

    /// The flush wrote the taken bytes.
    fn flushed(&self, (b_in, b_out): (u64, u64)) {
        self.stored.fetch_add(b_in + b_out, Ordering::SeqCst);
    }

    /// The flush failed: the taken bytes are pending again.
    fn unflush(&self, (b_in, b_out): (u64, u64)) {
        self.pending_in.fetch_add(b_in, Ordering::SeqCst);
        self.pending_out.fetch_add(b_out, Ordering::SeqCst);
    }

    /// A new period after a cutoff: drop the old period's bytes, which are
    /// what is stored plus `taken` (pending bytes taken at the cutoff and not
    /// stored, e.g. by a reset); what was counted after the cutoff stays.
    fn restart(&self, taken: (u64, u64)) {
        let _t = self.transition();
        let old = self.stored.swap(0, Ordering::SeqCst) + taken.0 + taken.1;
        let mut current = self.total.load(Ordering::SeqCst);
        while let Err(seen) =
            self.total.compare_exchange_weak(current, current.saturating_sub(old), Ordering::SeqCst, Ordering::SeqCst)
        {
            current = seen;
        }
        self.settle();
    }

    fn has_pending(&self) -> bool {
        self.pending_in.load(Ordering::SeqCst) != 0 || self.pending_out.load(Ordering::SeqCst) != 0
    }
}

/// One user's pending bytes taken at a cutoff: a flush writes them
/// ([`Self::flushed`]) or gives them back ([`Self::unflush`]); a reset drops
/// them with the old period ([`Self::restart`]).
#[must_use]
struct Cutoff<'a> {
    user: &'a UserUsage,
    taken: (u64, u64),
}

impl Cutoff<'_> {
    fn is_empty(&self) -> bool {
        self.taken == (0, 0)
    }

    /// The flush row: user id, bytes in, bytes out.
    fn row(&self) -> (String, u64, u64) {
        (self.user.user_id.clone(), self.taken.0, self.taken.1)
    }

    fn flushed(self) {
        self.user.flushed(self.taken);
    }

    fn unflush(self) {
        self.user.unflush(self.taken);
    }

    fn restart(self) {
        self.user.restart(self.taken);
    }

    #[cfg(test)]
    fn taken(&self) -> (u64, u64) {
        self.taken
    }
}

/// The in-memory side: loaded users and the month they count for.
pub struct Traffic {
    users: Mutex<HashMap<String, Arc<UserUsage>>>,
    month: AtomicU32,
    notify: Arc<Notify>,
    /// Written for every change besides counting: flushes, the month
    /// rollover, resets, first loads and admins' cap changes (with their
    /// commit). Read while a tunnel's stored bytes and its in-memory delta
    /// are combined for a view, so no flush lands in between.
    changes: tokio::sync::RwLock<()>,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            users: Mutex::default(),
            month: AtomicU32::new(now_month()),
            notify: Arc::new(Notify::new()),
            changes: tokio::sync::RwLock::new(()),
        }
    }
}

/// Proof that [`Traffic::changes`] is held for writing.
pub struct Changes<'a>(#[allow(dead_code)] tokio::sync::RwLockWriteGuard<'a, ()>);

/// Held while building tunnel views (see [`Traffic::changes`]).
pub struct Reading<'a>(#[allow(dead_code)] tokio::sync::RwLockReadGuard<'a, ()>);

impl Traffic {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<UserUsage>>> {
        self.users.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub async fn changes(&self) -> Changes<'_> {
        Changes(self.changes.write().await)
    }

    /// For combining stored tunnel bytes with unflushed ones (no cold loads inside).
    pub async fn reading(&self) -> Reading<'_> {
        Reading(self.changes.read().await)
    }

    pub fn month(&self) -> u32 {
        self.month.load(Ordering::SeqCst)
    }

    /// The user's usage if it is in memory.
    pub fn loaded(&self, user_id: &str) -> Option<Arc<UserUsage>> {
        self.lock().get(user_id).cloned()
    }

    /// Blocked users stay in memory, so "not loaded" means "not blocked".
    pub fn user_blocked(&self, user_id: &str) -> bool {
        self.loaded(user_id).is_some_and(|u| u.blocked())
    }

    /// The user's usage, loaded from the database (cap and this month's
    /// stored total) the first time it is needed.
    pub async fn usage(&self, db: &Db, user_id: &str) -> anyhow::Result<Arc<UserUsage>> {
        if let Some(u) = self.loaded(user_id) {
            return Ok(u);
        }
        let changes = self.changes().await;
        self.usage_locked(&changes, db, user_id).await
    }

    async fn usage_locked(&self, _: &Changes<'_>, db: &Db, user_id: &str) -> anyhow::Result<Arc<UserUsage>> {
        if let Some(u) = self.loaded(user_id) {
            return Ok(u);
        }
        let (cap, stored) = db.user_traffic(user_id.to_string(), self.month()).await?;
        let usage = Arc::new(UserUsage::new(user_id, stored, cap.unwrap_or(0), self.notify.clone()));
        self.lock().insert(user_id.to_string(), usage.clone());
        Ok(usage)
    }

    /// The month rollover's in-memory side: count for `current` from now on,
    /// and every loaded user's stored total starts again.
    fn start_month(&self, _: &Changes<'_>, current: u32) {
        self.month.store(current, Ordering::SeqCst);
        let users: Vec<Arc<UserUsage>> = self.lock().values().cloned().collect();
        for u in users {
            u.restart((0, 0));
        }
    }

    /// Wait until a user becomes blocked (see [`UserUsage::add`]).
    async fn new_block(&self) {
        self.notify.notified().await;
    }
}

/// The tunnel's counter, with its owner's usage attached (loaded on first
/// use). An error when the owner's usage cannot be loaded: the request must
/// not be relayed uncounted.
pub async fn counter(state: &AppState, tunnel: &TunnelRow) -> anyhow::Result<Arc<TunnelBytes>> {
    let bytes = state.metrics.tunnel_bytes(&tunnel.id);
    if bytes.user.get().is_none() {
        let user = match &tunnel.user_id {
            Some(id) => Some(state.traffic.usage(&state.db, id).await?),
            None => None,
        };
        let _ = bytes.user.set(user);
    }
    Ok(bytes)
}

/// Whether the tunnel's owner has reached their cap (no database access).
pub fn tunnel_blocked(state: &AppState, tunnel_id: &str) -> bool {
    state.metrics.get(tunnel_id).is_some_and(|b| b.blocked())
}

/// Bytes counted for the tunnel since the last flush (in, out).
pub fn unflushed(state: &AppState, tunnel_id: &str) -> (u64, u64) {
    state.metrics.get(tunnel_id).map(|b| b.unflushed()).unwrap_or_default()
}

/// A user's traffic this month, for the API and the UI.
#[derive(Debug, Clone, Serialize, serde::Deserialize, ToSchema)]
pub struct TrafficView {
    /// `YYYY-MM` (UTC).
    pub month: String,
    pub used_bytes: u64,
    /// `None`: no cap.
    pub cap_bytes: Option<u64>,
    /// The cap is reached: visitors see "traffic limit reached".
    pub limited: bool,
}

pub async fn view(state: &AppState, user_id: &str) -> anyhow::Result<TrafficView> {
    let u = state.traffic.usage(&state.db, user_id).await?;
    Ok(TrafficView {
        month: month_label(state.traffic.month()),
        used_bytes: u.total(),
        cap_bytes: u.cap(),
        limited: u.blocked(),
    })
}

/// This month's bytes for a user in a listing: memory if loaded (it includes
/// what is not flushed yet), else the stored figure.
pub fn used_or(state: &AppState, user_id: &str, stored: u64) -> u64 {
    state.traffic.loaded(user_id).map_or(stored, |u| u.total())
}

/// Apply a cap an admin just committed (call with [`Traffic::changes`] held
/// across the commit and this, so two changes apply in commit order).
pub async fn set_cap(state: &AppState, changes: &Changes<'_>, user_id: &str, cap: Option<u64>) -> anyhow::Result<()> {
    state.traffic.usage_locked(changes, &state.db, user_id).await?.set_cap(cap);
    Ok(())
}

/// An admin's "reset this month" (`actor` with `session`, authorized in the
/// same transaction as the delete, audited in it too). The user's pending
/// bytes are the cutoff: taken first, dropped once the delete commits (put
/// back if it fails); what is counted after belongs to the new start. Tunnel
/// totals are not touched. Runs as its own task, so a cancelled request
/// cannot stop it halfway. Returns the username.
pub async fn reset_month(
    state: Arc<AppState>,
    user_id: String,
    actor: String,
    session: String,
    ip: Option<String>,
) -> anyhow::Result<Result<String, AdminError>> {
    tokio::spawn(async move {
        let changes = state.traffic.changes().await;
        let user = state.traffic.usage_locked(&changes, &state.db, &user_id).await?;
        let taken = user.cut_off();
        let reset = state.db.reset_traffic_for(actor.clone(), session, user_id, state.traffic.month()).await;
        match &reset {
            Ok(Ok(username)) => {
                taken.restart();
                if let Err(e) = state.db.audit(Some(actor), "traffic_reset", Some(username.clone()), ip).await {
                    tracing::warn!(error = %format!("{e:#}"), "audit write failed");
                }
            }
            _ => taken.unflush(),
        }
        reset
    })
    .await?
}

/// One tunnel's bytes for a flush.
pub struct TunnelDelta {
    pub tunnel_id: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Write pending bytes (one transaction; none when idle).
pub async fn flush(state: &AppState) -> anyhow::Result<()> {
    let changes = state.traffic.changes().await;
    flush_locked(state, &changes, state.traffic.month()).await
}

async fn flush_locked(state: &AppState, _: &Changes<'_>, month: u32) -> anyhow::Result<()> {
    let mut tunnels = Vec::new();
    let mut marks = Vec::new();
    for (id, b) in state.metrics.snapshot() {
        // One read: the delta written and the baseline stored come from it.
        let (now_in, now_out) = b.totals();
        let (d_in, d_out) = b.pending_at(now_in, now_out);
        if d_in != 0 || d_out != 0 {
            tunnels.push(TunnelDelta { tunnel_id: id, bytes_in: d_in, bytes_out: d_out });
            marks.push((b, now_in, now_out));
        }
    }
    // Scoped: the users' references must be gone before the pruning below,
    // which keeps users that something else still holds.
    {
        let users: Vec<Arc<UserUsage>> = state.traffic.lock().values().filter(|u| u.has_pending()).cloned().collect();
        let taken: Vec<Cutoff<'_>> = users.iter().map(|u| u.cut_off()).filter(|c| !c.is_empty()).collect();
        if !tunnels.is_empty() || !taken.is_empty() {
            let rows = taken.iter().map(Cutoff::row).collect();
            if let Err(e) = state.db.flush_traffic(month, tunnels, rows).await {
                for c in taken {
                    c.unflush();
                }
                return Err(e);
            }
            for c in taken {
                c.flushed();
            }
        }
    }
    for (b, now_in, now_out) in marks {
        b.mark_flushed_at(now_in, now_out);
    }
    // Forget counters nobody uses any more, and users without counters or
    // pending bytes (blocked users stay, so their block is known without a lookup).
    state.metrics.prune(|id, b| b.unflushed() != (0, 0) || state.registry.get(id).is_some());
    state.traffic.lock().retain(|_, u| Arc::strong_count(u) > 1 || u.blocked() || u.has_pending());
    Ok(())
}

/// Flush every minute; at a new month, close the old one first.
pub async fn run(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Err(e) = flush_or_roll_over(&state, now_month()).await {
            tracing::warn!(error = %format!("{e:#}"), "traffic flush failed; retrying in a minute");
        }
    }
}

/// Flush; if `current` is a new month, that flush closes the old month (its
/// swaps are the cutoff) and every user's stored total starts again.
pub(crate) async fn flush_or_roll_over(state: &AppState, current: u32) -> anyhow::Result<()> {
    let changes = state.traffic.changes().await;
    let month = state.traffic.month();
    flush_locked(state, &changes, month).await?;
    if current != month {
        state.traffic.start_month(&changes, current);
        tracing::info!(month = %month_label(current), "traffic counters start a new month");
    }
    Ok(())
}

/// When a user becomes blocked, cut what their tunnels are relaying.
pub async fn enforce(state: Arc<AppState>) {
    loop {
        state.traffic.new_block().await;
        for (id, b) in state.metrics.snapshot() {
            if b.blocked() {
                tracing::info!(tunnel = %id, "traffic limit reached; cutting in-flight requests");
                state.registry.rotate_gate_epoch(&id);
            }
        }
    }
}

/// At startup: load users already over their cap this month, so their
/// tunnels are refused from the first request.
pub async fn preload(state: &AppState) -> anyhow::Result<()> {
    let changes = state.traffic.changes().await;
    for user_id in state.db.users_over_cap(state.traffic.month()).await? {
        state.traffic.usage_locked(&changes, &state.db, &user_id).await?;
    }
    Ok(())
}

impl Db {
    /// `(cap, stored total of month)` of a user; the owner never has a cap,
    /// and an unknown user counts as `(None, 0)`.
    pub async fn user_traffic(&self, user_id: String, month: u32) -> anyhow::Result<(Option<u64>, u64)> {
        let defaults = self.limit_defaults();
        self.call(move |c| {
            let row = c
                .query_row(
                    "SELECT u.role, u.limit_traffic_bytes,
                            COALESCE((SELECT bytes_in + bytes_out FROM traffic WHERE user_id = u.id AND month = ?2), 0)
                     FROM users u WHERE u.id = ?1",
                    params![user_id, month],
                    |r| {
                        let role = crate::role::Role::parse(&r.get::<_, String>(0)?);
                        let setting = crate::limits::Setting::from_column(r.get(1)?);
                        let total: i64 = r.get(2)?;
                        let cap = defaults.resolve(crate::limits::Kind::Traffic, role, setting);
                        Ok((cap.filter(|c| *c != 0), total.max(0) as u64))
                    },
                )
                .optional()?;
            Ok(row.unwrap_or((None, 0)))
        })
        .await
    }

    /// Add tunnels' and users' pending bytes (users: `(id, in, out)`).
    pub async fn flush_traffic(
        &self,
        month: u32,
        tunnels: Vec<TunnelDelta>,
        users: Vec<(String, u64, u64)>,
    ) -> anyhow::Result<()> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            {
                let mut tunnel = tx.prepare_cached(
                    "UPDATE tunnels SET bytes_in = bytes_in + ?2, bytes_out = bytes_out + ?3 WHERE id = ?1",
                )?;
                for d in &tunnels {
                    tunnel.execute(params![d.tunnel_id, d.bytes_in as i64, d.bytes_out as i64])?;
                }
                // A deleted user's bytes are dropped instead of failing the batch.
                let mut user = tx.prepare_cached(
                    "INSERT INTO traffic (user_id, month, bytes_in, bytes_out)
                     SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1)
                     ON CONFLICT (user_id, month) DO UPDATE
                     SET bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out",
                )?;
                for (id, b_in, b_out) in &users {
                    user.execute(params![id, month, *b_in as i64, *b_out as i64])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Delete `id`'s row for `month` if `actor` (signed in with `session`)
    /// may change that user: as for `admin_update_user`, never the owner or
    /// oneself, admins only members. Returns the username.
    pub async fn reset_traffic_for(
        &self,
        actor: String,
        session: String,
        id: String,
        month: u32,
    ) -> anyhow::Result<Result<String, AdminError>> {
        self.call(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            if !crate::db::authorized(&tx, &actor, None, &session)? {
                return Ok(Err(AdminError::SignedOut));
            }
            let actor_role: String =
                tx.query_row("SELECT role FROM users WHERE id = ?1", params![actor], |r| r.get(0))?;
            let target: Option<(String, String)> = tx
                .query_row("SELECT role, username FROM users WHERE id = ?1", params![id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            let Some((role, username)) = target else {
                return Ok(Err(AdminError::NotFound));
            };
            let (actor_role, role) = (Role::parse(&actor_role), Role::parse(&role));
            let allowed = id != actor
                && role != Role::Owner
                && (actor_role == Role::Owner || (actor_role == Role::Admin && role == Role::Member));
            if !allowed {
                return Ok(Err(AdminError::Forbidden));
            }
            tx.execute("DELETE FROM traffic WHERE user_id = ?1 AND month = ?2", params![id, month])?;
            tx.commit()?;
            Ok(Ok(username))
        })
        .await
    }

    /// Users with a cap whose stored total of `month` reaches it.
    pub async fn users_over_cap(&self, month: u32) -> anyhow::Result<Vec<String>> {
        let defaults = self.limit_defaults();
        self.call(move |c| {
            let mut stmt = c.prepare(
                "SELECT u.id, u.role, u.limit_traffic_bytes, t.bytes_in + t.bytes_out FROM users u
                 JOIN traffic t ON t.user_id = u.id AND t.month = ?1 WHERE u.role != 'owner'",
            )?;
            let rows = stmt.query_map(params![month], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?, r.get::<_, i64>(3)?))
            })?;
            let mut over = Vec::new();
            for row in rows {
                let (id, role, setting, total) = row?;
                let role = crate::role::Role::parse(&role);
                let cap =
                    defaults.resolve(crate::limits::Kind::Traffic, role, crate::limits::Setting::from_column(setting));
                if cap.is_some_and(|cap| cap > 0 && total.max(0) as u64 >= cap) {
                    over.push(id);
                }
            }
            Ok(over)
        })
        .await
    }

    /// Delete monthly rows older than a year (purge loop).
    pub async fn purge_traffic(&self, before_month: u32) -> anyhow::Result<usize> {
        self.call(move |c| Ok(c.execute("DELETE FROM traffic WHERE month < ?1", params![before_month])?)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn months() {
        assert_eq!(month_of(0), 197001);
        assert_eq!(month_of(1_795_400_000), 202611);
        assert_eq!(month_of(1_798_761_599), 202612); // 2026-12-31T23:59:59Z
        assert_eq!(month_of(1_798_761_600), 202701); // 2027-01-01T00:00:00Z
        assert_eq!(month_of(951_782_400), 200002); // 2000-02-29
        assert_eq!(month_of(-1), 196912);
        assert_eq!(month_label(202611), "2026-11");
    }

    fn usage(stored: u64, cap: u64) -> (UserUsage, Arc<Notify>) {
        let notify = Arc::new(Notify::new());
        (UserUsage::new("u", stored, cap, notify.clone()), notify)
    }

    #[tokio::test]
    async fn crossing_the_cap_blocks_once_and_wakes_the_enforcer() {
        let (u, notify) = usage(0, 100);
        u.add(60, false);
        assert!(!u.blocked());
        u.add(40, true);
        assert!(u.blocked());
        // One permit for the crossing, none for later bytes.
        tokio::time::timeout(Duration::from_millis(50), notify.notified()).await.unwrap();
        u.add(10, true);
        assert!(tokio::time::timeout(Duration::from_millis(50), notify.notified()).await.is_err());
        assert_eq!(u.total(), 110);
        // Raising the cap unblocks; lowering it below the total blocks again.
        u.set_cap(Some(1000));
        assert!(!u.blocked());
        u.set_cap(Some(50));
        assert!(u.blocked());
        tokio::time::timeout(Duration::from_millis(50), notify.notified()).await.unwrap();
        u.set_cap(None);
        assert!(!u.blocked());
        u.add(1_000_000, false);
        assert!(!u.blocked(), "no cap, no block");
    }

    #[test]
    fn flush_cutoffs_neither_lose_nor_double_count() {
        let (u, _) = usage(100, 0);
        u.add(30, false);
        u.add(20, true);
        let taken = u.cut_off();
        assert_eq!(taken.taken(), (30, 20));
        assert_eq!(u.total(), 150, "a flush in progress does not move the total");
        u.add(5, false);
        // A failed flush puts them back; nothing is counted twice.
        taken.unflush();
        assert_eq!(u.total(), 155);
        let taken = u.cut_off();
        assert_eq!(taken.taken(), (35, 20));
        taken.flushed();
        assert_eq!(u.total(), 155);
        // A new month keeps only what came after the cutoff.
        u.add(7, true);
        u.restart((0, 0));
        assert_eq!(u.total(), 7);
        assert!(u.has_pending());
        // A reset drops the stored bytes and what it took at its cutoff.
        let taken = u.cut_off();
        u.add(2, false);
        taken.restart();
        assert_eq!(u.total(), 2);
    }

    #[test]
    fn a_cutoff_in_the_middle_of_counting_leaves_no_phantom_usage() {
        // `add` interrupted between its two steps by a reset, then by a new month.
        for month in [false, true] {
            let (u, _) = usage(100, 0);
            u.count_total(20);
            let taken = u.cut_off();
            if month {
                taken.flushed();
                u.restart((0, 0));
            } else {
                taken.restart();
            }
            u.count_pending(20, true);
            // The 20 bytes belong to the new period everywhere: in the total
            // and in what the next flush writes.
            assert_eq!(u.total(), 20, "month {month}");
            assert_eq!(u.cut_off().taken(), (0, 20), "month {month}");
        }
    }

    #[test]
    fn a_block_is_never_lifted_while_over_the_cap() {
        let (u, _) = usage(0, 100);
        u.add(150, true);
        assert!(u.blocked());
        // Re-settling while over (a second crossing, a lower cap) keeps it blocked throughout.
        u.set_cap(Some(120));
        assert!(u.blocked());
        u.set_cap(Some(200));
        assert!(!u.blocked());
        u.add(60, false);
        assert!(u.blocked());
    }
}
