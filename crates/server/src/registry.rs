//! In-memory map of connected tunnels (one control connection per tunnel id).

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tunnel_protocol::{CloseReason, ServerMsg};

pub struct LiveTunnel {
    /// Distinguishes successive connections for the same tunnel id.
    pub conn_id: u64,
    pub tunnel_id: String,
    /// Clone per request and call `open_stream()`.
    pub control: tunnel_protocol::mux::Control,
    /// Ports the client has declared (and the server accepted).
    pub ports: RwLock<BTreeSet<u16>>,
    /// Outbound control-stream messages (written by the session's writer task).
    pub ctrl_tx: mpsc::Sender<ServerMsg>,
    /// Cancelled when the session must end; the session task cleans up.
    pub cancel: CancellationToken,
    pub connected_at: i64,
    /// Visitor requests and WebSockets in progress on this connection.
    pub streams: AtomicUsize,
    /// Idle origin connections for reuse.
    pub pool: crate::pool::OriginPool,
}

impl LiveTunnel {
    pub fn has_port(&self, port: u16) -> bool {
        self.ports.read().map(|p| p.contains(&port)).unwrap_or(false)
    }

    pub fn ports(&self) -> Vec<u16> {
        self.ports.read().map(|p| p.iter().copied().collect()).unwrap_or_default()
    }

    /// Tell the client why it is being closed, then cancel the session shortly
    /// after so the message has a chance to flush.
    pub fn close(&self, reason: CloseReason) {
        let _ = self.ctrl_tx.try_send(ServerMsg::Close { reason });
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            cancel.cancel();
        });
    }
}

/// Tokens captured before gate authorization stay cancelled after rotation.
#[derive(Default)]
struct GateEpoch {
    token: CancellationToken,
}

impl GateEpoch {
    fn rotate(&mut self) {
        self.token.cancel();
        self.token = CancellationToken::new();
    }
}

struct Entry {
    live: Arc<LiveTunnel>,
    gate: GateEpoch,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.gate.token.cancel();
    }
}

#[derive(Default)]
pub struct Registry {
    inner: RwLock<HashMap<String, Entry>>,
    next_conn_id: AtomicU64,
}

impl Registry {
    pub fn next_conn_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Insert, returning the connection it replaced (caller closes it with
    /// [`CloseReason::Replaced`]).
    pub fn insert(&self, live: Arc<LiveTunnel>) -> Option<Arc<LiveTunnel>> {
        let entry = Entry { live, gate: GateEpoch::default() };
        self.inner.write().expect("registry lock").insert(entry.live.tunnel_id.clone(), entry).map(|e| e.live.clone())
    }

    pub fn get(&self, tunnel_id: &str) -> Option<Arc<LiveTunnel>> {
        self.inner.read().expect("registry lock").get(tunnel_id).map(|e| e.live.clone())
    }

    /// Capture before looking up grants so a concurrent revoke cancels even
    /// an authorization or upgrade that is still in flight.
    pub fn gate_epoch(&self, tunnel_id: &str) -> CancellationToken {
        if let Some(entry) = self.inner.read().expect("registry lock").get(tunnel_id) {
            return entry.gate.token.clone();
        }
        let token = CancellationToken::new();
        token.cancel();
        token
    }

    pub fn rotate_gate_epoch(&self, tunnel_id: &str) {
        if let Some(entry) = self.inner.write().expect("registry lock").get_mut(tunnel_id) {
            entry.gate.rotate();
        }
    }

    /// Remove only if the entry still belongs to `conn_id` (a newer
    /// connection may already have replaced it).
    pub fn remove_if(&self, tunnel_id: &str, conn_id: u64) {
        let mut map = self.inner.write().expect("registry lock");
        if map.get(tunnel_id).is_some_and(|e| e.live.conn_id == conn_id) {
            map.remove(tunnel_id);
        }
    }

    pub fn remove(&self, tunnel_id: &str) -> Option<Arc<LiveTunnel>> {
        self.inner.write().expect("registry lock").remove(tunnel_id).map(|e| e.live.clone())
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("registry lock").len()
    }

    pub fn all(&self) -> Vec<Arc<LiveTunnel>> {
        self.inner.read().expect("registry lock").values().map(|e| e.live.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_epoch_rotation_cancels_old_tokens_only() {
        let mut epoch = GateEpoch::default();
        let first = epoch.token.clone();
        epoch.rotate();
        assert!(first.is_cancelled());
        assert!(!epoch.token.is_cancelled());
        let second = epoch.token.clone();
        epoch.rotate();
        assert!(first.is_cancelled());
        assert!(second.is_cancelled());
        assert!(!epoch.token.is_cancelled());
    }
}
