//! Prometheus text metrics on `metrics_listen` (loopback by default).

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::state::AppState;
use crate::util::{Body, full};

#[derive(Default)]
pub struct TunnelBytes {
    /// Visitor → origin.
    pub bytes_in: AtomicU64,
    /// Origin → visitor.
    pub bytes_out: AtomicU64,
    /// What the last traffic flush stored (see `traffic`).
    flushed_in: AtomicU64,
    flushed_out: AtomicU64,
    /// The owning user's usage once resolved; `Some(None)`: no user (a
    /// service or the admin token).
    pub user: OnceLock<Option<Arc<crate::traffic::UserUsage>>>,
}

impl TunnelBytes {
    /// Count `n` proxied bytes (`outbound`: origin → visitor), also for the owner.
    pub fn count(&self, n: u64, outbound: bool) {
        let counter = if outbound { &self.bytes_out } else { &self.bytes_in };
        counter.fetch_add(n, Ordering::Relaxed);
        if let Some(user) = self.owner() {
            user.add(n, outbound);
        }
    }

    pub fn owner(&self) -> Option<&Arc<crate::traffic::UserUsage>> {
        self.user.get().and_then(Option::as_ref)
    }

    /// The owner reached their traffic cap.
    pub fn blocked(&self) -> bool {
        self.owner().is_some_and(|u| u.blocked())
    }

    pub fn totals(&self) -> (u64, u64) {
        (self.bytes_in.load(Ordering::Relaxed), self.bytes_out.load(Ordering::Relaxed))
    }

    /// Counted since the last flush (in, out).
    pub fn unflushed(&self) -> (u64, u64) {
        let (i, o) = self.totals();
        self.pending_at(i, o)
    }

    /// What totals read as (`at_in`, `at_out`) add since the last flush.
    pub fn pending_at(&self, at_in: u64, at_out: u64) -> (u64, u64) {
        (
            at_in.saturating_sub(self.flushed_in.load(Ordering::Relaxed)),
            at_out.saturating_sub(self.flushed_out.load(Ordering::Relaxed)),
        )
    }

    /// A flush stored the totals it read (`at_in`, `at_out`).
    pub fn mark_flushed_at(&self, at_in: u64, at_out: u64) {
        self.flushed_in.store(at_in, Ordering::Relaxed);
        self.flushed_out.store(at_out, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Metrics {
    pub live_streams: AtomicI64,
    pub gate_denials: AtomicU64,
    /// Visitor lookups answered 503 because the lookup slots were full.
    pub lookups_shed: AtomicU64,
    /// Proxied exchanges cut in flight because their access was lost.
    pub access_cuts: AtomicU64,
    /// Built-in TURN relay gauges.
    pub turn: Arc<crate::turn_relay::MetricsRef>,
    pub access_redemptions: AtomicU64,
    pub access_failures: AtomicU64,
    pub requests: AtomicU64,
    per_tunnel: Mutex<HashMap<String, Arc<TunnelBytes>>>,
}

impl Metrics {
    pub fn tunnel_bytes(&self, tunnel_id: &str) -> Arc<TunnelBytes> {
        let mut map = self.per_tunnel.lock().expect("metrics lock");
        if let Some(b) = map.get(tunnel_id) {
            return b.clone();
        }
        map.entry(tunnel_id.to_string()).or_default().clone()
    }

    pub fn get(&self, tunnel_id: &str) -> Option<Arc<TunnelBytes>> {
        self.per_tunnel.lock().expect("metrics lock").get(tunnel_id).cloned()
    }

    /// A deleted tunnel: its series ends (its row is gone, so its own total
    /// has nowhere to go; its owner's bytes are in the owner's usage).
    pub fn forget_tunnel(&self, tunnel_id: &str) {
        self.per_tunnel.lock().expect("metrics lock").remove(tunnel_id);
    }

    pub fn snapshot(&self) -> Vec<(String, Arc<TunnelBytes>)> {
        self.per_tunnel.lock().expect("metrics lock").iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Drop counters that only this map holds and `keep` does not want.
    pub fn prune(&self, keep: impl Fn(&str, &Arc<TunnelBytes>) -> bool) {
        self.per_tunnel.lock().expect("metrics lock").retain(|id, b| Arc::strong_count(b) > 1 || keep(id, b));
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self, state: &AppState) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# TYPE tunnel_tunnels_connected gauge");
        let _ = writeln!(out, "tunnel_tunnels_connected {}", state.registry.len());
        let _ = writeln!(out, "# TYPE tunnel_streams_live gauge");
        let _ = writeln!(out, "tunnel_streams_live {}", self.live_streams.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_requests_total counter");
        let _ = writeln!(out, "tunnel_requests_total {}", self.requests.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_gate_denials_total counter");
        let _ = writeln!(out, "tunnel_gate_denials_total {}", self.gate_denials.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_lookups_shed_total counter");
        let _ = writeln!(out, "tunnel_lookups_shed_total {}", self.lookups_shed.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_access_cuts_total counter");
        let _ = writeln!(out, "tunnel_access_cuts_total {}", self.access_cuts.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_turn_allocations gauge");
        let _ = writeln!(out, "tunnel_turn_allocations {}", self.turn.allocations.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_access_redemptions_total counter");
        let _ = writeln!(out, "tunnel_access_redemptions_total {}", self.access_redemptions.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_access_failures_total counter");
        let _ = writeln!(out, "tunnel_access_failures_total {}", self.access_failures.load(Ordering::Relaxed));
        if let Some(not_after) = state.certs.not_after() {
            let _ = writeln!(out, "# TYPE tunnel_cert_not_after_seconds gauge");
            let _ = writeln!(out, "tunnel_cert_not_after_seconds {not_after}");
        }
        let _ = writeln!(out, "# TYPE tunnel_bytes_total counter");
        for (id, b) in self.per_tunnel.lock().expect("metrics lock").iter() {
            let _ = writeln!(
                out,
                "tunnel_bytes_total{{tunnel=\"{id}\",direction=\"in\"}} {}",
                b.bytes_in.load(Ordering::Relaxed)
            );
            let _ = writeln!(
                out,
                "tunnel_bytes_total{{tunnel=\"{id}\",direction=\"out\"}} {}",
                b.bytes_out.load(Ordering::Relaxed)
            );
        }
        out
    }
}

pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(state.config.metrics_listen).await?;
    loop {
        let tcp = match listener.accept().await {
            Ok((tcp, _)) => tcp,
            Err(e) => {
                // EMFILE and friends are transient; never take the listener down.
                tracing::warn!(error = %e, "metrics accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |_req| {
                let text = state.metrics.render(&state);
                async move {
                    Ok::<_, Infallible>(
                        http::Response::builder()
                            .header(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body::<Body>(full(text))
                            .expect("valid response"),
                    )
                }
            });
            let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
        });
    }
}
