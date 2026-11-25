//! Prometheus text metrics on `metrics_listen` (loopback by default).

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::traffic::TunnelBytes;
use crate::util::{Body, full};

/// The built-in TURN relay's gauges (the relay holds them).
#[derive(Default)]
pub struct TurnMetrics {
    allocations: AtomicI64,
}

impl TurnMetrics {
    pub fn allocation_opened(&self) {
        self.allocations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn allocation_closed(&self) {
        self.allocations.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn allocations(&self) -> i64 {
        self.allocations.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
pub struct Metrics {
    live_streams: AtomicI64,
    gate_denials: AtomicU64,
    /// Visitor lookups answered 503 because the lookup slots were full.
    lookups_shed: AtomicU64,
    /// Proxied exchanges cut in flight because their access was lost.
    access_cuts: AtomicU64,
    /// Built-in TURN relay gauges.
    pub turn: Arc<TurnMetrics>,
    access_redemptions: AtomicU64,
    access_failures: AtomicU64,
    requests: AtomicU64,
}

impl Metrics {
    /// A visitor request reached the edge.
    pub fn request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    /// The gate refused a visitor.
    pub fn gate_denied(&self) {
        self.gate_denials.fetch_add(1, Ordering::Relaxed);
    }

    /// A visitor lookup was answered 503 because the lookup slots were full.
    pub fn lookup_shed(&self) {
        self.lookups_shed.fetch_add(1, Ordering::Relaxed);
    }

    /// A proxied exchange was cut in flight because its access was lost.
    pub fn access_cut(&self) {
        self.access_cuts.fetch_add(1, Ordering::Relaxed);
    }

    /// An access link or password login granted a gate session.
    pub fn access_redeemed(&self) {
        self.access_redemptions.fetch_add(1, Ordering::Relaxed);
    }

    /// An access link or password login was refused.
    pub fn access_failed(&self) {
        self.access_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A proxied visitor request or WebSocket started.
    pub fn stream_opened(&self) {
        self.live_streams.fetch_add(1, Ordering::Relaxed);
    }

    /// A proxied visitor request or WebSocket ended.
    pub fn stream_closed(&self) {
        self.live_streams.fetch_sub(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn live_streams(&self) -> i64 {
        self.live_streams.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn access_cuts(&self) -> u64 {
        self.access_cuts.load(Ordering::SeqCst)
    }

    /// The Prometheus text: these counters, plus `tunnels_connected`, the
    /// certificate's expiry and every tunnel's byte counters.
    pub fn render(
        &self,
        tunnels_connected: usize,
        cert_not_after: Option<i64>,
        tunnels: &[(String, Arc<TunnelBytes>)],
    ) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# TYPE tunnel_tunnels_connected gauge");
        let _ = writeln!(out, "tunnel_tunnels_connected {tunnels_connected}");
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
        let _ = writeln!(out, "tunnel_turn_allocations {}", self.turn.allocations());
        let _ = writeln!(out, "# TYPE tunnel_access_redemptions_total counter");
        let _ = writeln!(out, "tunnel_access_redemptions_total {}", self.access_redemptions.load(Ordering::Relaxed));
        let _ = writeln!(out, "# TYPE tunnel_access_failures_total counter");
        let _ = writeln!(out, "tunnel_access_failures_total {}", self.access_failures.load(Ordering::Relaxed));
        if let Some(not_after) = cert_not_after {
            let _ = writeln!(out, "# TYPE tunnel_cert_not_after_seconds gauge");
            let _ = writeln!(out, "tunnel_cert_not_after_seconds {not_after}");
        }
        let _ = writeln!(out, "# TYPE tunnel_bytes_total counter");
        for (id, b) in tunnels {
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

/// Serve `render`'s text to every request on `listen`.
pub async fn serve(listen: SocketAddr, render: impl Fn() -> String + Send + Sync + 'static) -> anyhow::Result<()> {
    let render = Arc::new(render);
    let listener = TcpListener::bind(listen).await?;
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
        let render = render.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |_req| {
                let text = render();
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
