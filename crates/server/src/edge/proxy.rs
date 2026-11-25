//! Forwarding one visitor request to the sandbox origin over HTTP/1.1 on a
//! Yamux stream (reused from the tunnel's `pool` when one is idle), including
//! WebSocket upgrades (always on a fresh stream) and HTTP/2 Extended CONNECT.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::response::Parts;
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tunnel_protocol::mux::Stream as StreamHandle;
use tunnel_protocol::{STREAM_OK, STREAM_REFUSED, encode_preamble};

use crate::db::{HostHeaderMode, TunnelRow};
use crate::edge::gate::{Rechecking, Side};
use crate::edge::headers::{self, ResponseCtx};
use crate::edge::inject::{self, Injector};
use crate::edge::pages;
use crate::ice;
use crate::pool::OriginConn;
use crate::registry::LiveTunnel;
use crate::state::AppState;
use crate::traffic::TunnelBytes;
use crate::util::{Body, BoxError, empty, header_str, incoming, text_response};

/// Upper bound for opening a stream and reading the client's status byte.
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the origin may take to send response headers. Generous because
/// dev servers can compile on the first request; bodies, SSE, and WebSockets
/// are not limited by it.
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(120);
/// Requests and WebSockets in progress per tunnel connection; more get 503 so
/// one tunnel (or a hung origin) cannot hold unbounded server and client state.
const MAX_STREAMS_PER_TUNNEL: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsKind {
    /// HTTP/1.1 `Upgrade: websocket`.
    H1,
    /// HTTP/2 Extended CONNECT (RFC 8441) with `:protocol = websocket`.
    H2,
}

/// Forward `req` to `127.0.0.1:{port}` in the sandbox. The caller has already
/// passed the gate (or the CORS-preflight exception) and checked that `live`
/// declares `port`. `cookie` is the visitor's `Cookie` minus gate cookies;
/// `session_subject` (gate-session hash prefix) is set for gated requests and
/// enables ICE injection. `authorization` (absent only for the credential-free
/// CORS preflight) is watched by a task of its own ([`Exchange::spawn_watch`]) for as
/// long as any part of the exchange lives. From a gate-epoch rotation until
/// [`gate::watch`] has a verdict, nothing more is relayed in either direction
/// (opening the origin connection, waiting for its headers, both bodies and
/// the WebSocket splice pause). Once it reports the authorization lost, the
/// origin stream and connection are released at once and both bodies fail,
/// which aborts the visitor's connection (HTTP/1.1) or stream (HTTP/2); a
/// request still waiting for the origin gets a 401 and a WebSocket closes.
/// The stream slot is released when hyper drops the response body, as for
/// any slow visitor.
///
/// [`gate::watch`]: crate::edge::gate::watch
#[allow(clippy::too_many_arguments)]
pub async fn forward(
    state: &Arc<AppState>,
    tunnel: &TunnelRow,
    live: Arc<LiveTunnel>,
    port: u16,
    mut req: Request<Incoming>,
    cookie: Option<HeaderValue>,
    peer: SocketAddr,
    session_subject: Option<String>,
    authorization: Option<crate::edge::gate::Authorization>,
    bytes: Arc<TunnelBytes>,
) -> Response<Body> {
    let cfg = &state.config;
    let ws = websocket_kind(&req);
    if ws.is_none() && *req.method() == Method::CONNECT {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "CONNECT is not supported");
    }
    // Must be taken before the request is consumed.
    let visitor_upgrade = ws.map(|_| hyper::upgrade::on(&mut req));
    let inject_subject = session_subject.filter(|_| {
        tunnel.inject_ice && cfg.webrtc.enabled && *req.method() == Method::GET && is_navigation(req.headers())
    });

    // The watch runs in its own task for as long as any part of the exchange
    // holds an `Alive` (this future, either body, a splice).
    let exchange = Arc::new(Exchange::default());
    let alive = authorization.map(|grant| exchange.clone().spawn_watch(state, &tunnel.id, grant));

    let public_host = state.preview_host(port, &tunnel.id);
    let (parts, body) = req.into_parts();
    let headers = origin_request_headers(
        parts.headers,
        state,
        tunnel,
        port,
        &public_host,
        cookie,
        peer,
        ws,
        inject_subject.is_some(),
    );

    let req_body = if ws.is_some() {
        // Upgrade requests carry no body; for Extended CONNECT the stream
        // itself becomes the tunnel after the response.
        drop(body);
        empty()
    } else {
        let counted = Counted { inner: incoming(body), bytes: bytes.clone(), outbound: false, _guard: None }.boxed();
        match &alive {
            Some(alive) => {
                Revocable { inner: Some(counted), held: None, exchange: exchange.clone(), _alive: alive.clone() }
                    .boxed()
            }
            None => counted,
        }
    };
    let path = parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut out = Request::new(req_body);
    *out.method_mut() = if ws == Some(WsKind::H2) { Method::GET } else { parts.method };
    *out.uri_mut() = path.parse().unwrap_or_else(|_| Uri::from_static("/"));
    *out.version_mut() = Version::HTTP_11;
    *out.headers_mut() = headers;

    let Some(guard) = StreamGuard::admit(state, &live) else {
        tracing::warn!(tunnel = %tunnel.id, "too many streams in progress");
        return pages::busy();
    };
    // Ordinary requests reuse an idle origin connection when one is ready.
    let pooled = if ws.is_none() { live.pool.checkout(port) } else { None };
    let reused = pooled.is_some();
    let opened = guarded(&exchange, async {
        match pooled {
            Some(s) => Ok(s),
            None => origin_conn(&live, port, &tunnel.id).await,
        }
    });
    let mut sender = match opened.await {
        Some(Ok(conn)) => exchange.hold_origin(conn),
        Some(Err(page)) => return page,
        None => {
            tracing::debug!(tunnel = %tunnel.id, port, "access ended before the origin was reached");
            return pages::unauthorized();
        }
    };

    let sent = tokio::time::timeout(RESPONSE_HEADER_TIMEOUT, async {
        match sender.try_send_request(out).await {
            Ok(r) => Ok(r),
            // The idle connection closed before the request went out (the
            // origin's keep-alive ran out): retry once on a new connection.
            Err(mut e) if reused && e.message().is_some() => {
                let req = e.take_message().expect("checked above");
                let conn = origin_conn(&live, port, &tunnel.id).await.map_err(SendFail::Page)?;
                sender = exchange.hold_origin(conn);
                sender.send_request(req).await.map_err(SendFail::Origin)
            }
            Err(e) => Err(SendFail::Origin(e.into_error())),
        }
    });
    let Some(sent) = guarded(&exchange, sent).await else {
        tracing::debug!(tunnel = %tunnel.id, port, "access ended before the origin responded");
        return pages::unauthorized();
    };
    let mut resp = match sent {
        Ok(Ok(r)) => r,
        Ok(Err(SendFail::Page(page))) => return page,
        Ok(Err(SendFail::Origin(e))) => {
            tracing::debug!(tunnel = %tunnel.id, port, error = %e, "origin request failed");
            return pages::bad_gateway();
        }
        Err(_) => {
            tracing::debug!(tunnel = %tunnel.id, port, "origin sent no response headers in time");
            return pages::gateway_timeout();
        }
    };
    if ws.is_none() {
        // Back to the pool once this response's body has been read (hyper
        // reports ready only for a keep-alive connection), unless a loss
        // aborted it first; once pooled, a loss no longer touches it.
        let weak = Arc::downgrade(&live);
        let exchange = exchange.clone();
        tokio::spawn(async move {
            if sender.ready().await.is_ok()
                && let Some(driver) = exchange.release_origin()
                && let Some(live) = weak.upgrade().filter(|l| l.has_port(port))
            {
                live.pool.put(port, OriginConn { sender, driver });
            }
        });
    }

    if let (Some(kind), Some(visitor_upgrade)) = (ws, visitor_upgrade) {
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let origin_upgrade = hyper::upgrade::on(&mut resp);
            let reply = upgrade_response(kind, resp.headers());
            let splice_tunnel = tunnel.id.clone();
            let exchange = exchange.clone();
            let alive = alive.clone();
            tokio::spawn(async move {
                let _guard = guard;
                let _alive = alive;
                let splice = async {
                    let (visitor, origin) = match tokio::try_join!(visitor_upgrade, origin_upgrade) {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::debug!(tunnel = %splice_tunnel, error = %e, "websocket upgrade failed");
                            return;
                        }
                    };
                    let mut visitor =
                        Gated { io: TokioIo::new(visitor), exchange: &exchange, side: Side::ToVisitor, bytes: &bytes };
                    let mut origin =
                        Gated { io: TokioIo::new(origin), exchange: &exchange, side: Side::ToOrigin, bytes: &bytes };
                    // Bytes were counted as they were written, also when the splice fails or is cut.
                    if let Err(e) = tokio::io::copy_bidirectional(&mut visitor, &mut origin).await {
                        tracing::debug!(tunnel = %splice_tunnel, error = %e, "websocket splice ended");
                    }
                };
                if guarded(&exchange, splice).await.is_none() {
                    tracing::debug!(tunnel = %splice_tunnel, "access ended; closing websocket");
                }
            });
            return reply;
        }
        // Any 2xx to an Extended CONNECT means "tunnel open" to the browser;
        // an origin that did not upgrade must not produce one.
        if kind == WsKind::H2 && resp.status().is_success() {
            return pages::bad_gateway();
        }
    }

    let (mut parts, body) = resp.into_parts();
    // The visitor connection decides its own version (h1 or h2).
    parts.version = Version::HTTP_11;
    let script = inject_subject
        .filter(|_| injectable(&parts))
        .map(|subject| inject::script(&ice::mint(cfg, &tunnel.id, &subject, cfg.webrtc.browser_ttl_s), &cfg.turn_host));
    let hash = script.as_deref().map(inject::csp_hash);
    let ctx = ResponseCtx { zone: &cfg.preview_zone, tunnel_id: &tunnel.id, frame_ancestors: &cfg.frame_ancestors };
    headers::rewrite_response(&mut parts.headers, &ctx, hash.as_deref());

    let origin_body = incoming(body);
    // An empty body has nothing left to cut; anything else is relayed under
    // the watch, the slot kept in the exchange until hyper drops the body.
    let watched = alive.as_ref().filter(|_| !origin_body.is_end_stream());
    let (body_guard, relay_guard) = if watched.is_some() { (None, Some(guard)) } else { (Some(guard), None) };
    let counted = Counted { inner: origin_body, bytes, outbound: true, _guard: body_guard }.boxed();
    let body = match script {
        Some(s) => {
            parts.headers.remove(header::CONTENT_LENGTH);
            // The body differs per response, so the origin's validators do
            // not describe it, and without them the browser never sends a
            // conditional request for this page.
            parts.headers.remove(header::ETAG);
            parts.headers.remove(header::LAST_MODIFIED);
            Injector::new(counted, inject::tag(&s)).boxed()
        }
        None => counted,
    };
    // Outermost, so nothing buffered upstream (the injector's look-ahead
    // included) reaches the visitor while the watch rechecks.
    let body = match watched {
        Some(alive) => {
            let mut slot = exchange.lock_response();
            // Checked under the slot's lock: a loss either happened before
            // (and is answered here) or takes what is stored now.
            if exchange.is_lost() {
                return pages::unauthorized();
            }
            *slot = Relaying { body: Some(body), _guard: relay_guard };
            drop(slot);
            Relayed { exchange: exchange.clone(), done: false, held: None, _alive: alive.clone() }.boxed()
        }
        None => body,
    };
    Response::from_parts(parts, body)
}

/// Run `inner` as part of `exchange`: paused while its watch rechecks,
/// abandoned (`None`) once access is lost. Unwatched, just `inner`. Its
/// output is checked again once it is ready, so a rotation during that poll
/// holds it until the verdict.
async fn guarded<F: std::future::Future>(exchange: &Exchange, inner: F) -> Option<F::Output> {
    tokio::pin!(inner);
    let mut output = None;
    std::future::poll_fn(|cx| {
        loop {
            if !std::task::ready!(exchange.poll_gate(Side::Driver, cx)) {
                return Poll::Ready(None);
            }
            if output.is_some() {
                return Poll::Ready(output.take());
            }
            output = Some(std::task::ready!(inner.as_mut().poll(cx)));
        }
    })
    .await
}

/// One direction of a WebSocket splice: every write (and the final
/// shutdown) waits for the watch's verdict and fails once access is lost, so
/// bytes read before a rotation are not written after it.
struct Gated<'a, T> {
    io: T,
    exchange: &'a Exchange,
    /// The side whose waker this writer registers.
    side: Side,
    /// Written bytes are counted as they go (toward the visitor: outbound).
    bytes: &'a TunnelBytes,
}

impl<T: Unpin> Gated<'_, T> {
    fn poll_gate(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !std::task::ready!(self.exchange.poll_gate(self.side, cx)) {
            return Poll::Ready(Err(std::io::Error::other(ACCESS_ENDED)));
        }
        Poll::Ready(Ok(()))
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Gated<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Gated<'_, T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        std::task::ready!(self.poll_gate(cx))?;
        let written = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &written {
            self.bytes.count(*n as u64, matches!(self.side, Side::ToVisitor));
        }
        written
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.poll_gate(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[allow(clippy::too_many_arguments)]
fn origin_request_headers(
    mut h: HeaderMap,
    state: &AppState,
    tunnel: &TunnelRow,
    port: u16,
    public_host: &str,
    cookie: Option<HeaderValue>,
    peer: SocketAddr,
    ws: Option<WsKind>,
    inject: bool,
) -> HeaderMap {
    headers::strip_hop_by_hop(&mut h);
    h.remove(header::COOKIE);
    if let Some(c) = cookie {
        h.insert(header::COOKIE, c);
    }
    // hyper already answered any `100-continue` toward the visitor.
    h.remove(header::EXPECT);

    h.remove(header::FORWARDED);
    let spoofable: Vec<HeaderName> = h.keys().filter(|n| n.as_str().starts_with("x-forwarded-")).cloned().collect();
    for name in &spoofable {
        h.remove(name);
    }
    h.remove("x-real-ip");
    h.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    if let Ok(v) = HeaderValue::from_str(public_host) {
        h.insert(HeaderName::from_static("x-forwarded-host"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&peer.ip().to_canonical().to_string()) {
        h.insert(HeaderName::from_static("x-forwarded-for"), v);
    }

    let host = match tunnel.host_header {
        HostHeaderMode::Rewrite => format!("localhost:{port}"),
        HostHeaderMode::Preserve => public_host.to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&host) {
        h.insert(header::HOST, v);
    }
    if tunnel.host_header == HostHeaderMode::Rewrite {
        headers::rewrite_request_origin(&mut h, &state.config.preview_zone, &tunnel.id);
    }

    if inject {
        // The injector needs uncompressed HTML.
        h.remove(header::ACCEPT_ENCODING);
        // A 304 would revalidate a cached page whose injected script (and
        // credential) is stale and whose CSP hash no longer matches; always
        // fetch the full document.
        h.remove(header::IF_NONE_MATCH);
        h.remove(header::IF_MODIFIED_SINCE);
        // Injection changes byte offsets, so always request the whole body.
        h.remove(header::RANGE);
        h.remove(header::IF_RANGE);
    }

    if let Some(kind) = ws {
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        if kind == WsKind::H2 {
            // RFC 8441 requests have no key; the origin speaks RFC 6455 and needs one.
            h.insert(header::SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
            let key = STANDARD.encode(rand::random::<[u8; 16]>());
            h.insert(header::SEC_WEBSOCKET_KEY, HeaderValue::from_str(&key).expect("base64 is a valid header value"));
        }
    }
    h
}

pub fn is_websocket<B>(req: &Request<B>) -> bool {
    websocket_kind(req).is_some()
}

fn websocket_kind<B>(req: &Request<B>) -> Option<WsKind> {
    if *req.method() == Method::CONNECT {
        return req
            .extensions()
            .get::<hyper::ext::Protocol>()
            .filter(|p| p.as_str().eq_ignore_ascii_case("websocket"))
            .map(|_| WsKind::H2);
    }
    let h1 = req.version() == Version::HTTP_11 || req.version() == Version::HTTP_10;
    let connection_upgrade = req
        .headers()
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    let upgrade_ws = header_str(req.headers().get(header::UPGRADE))
        .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("websocket")));
    (h1 && *req.method() == Method::GET && connection_upgrade && upgrade_ws).then_some(WsKind::H1)
}

/// Top-level or iframe navigation (`fetch()` and htmx fragments are excluded).
fn is_navigation(headers: &HeaderMap) -> bool {
    header_str(headers.get("sec-fetch-dest"))
        .is_some_and(|d| matches!(d.trim().to_ascii_lowercase().as_str(), "document" | "iframe" | "frame"))
}

/// Non-empty, uncompressed `text/html` with a body.
fn injectable(parts: &Parts) -> bool {
    if parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED
        || parts.status.is_informational()
    {
        return false;
    }
    let html = header_str(parts.headers.get(header::CONTENT_TYPE))
        .is_some_and(|ct| ct.split(';').next().unwrap_or_default().trim().eq_ignore_ascii_case("text/html"));
    let identity = parts.headers.get_all(header::CONTENT_ENCODING).iter().all(|v| {
        v.to_str().is_ok_and(|e| e.split(',').all(|t| t.trim().is_empty() || t.trim().eq_ignore_ascii_case("identity")))
    });
    let empty = header_str(parts.headers.get(header::CONTENT_LENGTH)).is_some_and(|l| l.trim() == "0");
    html && identity && !empty
}

fn upgrade_response(kind: WsKind, origin: &HeaderMap) -> Response<Body> {
    let mut resp = Response::new(empty());
    *resp.status_mut() = match kind {
        WsKind::H1 => StatusCode::SWITCHING_PROTOCOLS,
        WsKind::H2 => StatusCode::OK,
    };
    let h = resp.headers_mut();
    for name in [header::SEC_WEBSOCKET_PROTOCOL, header::SEC_WEBSOCKET_EXTENSIONS] {
        if let Some(v) = origin.get(&name) {
            h.insert(name, v.clone());
        }
    }
    if kind == WsKind::H1 {
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        // The visitor's key was forwarded unchanged, so the origin's accept matches.
        if let Some(v) = origin.get(header::SEC_WEBSOCKET_ACCEPT) {
            h.insert(header::SEC_WEBSOCKET_ACCEPT, v.clone());
        }
    }
    resp
}

enum SendFail {
    /// No new connection could be opened; the page says why.
    Page(Response<Body>),
    Origin(hyper::Error),
}

/// A new HTTP/1.1 connection to `port`: a Yamux stream the client splices
/// to the loopback origin. `Err` is the page to show the visitor.
// The error is an HTTP response returned directly to the visitor; boxing would
// allocate only to immediately unbox it at the call site.
#[allow(clippy::result_large_err)]
async fn origin_conn(live: &LiveTunnel, port: u16, tunnel_id: &str) -> Result<OriginConn, Response<Body>> {
    let stream = match tokio::time::timeout(STREAM_OPEN_TIMEOUT, open_stream(live, port)).await {
        Ok(Opened::Ready(s)) => s,
        Ok(Opened::Refused) => return Err(pages::app_not_running(port)),
        Ok(Opened::Offline) | Err(_) => return Err(pages::offline()),
    };
    let (sender, conn) = match hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(stream)).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(tunnel = %tunnel_id, port, error = %e, "origin handshake failed");
            return Err(pages::bad_gateway());
        }
    };
    let conn_tunnel = tunnel_id.to_string();
    let driver = tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(tunnel = %conn_tunnel, error = %e, "origin connection error");
        }
    })
    .abort_handle();
    Ok(OriginConn { sender, driver })
}

enum Opened {
    Ready(StreamHandle),
    Refused,
    Offline,
}

/// Open a Yamux stream, send the port preamble, and read the client's verdict.
async fn open_stream(live: &LiveTunnel, port: u16) -> Opened {
    let mut control = live.control.clone();
    let Ok(mut stream) = control.open_stream().await else {
        return Opened::Offline;
    };
    if stream.write_all(&encode_preamble(port)).await.is_err() || stream.flush().await.is_err() {
        return Opened::Offline;
    }
    let mut status = [0u8; 1];
    if stream.read_exact(&mut status).await.is_err() {
        return Opened::Offline;
    }
    match status[0] {
        STREAM_OK => Opened::Ready(stream),
        STREAM_REFUSED => Opened::Refused,
        // STREAM_NOT_EXPOSED and anything unknown.
        _ => Opened::Offline,
    }
}

/// One visitor request or WebSocket in progress, counted globally (metrics)
/// and against the tunnel's [`MAX_STREAMS_PER_TUNNEL`].
struct StreamGuard(Arc<AppState>, Arc<LiveTunnel>);

impl StreamGuard {
    fn admit(state: &Arc<AppState>, live: &Arc<LiveTunnel>) -> Option<Self> {
        if live.streams.fetch_add(1, Ordering::AcqRel) >= MAX_STREAMS_PER_TUNNEL {
            live.streams.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        state.metrics.stream_opened();
        Some(Self(state.clone(), live.clone()))
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.metrics.stream_closed();
        self.1.streams.fetch_sub(1, Ordering::AcqRel);
    }
}

const ACCESS_ENDED: &str = "visitor access ended";

/// What one proxied exchange shares with its watch task (see [`forward`]).
#[derive(Default)]
struct Exchange {
    /// Cancelled at a loss, before `rechecking` ends and wakes every side.
    cut: tokio_util::sync::CancellationToken,
    rechecking: Rechecking,
    /// The response body and stream slot while [`Relayed`] owes them to the
    /// visitor; the watch takes the body at a loss.
    response: std::sync::Mutex<Relaying>,
    /// The task driving this exchange's origin connection until it is back
    /// in the pool; aborted at a loss, which drops the origin stream and the
    /// request body even when the origin stopped reading the upload.
    origin: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
}

#[derive(Default)]
struct Relaying {
    body: Option<Body>,
    /// Released with the slot when hyper drops [`Relayed`], also after a loss:
    /// hyper may still hold a frame for a visitor that grants no window, and
    /// such lingering streams stay bounded by [`MAX_STREAMS_PER_TUNNEL`].
    _guard: Option<StreamGuard>,
}

impl Exchange {
    fn lock_response(&self) -> std::sync::MutexGuard<'_, Relaying> {
        self.response.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_origin(&self) -> std::sync::MutexGuard<'_, Option<tokio::task::AbortHandle>> {
        self.origin.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Make `conn` this exchange's origin connection (aborted at once if
    /// access is already lost) and hand back its sender.
    fn hold_origin(&self, conn: OriginConn) -> hyper::client::conn::http1::SendRequest<Body> {
        let mut origin = self.lock_origin();
        // Checked under the lock `lose` takes after cancelling `cut`.
        if self.cut.is_cancelled() {
            conn.driver.abort();
        } else if let Some(previous) = origin.replace(conn.driver) {
            previous.abort();
        }
        conn.sender
    }

    /// The origin connection's driver, for pooling; `None` once a loss
    /// aborted it.
    fn release_origin(&self) -> Option<tokio::task::AbortHandle> {
        self.lock_origin().take()
    }

    /// Access is lost: mark it, release the origin stream and connection now
    /// (whether or not the visitor is reading or the origin reading the
    /// upload), then wake every side. The slot stays until hyper drops
    /// [`Relayed`].
    fn lose(&self) {
        self.cut.cancel();
        let released = self.lock_response().body.take();
        drop(released);
        if let Some(driver) = self.release_origin() {
            driver.abort();
        }
        self.rechecking.finish_lost();
    }

    /// Whether `side` may go on: pending (with its waker registered, also for
    /// a later loss) while the watch rechecks, then `false` once access is lost.
    fn poll_gate(&self, side: Side, cx: &mut Context<'_>) -> Poll<bool> {
        if self.rechecking.poll_idle(side, cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(!self.cut.is_cancelled())
    }

    fn is_lost(&self) -> bool {
        self.cut.is_cancelled()
    }

    /// Access stands and no recheck is in progress.
    fn is_settled(&self) -> bool {
        !self.cut.is_cancelled() && self.rechecking.is_settled()
    }

    /// Watch `grant` in a task of its own, so enforcement never depends on the
    /// visitor reading or the origin sending. It lives as long as any part of
    /// the exchange holds the returned [`Alive`], so a finished response cannot
    /// leave an upload unwatched, and nothing outlives the exchange.
    fn spawn_watch(
        self: Arc<Self>,
        state: &Arc<AppState>,
        tunnel_id: &str,
        grant: crate::edge::gate::Authorization,
    ) -> Alive {
        let (alive, mut gone) = tokio::sync::mpsc::channel::<()>(1);
        // Before the task first runs, so a rotation right now already pauses.
        self.rechecking.follow(&grant.cancel);
        let state = state.clone();
        let tunnel_id = tunnel_id.to_string();
        tokio::spawn(async move {
            tokio::select! {
                () = crate::edge::gate::watch(&state, &tunnel_id, grant, &self.rechecking) => {
                    self.lose();
                    state.metrics.access_cut();
                }
                // Nothing is ever sent: `None` once every `Alive` is dropped.
                _ = gone.recv() => {}
            }
        });
        alive
    }
}

/// Keeps an exchange's watch task running; it ends once every clone is gone.
type Alive = tokio::sync::mpsc::Sender<()>;

/// The visitor's request body: paused while the watch rechecks, failing once
/// access is lost, which aborts the origin exchange so the sandbox can tell a
/// cut upload from a complete one.
struct Revocable {
    inner: Option<Body>,
    /// A result polled while a rotation landed, held until the verdict.
    held: Option<Option<Result<Frame<Bytes>, BoxError>>>,
    exchange: Arc<Exchange>,
    _alive: Alive,
}

impl HttpBody for Revocable {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        loop {
            if this.inner.is_none() {
                return Poll::Ready(None);
            }
            // Registered on every poll, so a loss wakes this side even while
            // it waits on the visitor.
            if !std::task::ready!(this.exchange.poll_gate(Side::ToOrigin, cx)) {
                this.inner = None;
                this.held = None;
                return Poll::Ready(Some(Err(ACCESS_ENDED.into())));
            }
            // Checked again after the poll that produced it (the loop).
            if let Some(polled) = this.held.take() {
                if polled.is_none() {
                    this.inner = None;
                }
                return Poll::Ready(polled);
            }
            let inner = this.inner.as_mut().expect("checked above");
            this.held = Some(std::task::ready!(Pin::new(inner).poll_frame(cx)));
        }
    }

    /// Hyper may finish the upload on this alone, without polling again, so
    /// an end counts only while the grant stands (as a polled one does).
    fn is_end_stream(&self) -> bool {
        match &self.inner {
            None => true,
            Some(inner) => self.held.is_none() && inner.is_end_stream() && self.exchange.is_settled(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Some(inner) => with_held(inner.size_hint(), &self.held),
            None => SizeHint::with_exact(0),
        }
    }
}

/// `hint` for what is still to be polled, plus a data frame `held` back.
fn with_held(mut hint: SizeHint, held: &Option<Option<Result<Frame<Bytes>, BoxError>>>) -> SizeHint {
    if let Some(Some(Ok(frame))) = held
        && let Some(data) = frame.data_ref()
    {
        let len = data.len() as u64;
        // Upper first, so the bounds never cross.
        if let Some(upper) = hint.upper() {
            hint.set_upper(upper.saturating_add(len));
        }
        hint.set_lower(hint.lower().saturating_add(len));
    }
    hint
}

/// The response body toward the visitor, read from the exchange's slot. It
/// relays nothing while the watch rechecks and fails (aborting the visitor's
/// connection or stream) instead of ending cleanly once access is lost; the
/// watch has then already released the origin stream. Either way it keeps the
/// slot until hyper drops it, as an unwatched body would.
struct Relayed {
    exchange: Arc<Exchange>,
    done: bool,
    /// A result polled while a rotation landed, held until the verdict.
    held: Option<Option<Result<Frame<Bytes>, BoxError>>>,
    _alive: Alive,
}

impl HttpBody for Relayed {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            // `lose` cancels `cut` before it empties the slot.
            if !std::task::ready!(this.exchange.poll_gate(Side::ToVisitor, cx)) {
                this.done = true;
                this.held = None;
                return Poll::Ready(Some(Err(ACCESS_ENDED.into())));
            }
            // Checked again after the poll that produced it (the loop), so a
            // rotation during that poll holds the frame or the end.
            if let Some(polled) = this.held.take() {
                match &polled {
                    None => {
                        this.done = true;
                        // The origin stream is finished; the slot stays until drop.
                        let finished = this.exchange.lock_response().body.take();
                        drop(finished);
                    }
                    Some(Err(_)) => this.done = true,
                    Some(Ok(_)) => {}
                }
                return Poll::Ready(polled);
            }
            let mut slot = this.exchange.lock_response();
            let Some(body) = slot.body.as_mut() else {
                this.done = true;
                return Poll::Ready(Some(Err(ACCESS_ENDED.into())));
            };
            let polled = std::task::ready!(Pin::new(body).poll_frame(cx));
            drop(slot);
            this.held = Some(polled);
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        if self.done {
            return SizeHint::with_exact(0);
        }
        // Unknown once a loss took the body: hyper must not encode a cut
        // response as a complete empty one (`Content-Length: 0`).
        let hint = self.exchange.lock_response().body.as_ref().map(HttpBody::size_hint).unwrap_or_default();
        with_held(hint, &self.held)
    }
}

impl Drop for Relayed {
    fn drop(&mut self) {
        let released = std::mem::take(&mut *self.exchange.lock_response());
        drop(released);
    }
}

/// Counts data bytes into the tunnel's metrics; frames pass through as-is.
struct Counted {
    inner: Body,
    bytes: Arc<TunnelBytes>,
    /// Origin → visitor when true.
    outbound: bool,
    _guard: Option<StreamGuard>,
}

impl HttpBody for Counted {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let poll = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &poll
            && let Some(data) = frame.data_ref()
        {
            this.bytes.count(data.len() as u64, this.outbound);
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(status: StatusCode, headers: &[(&'static str, &'static str)]) -> Parts {
        let mut b = Response::builder().status(status);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn injectable_rules() {
        assert!(injectable(&parts(StatusCode::OK, &[("content-type", "text/html; charset=utf-8")])));
        assert!(!injectable(&parts(StatusCode::OK, &[("content-type", "application/json")])));
        assert!(!injectable(&parts(StatusCode::OK, &[("content-type", "text/html"), ("content-encoding", "gzip")])));
        assert!(!injectable(&parts(StatusCode::NOT_MODIFIED, &[("content-type", "text/html")])));
        assert!(!injectable(&parts(StatusCode::OK, &[("content-type", "text/html"), ("content-length", "0")])));
    }

    #[test]
    fn detects_h1_websocket() {
        let req = Request::builder()
            .method(Method::GET)
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .body(())
            .unwrap();
        assert_eq!(websocket_kind(&req), Some(WsKind::H1));
        let plain = Request::builder().method(Method::GET).body(()).unwrap();
        assert_eq!(websocket_kind(&plain), None);
    }

    #[tokio::test]
    async fn public_watch_follows_rotated_epochs_until_access_becomes_protected() {
        use crate::db::{Access, AccessMode, TunnelPatch};
        use crate::edge::gate::Authorization;

        for mode in [AccessMode::Password, AccessMode::Link] {
            let state = crate::listener::tests::test_state(&[]);
            let tunnel = crate::listener::tests::create_tunnel(&state, AccessMode::Public).await;
            let (transport, _peer) = tokio::io::duplex(64);
            let session = tunnel_protocol::mux::Session::new_server(transport);
            let (ctrl_tx, _ctrl_rx) = tokio::sync::mpsc::channel(1);
            state.registry.insert(Arc::new(LiveTunnel {
                conn_id: 1,
                tunnel_id: tunnel.id.clone(),
                control: session.control(),
                ports: Default::default(),
                ctrl_tx,
                cancel: tokio_util::sync::CancellationToken::new(),
                connected_at: crate::tokens::now(),
                streams: Default::default(),
                pool: Default::default(),
                token_hash: String::new(),
            }));
            state.tunnel(&tunnel.id).await.unwrap();
            let grant = Authorization {
                session_hash: None,
                candidates: Default::default(),
                expires_at: None,
                cancel: state.registry.gate_epoch(&tunnel.id),
            };
            let (mut visitor, mut origin) = tokio::io::duplex(64);
            let splice = async move {
                let mut byte = [0];
                let _ = origin.read(&mut byte).await;
            };
            let rechecking = Rechecking::default();
            let watched = async {
                tokio::select! {
                    () = crate::edge::gate::watch(&state, &tunnel.id, grant, &rechecking) => {}
                    () = splice => {}
                }
            };
            tokio::pin!(watched);
            assert!(futures_util::poll!(&mut watched).is_pending());
            // A rotation that leaves the tunnel public must retain the splice
            // and start watching the new epoch (the cached lookup is ready).
            state.registry.rotate_gate_epoch(&tunnel.id);
            assert!(futures_util::poll!(&mut watched).is_pending());
            state
                .db
                .update_tunnel(
                    tunnel.id.clone(),
                    TunnelPatch {
                        access: Some(Access {
                            mode,
                            password_user: (mode == AccessMode::Password).then(|| "visitor".into()),
                            password_hash: (mode == AccessMode::Password).then(|| "test-placeholder".into()),
                        }),
                        ..Default::default()
                    },
                )
                .await
                .unwrap()
                .unwrap();
            state.invalidate_tunnel(&tunnel.id);
            state.invalidate_sessions();
            state.registry.rotate_gate_epoch(&tunnel.id);
            tokio::time::timeout(Duration::from_secs(1), &mut watched)
                .await
                .expect("public splice must close when access becomes protected");
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), visitor.read(&mut byte)).await.unwrap().unwrap(),
                0
            );
        }
    }

    fn data(frame: Option<Result<Frame<Bytes>, BoxError>>) -> Bytes {
        frame.expect("a frame").expect("not an error").into_data().expect("data")
    }

    /// A body fed by the returned sender, one chunk per frame.
    fn fed() -> (tokio::sync::mpsc::Sender<Bytes>, Body) {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
        let body = http_body_util::StreamBody::new(futures_util::stream::unfold(rx, |mut rx| async {
            let chunk = rx.recv().await?;
            Some((Ok::<_, BoxError>(Frame::data(chunk)), rx))
        }))
        .boxed();
        (tx, body)
    }

    #[tokio::test]
    async fn relayed_pauses_during_a_recheck_and_never_fakes_an_end() {
        let relayed = |body| {
            let exchange = Arc::new(Exchange::default());
            *exchange.lock_response() = Relaying { body: Some(body), _guard: None };
            let (alive, _) = tokio::sync::mpsc::channel(1);
            (exchange.clone(), Relayed { exchange, done: false, held: None, _alive: alive })
        };
        let (tx, body) = fed();
        let (exchange, mut body) = relayed(body);
        tx.send(Bytes::from_static(b"one")).await.unwrap();
        assert_eq!(data(body.frame().await), &b"one"[..]);
        tx.send(Bytes::from_static(b"ready")).await.unwrap();
        exchange.rechecking.start();
        assert!(futures_util::poll!(body.frame()).is_pending(), "relayed during the recheck");
        exchange.rechecking.end();
        assert_eq!(data(body.frame().await), &b"ready"[..]);

        // Waiting on the origin, then lost: woken, and a failure, not an end.
        tx.send(Bytes::from_static(b"late")).await.unwrap();
        let waiting = tokio::spawn(async move {
            let first = body.frame().await.map(|f| f.is_err());
            (first, body.frame().await.is_none(), body)
        });
        exchange.rechecking.start();
        tokio::task::yield_now().await;
        exchange.lose();
        let (first, then_none, body) =
            tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("woken at the loss").unwrap();
        assert_eq!(first, Some(true), "the frame ready at the loss must not be relayed");
        assert!(then_none);
        assert!(exchange.lock_response().body.is_none(), "the loss releases the origin body");
        assert!(tx.is_closed());
        drop(body);

        // A rotated epoch pauses at once, before any recheck has started.
        let (tx, body) = fed();
        let (exchange, mut body) = relayed(body);
        let epoch = tokio_util::sync::CancellationToken::new();
        exchange.rechecking.follow(&epoch);
        tx.send(Bytes::from_static(b"rotated")).await.unwrap();
        epoch.cancel();
        assert!(futures_util::poll!(body.frame()).is_pending(), "relayed after the rotation, before a verdict");
        exchange.rechecking.follow(&tokio_util::sync::CancellationToken::new());
        exchange.rechecking.end();
        assert_eq!(data(body.frame().await), &b"rotated"[..]);
        drop(body);

        // Only the origin's own end is clean.
        let (tx, body) = fed();
        let (exchange, mut body) = relayed(body);
        drop(tx);
        assert!(body.frame().await.is_none());
        drop(body);
        assert!(exchange.lock_response().body.is_none(), "dropping the body empties the slot");
    }

    /// Rotates `epoch` while producing its one result, as a revocation on
    /// another worker can in the middle of a poll.
    struct RotatingBody(tokio_util::sync::CancellationToken, Option<Option<Result<Frame<Bytes>, BoxError>>>);

    impl HttpBody for RotatingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            self.0.cancel();
            Poll::Ready(self.1.take().unwrap_or(None))
        }

        // A fixed length: what is left to produce.
        fn size_hint(&self) -> SizeHint {
            let left = match &self.1 {
                Some(Some(Ok(frame))) => frame.data_ref().map_or(0, |d| d.len() as u64),
                _ => 0,
            };
            SizeHint::with_exact(left)
        }
    }

    /// The verdict after a rotation: kept (a new epoch, recheck passed) or lost.
    fn settle(exchange: &Exchange, keep: bool) {
        if keep {
            exchange.rechecking.follow(&tokio_util::sync::CancellationToken::new());
            exchange.rechecking.end();
        } else {
            exchange.lose();
        }
    }

    #[tokio::test]
    async fn a_rotation_during_a_poll_holds_its_result_until_the_verdict() {
        for keep in [true, false] {
            for end in [false, true] {
                let result = || if end { None } else { Some(Ok(Frame::data(Bytes::from_static(b"x")))) };
                let check = |got: Option<Result<Frame<Bytes>, BoxError>>| match (keep, end, got) {
                    (true, true, None) => {}
                    (true, false, Some(Ok(f))) => assert_eq!(f.into_data().unwrap(), &b"x"[..]),
                    (false, _, Some(Err(_))) => {}
                    (keep, end, got) => panic!("keep={keep} end={end}: {:?}", got.map(|r| r.is_ok())),
                };

                // Toward the visitor.
                let exchange = Arc::new(Exchange::default());
                let epoch = tokio_util::sync::CancellationToken::new();
                exchange.rechecking.follow(&epoch);
                *exchange.lock_response() =
                    Relaying { body: Some(RotatingBody(epoch, Some(result())).boxed()), _guard: None };
                let (alive, _) = tokio::sync::mpsc::channel(1);
                let mut body = Relayed { exchange: exchange.clone(), done: false, held: None, _alive: alive };
                assert!(futures_util::poll!(body.frame()).is_pending(), "relayed what a rotation's poll produced");
                assert_eq!(body.size_hint().exact(), Some(u64::from(!end)), "a held frame is still owed");
                settle(&exchange, keep);
                check(body.frame().await);

                // Toward the origin.
                let exchange = Arc::new(Exchange::default());
                let epoch = tokio_util::sync::CancellationToken::new();
                exchange.rechecking.follow(&epoch);
                let (alive, _) = tokio::sync::mpsc::channel(1);
                let inner = RotatingBody(epoch, Some(result())).boxed();
                let mut body = Revocable { inner: Some(inner), held: None, exchange: exchange.clone(), _alive: alive };
                assert!(futures_util::poll!(body.frame()).is_pending(), "uploaded what a rotation's poll produced");
                assert!(!body.is_end_stream(), "a held result is not the end yet");
                assert_eq!(body.size_hint().exact(), Some(u64::from(!end)), "a held frame is still owed");
                settle(&exchange, keep);
                check(body.frame().await);
            }

            // The request driver (origin connect, headers).
            let exchange = Arc::new(Exchange::default());
            let epoch = tokio_util::sync::CancellationToken::new();
            exchange.rechecking.follow(&epoch);
            let mut driven = Box::pin(guarded(&exchange, async {
                epoch.cancel();
                7
            }));
            assert!(futures_util::poll!(driven.as_mut()).is_pending(), "answered from a rotation's poll");
            settle(&exchange, keep);
            assert_eq!(driven.await, keep.then_some(7));

            // A WebSocket direction: read before a rotation, never written after it.
            let exchange = Arc::new(Exchange::default());
            let epoch = tokio_util::sync::CancellationToken::new();
            exchange.rechecking.follow(&epoch);
            let (mut far, near) = tokio::io::duplex(64);
            let source = futures_util::stream::once(async {
                epoch.cancel();
                Ok::<_, std::io::Error>(Bytes::from_static(b"x"))
            });
            let mut source = tokio_util::io::StreamReader::new(Box::pin(source));
            let bytes = TunnelBytes::default();
            let mut dest = Gated { io: near, exchange: &exchange, side: Side::ToVisitor, bytes: &bytes };
            let mut copy = Box::pin(tokio::io::copy(&mut source, &mut dest));
            assert!(futures_util::poll!(copy.as_mut()).is_pending());
            settle(&exchange, keep);
            assert_eq!(copy.await.is_ok(), keep);
            drop(dest);
            // Counted as written: one byte toward the visitor, or none when cut.
            assert_eq!(bytes.totals(), (0, u64::from(keep)));
            let mut seen = Vec::new();
            far.read_to_end(&mut seen).await.unwrap();
            assert_eq!(seen, if keep { &b"x"[..] } else { &b""[..] }, "keep={keep}");
        }
    }

    #[tokio::test]
    async fn an_upload_end_is_not_reported_while_a_rotation_awaits_its_verdict() {
        for keep in [true, false] {
            let exchange = Arc::new(Exchange::default());
            let epoch = tokio_util::sync::CancellationToken::new();
            exchange.rechecking.follow(&epoch);
            let (alive, _) = tokio::sync::mpsc::channel(1);
            let inner = http_body_util::Full::new(Bytes::from_static(b"last")).map_err(BoxError::from).boxed();
            let mut body = Revocable { inner: Some(inner), held: None, exchange: exchange.clone(), _alive: alive };
            assert_eq!(data(body.frame().await), &b"last"[..]);
            assert!(body.is_end_stream(), "an upload whose grant stands ends with its last frame");
            // Rotated after the last frame went out, before hyper asks.
            epoch.cancel();
            assert!(!body.is_end_stream(), "upload end reported before the verdict");
            settle(&exchange, keep);
            if keep {
                assert!(body.is_end_stream());
                assert!(body.frame().await.is_none());
            } else {
                assert!(!body.is_end_stream());
                assert!(matches!(body.frame().await, Some(Err(_))), "a cut upload must not end cleanly");
            }
        }
    }

    #[tokio::test]
    async fn a_body_lost_before_its_head_is_encoded_never_looks_complete() {
        // Lost between `forward` installing the body and hyper encoding the
        // response head.
        let lost = || {
            let exchange = Arc::new(Exchange::default());
            let (_tx, body) = fed();
            *exchange.lock_response() = Relaying { body: Some(body), _guard: None };
            exchange.lose();
            let (alive, _) = tokio::sync::mpsc::channel(1);
            Relayed { exchange, done: false, held: None, _alive: alive }
        };
        let body = lost();
        assert_eq!(body.size_hint().exact(), None, "a cut body has no known length");
        assert!(!body.is_end_stream());

        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |_req| {
                let body = lost().boxed();
                async move { Ok::<_, std::convert::Infallible>(Response::new(body)) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(server), svc).await;
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(connection);
        let complete = match sender.send_request(Request::new(empty())).await {
            Err(_) => false,
            Ok(resp) => {
                assert_ne!(resp.headers().get(header::CONTENT_LENGTH).map(|v| v.as_bytes()), Some(&b"0"[..]));
                tokio::time::timeout(Duration::from_secs(5), resp.into_body().collect()).await.expect("ends").is_ok()
            }
        };
        assert!(!complete, "a cut response must not reach the visitor as a complete empty one");
    }

    #[tokio::test]
    async fn revocable_upload_pauses_during_a_recheck_and_wakes_to_fail_at_a_loss() {
        let (tx, inner) = fed();
        let exchange = Arc::new(Exchange::default());
        let (alive, _) = tokio::sync::mpsc::channel(1);
        let mut body = Revocable { inner: Some(inner), held: None, exchange: exchange.clone(), _alive: alive };
        tx.send(Bytes::from_static(b"one")).await.unwrap();
        assert_eq!(data(body.frame().await), &b"one"[..]);
        tx.send(Bytes::from_static(b"during")).await.unwrap();
        exchange.rechecking.start();
        assert!(futures_util::poll!(body.frame()).is_pending(), "upload relayed during the recheck");
        exchange.rechecking.end();
        assert_eq!(data(body.frame().await), &b"during"[..]);

        // Idle (waiting on the visitor), then lost: it must wake and fail.
        let waiting = tokio::spawn(async move { body.frame().await.map(|f| f.is_err()) });
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!waiting.is_finished());
        exchange.lose();
        let ended = tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("woken at the loss").unwrap();
        assert_eq!(ended, Some(true));
        drop(tx);
    }

    #[tokio::test]
    async fn watch_task_lives_exactly_as_long_as_the_exchange() {
        let state = crate::listener::tests::test_state(&[]);
        let tunnel = crate::listener::tests::create_tunnel(&state, crate::db::AccessMode::Public).await;
        let (transport, _peer) = tokio::io::duplex(64);
        let session = tunnel_protocol::mux::Session::new_server(transport);
        let (ctrl_tx, _ctrl_rx) = tokio::sync::mpsc::channel(1);
        state.registry.insert(Arc::new(LiveTunnel {
            conn_id: 1,
            tunnel_id: tunnel.id.clone(),
            control: session.control(),
            ports: Default::default(),
            ctrl_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            connected_at: crate::tokens::now(),
            streams: Default::default(),
            pool: Default::default(),
            token_hash: String::new(),
        }));
        let grant = || crate::edge::gate::Authorization {
            session_hash: None,
            candidates: Default::default(),
            expires_at: None,
            cancel: state.registry.gate_epoch(&tunnel.id),
        };
        // Every holder gone: the task ends without a loss.
        let exchange = Arc::new(Exchange::default());
        let alive = exchange.clone().spawn_watch(&state, &tunnel.id, grant());
        let held = alive.clone();
        drop(alive);
        tokio::task::yield_now().await;
        assert!(!held.is_closed(), "a holder keeps the watch running");
        drop(held);
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::strong_count(&exchange) > 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("watch task ended with its exchange");
        assert!(!exchange.cut.is_cancelled());

        // A loss while held: cut, and the task ends.
        let exchange = Arc::new(Exchange::default());
        let alive = exchange.clone().spawn_watch(&state, &tunnel.id, grant());
        state.registry.remove(&tunnel.id);
        tokio::time::timeout(Duration::from_secs(5), exchange.cut.cancelled()).await.expect("lost");
        tokio::time::timeout(Duration::from_secs(5), alive.closed()).await.expect("watch task ended at the loss");
    }

    #[test]
    fn navigation_dest() {
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-dest", HeaderValue::from_static("iframe"));
        assert!(is_navigation(&h));
        h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
        assert!(!is_navigation(&h));
    }

    #[tokio::test]
    async fn injection_drops_range_and_validators() {
        let state = crate::listener::tests::test_state(&[]);
        let tunnel = crate::listener::tests::create_tunnel(&state, crate::db::AccessMode::Public).await;
        let mut h = HeaderMap::new();
        for (name, value) in [
            (header::RANGE, "bytes=0-99"),
            (header::IF_RANGE, "\"version\""),
            (header::IF_NONE_MATCH, "\"version\""),
            (header::IF_MODIFIED_SINCE, "Mon, 09 Nov 2026 00:00:00 GMT"),
            (header::ACCEPT_ENCODING, "gzip"),
        ] {
            h.insert(name, HeaderValue::from_static(value));
        }
        for inject in [false, true] {
            let out = origin_request_headers(
                h.clone(),
                &state,
                &tunnel,
                3000,
                "3000-abcdefghij.previews.example.com",
                None,
                "127.0.0.1:1234".parse().unwrap(),
                None,
                inject,
            );
            for name in h.keys() {
                assert_eq!(out.contains_key(name), !inject, "{name}");
            }
        }
    }
}
