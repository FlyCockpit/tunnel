//! Public listeners: `:443` (SNI `turn_host` → TURN over TLS to the built-in relay, else TLS + HTTP/1.1 and
//! HTTP/2 routed by `Host`) and `:80` (redirect to HTTPS only).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use http::{HeaderValue, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tunnel_protocol::CONNECT_PATH;

use crate::sni::{self, SniPeek};
use crate::state::AppState;
use crate::util::{Body, BoxError, empty, request_host, text_response};
use crate::{api, control, edge, edge::gatehost, edge::pages, tls};

const SNI_PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Lowercased names used for routing, computed once.
struct Hosts {
    /// The web UI host, if configured (it also serves the API).
    ui: Option<String>,
    api: String,
    tunnel: String,
    turn: String,
    /// `<preview_zone>`: sign-in pages (see `gatehost`).
    zone: String,
    /// `.<preview_zone>`
    zone_suffix: String,
}

impl Hosts {
    fn new(state: &AppState) -> Self {
        let cfg = &state.config;
        Self {
            ui: cfg.ui_host.as_ref().map(|h| h.to_ascii_lowercase()),
            api: cfg.api_host.to_ascii_lowercase(),
            tunnel: cfg.tunnel_host.to_ascii_lowercase(),
            turn: cfg.turn_host.to_ascii_lowercase(),
            zone: cfg.preview_zone.to_ascii_lowercase(),
            zone_suffix: format!(".{}", cfg.preview_zone.to_ascii_lowercase()),
        }
    }

    fn preview_label<'a>(&self, host: &'a str) -> Option<&'a str> {
        host.strip_suffix(&self.zone_suffix).filter(|l| !l.is_empty())
    }

    fn is_ours(&self, host: &str) -> bool {
        self.ui.as_deref() == Some(host)
            || host == self.api
            || host == self.tunnel
            || host == self.zone
            || self.preview_label(host).is_some()
    }
}

pub async fn run_https(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = state.config.listen_https;
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    let acceptor = TlsAcceptor::from(Arc::new(tls::server_config(state.certs.clone())));
    let turn_acceptor = TlsAcceptor::from(Arc::new(tls::turn_server_config(state.certs.clone())));
    let hosts = Arc::new(Hosts::new(&state));
    tracing::info!(%addr, "https listener started");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // EMFILE and friends are transient; never take the listener down.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let peer = canonical(peer);
        let state = state.clone();
        let acceptor = acceptor.clone();
        let turn_acceptor = turn_acceptor.clone();
        let hosts = hosts.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_https_conn(state, acceptor, turn_acceptor, hosts, tcp, peer).await {
                tracing::debug!(%peer, error = %e, "https connection ended with error");
            }
        });
    }
}

/// `[::]` listeners report IPv4 peers as `::ffff:a.b.c.d`.
fn canonical(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

async fn serve_https_conn(
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
    turn_acceptor: TlsAcceptor,
    hosts: Arc<Hosts>,
    tcp: TcpStream,
    peer: SocketAddr,
) -> Result<(), BoxError> {
    let _ = tcp.set_nodelay(true);

    let webrtc = &state.config.webrtc;
    if let (true, Some(relay)) = (webrtc.enabled, state.turn.get()) {
        let to_turn = match sni::peek_sni(&tcp, SNI_PEEK_TIMEOUT).await? {
            SniPeek::Sni(name) => name == hosts.turn,
            SniPeek::NoSni => webrtc.passthrough_no_sni,
            SniPeek::NotTls => return Ok(()),
        };
        if to_turn {
            // TURN over TLS: same certificate, no ALPN (TURN clients send none
            // or `stun.turn`, which an h2/http1.1 list would refuse).
            let local = tcp.local_addr()?;
            let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, turn_acceptor.accept(tcp)).await??;
            relay.serve_stream(tls, local, peer).await;
            return Ok(());
        }
    }

    let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await??;

    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let hosts = hosts.clone();
        async move { Ok::<_, Infallible>(route(state, &hosts, peer, req).await) }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
    // RFC 8441 Extended CONNECT carries HTTP/2 WebSockets.
    builder.http2().timer(TokioTimer::new()).enable_connect_protocol();
    builder.serve_connection_with_upgrades(TokioIo::new(tls), svc).await
}

/// Route by `Host`, not SNI: HTTP/2 clients may coalesce connections across
/// names the certificate covers.
async fn route(state: Arc<AppState>, hosts: &Hosts, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let mut response = route_host(state, hosts, peer, req).await;
    // This wrapper runs only on HTTPS, including errors and upgrades. Our
    // policy overwrites any HSTS supplied by a proxied app.
    response.headers_mut().insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    response
}

async fn route_host(state: Arc<AppState>, hosts: &Hosts, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let Some(host) = request_host(&req) else {
        return pages::not_found();
    };
    if host == hosts.tunnel && req.uri().path() == CONNECT_PATH {
        return control::handle_connect(state, req).await;
    }
    if host == hosts.zone && gatehost::handles(req.uri().path()) {
        return gatehost::handle(state, peer, req).await;
    }
    if hosts.ui.as_deref() == Some(host.as_str()) {
        return crate::ui::handle(state, peer, req).await;
    }
    if host == hosts.api {
        let mut req = req;
        req.extensions_mut().insert(api::PeerAddr(peer));
        return api::handle(state, req).await;
    }
    if let Some(label) = hosts.preview_label(&host) {
        return edge::handle(state, peer, label, req).await;
    }
    pages::not_found()
}

pub async fn run_http_redirect(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = state.config.listen_http;
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    let hosts = Arc::new(Hosts::new(&state));
    tracing::info!(%addr, "http redirect listener started");

    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let hosts = hosts.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let resp = redirect(&hosts, &req);
                async move { Ok::<_, Infallible>(resp) }
            });
            let result = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(tcp), svc)
                .await;
            if let Err(e) = result {
                tracing::debug!(error = %e, "http connection ended with error");
            }
        });
    }
}

fn redirect<B>(hosts: &Hosts, req: &Request<B>) -> Response<Body> {
    let Some(host) = request_host(req).filter(|h| hosts.is_ours(h)) else {
        return text_response(StatusCode::BAD_REQUEST, "unknown host\n");
    };
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let location = format!("https://{host}{path}");
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(empty())
        .unwrap_or_else(|_| text_response(StatusCode::BAD_REQUEST, "bad request\n"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::{Access, AccessMode, Db, HostHeaderMode, NewTunnel, TunnelRow};
    use http::Method;
    use http_body_util::BodyExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tunnel_protocol::ACCESS_TOKEN_PREFIX;

    const ID: &str = "abcdefghij";
    const PREVIEW: &str = "3000-abcdefghij.previews.example.com";
    const HSTS: &str = "max-age=31536000";

    pub(crate) fn test_state(parents: &[&str]) -> Arc<AppState> {
        let mut config: crate::config::Config = toml::from_str(
            r#"
preview_zone = "previews.example.com"
api_host = "api.example.com"
tunnel_host = "tunnel.example.com"
turn_host = "turn.example.com"
admin_token_hash = "unused-test-hash"
data_dir = "."
[acme]
email = "admin@example.com"
[dns]
provider = "cloudflare"
zone = "example.com"
"#,
        )
        .unwrap();
        config.frame_ancestors = parents.iter().map(|s| s.to_string()).collect();
        AppState::new(
            config,
            Db::open(std::path::Path::new(":memory:")).unwrap(),
            tls::CertStore::new("unused-test-certs".into()),
        )
    }

    pub(crate) async fn create_tunnel(state: &AppState, mode: AccessMode) -> TunnelRow {
        state
            .db
            .create_tunnel(
                NewTunnel {
                    id: ID.into(),
                    token_hash: "unused-tunnel-hash".into(),
                    label: None,
                    name: None,
                    metadata: None,
                    max_ports: 8,
                    host_header: HostHeaderMode::Rewrite,
                    inject_ice: false,
                    expires_at: crate::tokens::now() + 3600,
                    access: Access {
                        mode,
                        password_user: Some("visitor".into()),
                        password_hash: Some("unused-password-hash".into()),
                    },
                    client_id: None,
                },
                state.config.limits.max_tunnels_per_client,
            )
            .await
            .unwrap()
            .unwrap()
    }

    async fn request(
        state: &Arc<AppState>,
        host: &str,
        path: &str,
        method: Method,
        extra: &[(&str, &str)],
    ) -> Response<Body> {
        request_from(state, "127.0.0.1:1234".parse().unwrap(), host, path, method, extra).await
    }

    /// [`request`] from the visitor address `peer`.
    pub(crate) async fn request_from(
        state: &Arc<AppState>,
        peer: SocketAddr,
        host: &str,
        path: &str,
        method: Method,
        extra: &[(&str, &str)],
    ) -> Response<Body> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let service_state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = service_state.clone();
                // Hosts is cheap test routing data; production uses Arc.
                let hosts = Hosts::new(&state);
                async move { Ok::<_, Infallible>(route(state, &hosts, peer, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(server), svc).await;
        });
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut req = Request::builder().method(method).uri(path).header(header::HOST, host);
        for (name, value) in extra {
            req = req.header(*name, *value);
        }
        let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(req.body(empty()).unwrap()))
            .await
            .unwrap()
            .unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        Response::from_parts(parts, crate::util::full(body))
    }

    /// A real multiplexed sandbox origin, counting both stream opens and HTTP
    /// requests. Keeping the server session alive keeps its driver running.
    async fn sandbox(state: &AppState) -> (tunnel_protocol::mux::Session, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tunnel_protocol::mux::Session;
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = Session::new_server(server_io);
        let mut client = Session::new_client(client_io);
        let streams = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let opened = streams.clone();
        let received = requests.clone();
        tokio::spawn(async move {
            while let Some(mut stream) = client.next().await {
                opened.fetch_add(1, Ordering::SeqCst);
                let received = received.clone();
                tokio::spawn(async move {
                    let mut port = [0; 2];
                    stream.read_exact(&mut port).await.unwrap();
                    assert_eq!(tunnel_protocol::decode_preamble(port), 3000);
                    stream.write_all(&[tunnel_protocol::STREAM_OK]).await.unwrap();
                    stream.flush().await.unwrap();
                    let svc = service_fn(move |_: Request<Incoming>| {
                        received.fetch_add(1, Ordering::SeqCst);
                        async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header(header::STRICT_TRANSPORT_SECURITY, "max-age=0")
                                    .body(crate::util::full("sandbox"))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ =
                        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
                });
            }
        });
        let (ctrl_tx, _) = tokio::sync::mpsc::channel(1);
        state.registry.insert(Arc::new(crate::registry::LiveTunnel {
            conn_id: 1,
            tunnel_id: ID.into(),
            control: server.control(),
            ports: std::sync::RwLock::new([3000].into_iter().collect()),
            ctrl_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            connected_at: crate::tokens::now(),
            streams: AtomicUsize::new(0),
            pool: crate::pool::OriginPool::default(),
            token_hash: String::new(),
        }));
        (server, streams, requests)
    }

    #[tokio::test]
    async fn https_hsts_covers_preview_gate_api_and_unknown_hosts() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Password).await;
        let cookie = authenticated_cookie(&state).await;
        let (_session, _, received) = sandbox(&state).await;
        for (host, path, extra, expected) in [
            (PREVIEW, "/", vec![("cookie", cookie.as_str())], StatusCode::OK),
            ("previews.example.com", "/__login?to=3000-abcdefghij", vec![], StatusCode::OK),
            ("api.example.com", "/v1/tunnels", vec![], StatusCode::UNAUTHORIZED),
            ("unknown.example.com", "/", vec![], StatusCode::NOT_FOUND),
            ("turn.example.com", "/", vec![], StatusCode::NOT_FOUND),
        ] {
            let response = request(&state, host, path, Method::GET, &extra).await;
            assert_eq!(response.status(), expected, "{host}");
            assert_eq!(response.headers()[header::STRICT_TRANSPORT_SECURITY], HSTS, "{host}");
            assert_eq!(response.headers().get_all(header::STRICT_TRANSPORT_SECURITY).iter().count(), 1);
        }
        assert_eq!(received.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn http_redirect_has_no_hsts() {
        let state = test_state(&[]);
        let response = redirect(
            &Hosts::new(&state),
            &Request::builder().uri("/path?x=1").header(header::HOST, PREVIEW).body(()).unwrap(),
        );
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers()[header::LOCATION], format!("https://{PREVIEW}/path?x=1"));
        assert!(!response.headers().contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    #[tokio::test]
    async fn edge_reserved_gate_paths_never_forward() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Public).await;
        let (_session, opened, received) = sandbox(&state).await;
        for method in [Method::GET, Method::HEAD, Method::POST] {
            for path in [
                "/__access",
                "/__access/",
                "/__access/tnacc_test",
                "/__access/id/tnacc_test",
                "/__login",
                "/__login?next=%2Fapp",
            ] {
                let response = request(&state, PREVIEW, path, method.clone(), &[]).await;
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
                assert!(!response.headers().contains_key(header::LOCATION));
            }
        }
        assert_eq!(opened.load(Ordering::SeqCst), 0);
        assert_eq!(received.load(Ordering::SeqCst), 0);
        // The sandbox is reachable for ordinary paths, including similar names.
        for path in ["/", "/__accessible", "/__loginx"] {
            assert_eq!(request(&state, PREVIEW, path, Method::GET, &[]).await.status(), StatusCode::OK);
        }
        assert_eq!(received.load(Ordering::SeqCst), 3);
    }

    async fn authenticated_cookie(state: &AppState) -> String {
        let grant =
            state.db.login_grant(ID.into(), "unused-password-hash".into(), 3600, vec![]).await.unwrap().unwrap();
        let crate::db::Redemption::Granted { session_id, .. } = grant else { panic!("test grant denied") };
        format!("{}={session_id}", tunnel_protocol::GATE_COOKIE)
    }

    #[tokio::test]
    async fn edge_authenticated_origin_policy_and_public_mode() {
        for mode in [AccessMode::Password, AccessMode::Public] {
            let state = test_state(&["*", "https://app.example.com", "https://*.trusted.example.com"]);
            create_tunnel(&state, mode).await;
            let cookie = if mode == AccessMode::Password {
                authenticated_cookie(&state).await
            } else {
                format!("{}=unused-public-cookie", tunnel_protocol::GATE_COOKIE)
            };
            let (_session, _, received) = sandbox(&state).await;
            let mut allowed = 0;
            for method in [Method::POST, Method::GET] {
                for (origin, trusted) in [
                    (None, true),
                    (Some("https://5173-abcdefghij.previews.example.com"), true),
                    (Some("https://app.example.com"), true),
                    (Some("https://nested.trusted.example.com"), true),
                    (Some("https://3000-zzzzzzzzzz.previews.example.com"), false),
                    (Some("https://previews.example.com"), false),
                    (Some("null"), false),
                    (Some("https://evil.example.net"), false),
                ] {
                    let mut extra = vec![("cookie", cookie.as_str())];
                    if let Some(origin) = origin {
                        extra.push(("origin", origin));
                    }
                    if method == Method::GET {
                        extra.push(("upgrade", "websocket"));
                        extra.push(("connection", "Upgrade"));
                    }
                    let response = request(&state, PREVIEW, "/", method.clone(), &extra).await;
                    if trusted || mode == AccessMode::Public {
                        allowed += 1;
                        assert_eq!(response.status(), StatusCode::OK, "{mode:?} {origin:?}");
                    } else {
                        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin:?}");
                    }
                    assert_eq!(received.load(Ordering::SeqCst), allowed, "blocked origin must not reach sandbox");
                }
            }
            if mode == AccessMode::Public {
                let response = request(
                    &state,
                    PREVIEW,
                    "/",
                    Method::GET,
                    &[("origin", "https://evil.example.net"), ("upgrade", "websocket"), ("connection", "Upgrade")],
                )
                .await;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(received.load(Ordering::SeqCst), allowed + 1);
            }
        }
    }

    /// What the streaming sandbox hands the test for each origin request: the
    /// path, the sender feeding that response's body, and the request body.
    type OriginStream = (String, tokio::sync::mpsc::Sender<bytes::Bytes>, Incoming);

    /// A sandbox whose responses stream whatever the test pushes: `/events` as
    /// SSE (chunked), `/download` as a large fixed-length file.
    async fn streaming_sandbox(
        state: &AppState,
    ) -> (tunnel_protocol::mux::Session, tokio::sync::mpsc::UnboundedReceiver<OriginStream>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tunnel_protocol::mux::Session;
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let server = Session::new_server(server_io);
        let mut client = Session::new_client(client_io);
        let (origin_tx, origin_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(mut stream) = client.next().await {
                let origin_tx = origin_tx.clone();
                tokio::spawn(async move {
                    let mut port = [0; 2];
                    stream.read_exact(&mut port).await.unwrap();
                    stream.write_all(&[tunnel_protocol::STREAM_OK]).await.unwrap();
                    stream.flush().await.unwrap();
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let path = req.uri().path().to_string();
                        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(16);
                        let _ = origin_tx.send((path.clone(), tx, req.into_body()));
                        async move {
                            // `/hold` sends its headers only once the test pushes a chunk.
                            if path == "/hold" && rx.recv().await.is_none() {
                                return Err("held response abandoned");
                            }
                            let body =
                                http_body_util::StreamBody::new(futures_util::stream::unfold(rx, |mut rx| async {
                                    let chunk = rx.recv().await?;
                                    Some((Ok::<_, crate::util::BoxError>(http_body::Frame::data(chunk)), rx))
                                }))
                                .boxed();
                            if path == "/accept" {
                                // Answer at once with an empty body; the upload goes on.
                                return Ok(Response::new(empty()));
                            }
                            let response = if path == "/download" {
                                Response::builder()
                                    .header(header::CONTENT_TYPE, "application/octet-stream")
                                    .header(header::CONTENT_LENGTH, "1000000")
                            } else {
                                Response::builder().header(header::CONTENT_TYPE, "text/event-stream")
                            };
                            Ok::<_, &str>(response.body(body).unwrap())
                        }
                    });
                    let _ =
                        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
                });
            }
        });
        let (ctrl_tx, _) = tokio::sync::mpsc::channel(1);
        state.registry.insert(Arc::new(crate::registry::LiveTunnel {
            conn_id: 1,
            tunnel_id: ID.into(),
            control: server.control(),
            ports: std::sync::RwLock::new([3000].into_iter().collect()),
            ctrl_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            connected_at: crate::tokens::now(),
            streams: AtomicUsize::new(0),
            pool: crate::pool::OriginPool::default(),
            token_hash: String::new(),
        }));
        (server, origin_rx)
    }

    /// One streaming visitor request through the edge on its own HTTP/1.1
    /// connection, with the origin's body sender for it.
    struct Visitor {
        body: Incoming,
        origin: tokio::sync::mpsc::Sender<bytes::Bytes>,
        /// The visitor's request body as the origin receives it.
        upload: Incoming,
    }

    impl Visitor {
        async fn open(
            state: &Arc<AppState>,
            origins: &mut tokio::sync::mpsc::UnboundedReceiver<OriginStream>,
            path: &str,
            cookie: Option<&str>,
        ) -> Self {
            Self::open_with(state, origins, Method::GET, path, cookie, empty()).await
        }

        async fn open_with(
            state: &Arc<AppState>,
            origins: &mut tokio::sync::mpsc::UnboundedReceiver<OriginStream>,
            method: Method,
            path: &str,
            cookie: Option<&str>,
            upload: Body,
        ) -> Self {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let service_state = state.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let state = service_state.clone();
                    let hosts = Hosts::new(&state);
                    async move { Ok::<_, Infallible>(route(state, &hosts, "127.0.0.1:1234".parse().unwrap(), req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(server), svc).await;
            });
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut req = Request::builder().method(method).uri(path).header(header::HOST, PREVIEW);
            if let Some(cookie) = cookie {
                req = req.header(header::COOKIE, cookie);
            }
            let response = sender.send_request(req.body(upload).unwrap()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let (seen, origin, upload) = origins.recv().await.unwrap();
            assert_eq!(seen, path);
            Self { body: response.into_body(), origin, upload }
        }

        /// The origin's next chunk reaches the visitor.
        async fn relays(&mut self, chunk: &'static str) {
            self.origin.send(bytes::Bytes::from_static(chunk.as_bytes())).await.unwrap();
            let frame = self.body.frame().await.expect("stream open").expect("stream intact");
            assert_eq!(frame.into_data().unwrap(), chunk.as_bytes());
        }

        /// The visitor's response fails (cut, not completed) and the origin's
        /// stream is released.
        async fn assert_cut(mut self) {
            let next = tokio::time::timeout(Duration::from_secs(5), self.body.frame()).await.expect("cut promptly");
            assert!(matches!(next, Some(Err(_))), "a cut stream must not look complete");
            tokio::time::timeout(Duration::from_secs(5), self.origin.closed()).await.expect("origin released");
        }
    }

    async fn link_session(state: &AppState, link: &str) -> String {
        state
            .db
            .create_access_link(crate::db::NewAccessLink {
                id: link.into(),
                tunnel_id: ID.into(),
                token_hash: format!("{link}-placeholder"),
                single_use: false,
                label: None,
                owner_port: None,
                session_ttl_s: 3600,
                expires_at: crate::tokens::now() + 3600,
            })
            .await
            .unwrap();
        let crate::db::Redemption::Granted { session_id, .. } = state
            .db
            .redeem_access_link(ID.into(), format!("{link}-placeholder"), vec![], None, String::new())
            .await
            .unwrap()
        else {
            panic!("test link denied")
        };
        format!("{}={session_id}", tunnel_protocol::GATE_COOKIE)
    }

    fn live_streams(state: &AppState) -> usize {
        state.metrics.live_streams() as usize
    }

    #[tokio::test]
    async fn revoking_a_link_cuts_its_streaming_responses_only() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let revoked = link_session(&state, "link-revoked").await;
        let kept = link_session(&state, "link-kept").await;
        let mut events = Visitor::open(&state, &mut origins, "/events", Some(&revoked)).await;
        let mut download = Visitor::open(&state, &mut origins, "/download", Some(&revoked)).await;
        let mut other = Visitor::open(&state, &mut origins, "/events", Some(&kept)).await;
        for visitor in [&mut events, &mut download, &mut other] {
            visitor.relays("data: one\n\n").await;
        }
        assert_eq!(live_streams(&state), 3);

        // Exactly what `DELETE /v1/access-links/{id}` does after the delete.
        assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(ID);
        events.assert_cut().await;
        download.assert_cut().await;
        other.relays("data: two\n\n").await;
        assert_eq!(live_streams(&state), 1, "cut requests must release their registration");

        // Closing the tunnel cuts what is left.
        state.registry.remove(ID);
        other.assert_cut().await;
        assert_eq!(live_streams(&state), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn session_expiry_cuts_its_streaming_responses_only() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Password).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let login = |ttl| {
            let state = state.clone();
            async move {
                let grant =
                    state.db.login_grant(ID.into(), "unused-password-hash".into(), ttl, vec![]).await.unwrap().unwrap();
                let crate::db::Redemption::Granted { session_id, .. } = grant else { panic!("test grant denied") };
                format!("{}={session_id}", tunnel_protocol::GATE_COOKIE)
            }
        };
        let short = login(60).await;
        let long = login(7200).await;
        let mut events = Visitor::open(&state, &mut origins, "/events", Some(&short)).await;
        // Only the short session is cached now, so this request is admitted on
        // it; at its expiry the recheck must find the long one it also presented.
        let both = format!("{short}; {long}");
        let mut both = Visitor::open(&state, &mut origins, "/events", Some(&both)).await;
        let mut download = Visitor::open(&state, &mut origins, "/download", Some(&short)).await;
        let mut other = Visitor::open(&state, &mut origins, "/events", Some(&long)).await;
        for visitor in [&mut events, &mut both, &mut download, &mut other] {
            visitor.relays("data: one\n\n").await;
        }

        // Wall-clock seconds may tick during setup: the deadline is 59-60 s out.
        tokio::time::advance(Duration::from_secs(55)).await;
        events.relays("data: still\n\n").await;
        tokio::time::advance(Duration::from_secs(6)).await;
        events.assert_cut().await;
        download.assert_cut().await;
        both.relays("data: two\n\n").await;
        other.relays("data: two\n\n").await;
        assert_eq!(live_streams(&state), 2);
    }

    #[tokio::test]
    async fn nothing_is_relayed_while_a_revocation_is_rechecked() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let revoked = link_session(&state, "link-revoked").await;
        let kept = link_session(&state, "link-kept").await;
        let mut events = Visitor::open(&state, &mut origins, "/events", Some(&revoked)).await;
        let mut other = Visitor::open(&state, &mut origins, "/events", Some(&kept)).await;
        events.relays("data: one\n\n").await;
        other.relays("data: one\n\n").await;
        assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
        state.invalidate_sessions();

        // Hold the database so both rechecks stay pending.
        let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let db_state = state.clone();
        let held = tokio::spawn(async move {
            db_state
                .db
                .call(move |_| {
                    let _ = locked_tx.send(());
                    let _ = release_rx.recv();
                    Ok(())
                })
                .await
        });
        locked_rx.await.unwrap();
        state.registry.rotate_gate_epoch(ID);
        for visitor in [&mut events, &mut other] {
            visitor.origin.send(bytes::Bytes::from_static(b"data: during\n\n")).await.unwrap();
        }
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        for visitor in [&mut events, &mut other] {
            assert!(futures_util::poll!(visitor.body.frame()).is_pending(), "relayed during the recheck");
        }

        release_tx.send(()).unwrap();
        held.await.unwrap().unwrap();
        // The revoked stream never sees the chunk sent during the recheck.
        events.assert_cut().await;
        let frame = other.body.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), &b"data: during\n\n"[..]);
        other.relays("data: after\n\n").await;
    }

    #[tokio::test]
    async fn revoking_a_link_ends_a_request_still_waiting_for_the_origin() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let cookie = link_session(&state, "link-revoked").await;
        let waiting = {
            let state = state.clone();
            tokio::spawn(async move {
                request(&state, PREVIEW, "/hold", Method::GET, &[("cookie", cookie.as_str())]).await.status()
            })
        };
        let (path, origin, _) = origins.recv().await.unwrap();
        assert_eq!(path, "/hold");
        assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(ID);
        assert_eq!(waiting.await.unwrap(), StatusCode::UNAUTHORIZED);
        tokio::time::timeout(Duration::from_secs(5), origin.closed()).await.expect("origin released");
        assert_eq!(live_streams(&state), 0);
    }

    #[tokio::test]
    async fn a_visitor_that_stops_reading_cannot_hold_a_revoked_exchange_open() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let cookie = link_session(&state, "link-revoked").await;
        let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(1);
        let upload = http_body_util::StreamBody::new(futures_util::stream::unfold(upload_rx, |mut rx| async {
            let chunk = rx.recv().await?;
            Some((Ok::<_, crate::util::BoxError>(http_body::Frame::data(chunk)), rx))
        }))
        .boxed();
        let mut visitor =
            Visitor::open_with(&state, &mut origins, Method::POST, "/events", Some(&cookie), upload).await;
        upload_tx.send(bytes::Bytes::from_static(b"part one")).await.unwrap();
        assert_eq!(visitor.upload.frame().await.unwrap().unwrap().into_data().unwrap(), &b"part one"[..]);

        // Fill every buffer toward the visitor, which never reads again.
        let chunk = bytes::Bytes::from(vec![b'x'; 64 * 1024]);
        let mut stalled = 0;
        while stalled < 200 {
            match visitor.origin.try_send(chunk.clone()) {
                Ok(()) => stalled = 0,
                Err(_) => {
                    stalled += 1;
                    tokio::task::yield_now().await;
                }
            }
        }

        assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(ID);
        // The origin side ends without the visitor reading anything.
        tokio::time::timeout(Duration::from_secs(5), visitor.origin.closed()).await.expect("origin released");
        let upload_end =
            tokio::time::timeout(Duration::from_secs(5), visitor.upload.frame()).await.expect("upload cut");
        assert!(!matches!(upload_end, Some(Ok(_))), "no upload data after the revocation");
        // Hyper still holds the visitor's connection, so its slot counts on.
        assert_eq!(live_streams(&state), 1);
        // Reading again, the visitor gets what was already buffered, then a
        // failure: never a clean end.
        let drained = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match visitor.body.frame().await {
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return true,
                    None => return false,
                }
            }
        })
        .await
        .expect("cut, not stalled");
        assert!(drained, "a cut response must not end cleanly");
        streams_drop_to(&state, 0, "slot released once hyper let go of the visitor").await;
        drop(upload_tx);
    }

    /// Waits until `live_streams` is `n`.
    async fn streams_drop_to(state: &AppState, n: usize, why: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while live_streams(state) != n {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect(why);
    }

    #[tokio::test]
    async fn a_revocation_tears_down_an_origin_that_stopped_reading_the_upload() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let cookie = link_session(&state, "link-revoked").await;
        let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(1);
        let upload = http_body_util::StreamBody::new(futures_util::stream::unfold(upload_rx, |mut rx| async {
            let chunk = rx.recv().await?;
            Some((Ok::<_, crate::util::BoxError>(http_body::Frame::data(chunk)), rx))
        }))
        .boxed();
        // The origin answers at once and never reads the upload.
        let mut visitor =
            Visitor::open_with(&state, &mut origins, Method::POST, "/accept", Some(&cookie), upload).await;
        assert!(visitor.body.frame().await.is_none(), "the empty response is complete");
        let chunk = bytes::Bytes::from(vec![b'u'; 64 * 1024]);
        let mut stalled = 0;
        while stalled < 200 {
            match upload_tx.try_send(chunk.clone()) {
                Ok(()) => stalled = 0,
                Err(_) => {
                    stalled += 1;
                    tokio::task::yield_now().await;
                }
            }
        }

        assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(ID);
        // With the origin still not reading, the exchange ends on both sides.
        tokio::time::timeout(Duration::from_secs(5), upload_tx.closed()).await.expect("visitor's upload cut");
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match visitor.upload.frame().await {
                    Some(Ok(_)) => {}
                    Some(Err(_)) => return true,
                    None => return false,
                }
            }
        })
        .await
        .expect("origin connection torn down");
        assert!(ended, "a cut upload must not look complete to the origin");
        assert_eq!(live_streams(&state), 0);
    }

    #[tokio::test]
    async fn an_upload_is_cut_even_after_its_response_is_done() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let cookie = link_session(&state, "link-revoked").await;
        let (upload_tx, upload_rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(1);
        let upload = http_body_util::StreamBody::new(futures_util::stream::unfold(upload_rx, |mut rx| async {
            let chunk = rx.recv().await?;
            Some((Ok::<_, crate::util::BoxError>(http_body::Frame::data(chunk)), rx))
        }))
        .boxed();
        let mut visitor =
            Visitor::open_with(&state, &mut origins, Method::POST, "/accept", Some(&cookie), upload).await;
        assert!(visitor.body.frame().await.is_none(), "the empty response is complete");
        upload_tx.send(bytes::Bytes::from_static(b"part one")).await.unwrap();
        assert_eq!(visitor.upload.frame().await.unwrap().unwrap().into_data().unwrap(), &b"part one"[..]);

        assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(ID);
        // Offered after the revocation, this part must never reach the origin.
        let _ = upload_tx.try_send(bytes::Bytes::from_static(b"late part"));
        let next = tokio::time::timeout(Duration::from_secs(5), visitor.upload.frame()).await.expect("upload cut");
        assert!(!matches!(next, Some(Ok(_))), "upload data reached the origin after the revocation");
    }

    #[tokio::test]
    async fn a_visitor_leaving_an_idle_stream_releases_the_origin() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Public).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let mut events = Visitor::open(&state, &mut origins, "/events", None).await;
        events.relays("data: one\n\n").await;
        let Visitor { body, origin, .. } = events;
        drop(body);
        tokio::time::timeout(Duration::from_secs(5), origin.closed()).await.expect("origin released");
        assert_eq!(live_streams(&state), 0);
    }

    #[tokio::test]
    async fn a_finished_origin_keeps_the_slot_and_the_watch_until_the_visitor_is_served() {
        for revoke in [false, true] {
            h2_zero_window_visitor(revoke).await;
        }
    }

    /// An HTTP/2 visitor granting no flow-control window: the origin finishes,
    /// nothing reaches the visitor, and its slot counts on, also once `revoke`
    /// cut the exchange (hyper may hold a frame for it). Once the visitor
    /// grants credit, the stream ends: cleanly, or, if revoked, with a reset.
    async fn h2_zero_window_visitor(revoke: bool) {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let cookie = link_session(&state, "link-revoked").await;
        let (client, server) = tokio::io::duplex(64 * 1024);
        let service_state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = service_state.clone();
                let hosts = Hosts::new(&state);
                async move { Ok::<_, Infallible>(route(state, &hosts, "127.0.0.1:1234".parse().unwrap(), req).await) }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server), svc)
                .await;
        });
        // A visitor that grants no flow-control window until told to.
        let (sender, mut connection) =
            h2::client::Builder::new().initial_window_size(0).handshake::<_, bytes::Bytes>(client).await.unwrap();
        let (grant_tx, grant_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut grant = Some(grant_rx);
            std::future::poll_fn(|cx| {
                if let Some(rx) = grant.as_mut()
                    && std::pin::Pin::new(rx).poll(cx).is_ready()
                {
                    grant = None;
                    connection.set_initial_window_size(65_535).unwrap();
                }
                std::pin::Pin::new(&mut connection).poll(cx)
            })
            .await
        });
        let mut sender = sender.ready().await.unwrap();
        let req = Request::builder()
            .uri(format!("https://{PREVIEW}/events"))
            .header(header::COOKIE, cookie)
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(req, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let (_, origin, _) = origins.recv().await.unwrap();
        origin.send(bytes::Bytes::from_static(b"data: last\n\n")).await.unwrap();
        drop(origin);
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        assert_eq!(live_streams(&state), 1, "the response is still owed to the visitor");
        if revoke {
            // The origin is long done; the watch must still act, and the
            // stream hyper still holds keeps counting against the tunnel.
            assert!(state.db.delete_access_link("link-revoked".into()).await.unwrap());
            state.invalidate_sessions();
            state.registry.rotate_gate_epoch(ID);
            tokio::time::timeout(Duration::from_secs(5), async {
                while state.metrics.access_cuts() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("cut at the revocation");
            assert_eq!(live_streams(&state), 1, "a stream hyper still holds must keep its slot");
        }
        grant_tx.send(()).unwrap();
        let mut body = response.into_body();
        let clean = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match body.data().await {
                    Some(Ok(data)) => {
                        // Only bytes sent before any revocation can arrive
                        // (or the empty frame carrying END_STREAM).
                        assert!(data.is_empty() || data == b"data: last\n\n"[..], "{data:?}");
                        body.flow_control().release_capacity(data.len()).unwrap();
                    }
                    Some(Err(_)) => return false,
                    None => return true,
                }
            }
        })
        .await
        .expect("stream ends once the visitor grants credit");
        assert_eq!(clean, !revoke, "only an unrevoked stream ends cleanly");
        streams_drop_to(&state, 0, "slot released once the stream ended").await;
    }

    #[tokio::test]
    async fn protecting_a_public_tunnel_cuts_its_streaming_responses() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Public).await;
        let (_session, mut origins) = streaming_sandbox(&state).await;
        let mut events = Visitor::open(&state, &mut origins, "/events", None).await;
        events.relays("data: one\n\n").await;
        // A rotation that keeps the tunnel public keeps the stream.
        state.registry.rotate_gate_epoch(ID);
        events.relays("data: two\n\n").await;
        state
            .db
            .update_tunnel(
                ID.into(),
                crate::db::TunnelPatch {
                    access: Some(Access { mode: AccessMode::Link, ..Default::default() }),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        state.invalidate_tunnel(ID);
        state.invalidate_sessions();
        state.registry.rotate_gate_epoch(ID);
        events.assert_cut().await;
        assert_eq!(live_streams(&state), 0);
    }

    async fn body_text(response: Response<Body>) -> String {
        String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    /// A browser asks the page's own origin for `/favicon.ico` when a page
    /// names no icon; on a gated preview that must stop at the gate.
    #[tokio::test]
    async fn a_gated_favicon_request_never_reaches_the_origin() {
        for mode in [AccessMode::Link, AccessMode::Password] {
            let state = test_state(&[]);
            create_tunnel(&state, mode).await;
            let (_session, opened, received) = sandbox(&state).await;
            for extra in [
                vec![("sec-fetch-dest", "image"), ("accept", "image/avif,image/webp,image/png,*/*;q=0.8")],
                vec![("accept", "image/*")],
                vec![],
            ] {
                let response = request(&state, PREVIEW, "/favicon.ico", Method::GET, &extra).await;
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{mode:?} {extra:?}");
            }
            assert_eq!(opened.load(Ordering::SeqCst), 0, "{mode:?}");
            assert_eq!(received.load(Ordering::SeqCst), 0, "{mode:?}");
        }
    }

    #[tokio::test]
    async fn an_unauthenticated_non_page_request_learns_how_its_mode_signs_in() {
        const LOGIN: &str = "https://previews.example.com/__login?to=3000-abcdefghij&next=%2F";
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Password).await;
        let (_session, _, received) = sandbox(&state).await;
        // curl, a fetch, an agent: no redirect, the login URL in the body.
        for extra in [vec![], vec![("accept", "*/*")], vec![("sec-fetch-dest", "empty"), ("accept", "text/html")]] {
            let response = request(&state, PREVIEW, "/app?x=1", Method::GET, &extra).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{extra:?}");
            assert!(!response.headers().contains_key(header::LOCATION));
            assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"));
            let body = body_text(response).await;
            assert!(body.contains(&LOGIN.replace('&', "&amp;")), "{body}");
            assert!(body.contains("password protected"), "{body}");
            assert!(!body.contains("link you were given"), "{body}");
            assert!(!body.contains("visitor"), "names no username: {body}");
        }
        for extra in [
            vec![("accept", "application/json")],
            vec![("sec-fetch-dest", "empty"), ("accept", "application/json, */*")],
        ] {
            let response = request(&state, PREVIEW, "/api/x", Method::GET, &extra).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
            assert_eq!(body["error"], "password_required");
            assert_eq!(body["login_url"], LOGIN);
            assert_eq!(body.as_object().unwrap().len(), 3, "{body}");
        }
        // Page loads still go straight to the login form, keeping the path.
        for extra in
            [vec![("sec-fetch-dest", "document")], vec![("sec-fetch-dest", "iframe")], vec![("accept", "text/html")]]
        {
            let response = request(&state, PREVIEW, "/app", Method::GET, &extra).await;
            assert_eq!(response.status(), StatusCode::FOUND, "{extra:?}");
            assert_eq!(
                response.headers()[header::LOCATION],
                "https://previews.example.com/__login?to=3000-abcdefghij&next=%2Fapp"
            );
        }
        // Link mode keeps its own copy, whatever the client accepts.
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        for extra in [vec![], vec![("accept", "application/json")], vec![("sec-fetch-dest", "document")]] {
            let response = request(&state, PREVIEW, "/", Method::GET, &extra).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = body_text(response).await;
            assert!(body.contains("link you were given"), "{body}");
            assert!(!body.contains("__login"), "{body}");
        }
        assert_eq!(received.load(Ordering::SeqCst), 0);
    }

    /// Every gate page carries the inline padlock icon (and a CSP that lets
    /// it load); none points the browser at another URL for one.
    #[tokio::test]
    async fn gate_pages_carry_the_inline_padlock_icon() {
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Password).await;
        let zone = "previews.example.com";
        let mut pages = vec![
            (zone, "/__login?to=3000-abcdefghij&next=%2F", Method::GET, vec![], StatusCode::OK),
            // A used or unknown link on a password tunnel: the form, as a 401.
            (zone, "/__access/3000-abcdefghij/tnacc_unknown", Method::GET, vec![], StatusCode::UNAUTHORIZED),
            (zone, "/__login?to=3000-zzzzzzzzzz", Method::GET, vec![], StatusCode::NOT_FOUND),
            (zone, "/__login", Method::POST, vec![], StatusCode::NOT_FOUND),
            (PREVIEW, "/", Method::GET, vec![], StatusCode::UNAUTHORIZED),
        ];
        for (host, path, method, extra, status) in pages.drain(..) {
            let response = request(&state, host, path, method.clone(), &extra).await;
            assert_eq!(response.status(), status, "{method} {host}{path}");
            let csp = response.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
            assert!(csp.starts_with("default-src 'none'; style-src 'unsafe-inline'; img-src data:"), "{csp}");
            let body = body_text(response).await;
            assert!(
                body.contains(r#"<link rel="icon" type="image/svg+xml" sizes="any" href="data:image/svg+xml;base64,"#)
            );
            assert!(body.contains(r#"<link rel="icon" type="image/png" sizes="32x32" href="data:image/png;base64,"#));
            assert_eq!(body.matches("rel=\"icon\"").count(), 2, "{path}");
            assert!(!body.contains("favicon"), "{path}");
        }
        // Link mode's generic 401 and an unknown link on the zone host too.
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Link).await;
        for (host, path) in [(zone, "/__access/3000-abcdefghij/tnacc_unknown"), (PREVIEW, "/")] {
            let response = request(&state, host, path, Method::GET, &[]).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{host}{path}");
            assert!(body_text(response).await.contains("data:image/svg+xml;base64,"), "{host}{path}");
        }
    }

    /// The dashboard's Open button: a single-use, one-minute link for one
    /// port takes the browser through the zone host to the app, once.
    #[tokio::test]
    async fn an_open_link_reaches_the_app_through_the_gate_once() {
        for mode in [AccessMode::Link, AccessMode::Password] {
            let state = test_state(&[]);
            let tunnel = create_tunnel(&state, mode).await;
            let (_session, _, received) = sandbox(&state).await;
            let req: crate::api::CreateAccessLinkRequest = serde_json::from_value(serde_json::json!({
                "port": 3000, "ttl_s": 60, "single_use": true, "label": "Opened from the dashboard"
            }))
            .unwrap();
            let link = crate::api::mint_access_link(&state, &tunnel, req, None).await.unwrap();
            let path = link.url.strip_prefix("https://previews.example.com").unwrap().to_string();
            assert!(path.starts_with("/__access/3000-abcdefghij/tnacc_"), "{path}");
            let document = [("sec-fetch-dest", "document")];

            let response = request(&state, "previews.example.com", &path, Method::GET, &document).await;
            assert_eq!(response.status(), StatusCode::FOUND, "{mode:?}");
            assert_eq!(response.headers()[header::LOCATION], format!("https://{PREVIEW}/"));
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            let cookie =
                response.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
            let app = request(&state, PREVIEW, "/", Method::GET, &[("cookie", cookie.as_str()), document[0]]).await;
            assert_eq!(app.status(), StatusCode::OK);
            assert_eq!(body_text(app).await, "sandbox");
            assert_eq!(received.load(Ordering::SeqCst), 1);

            // The same link again: no new session, and the origin is not asked.
            let again = request(&state, "previews.example.com", &path, Method::GET, &document).await;
            assert_eq!(again.status(), StatusCode::UNAUTHORIZED, "{mode:?}");
            assert!(!again.headers().contains_key(header::SET_COOKIE));
            assert!(!again.headers().contains_key(header::LOCATION));
            let body = body_text(again).await;
            match mode {
                AccessMode::Password => assert!(body.contains(r#"action="/__login""#), "{body}"),
                // Says the link cannot be used and what to do, never which
                // reason: a used link reads exactly as an unknown one.
                _ => {
                    assert!(body.contains("Link not valid") && body.contains("Ask whoever shared"), "{body}");
                    assert!(!body.contains("link you were given"), "{body}");
                    let unknown = path.rsplit_once('/').unwrap().0.to_string() + "/tnacc_unknown";
                    let unknown = request(&state, "previews.example.com", &unknown, Method::GET, &document).await;
                    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
                    assert!(!unknown.headers().contains_key(header::SET_COOKIE));
                    assert_eq!(body_text(unknown).await, body, "used and unknown links look the same");
                    // An expired, never used link too.
                    let late = format!("{ACCESS_TOKEN_PREFIX}late-token");
                    state
                        .db
                        .create_access_link(crate::db::NewAccessLink {
                            id: "al_late".into(),
                            tunnel_id: tunnel.id.clone(),
                            token_hash: crate::tokens::hash_token(&late),
                            single_use: true,
                            label: None,
                            owner_port: None,
                            session_ttl_s: 3600,
                            expires_at: crate::tokens::now() - 1,
                        })
                        .await
                        .unwrap();
                    let late = path.rsplit_once('/').unwrap().0.to_string() + "/" + &late;
                    let late = request(&state, "previews.example.com", &late, Method::GET, &document).await;
                    assert_eq!(late.status(), StatusCode::UNAUTHORIZED);
                    assert!(!late.headers().contains_key(header::SET_COOKIE));
                    assert_eq!(body_text(late).await, body, "expired and used links look the same");
                }
            }
            assert_eq!(received.load(Ordering::SeqCst), 1);
        }
    }

    /// An owner link (the dashboard's Open on your own tunnel) for port 3000.
    async fn owner_link(state: &AppState, token: &str) -> String {
        state
            .db
            .create_access_link(crate::db::NewAccessLink {
                id: "al_owner".into(),
                tunnel_id: ID.into(),
                token_hash: crate::tokens::hash_token(token),
                single_use: true,
                label: Some("Opened from the dashboard".into()),
                owner_port: Some(3000),
                session_ttl_s: 3600,
                expires_at: crate::tokens::now() + 60,
            })
            .await
            .unwrap();
        format!("/__access/3000-{ID}/{token}")
    }

    /// Regression (owner 11-23: Open still asked for the password). The
    /// browser sent the one-time Open URL twice, 47 ms apart; the second
    /// request found the link used and answered the password form, which is
    /// what the tab showed. A repeat from the same address within seconds now
    /// signs in again; anyone else, or later, still gets the normal prompt.
    #[tokio::test]
    async fn an_owner_link_repeated_by_the_browser_still_lands_on_the_app() {
        let zone = "previews.example.com";
        let document = [("sec-fetch-dest", "document")];
        let owner_ip: SocketAddr = "203.0.113.7:50000".parse().unwrap();
        let other_ip: SocketAddr = "198.51.100.9:40000".parse().unwrap();
        for mode in [AccessMode::Password, AccessMode::Link] {
            let state = test_state(&[]);
            create_tunnel(&state, mode).await;
            let (_session, _, received) = sandbox(&state).await;
            let token = format!("{ACCESS_TOKEN_PREFIX}owner-open-token");
            let path = owner_link(&state, &token).await;

            // A HEAD (a link checker) neither signs in nor uses the link up.
            let head = request_from(&state, owner_ip, zone, &path, Method::HEAD, &[]).await;
            assert_eq!(head.status(), StatusCode::NOT_FOUND, "{mode:?}");
            assert!(!head.headers().contains_key(header::SET_COOKIE));

            // The click, then the browser's repeat a moment later (new connection, same address):
            // both land on the app with a session of their own.
            for attempt in ["first", "repeat"] {
                let r = request_from(&state, owner_ip, zone, &path, Method::GET, &document).await;
                assert_eq!(r.status(), StatusCode::FOUND, "{mode:?} {attempt}");
                assert_eq!(r.headers()[header::LOCATION], format!("https://{PREVIEW}/"));
                let cookie = r.headers()[header::SET_COOKIE].to_str().unwrap().to_string();
                assert!(cookie.contains("Domain=previews.example.com"), "{cookie}");
                let pair = cookie.split(';').next().unwrap().to_string();
                let app = request(&state, PREVIEW, "/", Method::GET, &[("cookie", pair.as_str()), document[0]]).await;
                assert_eq!(app.status(), StatusCode::OK, "{mode:?} {attempt}");
            }
            assert_eq!(received.load(Ordering::SeqCst), 2);

            // Someone else with the URL: the tunnel's normal prompt, no session.
            let r = request_from(&state, other_ip, zone, &path, Method::GET, &document).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{mode:?}");
            assert!(!r.headers().contains_key(header::SET_COOKIE));

            // The same address after the repeat window: refused too.
            state
                .db
                .call(|c| {
                    c.execute("UPDATE access_links SET used_at = used_at - ?1", [crate::db::OWNER_LINK_RETRY_S + 1])?;
                    Ok(())
                })
                .await
                .unwrap();
            let r = request_from(&state, owner_ip, zone, &path, Method::GET, &document).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{mode:?}");
            let body = body_text(r).await;
            if matches!(mode, AccessMode::Password) {
                assert!(body.contains(r#"action="/__login""#), "{body}");
            }
            assert_eq!(received.load(Ordering::SeqCst), 2, "the origin is not asked");
        }
    }

    /// An owner link opens only the port it was made for.
    #[tokio::test]
    async fn an_owner_link_is_bound_to_its_port() {
        let zone = "previews.example.com";
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Password).await;
        let (_session, _, _) = sandbox(&state).await;
        let token = format!("{ACCESS_TOKEN_PREFIX}owner-port-token");
        owner_link(&state, &token).await;
        // Another port, no port, or another tunnel: refused.
        for path in [
            format!("/__access/3001-{ID}/{token}"),
            format!("/__access/{ID}/{token}"),
            format!("/__access/3000-bcdefghijk/{token}"),
        ] {
            let r = request(&state, zone, &path, Method::GET, &[]).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert!(!r.headers().contains_key(header::SET_COOKIE), "{path}");
        }
        // Not used up by the wrong-port attempts.
        let r = request(&state, zone, &format!("/__access/3000-{ID}/{token}"), Method::GET, &[]).await;
        assert_eq!(r.status(), StatusCode::FOUND);

        // An expired owner link is refused even before its first use.
        let late = format!("{ACCESS_TOKEN_PREFIX}owner-late-token");
        state
            .db
            .create_access_link(crate::db::NewAccessLink {
                id: "al_late".into(),
                tunnel_id: ID.into(),
                token_hash: crate::tokens::hash_token(&late),
                single_use: true,
                label: None,
                owner_port: Some(3000),
                session_ttl_s: 3600,
                expires_at: crate::tokens::now() - 1,
            })
            .await
            .unwrap();
        let r = request(&state, zone, &format!("/__access/3000-{ID}/{late}"), Method::GET, &[]).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// Ordinary (visitor) single-use links get no repeat window.
    #[tokio::test]
    async fn a_visitor_link_is_still_single_use_from_the_same_address() {
        let zone = "previews.example.com";
        let state = test_state(&[]);
        create_tunnel(&state, AccessMode::Password).await;
        let token = format!("{ACCESS_TOKEN_PREFIX}visitor-token");
        state
            .db
            .create_access_link(crate::db::NewAccessLink {
                id: "al_visitor".into(),
                tunnel_id: ID.into(),
                token_hash: crate::tokens::hash_token(&token),
                single_use: true,
                label: None,
                owner_port: None,
                session_ttl_s: 3600,
                expires_at: crate::tokens::now() + 60,
            })
            .await
            .unwrap();
        let path = format!("/__access/3000-{ID}/{token}");
        assert_eq!(request(&state, zone, &path, Method::GET, &[]).await.status(), StatusCode::FOUND);
        assert_eq!(request(&state, zone, &path, Method::GET, &[]).await.status(), StatusCode::UNAUTHORIZED);
    }
}
