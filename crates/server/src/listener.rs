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
use crate::{api, control, edge, gatehost, pages, tls};

const SNI_PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Lowercased names used for routing, computed once.
struct Hosts {
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
        host == self.api || host == self.tunnel || host == self.zone || self.preview_label(host).is_some()
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
        let (client, server) = tokio::io::duplex(64 * 1024);
        let service_state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = service_state.clone();
                // Hosts is cheap test routing data; production uses Arc.
                let hosts = Hosts::new(&state);
                async move { Ok::<_, Infallible>(route(state, &hosts, "127.0.0.1:1234".parse().unwrap(), req).await) }
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
}
