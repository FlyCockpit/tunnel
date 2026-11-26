use super::*;
use turn::client::{Client, ClientConfig};

const SECRET: &str = "test-secret";
/// Advertised relay address; any 127/8 address reaches the 0.0.0.0-bound relays.
const PUBLIC: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

fn creds(valid_for: i64) -> (String, String) {
    let user = format!("{}:abcdefghij:test", crate::tokens::now() + valid_for);
    let pass = crate::ice::credential(SECRET, &user);
    (user, pass)
}

async fn udp_server(ports: (u16, u16)) -> (Relay, SocketAddr) {
    let relay = Relay::for_test(PUBLIC, ports.0, ports.1, SECRET);
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    relay.serve_udp(udp).await.unwrap();
    (relay, addr)
}

async fn client(server: SocketAddr, conn: Arc<dyn Conn + Send + Sync>, (user, pass): (String, String)) -> Client {
    let c = Client::new(ClientConfig {
        stun_serv_addr: server.to_string(),
        turn_serv_addr: server.to_string(),
        username: user,
        password: pass,
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn,
        vnet: None,
    })
    .await
    .unwrap();
    c.listen().await.unwrap();
    c
}

async fn udp_client(server: SocketAddr, creds: (String, String)) -> Client {
    client(server, Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), creds).await
}

/// Relay a datagram to a plain UDP peer and back.
async fn round_trip(c: &Client) {
    let relay = c.allocate().await.expect("allocate");
    let relay_addr = relay.local_addr().unwrap();
    assert_eq!(relay_addr.ip(), IpAddr::V4(PUBLIC));
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay.send_to(b"ping", peer.local_addr().unwrap()).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"ping");
    assert_eq!(from.port(), relay_addr.port());
    peer.send_to(b"pong", SocketAddr::from(([127, 0, 0, 1], relay_addr.port()))).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"pong");
    relay.close().await.unwrap();
}

/// Models rustls waiting forever to send close_notify to a peer that
/// never drains its socket. The drop flag verifies transport ownership.
struct PendingShutdown {
    inner: tokio::io::DuplexStream,
    started: CancellationToken,
    dropped: Arc<AtomicBool>,
}

impl AsyncRead for PendingShutdown {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PendingShutdown {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.started.cancel();
        std::task::Poll::Pending
    }
}

impl Drop for PendingShutdown {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_shutdown_does_not_block_revocation_and_drops_transport() {
    let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
    let (_peer, inner) = tokio::io::duplex(1);
    let started = CancellationToken::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let stream = PendingShutdown { inner, started: started.clone(), dropped: dropped.clone() };
    let task = tokio::spawn({
        let relay = relay.clone();
        async move { relay.serve_stream(stream, "127.0.0.1:3478".parse().unwrap(), "127.0.0.1:1".parse().unwrap()).await }
    });
    started.cancelled().await;
    assert!(!dropped.load(Ordering::Acquire));
    tokio::time::timeout(Duration::from_millis(250), relay.revoke_tunnel("abcdefghij"))
        .await
        .expect("shutdown cannot hold a global command lock");
    tokio::time::timeout(STREAM_CLOSE_TIMEOUT + Duration::from_millis(100), task).await.unwrap().unwrap();
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
    assert!(relay.shared.stream_ips.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn stream_close_interrupts_pending_io_and_bounds_shutdown() {
    let (_peer, inner) = tokio::io::duplex(1);
    let started = CancellationToken::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let conn = Arc::new(StreamConn::new(
        PendingShutdown { inner, started: started.clone(), dropped: dropped.clone() },
        "127.0.0.1:3478".parse().unwrap(),
        "127.0.0.1:1".parse().unwrap(),
    ));
    let read = tokio::spawn({
        let conn = conn.clone();
        async move { conn.recv(&mut [0; 64]).await }
    });
    let write = tokio::spawn({
        let conn = conn.clone();
        async move { conn.send(&[0; 64]).await }
    });
    tokio::task::yield_now().await;
    assert!(!read.is_finished());
    assert!(!write.is_finished());
    tokio::time::timeout(STREAM_CLOSE_TIMEOUT + Duration::from_millis(100), conn.close()).await.unwrap().unwrap();
    assert!(started.is_cancelled());
    assert!(dropped.load(Ordering::Acquire));
    assert!(read.await.unwrap().is_err());
    assert!(write.await.unwrap().is_err());
    assert!(conn.reader.lock().await.is_none());
    assert!(conn.writer.lock().await.is_none());
}

#[tokio::test]
async fn forget_validation_drops_cached_expiry() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
    state.install_turn(relay.clone());
    assert!(relay.shared.validate(&creds(600).0).await);
    assert_eq!(relay.shared.cached_validation("abcdefghij"), Some(true));
    let expiry = crate::tokens::now() + 7200;
    state
        .db
        .update_tunnel("abcdefghij".into(), crate::db::TunnelPatch { expires_at: Some(expiry), ..Default::default() })
        .await
        .unwrap();
    let epoch = relay.shared.revocation_epoch.load(Ordering::Acquire);
    state.invalidate_tunnel("abcdefghij");
    assert_eq!(relay.shared.revocation_epoch.load(Ordering::Acquire), epoch);
    assert_eq!(relay.shared.cached_validation("abcdefghij"), None);
    assert!(relay.shared.validate(&creds(600).0).await);
    assert_eq!(relay.shared.security.lock().unwrap().validated["abcdefghij"].1, expiry);
}

/// Hold the database across a deterministic cancellation/invalidation.
async fn block_database(
    state: &Arc<crate::state::AppState>,
) -> (tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let state = state.clone();
    let task = tokio::spawn(async move {
        state
            .db
            .call(move |_| {
                let _ = entered_tx.send(());
                let _ = release_rx.blocking_recv();
                Ok(())
            })
            .await
            .unwrap();
    });
    entered_rx.await.unwrap();
    (release_tx, task)
}

#[tokio::test]
async fn forget_validation_fences_in_flight_reads() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
    state.install_turn(relay.clone());
    let (release, blocker) = block_database(&state).await;
    let user = creds(600).0;
    let mut validation = Box::pin(relay.shared.validate_stream(&user));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(validation.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let _ = release.send(());
    blocker.await.unwrap();
    // Leave the validation future unpolled, then change the expiry and
    // fence any old result before it can be used.
    let expiry = crate::tokens::now() + 7200;
    state
        .db
        .update_tunnel("abcdefghij".into(), crate::db::TunnelPatch { expires_at: Some(expiry), ..Default::default() })
        .await
        .unwrap();
    state.invalidate_tunnel("abcdefghij");
    assert!(validation.await);
    assert_eq!(relay.shared.security.lock().unwrap().validated["abcdefghij"].1, expiry);
    assert!(relay.shared.security.lock().unwrap().validation_fenced.is_empty());
}

#[tokio::test]
async fn unrelated_tunnel_invalidation_preserves_in_flight_validation_and_epoch() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
    state.install_turn(relay.clone());
    let (release, blocker) = block_database(&state).await;
    let user = creds(600).0;
    let mut validation = Box::pin(relay.shared.validate_stream(&user));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(validation.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let epoch = relay.shared.revocation_epoch.load(Ordering::Acquire);
    // Creation and PATCH both invalidate the affected tunnel id.
    state.invalidate_tunnel("unrelated1");
    state.invalidate_tunnel("unrelated1");
    assert_eq!(relay.shared.revocation_epoch.load(Ordering::Acquire), epoch);
    assert!(relay.shared.security.lock().unwrap().validation_fenced.is_empty());
    let _ = release.send(());
    blocker.await.unwrap();
    assert!(validation.await);
}

#[tokio::test]
async fn cancelled_delete_still_completes_teardown() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 53500, 53599, SECRET));
    state.install_turn(relay.clone());
    assert!(relay.shared.validate(&creds(600).0).await);
    let bytes = state.traffic.tunnel_bytes("abcdefghij");
    let (transport, _peer) = tokio::io::duplex(64);
    let session = tunnel_protocol::mux::Session::new_server(transport);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
    state.registry.insert(Arc::new(crate::registry::LiveTunnel {
        conn_id: 1,
        tunnel_id: "abcdefghij".into(),
        control: session.control(),
        ports: std::sync::RwLock::new(Default::default()),
        ctrl_tx,
        cancel: CancellationToken::new(),
        connected_at: crate::tokens::now(),
        streams: AtomicUsize::new(0),
        pool: crate::pool::OriginPool::default(),
        token_hash: String::new(),
    }));
    let gate_epoch = state.registry.gate_epoch("abcdefghij");
    let (release, blocker) = block_database(&state).await;
    let mut delete = Box::pin(state.delete_tunnel("abcdefghij", tunnel_protocol::CloseReason::Deleted));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(delete.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(delete);
    let _ = release.send(());
    blocker.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !Arc::ptr_eq(&bytes, &state.traffic.tunnel_bytes("abcdefghij")) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached deletion must finish its in-memory teardown");
    assert!(state.registry.get("abcdefghij").is_none());
    assert!(gate_epoch.is_cancelled());
    assert!(!relay.shared.credential_allowed(&creds(600).0));
    assert!(matches!(
        ctrl_rx.try_recv(),
        Ok(tunnel_protocol::ServerMsg::Close { reason: tunnel_protocol::CloseReason::Deleted })
    ));
    assert!(matches!(state.tunnel("abcdefghij").await.unwrap().as_ref(), crate::db::TunnelLookup::Tombstoned));
}

#[tokio::test]
async fn state_delete_fences_without_waiting_for_relay_commands() {
    let (state, _dir) = state_with_tunnel().await;
    let (relay, _) = udp_server((53200, 53299)).await;
    let relay = Arc::new(relay);
    state.install_turn(relay.clone());
    assert!(relay.shared.validate(&creds(600).0).await);
    let epoch = relay.shared.revocation_epoch.load(Ordering::Acquire);
    let (transport, _peer) = tokio::io::duplex(64);
    let session = tunnel_protocol::mux::Session::new_server(transport);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel(1);
    state.registry.insert(Arc::new(crate::registry::LiveTunnel {
        conn_id: 1,
        tunnel_id: "abcdefghij".into(),
        control: session.control(),
        ports: std::sync::RwLock::new(Default::default()),
        ctrl_tx,
        cancel: CancellationToken::new(),
        connected_at: crate::tokens::now(),
        streams: AtomicUsize::new(0),
        pool: crate::pool::OriginPool::default(),
        token_hash: String::new(),
    }));
    let server = relay.udp.lock().unwrap().clone().unwrap();
    let commands = server.commands.lock().await;
    tokio::time::timeout(
        Duration::from_millis(250),
        state.delete_tunnel("abcdefghij", tunnel_protocol::CloseReason::Deleted),
    )
    .await
    .expect("delete must not wait for relay commands")
    .unwrap();
    assert!(!relay.shared.credential_allowed(&creds(600).0));
    assert!(relay.shared.revocation_epoch.load(Ordering::Acquire) > epoch);
    assert!(state.registry.get("abcdefghij").is_none());
    assert!(matches!(
        ctrl_rx.try_recv(),
        Ok(tunnel_protocol::ServerMsg::Close { reason: tunnel_protocol::CloseReason::Deleted })
    ));
    // Both maintenance paths must bound even acquisition of this lock.
    tokio::time::pause();
    tokio::time::timeout(SERVER_COMMAND_TIMEOUT + Duration::from_millis(100), relay.revoke_tunnel("abcdefghij"))
        .await
        .unwrap();
    tokio::time::timeout(SERVER_COMMAND_TIMEOUT + Duration::from_millis(100), sweep_server(&server, &relay.shared))
        .await
        .unwrap();
    drop(commands);
    drop(state);
}

#[tokio::test]
async fn stream_allocate_succeeds_on_first_send_and_refresh_uses_cache_after_31s() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 53300, 53399, SECRET));
    state.install_turn(relay.clone());
    let (stream, peer) = tokio::io::duplex(4096);
    let local = "127.0.0.1:3478".parse().unwrap();
    let remote = "127.0.0.1:1".parse().unwrap();
    let task = tokio::spawn({
        let relay = relay.clone();
        async move { relay.serve_stream(stream, local, remote).await }
    });
    let conn = StreamConn::new(peer, remote, local);
    let mut buf = [0; 2048];
    conn.send(&packet(0x0003, &[(0x0019, &[17, 0, 0, 0])], None)).await.unwrap();
    let n = conn.recv(&mut buf).await.unwrap();
    assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0113);
    // RestAuth inherits turn 0.17.3's MD5-only advertisement in 401.
    assert_eq!(attribute(&buf[..n], 0x8002).unwrap(), &[0, 1, 0, 0]);
    let nonce = attribute(&buf[..n], 0x0015).unwrap().to_vec();
    let (user, password) = creds(600);
    let key = generate_auth_key(&user, "turn.test", &password);
    assert!(relay.shared.security.lock().unwrap().validated.is_empty());
    let allocate = packet(
        0x0003,
        &[(0x0006, user.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce), (0x0019, &[17, 0, 0, 0])],
        Some(&key),
    );
    conn.send(&allocate).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(2), conn.recv(&mut buf))
        .await
        .expect("reliable transports do not retransmit Allocate")
        .unwrap();
    assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0103);
    let cached_at = relay.shared.security.lock().unwrap().validated["abcdefghij"].0;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(relay.shared.cached_validation("abcdefghij"), Some(true));
    let refresh = packet(0x0004, &[(0x0006, user.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce)], Some(&key));
    conn.send(&refresh).await.unwrap();
    let n = conn.recv(&mut buf).await.unwrap();
    assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0104);
    assert_eq!(relay.shared.security.lock().unwrap().validated["abcdefghij"].0, cached_at);
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    conn.close().await.unwrap();
    task.await.unwrap();
    drop(state);
}

#[tokio::test]
async fn stream_validation_waits_for_a_busy_slot_without_losing_request() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
    state.install_turn(relay.clone());
    let slots = relay.shared.validation_slots.clone().acquire_many_owned(VALIDATION_LOOKUPS as u32).await.unwrap();
    let validation = tokio::spawn({
        let shared = relay.shared.clone();
        async move { shared.validate_stream(&creds(600).0).await }
    });
    tokio::task::yield_now().await;
    assert!(!validation.is_finished());
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    drop(slots);
    assert!(validation.await.unwrap());
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
    drop(state);
}

#[tokio::test]
async fn sweep_refreshes_validation_before_expiry() {
    let (state, _dir) = state_with_tunnel().await;
    let (relay, addr) = udp_server((53400, 53499)).await;
    let relay = Arc::new(relay);
    state.install_turn(relay.clone());
    let client = udp_client(addr, creds(600)).await;
    let _allocation = client.allocate().await.unwrap();
    let old = tokio::time::Instant::now() - Duration::from_secs(60);
    relay.shared.security.lock().unwrap().validated.get_mut("abcdefghij").unwrap().0 = old;
    assert_eq!(relay.shared.cached_validation("abcdefghij"), Some(true));
    let server = relay.udp.lock().unwrap().clone().unwrap();
    sweep_server(&server, &relay.shared).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while relay.shared.security.lock().unwrap().validated["abcdefghij"].0 == old {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("sweep must refresh a still-valid cache entry");
    client.close().await.unwrap();
    drop(state);
}

#[tokio::test]
async fn validation_timeout_and_cancellation_release_all_slots_and_identities() {
    // A drop guard unblocks the SQLite worker even if an assertion fails.
    struct Release(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
    state.install_turn(relay.clone());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release = Release(Some(release_tx));
    let db = state.db.clone();
    let blocked = tokio::spawn(async move {
        db.call(move |_| {
            let _ = ready_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
        .await
        .unwrap();
    });
    ready_rx.await.unwrap();
    tokio::time::pause();
    for i in 0..VALIDATION_LOOKUPS {
        assert!(!relay.shared.request_validation(&tunnel_creds(&format!("blocked-{i}")).0));
    }
    tokio::task::yield_now().await;
    assert_eq!(relay.shared.validation_slots.available_permits(), 0);
    tokio::time::advance(VALIDATION_TIMEOUT + Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
    let stream = tokio::spawn({
        let shared = relay.shared.clone();
        async move { shared.validate_stream(&creds(600).0).await }
    });
    tokio::task::yield_now().await;
    assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS - 1);
    tokio::time::advance(STREAM_VALIDATION_TIMEOUT + Duration::from_millis(1)).await;
    assert!(!stream.await.unwrap());
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
    let cancelled = tokio::spawn({
        let shared = relay.shared.clone();
        async move { shared.validate_stream(&creds(600).0).await }
    });
    tokio::task::yield_now().await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
    drop(release);
    blocked.await.unwrap();
    drop(state);
}

#[tokio::test]
async fn binding_and_non_requests_bypass_exhausted_challenge_limits() {
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let guard = GuardConn::new(socket, relay.shared.clone());
    relay.shared.challenges.lock().unwrap().global.tokens = 0.0;
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    relay.shared.challenges.lock().unwrap().ips.insert(source.local_addr().unwrap().ip(), RequestBucket::new(0.0));
    let mut buf = [0; 2048];
    for kind in [0x0001, 0x0013, 0x0103, 0x0113] {
        for _ in 0..CHALLENGE_IP_BURST as usize + 1 {
            let raw = packet(kind, &[], None);
            source.send_to(&raw, addr).await.unwrap();
            let (n, _) =
                tokio::time::timeout(Duration::from_millis(250), guard.recv_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!(&buf[..n], raw);
        }
    }
    assert_eq!(relay.shared.challenges.lock().unwrap().global.tokens, 0.0);
}

#[tokio::test]
async fn modern_auth_requests_never_reach_turn() {
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let guard = GuardConn::new(socket, relay.shared.clone());
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (user, password) = creds(600);
    let key = generate_auth_key(&user, "turn.test", &password);
    let mut buf = [0; 2048];
    for typ in [0x001c, 0x001d, 0x8002] {
        for kind in [0x0003, 0x0004, 0x0008, 0x0009] {
            for legacy in [None, Some(key.as_slice())] {
                let raw = packet(kind, &[(0x0006, user.as_bytes()), (typ, &[0; 32])], legacy);
                source.send_to(&raw, addr).await.unwrap();
                source.send_to(&[0x40, 0, 0, 0], addr).await.unwrap();
                let (n, _) =
                    tokio::time::timeout(Duration::from_millis(250), guard.recv_from(&mut buf)).await.unwrap().unwrap();
                assert_eq!(&buf[..n], &[0x40, 0, 0, 0]);
                assert!(guard.context.lock().unwrap().is_none());
            }
        }
    }
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    assert!(relay.shared.challenges.lock().unwrap().ips.is_empty());
}

#[tokio::test]
async fn stun_binding_and_udp_relay() {
    let (_relay, server) = udp_server((51000, 51099)).await;
    let c = udp_client(server, creds(600)).await;
    let mapped = c.send_binding_request().await.unwrap();
    assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    round_trip(&c).await;
    c.close().await.unwrap();
}

async fn wait_allocations(relay: &Relay, want: usize) {
    for _ in 0..50 {
        if relay.shared.allocations.load(Ordering::SeqCst) == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("allocations: want {want}, have {}", relay.shared.allocations.load(Ordering::SeqCst));
}

#[tokio::test]
async fn tcp_relay_and_allocations_end_with_the_connection() {
    let relay = Arc::new(Relay::for_test(PUBLIC, 51100, 51199, SECRET));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(relay.clone().accept_tcp(listener));
    let tcp_client = |server| async move {
        let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
        let local = tcp.local_addr().unwrap();
        let conn = Arc::new(StreamConn::new(tcp, local, server));
        (client(server, conn.clone(), creds(600)).await, conn)
    };

    // Relaying works, and closing the relay (refresh with lifetime 0) frees it.
    let (c, _conn) = tcp_client(server).await;
    round_trip(&c).await;
    wait_allocations(&relay, 0).await;

    // An allocation is freed when its TCP connection goes away.
    let (c2, conn2) = tcp_client(server).await;
    let _held = c2.allocate().await.expect("allocate");
    wait_allocations(&relay, 1).await;
    conn2.close().await.unwrap();
    wait_allocations(&relay, 0).await;
}

#[tokio::test]
async fn relay_to_relay_is_delivered_in_process() {
    let (_relay, server) = udp_server((51200, 51299)).await;
    let a = udp_client(server, creds(600)).await;
    let b = udp_client(server, creds(600)).await;
    let ra = a.allocate().await.unwrap();
    let rb = b.allocate().await.unwrap();
    let (aa, ba) = (ra.local_addr().unwrap(), rb.local_addr().unwrap());
    // Each side permits the other, as ICE does.
    rb.send_to(b"hello-a", aa).await.unwrap();
    ra.send_to(b"hello-b", ba).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), rb.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!((&buf[..n], from), (&b"hello-b"[..], aa));
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), ra.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!((&buf[..n], from), (&b"hello-a"[..], ba));
}

#[tokio::test]
async fn bad_and_expired_credentials_are_refused() {
    let (_relay, server) = udp_server((51300, 51399)).await;
    let (user, _) = creds(600);
    let wrong = udp_client(server, (user, "nope".into())).await;
    assert!(wrong.allocate().await.is_err());
    let expired = udp_client(server, creds(-10)).await;
    allocation_refused(&expired).await;
    let garbage = udp_client(server, ("someone".into(), "x".into())).await;
    allocation_refused(&garbage).await;
}

async fn allocation_refused(c: &Client) {
    assert!(!matches!(tokio::time::timeout(Duration::from_millis(250), c.allocate()).await, Ok(Ok(_))));
}

fn tunnel_creds(tunnel: &str) -> (String, String) {
    let username = format!("{}:{tunnel}:test", crate::tokens::now() + 600);
    let password = crate::ice::credential(SECRET, &username);
    (username, password)
}

fn attribute(raw: &[u8], typ: u16) -> Option<&[u8]> {
    let mut pos = 20;
    while pos + 4 <= raw.len() {
        let kind = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        pos += 4;
        if kind == typ {
            return raw.get(pos..pos + len);
        }
        pos += (len + 3) & !3;
    }
    None
}

fn packet(kind: u16, attrs: &[(u16, &[u8])], key: Option<&[u8]>) -> Vec<u8> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut raw = vec![0; 20];
    raw[..2].copy_from_slice(&kind.to_be_bytes());
    raw[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    raw[8..20].copy_from_slice(&rand::random::<[u8; 12]>());
    for (typ, value) in attrs {
        raw.extend_from_slice(&typ.to_be_bytes());
        raw.extend_from_slice(&(value.len() as u16).to_be_bytes());
        raw.extend_from_slice(value);
        while !raw.len().is_multiple_of(4) {
            raw.push(0);
        }
    }
    let size = raw.len() - 20 + if key.is_some() { 24 } else { 0 };
    raw[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    if let Some(key) = key {
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
        mac.update(&raw);
        raw.extend_from_slice(&[0, 8, 0, 20]);
        raw.extend_from_slice(&mac.finalize().into_bytes());
    }
    raw
}

async fn raw_allocate(socket: &UdpSocket, server: SocketAddr, username: &str) -> (Vec<u8>, Vec<u8>) {
    let transport = [17, 0, 0, 0];
    socket.send_to(&packet(0x0003, &[(0x0019, &transport)], None), server).await.unwrap();
    let mut buf = [0; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
    let nonce = attribute(&buf[..n], 0x0015).unwrap().to_vec();
    let password = crate::ice::credential(SECRET, username);
    let key = generate_auth_key(username, "turn.test", &password);
    let allocate = packet(
        0x0003,
        &[(0x0006, username.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce), (0x0019, &transport)],
        Some(&key),
    );
    socket.send_to(&allocate, server).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0103);
    (nonce, key)
}

#[tokio::test]
async fn expired_cached_key_cannot_refresh_and_sweep_closes_allocation() {
    let (relay, server) = udp_server((51400, 51499)).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (user, _) = creds(60);
    let (nonce, key) = raw_allocate(&socket, server, &user).await;
    let refresh =
        |kind| packet(kind, &[(0x0006, user.as_bytes()), (0x0014, b"turn.test"), (0x0015, &nonce)], Some(&key));
    let mut buf = [0; 2048];
    // Prove the signed Refresh works before expiry, with the cached key.
    socket.send_to(&refresh(0x0004), server).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0104);
    // Move this relay's Unix clock to the credential's expiry.
    let expiry = credential_parts(&user).unwrap().0;
    relay.shared.clock_skew.store(expiry - crate::tokens::now(), Ordering::SeqCst);
    assert!(relay.shared.now() >= expiry);
    // All four authenticated methods are blocked even before the sweep.
    // The UDP path handles datagrams in order, so the Binding answer
    // arriving first proves the request before it got no reply.
    for kind in [0x0003, 0x0004, 0x0008, 0x0009] {
        socket.send_to(&refresh(kind), server).await.unwrap();
        let binding = packet(0x0001, &[], None);
        socket.send_to(&binding, server).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        assert_eq!(stun_packet(&buf[..n]).unwrap().unwrap().kind, 0x0101, "reply to expired {kind:#06x}");
        assert_eq!(buf[8..20], binding[8..20]);
    }
    let handle = relay.udp.lock().unwrap().clone().unwrap();
    assert_eq!(handle.get_allocations_info(None).await.unwrap().len(), 1);
    // Exercise the scheduled sweep with virtual time after wall-clock expiry.
    tokio::time::pause();
    tokio::time::advance(SWEEP_INTERVAL).await;
    wait_allocations(&relay, 0).await;
    assert!(handle.get_allocations_info(None).await.unwrap().is_empty());
    assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
}

#[tokio::test]
async fn per_tunnel_quota_and_release() {
    let (relay, server) = udp_server((51500, 51799)).await;
    let mut permits = Vec::new();
    for i in 1..MAX_ALLOCATIONS_PER_TUNNEL {
        permits.push(
            relay
                .shared
                .reserve(&Identity {
                    username: tunnel_creds("quota-tunnel").0,
                    source: SocketAddr::from(([192, 0, 2, i as u8], 1)),
                })
                .unwrap(),
        );
    }
    let c = udp_client(server, tunnel_creds("quota-tunnel")).await;
    let held = c.allocate().await.unwrap();
    let extra = udp_client(server, tunnel_creds("quota-tunnel")).await;
    let error = extra.allocate().await.err().expect("quota refusal");
    assert!(error.to_string().contains("486"), "quota response must be visible: {error}");
    assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 1);
    held.close().await.unwrap();
    wait_allocations(&relay, 0).await;
    let replacement = extra.allocate().await.unwrap();
    replacement.close().await.unwrap();
    wait_allocations(&relay, 0).await;
    drop(permits);
    let security = relay.shared.security.lock().unwrap();
    assert!(security.tunnels.is_empty() && security.ips.is_empty());
}

#[tokio::test]
async fn relay_bind_failure_close_and_drop_release_quota() {
    let occupied = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let port = occupied.local_addr().unwrap().port();
    let relay = Relay::for_test(PUBLIC, port, port, SECRET);
    let generator = RelayGen {
        shared: relay.shared.clone(),
        refused: Arc::new(AtomicBool::new(false)),
        activity: Arc::new(AllocationActivity::new()),
        context: Arc::new(Mutex::new(Some(Identity {
            username: creds(600).0,
            source: "127.0.0.1:1".parse().unwrap(),
        }))),
    };
    assert!(generator.allocate_conn(true, 0).await.is_err());
    assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
    assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 0);
    drop(occupied);
    let (conn, _) = generator.allocate_conn(true, 0).await.unwrap();
    drop(conn);
    assert!(relay.shared.security.lock().unwrap().ips.is_empty());
    let (conn, _) = generator.allocate_conn(true, 0).await.unwrap();
    conn.close().await.unwrap();
    conn.close().await.unwrap();
    drop(conn);
    assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
    assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 0);
    assert_eq!(relay.shared.metrics.allocations(), 0);
}

#[tokio::test]
async fn per_source_ip_quota_across_tunnels_and_release() {
    let (relay, server) = udp_server((51800, 52299)).await;
    let mut permits = Vec::new();
    for i in 1..MAX_ALLOCATIONS_PER_IP {
        permits.push(
            relay
                .shared
                .reserve(&Identity {
                    username: tunnel_creds(&format!("ip-tunnel-{i}")).0,
                    source: "127.0.0.1:1".parse().unwrap(),
                })
                .unwrap(),
        );
    }
    let c = udp_client(server, tunnel_creds("last-tunnel")).await;
    let held = c.allocate().await.unwrap();
    let extra = udp_client(server, tunnel_creds("another-tunnel")).await;
    let error = extra.allocate().await.err().expect("quota refusal");
    assert!(error.to_string().contains("486"), "quota response must be visible: {error}");
    held.close().await.unwrap();
    wait_allocations(&relay, 0).await;
    let replacement = extra.allocate().await.unwrap();
    replacement.close().await.unwrap();
    wait_allocations(&relay, 0).await;
    drop(permits);
    let security = relay.shared.security.lock().unwrap();
    assert!(security.tunnels.is_empty() && security.ips.is_empty());
}

#[test]
fn ipv6_quota_uses_64_bit_network_and_normalizes_mapped_ipv4() {
    assert_eq!(
        source_network("2001:db8:1:2::1".parse().unwrap()),
        source_network("2001:db8:1:2:ffff::9".parse().unwrap())
    );
    assert_ne!(source_network("2001:db8:1:2::1".parse().unwrap()), source_network("2001:db8:1:3::1".parse().unwrap()));
    assert_eq!(source_network("::ffff:127.0.0.1".parse().unwrap()), "127.0.0.1".parse::<IpAddr>().unwrap());
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    let mut permits = Vec::new();
    for i in 0..MAX_ALLOCATIONS_PER_IP {
        let identity = Identity {
            username: tunnel_creds(&format!("ipv6-{}", i / 32)).0,
            source: format!("[2001:db8:1:2::{:x}]:1234", i + 1).parse().unwrap(),
        };
        permits.push(relay.shared.reserve(&identity).unwrap());
    }
    let identity =
        Identity { username: tunnel_creds("ipv6-extra").0, source: "[2001:db8:1:2::ffff]:1".parse().unwrap() };
    assert!(relay.shared.reserve(&identity).is_err());
    permits.pop();
    assert!(relay.shared.reserve(&identity).is_ok());
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_stream_deadline_is_absolute_and_releases_slot() {
    let relay = Arc::new(Relay::for_test(PUBLIC, 52300, 52399, SECRET));
    let (mut client, stream) = tokio::io::duplex(4096);
    let local = "127.0.0.1:3478".parse().unwrap();
    let peer = "127.0.0.1:12345".parse().unwrap();
    let task = tokio::spawn({
        let relay = relay.clone();
        async move { relay.serve_stream(stream, local, peer).await }
    });
    tokio::task::yield_now().await;
    assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS - 1);
    // Repeated valid Binding requests do not authenticate the stream.
    for _ in 0..9 {
        client.write_all(&packet(0x0001, &[], None)).await.unwrap();
        let mut head = [0; 4];
        client.read_exact(&mut head).await.unwrap();
        let (len, _) = frame_len(head).unwrap();
        client.read_exact(&mut vec![0; len - 4]).await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    task.await.unwrap();
    assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn partial_stream_frame_cannot_hold_auth_slot() {
    let relay = Arc::new(Relay::for_test(PUBLIC, 52400, 52499, SECRET));
    let (mut client, stream) = tokio::io::duplex(64);
    let task = tokio::spawn({
        let relay = relay.clone();
        async move {
            relay.serve_stream(stream, "127.0.0.1:3478".parse().unwrap(), "127.0.0.1:1".parse().unwrap()).await;
        }
    });
    client.write_all(&[0, 3]).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(STREAM_AUTH_DEADLINE).await;
    task.await.unwrap();
    assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
}

#[tokio::test]
async fn authenticated_stream_survives_auth_deadline() {
    let relay = Arc::new(Relay::for_test(PUBLIC, 52500, 52599, SECRET));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(relay.clone().accept_tcp(listener));
    let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
    let conn = Arc::new(StreamConn::new(tcp, "127.0.0.1:1".parse().unwrap(), server));
    let c = client(server, conn.clone(), creds(600)).await;
    let _allocation = c.allocate().await.unwrap();
    tokio::time::pause();
    tokio::time::advance(STREAM_AUTH_DEADLINE + Duration::from_secs(1)).await;
    assert!(!conn.closed.is_cancelled());
    assert_eq!(relay.shared.allocations.load(Ordering::SeqCst), 1);
    assert!(c.send_binding_request().await.is_ok());
    conn.close().await.unwrap();
    wait_allocations(&relay, 0).await;
}

#[tokio::test]
async fn refresh_zero_releases_stream_slot_within_auth_deadline() {
    let relay = Arc::new(Relay::for_test(PUBLIC, 53100, 53199, SECRET));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let accept = tokio::spawn(relay.clone().accept_tcp(listener));
    let tcp = tokio::net::TcpStream::connect(server).await.unwrap();
    let conn = Arc::new(StreamConn::new(tcp, "127.0.0.1:1".parse().unwrap(), server));
    let c = client(server, conn.clone(), creds(600)).await;
    let allocation = c.allocate().await.unwrap();
    allocation.close().await.unwrap();
    wait_allocations(&relay, 0).await;
    // turn 0.17.3 also closes its transport on allocation teardown. Accept
    // that immediate closure; never permit the stream to retain a slot.
    tokio::time::pause();
    tokio::time::advance(STREAM_AUTH_DEADLINE + Duration::from_secs(1)).await;
    for _ in 0..100 {
        if relay.streams.available_permits() == MAX_STREAM_CONNS {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(relay.streams.available_permits(), MAX_STREAM_CONNS);
    assert!(relay.shared.stream_ips.lock().unwrap().is_empty());
    accept.abort();
}

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn temp_dir_guard_removes_sidecars_on_unwind() {
    let path = std::env::temp_dir().join("tunnel-turn-tests").join(crate::tokens::random_tunnel_id());
    let result = std::panic::catch_unwind(|| {
        let _dir = TempDir(path.clone());
        std::fs::create_dir_all(&path).unwrap();
        for file in ["state.db", "state.db-wal", "state.db-shm"] {
            std::fs::write(path.join(file), b"test").unwrap();
        }
        panic!("exercise fixture cleanup");
    });
    assert!(result.is_err());
    assert!(!path.exists());
}

async fn state_with_tunnel() -> (Arc<crate::state::AppState>, TempDir) {
    let dir = TempDir(std::env::temp_dir().join("tunnel-turn-tests").join(crate::tokens::random_tunnel_id()));
    std::fs::create_dir_all(&dir.0).unwrap();
    let path = dir.0.join("state.db");
    let db = crate::db::Db::open(&path).unwrap();
    let config: Config = toml::from_str(
        r#"
ui_secret = "public-test-fixture-server-secret-0123456789"
preview_zone = "previews.example.com"
api_host = "api.example.com"
tunnel_host = "tunnel.example.com"
turn_host = "turn.test"
admin_token_hash = "test-placeholder"
[acme]
email = "admin@example.com"
[dns]
provider = "cloudflare"
zone = "example.com"
"#,
    )
    .unwrap();
    db.create_tunnel(
        crate::db::NewTunnel {
            id: "abcdefghij".into(),
            token_hash: "test-token-hash".into(),
            label: None,
            name: None,
            metadata: None,
            max_ports: 8,
            host_header: crate::db::HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: crate::tokens::now() + 3600,
            access: crate::db::Access::default(),
            client_id: None,
        },
        100,
    )
    .await
    .unwrap();
    let certs = crate::tls::CertStore::new(path.with_extension("certs"));
    (crate::state::AppState::new(config, db, certs), dir)
}

#[tokio::test]
async fn state_delete_revokes_new_and_existing_udp_and_stream_allocations() {
    let (state, _dir) = state_with_tunnel().await;
    let (relay, server) = udp_server((52600, 52699)).await;
    let relay = Arc::new(relay);
    state.install_turn(relay.clone());
    let udp = udp_client(server, creds(600)).await;
    let _udp_allocation = udp.allocate().await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stream_server = listener.local_addr().unwrap();
    let accept = tokio::spawn(relay.clone().accept_tcp(listener));
    let tcp = tokio::net::TcpStream::connect(stream_server).await.unwrap();
    let conn = Arc::new(StreamConn::new(tcp, "127.0.0.1:1".parse().unwrap(), stream_server));
    let stream_client = client(stream_server, conn, creds(600)).await;
    let _stream_allocation = stream_client.allocate().await.unwrap();
    wait_allocations(&relay, 2).await;
    state.delete_tunnel("abcdefghij", tunnel_protocol::CloseReason::Deleted).await.unwrap();
    wait_allocations(&relay, 0).await;
    let fresh = udp_client(server, creds(600)).await;
    allocation_refused(&fresh).await;
    assert!(!relay.shared.validate(&creds(600).0).await);
    let handle = relay.udp.lock().unwrap().clone().unwrap();
    assert!(handle.get_allocations_info(None).await.unwrap().is_empty());
    assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
    accept.abort();
    drop(state);
}

#[tokio::test]
async fn external_delete_is_detected_by_cached_refresh_validation() {
    let (state, _dir) = state_with_tunnel().await;
    let (relay, server) = udp_server((52700, 52799)).await;
    let relay = Arc::new(relay);
    state.install_turn(relay.clone());
    let c = udp_client(server, creds(600)).await;
    let _allocation = c.allocate().await.unwrap();
    // A second DB connection models the separate CLI process.
    let external = crate::db::Db::open(&_dir.0.join("state.db")).unwrap();
    external.delete_tunnel("abcdefghij".into()).await.unwrap();
    // Age both the AppState cache and the relay's refresh validation cache.
    state.invalidate_tunnel("abcdefghij");
    tokio::time::pause();
    tokio::time::advance(VALIDATION_TTL).await;
    assert!(!relay.shared.validate(&creds(600).0).await);
    let handle = relay.udp.lock().unwrap().clone().unwrap();
    sweep_server(&handle, &relay.shared).await;
    wait_allocations(&relay, 0).await;
    let fresh = udp_client(server, creds(600)).await;
    allocation_refused(&fresh).await;
    drop(external);
    drop(state);
}

#[tokio::test]
async fn external_delete_is_checked_after_allocate_validation_cache_expires() {
    let (state, _dir) = state_with_tunnel().await;
    let (relay, server) = udp_server((52800, 52899)).await;
    let relay = Arc::new(relay);
    state.install_turn(relay.clone());
    assert!(!relay.shared.validate(&tunnel_creds("unknown-tunnel").0).await);
    assert!(relay.shared.security.lock().unwrap().revoked.is_empty());
    let c = udp_client(server, creds(600)).await;
    let _allocation = c.allocate().await.unwrap();
    assert!(relay.shared.security.lock().unwrap().validated.contains_key("abcdefghij"));
    let external = crate::db::Db::open(&_dir.0.join("state.db")).unwrap();
    external.delete_tunnel("abcdefghij".into()).await.unwrap();
    state.invalidate_tunnel("abcdefghij");
    tokio::time::pause();
    tokio::time::advance(VALIDATION_TTL).await;
    let fresh = udp_client(server, creds(600)).await;
    allocation_refused(&fresh).await;
    // The packet queued validation without awaiting it. Wait for the task.
    while relay.shared.security.lock().unwrap().validating.contains("abcdefghij") {
        tokio::task::yield_now().await;
    }
    assert!(!relay.shared.credential_allowed(&creds(600).0));
    let handle = relay.udp.lock().unwrap().clone().unwrap();
    sweep_server(&handle, &relay.shared).await;
    wait_allocations(&relay, 0).await;
    drop(external);
    drop(state);
}

#[test]
fn request_gate_rejects_ambiguous_and_malformed_stun() {
    let user = creds(600).0;
    assert!(stun_packet(&packet(0x0004, &[(0x0006, user.as_bytes())], None)).unwrap().unwrap().username.is_some());
    assert!(stun_packet(&packet(0x0004, &[(0x0006, user.as_bytes()), (0x0006, b"other")], None)).is_err());
    let mut truncated = packet(0x0004, &[(0x0006, user.as_bytes())], None);
    truncated.pop();
    assert!(stun_packet(&truncated).is_err());
    assert!(stun_packet(&[0, 3, 0, 0]).is_err());
    assert!(stun_packet(&packet(0x0003, &[(0x0006, &[b'x'; 514])], None)).is_err());
    assert!(stun_packet(&[0x40, 0, 0, 0]).unwrap().is_none());
    assert!(stun_packet(&packet(0x0003, &[(0x0022, &[0; 8])], None)).unwrap().unwrap().reservation);
}

#[tokio::test(start_paused = true)]
async fn revocation_fences_only_seen_tunnels_are_short_and_never_deny_globally() {
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    for i in 0..SECURITY_ENTRIES + 1 {
        relay.shared.revoke(&format!("unseen-{i}"));
    }
    assert!(relay.shared.security.lock().unwrap().revoked.is_empty());
    assert!(relay.shared.credential_allowed(&creds(600).0));
    {
        let mut security = relay.shared.security.lock().unwrap();
        for i in 0..SECURITY_ENTRIES {
            security.revoked.insert(format!("id-{i}"), tokio::time::Instant::now() + REVOCATION_TTL);
        }
        security.validated.insert("overflow".into(), (tokio::time::Instant::now(), crate::tokens::now() + 600));
    }
    relay.shared.revoke("overflow");
    assert_eq!(relay.shared.security.lock().unwrap().revoked.len(), SECURITY_ENTRIES);
    assert!(!relay.shared.credential_allowed(&tunnel_creds("overflow").0));
    assert!(relay.shared.credential_allowed(&creds(600).0));
    tokio::time::advance(REVOCATION_TTL).await;
    assert!(relay.shared.credential_allowed(&tunnel_creds("overflow").0));
    relay.shared.security.lock().unwrap().revoked.retain(|_, until| *until > tokio::time::Instant::now());
    assert!(relay.shared.security.lock().unwrap().revoked.is_empty());
}

#[test]
fn request_integrity_requires_the_long_term_key_and_authenticated_username() {
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    let (user, password) = creds(600);
    let key = generate_auth_key(&user, "turn.test", &password);
    let raw = packet(0x0003, &[(0x0006, user.as_bytes())], Some(&key));
    assert!(verify_integrity(&raw, &user, &relay.shared));
    let quota = quota_response(&packet(0x0113, &[], None), &user, &relay.shared).unwrap();
    assert_eq!(stun_packet(&quota).unwrap().unwrap().kind, 0x0113);
    assert_eq!(&attribute(&quota, 0x0009).unwrap()[..4], &[0, 0, 4, 86]);
    assert!(verify_integrity(&quota, &user, &relay.shared));
    assert!(!verify_integrity(&packet(0x0003, &[(0x0006, user.as_bytes())], None), &user, &relay.shared));
    assert!(!verify_integrity(&packet(0x0003, &[(0x0006, user.as_bytes())], Some(b"wrong")), &user, &relay.shared));
    let mut tampered = raw.clone();
    tampered[24] ^= 1;
    assert!(!verify_integrity(&tampered, &user, &relay.shared));
    let mut duplicate = raw.clone();
    duplicate.extend_from_slice(&[0, 8, 0, 20]);
    duplicate.extend_from_slice(&[0; 20]);
    let len = (duplicate.len() - 20) as u16;
    duplicate[2..4].copy_from_slice(&len.to_be_bytes());
    assert!(stun_packet(&duplicate).is_err());
    let mut suffix = raw;
    suffix.extend_from_slice(&[0, 6, 0, 4, b'l', b'a', b't', b'e']);
    let len = (suffix.len() - 20) as u16;
    suffix[2..4].copy_from_slice(&len.to_be_bytes());
    assert!(stun_packet(&suffix).is_err());
}

#[tokio::test]
async fn guard_checks_integrity_before_bounded_deduplicated_background_validation() {
    let (state, _dir) = state_with_tunnel().await;
    let relay = Arc::new(Relay::for_test(PUBLIC, 0, 0, SECRET));
    state.install_turn(relay.clone());
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let guard = GuardConn::new(socket, relay.shared.clone());
    let (user, password) = creds(600);
    let mut buf = [0; 2048];
    for key in [None, Some(b"wrong".as_slice())] {
        let raw = packet(0x0003, &[(0x0006, user.as_bytes())], key);
        source.send_to(&raw, addr).await.unwrap();
        let (n, _) = guard.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], raw);
        assert!(guard.context.lock().unwrap().is_none());
    }
    assert!(relay.shared.security.lock().unwrap().validating.is_empty());
    assert!(relay.shared.security.lock().unwrap().validated.is_empty());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let db = state.db.clone();
    let blocked = tokio::spawn(async move {
        db.call(move |_| {
            let _ = ready_tx.send(());
            release_rx.recv().unwrap();
            Ok(())
        })
        .await
        .unwrap();
    });
    ready_rx.await.unwrap();
    let key = generate_auth_key(&user, "turn.test", &password);
    source.send_to(&packet(0x0003, &[(0x0006, user.as_bytes())], Some(&key)), addr).await.unwrap();
    let binding = packet(0x0001, &[], None);
    source.send_to(&binding, addr).await.unwrap();
    let received = tokio::time::timeout(Duration::from_millis(250), guard.recv_from(&mut buf)).await;
    // Duplicate misses share one lookup; other ids can use at most 8 slots.
    for _ in 0..20 {
        assert!(!relay.shared.request_validation(&user));
    }
    assert_eq!(relay.shared.security.lock().unwrap().validating.len(), 1);
    for i in 0..VALIDATION_LOOKUPS * 2 {
        assert!(!relay.shared.request_validation(&tunnel_creds(&format!("missing-{i}")).0));
    }
    assert_eq!(relay.shared.security.lock().unwrap().validating.len(), VALIDATION_LOOKUPS);
    assert_eq!(relay.shared.validation_slots.available_permits(), 0);
    release_tx.send(()).unwrap();
    blocked.await.unwrap();
    let (n, _) = received.expect("DB cannot stall UDP").unwrap();
    assert_eq!(&buf[..n], binding);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !relay.shared.security.lock().unwrap().validating.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Unknown-id revocations may invalidate a simultaneous positive lookup;
    // an ordinary retransmit queues it again and then uses its cache result.
    if relay.shared.cached_validation("abcdefghij") != Some(true) {
        assert!(!relay.shared.request_validation(&user));
        while relay.shared.security.lock().unwrap().validating.contains("abcdefghij") {
            tokio::task::yield_now().await;
        }
    }
    assert!(relay.shared.request_validation(&user));
    assert_eq!(relay.shared.validation_slots.available_permits(), VALIDATION_LOOKUPS);
    drop(state);
}

#[tokio::test(start_paused = true)]
async fn challenge_limits_burst_refill_networks_global_cap_and_map_size() {
    let mut limiter = ChallengeLimiter::new();
    let ip = "2001:db8:1:2::1".parse().unwrap();
    for _ in 0..CHALLENGE_IP_BURST as usize {
        assert!(limiter.allow(ip));
    }
    for _ in 0..100 {
        assert!(!limiter.allow("2001:db8:1:2::2".parse().unwrap()));
    }
    assert!(limiter.allow("2001:db8:1:3::1".parse().unwrap()));
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(limiter.allow(ip));
    assert!(!limiter.allow(ip));
    let mut limiter = ChallengeLimiter::new();
    for i in 0..CHALLENGE_GLOBAL_BURST as usize {
        assert!(limiter.allow(IpAddr::V4(Ipv4Addr::from(i as u32 + 1))));
    }
    assert!(!limiter.allow("203.0.113.1".parse().unwrap()));
    tokio::time::advance(Duration::from_millis(5)).await;
    assert!(limiter.allow("203.0.113.1".parse().unwrap()));
    assert!(!limiter.allow("203.0.113.1".parse().unwrap()));
    // Fill the table without exceeding the global rate.
    let mut limiter = ChallengeLimiter::new();
    for i in 0..CHALLENGE_IP_ENTRIES {
        tokio::time::advance(Duration::from_millis(20)).await;
        limiter.ips.insert(IpAddr::V4(Ipv4Addr::from(i as u32 + 1)), RequestBucket::new(CHALLENGE_IP_BURST));
    }
    // Refresh timestamps to model a full active table.
    for bucket in limiter.ips.values_mut() {
        bucket.at = tokio::time::Instant::now();
    }
    let oldest = "198.51.100.1".parse().unwrap();
    limiter.ips.remove(&IpAddr::V4(Ipv4Addr::from(1)));
    limiter.ips.insert(
        oldest,
        RequestBucket { tokens: CHALLENGE_IP_BURST, at: tokio::time::Instant::now() - Duration::from_secs(1) },
    );
    assert!(limiter.allow("203.0.113.2".parse().unwrap()));
    assert!(!limiter.ips.contains_key(&oldest));
    assert_eq!(limiter.ips.len(), CHALLENGE_IP_ENTRIES);
    tokio::time::advance(CHALLENGE_IDLE).await;
    assert!(limiter.allow("203.0.113.2".parse().unwrap()));
    assert_eq!(limiter.ips.len(), 1);
}

#[tokio::test]
async fn guard_drops_excess_challenges_before_turn() {
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let guard = GuardConn::new(socket, relay.shared.clone());
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let challenge = packet(0x0003, &[], None);
    let mut buf = [0; 2048];
    for _ in 0..CHALLENGE_IP_BURST as usize {
        source.send_to(&challenge, addr).await.unwrap();
        guard.recv_from(&mut buf).await.unwrap();
    }
    source.send_to(&challenge, addr).await.unwrap();
    // A ChannelData marker proves recv continued past the dropped request.
    source.send_to(&[0x40, 0, 0, 0], addr).await.unwrap();
    let (n, _) = guard.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &[0x40, 0, 0, 0]);
}

#[test]
fn stream_slots_are_per_network_and_return_on_drop() {
    let relay = Relay::for_test(PUBLIC, 0, 0, SECRET);
    let ip = "2001:db8:1:2::1".parse().unwrap();
    let mut held: Vec<_> = (0..MAX_STREAM_CONNS_PER_IP).map(|_| relay.shared.reserve_stream(ip).unwrap()).collect();
    assert!(relay.shared.reserve_stream("2001:db8:1:2::ffff".parse().unwrap()).is_none());
    assert!(relay.shared.reserve_stream("2001:db8:1:3::1".parse().unwrap()).is_some());
    held.pop();
    assert!(relay.shared.reserve_stream(ip).is_some());
    drop(held);
    assert!(relay.shared.stream_ips.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn empty_stream_deadline_restarts_only_after_last_allocation_closes() {
    let activity = Arc::new(AllocationActivity::new());
    let timeout = tokio::spawn({
        let activity = activity.clone();
        async move { activity.empty_timeout().await }
    });
    activity.open();
    activity.open();
    tokio::time::advance(STREAM_AUTH_DEADLINE * 2).await;
    assert!(!timeout.is_finished());
    activity.close();
    tokio::time::advance(STREAM_AUTH_DEADLINE * 2).await;
    assert!(!timeout.is_finished());
    activity.close();
    tokio::task::yield_now().await;
    tokio::time::advance(STREAM_AUTH_DEADLINE - Duration::from_secs(1)).await;
    assert!(!timeout.is_finished());
    activity.open();
    tokio::time::advance(STREAM_AUTH_DEADLINE * 2).await;
    assert!(!timeout.is_finished());
    activity.close();
    tokio::task::yield_now().await;
    tokio::time::advance(STREAM_AUTH_DEADLINE).await;
    timeout.await.unwrap();
}

#[tokio::test]
async fn relay_fast_path_avoids_quota_and_security_locks_and_latches_revocation() {
    let relay = Relay::for_test(PUBLIC, 52900, 52999, SECRET);
    let generator = RelayGen {
        shared: relay.shared.clone(),
        refused: Arc::new(AtomicBool::new(false)),
        activity: Arc::new(AllocationActivity::new()),
        context: Arc::new(Mutex::new(Some(Identity {
            username: creds(600).0,
            source: "127.0.0.1:1".parse().unwrap(),
        }))),
    };
    let (conn, _) = generator.allocate_conn(true, 0).await.unwrap();
    let relay_conn = conn.as_any().downcast_ref::<RelayConn>().unwrap();
    assert!(relay_conn.allow(1));
    let (result, fast) = {
        let _security = relay.shared.security.lock().unwrap();
        let _quota = relay_conn.quota.lock().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let fast = std::thread::spawn({
            let conn = conn.clone();
            move || {
                let allowed = conn.as_any().downcast_ref::<RelayConn>().unwrap().allow(1);
                let _ = done_tx.send(allowed);
            }
        });
        (done_rx.recv_timeout(Duration::from_millis(250)), fast)
    };
    fast.join().unwrap();
    assert!(result.expect("fast path must not lock either mutex"));
    relay.shared.revoke("abcdefghij");
    assert!(!relay_conn.allow(1));
    relay.shared.security.lock().unwrap().revoked.clear();
    relay.shared.revocation_epoch.fetch_add(1, Ordering::Release);
    assert!(!relay_conn.allow(1));
    conn.close().await.unwrap();
}

#[tokio::test]
async fn sweep_retries_revoked_allocations_even_without_a_remaining_fence() {
    let (relay, server) = udp_server((53000, 53099)).await;
    let c = udp_client(server, creds(600)).await;
    let _held = c.allocate().await.unwrap();
    // Model a missed broadcast deletion: fence locally but send no command.
    relay.shared.revoke("abcdefghij");
    relay.shared.security.lock().unwrap().revoked.clear();
    let handle = relay.udp.lock().unwrap().clone().unwrap();
    sweep_server(&handle, &relay.shared).await;
    wait_allocations(&relay, 0).await;
    assert!(handle.get_allocations_info(None).await.unwrap().is_empty());
    sweep_server(&handle, &relay.shared).await;
    assert!(relay.shared.security.lock().unwrap().tunnels.is_empty());
}

#[test]
fn peer_rules() {
    for ip in [
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "2001:db8::1",
    ] {
        assert!(denied_peer(ip.parse().unwrap(), false), "{ip}");
    }
    for ip in ["8.8.8.8", "203.0.113.9", "100.128.0.1"] {
        assert!(!denied_peer(ip.parse().unwrap(), false), "{ip}");
    }
}

#[test]
fn stream_framing() {
    // STUN binding request header, length 8.
    assert_eq!(frame_len([0x00, 0x01, 0x00, 0x08]), Some((28, 0)));
    // ChannelData 0x4000 with 5 bytes: padded by 3 over streams.
    assert_eq!(frame_len([0x40, 0x00, 0x00, 0x05]), Some((9, 3)));
    assert_eq!(frame_len([0x40, 0x00, 0x00, 0x08]), Some((12, 0)));
    assert_eq!(frame_len([0x80, 0, 0, 0]), None);
    assert_eq!(frame_len([0xC0, 0, 0, 0]), None);
}
