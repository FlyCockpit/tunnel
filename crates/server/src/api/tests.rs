use super::*;

#[tokio::test]
async fn access_patch_defers_omitted_password_to_transaction() {
    let current = Access {
        mode: AccessMode::Password,
        password_user: Some("ann".into()),
        password_hash: Some("test-hash".into()),
    };
    let access = build_access(
        AccessRequest { mode: AccessMode::Password, username: Some("beth".into()), password: None },
        Some(&current),
        test_state(false, 20).pepper.clone(),
        "row1",
    )
    .await
    .unwrap();
    assert_eq!(access.password_user.as_deref(), Some("beth"));
    assert!(access.password_hash.is_none(), "a partial PATCH must not carry an earlier hash");
    assert!(
        build_access(
            AccessRequest { mode: AccessMode::Password, username: Some("ann".into()), password: None },
            None,
            test_state(false, 20).pepper.clone(),
            "row1"
        )
        .await
        .is_err(),
        "creation still requires a password"
    );
}

const ADMIN_CREDENTIAL: &str = "tnadm_public-test-fixture";
const CLIENT_CREDENTIAL: &str = "tncli_public-test-fixture";
const HEALTH_CREDENTIAL: &str = "public-health-test-fixture";

fn test_state(health: bool, quota: u32) -> Arc<AppState> {
    let mut config: crate::config::Config = serde_json::from_value(serde_json::json!({
        "ui_secret": "public-test-fixture-server-secret-0123456789",
        "preview_zone": "previews.example.com", "api_host": "api.example.com",
        "tunnel_host": "tunnel.example.com", "turn_host": "turn.example.com",
        "admin_token_hash": tokens::hash_token(ADMIN_CREDENTIAL),
        "acme": {"email": "test@example.com"},
        "dns": {"provider": "cloudflare", "zone": "example.com"}
    }))
    .unwrap();
    config.health_token_hash = health.then(|| tokens::hash_token(HEALTH_CREDENTIAL));
    config.limits.max_tunnels_per_client = quota;
    let db = crate::db::Db::open(std::path::Path::new(":memory:")).unwrap();
    let certs = crate::tls::CertStore::new(std::env::temp_dir().join("tunnel-api-tests").join("certs"));
    AppState::new(config, db, certs)
}

async fn request(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    credential: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(credential) = credential {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    let body = if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        axum::body::Body::from(body.to_string())
    } else {
        axum::body::Body::empty()
    };
    let response = build_router().with_state(state.clone()).oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    (status, body)
}

async fn enroll_test_client(state: &Arc<AppState>, id: &str, name: &str) {
    state.db.insert_test_user("utest", "tester", Role::Member).await;
    state
        .db
        .create_client(id.into(), name.into(), "utest".into(), format!("code-{id}"), now() + 600, None)
        .await
        .unwrap()
        .unwrap();
    state.db.enroll_client(format!("code-{id}"), tokens::hash_token(CLIENT_CREDENTIAL)).await.unwrap().unwrap();
}

async fn gate_password_login(state: &AppState, id: &str, username: &str, password: &str) -> bool {
    use crate::edge::gate::{LoginForm, LoginOutcome};
    let tunnel = state.db.get_tunnel(id.into()).await.unwrap().unwrap();
    let form = LoginForm { to: id.into(), username: username.into(), password: password.into(), next: "/".into() };
    matches!(
        crate::edge::gate::login(state, "203.0.113.1".parse().unwrap(), &tunnel, form, &[]).await,
        LoginOutcome::Granted(_)
    )
}

#[tokio::test]
async fn open_health_omits_version_even_with_admin_token() {
    let state = test_state(false, 20);
    for credential in [None, Some(ADMIN_CREDENTIAL), Some(HEALTH_CREDENTIAL)] {
        let (status, body) = request(&state, "GET", "/healthz", credential, None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE); // No test certificate loaded.
        assert_eq!(body["database"], true);
        assert!(body.get("version").is_none());
    }
}

#[tokio::test]
async fn password_tunnel_creation_rotation_and_preservation_use_stored_seals() {
    let state = test_state(false, 20);
    enroll_test_client(&state, "cltest", "test-machine").await;
    let (status, created) = request(
        &state,
        "POST",
        "/v1/tunnels",
        Some(CLIENT_CREDENTIAL),
        Some(serde_json::json!({"ttl_s": 600, "access": {
            "mode": "password", "username": "ann", "password": "original-password"
        }})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap();
    let first = state.db.get_tunnel(id.into()).await.unwrap().unwrap().access.password_hash.unwrap();
    assert!(first.starts_with(&format!("pw1:{}:", state.pepper.clone().id())));
    assert!(gate_password_login(&state, id, "ann", "original-password").await);
    let path = format!("/v1/tunnels/{id}");
    let (status, body) = request(
        &state,
        "PATCH",
        &path,
        Some(CLIENT_CREDENTIAL),
        Some(serde_json::json!({"access": {"mode": "password", "password": "replacement-password"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second = state.db.get_tunnel(id.into()).await.unwrap().unwrap().access.password_hash.unwrap();
    assert_ne!(first, second);
    assert!(second.starts_with("pw1:"));
    assert!(!gate_password_login(&state, id, "ann", "original-password").await);
    assert!(gate_password_login(&state, id, "ann", "replacement-password").await);
    let (status, body) = request(
        &state,
        "PATCH",
        &path,
        Some(CLIENT_CREDENTIAL),
        Some(serde_json::json!({"access": {"mode": "password", "username": "beth"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        state.db.get_tunnel(id.into()).await.unwrap().unwrap().access.password_hash.as_deref(),
        Some(second.as_str())
    );
    assert!(gate_password_login(&state, id, "beth", "replacement-password").await);
    assert!(!gate_password_login(&state, id, "ann", "replacement-password").await);
}

#[tokio::test]
async fn protected_health_accepts_only_health_token_in_header_or_query() {
    let state = test_state(true, 20);
    for (uri, credential) in
        [("/healthz".to_string(), Some(HEALTH_CREDENTIAL)), (format!("/healthz?token={HEALTH_CREDENTIAL}"), None)]
    {
        let (status, body) = request(&state, "GET", &uri, credential, None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }
    for (uri, credential) in [
        ("/healthz".to_string(), None),
        ("/healthz".to_string(), Some(ADMIN_CREDENTIAL)),
        (format!("/healthz?token={ADMIN_CREDENTIAL}"), None),
        ("/healthz".to_string(), Some("wrong")),
        ("/healthz?token=wrong".to_string(), None),
    ] {
        let (status, body) = request(&state, "GET", &uri, credential, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"]["code"], "not_found");
    }
}

#[tokio::test]
async fn client_tunnel_quota_returns_429_and_admin_is_unlimited() {
    let state = test_state(false, 1);
    enroll_test_client(&state, "c1", "one").await;
    for expected in [StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS] {
        let (status, body) =
            request(&state, "POST", "/v1/tunnels", Some(CLIENT_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600})))
                .await;
        assert_eq!(status, expected);
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["error"]["code"], "tunnel_quota");
        }
    }
    for _ in 0..2 {
        let (status, _) =
            request(&state, "POST", "/v1/tunnels", Some(ADMIN_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600})))
                .await;
        assert_eq!(status, StatusCode::CREATED);
    }
}

#[tokio::test]
async fn tunnel_and_client_lists_have_two_keyset_pages() {
    let state = test_state(false, 20);
    enroll_test_client(&state, "c1", "one").await;
    for (id, name) in [("c2", "two"), ("c3", "three")] {
        state.db.insert_test_user("utest", "tester", Role::Member).await;
        state
            .db
            .create_client(id.into(), name.into(), "utest".into(), format!("code-{id}"), now() + 600, None)
            .await
            .unwrap()
            .unwrap();
    }
    for _ in 0..3 {
        assert_eq!(
            request(&state, "POST", "/v1/tunnels", Some(CLIENT_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600})))
                .await
                .0,
            StatusCode::CREATED
        );
    }
    assert_eq!(
        request(&state, "POST", "/v1/tunnels", Some(ADMIN_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600}))).await.0,
        StatusCode::CREATED
    );
    for (path, field, key, credential, total) in [
        ("/v1/tunnels", "tunnels", "id", CLIENT_CREDENTIAL, 3),
        ("/v1/tunnels", "tunnels", "id", ADMIN_CREDENTIAL, 4),
        ("/v1/clients", "clients", "name", ADMIN_CREDENTIAL, 3),
    ] {
        let (status, first) = request(&state, "GET", &format!("{path}?limit=2"), Some(credential), None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = first[field].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let cursor = first["next_cursor"].as_str().unwrap();
        assert_eq!(cursor, rows[1][key].as_str().unwrap());
        let (status, second) =
            request(&state, "GET", &format!("{path}?limit=2&cursor={cursor}"), Some(credential), None).await;
        assert_eq!(status, StatusCode::OK);
        let remaining = second[field].as_array().unwrap();
        assert_eq!(remaining.len(), total - 2);
        assert!(remaining[0][key].as_str().unwrap() > cursor);
        assert!(second.get("next_cursor").is_none());
    }
}

#[tokio::test]
async fn list_default_page_size_is_100() {
    let state = test_state(false, 20);
    state
        .db
        .call(|c| {
            let tx = c.transaction()?;
            tx.execute(
                "INSERT INTO users (id, username, password_hash, role, limit_tunnels, limit_clients, created_at)
                 VALUES ('utest', 'tester', 'x', 'member', 1000, 1000, 0)",
                [],
            )?;
            for i in 0..101 {
                tx.execute(
                    "INSERT INTO clients (id, name, created_at, user_id) VALUES (?1, ?1, ?2, 'utest')",
                    rusqlite::params![format!("client-{i:03}"), now()],
                )?;
                tx.execute(
                    "INSERT INTO tunnels (id, token_hash, max_ports, host_header, inject_ice, created_at, expires_at)
                 VALUES (?1, ?1, 8, 'rewrite', 0, ?2, ?3)",
                    rusqlite::params![tokens::random_tunnel_id(), now(), now() + 600],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
    for (path, field) in [("/v1/tunnels", "tunnels"), ("/v1/clients", "clients")] {
        let (status, first) = request(&state, "GET", path, Some(ADMIN_CREDENTIAL), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first[field].as_array().unwrap().len(), 100);
        let cursor = first["next_cursor"].as_str().unwrap();
        let (_, last) = request(&state, "GET", &format!("{path}?cursor={cursor}"), Some(ADMIN_CREDENTIAL), None).await;
        assert_eq!(last[field].as_array().unwrap().len(), 1);
        assert!(last.get("next_cursor").is_none());
    }
}

#[tokio::test]
async fn pagination_rejects_bad_cursors_and_limits_with_422() {
    let state = test_state(false, 20);
    for path in ["/v1/tunnels", "/v1/clients"] {
        for query in ["cursor=bad!", "cursor=", "limit=0", "limit=501", "limit=-1", "limit=abc"] {
            let (status, body) = request(&state, "GET", &format!("{path}?{query}"), Some(ADMIN_CREDENTIAL), None).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(body["error"]["code"], "validation");
        }
        for query in ["", "?limit=1", "?limit=500"] {
            let (status, _) = request(&state, "GET", &format!("{path}{query}"), Some(ADMIN_CREDENTIAL), None).await;
            assert_eq!(status, StatusCode::OK);
        }
    }
}

#[tokio::test]
async fn access_link_response_keeps_full_url_without_url_path() {
    let state = test_state(false, 20);
    let (_, tunnel) =
        request(&state, "POST", "/v1/tunnels", Some(ADMIN_CREDENTIAL), Some(serde_json::json!({"ttl_s": 600}))).await;
    let id = tunnel["id"].as_str().unwrap();
    let (status, link) = request(
        &state,
        "POST",
        &format!("/v1/tunnels/{id}/access-links"),
        Some(ADMIN_CREDENTIAL),
        Some(serde_json::json!({"ttl_s": 60})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(link["url"].as_str().unwrap().starts_with("https://previews.example.com/__access/"));
    assert!(link["id"].is_string());
    assert!(link["expires_at"].is_i64());
    assert!(link.get("url_path").is_none());
}

#[test]
fn openapi_keeps_management_paths() {
    let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    let expected = [
        ("/healthz", vec!["get"]),
        ("/v1/tunnels", vec!["get", "post"]),
        ("/v1/tunnels/{id}", vec!["get", "patch", "delete"]),
        ("/v1/tunnels/{id}/access-links", vec!["get", "post"]),
        ("/v1/access-links/{id}", vec!["delete"]),
        ("/v1/tunnels/{id}/turn-credentials", vec!["post"]),
        ("/v1/clients", vec!["get", "post"]),
        ("/v1/clients/{name}", vec!["patch", "delete"]),
        ("/v1/clients/enroll", vec!["post"]),
        ("/v1/tunnels/{id}/token", vec!["post"]),
        ("/v1/services", vec!["get", "post"]),
        ("/v1/services/{name}", vec!["patch", "delete"]),
        ("/v1/services/{name}/token", vec!["post"]),
        ("/v1/server", vec!["get"]),
        ("/v1/device/code", vec!["post"]),
        ("/v1/device/token", vec!["post"]),
    ];
    assert_eq!(doc["paths"].as_object().unwrap().len(), expected.len());
    for path in ["/v1/device/code", "/v1/device/token"] {
        assert_eq!(doc["paths"][path]["post"]["tags"], serde_json::json!(["crate::device"]), "{path}");
    }
    for (path, methods) in expected {
        for method in methods {
            assert!(doc["paths"][path][method].is_object(), "missing {method} {path}");
        }
    }
    assert_eq!(doc["components"]["securitySchemes"]["admin"]["scheme"], "bearer");
    assert!(doc["components"]["schemas"]["CreateTunnelRequest"].is_object());
    assert!(doc["components"]["schemas"]["AccessLinkResponse"]["properties"].get("url_path").is_none());
    assert!(doc["components"]["schemas"]["Health"]["required"].as_array().unwrap().iter().all(|v| v != "version"));
    assert!(doc["paths"]["/v1/tunnels"]["post"]["responses"]["429"].is_object());
    assert!(doc["paths"]["/v1/tunnels"]["post"]["responses"]["403"].is_object());
    assert!(doc["paths"]["/v1/tunnels"]["get"]["parameters"].as_array().unwrap().iter().any(|p| p["name"] == "label"));
    for path in ["/v1/tunnels", "/v1/clients", "/v1/services"] {
        let params = doc["paths"][path]["get"]["parameters"].as_array().unwrap();
        assert!(
            params.iter().any(|p| p["name"] == "limit" && p["schema"]["minimum"] == 1 && p["schema"]["maximum"] == 500)
        );
        assert!(params.iter().any(|p| p["name"] == "cursor"));
        assert!(doc["paths"][path]["get"]["responses"]["422"].is_object());
    }
}

async fn add_service(state: &Arc<AppState>, name: &str, max_tunnels: u32) -> String {
    let (status, body) = request(
        state,
        "POST",
        "/v1/services",
        Some(ADMIN_CREDENTIAL),
        Some(serde_json::json!({"name": name, "max_tunnels": max_tunnels})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["name"], name);
    assert_eq!(body["api"], "https://api.example.com");
    assert_eq!(body["server"], "wss://tunnel.example.com");
    let token = body["token"].as_str().unwrap().to_string();
    assert!(token.starts_with(SERVICE_TOKEN_PREFIX));
    token
}

async fn create(state: &Arc<AppState>, credential: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    request(state, "POST", "/v1/tunnels", Some(credential), Some(body)).await
}

#[tokio::test]
async fn service_owns_only_its_tunnels_within_its_quota() {
    let state = test_state(false, 1);
    enroll_test_client(&state, "c1", "one").await;
    let svc = add_service(&state, "wssp", 3).await;

    // Its own quota, not the client default of 1.
    for expected in [StatusCode::CREATED, StatusCode::CREATED, StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS] {
        let (status, body) = create(&state, &svc, serde_json::json!({"ttl_s": 600, "label": "sbx"})).await;
        assert_eq!(status, expected);
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["error"]["code"], "tunnel_quota");
        }
    }
    let (status, mine) = request(&state, "GET", "/v1/tunnels", Some(&svc), None).await;
    assert_eq!(status, StatusCode::OK);
    let mine: Vec<String> =
        mine["tunnels"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap().to_string()).collect();
    assert_eq!(mine.len(), 3);

    // Other owners' tunnels and links are invisible to the service, and its tunnels to them.
    let (_, client_tunnel) = create(&state, CLIENT_CREDENTIAL, serde_json::json!({"ttl_s": 600})).await;
    let (_, admin_tunnel) = create(&state, ADMIN_CREDENTIAL, serde_json::json!({"ttl_s": 600})).await;
    for other in [&client_tunnel, &admin_tunnel] {
        let id = other["id"].as_str().unwrap();
        let (status, link) = request(
            &state,
            "POST",
            &format!("/v1/tunnels/{id}/access-links"),
            Some(ADMIN_CREDENTIAL),
            Some(serde_json::json!({"ttl_s": 60})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let link = link["id"].as_str().unwrap();
        for (method, uri) in [
            ("GET", format!("/v1/tunnels/{id}")),
            ("PATCH", format!("/v1/tunnels/{id}")),
            ("DELETE", format!("/v1/tunnels/{id}")),
            ("POST", format!("/v1/tunnels/{id}/token")),
            ("POST", format!("/v1/tunnels/{id}/access-links")),
            ("DELETE", format!("/v1/access-links/{link}")),
        ] {
            let body = (method != "DELETE" && !uri.ends_with("/token")).then(|| serde_json::json!({"ttl_s": 60}));
            let (status, _) = request(&state, method, &uri, Some(&svc), body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
        }
        assert!(state.db.get_tunnel(id.to_string()).await.unwrap().is_some(), "service deleted {id}");
    }
    let (_, client_list) = request(&state, "GET", "/v1/tunnels", Some(CLIENT_CREDENTIAL), None).await;
    assert_eq!(client_list["tunnels"].as_array().unwrap().len(), 1);

    // No client or service management.
    for (method, uri) in [
        ("GET", "/v1/clients"),
        ("POST", "/v1/clients"),
        ("DELETE", "/v1/clients/one"),
        ("PATCH", "/v1/clients/one"),
        ("GET", "/v1/services"),
        ("POST", "/v1/services"),
        ("PATCH", "/v1/services/wssp"),
        ("POST", "/v1/services/wssp/token"),
        ("DELETE", "/v1/services/wssp"),
        ("GET", "/v1/openapi.json"),
    ] {
        let body = matches!(method, "POST" | "PATCH").then(|| serde_json::json!({"name": "x", "max_tunnels": 9}));
        let (status, _) = request(&state, method, uri, Some(&svc), body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }

    // The admin raises the quota; the listing shows it and the usage.
    let (status, view) = request(
        &state,
        "PATCH",
        "/v1/services/wssp",
        Some(ADMIN_CREDENTIAL),
        Some(serde_json::json!({"max_tunnels": 4})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["max_tunnels"], 4);
    assert_eq!(view["tunnels"], 3);
    assert_eq!(create(&state, &svc, serde_json::json!({"ttl_s": 600})).await.0, StatusCode::CREATED);
    let (_, list) = request(&state, "GET", "/v1/services", Some(ADMIN_CREDENTIAL), None).await;
    assert_eq!(list["services"][0]["name"], "wssp");
    assert_eq!(list["services"][0]["tunnels"], 4);
    assert!(list["services"][0]["last_used_at"].is_i64());

    // Own tunnels: delete works.
    let (status, _) = request(&state, "DELETE", &format!("/v1/tunnels/{}", mine[0]), Some(&svc), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Deleting the service ends its tunnels and its token.
    let (status, _) = request(&state, "DELETE", "/v1/services/wssp", Some(ADMIN_CREDENTIAL), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(request(&state, "GET", "/v1/tunnels", Some(&svc), None).await.0, StatusCode::UNAUTHORIZED);
    for id in &mine[1..] {
        assert!(state.db.get_tunnel(id.clone()).await.unwrap().is_none(), "{id} survived its service");
    }
    assert!(state.db.get_tunnel(client_tunnel["id"].as_str().unwrap().into()).await.unwrap().is_some());
}

#[tokio::test]
async fn service_admin_validation_and_token_rotation() {
    let state = test_state(false, 20);
    for body in [
        serde_json::json!({"name": "bad name", "max_tunnels": 5}),
        serde_json::json!({"name": "ok", "max_tunnels": 0}),
        serde_json::json!({"name": "ok", "max_tunnels": 10_001}),
        serde_json::json!({"name": "ok"}),
    ] {
        let (status, _) = request(&state, "POST", "/v1/services", Some(ADMIN_CREDENTIAL), Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let old = add_service(&state, "wssp", 5).await;
    let (status, body) = request(
        &state,
        "POST",
        "/v1/services",
        Some(ADMIN_CREDENTIAL),
        Some(serde_json::json!({"name": "wssp", "max_tunnels": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "service_exists");
    let (status, body) = request(&state, "POST", "/v1/services/wssp/token", Some(ADMIN_CREDENTIAL), None).await;
    assert_eq!(status, StatusCode::OK);
    let new = body["token"].as_str().unwrap();
    assert_ne!(new, old);
    assert_eq!(request(&state, "GET", "/v1/tunnels", Some(&old), None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(request(&state, "GET", "/v1/tunnels", Some(new), None).await.0, StatusCode::OK);
    for (method, uri) in [("POST", "/v1/services/nope/token"), ("DELETE", "/v1/services/nope")] {
        assert_eq!(request(&state, method, uri, Some(ADMIN_CREDENTIAL), None).await.0, StatusCode::NOT_FOUND);
    }
    let (status, _) = request(
        &state,
        "PATCH",
        "/v1/services/nope",
        Some(ADMIN_CREDENTIAL),
        Some(serde_json::json!({"max_tunnels": 3})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn public_previews_need_the_admin_unless_allowed() {
    let state = test_state(false, 20);
    enroll_test_client(&state, "c1", "one").await;
    let svc = add_service(&state, "wssp", 5).await;
    let public = serde_json::json!({"ttl_s": 600, "access": {"mode": "public"}});
    for credential in [CLIENT_CREDENTIAL, svc.as_str()] {
        let (status, body) = create(&state, credential, public.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "public_not_allowed");
        // Links and password mode stay available.
        assert_eq!(create(&state, credential, serde_json::json!({"ttl_s": 600})).await.0, StatusCode::CREATED);
        let (status, created) = create(
            &state,
            credential,
            serde_json::json!({"ttl_s": 600, "access": {"mode": "password", "username": "u", "password": "long-enough-pw"}}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().unwrap();
        let (status, body) = request(
            &state,
            "PATCH",
            &format!("/v1/tunnels/{id}"),
            Some(credential),
            Some(serde_json::json!({"access": {"mode": "public"}})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "public_not_allowed");
    }
    assert_eq!(create(&state, ADMIN_CREDENTIAL, public.clone()).await.0, StatusCode::CREATED);

    // A tunnel that is already public (made while the setting was on) stays editable.
    let (status, created) = {
        let mut config = state.config.clone();
        config.limits.allow_public_for_clients = true;
        let allowed = AppState::new(config, state.db.clone(), state.certs.clone());
        create(&allowed, &svc, public.clone()).await
    };
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_str().unwrap();
    let (status, _) = request(
        &state,
        "PATCH",
        &format!("/v1/tunnels/{id}"),
        Some(&svc),
        Some(serde_json::json!({"label": "x", "access": {"mode": "public"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tunnel_list_filters_by_exact_label_within_owner() {
    let state = test_state(false, 20);
    let svc = add_service(&state, "wssp", 10).await;
    for (credential, label) in
        [(svc.as_str(), "sbx-1"), (svc.as_str(), "sbx-1"), (svc.as_str(), "sbx-10"), (ADMIN_CREDENTIAL, "sbx-1")]
    {
        let (status, _) = create(&state, credential, serde_json::json!({"ttl_s": 600, "label": label})).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    for (credential, label, n) in [
        (svc.as_str(), "sbx-1", 2),
        (svc.as_str(), "sbx-10", 1),
        (svc.as_str(), "sbx", 0),
        (ADMIN_CREDENTIAL, "sbx-1", 3),
    ] {
        let (status, body) =
            request(&state, "GET", &format!("/v1/tunnels?label={label}"), Some(credential), None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = body["tunnels"].as_array().unwrap();
        assert_eq!(rows.len(), n, "{label}");
        assert!(rows.iter().all(|t| t["label"] == label));
    }
    // A misspelt filter must not silently list everything.
    let (status, _) = request(&state, "GET", "/v1/tunnels?labels=sbx-1", Some(&svc), None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

type Live = (
    Arc<crate::registry::LiveTunnel>,
    tokio::sync::mpsc::Receiver<tunnel_protocol::ServerMsg>,
    tunnel_protocol::mux::Session,
);

fn live_tunnel(id: &str, token_hash: String) -> Live {
    let (transport, _peer) = tokio::io::duplex(64);
    let session = tunnel_protocol::mux::Session::new_server(transport);
    let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel(1);
    let live = Arc::new(crate::registry::LiveTunnel {
        conn_id: 1,
        tunnel_id: id.into(),
        control: session.control(),
        ports: Default::default(),
        ctrl_tx,
        cancel: tokio_util::sync::CancellationToken::new(),
        connected_at: now(),
        streams: Default::default(),
        pool: Default::default(),
        token_hash,
    });
    (live, ctrl_rx, session)
}

fn closed_as(rx: &mut tokio::sync::mpsc::Receiver<tunnel_protocol::ServerMsg>) -> Option<CloseReason> {
    match rx.try_recv() {
        Ok(tunnel_protocol::ServerMsg::Close { reason }) => Some(reason),
        _ => None,
    }
}

#[tokio::test]
async fn tunnel_token_rotation_replaces_the_old_host() {
    let state = test_state(false, 20);
    let svc = add_service(&state, "wssp", 10).await;
    let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
    let id = created["id"].as_str().unwrap().to_string();
    let old = created["tunnel_token"].as_str().unwrap().to_string();
    let (live, mut live_rx, _session) = live_tunnel(&id, tokens::hash_token(&old));
    state.registry.insert(live.clone());

    let (status, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id);
    let new = body["tunnel_token"].as_str().unwrap();
    assert!(new.starts_with(TUNNEL_TOKEN_PREFIX));
    assert_ne!(new, old);
    assert_eq!(closed_as(&mut live_rx), Some(CloseReason::Replaced), "the old host's connection must close");
    assert!(state.db.find_tunnel_by_token_hash(tokens::hash_token(&old)).await.unwrap().is_none());
    let row = state.db.find_tunnel_by_token_hash(tokens::hash_token(new)).await.unwrap().unwrap();
    assert_eq!(row.id, id);

    // A host already holding the newest token is left alone.
    let (status, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
    assert_eq!(status, StatusCode::OK);
    let newest = body["tunnel_token"].as_str().unwrap();
    let (current, mut current_rx, _session2) = live_tunnel(&id, tokens::hash_token(newest));
    state.registry.insert(current.clone());
    crate::control::recheck(&state, &current).await;
    assert_eq!(closed_as(&mut current_rx), None);
    // A connection that authenticated with a superseded token closes on recheck.
    let (stale, mut stale_rx, _session3) = live_tunnel(&id, tokens::hash_token(new));
    crate::control::recheck(&state, &stale).await;
    assert_eq!(closed_as(&mut stale_rx), Some(CloseReason::Replaced));

    // Admin may rotate any tunnel; an expired one cannot be rotated.
    assert_eq!(
        request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(ADMIN_CREDENTIAL), None).await.0,
        StatusCode::OK
    );
    state
        .db
        .call({
            let id = id.clone();
            move |c| Ok(c.execute("UPDATE tunnels SET expires_at = 1 WHERE id = ?1", rusqlite::params![id])?)
        })
        .await
        .unwrap();
    let (status, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "tunnel_expired");
}

#[tokio::test]
async fn stale_handshake_cannot_evict_the_host_with_the_new_token() {
    let state = test_state(false, 20);
    let svc = add_service(&state, "wssp", 10).await;
    let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
    let id = created["id"].as_str().unwrap().to_string();
    let old = created["tunnel_token"].as_str().unwrap().to_string();
    let (_, body) = request(&state, "POST", &format!("/v1/tunnels/{id}/token"), Some(&svc), None).await;
    let new = body["tunnel_token"].as_str().unwrap().to_string();

    let (host, mut host_rx, _s1) = live_tunnel(&id, tokens::hash_token(&new));
    assert_eq!(crate::control::register(&state, &host).await.unwrap(), None);
    // A connection that authenticated with the old token before the
    // rotation finishes its handshake now.
    let (stale, mut stale_rx, _s2) = live_tunnel(&id, tokens::hash_token(&old));
    let mut stale = stale;
    Arc::get_mut(&mut stale).unwrap().conn_id = 2;
    assert_eq!(crate::control::register(&state, &stale).await.unwrap(), Some(CloseReason::Replaced));
    assert_eq!(closed_as(&mut stale_rx), None, "the session loop sends the reason, not register");
    assert_eq!(closed_as(&mut host_rx), None, "the current host must stay connected");
    assert_eq!(state.registry.get(&id).unwrap().conn_id, host.conn_id);
}

#[tokio::test]
async fn rotation_waits_for_registration_in_progress() {
    let state = test_state(false, 20);
    let svc = add_service(&state, "wssp", 10).await;
    let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
    let id = created["id"].as_str().unwrap().to_string();
    let held = state.token_lock(&id).lock().await;
    let rotation = tokio::spawn({
        let state = state.clone();
        let uri = format!("/v1/tunnels/{id}/token");
        async move { request(&state, "POST", &uri, Some(&svc), None).await.0 }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!rotation.is_finished(), "rotation must not interleave with a registration");
    assert!(
        state
            .db
            .find_tunnel_by_token_hash(tokens::hash_token(created["tunnel_token"].as_str().unwrap()))
            .await
            .unwrap()
            .is_some()
    );
    drop(held);
    assert_eq!(rotation.await.unwrap(), StatusCode::OK);
}

#[tokio::test]
async fn dropped_rotation_request_still_completes_under_the_lock() {
    let state = test_state(false, 20);
    let svc = add_service(&state, "wssp", 10).await;
    let (_, created) = create(&state, &svc, serde_json::json!({"ttl_s": 600})).await;
    let id = created["id"].as_str().unwrap().to_string();
    let old = created["tunnel_token"].as_str().unwrap().to_string();
    let (host, mut host_rx, _s) = live_tunnel(&id, tokens::hash_token(&old));
    state.registry.insert(host);

    let held = state.token_lock(&id).lock().await;
    let request_task = tokio::spawn({
        let state = state.clone();
        let uri = format!("/v1/tunnels/{id}/token");
        async move { request(&state, "POST", &uri, Some(&svc), None).await }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    request_task.abort(); // The client went away mid-rotation.
    let _ = request_task.await;
    drop(held);
    // The detached rotation finishes on its own: the old host is told and the old token is gone.
    let reason = tokio::time::timeout(std::time::Duration::from_secs(5), host_rx.recv()).await.unwrap();
    assert_eq!(reason, Some(tunnel_protocol::ServerMsg::Close { reason: CloseReason::Replaced }));
    assert!(state.db.find_tunnel_by_token_hash(tokens::hash_token(&old)).await.unwrap().is_none());
}
