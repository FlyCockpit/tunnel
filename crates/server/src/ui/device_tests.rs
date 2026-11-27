//! Device login, approval freshness and machine logout.

use super::*;

#[tokio::test]
async fn device_flow_states_and_phishing_resistance() {
    let state = state();
    let mut owner = owner(&state).await;
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "attacker-box" })).await;
    let device_code = r.body["device_code"].as_str().unwrap().to_string();
    let user_code = r.body["user_code"].as_str().unwrap().to_string();
    assert!(!r.body["verification_uri"].as_str().unwrap().contains(&user_code), "no prefilled code");
    let poll = || bearer_free(&state, "/v1/device/token", json!({ "device_code": device_code }));
    assert_eq!(poll().await.body["error"]["code"], "authorization_pending");
    assert_eq!(poll().await.body["error"]["code"], "slow_down", "polled faster than the interval");
    // The approval page shows what is being approved.
    let look = owner
        .call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": user_code.to_lowercase() })))
        .await;
    assert_eq!(look.body["request"]["client_name"], "attacker-box");
    assert_eq!(look.body["request"]["ip"], "203.0.113.9");
    // A wrong code finds nothing.
    let r = owner.call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": "BBBB-BBBB" }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Deny: the CLI hears access_denied, then the code is gone.
    owner
        .call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": false })))
        .await;
    state
        .db
        .call({
            let h = tokens::hash_token(&device_code);
            move |c| {
                c.execute("UPDATE device_logins SET last_poll_at = 0 WHERE device_code_hash = ?1", [h])?;
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(poll().await.body["error"]["code"], "access_denied");
    assert_eq!(poll().await.body["error"]["code"], "invalid_grant");
    // Expiry.
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "slow" })).await;
    let dc = r.body["device_code"].as_str().unwrap().to_string();
    state
        .db
        .call({
            let h = tokens::hash_token(&dc);
            move |c| {
                c.execute("UPDATE device_logins SET expires_at = 0 WHERE device_code_hash = ?1", [h])?;
                Ok(())
            }
        })
        .await
        .unwrap();
    assert_eq!(
        bearer_free(&state, "/v1/device/token", json!({ "device_code": dc })).await.body["error"]["code"],
        "expired_token"
    );
    // The token is handed out exactly once.
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "once" })).await;
    let dc = r.body["device_code"].as_str().unwrap().to_string();
    owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": r.body["user_code"], "approve": true })),
        )
        .await;
    let first = bearer_free(&state, "/v1/device/token", json!({ "device_code": dc })).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["api"], "https://api.example.com");
    assert_eq!(
        bearer_free(&state, "/v1/device/token", json!({ "device_code": dc })).await.body["error"]["code"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn approving_a_machine_after_ten_minutes_needs_a_fresh_code() {
    let state = state();
    let mut owner = owner(&state).await;
    let setup =
        owner.call(&state, "POST", "/ui/api/account/totp/setup", Some(json!({ "password": "olivia-password" }))).await;
    let mut codes = Codes::new(base32_decode(setup.body["secret"].as_str().unwrap()));
    assert_eq!(
        owner.call(&state, "POST", "/ui/api/account/totp/enable", Some(json!({ "code": codes.next() }))).await.status,
        StatusCode::OK
    );
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let r = bearer_free(&state, "/v1/device/code", json!({ "client_name": "box" })).await;
    let user_code = r.body["user_code"].as_str().unwrap().to_string();
    let look = owner.call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": user_code }))).await;
    assert_eq!(look.body["needs_code"], true);
    assert_eq!(look.body["needs_password"], false);
    let r = owner
        .call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": true })))
        .await;
    assert_eq!(r.body["error"]["code"], "code_required");
    let code = codes.next();
    let r = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": user_code, "approve": true, "code": code })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn adding_a_headless_machine_needs_a_fresh_code_too() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut codes = enable_totp(&state, &mut owner, "olivia-password").await;
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let r = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "ci" }))).await;
    assert_eq!(r.body["error"]["code"], "code_required");
    let r =
        owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "ci", "code": codes.invalid() }))).await;
    assert_eq!(r.body["error"]["code"], "invalid_code");
    let code = codes.next();
    let r = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "ci", "code": code }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body["login_code"].as_str().unwrap().starts_with("tnenr_"));
    let r = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "fresh-ci" }))).await;
    assert_eq!(r.status, StatusCode::OK, "fresh TOTP session: {}", r.body);
}

#[tokio::test]
async fn headless_enrollment_rechecks_stale_passwords_and_shares_the_limiter() {
    let state = state();
    let mut owner = owner(&state).await;
    let fresh = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "fresh-ci" }))).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.body);
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let missing = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "ci" }))).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.body["error"]["code"], "password_required");
    let wrong = owner
        .call(
            &state,
            "POST",
            "/ui/api/machines",
            Some(json!({
                "name": "ci", "password": "incorrect"
            })),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"]["code"], "invalid_password");
    assert_eq!(wrong.body["error"]["message"], "Wrong password.");
    let machines = owner.call(&state, "GET", "/ui/api/machines", None).await;
    assert_eq!(machines.body["machines"].as_array().unwrap().len(), 1, "failed checks mint no login");
    let audit = owner.call(&state, "GET", "/ui/api/audit", None).await;
    assert!(
        audit.body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "login_failed" && e["target"] == "machine enrollment password")
    );
    let accepted = owner
        .call(
            &state,
            "POST",
            "/ui/api/machines",
            Some(json!({
                "name": "ci", "password": "olivia-password"
            })),
        )
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    assert!(accepted.body["login_code"].as_str().unwrap().starts_with("tnenr_"));
    let fresh_again = owner.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "next-ci" }))).await;
    assert_eq!(fresh_again.status, StatusCode::OK, "password check refreshed auth_at");
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let user_id = state.db.owner().await.unwrap().unwrap().id;
    while state.ui.reauth.check_key(user_id.clone()) {}
    let limited = owner
        .call(
            &state,
            "POST",
            "/ui/api/machines",
            Some(json!({
                "name": "limited-ci", "password": "olivia-password"
            })),
        )
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn factor_changes_keep_the_current_epoch_and_end_other_sessions() {
    let state = state();
    let mut owner = owner(&state).await;
    let mut other = Browser::new(2);
    let signed_in = other
        .call(
            &state,
            "POST",
            "/ui/api/login",
            Some(json!({
                "username": "olivia", "password": "olivia-password"
            })),
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK);
    let mut codes = enable_totp(&state, &mut owner, "olivia-password").await;
    assert_eq!(other.call(&state, "GET", "/ui/api/machines", None).await.status, StatusCode::UNAUTHORIZED);
    let stale_epochs: i64 = state
        .db
        .call(|c| {
            Ok(c.query_row(
        "SELECT COUNT(*) FROM ui_sessions s JOIN users u ON u.id = s.user_id WHERE s.auth_epoch != u.auth_epoch",
        [], |r| r.get(0),
    )?)
        })
        .await
        .unwrap();
    assert_eq!(stale_epochs, 0, "enabling synchronizes the retained session");
    other
        .call(
            &state,
            "POST",
            "/ui/api/login",
            Some(json!({
                "username": "olivia", "password": "olivia-password"
            })),
        )
        .await;
    let signed_in = other.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": codes.next() }))).await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.body);
    let disabled = owner
        .call(
            &state,
            "POST",
            "/ui/api/account/totp/disable",
            Some(json!({
                "password": "olivia-password"
            })),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.body);
    assert_eq!(other.call(&state, "GET", "/ui/api/machines", None).await.status, StatusCode::UNAUTHORIZED);
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let request = bearer_free(&state, "/v1/device/code", json!({ "client_name": "after-factor-change" })).await;
    let approved = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({
                "user_code": request.body["user_code"], "approve": true, "password": "olivia-password"
            })),
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(approved.body["status"], "approved");
}

#[tokio::test]
async fn device_approval_rechecks_stale_passwords_only_when_approving() {
    let state = state();
    let mut owner = owner(&state).await;
    assert_eq!(owner.call(&state, "GET", "/ui/api/session", None).await.body["user"]["recovery_codes_left"], 0);
    let first = bearer_free(&state, "/v1/device/code", json!({ "client_name": "fresh" })).await;
    let look = owner
        .call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": first.body["user_code"] })))
        .await;
    assert_eq!(look.body["needs_password"], false);
    let approved = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": first.body["user_code"], "approve": true })),
        )
        .await;
    assert_eq!(approved.body["status"], "approved");
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let request = bearer_free(&state, "/v1/device/code", json!({ "client_name": "stale" })).await;
    let code = &request.body["user_code"];
    let look = owner.call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": code }))).await;
    assert_eq!(look.body["needs_password"], true);
    assert_eq!(look.body["needs_code"], false);
    let missing =
        owner.call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": code, "approve": true }))).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.body["error"]["code"], "password_required");
    assert_eq!(missing.body["error"]["message"], "Enter your password to approve the machine.");
    let wrong = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": code, "approve": true, "password": "incorrect" })),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"]["code"], "invalid_password");
    assert_eq!(wrong.body["error"]["message"], "Wrong password.");
    let approved = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": code, "approve": true, "password": "olivia-password" })),
        )
        .await;
    assert_eq!(approved.body["status"], "approved");
    let fresh = bearer_free(&state, "/v1/device/code", json!({ "client_name": "after-password" })).await;
    let look = owner
        .call(&state, "POST", "/ui/api/device/lookup", Some(json!({ "user_code": fresh.body["user_code"] })))
        .await;
    assert_eq!(look.body["needs_password"], false, "password check refreshed auth_at");
    let audit = owner.call(&state, "GET", "/ui/api/audit", None).await;
    assert!(
        audit.body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "login_failed" && e["target"] == "machine enrollment password")
    );
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let denied = bearer_free(&state, "/v1/device/code", json!({ "client_name": "denied" })).await;
    let denied = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({ "user_code": denied.body["user_code"], "approve": false })),
        )
        .await;
    assert_eq!(denied.body["status"], "denied");
    let user_id = state.db.owner().await.unwrap().unwrap().id;
    while state.ui.reauth.check_key(user_id.clone()) {}
    let limited = owner
        .call(
            &state,
            "POST",
            "/ui/api/device/decide",
            Some(json!({
                "user_code": fresh.body["user_code"], "approve": true, "password": "olivia-password"
            })),
        )
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn machine_logout_revokes_only_itself_and_closes_its_tunnels() {
    let state = state();
    let mut owner = owner(&state).await;
    let token = approve_machine(&state, &mut owner, "one").await;
    let other = approve_machine(&state, &mut owner, "two").await;
    let tunnel = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    let id = tunnel.body["id"].as_str().unwrap();
    let _live = connect(&state, id, &[3000]);
    let ended = state.registry.get(id).unwrap().cancel.clone();
    assert_eq!(bearer(&state, "DELETE", "/v1/clients/two", &token, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bearer(&state, "DELETE", "/v1/login", ADMIN_CREDENTIAL, None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(bearer(&state, "DELETE", "/v1/login", &token, None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(bearer(&state, "DELETE", "/v1/login", &token, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &token, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &other, None).await.status, StatusCode::OK);
    assert!(state.registry.get(id).is_none());
    tokio::time::timeout(std::time::Duration::from_secs(2), ended.cancelled()).await.unwrap();
    assert!(matches!(state.db.lookup_tunnel(id.into()).await.unwrap(), crate::db::TunnelLookup::Tombstoned));
}

#[tokio::test]
async fn revocation_closes_every_tunnel_when_the_caller_is_cancelled_after_commit() {
    let state = state();
    let mut owner = owner(&state).await;
    let token = approve_machine(&state, &mut owner, "revoked").await;
    let client = state.db.client_by_token_hash(tokens::hash_token(&token)).await.unwrap().unwrap();
    let mut ids = Vec::new();
    let mut connections = Vec::new();
    let mut epochs = Vec::new();
    for _ in 0..2 {
        let tunnel = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
        let id = tunnel.body["id"].as_str().unwrap().to_string();
        connections.push(connect(&state, &id, &[3000]));
        epochs.push(state.registry.gate_epoch(&id));
        assert!(matches!(&*state.tunnel(&id).await.unwrap(), crate::db::TunnelLookup::Live(_)));
        ids.push(id);
    }
    // Warm a gate grant as well as both tunnel caches before the revocation.
    let granted = ids[0].clone();
    state
        .db
        .call(move |c| {
            c.execute("INSERT INTO gate_sessions VALUES ('visitor', ?1, ?2)", rusqlite::params![now(), now() + 600])?;
            c.execute("INSERT INTO gate_grants VALUES ('visitor', ?1, ?2)", rusqlite::params![granted, now() + 600])?;
            Ok(())
        })
        .await
        .unwrap();
    state.load_session_grants(vec!["visitor".into()]).await.unwrap();
    assert_eq!(state.cached_session_grants(&["visitor".into()]).0.len(), 1);

    let (committed, commit) = tokio::sync::oneshot::channel();
    let (resume, paused) = tokio::sync::oneshot::channel();
    let request_state = state.clone();
    let request = tokio::spawn(async move {
        request_state
            .revoke_tunnels(move |state| async move {
                let tunnels = state.db.delete_own_client(client.id).await?;
                committed.send(()).unwrap();
                paused.await.unwrap(); // Deterministic pause after commit, before teardown.
                Ok(((), tunnels))
            })
            .await
    });
    commit.await.unwrap();
    assert!(state.db.client_by_token_hash(tokens::hash_token(&token)).await.unwrap().is_none());
    assert!(ids.iter().all(|id| state.registry.get(id).is_some()));
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    resume.send(()).unwrap();

    // No sweep runs: removal cancels each gate epoch after clearing the caches.
    for (id, epoch) in ids.iter().zip(epochs) {
        tokio::time::timeout(std::time::Duration::from_secs(2), epoch.cancelled()).await.unwrap();
        assert!(state.registry.get(id).is_none());
        assert!(matches!(&*state.tunnel(id).await.unwrap(), crate::db::TunnelLookup::Tombstoned));
    }
    assert!(state.cached_session_grants(&["visitor".into()]).0.is_empty());
}

#[tokio::test]
async fn deleting_a_machine_through_either_api_closes_its_live_tunnel() {
    let state = state();
    let mut owner = owner(&state).await;
    for (name, ui) in [("admin-deleted", false), ("ui-deleted", true)] {
        let token = approve_machine(&state, &mut owner, name).await;
        let tunnel = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
        let id = tunnel.body["id"].as_str().unwrap();
        let _live = connect(&state, id, &[3000]);
        let epoch = state.registry.gate_epoch(id);
        assert!(matches!(&*state.tunnel(id).await.unwrap(), crate::db::TunnelLookup::Live(_)));
        let deleted = if ui {
            owner.call(&state, "DELETE", &format!("/ui/api/machines/{name}"), None).await
        } else {
            bearer(&state, "DELETE", &format!("/v1/clients/{name}"), ADMIN_CREDENTIAL, None).await
        };
        assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{}", deleted.body);
        assert!(state.registry.get(id).is_none());
        assert!(epoch.is_cancelled());
        assert!(matches!(&*state.tunnel(id).await.unwrap(), crate::db::TunnelLookup::Tombstoned));
        assert_eq!(bearer(&state, "GET", "/v1/tunnels", &token, None).await.status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn admin_can_create_rename_and_delete_a_machine_named_self() {
    let state = state();
    let _owner = owner(&state).await;
    let created = bearer(&state, "POST", "/v1/clients", ADMIN_CREDENTIAL, Some(json!({ "name": "self" }))).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    for (old, new) in [("self", "renamed"), ("renamed", "self")] {
        let renamed = bearer(
            &state,
            "PATCH",
            &format!("/v1/clients/{old}"),
            ADMIN_CREDENTIAL,
            Some(json!({
                "name": new
            })),
        )
        .await;
        assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
        assert_eq!(renamed.body["name"], new);
    }
    assert_eq!(
        bearer(&state, "DELETE", "/v1/clients/self", ADMIN_CREDENTIAL, None).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        bearer(&state, "DELETE", "/v1/clients/self", ADMIN_CREDENTIAL, None).await.status,
        StatusCode::NOT_FOUND
    );
}
