//! Per-user limits: who may set them, how each setting resolves, what is
//! enforced (and what keeps running) after a change, and the audit trail.

use super::*;

/// The owner `olivia`, admins `adam` and `amy`, members `ann` and `bob`.
struct People {
    owner: Browser,
    adam: Browser,
    amy: Browser,
    ann: Browser,
    ids: std::collections::HashMap<&'static str, String>,
}

async fn admin(state: &Arc<AppState>, owner: &mut Browser, name: &str, ip: u8) -> Browser {
    let r = owner.call(state, "POST", "/ui/api/invites", Some(json!({ "role": "admin" }))).await;
    let token = r.body["url"].as_str().unwrap().split_once('#').unwrap().1.to_string();
    sign_up(state, &token, name, ip).await
}

async fn people(state: &Arc<AppState>) -> People {
    let mut owner = owner(state).await;
    let adam = admin(state, &mut owner, "adam", 20).await;
    let amy = admin(state, &mut owner, "amy", 21).await;
    let ann = member(state, &mut owner, "ann", 22).await;
    let _bob = member(state, &mut owner, "bob", 23).await;
    let users = owner.call(state, "GET", "/ui/api/users", None).await;
    let ids = ["olivia", "adam", "amy", "ann", "bob"].into_iter().map(|n| (n, user_id(&users.body, n))).collect();
    People { owner, adam, amy, ann, ids }
}

impl People {
    fn by(&mut self, name: &str) -> &mut Browser {
        match name {
            "olivia" => &mut self.owner,
            "adam" => &mut self.adam,
            "amy" => &mut self.amy,
            _ => &mut self.ann,
        }
    }
}

/// `{ kind: value }`.
fn one(kind: &str, value: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(kind.to_string(), value);
    Value::Object(m)
}

async fn set(state: &Arc<AppState>, by: &mut Browser, id: &str, limits: Value) -> Resp {
    by.call(state, "PATCH", &format!("/ui/api/users/{id}"), Some(json!({ "limits": limits }))).await
}

async fn audit_targets(state: &Arc<AppState>, owner: &mut Browser, action: &str) -> Vec<(String, String)> {
    let log = owner.call(state, "GET", "/ui/api/audit", None).await;
    log.body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == action)
        .map(|e| (e["user"].as_str().unwrap_or_default().to_string(), e["target"].as_str().unwrap().to_string()))
        .collect()
}

const KINDS: [&str; 4] = ["tunnels", "machines", "tunnel_ttl_s", "traffic_bytes"];

/// A valid explicit number for each limit.
fn number(kind: &str) -> u64 {
    match kind {
        "tunnel_ttl_s" => 7200,
        "traffic_bytes" => 2_000_000,
        _ => 3,
    }
}

#[tokio::test]
async fn admins_set_members_the_owner_sets_admins_and_nobody_limits_the_owner() {
    let state = state_with(|c| c.limits.member_monthly_traffic_gb = Some(5));
    let mut p = people(&state).await;
    let id = |p: &People, name: &str| p.ids[name].clone();
    let member_default = [Some(10u64), Some(5), Some(7 * 86_400), Some(5_000_000_000)];
    let admin_default = [None, None, Some(30 * 86_400), None];
    for (i, kind) in KINDS.into_iter().enumerate() {
        for (setting, member_effective, admin_effective) in [
            (json!(number(kind)), Some(number(kind)), Some(number(kind))),
            (json!("unlimited"), None, None),
            (json!("default"), member_default[i], admin_default[i]),
        ] {
            // An admin sets a member's limit; the owner sets a member's and an admin's.
            for (by, target, effective, default) in [
                ("adam", "ann", member_effective, member_default[i]),
                ("olivia", "bob", member_effective, member_default[i]),
                ("olivia", "amy", admin_effective, admin_default[i]),
            ] {
                let target = id(&p, target);
                let r = set(&state, p.by(by), &target, one(kind, setting.clone())).await;
                assert_eq!(r.status, StatusCode::OK, "{kind} {setting}: {}", r.body);
                let view = &r.body["user"]["limits"][kind];
                assert_eq!(view["setting"], setting, "{kind}");
                assert_eq!(view["effective"], json!(effective), "{kind} {setting}");
                assert_eq!(view["default"], json!(default), "{kind}");
            }
            // Refused: an admin for another admin or themselves, a member for
            // anyone, anyone for the owner.
            for (by, target, why) in [
                ("adam", "amy", "an admin changing another admin"),
                ("adam", "adam", "an admin changing themselves"),
                ("ann", "ann", "a member changing themselves"),
                ("ann", "bob", "a member changing another member"),
                ("adam", "olivia", "an admin limiting the owner"),
                ("olivia", "olivia", "the owner limiting themselves"),
            ] {
                let target = id(&p, target);
                let r = set(&state, p.by(by), &target, one(kind, setting.clone())).await;
                assert_eq!(r.status, StatusCode::FORBIDDEN, "{why} ({kind} {setting})");
            }
        }
    }
    // The owner is unlimited, whatever is stored.
    let users = p.owner.call(&state, "GET", "/ui/api/users", None).await;
    for kind in KINDS {
        let view = &listed(&users.body, "olivia")["limits"][kind];
        assert_eq!(*view, json!({ "setting": "unlimited", "default": null, "effective": null }), "{kind}");
    }
    let me = p.owner.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(me.body["user"]["limits"]["tunnels"]["effective"], Value::Null);
}

#[tokio::test]
async fn limit_values_are_validated() {
    let state = state();
    let mut p = people(&state).await;
    let ann = p.ids["ann"].clone();
    for bad in [
        json!({ "tunnels": 10_001 }),
        json!({ "tunnels": -1 }),
        json!({ "tunnels": "none" }),
        json!({ "machines": 1001 }),
        json!({ "tunnel_ttl_s": 59 }),
        json!({ "tunnel_ttl_s": crate::limits::MAX_TTL_S + 1 }),
        json!({ "traffic_bytes": 999_999 }),
        json!({ "traffic_bytes": 0 }),
        json!({ "traffic_bytes": 1.5 }),
        json!({ "lifetime": 60 }),
    ] {
        let r = set(&state, &mut p.owner, &ann, bad.clone()).await;
        assert!(matches!(r.status, StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST), "{bad}: {}", r.status);
    }
    // Zero tunnels or machines is a limit (none allowed), not "unlimited".
    let r = set(&state, &mut p.owner, &ann, json!({ "tunnels": 0, "machines": 0 })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["user"]["limits"]["tunnels"]["effective"], 0);
    let r = p.ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "none-allowed" }))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("client_quota")));
}

#[tokio::test]
async fn live_tunnels_default_number_unlimited_and_lowering_below_use() {
    let state = state_with(|c| c.limits.member_max_tunnels = 2);
    let mut p = people(&state).await;
    let ann = p.ids["ann"].clone();
    let token = approve_machine(&state, &mut p.ann, "laptop").await;
    let second = approve_machine(&state, &mut p.ann, "desktop").await;
    let mut live = Vec::new();
    // Server default (2), across both machines.
    for t in [&token, &second] {
        let r = create_tunnel(&state, t, json!({ "mode": "link" })).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        live.push(r.body["id"].as_str().unwrap().to_string());
    }
    let r = create_tunnel(&state, &second, json!({ "mode": "link" })).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("tunnel_quota")));
    let message = r.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("live-tunnel limit (2, across all its machines)"), "{message}");
    assert!(message.contains("ask an admin to raise the limit"), "{message}");
    // A number above the default.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "tunnels": 3 })).await.status, StatusCode::OK);
    let r = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    assert_eq!(r.status, StatusCode::CREATED);
    live.push(r.body["id"].as_str().unwrap().to_string());
    let r = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    assert!(r.body["error"]["message"].as_str().unwrap().contains("live-tunnel limit (3,"), "{}", r.body);
    // Lowered below what runs: the three keep running, new ones are refused.
    let r = set(&state, &mut p.adam, &ann, json!({ "tunnels": 1 })).await;
    assert_eq!((r.status, r.body["shortened_tunnels"].clone()), (StatusCode::OK, json!(0)));
    for id in &live {
        let v = bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &token, None).await;
        let v = if v.status == StatusCode::OK {
            v
        } else {
            bearer(&state, "GET", &format!("/v1/tunnels/{id}"), &second, None).await
        };
        assert_eq!((v.status, v.body["expired"].clone()), (StatusCode::OK, json!(false)), "{id} keeps running");
    }
    let r = create_tunnel(&state, &token, json!({ "mode": "link" })).await;
    assert!(r.body["error"]["message"].as_str().unwrap().contains("live-tunnel limit (1,"), "{}", r.body);
    let info = bearer(&state, "GET", "/v1/server", &token, None).await;
    assert_eq!(info.body["limits"]["account"]["tunnels"], json!({ "limit": 1, "used": 3 }), "{}", info.body);
    assert_eq!(info.body["limits"]["account"]["raised_by"], "an admin");
    // Unlimited: only the per-machine limit is left.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "tunnels": "unlimited" })).await.status, StatusCode::OK);
    for _ in 0..4 {
        assert_eq!(create_tunnel(&state, &token, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    }
    let info = bearer(&state, "GET", "/v1/server", &token, None).await;
    assert_eq!(info.body["limits"]["account"]["tunnels"], json!({ "limit": null, "used": 7 }));

    // Admins: unlimited by default; the owner may limit them, and the
    // message says who can raise it.
    let adam = p.ids["adam"].clone();
    let adam_token = approve_machine(&state, &mut p.adam, "adam-box").await;
    for _ in 0..12 {
        assert_eq!(create_tunnel(&state, &adam_token, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    }
    assert_eq!(set(&state, &mut p.owner, &adam, json!({ "tunnels": 12 })).await.status, StatusCode::OK);
    let r = create_tunnel(&state, &adam_token, json!({ "mode": "link" })).await;
    let message = r.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("(12,") && message.contains("ask the server's owner"), "{message}");
    // The owner's machines are never limited by an account limit.
    let owner_token = approve_machine(&state, &mut p.owner, "server").await;
    for _ in 0..12 {
        assert_eq!(create_tunnel(&state, &owner_token, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    }
    let info = bearer(&state, "GET", "/v1/server", &owner_token, None).await;
    let account = &info.body["limits"]["account"];
    assert_eq!((account["tunnels"]["limit"].clone(), account["raised_by"].clone()), (Value::Null, Value::Null));

    let entries = audit_targets(&state, &mut p.owner, "limit_set").await;
    assert!(entries.contains(&("adam".into(), "ann: live tunnels Server default (2) → 3".into())), "{entries:?}");
    assert!(entries.contains(&("adam".into(), "ann: live tunnels 3 → 1".into())), "{entries:?}");
    assert!(entries.contains(&("adam".into(), "ann: live tunnels 1 → Unlimited".into())), "{entries:?}");
    assert!(entries.contains(&("olivia".into(), "adam: live tunnels Server default (unlimited) → 12".into())));
}

#[tokio::test]
async fn the_machine_limit_names_itself_and_spares_existing_machines() {
    let state = state_with(|c| {
        c.limits.member_max_clients = 1;
        c.limits.max_tunnels_per_client = 2;
    });
    let mut p = people(&state).await;
    let ann = p.ids["ann"].clone();
    let laptop = approve_machine(&state, &mut p.ann, "laptop").await;
    let code = bearer_free(&state, "/v1/device/code", json!({ "client_name": "desktop" })).await;
    let user_code = code.body["user_code"].as_str().unwrap().to_string();
    let r = p
        .ann
        .call(&state, "POST", "/ui/api/device/decide", Some(json!({ "user_code": user_code, "approve": true })))
        .await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("client_quota")));
    let message = r.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("machine limit (1)") && message.contains("ask an admin"), "{message}");
    // Raised to a number: a second and third machine.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "machines": 3 })).await.status, StatusCode::OK);
    let desktop = approve_machine(&state, &mut p.ann, "desktop").await;
    let r = p.ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "headless" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Lowered below use: every machine keeps working, a new one is refused.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "machines": 1 })).await.status, StatusCode::OK);
    for t in [&laptop, &desktop] {
        assert_eq!(bearer(&state, "GET", "/v1/server", t, None).await.status, StatusCode::OK);
        assert_eq!(create_tunnel(&state, t, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    }
    let r = p.ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "fourth" }))).await;
    assert!(r.body["error"]["message"].as_str().unwrap().contains("machine limit (1)"), "{}", r.body);
    let info = bearer(&state, "GET", "/v1/server", &laptop, None).await;
    assert_eq!(info.body["limits"]["account"]["machines"], json!({ "limit": 1, "used": 3 }));
    // The machine's own tunnel limit is named as such.
    assert_eq!(create_tunnel(&state, &laptop, json!({ "mode": "link" })).await.status, StatusCode::CREATED);
    let r = create_tunnel(&state, &laptop, json!({ "mode": "link" })).await;
    let message = r.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("this machine's live-tunnel limit (2, limits.max_tunnels_per_client)"), "{message}");
    // Unlimited, and the server-shell's `client add --user` sees the same rule.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "machines": "unlimited" })).await.status, StatusCode::OK);
    let r = p.ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "fourth" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "machines": 0 })).await.status, StatusCode::OK);
    let r = bearer(&state, "POST", "/v1/clients", ADMIN_CREDENTIAL, Some(json!({ "name": "ci", "user": "ann" }))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.body["error"]["message"].as_str().unwrap().contains("machine limit (0)"), "{}", r.body);
    // An admin's limit is raised by the owner.
    let amy = p.ids["amy"].clone();
    assert_eq!(set(&state, &mut p.owner, &amy, json!({ "machines": 0 })).await.status, StatusCode::OK);
    let r = p.amy.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "amy-box" }))).await;
    assert!(r.body["error"]["message"].as_str().unwrap().contains("ask the server's owner"), "{}", r.body);
    let entries = audit_targets(&state, &mut p.owner, "limit_set").await;
    assert!(entries.contains(&("adam".into(), "ann: machines Server default (1) → 3".into())), "{entries:?}");
}

#[tokio::test]
async fn lifetimes_cap_new_tunnels_and_renewals_and_unlimited_never_expires() {
    let state = state();
    let mut p = people(&state).await;
    let ann = p.ids["ann"].clone();
    let token = approve_machine(&state, &mut p.ann, "laptop").await;
    let create = |body: Value| {
        let (state, token) = (state.clone(), token.clone());
        async move { bearer(&state, "POST", "/v1/tunnels", &token, Some(body)).await }
    };
    // Server default for members: 7 days.
    let r = create(json!({ "ttl_s": 8 * 86_400 })).await;
    assert_eq!(
        (r.status, r.body["error"]["code"].clone()),
        (StatusCode::UNPROCESSABLE_ENTITY, json!("tunnel_ttl_limit"))
    );
    let message = r.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("tunnel lifetime limit is 7d") && message.contains("ask an admin"), "{message}");
    let r = create(json!({ "never_expires": true })).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(r.body["error"]["message"].as_str().unwrap().contains("a tunnel that never expires is not allowed"));
    for bad in [json!({}), json!({ "ttl_s": 600, "never_expires": true }), json!({ "ttl_s": 59 })] {
        assert_eq!(create(bad.clone()).await.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let info = bearer(&state, "GET", "/v1/server", &token, None).await;
    assert_eq!(info.body["limits"]["max_tunnel_ttl_s"], 7 * 86_400);

    // A number: new tunnels and renewals within it.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "tunnel_ttl_s": 3600 })).await.status, StatusCode::OK);
    assert_eq!(create(json!({ "ttl_s": 3601 })).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = create(json!({ "ttl_s": 3600 })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    let short = r.body["id"].as_str().unwrap().to_string();
    let renew = |id: String, body: Value| {
        let (state, token) = (state.clone(), token.clone());
        async move { bearer(&state, "PATCH", &format!("/v1/tunnels/{id}"), &token, Some(body)).await }
    };
    let r = renew(short.clone(), json!({ "ttl_s": 7200 })).await;
    assert_eq!(
        (r.status, r.body["error"]["code"].clone()),
        (StatusCode::UNPROCESSABLE_ENTITY, json!("tunnel_ttl_limit"))
    );
    assert!(r.body["error"]["message"].as_str().unwrap().contains("limit is 1h"), "{}", r.body);
    assert_eq!(renew(short.clone(), json!({ "ttl_s": 1800 })).await.status, StatusCode::OK);
    assert_eq!(renew(short.clone(), json!({ "never_expires": true })).await.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Unlimited: tunnels that never expire, beyond the server's own maximum too.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "tunnel_ttl_s": "unlimited" })).await.status, StatusCode::OK);
    let info = bearer(&state, "GET", "/v1/server", &token, None).await;
    assert_eq!(info.body["limits"]["max_tunnel_ttl_s"], Value::Null);
    assert_eq!(info.body["limits"]["account"]["tunnel_ttl_s"], Value::Null);
    let r = create(json!({ "never_expires": true, "access": { "mode": "link" } })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    assert_eq!(
        (r.body["never_expires"].clone(), r.body["expires_at"].clone()),
        (json!(true), json!(crate::db::NEVER_EXPIRES))
    );
    let forever = r.body["id"].as_str().unwrap().to_string();
    assert_eq!(create(json!({ "ttl_s": 60 * 86_400 })).await.status, StatusCode::CREATED);
    assert_eq!(renew(short.clone(), json!({ "never_expires": true })).await.body["never_expires"], true);
    let v = bearer(&state, "GET", &format!("/v1/tunnels/{forever}"), &token, None).await;
    assert_eq!((v.body["never_expires"].clone(), v.body["expired"].clone()), (json!(true), json!(false)));
    // The sweep never picks it up, while an expired tunnel next to it goes.
    let gone = create(json!({ "ttl_s": 600 })).await.body["id"].as_str().unwrap().to_string();
    let g = gone.clone();
    state
        .db
        .call(move |c| Ok(c.execute("UPDATE tunnels SET expires_at = 1 WHERE id = ?1", rusqlite::params![g])?))
        .await
        .unwrap();
    let expired = state.db.expired_tunnel_ids().await.unwrap();
    assert!(expired.contains(&gone) && !expired.contains(&forever) && !expired.contains(&short), "{expired:?}");
    // Access links on it work as on any tunnel.
    let link = bearer(
        &state,
        "POST",
        &format!("/v1/tunnels/{forever}/access-links"),
        &token,
        Some(json!({ "ttl_s": 7 * 86_400 })),
    )
    .await;
    assert_eq!(link.status, StatusCode::CREATED, "{}", link.body);
    // The UI lists it as never expiring.
    let list = p.ann.call(&state, "GET", "/ui/api/tunnels", None).await;
    let row = list.body["tunnels"].as_array().unwrap().iter().find(|t| t["id"] == forever.as_str()).unwrap();
    assert_eq!(row["never_expires"], true);

    // Lowered again: the never-expiring tunnels keep running, now ending
    // within the new limit; renewals follow it.
    let r = set(&state, &mut p.adam, &ann, json!({ "tunnel_ttl_s": 86_400 })).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["shortened_tunnels"], 3, "both never-expiring tunnels and the 60-day one");
    let v = bearer(&state, "GET", &format!("/v1/tunnels/{forever}"), &token, None).await;
    let expires_at = v.body["expires_at"].as_i64().unwrap();
    assert_eq!(
        (v.status, v.body["never_expires"].clone(), v.body["expired"].clone()),
        (StatusCode::OK, json!(false), json!(false))
    );
    assert!((now() + 86_390..=now() + 86_400).contains(&expires_at), "{expires_at}");
    assert_eq!(renew(forever.clone(), json!({ "ttl_s": 86_401 })).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    let shortened = audit_targets(&state, &mut p.owner, "tunnels_shortened").await;
    assert_eq!(shortened, vec![("adam".to_string(), "ann: 3 tunnel(s) now end within 1d".to_string())]);
    let entries = audit_targets(&state, &mut p.owner, "limit_set").await;
    assert!(entries.contains(&("adam".into(), "ann: tunnel lifetime Server default (7d) → 1h".into())), "{entries:?}");
    assert!(entries.contains(&("adam".into(), "ann: tunnel lifetime Unlimited → 1d".into())), "{entries:?}");
}

#[tokio::test]
async fn admins_owner_services_and_the_admin_token_keep_their_lifetime_rules() {
    let state = state();
    let mut p = people(&state).await;
    let adam = p.ids["adam"].clone();
    // An admin's default is the server's maximum (30 days), no "never".
    let adam_token = approve_machine(&state, &mut p.adam, "adam-box").await;
    let r = bearer(&state, "POST", "/v1/tunnels", &adam_token, Some(json!({ "ttl_s": 31 * 86_400 }))).await;
    let message = r.body["error"]["message"].as_str().unwrap();
    assert!(message.contains("limit is 30d") && message.contains("ask the server's owner"), "{message}");
    assert_eq!(set(&state, &mut p.owner, &adam, json!({ "tunnel_ttl_s": "unlimited" })).await.status, StatusCode::OK);
    let r = bearer(&state, "POST", "/v1/tunnels", &adam_token, Some(json!({ "never_expires": true }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    // The owner's machines may always make tunnels that never expire.
    let owner_token = approve_machine(&state, &mut p.owner, "server").await;
    let r = bearer(&state, "POST", "/v1/tunnels", &owner_token, Some(json!({ "never_expires": true }))).await;
    assert_eq!((r.status, r.body["never_expires"].clone()), (StatusCode::CREATED, json!(true)));
    // Services and the admin token keep `max_tunnel_ttl_s`.
    let svc =
        bearer(&state, "POST", "/v1/services", ADMIN_CREDENTIAL, Some(json!({ "name": "sbx", "max_tunnels": 5 })))
            .await;
    assert_eq!(svc.status, StatusCode::CREATED, "{}", svc.body);
    let svc_token = svc.body["token"].as_str().unwrap().to_string();
    for token in [svc_token.as_str(), ADMIN_CREDENTIAL] {
        let r = bearer(&state, "POST", "/v1/tunnels", token, Some(json!({ "never_expires": true }))).await;
        assert_eq!(
            (r.status, r.body["error"]["code"].clone()),
            (StatusCode::UNPROCESSABLE_ENTITY, json!("tunnel_ttl_limit"))
        );
        assert!(r.body["error"]["message"].as_str().unwrap().contains("limits.max_tunnel_ttl_s"), "{}", r.body);
        let r = bearer(&state, "POST", "/v1/tunnels", token, Some(json!({ "ttl_s": 30 * 86_400 }))).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
        let info = bearer(&state, "GET", "/v1/server", token, None).await;
        assert_eq!(info.body["limits"]["max_tunnel_ttl_s"], 30 * 86_400);
        assert!(info.body["limits"].get("account").is_none());
    }
    let r = bearer(&state, "POST", "/v1/tunnels", &svc_token, Some(json!({ "ttl_s": 600 }))).await;
    assert_eq!(r.status, StatusCode::CREATED);
}

#[tokio::test]
async fn traffic_follows_the_configured_default_until_set_and_a_role_change_resets_all_four() {
    let state = state_with(|c| c.limits.member_monthly_traffic_gb = Some(5));
    let mut p = people(&state).await;
    let (ann, amy) = (p.ids["ann"].clone(), p.ids["amy"].clone());
    let effective = |users: &Value, name: &str| listed(users, name)["limits"]["traffic_bytes"]["effective"].clone();
    let users = p.owner.call(&state, "GET", "/ui/api/users", None).await;
    assert_eq!(effective(&users.body, "ann"), json!(5_000_000_000u64));
    assert_eq!(effective(&users.body, "amy"), Value::Null, "admins have no default cap");
    assert_eq!(state.traffic.view(&state.db, &ann).await.unwrap().cap_bytes, Some(5_000_000_000));
    // Unlimited, then back to the default.
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "traffic_bytes": "unlimited" })).await.status, StatusCode::OK);
    assert_eq!(state.traffic.view(&state.db, &ann).await.unwrap().cap_bytes, None);
    assert_eq!(set(&state, &mut p.adam, &ann, json!({ "traffic_bytes": "default" })).await.status, StatusCode::OK);
    assert_eq!(state.traffic.view(&state.db, &ann).await.unwrap().cap_bytes, Some(5_000_000_000));
    // "Server default" follows the configuration (a restart with a new
    // config): users on it get the new value, explicit numbers stay.
    let bob = p.ids["bob"].clone();
    assert_eq!(set(&state, &mut p.adam, &bob, json!({ "traffic_bytes": 2_000_000 })).await.status, StatusCode::OK);
    state.db.set_limit_defaults(crate::limits::Defaults::new(&crate::config::Limits {
        member_monthly_traffic_gb: Some(7),
        ..state.config.limits.clone()
    }));
    let users = p.owner.call(&state, "GET", "/ui/api/users", None).await;
    assert_eq!(effective(&users.body, "ann"), json!(7_000_000_000u64));
    assert_eq!(effective(&users.body, "bob"), json!(2_000_000));
    state.db.set_limit_defaults(crate::limits::Defaults::new(&state.config.limits));

    // A role change resets the four (so it cannot come with limits).
    let r = p
        .owner
        .call(
            &state,
            "PATCH",
            &format!("/ui/api/users/{amy}"),
            Some(json!({ "role": "member", "limits": { "tunnel_ttl_s": "unlimited" } })),
        )
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    assert!(r.body["error"]["message"].as_str().unwrap().contains("separate requests"));
    let users = p.owner.call(&state, "GET", "/ui/api/users", None).await;
    assert_eq!(listed(&users.body, "amy")["role"], "admin", "nothing of a refused request applies");
    // A role change resets the four to the server default of the new role.
    let r = set(
        &state,
        &mut p.owner,
        &amy,
        json!({ "tunnels": 4, "tunnel_ttl_s": "unlimited", "traffic_bytes": 3_000_000 }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = p.owner.call(&state, "PATCH", &format!("/ui/api/users/{amy}"), Some(json!({ "role": "member" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    for (kind, value) in [
        ("tunnels", json!(10)),
        ("machines", json!(5)),
        ("tunnel_ttl_s", json!(7 * 86_400)),
        ("traffic_bytes", json!(5_000_000_000u64)),
    ] {
        let view = &r.body["user"]["limits"][kind];
        assert_eq!((view["setting"].clone(), view["effective"].clone()), (json!("default"), value), "{kind}");
    }
    assert_eq!(state.traffic.view(&state.db, &amy).await.unwrap().cap_bytes, Some(5_000_000_000));
    let entries = audit_targets(&state, &mut p.owner, "limit_set").await;
    for expected in [
        "amy: live tunnels 4 → Server default (10)",
        "amy: tunnel lifetime Unlimited → Server default (7d)",
        "amy: monthly traffic 3 MB → Server default (5 GB)",
        "ann: monthly traffic Server default (5 GB) → Unlimited",
    ] {
        assert!(entries.iter().any(|(_, t)| t == expected), "{expected}: {entries:?}");
    }
    // The member sees their limits and use on the Account page (session).
    let me = p.ann.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(me.body["user"]["limits"]["traffic_bytes"]["effective"], 5_000_000_000u64);
    assert_eq!(me.body["usage"], json!({ "tunnels": 0, "machines": 0 }));

    // Every change applies the committed row's cap, whatever this request
    // changed (a concurrent change may have committed just before it).
    let a = ann.clone();
    state
        .db
        .call(move |c| Ok(c.execute("UPDATE users SET limit_traffic_bytes = -1 WHERE id = ?1", rusqlite::params![a])?))
        .await
        .unwrap();
    let r = p.adam.call(&state, "PATCH", &format!("/ui/api/users/{ann}"), Some(json!({ "can_public": true }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(state.traffic.view(&state.db, &ann).await.unwrap().cap_bytes, None);

    // A role change on the server default is audited with what it moved.
    let adam = p.ids["adam"].clone();
    let r = p.owner.call(&state, "PATCH", &format!("/ui/api/users/{adam}"), Some(json!({ "role": "member" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(state.traffic.view(&state.db, &adam).await.unwrap().cap_bytes, Some(5_000_000_000));
    let entries = audit_targets(&state, &mut p.owner, "limit_set").await;
    for expected in [
        "adam: live tunnels Server default (unlimited) → Server default (10)",
        "adam: machines Server default (unlimited) → Server default (5)",
        "adam: tunnel lifetime Server default (30d) → Server default (7d)",
        "adam: monthly traffic Server default (unlimited) → Server default (5 GB)",
    ] {
        assert!(entries.iter().any(|(who, t)| who == "olivia" && t == expected), "{expected}: {entries:?}");
    }
}

#[test]
fn the_fresh_schema_stores_limits_in_four_nullable_checked_columns() {
    let path = std::env::temp_dir().join(format!("tunnel-limits-schema-{}.db", tokens::random_tunnel_id()));
    let db = crate::db::Db::open(&path).unwrap();
    drop(db);
    let c = rusqlite::Connection::open(&path).unwrap();
    let mut stmt = c.prepare("SELECT name, type, \"notnull\" FROM pragma_table_info('users') ORDER BY cid").unwrap();
    let cols: Vec<(String, String, bool)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<Result<_, _>>().unwrap();
    let names: Vec<&str> = cols.iter().map(|(n, _, _)| n.as_str()).collect();
    // The order the hand-applied upgrade (ADD COLUMN appends) must match.
    assert_eq!(
        names,
        [
            "id",
            "username",
            "password_hash",
            "totp_secret_sealed",
            "totp_pending_sealed",
            "totp_last_step",
            "role",
            "disabled_at",
            "can_public",
            "created_at",
            "auth_epoch",
            "factor_failures",
            "factor_locked_until",
            "limit_tunnels",
            "limit_clients",
            "limit_tunnel_ttl_s",
            "limit_traffic_bytes",
            "email",
            "email_verified_at",
        ]
    );
    for (name, ty, not_null) in &cols[13..17] {
        assert_eq!((ty.as_str(), *not_null), ("INTEGER", false), "{name}");
    }
    c.execute(
        "INSERT INTO users (id, username, password_hash, role, created_at) VALUES ('u', 'u', 'x', 'member', 0)",
        [],
    )
    .unwrap();
    for col in ["limit_tunnels", "limit_clients", "limit_tunnel_ttl_s", "limit_traffic_bytes"] {
        assert!(c.execute(&format!("UPDATE users SET {col} = -1"), []).is_ok(), "{col}: -1 is Unlimited");
        assert!(c.execute(&format!("UPDATE users SET {col} = -2"), []).is_err(), "{col}: below -1 is refused");
    }
    drop(stmt);
    drop(c);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
