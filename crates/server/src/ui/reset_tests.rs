//! Sign-in reset links (`account_reset`): who may make them, what redeeming
//! one does, and everything that voids one.

use super::*;

/// The owner `olivia`, admins `adam` and `amy`, members `ann` and `bob`.
struct People {
    owner: Browser,
    adam: Browser,
    amy: Browser,
    ann: Browser,
    bob: Browser,
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
    let bob = member(state, &mut owner, "bob", 23).await;
    let users = owner.call(state, "GET", "/ui/api/users", None).await;
    let ids = ["olivia", "adam", "amy", "ann", "bob"].into_iter().map(|n| (n, user_id(&users.body, n))).collect();
    People { owner, adam, amy, ann, bob, ids }
}

/// `actor` asks for a reset link for `target_id`; returns the response.
async fn reset(state: &Arc<AppState>, actor: &mut Browser, target_id: &str, body: Value) -> Resp {
    actor.call(state, "POST", &format!("/ui/api/users/{target_id}/reset"), Some(body)).await
}

fn token_of(r: &Resp) -> String {
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let url = r.body["url"].as_str().unwrap();
    assert!(url.starts_with("https://ui.example.com/invite#tninv_"), "{url}");
    url.split_once('#').unwrap().1.to_string()
}

async fn redeem(state: &Arc<AppState>, token: &str, password: &str, ip: u8) -> (Browser, Resp) {
    let mut b = Browser::new(ip);
    let r = b.call(state, "POST", "/ui/api/invite/accept", Some(json!({ "token": token, "password": password }))).await;
    (b, r)
}

async fn sign_in(state: &Arc<AppState>, username: &str, password: &str, ip: u8) -> Resp {
    Browser::new(ip)
        .call(state, "POST", "/ui/api/login", Some(json!({ "username": username, "password": password })))
        .await
}

#[tokio::test]
async fn a_reset_link_sets_a_new_password_and_clears_the_second_factor() {
    let state = state();
    let mut p = people(&state).await;
    let ann_id = p.ids["ann"].clone();
    enable_totp(&state, &mut p.ann, "ann-password").await;
    let mut ann_elsewhere = Browser::new(40);
    ann_elsewhere
        .call(&state, "POST", "/ui/api/login", Some(json!({ "username": "ann", "password": "ann-password" })))
        .await;
    assert_eq!(state.db.recovery_codes_left(ann_id.clone()).await.unwrap(), 10);

    let r = reset(&state, &mut p.adam, &ann_id, json!({})).await;
    let token = token_of(&r);
    let expires = r.body["invite"]["expires_at"].as_i64().unwrap();
    assert!((expires - now() - 3600).abs() <= 5, "one hour by default");
    assert_eq!(r.body["invite"]["kind"], "account_reset");
    assert_eq!(r.body["invite"]["user"], "ann");
    // The link is not stored, only its hash.
    let stored: i64 = state
        .db
        .call({
            let token = token.clone();
            move |c| Ok(c.query_row("SELECT COUNT(*) FROM invites WHERE token_hash = ?1", [token], |r| r.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(stored, 0);

    let info = Browser::new(41).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!((info.body["kind"].clone(), info.body["username"].clone()), (json!("account_reset"), json!("ann")));
    let (mut fresh, r) = redeem(&state, &token, "ann-new-password", 42).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let s = fresh.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!((s.body["user"]["username"].clone(), s.body["user"]["totp"].clone()), (json!("ann"), json!(false)));

    // Every earlier session ended; the old password is gone; sign-in needs no code.
    assert!(p.ann.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
    assert!(ann_elsewhere.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null());
    assert_eq!(sign_in(&state, "ann", "ann-password", 43).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(sign_in(&state, "ann", "ann-new-password", 44).await.body["status"], "ok");
    assert_eq!(state.db.recovery_codes_left(ann_id.clone()).await.unwrap(), 0);

    // Single use.
    let (_, again) = redeem(&state, &token, "someone-elses-password", 45).await;
    assert_eq!((again.status, again.body["error"]["code"].clone()), (StatusCode::NOT_FOUND, json!("invalid_invite")));

    let audit = p.owner.call(&state, "GET", "/ui/api/audit", None).await;
    let entries = audit.body["entries"].as_array().unwrap();
    let has = |user: &str, action: &str, target: Option<&str>| {
        entries.iter().any(|e| {
            e["user"] == user && e["action"] == action && target.is_none_or(|t| e["target"].as_str() == Some(t))
        })
    };
    assert!(has("adam", "reset_link_created", Some("ann")), "{entries:?}");
    assert!(has("ann", "account_reset", None), "{entries:?}");
    assert!(!audit.body.to_string().contains(&token), "no token in the audit log");

    let invites = p.owner.call(&state, "GET", "/ui/api/invites", None).await;
    let row =
        invites.body["invites"].as_array().unwrap().iter().find(|i| i["kind"] == "account_reset").cloned().unwrap();
    assert_eq!((row["user"].clone(), row["used_by"].clone()), (json!("ann"), json!("ann")));
    let _ = (&mut p.amy, &mut p.bob);
}

#[tokio::test]
async fn admins_reset_members_and_the_owner_resets_admins() {
    let state = state();
    let mut p = people(&state).await;
    let id = |n: &str| p.ids[n].clone();
    let forbidden = |r: &Resp| r.status == StatusCode::FORBIDDEN;
    // An admin: members only.
    assert_eq!(reset(&state, &mut p.adam, &id("ann"), json!({})).await.status, StatusCode::OK);
    assert!(forbidden(&reset(&state, &mut p.adam, &id("amy"), json!({})).await), "not another admin");
    assert!(forbidden(&reset(&state, &mut p.adam, &id("olivia"), json!({})).await), "not the owner");
    assert!(forbidden(&reset(&state, &mut p.adam, &id("adam"), json!({})).await), "not themselves");
    // The owner: admins and members, never themselves (that is `admin link`).
    assert_eq!(reset(&state, &mut p.owner, &id("adam"), json!({})).await.status, StatusCode::OK);
    assert_eq!(reset(&state, &mut p.owner, &id("bob"), json!({})).await.status, StatusCode::OK);
    assert!(forbidden(&reset(&state, &mut p.owner, &id("olivia"), json!({})).await));
    // A member: nobody.
    let r = reset(&state, &mut p.ann, &id("bob"), json!({})).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::FORBIDDEN, json!("admin_only")));
    assert_eq!(reset(&state, &mut p.adam, "usnosuchuser", json!({})).await.status, StatusCode::NOT_FOUND);
    // Lifetimes outside 15 min ..= 24 h are refused.
    for ttl in [60, 86_401] {
        let r = reset(&state, &mut p.adam, &id("ann"), json!({ "ttl_s": ttl })).await;
        assert_eq!(r.body["error"]["code"], "validation", "{ttl}: {}", r.body);
    }
    let r = reset(&state, &mut p.adam, &id("ann"), json!({ "ttl_s": 900 })).await;
    assert_eq!(r.status, StatusCode::OK);
    // A disabled account gets no link.
    p.owner.call(&state, "PATCH", &format!("/ui/api/users/{}", id("bob")), Some(json!({ "disabled": true }))).await;
    let r = reset(&state, &mut p.owner, &id("bob"), json!({})).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::CONFLICT, json!("disabled")));
    // The shell (`user reset`) may reset anyone but the owner.
    let owner_id = id("olivia");
    let made =
        state.db.create_reset_link("inshell".into(), "h1".into(), owner_id, None, now() + 600, false).await.unwrap();
    assert_eq!(made.unwrap_err(), crate::accounts::ResetLinkError::Forbidden);
    let made =
        state.db.create_reset_link("inshell2".into(), "h2".into(), id("amy"), None, now() + 600, false).await.unwrap();
    assert_eq!(made.unwrap().created_by, None);
    let _ = (&mut p.amy, &mut p.bob);
}

#[tokio::test]
async fn a_reset_link_is_void_after_any_change_to_the_account_or_its_maker() {
    let state = state();
    let mut p = people(&state).await;
    let ann_id = p.ids["ann"].clone();
    let dead = |r: &Resp| r.status == StatusCode::NOT_FOUND && r.body["error"]["code"] == "invalid_invite";

    // A newer link replaces the earlier one.
    let first = token_of(&reset(&state, &mut p.adam, &ann_id, json!({})).await);
    let second = token_of(&reset(&state, &mut p.amy, &ann_id, json!({})).await);
    assert!(dead(&redeem(&state, &first, "ann-new-password", 50).await.1));

    // The account changed its own sign-in meanwhile (here: its password).
    let r = p
        .ann
        .call(
            &state,
            "POST",
            "/ui/api/account/password",
            Some(json!({ "current": "ann-password", "new": "ann-changed-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(dead(&redeem(&state, &second, "ann-new-password", 51).await.1));

    // The maker is no longer an admin.
    let by_adam = token_of(&reset(&state, &mut p.adam, &ann_id, json!({})).await);
    let adam_id = p.ids["adam"].clone();
    let r = p.owner.call(&state, "PATCH", &format!("/ui/api/users/{adam_id}"), Some(json!({ "role": "member" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(dead(&redeem(&state, &by_adam, "ann-new-password", 52).await.1));
    let r = p.owner.call(&state, "PATCH", &format!("/ui/api/users/{adam_id}"), Some(json!({ "role": "admin" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(dead(&redeem(&state, &by_adam, "ann-new-password", 66).await.1), "a demotion undone does not revive it");

    // The maker was disabled.
    let by_amy = token_of(&reset(&state, &mut p.amy, &ann_id, json!({})).await);
    let amy_id = p.ids["amy"].clone();
    p.owner.call(&state, "PATCH", &format!("/ui/api/users/{amy_id}"), Some(json!({ "disabled": true }))).await;
    assert!(dead(&redeem(&state, &by_amy, "ann-new-password", 53).await.1));

    // The maker changed their own sign-in since (e.g. recovering from a stolen session).
    let by_owner = token_of(&reset(&state, &mut p.owner, &ann_id, json!({})).await);
    let r = p
        .owner
        .call(
            &state,
            "POST",
            "/ui/api/account/password",
            Some(json!({ "current": "olivia-password", "new": "olivia-recovered-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let info = Browser::new(67).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": by_owner }))).await;
    assert_eq!(info.status, StatusCode::NOT_FOUND, "a void link names nobody: {}", info.body);
    assert!(dead(&redeem(&state, &by_owner, "ann-new-password", 65).await.1));

    // The account was promoted (its role and epoch moved on).
    let by_owner = token_of(&reset(&state, &mut p.owner, &ann_id, json!({})).await);
    p.owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "role": "admin" }))).await;
    assert!(dead(&redeem(&state, &by_owner, "ann-new-password", 54).await.1));

    // The account was disabled.
    let bob_id = p.ids["bob"].clone();
    let for_bob = token_of(&reset(&state, &mut p.owner, &bob_id, json!({})).await);
    p.owner.call(&state, "PATCH", &format!("/ui/api/users/{bob_id}"), Some(json!({ "disabled": true }))).await;
    assert!(dead(&redeem(&state, &for_bob, "bob-new-password", 55).await.1));
    p.owner.call(&state, "PATCH", &format!("/ui/api/users/{bob_id}"), Some(json!({ "disabled": false }))).await;
    assert!(dead(&redeem(&state, &for_bob, "bob-new-password", 56).await.1), "still void once enabled again");

    // Expired.
    let expired = tokens::random_token(super::super::INVITE_PREFIX);
    state
        .db
        .create_reset_link("inexpired".into(), tokens::hash_token(&expired), bob_id.clone(), None, now() - 1, false)
        .await
        .unwrap()
        .unwrap();
    assert!(dead(&redeem(&state, &expired, "bob-new-password", 57).await.1));

    // The account was deleted: its links go with it.
    let for_bob = token_of(&reset(&state, &mut p.owner, &bob_id, json!({})).await);
    state.db.delete_user("bob".into()).await.unwrap().unwrap();
    assert!(dead(&redeem(&state, &for_bob, "bob-new-password", 58).await.1));
    assert_eq!(sign_in(&state, "ann", "ann-changed-password", 59).await.body["status"], "ok", "nothing redeemed");
}

#[tokio::test]
async fn making_a_reset_link_needs_a_fresh_code_and_can_be_revoked() {
    let state = state();
    let mut p = people(&state).await;
    let ann_id = p.ids["ann"].clone();
    let mut codes = enable_totp(&state, &mut p.adam, "adam-password").await;
    state
        .db
        .call(|c| {
            c.execute("UPDATE ui_sessions SET auth_at = auth_at - 3600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let r = reset(&state, &mut p.adam, &ann_id, json!({})).await;
    assert_eq!(r.body["error"]["code"], "code_required");
    // Refusals come before a code is asked for (and spent).
    let amy_id = p.ids["amy"].clone();
    assert_eq!(reset(&state, &mut p.adam, &amy_id, json!({})).await.status, StatusCode::FORBIDDEN);
    let r = reset(&state, &mut p.adam, &ann_id, json!({ "code": codes.invalid() })).await;
    assert_eq!(r.body["error"]["code"], "invalid_code");
    let r = reset(&state, &mut p.adam, &ann_id, json!({ "code": codes.next() })).await;
    let token = token_of(&r);
    let invite_id = r.body["invite"]["id"].as_str().unwrap().to_string();

    // An admin may not revoke a reset link for an admin; the owner's link for amy stays.
    let for_amy = reset(&state, &mut p.owner, &amy_id, json!({})).await;
    let amy_link = for_amy.body["invite"]["id"].as_str().unwrap().to_string();
    let r = p.adam.call(&state, "DELETE", &format!("/ui/api/invites/{amy_link}"), None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = p.adam.call(&state, "DELETE", &format!("/ui/api/invites/{invite_id}"), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(redeem(&state, &token, "ann-new-password", 60).await.1.status, StatusCode::NOT_FOUND);
    let amy_token = token_of(&for_amy);
    assert_eq!(redeem(&state, &amy_token, "amy-new-password", 61).await.1.status, StatusCode::OK);
    let _ = (&mut p.ann, &mut p.bob);
}

#[tokio::test]
async fn a_reset_can_also_remove_the_accounts_machines() {
    let state = state();
    let mut p = people(&state).await;
    let ann_id = p.ids["ann"].clone();
    let machine = approve_machine(&state, &mut p.ann, "laptop").await;
    let keep = token_of(&reset(&state, &mut p.adam, &ann_id, json!({})).await);
    assert_eq!(redeem(&state, &keep, "ann-new-password", 62).await.1.status, StatusCode::OK);
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &machine, None).await.status, StatusCode::OK, "kept");
    let drop = token_of(&reset(&state, &mut p.adam, &ann_id, json!({})).await);
    let r = Browser::new(63)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": drop, "password": "ann-newer-password", "revoke_machines": true })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(bearer(&state, "GET", "/v1/tunnels", &machine, None).await.status, StatusCode::UNAUTHORIZED);
    let _ = (&mut p.amy, &mut p.bob, &mut p.owner);
}

#[tokio::test]
async fn an_owner_link_does_not_drop_pending_account_resets() {
    let state = state();
    let mut p = people(&state).await;
    let ann_id = p.ids["ann"].clone();
    let token = token_of(&reset(&state, &mut p.adam, &ann_id, json!({})).await);
    let _owner_link = invite_token(&state, InviteKind::OwnerReset, Role::Owner).await;
    assert_eq!(redeem(&state, &token, "ann-new-password", 64).await.1.status, StatusCode::OK);
    let _ = (&mut p.amy, &mut p.bob, &mut p.owner);
}

#[tokio::test]
async fn the_invite_list_says_which_reset_links_this_admin_may_revoke() {
    let state = state();
    let mut p = people(&state).await;
    let ann_id = p.ids["ann"].clone();
    let made = reset(&state, &mut p.owner, &ann_id, json!({})).await;
    let link = made.body["invite"]["id"].clone();
    let revocable =
        |r: &Resp| r.body["invites"].as_array().unwrap().iter().find(|i| i["id"] == link).unwrap()["revocable"].clone();
    let r = p.adam.call(&state, "GET", "/ui/api/invites", None).await;
    assert_eq!(revocable(&r), json!(true), "a member's reset");
    // Promoted after the link was made: an admin's now, so only the owner may revoke it.
    p.owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "role": "admin" }))).await;
    assert_eq!(revocable(&p.adam.call(&state, "GET", "/ui/api/invites", None).await), json!(false));
    assert_eq!(revocable(&p.owner.call(&state, "GET", "/ui/api/invites", None).await), json!(true));
    let r = p.adam.call(&state, "DELETE", &format!("/ui/api/invites/{}", link.as_str().unwrap()), None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = p.adam.call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member" }))).await;
    let invite = r.body["invite"]["id"].clone();
    let list = p.amy.call(&state, "GET", "/ui/api/invites", None).await;
    let row = list.body["invites"].as_array().unwrap().iter().find(|i| i["id"] == invite).unwrap().clone();
    assert_eq!(row["revocable"], true, "invites as before");
    assert!(row.get("token_hash").is_none() && row.get("user_role").is_none());
    let _ = (&mut p.ann, &mut p.bob);
}
