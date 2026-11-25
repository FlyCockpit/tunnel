//! Mail flows against the fake SMTP server: mailed invites confirm the
//! address, "Forgot password?" answers the same for everyone and keeps
//! two-factor sign-in, address changes are confirmed and announced, and
//! notices go out. With mail off none of it exists.

use super::*;
use crate::mail::fake::{FakeSmtp, Received, Script};

async fn mail_state() -> (Arc<AppState>, FakeSmtp) {
    mail_state_with(Script::default()).await
}

async fn mail_state_with(script: Script) -> (Arc<AppState>, FakeSmtp) {
    let server = FakeSmtp::start(script).await;
    let port = server.port;
    let state = state_with(|c| {
        c.smtp = Some(crate::config::smtp::SmtpConfig {
            host: "127.0.0.1".into(),
            port,
            user: None,
            pass: None,
            from: "Tunnel <tunnel@example.com>".into(),
        })
    });
    (state, server)
}

/// Wait until every queued mail went out.
async fn settle(state: &Arc<AppState>) {
    state.ui.mail.as_ref().unwrap().idle().await;
}

fn last(server: &FakeSmtp, to: &str) -> Received {
    server.to(to).pop().unwrap_or_else(|| panic!("no mail to {to}: {:?}", server.received()))
}

async fn sign_in(state: &Arc<AppState>, username: &str, password: &str, ip: u8) -> Resp {
    Browser::new(ip)
        .call(state, "POST", "/ui/api/login", Some(json!({ "username": username, "password": password })))
        .await
}

async fn forgot(state: &Arc<AppState>, login: &str, ip: u8) -> Resp {
    Browser::new(ip).call(state, "POST", "/ui/api/password/forgot", Some(json!({ "login": login }))).await
}

/// The owner invites `name` by mail to `email`; `name` signs up from the mail.
async fn invited(
    state: &Arc<AppState>,
    server: &FakeSmtp,
    owner: &mut Browser,
    name: &str,
    email: &str,
    ip: u8,
) -> Browser {
    let r = owner.call(state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": email }))).await;
    assert_eq!((r.status, r.body["mailed"].clone()), (StatusCode::OK, json!(true)), "{}", r.body);
    settle(state).await;
    let mail = last(server, &email.to_ascii_lowercase());
    assert_eq!(mail.link().unwrap(), r.body["url"].as_str().unwrap(), "the mail carries the shown link");
    sign_up(state, &mail.token().unwrap(), name, ip).await
}

#[tokio::test]
async fn with_mail_off_there_is_no_email_anything() {
    let state = state();
    assert!(state.ui.mail.as_ref().is_none());
    let mut owner = owner(&state).await;
    let s = owner.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(s.body["server"]["mail"], false);
    assert!(s.body["email_pending"].is_null());
    for (path, body) in [
        ("/ui/api/password/forgot", json!({ "login": "olivia" })),
        ("/ui/api/account/email", json!({ "email": "o@example.com", "password": "olivia-password" })),
        ("/ui/api/account/email/remove", json!({ "password": "olivia-password" })),
        ("/ui/api/email/verify", json!({ "token": "tninv_x" })),
    ] {
        let r = owner.call(&state, "POST", path, Some(body)).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}: {}", r.body);
    }
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "m@example.com" })))
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", r.body);
    let status = owner.call(&state, "GET", "/ui/api/status", None).await;
    assert_eq!(status.body["mail"]["enabled"], false);
    // A system install (the default data dir): its config is root's, so sudo…
    assert_eq!(state.config.data_dir, std::path::Path::new(crate::config::mode::SYSTEM_DATA_DIR));
    assert_eq!(status.body["mail"]["setup"], "sudo tunnel-server mail setup");
    // …but not for a rootless one (sudo would pick root's config).
    let mut rootless = state.config.clone();
    rootless.data_dir = "/home/ann/.local/share/tunnel".into();
    assert_eq!(crate::ui::email::command(&rootless, None, "setup"), "tunnel-server mail setup");
    // The default config file needs no flag; another one is passed on, quoted.
    let system = &state.config;
    let default = std::path::Path::new(crate::config::mode::SYSTEM_CONFIG_PATH);
    assert_eq!(crate::ui::email::command(system, Some(default), "setup"), "sudo tunnel-server mail setup");
    let custom = std::path::Path::new("/srv/my tunnel/it's.toml");
    assert_eq!(
        crate::ui::email::command(system, Some(custom), "test you@example.com"),
        r#"sudo tunnel-server --config '/srv/my tunnel/it'\''s.toml' mail test you@example.com"#
    );
}

#[tokio::test]
async fn a_mailed_invite_confirms_the_address_and_status_shows_mail_without_secrets() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "Ann@Example.com", 30).await;
    let mail = last(&server, "ann@example.com");
    assert!(mail.subject().contains("invited"), "{}", mail.subject());
    assert!(mail.text().contains("olivia invited you"), "{}", mail.text());
    let s = ann.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(
        (s.body["user"]["email"].clone(), s.body["server"]["mail"].clone()),
        (json!("ann@example.com"), json!(true))
    );
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    assert_eq!(listed(&users.body, "ann")["email"], "ann@example.com");
    // An address in use cannot be invited again.
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "ann@example.com" })))
        .await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::CONFLICT, json!("email_taken")));
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "not an address" })))
        .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // Status: on, through what; never the credentials.
    let status = owner.call(&state, "GET", "/ui/api/status", None).await;
    assert_eq!(status.body["mail"]["enabled"], true);
    assert_eq!(status.body["mail"]["security"], "plain, local relay");
    assert!(status.body["mail"].get("pass").is_none() && status.body["mail"].get("user").is_none());
    assert_eq!(status.body["mail"]["test"], "sudo tunnel-server mail test you@example.com");
}

#[tokio::test]
async fn forgot_password_answers_the_same_for_everyone_and_mails_only_confirmed_addresses() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let _bob = member(&state, &mut owner, "bob", 31).await; // no address
    let _carl = invited(&state, &server, &mut owner, "carl", "carl@example.com", 32).await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let carl_id = user_id(&users.body, "carl");
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{carl_id}"), Some(json!({ "disabled": true }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    let before = server.received().len();

    let mut answers = Vec::new();
    for (i, login) in ["ann", "nobody", "bob", "carl", "nobody@example.com", "CARL@example.com"].into_iter().enumerate()
    {
        let r = forgot(&state, login, 50 + i as u8).await;
        answers.push((r.status, r.body.to_string(), r.set_cookie.is_some()));
    }
    assert!(answers.iter().all(|a| *a == answers[0]), "identical answers: {answers:?}");
    assert_eq!(answers[0].0, StatusCode::OK);
    settle(&state).await;
    let sent: Vec<_> = server.received()[before..].to_vec();
    assert_eq!(sent.len(), 1, "only ann has a confirmed address and is enabled: {sent:?}");
    let mail = &sent[0];
    assert_eq!(mail.to, "ann@example.com");
    assert!(mail.text().contains("account ann") && !mail.text().contains("authenticator"), "{}", mail.text());
    // Built from ui_host, whatever Host the request came with.
    assert!(mail.link().unwrap().starts_with("https://ui.example.com/invite#tninv_"));

    // One link per account per two minutes, by name or address.
    forgot(&state, "ann@example.com", 60).await;
    settle(&state).await;
    assert_eq!(server.to("ann@example.com").len(), 2, "the invite and one reset");

    // The link sets a new password, ends sessions, and is single use.
    let token = mail.token().unwrap();
    let info = Browser::new(61).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!((info.body["kind"].clone(), info.body["needs_code"].clone()), (json!("password_reset"), json!(false)));
    let mut fresh = Browser::new(62);
    let r = fresh
        .call(&state, "POST", "/ui/api/invite/accept", Some(json!({ "token": token, "password": "ann-new-password" })))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let mut ann = ann;
    assert!(ann.call(&state, "GET", "/ui/api/session", None).await.body["user"].is_null(), "old sessions end");
    assert_eq!(sign_in(&state, "ann", "ann-password", 63).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(sign_in(&state, "ann", "ann-new-password", 64).await.body["status"], "ok");
    let again = Browser::new(65)
        .call(&state, "POST", "/ui/api/invite/accept", Some(json!({ "token": token, "password": "another-password" })))
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    settle(&state).await;
    assert!(last(&server, "ann@example.com").text().contains("was reset"), "a notice follows");

    // The cooldown is kept on the account: cleanup dropping the used link does not end it.
    let n = server.to("ann@example.com").len();
    state.db.purge_accounts().await.unwrap();
    forgot(&state, "ann", 66).await;
    settle(&state).await;
    assert_eq!(server.to("ann@example.com").len(), n, "within the cooldown, even after cleanup");
}

#[tokio::test]
async fn a_mailed_reset_keeps_two_factor_and_asks_for_a_code() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let mut codes = enable_totp(&state, &mut ann, "ann-password").await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = user_id(&users.body, "ann");
    forgot(&state, "ann", 40).await;
    settle(&state).await;
    let mail = last(&server, "ann@example.com");
    assert!(mail.text().contains("authenticator"), "the mail says a code is needed: {}", mail.text());
    let token = mail.token().unwrap();
    let info = Browser::new(41).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!(info.body["needs_code"], true);

    let accept = |code: Option<String>| {
        let mut body = json!({ "token": token, "password": "ann-new-password" });
        if let Some(c) = code {
            body["code"] = json!(c);
        }
        body
    };
    let r = Browser::new(42).call(&state, "POST", "/ui/api/invite/accept", Some(accept(None))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::UNAUTHORIZED, json!("code_required")));
    let r = Browser::new(42).call(&state, "POST", "/ui/api/invite/accept", Some(accept(Some(codes.invalid())))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::UNAUTHORIZED, json!("invalid_code")));
    assert_eq!(sign_in(&state, "ann", "ann-password", 43).await.body["status"], "totp_required", "nothing changed yet");
    let r = Browser::new(44).call(&state, "POST", "/ui/api/invite/accept", Some(accept(Some(codes.next())))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // Two-factor sign-in and the recovery codes stay.
    assert_eq!(sign_in(&state, "ann", "ann-new-password", 45).await.body["status"], "totp_required");
    assert_eq!(state.db.recovery_codes_left(ann_id).await.unwrap(), 10);
}

#[tokio::test]
async fn forgot_password_is_rate_limited_per_address_of_origin() {
    let (state, _server) = mail_state().await;
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(forgot(&state, "nobody", 70).await.status);
    }
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 10, "{statuses:?}");
    assert_eq!(statuses.last(), Some(&StatusCode::TOO_MANY_REQUESTS));
    assert_eq!(forgot(&state, "nobody", 71).await.status, StatusCode::OK, "another address is not limited");
    assert_eq!(forgot(&state, " ", 72).await.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn forgot_password_has_a_server_wide_budget_that_ignores_who_is_asked_for() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let _ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    // 60 a minute server-wide, from many addresses (each under its own 10).
    let mut ok = 0;
    for i in 0..60u8 {
        if forgot(&state, &format!("nobody{i}"), 100 + i / 8).await.status == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 60);
    // Then refused, for a real account exactly as for nobody.
    let known = forgot(&state, "ann", 120).await;
    let unknown = forgot(&state, "nobody-else", 121).await;
    assert_eq!((known.status, known.body.clone()), (unknown.status, unknown.body.clone()));
    assert_eq!(known.status, StatusCode::TOO_MANY_REQUESTS);
    settle(&state).await;
    assert_eq!(server.to("ann@example.com").len(), 1, "only the invite");
}

#[tokio::test]
async fn changing_the_address_is_confirmed_by_mail_and_announced_to_the_old_one() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let set = |email: &str, password: &str| json!({ "email": email, "password": password });

    let r = ann.call(&state, "POST", "/ui/api/account/email", Some(set("ann@new.example", "wrong-password"))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = ann.call(&state, "POST", "/ui/api/account/email", Some(set("ann@example.com", "ann-password"))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::CONFLICT, json!("unchanged")));
    let r = ann.call(&state, "POST", "/ui/api/account/email", Some(set("Ann@New.example", "ann-password"))).await;
    assert_eq!((r.status, r.body["pending"].clone()), (StatusCode::OK, json!("ann@new.example")), "{}", r.body);
    let s = ann.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(
        (s.body["user"]["email"].clone(), s.body["email_pending"].clone()),
        (json!("ann@example.com"), json!("ann@new.example"))
    );
    settle(&state).await;
    let mail = last(&server, "ann@new.example");
    let token = mail.token().unwrap();
    let info = Browser::new(31).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!(
        (info.body["kind"].clone(), info.body["email"].clone()),
        (json!("email_verify"), json!("ann@new.example"))
    );
    // Not a password link.
    let r = Browser::new(31)
        .call(&state, "POST", "/ui/api/invite/accept", Some(json!({ "token": token, "password": "hijacked-password" })))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = Browser::new(32).call(&state, "POST", "/ui/api/email/verify", Some(json!({ "token": token }))).await;
    assert_eq!((r.status, r.body["email"].clone()), (StatusCode::OK, json!("ann@new.example")), "{}", r.body);
    let s = ann.call(&state, "GET", "/ui/api/session", None).await;
    assert_eq!(
        (s.body["user"]["email"].clone(), s.body["email_pending"].clone()),
        (json!("ann@new.example"), Value::Null)
    );
    settle(&state).await;
    let notice = last(&server, "ann@example.com");
    assert!(notice.text().contains("changed from this address to a***@new.example"), "{}", notice.text());
    let again = Browser::new(33).call(&state, "POST", "/ui/api/email/verify", Some(json!({ "token": token }))).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "single use");

    // Another account's address: the same answer, nothing mailed, never confirmed.
    let mut bob = invited(&state, &server, &mut owner, "bob", "bob@example.com", 34).await;
    let n = server.received().len();
    let r = bob.call(&state, "POST", "/ui/api/account/email", Some(set("ann@new.example", "bob-password"))).await;
    assert_eq!((r.status, r.body["status"].clone()), (StatusCode::OK, json!("sent")));
    settle(&state).await;
    assert_eq!(server.received().len(), n, "nothing mailed for someone else's address");

    // With two-factor sign-in, a stale session also needs a code (as for a new machine).
    let mut codes = enable_totp(&state, &mut bob, "bob-password").await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let bob_id = user_id(&users.body, "bob");
    let stale = now() - 11 * 60;
    state
        .db
        .call(move |c| {
            Ok(c.execute("UPDATE ui_sessions SET auth_at = ?2 WHERE user_id = ?1", rusqlite::params![bob_id, stale])?)
        })
        .await
        .unwrap();
    let r = bob.call(&state, "POST", "/ui/api/account/email", Some(set("bob@new.example", "bob-password"))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::UNAUTHORIZED, json!("code_required")));
    let mut body = set("bob@new.example", "bob-password");
    body["code"] = json!(codes.next());
    let r = bob.call(&state, "POST", "/ui/api/account/email", Some(body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // A pending link stops working when the password changes.
    settle(&state).await;
    let token = last(&server, "bob@new.example").token().unwrap();
    let r = bob
        .call(
            &state,
            "POST",
            "/ui/api/account/password",
            Some(json!({ "current": "bob-password", "new": "bob-password-2" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let info = Browser::new(35).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!(info.status, StatusCode::NOT_FOUND, "a voided confirmation shows nothing: {}", info.body);
    let r = Browser::new(35).call(&state, "POST", "/ui/api/email/verify", Some(json!({ "token": token }))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let s = bob.call(&state, "GET", "/ui/api/session", None).await;
    assert!(s.body["email_pending"].is_null(), "a voided link is no longer shown as pending: {}", s.body);
    settle(&state).await;
    assert!(last(&server, "bob@example.com").text().contains("password of your account was changed"));

    // Removing the address announces it there; then nothing more is mailed.
    let r = ann.call(&state, "POST", "/ui/api/account/email/remove", Some(json!({ "password": "ann-password" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    assert!(last(&server, "ann@new.example").text().contains("removed from your account"));
    let n = server.received().len();
    forgot(&state, "ann", 36).await;
    settle(&state).await;
    assert_eq!(server.received().len(), n);
}

#[tokio::test]
async fn security_notices_and_the_admin_reset_go_by_mail() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let n0 = server.to("ann@example.com").len();
    let mut codes = enable_totp(&state, &mut ann, "ann-password").await;
    let r = ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": "laptop", "code": codes.next() }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    approve_machine(&state, &mut ann, "desk").await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = user_id(&users.body, "ann");
    let r = owner.call(&state, "PATCH", &format!("/ui/api/users/{ann_id}"), Some(json!({ "role": "admin" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    let texts: Vec<String> = server.to("ann@example.com")[n0..].iter().map(Received::text).collect();
    for want in ["Two-factor sign-in was turned on", "new machine, laptop", "new machine, desk", "from member to admin"]
    {
        assert!(texts.iter().any(|t| t.contains(want)), "{want:?} not in {texts:#?}");
    }
    for t in &texts {
        assert!(!t.contains("tncli_") && !t.contains("otpauth") && !t.contains("recovery code"), "no secrets: {t}");
    }

    // The owner's sign-in reset for ann, mailed to her confirmed address (and still shown).
    let n1 = server.to("ann@example.com").len();
    let r =
        owner.call(&state, "POST", &format!("/ui/api/users/{ann_id}/reset"), Some(json!({ "send_email": true }))).await;
    assert_eq!((r.status, r.body["mailed"].clone()), (StatusCode::OK, json!(true)), "{}", r.body);
    settle(&state).await;
    let mail = last(&server, "ann@example.com");
    assert_eq!(server.to("ann@example.com").len(), n1 + 1);
    assert_eq!(mail.link().unwrap(), r.body["url"].as_str().unwrap());
    assert!(mail.text().contains("olivia made a link"), "{}", mail.text());
    let r = Browser::new(80)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": mail.token().unwrap(), "password": "ann-reset-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    assert!(last(&server, "ann@example.com").text().contains("two-factor sign-in is off"));

    // No address, no mail: a clear refusal, and the link is not made.
    let mut bob = member(&state, &mut owner, "bob", 81).await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let bob_id = user_id(&users.body, "bob");
    let r =
        owner.call(&state, "POST", &format!("/ui/api/users/{bob_id}/reset"), Some(json!({ "send_email": true }))).await;
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::CONFLICT, json!("no_email")));
    let _ = bob.call(&state, "GET", "/ui/api/session", None).await;
}

#[tokio::test]
async fn a_revoked_reset_link_cannot_try_codes_or_outlive_the_address() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let mut codes = enable_totp(&state, &mut ann, "ann-password").await;
    forgot(&state, "ann", 40).await;
    settle(&state).await;
    let token = last(&server, "ann@example.com").token().unwrap();
    // The password changes: the link is void, so wrong codes through it are not even checked.
    let r = ann
        .call(
            &state,
            "POST",
            "/ui/api/account/password",
            Some(json!({ "current": "ann-password", "new": "ann-password-2" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let info = Browser::new(41).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": token }))).await;
    assert_eq!(info.status, StatusCode::NOT_FOUND);
    for _ in 0..6 {
        let body = json!({ "token": token, "password": "hijacked-password", "code": codes.invalid() });
        let r = Browser::new(42).call(&state, "POST", "/ui/api/invite/accept", Some(body)).await;
        assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::NOT_FOUND, json!("invalid_invite")));
    }
    let mut b = Browser::new(43);
    let r =
        b.call(&state, "POST", "/ui/api/login", Some(json!({ "username": "ann", "password": "ann-password-2" }))).await;
    assert_eq!(r.body["status"], "totp_required");
    let r = b.call(&state, "POST", "/ui/api/login/totp", Some(json!({ "code": codes.next() }))).await;
    assert_eq!(r.status, StatusCode::OK, "no lockout from the void link: {}", r.body);

    // An admin's reset mailed to ann's address stops working when she changes it.
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = user_id(&users.body, "ann");
    cool_down(&state, &ann_id).await; // after the "Forgot password?" mail above
    let r =
        owner.call(&state, "POST", &format!("/ui/api/users/{ann_id}/reset"), Some(json!({ "send_email": true }))).await;
    assert_eq!(r.body["mailed"], true, "{}", r.body);
    settle(&state).await;
    let reset = last(&server, "ann@example.com").token().unwrap();
    let mut ann = b;
    ann.refresh_csrf(&state).await;
    let body = json!({ "email": "ann@new.example", "password": "ann-password-2", "code": codes.next() });
    let r = ann.call(&state, "POST", "/ui/api/account/email", Some(body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    let verify = last(&server, "ann@new.example").token().unwrap();
    let r = Browser::new(44).call(&state, "POST", "/ui/api/email/verify", Some(json!({ "token": verify }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let info = Browser::new(45).call(&state, "POST", "/ui/api/invite/info", Some(json!({ "token": reset }))).await;
    assert_eq!(info.status, StatusCode::NOT_FOUND, "the page says nothing about it either: {}", info.body);
    let r = Browser::new(45)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": reset, "password": "old-mailbox-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "the old mailbox cannot reset ann: {}", r.body);

    // Nor does it come back when the same address is confirmed again later.
    cool_down(&state, &ann_id).await;
    let r =
        owner.call(&state, "POST", &format!("/ui/api/users/{ann_id}/reset"), Some(json!({ "send_email": true }))).await;
    assert_eq!(r.body["mailed"], true, "{}", r.body);
    settle(&state).await;
    let reset = last(&server, "ann@new.example").token().unwrap();
    let r =
        ann.call(&state, "POST", "/ui/api/account/email/remove", Some(json!({ "password": "ann-password-2" }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let body = json!({ "email": "ann@new.example", "password": "ann-password-2", "code": codes.next() });
    let r = ann.call(&state, "POST", "/ui/api/account/email", Some(body)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    let verify = last(&server, "ann@new.example").token().unwrap();
    let r = Browser::new(46).call(&state, "POST", "/ui/api/email/verify", Some(json!({ "token": verify }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let r = Browser::new(47)
        .call(
            &state,
            "POST",
            "/ui/api/invite/accept",
            Some(json!({ "token": reset, "password": "old-mailbox-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "a removed address's reset stays void: {}", r.body);
}

#[tokio::test]
async fn notices_are_rate_limited_per_address() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    // Add and remove a machine again and again: a notice each time, but only a few get out.
    for i in 0..12 {
        let r = ann.call(&state, "POST", "/ui/api/machines", Some(json!({ "name": format!("box-{i}") }))).await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
        let r = ann.call(&state, "DELETE", &format!("/ui/api/machines/box-{i}"), None).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    }
    settle(&state).await;
    let notices = server.to("ann@example.com").iter().filter(|m| m.text().contains("new machine")).count();
    assert_eq!(notices, 5, "five notices a minute per address");
    // Recovery mail still goes out.
    forgot(&state, "ann", 31).await;
    settle(&state).await;
    assert!(last(&server, "ann@example.com").text().contains("reset the password"));
}

#[tokio::test]
async fn a_machine_added_through_the_admin_api_is_announced_too() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let _ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let r = bearer(&state, "POST", "/v1/clients", ADMIN_CREDENTIAL, Some(json!({ "name": "ci", "user": "ann" }))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    settle(&state).await;
    let notice = last(&server, "ann@example.com");
    assert!(notice.text().contains("A login code for a new machine, ci, was made"), "{}", notice.text());
}

#[tokio::test]
async fn address_checks_and_admin_mails_have_their_own_limits() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    // An admin can invite a team by mail (10 a minute), and an address in use is a plain 409.
    for i in 0..9 {
        let r = owner
            .call(
                &state,
                "POST",
                "/ui/api/invites",
                Some(json!({ "role": "member", "email": format!("m{i}@example.com") })),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{i}: {}", r.body);
    }
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "ann@example.com" })))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "checked before the limit: {}", r.body);
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "late@example.com" })))
        .await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
    // Confirmation links to new addresses: three a minute per user.
    let mut statuses = Vec::new();
    for i in 0..4 {
        let body = json!({ "email": format!("ann{i}@new.example"), "password": "ann-password" });
        statuses.push(ann.call(&state, "POST", "/ui/api/account/email", Some(body)).await.status);
    }
    assert_eq!(statuses[..3], [StatusCode::OK; 3]);
    assert_eq!(statuses[3], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn one_address_gets_only_a_few_confirmation_mails_whoever_asks() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let mut bob = invited(&state, &server, &mut owner, "bob", "bob@example.com", 31).await;
    // Two members ask for someone else's address, in any case: the same answer every time…
    for i in 0..4 {
        let (who, email, password) = if i % 2 == 0 {
            (&mut ann, "Victim@Else.example", "ann-password")
        } else {
            (&mut bob, "victim@else.example", "bob-password")
        };
        let r = who
            .call(&state, "POST", "/ui/api/account/email", Some(json!({ "email": email, "password": password })))
            .await;
        assert_eq!((r.status, r.body["status"].clone()), (StatusCode::OK, json!("sent")), "{i}: {}", r.body);
    }
    // …but only three mails an hour reach it.
    settle(&state).await;
    assert_eq!(server.to("victim@else.example").len(), 3);
    // Other addresses are not held up.
    let r = bob
        .call(
            &state,
            "POST",
            "/ui/api/account/email",
            Some(json!({ "email": "bob@new.example", "password": "bob-password" })),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    settle(&state).await;
    assert_eq!(server.to("bob@new.example").len(), 1);
}

#[tokio::test]
async fn a_mail_dropped_by_a_full_queue_is_not_reported_as_mailed() {
    // A mail server that never answers: deliveries wait until the queue is full.
    let (state, _server) = mail_state_with(Script { silent: true, ..Default::default() }).await;
    let mut owner = owner(&state).await;
    let mailer = state.ui.mail.clone().unwrap();
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "a@example.com" })))
        .await;
    assert_eq!((r.status, r.body["mailed"].clone()), (StatusCode::OK, json!(true)), "queued: {}", r.body);
    let mut queued = 1;
    while mailer.send_later(
        "test",
        "x@example.com".into(),
        mailer.texts().invite("https://x/invite#tninv_x", "member", None, 60),
    ) {
        queued += 1;
    }
    assert_eq!(queued, 200, "the queue holds 200");
    let r = owner
        .call(&state, "POST", "/ui/api/invites", Some(json!({ "role": "member", "email": "b@example.com" })))
        .await;
    assert_eq!((r.status, r.body["mailed"].clone()), (StatusCode::OK, json!(false)), "{}", r.body);
    assert!(r.body["url"].as_str().unwrap().contains("/invite#tninv_"), "the link is still shown to hand over");
}

#[tokio::test]
async fn a_busy_server_does_not_use_up_a_recovery_code() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let mut ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let _codes = enable_totp(&state, &mut ann, "ann-password").await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let ann_id = user_id(&users.body, "ann");
    // A recovery code: only its hash is stored, so make a known one.
    let code = "abcdefghij";
    let (id, h) = (ann_id.clone(), tokens::hash_token(code));
    state
        .db
        .call(move |c| {
            Ok(c.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?1, ?2)", rusqlite::params![id, h])?)
        })
        .await
        .unwrap();
    forgot(&state, "ann", 40).await;
    settle(&state).await;
    let token = last(&server, "ann@example.com").token().unwrap();
    let body = json!({ "token": token, "password": "ann-new-password", "code": "abcde-fghij" });
    crate::password::HASH_BUSY.set(true);
    let r = Browser::new(41).call(&state, "POST", "/ui/api/invite/accept", Some(body.clone())).await;
    crate::password::HASH_BUSY.set(false);
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE, "{}", r.body);
    assert_eq!(state.db.recovery_codes_left(ann_id.clone()).await.unwrap(), 11, "the code is still there");
    let r = Browser::new(42).call(&state, "POST", "/ui/api/invite/accept", Some(body)).await;
    assert_eq!(r.status, StatusCode::OK, "it works once the server has room: {}", r.body);
    assert_eq!(state.db.recovery_codes_left(ann_id).await.unwrap(), 10);
}

/// End `user_id`'s recovery-mail cooldown as if `RECOVERY_MAIL_COOLDOWN_S` had passed.
async fn cool_down(state: &Arc<AppState>, user_id: &str) {
    let id = user_id.to_string();
    let wait = crate::addresses::RECOVERY_MAIL_COOLDOWN_S;
    state
        .db
        .call(move |c| {
            Ok(c.execute(
                "UPDATE users SET recovery_mail_at = recovery_mail_at - ?2 WHERE id = ?1",
                rusqlite::params![id, wait],
            )?)
        })
        .await
        .unwrap();
}

async fn mail_reset(state: &Arc<AppState>, admin: &mut Browser, user_id: &str, send_email: bool) -> Resp {
    admin
        .call(state, "POST", &format!("/ui/api/users/{user_id}/reset"), Some(json!({ "send_email": send_email })))
        .await
}

fn assert_cooldown(r: &Resp) {
    assert_eq!((r.status, r.body["error"]["code"].clone()), (StatusCode::TOO_MANY_REQUESTS, json!("mail_cooldown")));
    let message = r.body["error"]["message"].as_str().unwrap();
    let wait = message
        .strip_prefix("a reset mail was sent to this account recently; try again in ")
        .and_then(|m| m.split_once(" s")?.0.parse::<i64>().ok())
        .unwrap_or_else(|| panic!("says how long to wait: {message}"));
    assert!((1..=crate::addresses::RECOVERY_MAIL_COOLDOWN_S).contains(&wait), "{message}");
}

#[tokio::test]
async fn admin_reset_mails_and_forgot_password_share_one_cooldown_per_account() {
    let (state, server) = mail_state().await;
    let mut owner = owner(&state).await;
    let _ann = invited(&state, &server, &mut owner, "ann", "ann@example.com", 30).await;
    let _bea = invited(&state, &server, &mut owner, "bea", "bea@example.com", 31).await;
    let users = owner.call(&state, "GET", "/ui/api/users", None).await;
    let (ann_id, bea_id) = (user_id(&users.body, "ann"), user_id(&users.body, "bea"));
    let n = server.to("ann@example.com").len();

    // Admin, then admin again: the second is refused with the wait, and nothing more is mailed.
    let r = mail_reset(&state, &mut owner, &ann_id, true).await;
    assert_eq!((r.status, r.body["mailed"].clone()), (StatusCode::OK, json!(true)), "{}", r.body);
    let first = r.body["url"].as_str().unwrap().to_string();
    assert_cooldown(&mail_reset(&state, &mut owner, &ann_id, true).await);
    // Another account is not held up; a link that is only handed over stays unlimited.
    let r = mail_reset(&state, &mut owner, &bea_id, true).await;
    assert_eq!(r.body["mailed"], true, "{}", r.body);
    for _ in 0..3 {
        let r = mail_reset(&state, &mut owner, &ann_id, false).await;
        assert_eq!((r.status, r.body["mailed"].clone()), (StatusCode::OK, json!(false)), "{}", r.body);
        assert_ne!(r.body["url"].as_str().unwrap(), first);
    }
    // "Forgot password?" right after: the same answer as ever, but no second mail.
    let r = forgot(&state, "ann", 40).await;
    assert_eq!((r.status, r.body.clone()), (StatusCode::OK, json!({ "status": "ok" })));
    settle(&state).await;
    assert_eq!(server.to("ann@example.com").len(), n + 1, "one mail within the cooldown");

    // Self-service first: then the admin's mail waits.
    cool_down(&state, &ann_id).await;
    forgot(&state, "ann", 41).await;
    settle(&state).await;
    assert_eq!(server.to("ann@example.com").len(), n + 2);
    assert!(last(&server, "ann@example.com").text().contains("account ann"));
    assert_cooldown(&mail_reset(&state, &mut owner, &ann_id, true).await);

    // Revoking the mailed link does not free the slot.
    cool_down(&state, &ann_id).await;
    let r = mail_reset(&state, &mut owner, &ann_id, true).await;
    assert_eq!(r.body["mailed"], true, "{}", r.body);
    let invite = r.body["invite"]["id"].as_str().unwrap().to_string();
    let revoked = owner.call(&state, "DELETE", &format!("/ui/api/invites/{invite}"), None).await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
    assert_cooldown(&mail_reset(&state, &mut owner, &ann_id, true).await);
    settle(&state).await;
    assert_eq!(server.to("ann@example.com").len(), n + 3);
}

#[tokio::test]
async fn the_recovery_mail_cooldown_survives_a_restart() {
    let path =
        std::env::temp_dir().join("tunnel-ui-tests").join(format!("recovery-mail-{}.db", tokens::random_tunnel_id()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = crate::db::Db::open(&path).unwrap();
    db.insert_test_user("uann", "ann", Role::Member).await;
    db.call(|c| {
        Ok(c.execute("UPDATE users SET email = 'ann@example.com', email_verified_at = 0 WHERE id = 'uann'", [])?)
    })
    .await
    .unwrap();
    let made = db.create_password_reset("ann".into(), "in1".into(), "h1".into(), now() + 600).await.unwrap();
    assert!(made.is_some(), "the first recovery mail goes out");
    drop(db);

    // A new process: no in-memory limiter remembers anything, the database does.
    let db = crate::db::Db::open(&path).unwrap();
    let made = db.create_reset_link("in2".into(), "h2".into(), "uann".into(), None, now() + 600, true).await.unwrap();
    match made {
        Err(crate::accounts::ResetLinkError::MailCooldown(wait)) => {
            assert!((1..=crate::addresses::RECOVERY_MAIL_COOLDOWN_S).contains(&wait), "{wait}")
        }
        other => panic!("refused within the cooldown: {other:?}"),
    }
    let wait = db.recovery_mail_wait("uann".into()).await.unwrap();
    assert!(wait.is_some_and(|w| w > 0), "{wait:?}");
    let made = db.create_password_reset("ann".into(), "in3".into(), "h3".into(), now() + 600).await.unwrap();
    assert!(made.is_none(), "and no self-service mail either");
    // Unmailed, the link is made as ever.
    let made = db.create_reset_link("in4".into(), "h4".into(), "uann".into(), None, now() + 600, false).await.unwrap();
    assert_eq!(made.unwrap().email, None);
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
