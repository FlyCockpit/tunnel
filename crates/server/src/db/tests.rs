use super::*;

fn temp_db() -> (Db, std::path::PathBuf) {
    let path = std::env::temp_dir()
        .join("tunnel-db-tests")
        .join(format!("tunnel-test-{}.db", crate::tokens::random_tunnel_id()));
    let db = Db::open(&path).unwrap();
    // Clients belong to a user; tests share one member with generous quotas.
    db.conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO users (id, username, password_hash, role, limit_tunnels, limit_clients, created_at)
             VALUES ('utest', 'tester', 'x', 'member', 1000, 1000, 0)",
            [],
        )
        .unwrap();
    (db, path)
}

fn password_access(hash: &str) -> Access {
    Access { mode: AccessMode::Password, password_user: Some("ann".into()), password_hash: Some(hash.into()) }
}

async fn has_grant(db: &Db, session_id: &str, tunnel: &str) -> bool {
    let hash = crate::tokens::hash_token(session_id);
    let grants = db.session_grants(vec![hash.clone()]).await.unwrap();
    grants.get(&hash).is_some_and(|g| g.iter().any(|(t, _)| t == tunnel))
}

fn granted(r: Option<Redemption>) -> String {
    match r {
        Some(Redemption::Granted { session_id, .. }) => session_id,
        other => panic!("expected a grant, got {other:?}"),
    }
}

struct TestDir(std::path::PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn isolated_db() -> (Db, TestDir) {
    let dir = TestDir(std::env::temp_dir().join("tunnel-db-tests").join(crate::tokens::random_tunnel_id()));
    let db = Db::open(&dir.0.join("state.db")).unwrap();
    (db, dir)
}

async fn create_password_tunnel(db: &Db, id: &str) {
    db.create_tunnel(
        NewTunnel {
            id: id.into(),
            token_hash: format!("test-{id}"),
            label: None,
            name: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 86_400,
            access: password_access("h1"),
            client_id: None,
        },
        20,
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn copied_login_provenance_keeps_longest_expiry_in_either_order() {
    let (db, _dir) = isolated_db();
    create_password_tunnel(&db, "sourceaaaa").await;
    create_password_tunnel(&db, "targetaaaa").await;
    let mut hashes = Vec::new();
    for ttl in [60, 3600] {
        let session = granted(db.login_grant("sourceaaaa".into(), "h1".into(), ttl, vec![]).await.unwrap());
        hashes.push(crate::tokens::hash_token(&session));
    }
    let expected = db.session_grants(vec![hashes[1].clone()]).await.unwrap()[&hashes[1]][0].1;
    for presented in [hashes.clone(), hashes.into_iter().rev().collect()] {
        let merged = granted(db.login_grant("targetaaaa".into(), "h1".into(), 7200, presented).await.unwrap());
        let hash = crate::tokens::hash_token(&merged);
        let provenance: i64 = db
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT expires_at FROM gate_grant_logins WHERE session_hash = ?1 AND tunnel_id = 'sourceaaaa'",
                    params![hash],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(provenance, expected);
    }
}

#[tokio::test]
async fn omitted_password_preserves_transaction_hash_and_login_grants() {
    let (db, _dir) = isolated_db();
    let id = "preserveaa".to_string();
    create_password_tunnel(&db, &id).await;
    // A partial PATCH was prepared while h1 was current, then a different
    // PATCH rotated the password before the partial PATCH committed.
    let mut partial = password_access("h1");
    partial.password_user = Some("beth".into());
    let patch = TunnelPatch { access: Some(partial), keep_password_hash: true, ..Default::default() };
    db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
        .await
        .unwrap();
    let session = granted(db.login_grant(id.clone(), "h2".into(), 3600, vec![]).await.unwrap());
    let updated = db.update_tunnel(id.clone(), patch).await.unwrap().unwrap();
    assert_eq!(updated.row.access.password_hash.as_deref(), Some("h2"));
    assert_eq!(updated.row.access.password_user.as_deref(), Some("beth"));
    assert!(updated.access_changed);
    assert!(!updated.grants_changed, "username-only changes keep grants and gate epochs");
    assert!(has_grant(&db, &session, &id).await, "preserving the hash must not revoke logins");
    let unchanged = db
        .update_tunnel(
            id.clone(),
            TunnelPatch {
                access: Some(Access { password_hash: None, ..updated.row.access }),
                keep_password_hash: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!unchanged.access_changed);
    assert!(has_grant(&db, &session, &id).await);
}

#[tokio::test]
async fn omitted_password_cannot_restore_password_after_mode_change() {
    let (db, _dir) = isolated_db();
    let id = "modechange".to_string();
    create_password_tunnel(&db, &id).await;
    db.update_tunnel(id.clone(), TunnelPatch { access: Some(Access::default()), ..Default::default() }).await.unwrap();
    let error = db
        .update_tunnel(
            id.clone(),
            TunnelPatch {
                access: Some(password_access("h1")),
                keep_password_hash: true,
                label: Some("must roll back".into()),
                ..Default::default()
            },
        )
        .await
        .err()
        .expect("an omitted password cannot resurrect the earlier hash");
    assert!(error.is::<PasswordRequired>());
    let row = db.get_tunnel(id).await.unwrap().unwrap();
    assert_eq!(row.access, Access::default());
    assert!(row.label.is_none());
}

#[tokio::test]
async fn reusable_link_provenance_keeps_longest_redemption_and_copy() {
    let (db, _dir) = isolated_db();
    let id = "provenance".to_string();
    create_password_tunnel(&db, &id).await;
    db.create_access_link(NewAccessLink {
        id: "reusable".into(),
        tunnel_id: id.clone(),
        token_hash: "test-link".into(),
        single_use: false,
        label: None,
        owner_port: None,
        session_ttl_s: 60,
        expires_at: now() + 3600,
    })
    .await
    .unwrap();
    let short = granted(Some(
        db.redeem_access_link(id.clone(), "test-link".into(), vec![], None, String::new()).await.unwrap(),
    ));
    // Deterministically model a later redemption with a longer expiry.
    db.call(|c| {
        c.execute("UPDATE access_links SET session_ttl_s = 600 WHERE id = 'reusable'", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let long = granted(Some(
        db.redeem_access_link(
            id.clone(),
            "test-link".into(),
            vec![crate::tokens::hash_token(&short)],
            None,
            String::new(),
        )
        .await
        .unwrap(),
    ));
    let long_hash = crate::tokens::hash_token(&long);
    let expected = db.session_grants(vec![long_hash.clone()]).await.unwrap()[&long_hash][0].1;
    let provenance: i64 = db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT expires_at FROM gate_grant_links WHERE session_hash = ?1 AND link_id = 'reusable'",
                params![long_hash],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(provenance, expected, "re-redeeming must extend copied provenance");
    let mut merged = Vec::new();
    // Overlapping carried sessions must keep the maximum in either order.
    for sessions in [[&short, &long], [&long, &short]] {
        merged.push(granted(
            db.login_grant(id.clone(), "h1".into(), 7200, sessions.map(|s| crate::tokens::hash_token(s)).to_vec())
                .await
                .unwrap(),
        ));
    }
    db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
        .await
        .unwrap();
    for session in merged {
        let hash = crate::tokens::hash_token(&session);
        let expiry = db.session_grants(vec![hash.clone()]).await.unwrap()[&hash][0].1;
        assert_eq!(expiry, expected, "rotation must cap at the longest link provenance");
    }
}

#[tokio::test]
async fn password_change_revokes_only_login_grants() {
    let (db, path) = temp_db();
    let id = "t1aaaaaaaa".to_string();
    db.create_tunnel(
        NewTunnel {
            id: id.clone(),
            token_hash: "tok".into(),
            label: None,
            name: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 3600,
            access: password_access("h1"),
            client_id: None,
        },
        20,
    )
    .await
    .unwrap();
    db.create_access_link(NewAccessLink {
        id: "al1".into(),
        tunnel_id: id.clone(),
        token_hash: "link".into(),
        single_use: false,
        label: None,
        owner_port: None,
        session_ttl_s: 3600,
        expires_at: now() + 600,
    })
    .await
    .unwrap();

    // Link session; then a login that carries it (both provenances); then a login-only session.
    let s_link =
        granted(Some(db.redeem_access_link(id.clone(), "link".into(), vec![], None, String::new()).await.unwrap()));
    let s_both =
        granted(db.login_grant(id.clone(), "h1".into(), 3600, vec![crate::tokens::hash_token(&s_link)]).await.unwrap());
    let s_login = granted(db.login_grant(id.clone(), "h1".into(), 3600, vec![]).await.unwrap());
    assert!(db.login_grant(id.clone(), "wrong".into(), 3600, vec![]).await.unwrap().is_none());
    for s in [&s_link, &s_both, &s_login] {
        assert!(has_grant(&db, s, &id).await);
    }

    // New password: the login-only session is out; link-backed ones stay; the old hash no longer logs in.
    db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
        .await
        .unwrap();
    assert!(!has_grant(&db, &s_login, &id).await);
    assert!(has_grant(&db, &s_both, &id).await);
    assert!(has_grant(&db, &s_link, &id).await);
    assert!(db.login_grant(id.clone(), "h1".into(), 3600, vec![]).await.unwrap().is_none());

    // Same password again changes nothing; leaving password mode revokes new logins and blocks more.
    let s_login2 = granted(db.login_grant(id.clone(), "h2".into(), 3600, vec![]).await.unwrap());
    db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
        .await
        .unwrap();
    assert!(has_grant(&db, &s_login2, &id).await);
    db.update_tunnel(id.clone(), TunnelPatch { access: Some(Access::default()), ..Default::default() }).await.unwrap();
    assert!(!has_grant(&db, &s_login2, &id).await);
    assert!(has_grant(&db, &s_link, &id).await);
    assert!(db.login_grant(id.clone(), "h2".into(), 3600, vec![]).await.unwrap().is_none());
    let row = db.get_tunnel(id.clone()).await.unwrap().unwrap();
    assert_eq!(row.access, Access::default());

    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn client_enrollment_and_delete() {
    let (db, path) = temp_db();
    assert!(
        db.create_client("c1".into(), "laptop".into(), "utest".into(), "code".into(), now() + 900, None)
            .await
            .unwrap()
            .is_ok()
    );
    assert!(
        db.create_client("c2".into(), "laptop".into(), "utest".into(), "code2".into(), now() + 900, None)
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        db.create_client("c3".into(), "old".into(), "utest".into(), "stale".into(), now() - 1, None)
            .await
            .unwrap()
            .is_ok()
    );

    assert!(db.enroll_client("wrong".into(), "t".into()).await.unwrap().is_none());
    assert!(db.enroll_client("stale".into(), "t".into()).await.unwrap().is_none(), "expired code");
    assert_eq!(db.enroll_client("code".into(), "tok".into()).await.unwrap().as_deref(), Some("laptop"));
    assert!(db.enroll_client("code".into(), "tok2".into()).await.unwrap().is_none(), "single use");
    assert_eq!(db.client_by_token_hash("tok".into()).await.unwrap().map(|c| c.id).as_deref(), Some("c1"));

    let mk = |id: &str, client: Option<&str>| NewTunnel {
        id: id.into(),
        token_hash: format!("tt-{id}"),
        label: None,
        name: None,
        metadata: None,
        max_ports: 8,
        host_header: HostHeaderMode::Rewrite,
        inject_ice: false,
        expires_at: now() + 3600,
        access: Access::default(),
        client_id: client.map(str::to_string),
    };
    db.create_tunnel(mk("own1aaaaaa", Some("c1")), 20).await.unwrap();
    db.create_tunnel(mk("adm1aaaaaa", None), 20).await.unwrap();
    assert_eq!(db.list_tunnels_page(Some("c1".into()), None, None, 500).await.unwrap().len(), 1);
    let listed = db.list_clients().await.unwrap();
    let laptop = listed.iter().find(|c| c.name == "laptop").unwrap();
    assert!(laptop.enrolled && laptop.tunnels == 1);
    assert!(!listed.iter().find(|c| c.name == "old").unwrap().enrolled);

    assert_eq!(db.delete_client("laptop".into()).await.unwrap(), Some(vec!["own1aaaaaa".to_string()]));
    assert!(db.client_by_token_hash("tok".into()).await.unwrap().is_none());
    assert!(db.get_tunnel("own1aaaaaa".into()).await.unwrap().unwrap().is_expired());
    assert!(!db.get_tunnel("adm1aaaaaa".into()).await.unwrap().unwrap().is_expired());
    assert_eq!(db.expired_tunnel_ids().await.unwrap(), vec!["own1aaaaaa".to_string()]);
    assert!(db.delete_client("laptop".into()).await.unwrap().is_none());

    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn password_change_caps_merged_grant_at_link_expiry() {
    let (db, path) = temp_db();
    let id = "t2aaaaaaaa".to_string();
    db.create_tunnel(
        NewTunnel {
            id: id.clone(),
            token_hash: "tok2".into(),
            label: None,
            name: None,
            metadata: None,
            max_ports: 8,
            host_header: HostHeaderMode::Rewrite,
            inject_ice: false,
            expires_at: now() + 86_400,
            access: password_access("h1"),
            client_id: None,
        },
        20,
    )
    .await
    .unwrap()
    .unwrap();
    db.create_access_link(NewAccessLink {
        id: "short".into(),
        tunnel_id: id.clone(),
        token_hash: "shortlink".into(),
        single_use: false,
        label: None,
        owner_port: None,
        session_ttl_s: 60,
        expires_at: now() + 600,
    })
    .await
    .unwrap();
    let s_link = granted(Some(
        db.redeem_access_link(id.clone(), "shortlink".into(), vec![], None, String::new()).await.unwrap(),
    ));
    let merged =
        granted(db.login_grant(id.clone(), "h1".into(), 7200, vec![crate::tokens::hash_token(&s_link)]).await.unwrap());
    let hash = crate::tokens::hash_token(&merged);
    let before = db.session_grants(vec![hash.clone()]).await.unwrap()[&hash][0].1;
    assert!(before > now() + 3600, "merged grant carries the login's expiry");

    db.update_tunnel(id.clone(), TunnelPatch { access: Some(password_access("h2")), ..Default::default() })
        .await
        .unwrap();
    let after = db.session_grants(vec![hash.clone()]).await.unwrap()[&hash][0].1;
    assert!(after <= now() + 60, "capped at the link's own expiry, got {}", after - now());

    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn tunnel_for_deleted_client_is_not_created() {
    let (db, path) = temp_db();
    let t = |id: &str, client: &str| NewTunnel {
        id: id.into(),
        token_hash: format!("h-{id}"),
        label: None,
        name: None,
        metadata: None,
        max_ports: 8,
        host_header: HostHeaderMode::Rewrite,
        inject_ice: false,
        expires_at: now() + 600,
        access: Access::default(),
        client_id: Some(client.into()),
    };
    assert!(db.create_tunnel(t("gone1aaaaa", "no-such-client"), 20).await.unwrap().is_none());
    db.create_client("cx".into(), "x".into(), "utest".into(), "c".into(), now() + 60, None).await.unwrap().unwrap();
    assert!(db.create_tunnel(t("live1aaaaa", "cx"), 20).await.unwrap().is_some());
    db.delete_client("x".into()).await.unwrap();
    assert!(db.create_tunnel(t("late1aaaaa", "cx"), 20).await.unwrap().is_none());
    let indexes: i64 = db
        .call(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('tunnels_expires_at', 'tunnels_client')",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(indexes, 2);
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn service_quota_counts_live_tunnels_and_delete_expires_them() {
    let (db, path) = temp_db();
    db.create_service("sv1".into(), "wssp".into(), "svc-hash".into(), 2).await.unwrap().unwrap();
    assert!(db.create_service("sv2".into(), "wssp".into(), "other".into(), 2).await.unwrap().is_none());
    assert_eq!(db.service_by_token_hash("svc-hash".into()).await.unwrap(), Some(("sv1".into(), "wssp".into())));
    // The client default (1 here) does not apply to services.
    db.create_tunnel(new_tunnel("aaaaaaaaaa", Some("sv1"), now() + 600), 1).await.unwrap().unwrap();
    db.create_tunnel(new_tunnel("bbbbbbbbbb", Some("sv1"), now() - 1), 1).await.unwrap().unwrap();
    db.create_tunnel(new_tunnel("cccccccccc", Some("sv1"), now() + 600), 1).await.unwrap().unwrap();
    let over = db.create_tunnel(new_tunnel("dddddddddd", Some("sv1"), now() + 600), 1).await;
    assert!(over.unwrap_err().is::<TunnelQuotaExceeded>());
    assert!(db.set_service_quota("wssp".into(), 3).await.unwrap());
    db.create_tunnel(new_tunnel("dddddddddd", Some("sv1"), now() + 600), 1).await.unwrap().unwrap();
    let listed = db.list_services(None, None).await.unwrap();
    assert_eq!((listed[0].max_tunnels, listed[0].tunnels), (3, 3));

    let mut ended = db.delete_service("wssp".into()).await.unwrap().unwrap();
    ended.sort();
    assert_eq!(ended, ["aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "dddddddddd"]);
    assert!(db.get_tunnel("aaaaaaaaaa".into()).await.unwrap().unwrap().is_expired());
    assert!(db.service_by_token_hash("svc-hash".into()).await.unwrap().is_none());
    assert!(db.create_tunnel(new_tunnel("eeeeeeeeee", Some("sv1"), now() + 600), 1).await.unwrap().is_none());
    assert!(db.delete_service("wssp".into()).await.unwrap().is_none());
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn public_and_lifetime_rules_use_the_owners_current_permissions() {
    let (db, path) = temp_db();
    db.create_client("c1".into(), "laptop".into(), "utest".into(), "code".into(), now() + 900, None)
        .await
        .unwrap()
        .unwrap();
    let defaults =
        crate::limits::Defaults::new(&crate::config::Limits { member_max_tunnel_ttl_s: 3600, ..Default::default() });
    let policy = Policy { allow_all_public: false, defaults };
    let public = Access { mode: AccessMode::Public, password_user: None, password_hash: None };
    let mut t = new_tunnel("aaaaaaaaaa", Some("c1"), now() + 600);
    t.access = public.clone();
    let refused = db.create_tunnel_with(t, 20, policy).await;
    assert!(refused.err().unwrap().is::<PublicNotAllowed>(), "a member without can_public");
    let long = db.create_tunnel_with(new_tunnel("bbbbbbbbbb", Some("c1"), now() + 7200), 20, policy).await;
    assert!(long.err().unwrap().is::<TtlTooLong>());
    db.create_tunnel_with(new_tunnel("aaaaaaaaaa", Some("c1"), now() + 600), 20, policy).await.unwrap().unwrap();
    let patch = |access: Access| TunnelPatch {
        label: Some("changed".into()),
        access: Some(access),
        owner_policy: Some(("c1".into(), policy)),
        ..TunnelPatch::default()
    };
    let refused = db.update_tunnel("aaaaaaaaaa".into(), patch(public.clone())).await;
    assert!(refused.err().unwrap().is::<PublicNotAllowed>());
    let row = db.get_tunnel("aaaaaaaaaa".into()).await.unwrap().unwrap();
    assert_eq!((row.access.mode, row.label), (AccessMode::Link, None), "nothing of a refused patch is applied");
    let extend = TunnelPatch {
        expires_at: Some(now() + 7200),
        owner_policy: Some(("c1".into(), policy)),
        ..TunnelPatch::default()
    };
    assert!(db.update_tunnel("aaaaaaaaaa".into(), extend).await.err().unwrap().is::<TtlTooLong>());
    // Permission granted meanwhile: the same patch now passes.
    db.call(|c| {
        c.execute("UPDATE users SET can_public = 1 WHERE id = 'utest'", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let switched = db.update_tunnel("aaaaaaaaaa".into(), patch(public.clone())).await.unwrap().unwrap();
    assert_eq!(switched.row.access.mode, AccessMode::Public);
    // Revoked again: an already public tunnel stays editable.
    db.call(|c| {
        c.execute("UPDATE users SET can_public = 0 WHERE id = 'utest'", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let kept = db.update_tunnel("aaaaaaaaaa".into(), patch(public)).await.unwrap().unwrap();
    assert_eq!(kept.row.access.mode, AccessMode::Public);
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn tunnel_token_rotates_only_while_unexpired() {
    let (db, path) = temp_db();
    db.create_tunnel(new_tunnel("aaaaaaaaaa", None, now() + 600), 1).await.unwrap().unwrap();
    db.create_tunnel(new_tunnel("bbbbbbbbbb", None, now() - 1), 1).await.unwrap().unwrap();
    assert!(db.rotate_tunnel_token("aaaaaaaaaa".into(), "new-hash".into()).await.unwrap());
    assert_eq!(db.tunnel_token_state("aaaaaaaaaa".into()).await.unwrap().unwrap().0, "new-hash");
    assert!(db.find_tunnel_by_token_hash("hash-aaaaaaaaaa".into()).await.unwrap().is_none());
    assert!(!db.rotate_tunnel_token("bbbbbbbbbb".into(), "x".into()).await.unwrap());
    assert!(!db.rotate_tunnel_token("zzzzzzzzzz".into(), "y".into()).await.unwrap());
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

fn new_tunnel(id: &str, client_id: Option<&str>, expires_at: i64) -> NewTunnel {
    NewTunnel {
        id: id.into(),
        token_hash: format!("hash-{id}"),
        label: None,
        name: None,
        metadata: None,
        max_ports: 8,
        host_header: HostHeaderMode::Rewrite,
        inject_ice: false,
        expires_at,
        access: Access::default(),
        client_id: client_id.map(str::to_string),
    }
}

#[tokio::test]
async fn tunnel_quota_boundary_expiry_deletion_and_admin_exemption() {
    let (db, path) = temp_db();
    db.create_client("client".into(), "client".into(), "utest".into(), "code".into(), now() + 600, None)
        .await
        .unwrap()
        .unwrap();
    let denied = db.create_tunnel(new_tunnel("zero", Some("client"), now() + 600), 0).await.unwrap_err();
    assert!(denied.is::<TunnelQuotaExceeded>());
    db.create_tunnel(new_tunnel("expired", Some("client"), now()), 1).await.unwrap().unwrap();
    db.create_tunnel(new_tunnel("live", Some("client"), now() + 600), 1).await.unwrap().unwrap();
    let denied = db.create_tunnel(new_tunnel("denied", Some("client"), now() + 600), 1).await.unwrap_err();
    assert!(denied.is::<TunnelQuotaExceeded>());
    assert!(db.get_tunnel("denied".into()).await.unwrap().is_none());
    db.create_tunnel(new_tunnel("admin1", None, now() + 600), 0).await.unwrap().unwrap();
    db.create_tunnel(new_tunnel("admin2", None, now() + 600), 0).await.unwrap().unwrap();
    db.delete_tunnel("live".into()).await.unwrap();
    db.create_tunnel(new_tunnel("replacement", Some("client"), now() + 600), 1).await.unwrap().unwrap();
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[tokio::test]
async fn concurrent_connections_cannot_exceed_tunnel_quota() {
    let (db, path) = temp_db();
    db.create_client("client".into(), "client".into(), "utest".into(), "code".into(), now() + 600, None)
        .await
        .unwrap()
        .unwrap();
    let other = Db::open(&path).unwrap();
    let mut pending = Vec::new();
    for i in 0..12 {
        let conn = if i % 2 == 0 { db.clone() } else { other.clone() };
        pending.push(tokio::spawn(async move {
            conn.create_tunnel(new_tunnel(&format!("concurrent-{i}"), Some("client"), now() + 600), 3).await
        }));
    }
    let mut inserted = 0;
    for task in pending {
        match task.await.unwrap() {
            Ok(Some(_)) => inserted += 1,
            Err(e) => assert!(e.is::<TunnelQuotaExceeded>()),
            Ok(None) => panic!("client still exists"),
        }
    }
    assert_eq!(inserted, 3);
    assert_eq!(db.list_tunnels_page(Some("client".into()), None, None, 500).await.unwrap().len(), 3);
    drop(other);
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[test]
fn fresh_schema_is_versioned_and_reopens() {
    let (db, path) = temp_db();
    {
        let conn = db.conn.lock().unwrap();
        let version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        for table in ["gate_grant_links", "gate_grant_logins"] {
            let required: bool = conn
                .query_row(
                    &format!("SELECT [notnull] FROM pragma_table_info('{table}') WHERE name = 'expires_at'"),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(required);
        }
        conn.execute("INSERT INTO clients (id, name, created_at, user_id) VALUES ('c1', 'saved', 1, 'utest')", [])
            .unwrap();
    }
    drop(db);
    let reopened = Db::open(&path).unwrap();
    assert_eq!(
        reopened.conn.lock().unwrap().query_row("SELECT name FROM clients", [], |r| r.get::<_, String>(0)).unwrap(),
        "saved"
    );
    drop(reopened);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

#[test]
fn concurrent_first_opens_of_a_new_file_all_succeed() {
    let dir = std::env::temp_dir().join("tunnel-db-tests");
    std::fs::create_dir_all(&dir).unwrap();
    for _ in 0..20 {
        let path = dir.join(format!("first-open-{}.db", crate::tokens::random_tunnel_id()));
        let start = Arc::new(std::sync::Barrier::new(8));
        let opens: Vec<_> = (0..8)
            .map(|_| {
                let (path, start) = (path.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    Db::open(&path).map(drop).map_err(|e| format!("{e:#}"))
                })
            })
            .collect();
        for open in opens {
            open.join().unwrap().unwrap();
        }
        let c = Connection::open(&path).unwrap();
        assert_eq!(c.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0)).unwrap(), SCHEMA_VERSION);
        drop(c);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}

#[test]
fn refuses_a_database_with_another_schema_version_and_adds_nothing() {
    let path = std::env::temp_dir()
        .join("tunnel-db-tests")
        .join(format!("other-version-{}.db", crate::tokens::random_tunnel_id()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(&path).unwrap().execute_batch("CREATE TABLE tunnels (id TEXT PRIMARY KEY)").unwrap();
    let schema = |c: &Connection| -> Vec<String> {
        let mut q = c.prepare("SELECT name FROM sqlite_schema ORDER BY name").unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    let before = schema(&Connection::open(&path).unwrap());
    for version in [0, SCHEMA_VERSION + 1] {
        Connection::open(&path).unwrap().pragma_update(None, "user_version", version).unwrap();
        let err = Db::open(&path).err().expect("refused").to_string();
        assert_eq!(
            err,
            format!("unsupported database schema version {version}; this build needs schema version {SCHEMA_VERSION}")
        );
        let c = Connection::open(&path).unwrap();
        assert_eq!(schema(&c), before, "a refused database gains nothing");
        assert_eq!(c.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0)).unwrap(), version);
    }
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
