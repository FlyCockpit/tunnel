//! Deliveries against the fake server: content and headers, the TLS modes,
//! and a named failing step for every class of error a local test can make.

use super::fake::{FakeSmtp, Script};
use super::*;
use crate::config::smtp::Security;

fn smtp(port: u16) -> SmtpConfig {
    SmtpConfig { host: "localhost".into(), port, user: None, pass: None, from: "Tunnel <tunnel@example.com>".into() }
}

fn mailer(cfg: SmtpConfig, server: &FakeSmtp) -> Mailer {
    Mailer::new(cfg, "ui.example.com".into()).with_root(server.root.clone())
}

fn mail() -> Mail {
    Mail {
        subject: "Hello ünïcode".into(),
        body: "Line one\nhttps://ui.example.com/invite#tninv_abc\n".into(),
        expires_at: None,
    }
}

/// Deliver with an explicit security mode (the port decides it in real use).
async fn deliver_as(
    server: &FakeSmtp,
    security: Security,
    creds: Option<(&str, &str)>,
) -> Result<Vec<Step>, SendError> {
    let roots = vec![server.root.clone()];
    let t = transport::Target {
        host: "localhost",
        port: server.port,
        security,
        credentials: creds,
        hello: "ui.example.com",
        roots: &roots,
    };
    let mut steps = Vec::new();
    let from: lettre::Address = "tunnel@example.com".parse().unwrap();
    let to: lettre::Address = "bob@example.com".parse().unwrap();
    transport::deliver(&t, &from, &to, b"Subject: x\r\n\r\nbody\r\n", &mut |s| steps.push(s)).await.map(|()| steps)
}

#[tokio::test]
async fn a_plain_local_delivery_has_the_headers_and_the_body() {
    let server = FakeSmtp::start(Script::default()).await;
    let m = mailer(smtp(server.port), &server);
    let mut steps = Vec::new();
    m.send_now("Bob@Example.com", mail(), &mut |s| steps.push(s)).await.unwrap();
    assert_eq!(steps, [Step::Dns, Step::Connect, Step::Greeting, Step::Sender, Step::Recipient, Step::Data]);
    let got = server.received();
    assert_eq!(got.len(), 1);
    let r = &got[0];
    assert_eq!((r.from.as_str(), r.to.as_str(), r.tls), ("tunnel@example.com", "bob@example.com", false));
    for header in [
        "From: Tunnel <tunnel@example.com>",
        "Auto-Submitted: auto-generated",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ] {
        assert!(r.data.contains(header), "{header} missing in {}", r.data);
    }
    assert!(r.data.contains("Message-ID: <") && r.data.contains("@ui.example.com>"));
    assert!(r.data.contains("Date: "));
    assert_eq!(r.token().as_deref(), Some("tninv_abc"));

    // A body that needs a transfer encoding (e.g. a notice naming a machine "büro") says it is MIME.
    let notice = Mail { body: "New machine: büro\n".into(), ..mail() };
    m.send_now("bob@example.com", notice, &mut |_| {}).await.unwrap();
    let r = &server.received()[1];
    let (head, _) = r.data.split_once("\r\n\r\n").unwrap();
    assert!(head.contains("MIME-Version: 1.0") && head.contains("Content-Transfer-Encoding: "), "{}", r.data);
}

#[tokio::test]
async fn starttls_and_implicit_tls_encrypt_and_sign_in() {
    let server =
        FakeSmtp::start(Script { starttls: true, auth: Some("bob:secret-pass".into()), ..Default::default() }).await;
    let steps = deliver_as(&server, Security::StartTls, Some(("bob", "secret-pass"))).await.unwrap();
    assert_eq!(
        steps,
        [Step::Dns, Step::Connect, Step::Greeting, Step::Tls, Step::Auth, Step::Sender, Step::Recipient, Step::Data]
    );
    assert!(server.received()[0].tls);

    let tls = FakeSmtp::start(Script { implicit_tls: true, ..Default::default() }).await;
    let steps = deliver_as(&tls, Security::ImplicitTls, None).await.unwrap();
    assert_eq!(steps[..3], [Step::Dns, Step::Connect, Step::Tls]);
    assert!(tls.received()[0].tls);
}

#[tokio::test]
async fn every_failure_names_its_step() {
    // connect: nothing listens on the port.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let server = FakeSmtp::start(Script::default()).await;
    let m = mailer(smtp(port), &server);
    let e = m.send_now("bob@example.com", mail(), &mut |_| {}).await.unwrap_err();
    assert_eq!(e.step, Step::Connect, "{e}");
    assert!(e.to_string().contains("connect failed") && e.to_string().contains("firewall"), "{e}");

    // TLS: implicit TLS against a plain server; STARTTLS required but not offered.
    let e = deliver_as(&server, Security::ImplicitTls, None).await.unwrap_err();
    assert_eq!(e.step, Step::Tls, "{e}");
    let e = deliver_as(&server, Security::StartTls, None).await.unwrap_err();
    assert_eq!(e.step, Step::Tls, "{e}");
    assert!(e.detail.contains("does not offer STARTTLS"), "{e}");
    // TLS: a certificate nobody trusts.
    let untrusted = FakeSmtp::start(Script { starttls: true, ..Default::default() }).await;
    let t = transport::Target {
        host: "localhost",
        port: untrusted.port,
        security: Security::StartTls,
        credentials: None,
        hello: "ui.example.com",
        roots: &[],
    };
    let (from, to): (lettre::Address, lettre::Address) =
        ("a@example.com".parse().unwrap(), "b@example.com".parse().unwrap());
    let e = transport::deliver(&t, &from, &to, b"x", &mut |_| {}).await.unwrap_err();
    assert_eq!(e.step, Step::Tls, "{e}");

    // auth: wrong password (535), and a server that offers no sign-in.
    let auth = FakeSmtp::start(Script { auth: Some("bob:right".into()), ..Default::default() }).await;
    let e = deliver_as(&auth, Security::Plain, Some(("bob", "wrong"))).await.unwrap_err();
    assert_eq!((e.step, e.code), (Step::Auth, Some(535)), "{e}");
    assert!(e.to_string().contains("app password"), "{e}");
    let e = deliver_as(&server, Security::Plain, Some(("bob", "x"))).await.unwrap_err();
    assert_eq!(e.step, Step::Auth, "{e}");

    // sender and recipient refused.
    let refusing = FakeSmtp::start(Script { refuse_sender: true, ..Default::default() }).await;
    let e = deliver_as(&refusing, Security::Plain, None).await.unwrap_err();
    assert_eq!((e.step, e.code), (Step::Sender, Some(550)), "{e}");
    let refusing = FakeSmtp::start(Script { refuse_recipient: true, ..Default::default() }).await;
    let e = deliver_as(&refusing, Security::Plain, None).await.unwrap_err();
    assert_eq!((e.step, e.code), (Step::Recipient, Some(550)), "{e}");
    assert!(refusing.received().is_empty());
}

#[tokio::test]
async fn background_sends_are_counted_until_done() {
    let server = FakeSmtp::start(Script::default()).await;
    let m = Arc::new(mailer(smtp(server.port), &server));
    for i in 0..6 {
        assert!(m.send_later("test", format!("user{i}@example.com"), mail()));
    }
    m.idle().await;
    assert_eq!(server.received().len(), 6);
    // A failing delivery is dropped, not retried, and does not block the queue.
    let dead = Arc::new(Mailer::new(smtp(1), "ui.example.com".into()));
    assert!(dead.send_later("test", "bob@example.com".into(), mail()));
    dead.idle().await;
}

#[tokio::test]
async fn the_servers_words_stay_out_of_the_logged_detail() {
    let auth = FakeSmtp::start(Script { auth: Some("bob:right".into()), ..Default::default() }).await;
    let e = deliver_as(&auth, Security::Plain, Some(("bob", "wrong"))).await.unwrap_err();
    assert_eq!(e.detail, "the server refused it (535)");
    assert!(e.reply.as_deref().is_some_and(|r| r.contains("credentials invalid")), "{e:?}");
    assert!(!e.to_string().contains("credentials invalid"), "Display (logged) has no server text: {e}");
}

#[tokio::test]
async fn a_relay_that_skips_354_gets_no_message_body() {
    let broken = FakeSmtp::start(Script { data_250: true, ..Default::default() }).await;
    let e = deliver_as(&broken, Security::Plain, None).await.unwrap_err();
    assert_eq!((e.step, e.code), (Step::Data, Some(250)), "{e}");
    assert!(e.detail.contains("unexpected reply 250"), "{e}");
    assert!(broken.received().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_silent_server_times_out_at_the_step_it_is_on() {
    let silent = FakeSmtp::start(Script { silent: true, ..Default::default() }).await;
    let e = deliver_as(&silent, Security::Plain, None).await.unwrap_err();
    assert_eq!(e.step, Step::Greeting, "{e}");
    assert!(e.detail.contains("no answer within 20 s"), "{e}");
}

#[tokio::test]
async fn an_odd_auth_reply_is_not_taken_for_a_sign_in() {
    let odd = FakeSmtp::start(Script { auth: Some("bob:x".into()), auth_354: true, ..Default::default() }).await;
    let e = deliver_as(&odd, Security::Plain, Some(("bob", "x"))).await.unwrap_err();
    assert_eq!((e.step, e.code), (Step::Auth, Some(354)), "{e}");
}

#[tokio::test(start_paused = true)]
async fn the_overall_deadline_names_the_step_under_way() {
    // Every reply takes 9 s, each step under its own 20 s: greeting + EHLO until 18 s, AUTH 27 s,
    // MAIL FROM 36 s, RCPT TO 45 s, then DATA (two replies) runs into the 60 s for the whole delivery.
    let slow = FakeSmtp::start(Script { delay_s: 9, auth: Some("bob:x".into()), ..Default::default() }).await;
    let e = deliver_as(&slow, Security::Plain, Some(("bob", "x"))).await.unwrap_err();
    assert_eq!(e.step, Step::Data, "{e}");
    assert!(e.detail.contains("in all"), "{e}");
}

#[tokio::test]
async fn a_full_job_queue_drops_jobs_before_they_run() {
    let m = Arc::new(Mailer::new(smtp(1), "ui.example.com".into()));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..100 {
        let (gate, ran) = (gate.clone(), ran.clone());
        m.run_later(async move {
            let _ = gate.acquire().await;
            ran.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
    gate.add_permits(1000);
    m.idle().await;
    let ran = ran.load(std::sync::atomic::Ordering::SeqCst);
    // One running and MAX_JOBS waiting at most; the rest were dropped without running.
    assert!((MAX_JOBS..=MAX_JOBS + 1).contains(&ran), "{ran}");
}

#[tokio::test(start_paused = true)]
async fn a_delivery_accepted_near_the_deadline_stands_without_a_quit_reply() {
    // 8 s a reply: DATA is accepted at 56 s; QUIT is never answered.
    let slow =
        FakeSmtp::start(Script { delay_s: 8, auth: Some("bob:x".into()), quit_silent: true, ..Default::default() })
            .await;
    deliver_as(&slow, Security::Plain, Some(("bob", "x"))).await.unwrap();
    assert_eq!(slow.received().len(), 1);
}

#[tokio::test]
async fn notices_never_take_more_than_their_share_of_the_queue() {
    // Nothing listens on port 1, but deliveries wait for a slot first: fill the queue from many tasks.
    let m = Arc::new(Mailer::new(smtp(1), "ui.example.com".into()));
    let mut handles = Vec::new();
    for i in 0..400 {
        let m = m.clone();
        handles.push(tokio::spawn(async move { m.queue("notice", format!("u{i}@example.com"), mail(), NOTICE_QUEUE) }));
    }
    let mut queued = 0;
    for h in handles {
        queued += usize::from(h.await.unwrap());
    }
    assert!(queued <= NOTICE_QUEUE, "{queued}");
    m.idle().await;
}

#[tokio::test]
async fn plain_smtp_never_leaves_the_machine() {
    let server = FakeSmtp::start(Script::default()).await;
    // A name or address that is not loopback, with plain security (as a `localhost`
    // that resolved elsewhere would be): refused before connecting.
    let (from, to): (lettre::Address, lettre::Address) =
        ("a@example.com".parse().unwrap(), "b@example.com".parse().unwrap());
    for host in ["0.0.0.0", "192.0.2.1"] {
        let t = transport::Target {
            host,
            port: server.port,
            security: Security::Plain,
            credentials: Some(("u", "p")),
            hello: "ui.example.com",
            roots: &[],
        };
        let e = transport::deliver(&t, &from, &to, b"x", &mut |_| {}).await.unwrap_err();
        assert_eq!(e.step, Step::Connect, "{host}: {e}");
        assert!(e.detail.contains("not a loopback address"), "{e}");
    }
    assert!(server.received().is_empty());
}

#[tokio::test]
async fn a_link_mail_that_waited_past_its_link_is_dropped() {
    let server = FakeSmtp::start(Script::default()).await;
    let m = Arc::new(mailer(smtp(server.port), &server));
    let mut stale = m.texts().password_reset("https://ui.example.com/invite#tninv_x", "ann", false, 30);
    assert!(stale.expires_at.is_some());
    assert!(m.send_later("password_reset", "ann@example.com".into(), stale));
    stale = m.texts().password_reset("https://ui.example.com/invite#tninv_y", "ann", false, 30 * 60);
    assert!(m.send_later("password_reset", "ann@example.com".into(), stale));
    m.idle().await;
    let got = server.received();
    assert_eq!(got.len(), 1, "only the one with time left");
    assert_eq!(got[0].token().as_deref(), Some("tninv_y"));
}

#[tokio::test(start_paused = true)]
async fn a_stalled_first_address_leaves_time_for_the_next() {
    let addrs: Vec<std::net::SocketAddr> = vec!["[2001:db8::1]:25".parse().unwrap(), "192.0.2.1:25".parse().unwrap()];
    let ok = transport::connect_any(&addrs, std::time::Duration::from_secs(5), |a| async move {
        if a.is_ipv6() { std::future::pending().await } else { Ok(a.port()) }
    })
    .await
    .unwrap();
    assert_eq!(ok, 25, "the IPv4 address was tried after the IPv6 one stalled");
    let none = transport::connect_any(&addrs[..1], std::time::Duration::from_secs(5), |_| {
        std::future::pending::<std::io::Result<u16>>()
    })
    .await
    .unwrap_err();
    assert!(none.detail.contains("no answer within 5 s"), "{none}");
}
