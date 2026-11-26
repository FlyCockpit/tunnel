//! Small, unbranded status pages served by the edge.

use std::sync::LazyLock;

use base64::Engine as _;
use http::header::{self, HeaderName};
use http::{Response, StatusCode};

use crate::util::{Body, full};

/// The Tunnel logo with a padlock badge (`assets/gate-icon.svg`, with a 32px
/// PNG for browsers without SVG icons; `assets/make-gate-icon.py` makes
/// both). Inline, so these pages never make the browser ask a preview origin
/// (or anything else) for `/favicon.ico`.
const ICON_SVG: &[u8] = include_bytes!("../../assets/gate-icon.svg");
const ICON_PNG: &[u8] = include_bytes!("../../assets/gate-icon-32.png");

/// `<link rel="icon">` tags for [`ICON_PNG`] and [`ICON_SVG`] (the SVG last,
/// so browsers that support it prefer it).
static ICON_LINKS: LazyLock<String> = LazyLock::new(|| {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    format!(
        r#"<link rel="icon" type="image/png" sizes="32x32" href="data:image/png;base64,{}"><link rel="icon" type="image/svg+xml" sizes="any" href="data:image/svg+xml;base64,{}">"#,
        b64(ICON_PNG),
        b64(ICON_SVG)
    )
});

/// What every page here allows: its inline style and the inline icon.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

/// The web UI's viewport scale (crates/web/style/app.css, template rule
/// V1): the browser default up to a 1920px long side, then up to 150% at
/// 3840, so these pages are as legible on a 4K screen as the UI.
const SCALE: &str = "html{font-size:clamp(100%,calc(100% + (max(100vw,100vh) - 1920px) / 240),150%)}";

/// The web UI's neutral colours (crates/web/style/tokens.css: --background,
/// --foreground, --muted-foreground, --input, --destructive). These pages are
/// on other origins and cannot see the UI's light/dark choice, so they follow
/// the system, native controls and scrollbars included.
const PALETTE: &str = ":root{color-scheme:light dark;--bg:oklch(1 0 0);--fg:oklch(0.148 0.004 228.8);\
--muted:oklch(0.54 0.021 213.5);--line:oklch(0.925 0.005 214.3);--err:oklch(0.464 0.245 27.325)}\
@media (prefers-color-scheme:dark){:root{--bg:oklch(0.148 0.004 228.8);--fg:oklch(0.987 0.002 197.1);\
--muted:oklch(0.723 0.014 214.4);--line:oklch(1 0 0 / 15%);--err:oklch(0.867 0.191 22.216)}}";

fn page(status: StatusCode, title: &str, message: &str, retry_after: Option<u32>) -> Response<Body> {
    // A meta refresh lets the offline pages recover on their own once the
    // sandbox (re)connects, including inside an embedding iframe.
    let refresh = match retry_after {
        Some(s) if status.is_server_error() => format!(r#"<meta http-equiv="refresh" content="{s}">"#),
        _ => String::new(),
    };
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="color-scheme" content="light dark">{refresh}<title>{title}</title>{icon}
<style>{PALETTE}{SCALE}body{{margin:0;min-height:100vh;display:grid;place-items:center;font:1rem/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg)}}main{{max-width:30rem;padding:1.5rem;text-align:center}}h1{{margin:0 0 .5rem;font-size:1.25rem}}p{{margin:0;color:var(--muted)}}</style></head>
<body><main><h1>{title}</h1><p>{message}</p></main></body></html>
"#,
        icon = ICON_LINKS.as_str(),
    );
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-robots-tag"), "noindex")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::CONTENT_SECURITY_POLICY, CSP);
    if let Some(s) = retry_after {
        builder = builder.header(header::RETRY_AFTER, s.to_string());
    }
    builder.body(full(html)).expect("valid response")
}

/// Minimal HTML escaping for text and attribute values.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Where a login form sends the visitor, and who may frame it.
pub struct LoginTarget<'a> {
    /// Preview label (`{port}-{id}`) to sign in to.
    pub to: &'a str,
    /// Path on that preview to continue to (already sanitized).
    pub next: &'a str,
    /// `https://{to}.{zone}`: the form's redirect target, allowed by `form-action`.
    pub preview_origin: &'a str,
    /// `frame-ancestors` sources (see `headers::frame_sources`).
    pub frame_sources: &'a [String],
}

/// Login form for a password-protected preview, served on the zone host
/// (never on a preview origin, whose service workers the app controls).
/// Posts to `/__login` on the same host and works inside an iframe.
pub fn login(status: StatusCode, target: &LoginTarget<'_>, error: Option<&str>) -> Response<Body> {
    let error = error.map(|e| format!(r#"<p class="err" role="alert">{}</p>"#, escape(e))).unwrap_or_default();
    let html = format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="color-scheme" content="light dark"><title>Sign in</title>{icon}
<style>{PALETTE}{SCALE}body{{margin:0;min-height:100vh;display:grid;place-items:center;font:1rem/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg)}}main{{width:100%;max-width:20rem;padding:1.5rem;box-sizing:border-box}}h1{{margin:0 0 1rem;font-size:1.25rem}}label{{display:block;margin:.75rem 0 .25rem;font-size:.875rem;color:var(--muted)}}input{{width:100%;min-height:44px;box-sizing:border-box;padding:.5rem .625rem;font:inherit;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit}}button{{margin-top:1rem;width:100%;min-height:44px;padding:.55rem;font:inherit;font-weight:600;border:0;border-radius:6px;background:var(--fg);color:var(--bg);cursor:pointer}}.err{{margin:0 0 .5rem;color:var(--err);font-size:.875rem}}</style></head>
<body><main><h1>Sign in to view this preview</h1>{error}
<form method="post" action="/__login"><input type="hidden" name="to" value="{to}"><input type="hidden" name="next" value="{next}">
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form></main></body></html>
"#,
        to = escape(target.to),
        next = escape(target.next),
        icon = ICON_LINKS.as_str(),
    );
    // `form-action` also governs the redirect after a successful POST.
    let csp = format!(
        "{CSP}; form-action 'self' {}; frame-ancestors {}",
        target.preview_origin,
        target.frame_sources.join(" ")
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-robots-tag"), "noindex")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::CONTENT_SECURITY_POLICY, csp)
        .body(full(html))
        .expect("valid response")
}

/// A `302` to `location` that leaks nothing in `Referer`.
pub fn redirect(location: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(crate::util::empty())
        .unwrap_or_else(|_| not_found())
}

/// A sign-in form that could not be read (too large, wrong type).
pub fn bad_form(status: StatusCode, message: &str) -> Response<Body> {
    page(status, "Sign-in failed", &escape(message), None)
}

pub fn not_found() -> Response<Body> {
    page(StatusCode::NOT_FOUND, "Not found", "There is no preview at this address.", None)
}

/// Deliberately generic: never says whether a link was unknown, used, or expired.
pub fn unauthorized() -> Response<Body> {
    page(StatusCode::UNAUTHORIZED, "Access required", "Open this preview from the link you were given.", None)
}

/// A password-protected preview asked for by something other than a page
/// load (curl, `fetch`, an agent), which gets no redirect: say where to sign
/// in. JSON when the client asks for it. Names no secret.
pub fn password_required(login_url: &str, json: bool) -> Response<Body> {
    const MESSAGE: &str = "This preview is password protected. Sign in in a browser at the login URL, then open it.";
    if !json {
        let url = escape(login_url);
        let message = format!(
            r#"This preview is password protected. <a href="{url}">Sign in</a> at <code>{url}</code>, then open it."#
        );
        return page(StatusCode::UNAUTHORIZED, "Sign-in required", &message, None);
    }
    let body = serde_json::json!({ "error": "password_required", "message": MESSAGE, "login_url": login_url });
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-robots-tag"), "noindex")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(full(body.to_string()))
        .expect("valid response")
}

/// A gated WebSocket or write started by an untrusted origin (see `edge`).
pub fn forbidden_origin() -> Response<Body> {
    page(StatusCode::FORBIDDEN, "Blocked", "This preview does not accept requests from this origin.", None)
}

pub fn gateway_timeout() -> Response<Body> {
    page(
        StatusCode::GATEWAY_TIMEOUT,
        "App did not respond",
        "The app accepted the request but did not answer in time.",
        None,
    )
}

pub fn busy() -> Response<Body> {
    page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many open requests",
        "This preview has too many requests in progress. This page retries every few seconds.",
        Some(5),
    )
}

/// Too many visitor lookups in flight server-wide (see `state`).
pub fn server_busy() -> Response<Body> {
    page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Server busy",
        "The server is handling too many requests. This page retries every few seconds.",
        Some(5),
    )
}

/// The owner's account reached its monthly traffic cap (see `traffic`).
pub fn traffic_limit() -> Response<Body> {
    page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Traffic limit reached",
        "The account sharing this preview has used its traffic for this month. It works again next month, or once the server's admin raises the limit.",
        None,
    )
}

pub fn ended() -> Response<Body> {
    page(StatusCode::GONE, "Preview ended", "This preview has been stopped or has expired.", None)
}

pub fn offline() -> Response<Body> {
    page(
        StatusCode::BAD_GATEWAY,
        "Preview offline",
        "The preview is not connected right now. This page retries every few seconds.",
        Some(5),
    )
}

/// A link was redeemed but the tunnel has no connected port to go to yet.
pub fn offline_signed_in() -> Response<Body> {
    page(
        StatusCode::OK,
        "Signed in",
        "The preview is not connected yet. Open it from its preview address once it is running.",
        None,
    )
}

pub fn app_not_running(port: u16) -> Response<Body> {
    let message =
        format!("Nothing is listening on port {port} in the sandbox yet. This page retries every few seconds.");
    page(StatusCode::BAD_GATEWAY, "App not running", &message, Some(5))
}

pub fn bad_gateway() -> Response<Body> {
    page(StatusCode::BAD_GATEWAY, "Bad gateway", "The app closed the connection without a valid response.", None)
}

pub fn rate_limited() -> Response<Body> {
    page(StatusCode::TOO_MANY_REQUESTS, "Too many attempts", "Wait a minute and try again.", Some(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The icon is the web UI's logo with a badge: regenerate it
    /// (`assets/make-gate-icon.py`) when the logo changes.
    #[test]
    fn the_gate_icon_embeds_the_current_logo() {
        let logo = include_bytes!("../../../web/static/logo-64.png");
        let svg = std::str::from_utf8(ICON_SVG).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(logo);
        assert!(svg.contains(&format!(r#"href="data:image/png;base64,{encoded}""#)));
        assert!(ICON_PNG.starts_with(b"\x89PNG"));
    }

    #[test]
    fn every_page_has_the_icon_and_its_policy() {
        for response in
            [not_found(), unauthorized(), rate_limited(), offline(), bad_form(StatusCode::PAYLOAD_TOO_LARGE, "<x>")]
        {
            assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], CSP);
        }
        assert!(ICON_LINKS.contains("data:image/svg+xml;base64,"));
        assert!(ICON_LINKS.contains("data:image/png;base64,"));
    }

    /// Light and dark follow the system, in the web UI's colours.
    #[tokio::test]
    async fn every_page_follows_the_system_theme_in_the_ui_colours() {
        use http_body_util::BodyExt as _;
        let target =
            LoginTarget { to: "3000-x", next: "/", preview_origin: "https://3000-x.t.test", frame_sources: &[] };
        for response in [not_found(), offline(), login(StatusCode::OK, &target, None)] {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(html.contains(r#"<meta name="color-scheme" content="light dark">"#), "{html}");
            assert!(html.contains(PALETTE), "{html}");
            assert!(html.contains(&format!("{SCALE}body{{")), "{html}");
        }
        // The same scale as the web UI's root rule.
        let app = include_str!("../../../web/style/app.css");
        let squash = |s: &str| s.split_whitespace().collect::<String>();
        let scale = SCALE.strip_prefix("html{font-size:").and_then(|s| s.strip_suffix('}')).unwrap();
        assert!(
            squash(app).contains(&format!("html{{font-size:{};}}", squash(scale))),
            "app.css has another root scale"
        );
        let tokens = include_str!("../../../web/style/tokens.css");
        let colours: Vec<_> = PALETTE.split("oklch(").skip(1).map(|c| &c[..c.find(')').unwrap()]).collect();
        assert_eq!(colours.len(), 10);
        for c in colours {
            assert!(tokens.contains(&format!("oklch({c})")), "oklch({c}) is not a UI token");
        }
    }
}
