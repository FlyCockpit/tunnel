//! Shell and small components (ported from the template's header, page
//! shell, empty and error states and copy field).

use leptos::prelude::*;

use crate::api::ApiError;
use crate::{ctx, navigate, refresh_session};

/// `<a>` that navigates without a reload.
#[component]
pub fn A(
    href: &'static str,
    #[prop(optional)] class: &'static str,
    #[prop(optional, into)] title: Option<Signal<String>>,
    children: Children,
) -> impl IntoView {
    let c = ctx();
    let current = move || is_current(&c.path.get(), href).then_some("page");
    view! {
        <a href=href class=class title=move || title.map(|t| t.get()) aria-current=current
            on:click=move |ev| { ev.prevent_default(); navigate(href); }>
            {children()}
        </a>
    }
}

/// Whether the link to `href` is the page at `path`: the page itself or one
/// below it. `/` shows the tunnels list, so it counts as `/tunnels` (as
/// static/shell.js does for the first paint).
fn is_current(path: &str, href: &str) -> bool {
    let path = if path == "/" { "/tunnels" } else { path };
    path == href || path.strip_prefix(href).is_some_and(|rest| rest.starts_with('/'))
}

/// The header's page links: `(href, text)`. static/shell.html has the same
/// links for the first paint (checked in src/boot.rs). The admin pages are
/// in the user menu (static/menu.js).
pub const NAV: [(&str, &str); 3] = [("/tunnels", "Tunnels"), ("/machines", "Machines"), ("/cli", "Get the CLI")];

#[component]
pub fn Shell(children: ChildrenFn) -> impl IntoView {
    let c = ctx();
    let user = move || c.session.get().and_then(|s| s.user);
    let signed_in = move || user().is_some();
    let abuse = move || c.session.get().and_then(|s| s.server.abuse_contact);
    let version = move || c.session.get().map(|s| s.server.version).unwrap_or_default();
    view! {
        <header class="header" data-app-header>
            <a class="brand" href="/" on:click=move |ev| { ev.prevent_default(); navigate("/"); }>
                // The logo slot (static/shell.html has the same markup): 2rem
                // with 32/64/128px files from the same artwork as the favicon
                // (make-logos.py), picked by drawn size x density. sizes is the
                // largest drawn width (2rem at the 150% root cap) as a literal:
                // sizes resolves rem against the initial font size, not the
                // scaled root. The image names the link; the visible text
                // is aria-hidden, so the name is "Tunnel" once.
                <img src="/assets/favicon-32.png" srcset="/assets/favicon-32.png 32w, /assets/logo-64.png 64w, /assets/logo-128.png 128w" sizes="48px"
                    alt="Tunnel" width="32" height="32" decoding="async" />
                <span class="brand-text" aria-hidden="true">"Tunnel"</span>
            </a>
            <Show when=signed_in>
                <nav class="nav" aria-label="Main">
                    {NAV.map(|(href, text)| view! { <A href=href>{text}</A> })}
                </nav>
            </Show>
            <div class="spacer"></div>
            // The user menu: static/shell.js draws its button here and
            // static/menu.js the menu (src/boot.rs hands them the session).
            <div class="menu-wrap" id="menu-wrap"></div>
        </header>
        <main class="main" id="main-content">
            <div role="status">{move || c.notice.get().map(|n| view! { <div class="alert alert-success">{n}</div> })}</div>
            {children()}
        </main>
        <footer class="footer">
            "Tunnel " {version}
            {move || abuse().map(|a| view! { " · Report abuse: " {a} })}
        </footer>
    }
}

/// Keep this outside the routed page so signing in cannot discard it.
pub fn recovery_notice(v: &serde_json::Value) {
    if v["recovery_code"].as_bool() == Some(true) {
        let left = v["recovery_codes_left"].as_u64().unwrap_or(0);
        ctx().notice.set(Some(format!("Signed in with a recovery code; {left} left. To get new ones, turn two-factor sign-in off and on again under Account.")));
    }
}

/// A read-only value with a copy button.
#[component]
pub fn Copy(
    #[prop(into)] value: Signal<String>,
    #[prop(optional)] label: &'static str,
    #[prop(optional)] id: Option<String>,
) -> impl IntoView {
    let copied = RwSignal::new(false);
    let copy = move |_| {
        if let Some(w) = web_sys::window() {
            let _ = w.navigator().clipboard().write_text(&value.get());
            copied.set(true);
        }
    };
    view! {
        <div class="copy" aria-label=label>
            <code class="secret">{move || value.get()}</code>
            // Not a submit: a Copy inside a form (Machines) must not send it.
            <button id=id class="btn btn-ghost btn-sm" type="button" on:click=copy>{move || if copied.get() { "Copied" } else { "Copy" }}</button>
        </div>
    }
}

/// The shared two-factor field; the password variant uses the same feedback.
#[component]
pub fn CodeField(
    #[prop(into)] id: String,
    label: &'static str,
    value: RwSignal<String>,
    error: RwSignal<Option<String>>,
    #[prop(optional)] password: bool,
) -> impl IntoView {
    let described = format!("{id}-error");
    view! {
        <div class="field">
            <label for=id.clone()>{label}</label>
            <input id=id class=if password { "input" } else { "input code-input" }
                type=if password { "password" } else { "text" }
                autocomplete=if password { "current-password" } else { "one-time-code" } inputmode="text" required
                aria-describedby=described.clone() aria-invalid=move || error.get().map(|_| "true")
                prop:value=move || value.get() on:input=move |ev| { error.set(None); value.set(event_target_value(&ev)); } />
            <p id=described class="field-error" aria-live="polite">{move || error.get()}</p>
        </div>
    }
}

/// Only the named refusal belongs at this field; locked and network errors
/// still belong in the page's error box.
pub fn field_refused(e: &ApiError, code: &str, error: RwSignal<Option<String>>, id: &str) -> bool {
    if e.code != code {
        return false;
    }
    if !error.is_disposed() {
        error.set(Some(e.message.clone()));
        focus_id(id);
    }
    true
}

#[component]
pub fn ErrorBox(error: RwSignal<Option<String>>) -> impl IntoView {
    view! {
        {move || error.get().map(|e| view! { <div class="alert alert-error" role="alert">{e}</div> })}
    }
}

#[component]
pub fn Empty(title: &'static str, children: Children) -> impl IntoView {
    view! {
        <div class="empty">
            <h2>{title}</h2>
            {children()}
        </div>
    }
}

/// `2026-11-19 14:05` in the browser's local time.
pub fn when(unix: i64) -> String {
    if unix <= 0 {
        return "—".into();
    }
    let d = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(unix as f64 * 1000.0));
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        d.get_full_year(),
        d.get_month() + 1,
        d.get_date(),
        d.get_hours(),
        d.get_minutes()
    )
}

/// `0 B`, `12.3 MB`, `4.56 GB` (decimal units, like the caps). Integer
/// arithmetic only: float formatting would add tens of kB to the WASM.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 7] = ["B", "kB", "MB", "GB", "TB", "PB", "EB"];
    let (mut unit, mut base) = (0, 1u64);
    while unit < UNITS.len() - 1 && n / base >= 1000 {
        base *= 1000;
        unit += 1;
    }
    let (whole, rem, u) = (n / base, n % base, UNITS[unit]);
    match unit {
        0 => format!("{n} B"),
        _ if whole >= 100 => format!("{whole} {u}"),
        _ if whole >= 10 => format!("{whole}.{} {u}", rem * 10 / base),
        _ => format!("{whole}.{:02} {u}", rem / (base / 100)),
    }
}

/// Bytes as GB for an input field: `50`, `0.5`, `1.25`.
pub fn gb_text(n: u64) -> String {
    let (whole, rem) = (n / 1_000_000_000, n % 1_000_000_000);
    if rem == 0 {
        return whole.to_string();
    }
    let digits = format!("{rem:09}");
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// `50`, `0.5`, `1.25` (GB) as bytes; `None` unless a positive number with
/// at most nine decimals.
pub fn parse_gb(s: &str) -> Option<u64> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if (whole.is_empty() && frac.is_empty())
        || frac.len() > 9
        || !(whole.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let frac: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<9}").parse().ok()? };
    whole.checked_mul(1_000_000_000)?.checked_add(frac).filter(|b| *b > 0)
}

/// `90 s`, `30 min`, `8 h`, `7 d`, `1 d 12 h`.
pub fn duration_text(s: u64) -> String {
    let mut parts = Vec::new();
    let mut left = s;
    for (unit, size) in [("d", 86_400), ("h", 3600), ("min", 60), ("s", 1)] {
        if left >= size {
            parts.push(format!("{} {unit}", left / size));
            left %= size;
        }
    }
    if parts.is_empty() { "0 s".into() } else { parts.join(" ") }
}

/// A count and its limit, or the count when no limit applies.
pub fn used_of(used: u64, limit: Option<u64>) -> String {
    match limit {
        Some(l) => format!("{used} of {l}"),
        None => format!("{used} (unlimited)"),
    }
}

/// `used of cap`, or `used (no cap)`.
pub fn traffic_text(used: u64, cap: Option<u64>) -> String {
    match cap {
        Some(c) => format!("{} of {}", bytes(used), bytes(c)),
        None => format!("{} (no cap)", bytes(used)),
    }
}

/// `in 3 h`, `5 min ago`.
pub fn relative(unix: i64) -> String {
    if unix <= 0 {
        return "never".into();
    }
    let now = (js_sys::Date::now() / 1000.0) as i64;
    let d = unix - now;
    let a = d.abs();
    if a < 60 {
        return "just now".into();
    }
    let span = if a < 3600 {
        format!("{} min", a / 60)
    } else if a < 86_400 {
        format!("{} h", a / 3600)
    } else {
        format!("{} d", a / 86_400)
    };
    if d >= 0 { format!("in {span}") } else { format!("{span} ago") }
}

/// Moves the keyboard focus to the element with `id`, out from under the
/// header; false when it is not there.
pub fn focus_id(id: &str) -> bool {
    use wasm_bindgen::JsCast;
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else { return false };
    let Some(el) = doc.get_element_by_id(id).and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok()) else {
        return false;
    };
    let focused = el.focus().is_ok();
    if focused {
        clear_of_header(&doc, &el);
    }
    focused
}

/// Defer focus until the new control is rendered. The id is owned, and the
/// signal belongs to the requesting component, so leaving it cancels focus.
pub fn focus_later(alive: RwSignal<bool>, id: String) {
    set_timeout(
        move || {
            if let Some(id) = focus_target(alive, id) {
                focus_id(&id);
            }
        },
        std::time::Duration::ZERO,
    );
}

fn focus_target(alive: RwSignal<bool>, id: String) -> Option<String> {
    alive.try_with_untracked(|_| id)
}

/// `focus()` scrolls only an element outside the viewport; one under the
/// sticky header counts as in view and stays hidden. Scroll it out by the
/// overlap with the header as drawn (it wraps onto two rows on narrow
/// screens and grows with the font size).
fn clear_of_header(doc: &web_sys::Document, el: &web_sys::Element) {
    let Some(header) = doc.query_selector("header.header:not(.boot)").ok().flatten() else { return };
    let covered = header.get_bounding_client_rect().bottom() - el.get_bounding_client_rect().top();
    if covered > 0.0
        && let Some(w) = web_sys::window()
    {
        w.scroll_by_with_x_and_y(0.0, -(covered + 8.0));
    }
}

/// Run `fut`, storing its error message in `error`.
pub fn run<F>(error: RwSignal<Option<String>>, busy: RwSignal<bool>, fut: F)
where
    F: std::future::Future<Output = Result<(), ApiError>> + 'static,
{
    // Share the task's state machine across pages; only boxing depends on F.
    run_boxed(error, busy, None, Box::pin(fut));
}

/// As `run`, with only invalid_code routed to the shared code field.
pub fn run_code<F>(
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    code_error: RwSignal<Option<String>>,
    id: &'static str,
    fut: F,
) where
    F: std::future::Future<Output = Result<(), ApiError>> + 'static,
{
    code_error.set(None);
    run_boxed(error, busy, Some((code_error, id)), Box::pin(fut));
}

fn run_boxed(
    error: RwSignal<Option<String>>,
    busy: RwSignal<bool>,
    code_field: Option<(RwSignal<Option<String>>, &'static str)>,
    fut: std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ApiError>>>>,
) {
    busy.set(true);
    error.set(None);
    leptos::task::spawn_local(async move {
        if let Err(e) = fut.await {
            if e.status == 401 && e.code == "signed_out" {
                refresh_session().await;
            }
            // Writes to disposed signals are no-ops in reactive_graph 0.2;
            // field focus must also be skipped when the page has gone.
            if !code_field.is_some_and(|(field, id)| field_refused(&e, "invalid_code", field, id)) {
                error.set(Some(e.message.clone()));
            }
        }
        busy.set(false);
    });
}

pub fn value(ev: &leptos::ev::Event) -> String {
    event_target_value(ev)
}

#[cfg(test)]
/// The body of `fn <name>` in `src`, up to the next item.
pub fn source_body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = [format!("fn {name}("), format!("fn {name}<")]
        .iter()
        .find_map(|head| src.find(head.as_str()))
        .unwrap_or_else(|| panic!("no fn {name}"));
    let rest = &src[start..];
    &rest[..rest.find("\n}\n").expect("the item ends")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_focus_and_writes_tolerate_a_disposed_owner() {
        let owner = Owner::new();
        let (alive, stored, error) = owner
            .with(|| (RwSignal::new(false), StoredValue::new("copy-id".to_string()), RwSignal::new(None::<String>)));
        let id = stored.get_value();
        assert_eq!(focus_target(alive, id.clone()), Some(id.clone()));
        // Simulate closing a panel or navigating before a queued callback.
        let callback = move || focus_target(alive, id);
        owner.cleanup();
        assert_eq!(callback(), None);
        assert_eq!(stored.try_get_value(), None);
        assert_eq!(alive.try_get_untracked(), None);
        // These are the operations used by async run(...) completions.
        alive.set(true);
        alive.update(|v| *v = false);
        assert!(alive.is_disposed());
        let refusal = ApiError { status: 400, code: "invalid_code".into(), message: "Try again.".into() };
        // A late field error must not try to focus a control on another page.
        assert!(field_refused(&refusal, "invalid_code", error, "code"));
        assert!(error.is_disposed());
    }

    #[test]
    fn deferred_callbacks_do_not_read_disposed_state() {
        for (file, src) in [
            ("pages", include_str!("pages.rs")),
            ("auth", include_str!("auth.rs")),
            ("account", include_str!("account.rs")),
            ("limits", include_str!("limits.rs")),
            ("email", include_str!("email.rs")),
            ("ui", include_str!("ui.rs")),
        ] {
            let src = src.split("#[cfg(test)]").next().unwrap();
            for (start, _) in src.match_indices("set_timeout(") {
                let mut depth = 1;
                let rest = &src[start + "set_timeout(".len()..];
                let end = rest
                    .char_indices()
                    .find_map(|(i, c)| {
                        match c {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                        (depth == 0).then_some(i)
                    })
                    .unwrap();
                let callback = &rest[..end];
                for read in [".get_value(", ".get(", ".get_untracked(", ".with_untracked("] {
                    assert!(!callback.contains(read), "{file}: unsafe read {read} in {callback}");
                }
                assert!(
                    callback.contains("is_disposed()") || callback.contains("focus_target("),
                    "{file}: missing lifetime check in {callback}"
                );
            }
        }
        let pages = include_str!("pages.rs");
        for page in ["Links", "ResetPanel"] {
            let body = source_body(pages, page);
            let create = &body[body.find("let create =").unwrap()..];
            assert!(
                create.find("let copy_focus = copy_id.get_value();").unwrap() < create.find("async move {").unwrap()
            );
        }
        let reset = source_body(pages, "ResetPanel");
        assert!(reset.contains("let field_focus = field_id.get_value();"));
        assert!(reset.contains("if busy.is_disposed()"));
        assert!(
            !reset[reset.find("async move {").unwrap()..reset.find("let (name1").unwrap()].contains(".get_value()")
        );
        let users = source_body(pages, "Users");
        assert!(users.contains("let Some(previous) = generation.try_get_value() else"));
        let device = source_body(pages, "Device");
        assert!(device.contains("focus_later(busy, target.into())"));
        assert!(device.contains("if password_required"));
    }

    /// Copy sits inside forms (Machines' login code): it must not submit them.
    #[test]
    fn copy_never_submits_its_form() {
        let src = include_str!("ui.rs").split("#[cfg(test)]").next().unwrap();
        let copy = &src[src.find("pub fn Copy").unwrap()..src.find("pub fn ErrorBox").unwrap()];
        assert!(copy.contains(r#"<button id=id class="btn btn-ghost btn-sm" type="button" on:click=copy>"#), "{copy}");
    }

    #[test]
    fn the_home_page_marks_tunnels_as_current() {
        assert!(is_current("/", "/tunnels"));
        assert!(!is_current("/", "/machines"));
        assert!(is_current("/tunnels", "/tunnels"));
        assert!(is_current("/admin/users", "/admin/users"));
        assert!(is_current("/account/sessions", "/account"));
        assert!(!is_current("/tunnelsx", "/tunnels"));
        assert!(!is_current("/machines", "/tunnels"));
    }
}
