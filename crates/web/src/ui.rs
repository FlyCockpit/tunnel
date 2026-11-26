//! Shell and small components (ported from the template's header, page
//! shell, empty and error states, copy field and mode toggle).

use leptos::prelude::*;

use crate::api::ApiError;
use crate::theme;
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
    let current = move || {
        let p = c.path.get();
        (p == href || (href != "/" && p.starts_with(href))).then_some("page")
    };
    view! {
        <a href=href class=class title=move || title.map(|t| t.get()) aria-current=current
            on:click=move |ev| { ev.prevent_default(); navigate(href); }>
            {children()}
        </a>
    }
}

#[component]
pub fn Shell(children: ChildrenFn) -> impl IntoView {
    let c = ctx();
    let user = move || c.session.get().and_then(|s| s.user);
    let signed_in = move || user().is_some();
    let is_admin = move || user().is_some_and(|u| u.is_admin());
    let sign_out = move |_| {
        leptos::task::spawn_local(async move {
            let _ = crate::api::post::<serde_json::Value>("/ui/api/logout", &serde_json::json!({})).await;
            crate::refresh_session().await;
            navigate("/");
        });
    };
    let abuse = move || c.session.get().and_then(|s| s.server.abuse_contact);
    let version = move || c.session.get().map(|s| s.server.version).unwrap_or_default();
    view! {
        <header class="header">
            <a class="brand" href="/" on:click=move |ev| { ev.prevent_default(); navigate("/"); }>
                <img src="/assets/logo-64.png" alt="" width="24" height="24" />
                <span class="brand-text">"Tunnel"</span>
            </a>
            <Show when=signed_in>
                <nav class="nav" aria-label="Main">
                    <A href="/tunnels">"Tunnels"</A>
                    <A href="/machines">"Machines"</A>
                    <A href="/cli">"Get the CLI"</A>
                    <Show when=is_admin>
                        <A href="/admin/users">"Users"</A>
                        <A href="/admin/status">"Server"</A>
                    </Show>
                </nav>
            </Show>
            <div class="spacer"></div>
            <ThemeToggle />
            <Show when=signed_in>
                <A href="/account" class="account-link"
                    title=Signal::derive(move || format!("Account: {}", user().map(|u| u.username).unwrap_or_default()))>
                    {move || user().map(|u| u.username).unwrap_or_default()}
                </A>
                <button class="btn btn-ghost btn-sm" on:click=sign_out>"Sign out"</button>
            </Show>
        </header>
        <main class="main">{children()}</main>
        <footer class="footer">
            "Tunnel " {version}
            {move || abuse().map(|a| view! { " · Report abuse: " {a} })}
        </footer>
    }
}

#[component]
fn ThemeToggle() -> impl IntoView {
    let choice = RwSignal::new(theme::choice());
    let next = move |_| {
        let t = match choice.get().as_str() {
            "system" => "light",
            "light" => "dark",
            _ => "system",
        }
        .to_string();
        theme::set(&t);
        choice.set(t);
    };
    view! {
        <button class="btn btn-ghost btn-sm" on:click=next title="Theme: system, light or dark">
            {move || match choice.get().as_str() { "light" => "Light", "dark" => "Dark", _ => "Auto" }}
        </button>
    }
}

/// A read-only value with a copy button.
#[component]
pub fn Copy(#[prop(into)] value: Signal<String>, #[prop(optional)] label: &'static str) -> impl IntoView {
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
            <button class="btn btn-ghost btn-sm" on:click=copy>{move || if copied.get() { "Copied" } else { "Copy" }}</button>
        </div>
    }
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

/// Run `fut`, storing its error message in `error`.
pub fn run<F>(error: RwSignal<Option<String>>, busy: RwSignal<bool>, fut: F)
where
    F: std::future::Future<Output = Result<(), ApiError>> + 'static,
{
    busy.set(true);
    error.set(None);
    leptos::task::spawn_local(async move {
        if let Err(e) = fut.await {
            if e.status == 401 && e.code == "signed_out" {
                refresh_session().await;
            }
            error.set(Some(e.message.clone()));
        }
        busy.set(false);
    });
}

pub fn value(ev: &leptos::ev::Event) -> String {
    event_target_value(ev)
}
