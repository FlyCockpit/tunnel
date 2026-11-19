//! Shell and small components (ported from the template's header, page
//! shell, empty and error states, copy field and mode toggle).

use leptos::prelude::*;

use crate::{ctx, navigate};

/// `<a>` that navigates without a reload.
#[component]
pub fn A(href: &'static str, children: Children) -> impl IntoView {
    let c = ctx();
    let current = move || {
        let p = c.path.get();
        (p == href || (href != "/" && p.starts_with(href))).then_some("page")
    };
    view! {
        <a href=href aria-current=current on:click=move |ev| { ev.prevent_default(); navigate(href); }>
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
                <span>"Tunnel"</span>
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
                <A href="/account">{move || user().map(|u| u.username).unwrap_or_default()}</A>
                <button class="btn btn-ghost btn-sm" on:click=sign_out>"Sign out"</button>
            </Show>
        </header>
        <main>{children()}</main>
        <footer class="footer">
            "Tunnel " {version}
            {move || abuse().map(|a| view! { " · Report abuse: " {a} })}
        </footer>
    }
}

pub fn stored_theme() -> String {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("tunnel-theme").ok().flatten())
        .unwrap_or_else(|| "system".into())
}

pub fn apply_theme(theme: String) {
    let Some(w) = web_sys::window() else { return };
    let dark = match theme.as_str() {
        "dark" => true,
        "light" => false,
        _ => w.match_media("(prefers-color-scheme: dark)").ok().flatten().is_some_and(|m| m.matches()),
    };
    if let Some(root) = w.document().and_then(|d| d.document_element()) {
        let _ = if dark { root.class_list().add_1("dark") } else { root.class_list().remove_1("dark") };
    }
    if let Some(s) = w.local_storage().ok().flatten() {
        let _ = s.set_item("tunnel-theme", &theme);
    }
}

#[component]
fn ThemeToggle() -> impl IntoView {
    let theme = RwSignal::new(stored_theme());
    let next = move |_| {
        let t = match theme.get().as_str() {
            "system" => "light",
            "light" => "dark",
            _ => "system",
        }
        .to_string();
        apply_theme(t.clone());
        theme.set(t);
    };
    view! {
        <button class="btn btn-ghost btn-sm" on:click=next title="Theme: system, light or dark">
            {move || match theme.get().as_str() { "light" => "Light", "dark" => "Dark", _ => "Auto" }}
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
