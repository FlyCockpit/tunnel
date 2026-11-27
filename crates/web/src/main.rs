//! Tunnel's web UI: sign-in, machines, tunnels and links, machine approval,
//! the CLI, account security, and (for admins) users, invites and status.
//! Client-side rendered with Leptos and served by tunnel-server from its
//! binary; it talks only to `/ui/api/*` on its own origin.

mod account;
mod api;
mod auth;
mod boot;
mod device;
mod email;
mod limits;
mod pages;
mod theme;
mod types;
mod ui;

use leptos::prelude::*;
use types::SessionInfo;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::Closure;

/// The signed-in state, shared by every page.
#[derive(Clone, Copy)]
pub struct Ctx {
    pub session: RwSignal<Option<SessionInfo>>,
    pub path: RwSignal<String>,
    pub notice: RwSignal<Option<String>>,
}

thread_local! {
    // One app per page: a global is simpler than context, and it is also
    // reachable from async tasks, which run outside the component tree.
    static CTX: std::cell::OnceCell<Ctx> = const { std::cell::OnceCell::new() };
}

pub fn ctx() -> Ctx {
    CTX.with(|c| *c.get().expect("app state is set before mounting"))
}

fn location_path() -> String {
    web_sys::window().and_then(|w| w.location().pathname().ok()).unwrap_or_else(|| "/".into())
}

/// Client-side navigation (history API).
pub fn navigate(to: &str) {
    ctx().notice.set(None);
    if let Some(w) = web_sys::window()
        && let Ok(h) = w.history()
    {
        let _ = h.push_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(to));
    }
    ctx().path.set(to.split(['?', '#']).next().unwrap_or("/").to_string());
    if let Some(w) = web_sys::window() {
        w.scroll_to_with_x_and_y(0.0, 0.0);
    }
}

/// Re-read `/ui/api/session` (after sign-in, sign-out, role changes).
pub async fn refresh_session() {
    let session = api::get("/ui/api/session").await.ok().and_then(|v| serde_json::from_value::<SessionInfo>(v).ok());
    match session {
        Some(s) => {
            api::set_csrf(s.csrf.clone());
            boot::remember(Some(&s));
            ctx().session.set(Some(s));
        }
        // Shown as signed out, so the next first paint is too.
        None => {
            boot::remember(None);
            ctx().session.set(None);
        }
    }
}

#[component]
fn App() -> impl IntoView {
    let c = Ctx { session: RwSignal::new(None), path: RwSignal::new(location_path()), notice: RwSignal::new(None) };
    CTX.with(|cell| {
        let _ = cell.set(c);
    });
    let loaded = RwSignal::new(false);
    let auth = Memo::new(move |_| {
        c.session.with(|s| s.as_ref().map(|s| (s.user.as_ref().map(|u| (u.id.clone(), u.role.clone())), s.pending)))
    });
    leptos::task::spawn_local(async move {
        refresh_session().await;
        loaded.set(true);
        // The real shell is rendered: drop the first paint's copy (index.html).
        boot::remove();
    });
    // Back/forward buttons.
    let on_pop = Closure::<dyn Fn()>::new(move || {
        c.notice.set(None);
        c.path.set(location_path());
    });
    if let Some(w) = web_sys::window() {
        let _ = w.add_event_listener_with_callback("popstate", on_pop.as_ref().unchecked_ref());
    }
    on_pop.forget();

    view! {
        // Until the session is known, index.html's copy of the shell stays.
        <Show when=move || loaded.get()>
            <ui::Shell>{move || {
                // Re-route when who is signed in changes (sign-in, the TOTP
                // step, sign-out), not on every session refresh, so pages
                // keep their state when only, say, the 2FA flag changes.
                // Read, not just tracked: a memo that is never read is never
                // computed, so it would never subscribe to the session.
                let _ = auth.get();
                pages::route(c.path.get())
            }}</ui::Shell>
        </Show>
    }
}

fn main() {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}
