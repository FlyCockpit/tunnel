//! Route dispatch and the tunnel, machine and administrator pages.
//! Each page loads what it shows from `/ui/api/*` and keeps it in signals.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::account::Account;
use crate::api::{self, ApiError};
use crate::auth::{InvitePage, SignIn};
use crate::email::MailStatus;
use crate::limits::{FocusAt, LimitsEditor};
use crate::types::*;
use crate::ui::{
    CodeField, Copy, Empty, ErrorBox, bytes, duration_text, field_refused, focus_id, focus_later, relative, run,
    run_code, traffic_text, used_of, value, when,
};
use crate::{ctx, navigate, refresh_session};

pub fn route(path: String) -> AnyView {
    let session = ctx().session.get_untracked();
    let user = session.as_ref().and_then(|s| s.user.clone());
    if path.starts_with("/invite") {
        return view! { <InvitePage /> }.into_any();
    }
    let Some(user) = user else {
        return view! { <SignIn /> }.into_any();
    };
    match path.as_str() {
        "/" | "/tunnels" => view! { <Tunnels admin=user.is_admin() /> }.into_any(),
        "/machines" => view! { <Machines admin=user.is_admin() /> }.into_any(),
        "/device" => view! { <Device /> }.into_any(),
        "/cli" => view! { <Cli /> }.into_any(),
        "/account" => view! { <Account /> }.into_any(),
        "/admin/users" if user.is_admin() => view! { <Users me=user.clone() /> }.into_any(),
        "/admin/status" if user.is_admin() => view! { <Status /> }.into_any(),
        // The page's one heading is its h1, as on every other page.
        _ => view! {
            <div class="page"><div class="empty">
                <h1>"Page not found"</h1>
                <p>"There is nothing at this address."</p>
                <button class="btn btn-outline" on:click=move |_| navigate("/")>"Go to your tunnels"</button>
            </div></div>
        }
        .into_any(),
    }
}

fn err_text(e: &ApiError) -> String {
    e.message.clone()
}

/// `(name, login code)` of a headless machine the server just added.
fn created_login(v: &Value) -> Option<(String, String)> {
    Some((v["name"].as_str()?.to_string(), v["login_code"].as_str()?.to_string()))
}

/// Admins' switch between their own tunnels or machines and everyone's.
#[component]
fn ShowAll<F>(all: RwSignal<bool>, what: &'static str, on_change: F) -> impl IntoView
where
    F: Fn() + Copy + 'static,
{
    let hint = format!("Lists every user's {what}, not only yours. Only admins have this option.");
    let hint_id = format!("show-all-{what}");
    let title = hint.clone();
    view! {
        <label class="check" title=title>
            <input
                type="checkbox"
                aria-describedby=hint_id.clone()
                prop:checked=move || all.get()
                on:change=move |ev| { all.set(event_target_checked(&ev)); on_change(); }
            />
            "Show all users"
            <span id=hint_id class="sr-only">{hint}</span>
        </label>
    }
}

// ------------------------------------------------------------------ tunnels

/// Longest tunnel name, in characters (the server's limit).
const MAX_NAME_CHARS: usize = 80;

/// The tunnel's display name, or its id when it has none.
fn display_name(t: &Tunnel) -> String {
    t.name.clone().unwrap_or_else(|| t.id.clone())
}

/// Open `port`'s preview of one of your own tunnels in a new tab, signed in
/// as its owner. Previews live on other hosts (another site, even) and the UI
/// session never reaches them, so the server mints a single-use owner link
/// (a minute at most, bound to this port) and the tab goes through it; the
/// link's sign-in page then skips the tunnel's own password or link prompt.
/// The tab is opened during the click (so pop-up blockers allow it), cut off
/// from this page (`opener` is cleared; the page sends no referrer), and
/// navigated with `replace`, so the link is not left in its back history.
fn open_preview(tunnel: String, port: u16, error: RwSignal<Option<String>>) {
    let Some(window) = web_sys::window() else { return };
    let tab = match window.open_with_url_and_target("about:blank", "_blank") {
        Ok(Some(tab)) => tab,
        _ => {
            error.set(Some(
                "The browser blocked the new tab. Allow pop-ups for this site, or make a link under Links.".into(),
            ));
            return;
        }
    };
    let _ = tab.set_opener(&wasm_bindgen::JsValue::NULL);
    error.set(None);
    spawn_local(async move {
        let url = api::post(&format!("/ui/api/tunnels/{tunnel}/open"), &json!({ "port": port }))
            .await
            .map(|v| v["url"].as_str().map(str::to_string));
        match url {
            Ok(Some(url)) => {
                let _ = tab.location().replace(&url);
            }
            Ok(None) => {
                let _ = tab.close();
                error.set(Some("The server did not return a link.".into()));
            }
            Err(e) => {
                let _ = tab.close();
                if e.status == 401 && e.code == "signed_out" {
                    refresh_session().await;
                }
                error.set(Some(err_text(&e)));
            }
        }
    });
}

/// Per port: Open (your own tunnel: signed in, no prompt) or Visit (someone
/// else's: the tunnel's normal sign-in). Disabled while the port is not connected.
fn open_buttons(t: &Tunnel, error: RwSignal<Option<String>>) -> AnyView {
    let name = display_name(t);
    if t.ports.is_empty() {
        let hint = format!("{name} is not connected: start sharing on its machine to open it");
        return view! {
            <button class="btn btn-outline btn-sm" disabled=true aria-label=hint.clone() title=hint>"Open"</button>
        }
        .into_any();
    }
    let several = t.ports.len() > 1;
    t.ports
        .iter()
        .map(|p| {
            let (id, port) = (t.id.clone(), p.port);
            let live = t.connected && p.connected;
            let verb = if t.mine { "Open" } else { "Visit" };
            let text = if several { format!("{verb} {port}") } else { verb.to_string() };
            let hint = match (live, t.mine) {
                (false, _) => {
                    format!("Port {port} of {name} is not connected: start the app and the tunnel on its machine")
                }
                (true, true) => format!("Open {name}, port {port}, in a new tab, signed in as you"),
                (true, false) => format!("Visit {name}, port {port}, in a new tab (asks for the tunnel's own sign-in)"),
            };
            if t.mine || !live {
                view! {
                    <button class="btn btn-outline btn-sm" disabled=!live aria-label=hint.clone() title=hint
                        on:click=move |_| open_preview(id.clone(), port, error)
                    >{text}</button>
                }
                .into_any()
            } else {
                view! {
                    <a class="btn btn-outline btn-sm" href=format!("https://{}/", p.host) target="_blank"
                        rel="noopener noreferrer" aria-label=hint.clone() title=hint>{text}</a>
                }
                .into_any()
            }
        })
        .collect_view()
        .into_any()
}

#[component]
fn Tunnels(admin: bool) -> impl IntoView {
    let all = RwSignal::new(false);
    let tunnels = RwSignal::new(None::<Vec<Tunnel>>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let open = RwSignal::new(None::<String>);
    let focus_after = RwSignal::new(None::<String>);
    let load = move || {
        if busy.is_disposed() {
            return;
        }
        let path = if all.get_untracked() { "/ui/api/tunnels?all=true" } else { "/ui/api/tunnels" };
        run(error, busy, async move {
            let v = api::get(path).await?;
            let list: Vec<Tunnel> = serde_json::from_value(v["tunnels"].clone()).unwrap_or_default();
            tunnels.set(Some(list));
            if let Some(id) = focus_after.try_get_untracked().flatten() {
                focus_after.set(None);
                set_timeout(
                    move || {
                        if busy.is_disposed() {
                            return;
                        }
                        if !focus_id(&id) {
                            focus_id("tunnels-title");
                        }
                    },
                    std::time::Duration::ZERO,
                );
            }
            Ok(())
        });
    };
    load();
    let delete = move |id: String| {
        run(error, busy, async move {
            api::delete(&format!("/ui/api/tunnels/{id}")).await?;
            let next = tunnels
                .try_with_untracked(|list| {
                    list.as_ref().and_then(|list| {
                        let at = list.iter().position(|t| t.id == id)?;
                        list.get(at + 1)
                            .or_else(|| list.iter().find(|t| t.id != id))
                            .map(|t| format!("rename-tunnel-{}", t.id))
                    })
                })
                .flatten()
                .unwrap_or_else(|| "tunnels-title".into());
            focus_after.set(Some(next));
            load();
            Ok(())
        });
    };
    // The tunnel being renamed, and the name typed so far.
    let editing = RwSignal::new(None::<String>);
    let new_name = RwSignal::new(String::new());
    let cancel_rename = move || {
        if let Some(id) = editing.get_untracked() {
            editing.set(None);
            focus_later(busy, format!("rename-tunnel-{id}"));
        }
    };
    let save_name = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(id) = editing.get_untracked() else { return };
        // Characters as the server counts them (`maxlength` counts UTF-16 units).
        if new_name.get_untracked().trim().chars().count() > MAX_NAME_CHARS {
            error.set(Some(format!("A name has at most {MAX_NAME_CHARS} characters.")));
            return;
        }
        let body = json!({ "name": new_name.get_untracked() });
        run(error, busy, async move {
            api::patch(&format!("/ui/api/tunnels/{id}"), &body).await?;
            editing.set(None);
            focus_after.set(Some(format!("rename-tunnel-{id}")));
            load();
            Ok(())
        });
    };
    view! {
        <div class="page">
            <div class="page-head">
                <div>
                    <h1 id="tunnels-title" tabindex="-1">"Tunnels"</h1>
                    <p class="muted">"Live tunnels from your machines. Open your own signed in; share them with access links, which work once unless you make them reusable."</p>
                </div>
                <div class="head-actions">
                    {admin.then(|| view! { <ShowAll all=all what="tunnels" on_change=load /> })}
                    <button class="btn btn-outline" on:click=move |_| load()>"Refresh"</button>
                </div>
            </div>
            <ErrorBox error=error />
            {move || match tunnels.get() {
                None => view! { <p class="muted">"Loading…"</p> }.into_any(),
                Some(list) if list.is_empty() => view! {
                    <div class="card"><Empty title="No tunnels yet">
                        <p>"Install the CLI on a machine, sign it in, then run " <code>"tunnel share 3000 --name \"My app\""</code> "."</p>
                        <button class="btn" on:click=move |_| navigate("/cli")>"Get the CLI"</button>
                    </Empty></div>
                }.into_any(),
                Some(list) => view! {
                    <div class="card card-tight table-wrap">
                        <table class="table table-stack tunnels-table">
                            <thead><tr>
                                <th>"Tunnel"</th><th>"Ports"</th><th>"Access"</th><th>"Machine"</th><th>"Traffic"</th><th>"Expires"</th><th><span class="sr-only">"Actions"</span></th>
                            </tr></thead>
                            <tbody>
                                {list.into_iter().map(|t| {
                                    let id = t.id.clone();
                                    let id2 = t.id.clone();
                                    let id3 = t.id.clone();
                                    let (id_edit, id_row) = (t.id.clone(), t.id.clone());
                                    let is_open = move || open.get().as_deref() == Some(id3.as_str());
                                    let expanded = is_open.clone();
                                    let is_editing = move || editing.get().as_deref() == Some(id_row.as_str());
                                    let ports = if t.ports.is_empty() { "—".to_string() } else {
                                        t.ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ")
                                    };
                                    let owner = match (&t.owner, &t.user) {
                                        (Some(o), Some(u)) => format!("{o} ({u})"),
                                        (Some(o), None) => o.clone(),
                                        _ => "admin".into(),
                                    };
                                    let name = display_name(&t);
                                    let current_name = t.name.clone().unwrap_or_default();
                                    // Secondary line: where it lives (its first preview host), else its id.
                                    let secondary = match (&t.name, t.ports.first()) {
                                        (_, Some(p)) => p.host.clone(),
                                        (Some(_), None) => t.id.clone(),
                                        (None, None) => String::new(),
                                    };
                                    let named = t.name.is_some();
                                    let label_title = t.label.clone().unwrap_or_default();
                                    let t2 = t.clone();
                                    let rename_label = format!("Rename {name}");
                                    let links_label = format!("Access links of {name}");
                                    let delete_label = format!("Delete {name}");
                                    let delete_question = format!("Delete {name}? Its links stop working.");
                                    view! {
                                        <tr>
                                            <td class="cell-main">
                                                {move || if is_editing() {
                                                    view! {
                                                        <form class="row" on:submit=save_name on:keydown=move |ev| {
                                            if ev.key() == "Escape" { ev.prevent_default(); cancel_rename(); }
                                        }>
                                                            <label class="sr-only" for="rename-tunnel">"Name"</label>
                                                            <input id="rename-tunnel" class="input input-sm grow"
                                                                placeholder="e.g. Checkout redesign" autocomplete="off"
                                                                prop:value=move || new_name.get() on:input=move |ev| new_name.set(value(&ev)) />
                                                            <button class="btn btn-sm" type="submit" disabled=move || busy.get()>"Save"</button>
                                                            <button class="btn btn-ghost btn-sm" type="button" on:click=move |_| cancel_rename()>"Cancel"</button>
                                                        </form>
                                                        <p class="muted small">"A label only: links and URLs stay the same. Empty removes the name."</p>
                                                    }.into_any()
                                                } else {
                                                    view! {
                                                        <div class="tunnel-name" title=label_title.clone()>
                                                            <span class=if t.connected { "dot dot-on" } else { "dot" }
                                                                role="img" aria-label=if t.connected { "connected" } else { "not connected" }></span>
                                                            <span class=if named { "name" } else { "name mono" }>{name.clone()}</span>
                                                        </div>
                                                        {(!secondary.is_empty()).then(|| view! { <div class="muted small mono break">{secondary.clone()}</div> })}
                                                    }.into_any()
                                                }}
                                            </td>
                                            <td data-label="Ports">{ports}</td>
                                            <td data-label="Access"><span class="badge">{t.access.mode.clone()}</span></td>
                                            <td data-label="Machine">{owner}</td>
                                            <td data-label="Traffic" title=format!("in {} / out {}", bytes(t.bytes_in), bytes(t.bytes_out))>
                                                {bytes(t.bytes_in + t.bytes_out)}
                                                {t.traffic_limited.then(|| view! { " " <span class="badge badge-danger">"limit reached"</span> })}
                                            </td>
                                            {if t.never_expires {
                                                view! { <td data-label="Expires" title="This tunnel lives until it is deleted.">"never"</td> }.into_any()
                                            } else {
                                                view! { <td data-label="Expires" title=when(t.expires_at)>{relative(t.expires_at)}</td> }.into_any()
                                            }}
                                            <td class="actions">
                                                {open_buttons(&t, error)}
                                                <button id=format!("rename-tunnel-{}", t.id) class="btn btn-outline btn-sm" aria-label=rename_label on:click=move |_| {
                                                    new_name.set(current_name.clone());
                                                    editing.set(Some(id_edit.clone()));
                                                    focus_later(busy, "rename-tunnel".into());
                                                }>"Rename"</button>
                                                <button class="btn btn-outline btn-sm" aria-label=links_label
                                                    aria-expanded=move || expanded().to_string() on:click=move |_| {
                                                    let cur = open.get();
                                                    open.set(if cur.as_deref() == Some(id.as_str()) { None } else { Some(id.clone()) });
                                                }>"Links"</button>
                                                <button class="btn btn-destructive btn-sm" aria-label=delete_label data-confirm=delete_question on:click=move |_| delete(id2.clone())>"Delete"</button>
                                            </td>
                                        </tr>
                                        <Show when=is_open.clone()>
                                            <tr class="panel-row"><td colspan="7" class="links-panel"><Links tunnel=t2.clone() /></td></tr>
                                        </Show>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                    </div>
                }.into_any(),
            }}
        </div>
    }
}

#[component]
fn Links(tunnel: Tunnel) -> impl IntoView {
    let links = RwSignal::new(Vec::<Link>::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let minted = RwSignal::new(None::<String>);
    let ttl = RwSignal::new("600".to_string());
    let reusable = RwSignal::new(false);
    let port = RwSignal::new(tunnel.ports.first().map(|p| p.port.to_string()).unwrap_or_default());
    let copy_id = StoredValue::new(format!("link-copy-{}", tunnel.id));
    let id = tunnel.id.clone();
    let load = {
        let id = id.clone();
        move || {
            let id = id.clone();
            run(error, busy, async move {
                let v = api::get(&format!("/ui/api/tunnels/{id}/links")).await?;
                links.set(serde_json::from_value(v["links"].clone()).unwrap_or_default());
                Ok(())
            });
        }
    };
    load();
    let create = {
        let id = id.clone();
        let load = load.clone();
        move |ev: leptos::ev::SubmitEvent| {
            ev.prevent_default();
            let id = id.clone();
            let load = load.clone();
            let mut body = json!({ "ttl_s": ttl.get().parse::<u64>().unwrap_or(600), "single_use": !reusable.get() });
            if let Ok(p) = port.get().parse::<u16>() {
                body["port"] = json!(p);
            }
            let copy_focus = copy_id.get_value();
            run(error, busy, async move {
                let v = api::post(&format!("/ui/api/tunnels/{id}/links"), &body).await?;
                minted.set(v["url"].as_str().map(str::to_string));
                focus_later(busy, copy_focus);
                load();
                Ok(())
            });
        }
    };
    let revoke = move |link: String| {
        let load = load.clone();
        run(error, busy, async move {
            api::delete(&format!("/ui/api/links/{link}")).await?;
            load();
            Ok(())
        });
    };
    let ports = tunnel.ports.clone();
    view! {
        <div class="stack">
            <ErrorBox error=error />
            <form class="row link-form" on:submit=create>
                <label class="sr-only" for="link-port">"Port"</label>
                <select id="link-port" class="input w-auto" on:change=move |ev| port.set(value(&ev))>
                    {ports.iter().map(|p| view! { <option value=p.port.to_string()>{format!("port {}", p.port)}</option> }).collect_view()}
                    <option value="">"lowest connected port"</option>
                </select>
                <label class="sr-only" for="link-ttl">"Valid for"</label>
                <select id="link-ttl" class="input w-auto" on:change=move |ev| ttl.set(value(&ev))>
                    <option value="600">"valid 10 minutes"</option>
                    <option value="3600">"valid 1 hour"</option>
                    <option value="86400">"valid 1 day"</option>
                </select>
                <label class="check"><input type="checkbox" on:change=move |ev| reusable.set(event_target_checked(&ev)) />"Reusable"</label>
                <button class="btn btn-sm" type="submit" disabled=move || busy.get()>"New link"</button>
            </form>
            {move || minted.get().map(|url| view! {
                <div class="stack">
                    <p class="small">"Give this link only to the person it is for. It is shown once."</p>
                    <Copy value=Signal::derive(move || url.clone()) label="Access link" id=copy_id.get_value() />
                </div>
            })}
            {move || {
                let list = links.get();
                if list.is_empty() {
                    view! { <p class="muted small">"No access links."</p> }.into_any()
                } else {
                    view! {
                        <table class="table table-stack">
                            <thead><tr><th>"Link"</th><th>"Kind"</th><th>"Created"</th><th>"Expires"</th><th><span class="sr-only">"Actions"</span></th></tr></thead>
                            <tbody>
                            {list.into_iter().map(|l| {
                                let lid = l.id.clone();
                                let revoke = revoke.clone();
                                let state = match (l.single_use, l.used_at) {
                                    (true, Some(_)) => "used",
                                    (true, None) => "single use",
                                    (false, _) => "reusable",
                                };
                                let state = if l.kind == "owner" { format!("owner, {state}") } else { state.to_string() };
                                let revoke_label = format!("Revoke link {}", l.id);
                                let revoke_question = format!("Revoke link {}?", l.id);
                                view! { <tr>
                                    <td class="cell-main">
                                        <span class="mono">{l.id.clone()}</span>
                                        {l.label.clone().map(|x| view! { <div class="muted small">{x}</div> })}
                                    </td>
                                    <td data-label="Kind">{state}</td>
                                    <td data-label="Created">{relative(l.created_at)}</td>
                                    <td data-label="Expires">{relative(l.expires_at)}</td>
                                    <td class="actions"><button class="btn btn-destructive btn-sm" aria-label=revoke_label data-confirm=revoke_question on:click=move |_| revoke(lid.clone())>"Revoke"</button></td>
                                </tr> }
                            }).collect_view()}
                            </tbody>
                        </table>
                    }.into_any()
                }
            }}
        </div>
    }
}

// ----------------------------------------------------------------- machines

#[component]
fn Machines(admin: bool) -> impl IntoView {
    let all = RwSignal::new(false);
    let machines = RwSignal::new(None::<Vec<Machine>>);
    let code_error = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let needs_code = RwSignal::new(false);
    let password = RwSignal::new(String::new());
    let password_error = RwSignal::new(None::<String>);
    let needs_password = RwSignal::new(false);
    // The headless machine just added and its login code, until it is removed.
    let login_code = RwSignal::new(None::<(String, String)>);
    // A name the server refused, shown at the field.
    let name_error = RwSignal::new(None::<String>);
    let ui_origin = ctx().session.get_untracked().map(|s| s.server.ui_origin).unwrap_or_default();
    let focus_after = RwSignal::new(None::<String>);
    let load = move || {
        if busy.is_disposed() {
            return;
        }
        let path = if all.get_untracked() { "/ui/api/machines?all=true" } else { "/ui/api/machines" };
        run(error, busy, async move {
            let v = api::get(path).await?;
            machines.set(Some(serde_json::from_value(v["machines"].clone()).unwrap_or_default()));
            if let Some(id) = focus_after.try_get_untracked().flatten() {
                focus_after.set(None);
                set_timeout(
                    move || {
                        if busy.is_disposed() {
                            return;
                        }
                        if !focus_id(&id) {
                            focus_id("machine-name");
                        }
                    },
                    std::time::Duration::ZERO,
                );
            }
            Ok(())
        });
    };
    load();
    let add = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let sent = name.get();
        let mut body = json!({ "name": sent });
        if needs_code.get() {
            body["code"] = json!(code.get());
        }
        if needs_password.get() {
            body["password"] = json!(password.get());
        }
        busy.set(true);
        error.set(None);
        name_error.set(None);
        code_error.set(None);
        password_error.set(None);
        // The answer is about `sent`: a name typed since is left alone.
        let still = move || name.try_get_untracked().is_some_and(|name| name == sent);
        spawn_local(async move {
            let response = api::post("/ui/api/machines", &body).await;
            if busy.is_disposed() {
                return;
            }
            match response {
                Ok(v) => {
                    login_code.set(created_login(&v));
                    needs_code.set(false);
                    code.set(String::new());
                    needs_password.set(false);
                    password.set(String::new());
                    // Done with this name: Enter again must not ask for it twice.
                    if still() {
                        name.set(String::new());
                    }
                    load();
                }
                Err(e) if e.code == "code_required" => needs_code.set(true),
                Err(e) if e.code == "password_required" => {
                    needs_password.set(true);
                    focus_later(busy, "machine-password".into());
                }
                Err(e) if e.code == "client_exists" && still() => {
                    name_error.set(Some(e.message));
                    focus_id("machine-name");
                }
                Err(e) if field_refused(&e, "invalid_code", code_error, "machine-code") => {}
                Err(e) if field_refused(&e, "invalid_password", password_error, "machine-password") => {}
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };
    let remove = move |n: String| {
        run(error, busy, async move {
            api::delete(&format!("/ui/api/machines/{n}")).await?;
            // Its login code no longer works.
            login_code.update(|c| {
                if c.as_ref().is_some_and(|(m, _)| *m == n) {
                    *c = None;
                }
            });
            load();
            // The row is gone: the focus goes to adding one.
            if !busy.is_disposed() {
                focus_id("machine-name");
            }
            Ok(())
        });
    };
    // The machine being renamed, and the name typed so far.
    let editing = RwSignal::new(None::<String>);
    let new_name = RwSignal::new(String::new());
    let cancel_rename = move || {
        if let Some(id) = editing.get_untracked() {
            editing.set(None);
            focus_later(busy, format!("rename-machine-{id}"));
        }
    };
    let save_name = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(old) = editing.get_untracked() else { return };
        let body = json!({ "name": new_name.get_untracked().trim() });
        run(error, busy, async move {
            let v = api::patch(&format!("/ui/api/machines/{old}"), &body).await?;
            // A shown login code follows its machine's new name.
            if let Some(new) = v["name"].as_str() {
                login_code.update(|c| {
                    if let Some((m, _)) = c.as_mut().filter(|(m, _)| *m == old) {
                        *m = new.to_string();
                    }
                });
            }
            editing.set(None);
            focus_after.set(Some(format!("rename-machine-{}", v["name"].as_str().unwrap_or(&old))));
            load();
            Ok(())
        });
    };
    let login_cmd = format!("tunnel login {ui_origin}");
    view! {
        <div class="page">
            <div class="page-head">
                <div>
                    <h1>"Machines"</h1>
                    <p class="muted">"Computers signed in with the tunnel CLI. Renaming one keeps its login and tunnels; removing one stops its login and closes its tunnels."</p>
                </div>
                {admin.then(|| view! { <div class="head-actions"><ShowAll all=all what="machines" on_change=load /></div> })}
            </div>
            <ErrorBox error=error />
            <div class="grid2">
                <div class="card stack">
                    <h2>"Connect a machine"</h2>
                    <p class="muted small">"On the machine, run this and approve it in your browser:"</p>
                    <Copy value=Signal::derive(move || login_cmd.clone()) label="Login command" />
                    <p class="small"><a class="tap" href="/cli" on:click=move |ev| { ev.prevent_default(); navigate("/cli"); }>"Install the CLI first"</a></p>
                </div>
                <form class="card stack" on:submit=add>
                    <h2>"Add a headless machine"</h2>
                    <p class="muted small">"For servers without a browser: a one-time login code, valid 15 minutes."</p>
                    <div class="row row-fill">
                        <label class="sr-only" for="machine-name">"Name"</label>
                        <input id="machine-name" class="input grow" placeholder="name, e.g. ci-runner" required
                            aria-describedby="machine-name-error" aria-invalid=move || name_error.get().map(|_| "true")
                            prop:value=move || name.get() on:input=move |ev| { name_error.set(None); name.set(value(&ev)) } />
                        <button class="btn" type="submit" disabled=move || busy.get()>"Create code"</button>
                    </div>
                    <p id="machine-name-error" class="field-error" aria-live="polite">{move || name_error.get()}</p>
                    <Show when=move || needs_code.get()>
                        <CodeField id="machine-code" label="Code from your authenticator app (or a recovery code)" value=code error=code_error />
                    </Show>
                    <Show when=move || needs_password.get()>
                        <CodeField id="machine-password" label="Your password" value=password error=password_error password=true />
                    </Show>
                    {move || login_code.get().map(|(_, c)| view! {
                        <p class="small">"On that machine run " <code>"tunnel login"</code> " and paste:"</p>
                        <Copy value=Signal::derive(move || c.clone()) label="Login code" />
                    })}
                </form>
            </div>
            {move || match machines.get() {
                None => view! { <p class="muted">"Loading…"</p> }.into_any(),
                Some(list) if list.is_empty() => view! {
                    <div class="card"><Empty title="No machines yet"><p>"Connect one with the command above."</p></Empty></div>
                }.into_any(),
                Some(list) => view! {
                    <div class="card card-tight table-wrap"><table class="table table-stack">
                        <thead><tr><th>"Name"</th><th>"Account"</th><th>"Status"</th><th>"Last used"</th><th>"Tunnels"</th><th><span class="sr-only">"Actions"</span></th></tr></thead>
                        <tbody>
                        {list.into_iter().map(|m| {
                            let n = m.name.clone();
                            let (n_edit, n_row) = (m.name.clone(), m.name.clone());
                            let is_editing = move || editing.get().as_deref() == Some(n_row.as_str());
                            let shown_name = m.name.clone();
                            let (rename_label, remove_label) = (format!("Rename {}", m.name), format!("Remove {}", m.name));
                            let remove_question = format!("Remove {}? Its login and tunnels stop.", m.name);
                            view! { <tr>
                                <td class="cell-main">{move || if is_editing() {
                                    view! {
                                        <form class="row" on:submit=save_name on:keydown=move |ev| {
                                            if ev.key() == "Escape" { ev.prevent_default(); cancel_rename(); }
                                        }>
                                            <label class="sr-only" for="rename-machine">"New name"</label>
                                            <input id="rename-machine" class="input input-sm grow" required maxlength="64"
                                                pattern="[A-Za-z0-9._\\-]+" title="letters, digits, '.', '_', '-'"
                                                prop:value=move || new_name.get() on:input=move |ev| new_name.set(value(&ev)) />
                                            <button class="btn btn-sm" type="submit" disabled=move || busy.get()>"Save"</button>
                                            <button class="btn btn-ghost btn-sm" type="button" on:click=move |_| cancel_rename()>"Cancel"</button>
                                        </form>
                                    }.into_any()
                                } else {
                                    view! { <span class="name">{shown_name.clone()}</span> }.into_any()
                                }}</td>
                                <td data-label="Account">{m.user.clone()}</td>
                                <td data-label="Status">{if m.enrolled { view!{ <span class="badge badge-success">"signed in"</span> }.into_any() } else { view!{ <span class="badge badge-warning">"code not used"</span> }.into_any() }}</td>
                                <td data-label="Last used">{m.last_used_at.map(relative).unwrap_or_else(|| "never".into())}</td>
                                <td data-label="Tunnels">{m.tunnels}</td>
                                <td class="actions">
                                    <button id=format!("rename-machine-{}", m.name) class="btn btn-outline btn-sm" aria-label=rename_label on:click=move |_| { new_name.set(n_edit.clone()); editing.set(Some(n_edit.clone())); focus_later(busy, "rename-machine".into()); }>"Rename"</button>
                                    <button class="btn btn-destructive btn-sm" aria-label=remove_label data-confirm=remove_question on:click=move |_| remove(n.clone())>"Remove"</button>
                                </td>
                            </tr> }
                        }).collect_view()}
                        </tbody>
                    </table></div>
                }.into_any(),
            }}
        </div>
    }
}

// ------------------------------------------------------------------- device

#[component]
fn Device() -> impl IntoView {
    let code = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let password_error = RwSignal::new(None::<String>);
    let needs_password = RwSignal::new(false);
    let totp = RwSignal::new(String::new());
    let request = RwSignal::new(None::<DeviceRequest>);
    let needs_code = RwSignal::new(false);
    let done = RwSignal::new(None::<String>);
    let code_error = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let lookup = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "user_code": code.get() });
        run(error, busy, async move {
            let v = api::post("/ui/api/device/lookup", &body).await?;
            request.set(serde_json::from_value(v["request"].clone()).ok());
            let code_required = v["needs_code"].as_bool().unwrap_or(false);
            let password_required = v["needs_password"].as_bool().unwrap_or(false);
            needs_code.set(code_required);
            needs_password.set(password_required);
            let target = if password_required {
                "approve-password"
            } else if code_required {
                "approve-code"
            } else {
                "approve"
            };
            focus_later(busy, target.into());
            Ok(())
        });
    };
    let decide = move |approve: bool| {
        let Some(r) = request.get() else { return };
        let mut body = json!({ "user_code": r.user_code, "approve": approve });
        if approve && needs_code.get() {
            body["code"] = json!(totp.get());
        }
        if approve && needs_password.get() {
            body["password"] = json!(password.get());
        }
        password_error.set(None);
        run_code(error, busy, code_error, "approve-code", async move {
            let v = match api::post("/ui/api/device/decide", &body).await {
                Ok(v) => v,
                // The last check went stale while the page was open: ask for a code.
                Err(e) if e.code == "code_required" => {
                    needs_code.set(true);
                    focus_later(busy, "approve-code".into());
                    return Err(e);
                }
                Err(e) if e.code == "password_required" => {
                    needs_password.set(true);
                    focus_later(busy, "approve-password".into());
                    return Err(e);
                }
                Err(e) if field_refused(&e, "invalid_password", password_error, "approve-password") => return Ok(()),
                Err(e) => return Err(e),
            };
            done.set(Some(if approve {
                format!(
                    "Approved. {} is signing in; you can close this page.",
                    v["client_name"].as_str().unwrap_or("The machine")
                )
            } else {
                "Denied. The machine was not signed in.".to_string()
            }));
            password.set(String::new());
            totp.set(String::new());
            request.set(None);
            Ok(())
        });
    };
    view! {
        <div class="narrow">
            <div class="card stack">
                <h1>"Approve a machine"</h1>
                <ErrorBox error=error />
                <div role="status">{move || done.get().map(|d| view! { <div class="alert alert-success">{d}</div> })}</div>
                <Show when=move || request.get().is_none() && done.get().is_none()>
                    <form on:submit=lookup>
                        <p class="muted">"Type the code that " <code>"tunnel login"</code> " shows in your terminal. Only approve a machine you just started a login on."</p>
                        <div class="field">
                            <label for="user-code">"Code"</label>
                            <input id="user-code" class="input code-input" placeholder="XXXX-XXXX" autocomplete="off" required maxlength="12"
                                prop:value=move || code.get() on:input=move |ev| code.set(value(&ev)) />
                        </div>
                        <div class="field"><button class="btn" type="submit" disabled=move || busy.get()>"Continue"</button></div>
                    </form>
                </Show>
                {move || request.get().map(|r| view! {
                    <div class="stack">
                        <p>"This will let the machine below create tunnels as you."</p>
                        <table class="table table-kv">
                            <tr><th>"Machine"</th><td>{r.client_name.clone()}</td></tr>
                            <tr><th>"Address"</th><td>{r.ip.clone().unwrap_or_else(|| "unknown".into())}</td></tr>
                            <tr><th>"Requested"</th><td>{relative(r.created_at)}</td></tr>
                        </table>
                        <p class="muted small">"If you did not start this login, deny it."</p>
                        <Show when=move || needs_code.get()>
                            <CodeField id="approve-code" label="Code from your authenticator app (or a recovery code)" value=totp error=code_error />
                        </Show>
                        <Show when=move || needs_password.get()>
                            <CodeField id="approve-password" label="Your password" value=password error=password_error password=true />
                        </Show>
                        <div class="row">
                            <button id="approve" class="btn" disabled=move || busy.get() on:click=move |_| decide(true)>"Approve"</button>
                            <button class="btn btn-outline" disabled=move || busy.get() on:click=move |_| decide(false)>"Deny"</button>
                        </div>
                    </div>
                })}
            </div>
        </div>
    }
}

// ---------------------------------------------------------------------- cli

#[component]
fn Cli() -> impl IntoView {
    let info = RwSignal::new(None::<Value>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    run(error, busy, async move {
        info.set(Some(api::get("/ui/api/cli").await?));
        Ok(())
    });
    let s = move |k: &'static str| {
        Signal::derive(move || info.get().and_then(|v| v[k].as_str().map(str::to_string)).unwrap_or_default())
    };
    view! {
        <div class="page">
            <div class="page-head"><div>
                <h1>"Get the CLI"</h1>
                <p class="muted">{move || format!("tunnel {} for Linux and macOS.", s("version").get())}</p>
            </div></div>
            <ErrorBox error=error />
            <div class="card stack">
                <h2>"Install script"</h2>
                <p class="muted small">"Downloads this server's version from GitHub, installs it only if it matches the release's sha256.sum, then signs this machine in through your browser. Piping a script into a shell means trusting this server's operator; use the manual path below if you prefer."</p>
                <Copy value=s("install_sh") label="Install command" />
            </div>
            <div class="grid2">
                <div class="card stack">
                    <h2>"Homebrew (macOS)"</h2>
                    <Copy value=s("brew") label="Homebrew command" />
                    <p class="muted small">"Then:"</p>
                    <Copy value=s("login") label="Login command" />
                </div>
                <div class="card stack">
                    <h2>"Windows"</h2>
                    <p class="muted small">"tunnel needs Unix; use WSL and the install script above."</p>
                </div>
            </div>
            <div class="card stack">
                <h2>"Manual download"</h2>
                <p class="small">"Download " <code>"tunnel-<target>.tar.xz"</code> " and " <code>"sha256.sum"</code> " from the "
                    <a href=move || s("release_url").get() rel="noopener noreferrer">"release page"</a> ", then check them:"</p>
                <Copy value=Signal::derive(|| "sha256sum --ignore-missing -c sha256.sum".to_string()) label="Checksum command" />
                <p class="small">"Optionally verify the build provenance with the GitHub CLI:"</p>
                <Copy value=Signal::derive(|| "gh attestation verify tunnel-<target>.tar.xz --repo FlyCockpit/tunnel".to_string()) label="Attestation command" />
                <p class="small">"Unpack it, put " <code>"tunnel"</code> " on your PATH, and run:"</p>
                <Copy value=s("login") label="Login command" />
            </div>
            <div class="card stack">
                <h2>"From source"</h2>
                <Copy value=Signal::derive(move || format!("cargo install --git https://github.com/FlyCockpit/tunnel --tag v{} --locked tunnel-client", s("version").get())) label="Cargo command" />
            </div>
            <div class="card stack">
                <h2>"Then"</h2>
                <p class="small"><code>"tunnel share 3000"</code> " prints a one-time link to your local port 3000. "
                    <code>"tunnel link"</code> " makes another, " <code>"tunnel unshare"</code> " ends sharing. "
                    "Agents can follow " <code>"tunnel help agent"</code> "."</p>
            </div>
        </div>
    }
}

// -------------------------------------------------------------------- admin

/// The Users page's notice of the last change in the table; a saved limits
/// editor leaves the focus here when its row's Limits button is gone.
const NOTICE_ID: &str = "users-notice";

/// What a Users row's buttons depend on: they are drawn anew only when it
/// changes, so a reload that changes only numbers keeps them (and the focus).
#[derive(Clone, PartialEq)]
struct RowShape {
    /// Whether this admin may change the user (not the owner, not themselves,
    /// admins only by the owner).
    editable: bool,
    disabled: bool,
    role: String,
    name: String,
}

/// Whether an editor opened on `before` (none: this is the first look) no
/// longer matches the user's limits `now`. Usage (tunnels, machines, traffic)
/// is not part of them, so it never closes an editor.
fn outdated(before: Option<&Limits>, now: &Limits) -> bool {
    before.is_some_and(|b| b != now)
}

impl RowShape {
    fn of(u: &User, me: &str, owner: bool) -> Self {
        Self {
            editable: u.role != "owner" && u.id != me && (owner || u.role == "member"),
            disabled: u.disabled,
            role: u.role.clone(),
            name: u.username.clone(),
        }
    }
}

#[component]
fn Users(me: User) -> impl IntoView {
    let users = RwSignal::new(Vec::<UserRow>::new());
    let invites = RwSignal::new(Vec::<Invite>::new());
    let services = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let role = RwSignal::new("member".to_string());
    let invite_email = RwSignal::new(String::new());
    let mail = ctx().session.get_untracked().is_some_and(|s| s.server.mail);
    let new_url = RwSignal::new(None::<String>);
    let mailed_to = RwSignal::new(None::<String>);
    let month = RwSignal::new(String::new());
    // Open reset panels and the links made in them, by user id: kept outside
    // the rows, which every reload renders anew.
    let resets = RwSignal::new(std::collections::HashMap::<String, Option<String>>::new());
    // What the last change in the table did ("Saved the limits of member1.").
    let notice = RwSignal::new(None::<String>);
    // A limits save in flight (any user's); only limits saves set or clear it.
    let saving_limits = RwSignal::new(false);
    // Loading the lists does not disable the invite button (only a submit in flight does).
    let loading = RwSignal::new(false);
    // The three lists appear together once all are fetched (`listed`), so
    // they never push each other down while the page loads.
    let listed = RwSignal::new(false);
    // Only the latest reload shows its lists: an older one that returns later
    // would put back what a newer change (a limits save) already replaced.
    let generation = StoredValue::new(0u64);
    let load = move || {
        let Some(previous) = generation.try_get_value() else { return };
        let this = previous + 1;
        generation.set_value(this);
        run(error, loading, async move {
            let u = api::get("/ui/api/users").await;
            let i = api::get("/ui/api/invites").await;
            let s = api::get("/ui/api/services").await;
            if generation.try_get_value() != Some(this) {
                return Ok(());
            }
            // Each list that arrived is shown, even when another failed (its
            // error then shows above them).
            if let Ok(u) = &u {
                users.set(serde_json::from_value(u["users"].clone()).unwrap_or_default());
                month.set(u["month"].as_str().unwrap_or_default().to_string());
            }
            if let Ok(i) = &i {
                invites.set(serde_json::from_value(i["invites"].clone()).unwrap_or_default());
            }
            if let Ok(s) = &s {
                services.set(serde_json::from_value(s["services"].clone()).unwrap_or_default());
            }
            listed.set(true);
            u.and(i).and(s).map(|_| ())
        });
    };
    load();
    let invite = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let to = invite_email.get().trim().to_string();
        let mut body = json!({ "role": role.get() });
        if !to.is_empty() {
            body["email"] = json!(to);
        }
        run(error, busy, async move {
            let v = api::post("/ui/api/invites", &body).await?;
            new_url.set(v["url"].as_str().map(str::to_string));
            mailed_to.set((v["mailed"].as_bool() == Some(true)).then_some(to));
            invite_email.set(String::new());
            load();
            Ok(())
        });
    };
    let update = move |id: String, body: Value| {
        run(error, busy, async move {
            let v = api::patch(&format!("/ui/api/users/{id}"), &body).await?;
            if body.get("role").is_some() {
                let name = v["user"]["username"].as_str().unwrap_or_default();
                let role = if v["user"]["role"] == "admin" { "an admin" } else { "a member" };
                notice.set(Some(format!("{name} is now {role}.")));
            }
            load();
            Ok(())
        });
    };
    let reset_traffic = move |id: String| {
        run(error, busy, async move {
            api::post(&format!("/ui/api/users/{id}/traffic/reset"), &json!({})).await?;
            load();
            Ok(())
        });
    };
    let revoke_invite = move |id: String| {
        run(error, busy, async move {
            api::delete(&format!("/ui/api/invites/{id}")).await?;
            load();
            Ok(())
        });
    };
    let owner = me.role == "owner";
    let me_id = me.id.clone();
    view! {
        // Until the lists are in, the page fills the screen (as its first-paint
        // placeholder does), so lists longer than the screen push nothing the
        // reader sees: the footer starts below the fold.
        <div class="page page-wide" class:page-fill=move || !listed.get()>
            <div class="page-head"><div>
                <h1>"Users"</h1>
                <p class="muted">"Invite people with a single-use link. Members see only their own machines and tunnels. Reset sign-in makes a link for someone who is locked out."</p>
            </div></div>
            <ErrorBox error=error />
            <form class="card stack" on:submit=invite>
                <h2>"Invite someone"</h2>
                <div class="row">
                    <label class="sr-only" for="invite-role">"Role"</label>
                    <select id="invite-role" class="input w-auto" on:change=move |ev| role.set(value(&ev))>
                        <option value="member">"Member"</option>
                        {owner.then(|| view! { <option value="admin">"Admin"</option> })}
                    </select>
                    {mail.then(|| view! {
                        <label class="sr-only" for="invite-email">"Email (optional)"</label>
                        <input id="invite-email" class="input w-auto" type="email" placeholder="Email (optional)" maxlength="254"
                            prop:value=move || invite_email.get() on:input=move |ev| invite_email.set(value(&ev)) />
                    })}
                    <button class="btn" type="submit" disabled=move || busy.get()>"Create invite link"</button>
                </div>
                {move || new_url.get().map(|u| view! {
                    <p class="small">{match mailed_to.get() {
                        Some(to) => format!("Mailed to {to}; signing up with it confirms the address. You can also copy the link; it works once, for 7 days."),
                        None => "Send this link to the person you invite; it works once, for 7 days.".to_string(),
                    }}</p>
                    <Copy value=Signal::derive(move || u.clone()) label="Invite link" />
                })}
            </form>
            <div id=NOTICE_ID role="status" tabindex="-1">{move || notice.get().map(|n| view! { <div class="alert alert-success">{n}</div> })}</div>
            <Show when=move || !listed.get() && error.get().is_none()><p class="muted">"Loading…"</p></Show>
            <div class:pending=move || !listed.get()>
            <div class="card card-tight table-wrap">
                <table class="table table-stack table-stack-md">
                    <thead><tr><th>"User"</th><th>"Role"</th><th>"Machines"</th><th>"Tunnels"</th>
                        <th>{move || format!("Traffic {}", month.get())}</th><th>"Public previews"</th><th>"2FA"</th><th><span class="sr-only">"Actions"</span></th></tr></thead>
                    <tbody>
                    // Keyed by the user, not the row's data: a reload updates a row's cells in
                    // place, so its buttons, its open panels (and what is typed in them) and
                    // the keyboard focus stay. Only the buttons follow the row's shape
                    // (role, disabled, name), which a limits save or a usage change keeps.
                    <For each=move || users.get() key=|row: &UserRow| row.user.id.clone() children=move |first: UserRow| {
                        let id = first.user.id.clone();
                        // The row as last listed (a removed user's keeps its data until it goes).
                        let row = Memo::new({
                            let id = id.clone();
                            move |prev: Option<&UserRow>| {
                                users.with(|all| all.iter().find(|r| r.user.id == id).cloned())
                                    .or_else(|| prev.cloned())
                                    .unwrap_or_else(|| first.clone())
                            }
                        });
                        let shape = Memo::new({
                            let me_id = me_id.clone();
                            move |_| row.with(|r| RowShape::of(&r.user, &me_id, owner))
                        });
                        let editing = RwSignal::new(false);
                        let resetting = Memo::new({ let id = id.clone(); move |_| resets.with(|r| r.contains_key(&id)) });
                        let opener = StoredValue::new(crate::limits::opener_id(&id));
                        // Closes the row's editor; the focus, when it was in there (or
                        // lost), goes to the row's Limits button (the row stays, so it is
                        // still there), else to the notice. The row may be gone already.
                        let close = move |focus: FocusAt| {
                            if notice.is_disposed() { return; }
                            editing.try_set(false);
                            if focus.needs_a_place() && !opener.try_with_value(|o| focus_id(o)).unwrap_or(false) {
                                focus_id(NOTICE_ID);
                            }
                        };
                        // A save closes the editor (also one reopened while it was on its
                        // way: that one showed the limits from before it) and shows the
                        // saved user at once, so the editor opens on them even before
                        // the reload is back.
                        let saved = move |name: String, user: Option<User>, focus: FocusAt| {
                            if notice.is_disposed() { return; }
                            notice.set(Some(format!("Saved the limits of {name}.")));
                            close(focus);
                            if let Some(user) = user {
                                users.update(|all| all.iter_mut().filter(|r| r.user.id == user.id).for_each(|r| r.user = user.clone()));
                            }
                            load();
                        };
                        // Limits that change under an open editor (a role change, another
                        // admin) close it: what it would compare against is gone.
                        Effect::new({
                            let id = id.clone();
                            move |prev: Option<Limits>| {
                                let now = row.with(|r| r.user.limits.clone());
                                if outdated(prev.as_ref(), &now) && editing.get_untracked() {
                                    let name = row.with_untracked(|r| r.user.username.clone());
                                    notice.set(Some(format!("The limits of {name} changed meanwhile; open Limits to change them again.")));
                                    close(FocusAt::in_editor(&id));
                                }
                                now
                            }
                        });
                        let id = StoredValue::new(id);
                        view! { <tr>
                            <td class="cell-main">{move || row.with(|r| {
                                let u = &r.user;
                                view! {
                                    <span class="name">{u.username.clone()}</span>{u.disabled.then(|| view! { " " <span class="badge badge-danger">"disabled"</span> })}
                                    {u.email.clone().map(|e| view! { <div class="muted small break">{e}</div> })}
                                }
                            })}</td>
                            <td data-label="Role">{move || row.with(|r| r.user.role.clone())}</td>
                            <td data-label="Machines">{move || row.with(|r| used_of(r.clients.max(0) as u64, r.user.limits.machines.effective))}</td>
                            <td data-label="Tunnels">{move || row.with(|r| used_of(r.tunnels.max(0) as u64, r.user.limits.tunnels.effective))}
                                <div class="muted small">{move || row.with(|r| format!("lifetime {}", r.user.limits.tunnel_ttl_s.effective.map(duration_text).unwrap_or_else(|| "unlimited".into())))}</div></td>
                            <td data-label="Traffic">
                                <div>{move || row.with(|r| {
                                    let cap = r.user.limits.traffic_bytes.effective;
                                    let limited = cap.is_some_and(|c| r.traffic_bytes >= c);
                                    view! { {traffic_text(r.traffic_bytes, cap)}
                                        {limited.then(|| view! { " " <span class="badge badge-danger">"limit reached"</span> })} }
                                })}</div>
                                {move || shape.get().editable.then(|| view! {
                                    <button class="btn btn-ghost btn-sm" type="button" disabled=move || busy.get()
                                        aria-label=format!("Reset month for {}", shape.get().name) on:click=move |_| reset_traffic(id.get_value())>"Reset month"</button>
                                })}
                            </td>
                            <td data-label="Public previews">{move || {
                                let s = shape.get();
                                if s.role != "member" {
                                    view! { "admin" }.into_any()
                                } else if s.editable { view! {
                                    <label class="check"><input type="checkbox" aria-label=format!("Public previews allowed for {}", s.name) prop:checked=move || row.with(|r| r.user.can_public)
                                        on:change=move |ev| update(id.get_value(), json!({ "can_public": event_target_checked(&ev) })) />"allowed"</label>
                                }.into_any() } else {
                                    view! { {move || if row.with(|r| r.user.can_public) { "allowed" } else { "no" }} }.into_any()
                                }
                            }}</td>
                            <td data-label="2FA">{move || if row.with(|r| r.user.totp) { "on" } else { "off" }}</td>
                            <td class="actions actions-fold">{move || {
                                let s = shape.get();
                                let is_admin = s.role == "admin";
                                let (disabled, name) = (s.disabled, s.name);
                                s.editable.then(|| view! {
                                <button id=opener.get_value() class="btn btn-outline btn-sm" aria-expanded=move || editing.get().to_string()
                                    aria-label=format!("Limits for {name}")
                                    on:click=move |_| { notice.set(None); editing.update(|e| *e = !*e); }>"Limits"</button>" "
                                {(!disabled).then(|| view! {
                                    <button class="btn btn-outline btn-sm" aria-expanded=move || resetting.get().to_string()
                                        aria-label=format!("Reset sign-in for {name}")
                                        on:click=move |_| resets.update(|r| {
                                            if r.remove(&id.get_value()).is_none() {
                                                r.insert(id.get_value(), None);
                                            }
                                        })>"Reset sign-in"</button>" "
                                })}
                                {(owner && !disabled).then(|| view! {
                                    <button class="btn btn-outline btn-sm" aria-label=if is_admin { format!("Make member {name}") } else { format!("Make admin {name}") }
                                        data-confirm=role_question(&name, is_admin, mail)
                                        on:click=move |_| update(id.get_value(), json!({ "role": if is_admin { "member" } else { "admin" } }))>
                                        {if is_admin { "Make member" } else { "Make admin" }}
                                    </button>" "
                                })}
                                <button class=if disabled { "btn btn-outline btn-sm" } else { "btn btn-destructive btn-sm" }
                                    aria-label=if disabled { format!("Enable {name}") } else { format!("Disable {name}") }
                                    data-confirm=(!disabled).then(|| format!("Disable {name}? Their sessions end, their machines are removed and their tunnels close."))
                                    on:click=move |_| update(id.get_value(), json!({ "disabled": !disabled }))>
                                    {if disabled { "Enable" } else { "Disable" }}
                                </button>
                            })}}</td>
                        </tr>
                        // The panels take the row as it was when they opened.
                        {move || editing.get().then(|| row.with_untracked(|r| view! {
                            <tr class="limits-row panel-row"><td colspan="8" class="links-panel">
                                <LimitsEditor id=id.get_value() username=r.user.username.clone() limits=r.user.limits.clone() open=editing saving=saving_limits saved=saved />
                            </td></tr>
                        }))}
                        {move || resetting.get().then(|| row.with_untracked(|r| view! {
                            <tr class="panel-row"><td colspan="8" class="links-panel">
                                <ResetPanel id=id.get_value() username=r.user.username.clone() email=r.user.email.clone().filter(|_| mail) resets=resets reload=load />
                            </td></tr>
                        }))}
                        }
                    } />
                    </tbody>
                </table>
            </div>
            <div class="card card-tight table-wrap">
                <h2 class="card-head">"Invites"</h2>
                <table class="table table-stack">
                    <thead><tr><th>"Link"</th><th>"By"</th><th>"Created"</th><th>"Status"</th><th><span class="sr-only">"Actions"</span></th></tr></thead>
                    <tbody>
                    {move || invites.get().into_iter().map(|i| {
                        let id = i.id.clone();
                        let open = i.used_at.is_none() && i.expires_at > (js_sys::Date::now() / 1000.0) as i64;
                        let revocable = open && i.revocable;
                        let status = match (&i.used_by, open) {
                            (Some(u), _) => format!("used by {u}"),
                            (None, true) => format!("open, expires {}", relative(i.expires_at)),
                            (None, false) => "expired".into(),
                        };
                        let link = if i.kind == "account_reset" {
                            format!("sign-in reset for {}", i.user.clone().unwrap_or_default())
                        } else {
                            format!("{} invite", i.role)
                        };
                        let what = i.email.as_ref().map_or_else(|| link.clone(), |e| format!("{link} for {e}"));
                        view! { <tr>
                            <td class="cell-main">{link}{i.email.clone().map(|e| view! { <div class="muted small break">{format!("for {e}")}</div> })}</td>
                            <td data-label="By">{i.created_by.clone().unwrap_or_else(|| "—".into())}</td>
                            <td data-label="Created">{relative(i.created_at)}</td>
                            <td data-label="Status">{status}</td>
                            <td class="actions">{revocable.then(|| view! {
                                <button class="btn btn-outline btn-sm" aria-label=format!("Revoke {what}") data-confirm=format!("Revoke {what}? The link stops working.") on:click=move |_| revoke_invite(id.clone())>"Revoke"</button>
                            })}</td>
                        </tr> }
                    }).collect_view()}
                    </tbody>
                </table>
            </div>
            <div class="card stack">
                <h2>"Service credentials"</h2>
                <p class="muted small">"API-only credentials for platforms (created with " <code>"tunnel-server service add"</code> "). Member limits do not apply to them."</p>
                {move || {
                    let list = services.get();
                    if list.is_empty() { view! { <p class="muted small">"None."</p> }.into_any() } else {
                        view! { <table class="table table-stack">
                            <thead><tr><th>"Name"</th><th>"Tunnels"</th><th>"Last used"</th></tr></thead>
                            <tbody>{list.into_iter().map(|s| view! { <tr>
                                <td class="cell-main">{s["name"].as_str().unwrap_or_default().to_string()}</td>
                                <td data-label="Tunnels">{format!("{} / {}", s["tunnels"], s["max_tunnels"])}</td>
                                <td data-label="Last used">{s["last_used_at"].as_i64().map(relative).unwrap_or_else(|| "never".into())}</td>
                            </tr> }).collect_view()}</tbody>
                        </table> }.into_any()
                    }
                }}
            </div>
            </div>
        </div>
    }
}

fn role_question(name: &str, was_admin: bool, mail: bool) -> String {
    let role = if was_admin { "a member" } else { "an admin" };
    let defaults = if was_admin { "member" } else { "admin" };
    let mut question = format!(
        "Make {name} {role}? Their sessions end and their limits reset to the {defaults} defaults. Tunnels beyond the new lifetime limit end sooner."
    );
    if was_admin {
        question.push_str(" Their public-preview permission and unused invites are removed; public tunnels require access links unless the server allows public previews for everyone.");
    }
    if !was_admin {
        question.push_str(" They can invite and manage members, see every tunnel and allow public previews.");
    }
    if mail {
        question.push_str(" A notice is mailed to their confirmed email address, if they have one.");
    }
    question
}

/// Users: make a sign-in reset link for one account and show it once. Which
/// panels are open, and their links, live in `resets` (by user id); the rows
/// are keyed, so other rows' changes leave this panel (and its form) alone.
#[component]
fn ResetPanel<F>(
    id: String,
    username: String,
    /// The account's confirmed address, when the server sends mail.
    email: Option<String>,
    resets: RwSignal<std::collections::HashMap<String, Option<String>>>,
    reload: F,
) -> impl IntoView
where
    F: Fn() + Copy + Send + Sync + 'static,
{
    let code_error = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let needs_code = RwSignal::new(false);
    let code = RwSignal::new(String::new());
    let code_id = format!("reset-code-{id}");
    let copy_id = StoredValue::new(format!("reset-copy-{id}"));
    let send = RwSignal::new(email.is_some());
    let mailed = RwSignal::new(None::<String>);
    let email2 = email.clone();
    let url = Memo::new({
        let id = id.clone();
        move |_| resets.with(|r| r.get(&id).cloned().flatten())
    });
    let close = {
        let id = id.clone();
        move || {
            resets.update(|r| {
                r.remove(&id);
            })
        }
    };
    let field_id = StoredValue::new(code_id.clone());
    let create = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let mut body = json!({});
        if needs_code.get_untracked() {
            body["code"] = json!(code.get_untracked());
        }
        let to = email.clone().filter(|_| send.get_untracked());
        if to.is_some() {
            body["send_email"] = json!(true);
        }
        let path = format!("/ui/api/users/{id}/reset");
        let id = id.clone();
        busy.set(true);
        error.set(None);
        code_error.set(None);
        let copy_focus = copy_id.get_value();
        let field_focus = field_id.get_value();
        spawn_local(async move {
            let response = api::post(&path, &body).await;
            // Cancel may dispose this panel while its request is in flight.
            if busy.is_disposed() {
                return;
            }
            match response {
                Ok(v) => {
                    let made = v["url"].as_str().map(str::to_string);
                    mailed.set(to.filter(|_| v["mailed"].as_bool() == Some(true)));
                    resets.update(|r| {
                        r.insert(id, made);
                    });
                    needs_code.set(false);
                    code.set(String::new());
                    reload();
                    focus_later(busy, copy_focus);
                }
                Err(e) if e.code == "code_required" => {
                    needs_code.set(true);
                    error.set(Some(e.message));
                }
                Err(e) if field_refused(&e, "invalid_code", code_error, &field_focus) => {}
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };
    let (name1, name2) = (username.clone(), username);
    view! {
        <div class="stack">
            <ErrorBox error=error />
            {move || match url.get() {
                Some(u) => view! {
                    <p class="small">{match mailed.get() {
                        Some(to) => format!("Mailed to {to}. You can also hand it over: it works once, within an hour, and is a credential."),
                        None => format!("Send this link to {name1}; it works once, within an hour, and is a credential."),
                    }}</p>
                    <Copy value=Signal::derive(move || u.clone()) label="Reset link" id=copy_id.get_value() />
                    <div><button class="btn btn-outline btn-sm" type="button" on:click={
                        let close = close.clone();
                        move |_| close()
                    }>"Done"</button></div>
                }.into_any(),
                None => {
                    let code_id = code_id.clone();
                    view! {
                        <form class="stack" on:submit=create.clone()>
                            <p class="small">{format!(
                                "A single-use link lets {name2} choose a new password. Their two-factor sign-in and recovery codes are turned off and all their sessions end; all their machines are signed out and their tunnels end. Sign machines in again with tunnel login. It works for one hour; hand it over as you would an invite."
                            )}</p>
                            {email2.clone().map(|e| view! {
                                <label class="check">
                                    <input type="checkbox" prop:checked=move || send.get() on:change=move |ev| send.set(event_target_checked(&ev)) />
                                    {format!("Also mail it to {e}")}
                                </label>
                            })}
                            {move || needs_code.get().then(|| {
                                let code_id = code_id.clone();
                                view! {
                                    <CodeField id=code_id label="Code from your authenticator app (or a recovery code)" value=code error=code_error />
                                }
                            })}
                            <div class="row">
                                <button class="btn btn-sm" type="submit" disabled=move || busy.get()>"Create reset link"</button>
                                <button class="btn btn-outline btn-sm" type="button" on:click={
                                    let close = close.clone();
                                    move |_| close()
                                }>"Cancel"</button>
                            </div>
                        </form>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn Status() -> impl IntoView {
    let status = RwSignal::new(None::<Value>);
    let audit = RwSignal::new(Vec::<AuditEntry>::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    run(error, busy, async move {
        status.set(Some(api::get("/ui/api/status").await?));
        let a = api::get("/ui/api/audit").await?;
        audit.set(serde_json::from_value(a["entries"].clone()).unwrap_or_default());
        Ok(())
    });
    let field = move |path: &'static [&'static str]| {
        move || {
            let mut v = status.get().unwrap_or(Value::Null);
            for p in path {
                v = v[*p].clone();
            }
            match v {
                Value::String(s) => s,
                Value::Null => "—".into(),
                Value::Bool(on) => if on { "On" } else { "Off" }.into(),
                other => other.to_string(),
            }
        }
    };
    view! {
        <div class="page">
            <div class="page-head"><div><h1>"Server"</h1></div></div>
            <ErrorBox error=error />
            <Show when=move || status.get().is_some_and(|s| s["same_site"].as_bool() == Some(true))>
                <div class="alert alert-warning">
                    "Previews share this UI's registrable domain. That is fine for a server only you use; when others use it, move previews to a separate domain (see the README's \"Hosts and domains\")."
                </div>
            </Show>
            <div class="grid2">
                <div class="card stack">
                    <h2>"Hosts"</h2>
                    <table class="table table-kv">
                        <tr><th>"Version"</th><td>{field(&["version"])}</td></tr>
                        <tr><th>"Web UI"</th><td>{field(&["hosts", "ui"])}</td></tr>
                        <tr><th>"API"</th><td>{field(&["hosts", "api"])}</td></tr>
                        <tr><th>"Tunnel connections"</th><td>{field(&["hosts", "tunnel"])}</td></tr>
                        <tr><th>"Previews"</th><td>{move || format!("*.{}", field(&["hosts", "preview_zone"])())}</td></tr>
                        <tr><th>"Certificate until"</th><td>{move || status.get().and_then(|s| s["certificate_not_after"].as_i64()).map(when).unwrap_or_else(|| "—".into())}</td></tr>
                        <tr><th>"WebRTC relay"</th><td>{field(&["webrtc"])}</td></tr>
                    </table>
                </div>
                <div class="card stack">
                    <h2>"Usage and limits"</h2>
                    <table class="table table-kv">
                        <tr><th>"Connected tunnels"</th><td>{field(&["connected_tunnels"])}</td></tr>
                        <tr><th>"Tunnels"</th><td>{field(&["counts", "tunnels"])}</td></tr>
                        <tr><th>"Access links"</th><td>{field(&["counts", "access_links"])}</td></tr>
                        <tr><th>"Members' default tunnels / machines"</th><td>{move || format!("{} / {}", field(&["limits", "member_max_tunnels"])(), field(&["limits", "member_max_clients"])())}</td></tr>
                        <tr><th>"Members' default tunnel lifetime"</th><td>{move || status.get()
                            .and_then(|s| Some(s["limits"]["member_max_tunnel_ttl_s"].as_u64()?.min(s["limits"]["max_tunnel_ttl_s"].as_u64()?)))
                            .map(duration_text)
                            .unwrap_or_default()}</td></tr>
                        <tr><th>"Public previews for everyone"</th><td>{field(&["limits", "allow_public_for_clients"])}</td></tr>
                        <tr><th>"Members' default monthly traffic"</th><td>{move || status.get()
                            .and_then(|s| s["limits"]["member_monthly_traffic_gb"].as_u64())
                            .map(|gb| format!("{gb} GB"))
                            .unwrap_or_else(|| "no cap".into())}</td></tr>
                    </table>
                </div>
            </div>
            <MailStatus status=status />
            <div class="card card-tight table-wrap">
                <h2 class="card-head">"Audit log"</h2>
                <table class="table table-stack">
                    <thead><tr><th>"What"</th><th>"When"</th><th>"Who"</th><th>"Target"</th><th>"Address"</th></tr></thead>
                    <tbody>
                    {move || audit.get().into_iter().map(|e| view! { <tr>
                        <td class="cell-main">{e.action.replace('_', " ")}</td>
                        <td data-label="When">{when(e.at)}</td>
                        <td data-label="Who">{e.user.clone().unwrap_or_else(|| "—".into())}</td>
                        <td data-label="Target" class="mono small break">{e.target.clone().unwrap_or_default()}</td>
                        <td data-label="Address">{e.ip.clone().unwrap_or_default()}</td>
                    </tr> }).collect_view()}
                    </tbody>
                </table>
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ui::source_body as body;

    /// Every page names itself with one real h1 (the 404 included), and no
    /// element stands in for a heading through an ARIA role.
    #[test]
    fn every_page_has_one_h1() {
        let src = include_str!("pages.rs");
        let route = body(src, "route");
        let pages: Vec<&str> = route
            .match_indices("view! { <")
            .map(|(i, _)| {
                let name = &route[i + 9..];
                &name[..name.find([' ', '/']).unwrap()]
            })
            .filter(|n| *n != "div")
            .collect();
        // Every view the router returns is one of these or the 404 (a new
        // route, or one written another way, fails here until it is listed).
        assert_eq!(
            pages,
            ["InvitePage", "SignIn", "Tunnels", "Machines", "Device", "Cli", "Account", "Users", "Status"]
        );
        let arms = route.matches(" => ").count() + route.matches("return ").count();
        assert_eq!(arms, pages.len() + 1, "one listed page per route arm, plus the 404");
        assert_eq!(route.matches("view! {").count(), arms, "one view per route arm");
        for page in pages {
            let source = match page {
                "InvitePage" | "SignIn" => include_str!("auth.rs"),
                "Account" => include_str!("account.rs"),
                _ => src,
            };
            assert_eq!(body(source, page).matches("<h1").count(), 1, "{page}");
        }
        let (_, not_found) = route.split_once("_ => view!").expect("route has a fallback");
        assert_eq!(not_found.matches("<h1>").count(), 1, "the 404 page");
        // Sign-in's other state, Forgot password, replaces the whole card.
        assert!(body(include_str!("auth.rs"), "SignIn").contains("<ForgotPassword "));
        assert_eq!(body(include_str!("email.rs"), "ForgotPassword").matches("<h1>").count(), 1, "ForgotPassword");
        for (file, text) in
            [("pages.rs", src), ("email.rs", include_str!("email.rs")), ("ui.rs", include_str!("ui.rs"))]
        {
            assert!(!text.contains(concat!("role=", "\"heading\"")), "{file}");
        }
    }

    /// This file without its tests, so a check cannot match its own text.
    fn source() -> &'static str {
        include_str!("pages.rs").split("#[cfg(test)]").next().unwrap()
    }

    /// A refused two-factor code is said at the code field (next to Turn on),
    /// not in the page's error box at the top; typing or Not now clears it.
    #[test]
    fn a_refused_two_factor_code_is_said_at_the_field() {
        for (page, id, busy) in
            [("SignIn", "code", "busy"), ("InvitePage", "reset-code", "busy"), ("Account", "totp-code", "enabling")]
        {
            let source = if page == "Account" { include_str!("account.rs") } else { include_str!("auth.rs") };
            let page = body(source, page);
            assert!(page.contains(&format!("run_code(error, {busy}, code_error, \"{id}\"")));
            assert!(page.contains(&format!("<CodeField id=\"{id}\"")));
        }
        let ui = include_str!("ui.rs");
        assert!(ui.contains("aria-describedby=described.clone() aria-invalid=move || error.get().map(|_| \"true\")"));
        assert!(ui.contains("error.set(None); value.set(event_target_value(&ev))"));
        assert!(ui.contains("class=\"field-error\" aria-live=\"polite\""));
        assert!(ui.contains(r#"let described = format!("{id}-error")"#));
        assert!(ui.contains("field_refused(&e, \"invalid_code\", field, id)"));
        let account = include_str!("account.rs");
        let not_now = &account[account.find(r#""Turn on""#).unwrap()..];
        assert!(not_now[..not_now.find(r#""Not now""#).unwrap()].contains("code_error.set(None)"));
    }

    #[test]
    fn admin_reset_panel_explains_machine_sign_out() {
        let panel = body(source(), "ResetPanel");
        assert!(panel.contains("all their machines are signed out and their tunnels end."));
        assert!(panel.contains("Sign machines in again with tunnel login."));
        assert!(!panel.contains("machines stay"));
    }

    /// Row buttons name their user without reading out the internal id.
    #[test]
    fn user_row_buttons_name_the_user() {
        let src = source();
        assert!(src.contains(r#"aria-label=format!("Limits for {name}")"#));
        assert!(src.contains(r#"format!("Enable {name}") } else { format!("Disable {name}")"#));
        assert!(src.contains(r#"format!("Make member {name}") } else { format!("Make admin {name}")"#));
        assert!(src.contains(r#"aria-label=format!("Reset month for {}", shape.get().name)"#));
        assert!(src.contains(r#"aria-label=format!("Public previews allowed for {}", s.name)"#));
        assert!(!src.contains(r#"<span class="sr-only">{id.get_value()}</span>"#));
    }

    /// Notices that appear in place (Account, machine approval) are announced.
    #[test]
    fn in_place_notices_are_announced() {
        let src = source();
        assert!(include_str!("account.rs").contains(r#"<div role="status">{move || notice.get().map(|n| view! { <div class="alert alert-success">{n}</div> })}</div>"#));
        assert!(src.contains(r#"<div role="status">{move || done.get().map(|d| view! { <div class="alert alert-success">{d}</div> })}</div>"#));
    }

    /// Two-factor setup can be left without turning it on.

    #[test]
    fn in_place_steps_leave_focus_on_the_next_control() {
        let src = source();
        let account = body(include_str!("account.rs"), "Account");
        let start = &account[account.find("let start_totp").unwrap()..account.find("let confirm_totp").unwrap()];
        assert!(start.contains(r#"focus_later(starting, "totp-code".into())"#));
        for page in ["Links", "ResetPanel"] {
            let page = body(src, page);
            assert!(page.contains("let copy_focus = copy_id.get_value();"));
            assert!(page.contains("focus_later(busy, copy_focus)"));
            assert!(page.contains("id=copy_id.get_value()"));
        }
        let tunnels = body(src, "Tunnels");
        let delete = &tunnels[tunnels.find("let delete").unwrap()..tunnels.find("let editing").unwrap()];
        assert!(delete.contains("list.get(at + 1)"));
        assert!(delete.contains("focus_after.set(Some(next))"));
        assert!(delete.contains(r#"unwrap_or_else(|| "tunnels-title".into())"#));
        assert!(tunnels.contains(r#"<h1 id="tunnels-title" tabindex="-1">"#));
        assert!(tunnels.contains("if !focus_id(&id)"));
        let device = body(src, "Device");
        for id in ["approve-password", "approve-code", "approve"] {
            assert!(device.contains(&format!(r#""{id}""#)));
        }
        assert!(device.contains("focus_later(busy, target.into())"));
        assert!(device.contains(r#"<button id="approve""#));
        let machines = body(src, "Machines");
        assert!(
            machines
                .contains(r#"focus_after.set(Some(format!("rename-machine-{}", v["name"].as_str().unwrap_or(&old))))"#)
        );
        let load = &machines[machines.find("let load").unwrap()..machines.find("let add").unwrap()];
        assert!(load.find("machines.set(Some(").unwrap() < load.find("focus_id(&id)").unwrap());
        assert!(load.contains("set_timeout("));
    }

    #[test]
    fn in_place_focus_uses_owners_that_survive_the_step_or_list_change() {
        // Only an identity/role/pending change replaces a routed page.
        // In particular, refreshing Account's usage does not replace it.
        let app = body(include_str!("main.rs"), "App");
        let auth = &app[app.find("let auth = Memo::new").unwrap()..app.find("leptos::task::spawn_local").unwrap()];
        assert!(auth.contains("s.user.as_ref().map(|u| (u.id.clone(), u.role.clone())), s.pending"));
        assert!(app.contains("let _ = auth.get();"));
        assert!(body(source(), "route").contains("ctx().session.get_untracked()"));

        let account = body(include_str!("account.rs"), "Account");
        let start = &account[account.find("let start_totp").unwrap()..account.find("let confirm_totp").unwrap()];
        assert!(account.find("let starting = RwSignal::new(false)").unwrap() < account.find("let start_totp").unwrap());
        assert!(start.contains(r#"focus_later(starting, "totp-code".into())"#));
        assert!(!start.contains("refresh_session(") && !start.contains("navigate("));

        // Their busy signals belong to the page/panel, outside the step or
        // row that disappears. None of these successes changes the route.
        for (page, handler) in [
            ("Device", "let lookup"),
            ("Links", "let create"),
            ("Tunnels", "let delete"),
            ("ResetPanel", "let create"),
            ("Machines", "let save_name"),
        ] {
            let page = body(source(), page);
            let handlers = &page[..page.find("\n    view! {").unwrap()];
            assert!(handlers.find("let busy = RwSignal::new(false)").unwrap() < handlers.find(handler).unwrap());
            assert!(!handlers.contains("refresh_session(") && !handlers.contains("navigate("), "{handler}");
        }
        // A reset reload updates the keyed user row without replacing its
        // ResetPanel; publishing a URL keeps resetting=true in its memo.
        let users = body(source(), "Users");
        assert!(users.contains("key=|row: &UserRow| row.user.id.clone()"));
        assert!(users.contains("resets.with(|r| r.contains_key(&id))"));
        assert!(users.contains("resetting.get().then(|| row.with_untracked("));
    }

    #[test]
    fn rename_opens_at_the_field_and_escape_or_cancel_returns_to_rename() {
        for (page, kind) in [("Machines", "machine"), ("Tunnels", "tunnel")] {
            let page = body(source(), page);
            assert!(page.contains(&format!(r#"focus_later(busy, "rename-{kind}".into())"#)));
            assert!(page.contains(&format!(r#"focus_later(busy, format!("rename-{kind}-{{id}}"))"#)));
            assert!(page.contains(r#"ev.key() == "Escape" { ev.prevent_default(); cancel_rename(); }"#));
            assert!(page.contains(r#"on:click=move |_| cancel_rename()>"Cancel""#));
            let field = page.find(&format!(r#"<input id="rename-{kind}""#)).unwrap();
            let form = &page[field..];
            assert!(form.find(r#">"Save""#).unwrap() < form.find(r#">"Cancel""#).unwrap());
        }
    }

    #[test]
    fn device_approval_asks_for_and_checks_the_password_at_its_field() {
        let device = body(source(), "Device");
        for expected in [
            r#"v["needs_password"].as_bool()"#,
            r#"body["password"] = json!(password.get())"#,
            r#"e.code == "password_required""#,
            r#"field_refused(&e, "invalid_password", password_error, "approve-password")"#,
            r#"<CodeField id="approve-password" label="Your password" value=password error=password_error password=true"#,
            "password.set(String::new())",
        ] {
            assert!(device.contains(expected), "{expected}");
        }
        let ui = include_str!("ui.rs");
        assert!(ui.contains(r#"type=if password { "password" } else { "text" }"#));
        assert!(ui.contains(r#"autocomplete=if password { "current-password" } else { "one-time-code" }"#));
    }

    #[test]
    fn headless_enrollment_reuses_the_approval_password_field_and_feedback() {
        let machines = body(source(), "Machines");
        for expected in [
            r#"body["password"] = json!(password.get())"#,
            r#"e.code == "password_required""#,
            "needs_password.set(true)",
            r#"focus_later(busy, "machine-password".into())"#,
            r#"field_refused(&e, "invalid_password", password_error, "machine-password")"#,
            r#"<CodeField id="machine-password" label="Your password" value=password error=password_error password=true"#,
            "password_error.set(None)",
            "needs_password.set(false)",
            "password.set(String::new())",
        ] {
            assert!(machines.contains(expected), "{expected}");
        }
    }

    #[test]
    fn server_booleans_are_words() {
        assert!(body(source(), "Status").contains(r#"Value::Bool(on) => if on { "On" } else { "Off" }.into()"#));
    }

    #[test]
    fn a_new_machines_code_belongs_to_its_name() {
        let v = json!({ "name": "ci-runner", "login_code": "tnlc_x", "expires_at": 1 });
        assert_eq!(created_login(&v), Some(("ci-runner".into(), "tnlc_x".into())));
        assert_eq!(created_login(&json!({ "name": "ci" })), None);
    }

    /// Machines: a create clears the name, a taken name is flagged at the
    /// field, and removing the machine hides its code and keeps the focus.
    #[test]
    fn the_machines_form_forgets_what_is_done() {
        let src = source();
        let machines = &src[src.find("fn Machines").unwrap()..src.find("fn Device").unwrap()];
        // Answers are about the name sent; one typed since is left alone.
        assert!(machines.contains("let still = move || name.try_get_untracked().is_some_and(|name| name == sent);"));
        let ok = &machines[machines.find("login_code.set(created_login(&v))").unwrap()..];
        let ok = &ok[..ok.find("Err(e)").unwrap()];
        assert!(ok.contains("if still() {") && ok.contains("name.set(String::new())"), "{ok}");
        assert!(machines.contains(r#"Err(e) if e.code == "client_exists" && still() => {"#));
        assert!(machines.contains(r#"aria-describedby="machine-name-error" aria-invalid=move || name_error.get()"#));
        let remove = &machines[machines.find("let remove").unwrap()..machines.find("let editing").unwrap()];
        assert!(
            remove.contains("*m == n")
                && remove.contains("*c = None")
                && remove.contains(r#"focus_id("machine-name")"#)
        );
        // A rename carries a shown code over to the new name.
        let rename = &machines[machines.find("let save_name").unwrap()..];
        assert!(rename.contains("c.as_mut().filter(|(m, _)| *m == old)") && rename.contains("*m = new.to_string()"));
    }

    /// Every one-click destructive row action asks first: `data-confirm`
    /// holds the question, static/shell.js asks it before the click handler.
    #[test]
    fn destructive_row_actions_ask_first() {
        let src = source();
        for (label, action) in [
            ("Delete", "delete(id2.clone())"),
            ("Revoke", "revoke(lid.clone())"),
            ("Remove", "remove(n.clone())"),
            ("Revoke", "revoke_invite(id.clone())"),
        ] {
            let at = src.find(&format!("on:click=move |_| {action}>\"{label}\"")).unwrap_or_else(|| panic!("{action}"));
            let start = src[..at].rfind("<button").unwrap();
            assert!(src[start..at].contains(" data-confirm="), "{action} asks first");
            assert_eq!(src.matches(action).count(), 1, "{action} is reachable only from that button");
        }
        // Disabling a user ends their sessions, removes their machines and closes their tunnels.
        let disable = &src[src.find(r#"format!("Enable {name}") } else { format!("Disable {name}")"#).unwrap()..];
        assert!(
            disable[..disable.find("on:click").unwrap()]
                .contains(r#"data-confirm=(!disabled).then(|| format!("Disable {name}? "#),
            "Disable asks first"
        );
        let role = &src[src.find(r#"format!("Make member {name}") } else { format!("Make admin {name}")"#).unwrap()..];
        assert!(role[..role.find("on:click").unwrap()].contains("data-confirm=role_question(&name, is_admin, mail)"));
        assert!(body(src, "Users").contains(r#"notice.set(Some(format!("{name} is now {role}.")))"#));
        let admin = role_question("alex", false, true);
        assert!(admin.starts_with("Make alex an admin?"));
        assert!(admin.contains("admin defaults") && admin.contains("sessions end") && admin.contains("end sooner"));
        assert!(admin.contains("confirmed email address, if they have one"));
        let member = role_question("alex", true, false);
        assert!(member.starts_with("Make alex a member?"));
        assert!(member.contains("member defaults") && member.contains("public tunnels require access links unless"));
        assert!(member.contains("unused invites are removed") && !member.contains("mailed"));
        let shell = include_str!("../static/shell.js");
        // A click (mouse, Enter and Space all send one), on window in the
        // capture phase, from any element inside the button.
        assert!(shell.contains(
            "addEventListener(\n    \"click\",\n    (ev) => {\n      const b = ev.target.closest?.(\"[data-confirm]\");"
        ));
        let ask = &shell[shell.find(r#"closest?.("[data-confirm]")"#).expect("shell.js asks")..];
        let ask = &ask[..ask.find("    true,\n  );").expect("in the capture phase, ahead of the UI's handler")];
        assert!(ask.contains("!confirm(b.dataset.confirm)") && ask.contains("ev.stopImmediatePropagation()"), "{ask}");
    }

    fn row(id: &str, role: &str, traffic: u64) -> UserRow {
        serde_json::from_value(
            json!({ "id": id, "username": format!("{id}-name"), "role": role, "traffic_bytes": traffic }),
        )
        .unwrap()
    }

    #[test]
    fn a_users_row_keeps_its_buttons_when_only_numbers_change() {
        // The buttons (and the focus on them) are drawn anew only when the
        // shape changes: a saved limit or new traffic leaves it as it was.
        let before = row("u1", "member", 10);
        let mut after = row("u1", "member", 99);
        after.tunnels = 3;
        after.user.limits.tunnels.effective = Some(3);
        assert!(RowShape::of(&before.user, "me", false) == RowShape::of(&after.user, "me", false));
        after.user.disabled = true;
        assert!(RowShape::of(&before.user, "me", false) != RowShape::of(&after.user, "me", false));
    }

    #[test]
    fn an_open_editor_closes_only_when_the_limits_change() {
        let before = row("u1", "member", 10);
        // Usage only: the editor and what is typed in it stay.
        let mut used = row("u1", "member", 99);
        used.tunnels = 4;
        used.clients = 2;
        assert!(!outdated(Some(&before.user.limits), &used.user.limits));
        assert!(!outdated(None, &before.user.limits));
        // Another admin set a limit, or a role change reset them to other defaults.
        let mut set = before.clone();
        set.user.limits.tunnels.setting = json!(3);
        assert!(outdated(Some(&before.user.limits), &set.user.limits));
        let mut role = before.clone();
        role.user.limits.traffic_bytes.default = Some(1);
        assert!(outdated(Some(&before.user.limits), &role.user.limits));
    }

    #[test]
    fn who_may_change_a_user() {
        let shape = |role: &str, id: &str, owner: bool| RowShape::of(&row(id, role, 0).user, "me", owner).editable;
        assert!(shape("member", "u1", false) && shape("member", "u1", true));
        assert!(!shape("admin", "u1", false) && shape("admin", "u1", true));
        assert!(!shape("owner", "u1", true) && !shape("member", "me", true));
    }
}
