//! Pages. Each loads what it shows from `/ui/api/*` and keeps it in signals.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api::{self, ApiError};
use crate::types::*;
use crate::ui::{Copy, Empty, ErrorBox, bytes, gb_text, parse_gb, relative, traffic_text, when};
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
        _ => view! {
            <div class="page"><Empty title="Page not found">
                <p>"There is nothing at this address."</p>
                <button class="btn btn-outline" on:click=move |_| navigate("/")>"Go to your tunnels"</button>
            </Empty></div>
        }
        .into_any(),
    }
}

fn err_text(e: &ApiError) -> String {
    e.message.clone()
}

/// Run `fut`, storing its error message in `error`.
fn run<F>(error: RwSignal<Option<String>>, busy: RwSignal<bool>, fut: F)
where
    F: std::future::Future<Output = Result<(), ApiError>> + 'static,
{
    busy.set(true);
    error.set(None);
    spawn_local(async move {
        if let Err(e) = fut.await {
            if e.status == 401 && e.code == "signed_out" {
                refresh_session().await;
            }
            error.set(Some(err_text(&e)));
        }
        busy.set(false);
    });
}

fn value(ev: &leptos::ev::Event) -> String {
    event_target_value(ev)
}

// ------------------------------------------------------------------ sign in

#[component]
fn SignIn() -> impl IntoView {
    let c = ctx();
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let pending = move || c.session.get().is_some_and(|s| s.pending);
    let owner_missing = move || c.session.get().is_some_and(|s| !s.owner_exists);
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "username": username.get(), "password": password.get() });
        run(error, busy, async move {
            api::post::<Value>("/ui/api/login", &body).await?;
            password.set(String::new());
            refresh_session().await;
            Ok(())
        });
    };
    let submit_code = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "code": code.get() });
        run(error, busy, async move {
            api::post::<Value>("/ui/api/login/totp", &body).await?;
            refresh_session().await;
            Ok(())
        });
    };
    let cancel = move |_| {
        spawn_local(async move {
            let _ = api::post::<Value>("/ui/api/logout", &json!({})).await;
            refresh_session().await;
        });
    };
    view! {
        <div class="narrow">
            <div class="card stack">
                <h1>"Sign in"</h1>
                <ErrorBox error=error />
                <Show when=owner_missing>
                    <div class="alert alert-warning">
                        "No owner account yet. On the server, run " <code>"tunnel-server admin link"</code>
                        " and open the link it prints."
                    </div>
                </Show>
                <Show
                    when=pending
                    fallback=move || view! {
                        <form on:submit=submit>
                            <div class="field">
                                <label for="username">"Username"</label>
                                <input id="username" class="input" autocomplete="username" required
                                    prop:value=move || username.get() on:input=move |ev| username.set(value(&ev)) />
                            </div>
                            <div class="field">
                                <label for="password">"Password"</label>
                                <input id="password" class="input" type="password" autocomplete="current-password" required
                                    prop:value=move || password.get() on:input=move |ev| password.set(value(&ev)) />
                            </div>
                            <div class="field">
                                <button class="btn" type="submit" disabled=move || busy.get()>"Sign in"</button>
                            </div>
                        </form>
                    }
                >
                    <form on:submit=submit_code>
                        <p class="muted">"Enter the 6-digit code from your authenticator app, or a recovery code."</p>
                        <div class="field">
                            <label for="code">"Code"</label>
                            <input id="code" class="input code-input" autocomplete="one-time-code" inputmode="text" required
                                prop:value=move || code.get() on:input=move |ev| code.set(value(&ev)) />
                        </div>
                        <div class="field row">
                            <button class="btn" type="submit" disabled=move || busy.get()>"Continue"</button>
                            <button class="btn btn-ghost" type="button" on:click=cancel>"Use another account"</button>
                        </div>
                    </form>
                </Show>
            </div>
        </div>
    }
}

// ------------------------------------------------------------------ invite

#[component]
fn InvitePage() -> impl IntoView {
    let token = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| h.trim_start_matches('#').to_string())
        .unwrap_or_default();
    let info = RwSignal::new(None::<Value>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let revoke = RwSignal::new(false);
    {
        let token = token.clone();
        run(error, busy, async move {
            let v = api::post::<Value>("/ui/api/invite/info", &json!({ "token": token })).await?;
            info.set(Some(v));
            Ok(())
        });
    }
    let kind = move || info.get().and_then(|v| v["kind"].as_str().map(str::to_string)).unwrap_or_default();
    let title = move || match kind().as_str() {
        "owner_setup" => "Create the owner account".to_string(),
        "owner_reset" => "Reset the owner's password".to_string(),
        _ => format!(
            "Join as {}",
            info.get().and_then(|v| v["role"].as_str().map(str::to_string)).unwrap_or_else(|| "member".into())
        ),
    };
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if password.get() != confirm.get() {
            error.set(Some("The passwords do not match.".into()));
            return;
        }
        let mut body = json!({ "token": token.clone(), "password": password.get() });
        if kind() == "owner_reset" {
            body["revoke_machines"] = json!(revoke.get());
        } else {
            body["username"] = json!(username.get());
        }
        run(error, busy, async move {
            api::post::<Value>("/ui/api/invite/accept", &body).await?;
            // Drop the token from the address bar and history.
            if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
                let _ = h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/account"));
            }
            refresh_session().await;
            navigate("/account");
            Ok(())
        });
    };
    view! {
        <div class="narrow">
            <div class="card stack">
                <h1>{title}</h1>
                <ErrorBox error=error />
                <Show when=move || info.get().is_some() fallback=move || view! {
                    <Show when=move || error.get().is_none()><p class="muted">"Checking the link…"</p></Show>
                }>
                    <form on:submit=submit.clone()>
                        <Show when=move || kind() == "owner_reset" fallback=move || view! {
                            <div class="field">
                                <label for="new-username">"Username"</label>
                                <input id="new-username" class="input" autocomplete="username" required maxlength="32"
                                    prop:value=move || username.get() on:input=move |ev| username.set(value(&ev)) />
                                <p class="muted small">"Letters, digits, '.', '_' and '-'."</p>
                            </div>
                        }>
                            <p class="muted">
                                "Signing in as " <strong>{move || info.get().and_then(|v| v["username"].as_str().map(str::to_string)).unwrap_or_default()}</strong>
                                ". Two-factor sign-in is turned off; turn it on again afterwards."
                            </p>
                            <label class="check">
                                <input type="checkbox" prop:checked=move || revoke.get() on:change=move |ev| revoke.set(event_target_checked(&ev)) />
                                "Also remove all of the owner's machines (their logins stop working)"
                            </label>
                        </Show>
                        <div class="field">
                            <label for="new-password">"Password"</label>
                            <input id="new-password" class="input" type="password" autocomplete="new-password" required minlength="10"
                                prop:value=move || password.get() on:input=move |ev| password.set(value(&ev)) />
                            <p class="muted small">"At least 10 characters."</p>
                        </div>
                        <div class="field">
                            <label for="confirm-password">"Repeat the password"</label>
                            <input id="confirm-password" class="input" type="password" autocomplete="new-password" required
                                prop:value=move || confirm.get() on:input=move |ev| confirm.set(value(&ev)) />
                        </div>
                        <div class="field"><button class="btn" type="submit" disabled=move || busy.get()>"Continue"</button></div>
                    </form>
                </Show>
            </div>
        </div>
    }
}

// ------------------------------------------------------------------ tunnels

#[component]
fn Tunnels(admin: bool) -> impl IntoView {
    let all = RwSignal::new(false);
    let tunnels = RwSignal::new(None::<Vec<Tunnel>>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let open = RwSignal::new(None::<String>);
    let load = move || {
        let path = if all.get_untracked() { "/ui/api/tunnels?all=true" } else { "/ui/api/tunnels" };
        run(error, busy, async move {
            let v = api::get::<Value>(path).await?;
            let list: Vec<Tunnel> = serde_json::from_value(v["tunnels"].clone()).unwrap_or_default();
            tunnels.set(Some(list));
            Ok(())
        });
    };
    load();
    let delete = move |id: String| {
        run(error, busy, async move {
            api::delete(&format!("/ui/api/tunnels/{id}")).await?;
            load();
            Ok(())
        });
    };
    view! {
        <div class="page">
            <div class="page-head">
                <div>
                    <h1>"Tunnels"</h1>
                    <p class="muted">"Live tunnels from your machines. Share them with access links; links work once unless you make them reusable."</p>
                </div>
                {admin.then(|| view! {
                    <label class="check">
                        <input type="checkbox" prop:checked=move || all.get() on:change=move |ev| { all.set(event_target_checked(&ev)); load(); } />
                        "Everyone's"
                    </label>
                })}
                <button class="btn btn-outline" on:click=move |_| load()>"Refresh"</button>
            </div>
            <ErrorBox error=error />
            {move || match tunnels.get() {
                None => view! { <p class="muted">"Loading…"</p> }.into_any(),
                Some(list) if list.is_empty() => view! {
                    <div class="card"><Empty title="No tunnels yet">
                        <p>"Install the CLI on a machine, sign it in, then run " <code>"tunnel share 3000"</code> "."</p>
                        <button class="btn" on:click=move |_| navigate("/cli")>"Get the CLI"</button>
                    </Empty></div>
                }.into_any(),
                Some(list) => view! {
                    <div class="card card-tight table-wrap">
                        <table class="table">
                            <thead><tr>
                                <th>"Tunnel"</th><th>"Ports"</th><th>"Access"</th><th>"Machine"</th><th>"Traffic"</th><th>"Expires"</th><th></th>
                            </tr></thead>
                            <tbody>
                                {list.into_iter().map(|t| {
                                    let id = t.id.clone();
                                    let id2 = t.id.clone();
                                    let id3 = t.id.clone();
                                    let is_open = move || open.get().as_deref() == Some(id3.as_str());
                                    let ports = if t.ports.is_empty() { "—".to_string() } else {
                                        t.ports.iter().map(|p| p.port.to_string()).collect::<Vec<_>>().join(", ")
                                    };
                                    let owner = match (&t.owner, &t.user) {
                                        (Some(o), Some(u)) => format!("{o} ({u})"),
                                        (Some(o), None) => o.clone(),
                                        _ => "admin".into(),
                                    };
                                    let t2 = t.clone();
                                    view! {
                                        <tr>
                                            <td>
                                                <span class=if t.connected { "dot dot-on" } else { "dot" }></span>" "
                                                <span class="mono">{t.id.clone()}</span>
                                                {t.label.clone().map(|l| view! { <div class="muted small">{l}</div> })}
                                            </td>
                                            <td>{ports}</td>
                                            <td><span class="badge">{t.access.mode.clone()}</span></td>
                                            <td>{owner}</td>
                                            <td title=format!("in {} / out {}", bytes(t.bytes_in), bytes(t.bytes_out))>
                                                {bytes(t.bytes_in + t.bytes_out)}
                                                {t.traffic_limited.then(|| view! { " " <span class="badge badge-danger">"limit reached"</span> })}
                                            </td>
                                            <td title=when(t.expires_at)>{relative(t.expires_at)}</td>
                                            <td class="actions">
                                                <button class="btn btn-outline btn-sm" on:click=move |_| {
                                                    let cur = open.get();
                                                    open.set(if cur.as_deref() == Some(id.as_str()) { None } else { Some(id.clone()) });
                                                }>"Links"</button>" "
                                                <button class="btn btn-destructive btn-sm" on:click=move |_| delete(id2.clone())>"Delete"</button>
                                            </td>
                                        </tr>
                                        <Show when=is_open.clone()>
                                            <tr><td colspan="7" class="links-panel"><Links tunnel=t2.clone() /></td></tr>
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
    let id = tunnel.id.clone();
    let load = {
        let id = id.clone();
        move || {
            let id = id.clone();
            run(error, busy, async move {
                let v = api::get::<Value>(&format!("/ui/api/tunnels/{id}/links")).await?;
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
            run(error, busy, async move {
                let v = api::post::<Value>(&format!("/ui/api/tunnels/{id}/links"), &body).await?;
                minted.set(v["url"].as_str().map(str::to_string));
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
            <form class="row" on:submit=create>
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
                    <Copy value=Signal::derive(move || url.clone()) label="Access link" />
                </div>
            })}
            {move || {
                let list = links.get();
                if list.is_empty() {
                    view! { <p class="muted small">"No access links."</p> }.into_any()
                } else {
                    view! {
                        <table class="table">
                            <thead><tr><th>"Link"</th><th>"Kind"</th><th>"Created"</th><th>"Expires"</th><th></th></tr></thead>
                            <tbody>
                            {list.into_iter().map(|l| {
                                let lid = l.id.clone();
                                let revoke = revoke.clone();
                                let state = match (l.single_use, l.used_at) {
                                    (true, Some(_)) => "used",
                                    (true, None) => "single use",
                                    (false, _) => "reusable",
                                };
                                view! { <tr>
                                    <td class="mono">{l.id.clone()}</td>
                                    <td>{state}</td>
                                    <td>{relative(l.created_at)}</td>
                                    <td>{relative(l.expires_at)}</td>
                                    <td class="actions"><button class="btn btn-destructive btn-sm" on:click=move |_| revoke(lid.clone())>"Revoke"</button></td>
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
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let name = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let needs_code = RwSignal::new(false);
    let login_code = RwSignal::new(None::<String>);
    let ui_origin = ctx().session.get_untracked().map(|s| s.server.ui_origin).unwrap_or_default();
    let load = move || {
        let path = if all.get_untracked() { "/ui/api/machines?all=true" } else { "/ui/api/machines" };
        run(error, busy, async move {
            let v = api::get::<Value>(path).await?;
            machines.set(Some(serde_json::from_value(v["machines"].clone()).unwrap_or_default()));
            Ok(())
        });
    };
    load();
    let add = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let mut body = json!({ "name": name.get() });
        if needs_code.get() {
            body["code"] = json!(code.get());
        }
        busy.set(true);
        error.set(None);
        spawn_local(async move {
            match api::post::<Value>("/ui/api/machines", &body).await {
                Ok(v) => {
                    login_code.set(v["login_code"].as_str().map(str::to_string));
                    needs_code.set(false);
                    code.set(String::new());
                    load();
                }
                Err(e) if e.code == "code_required" => needs_code.set(true),
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };
    let remove = move |n: String| {
        run(error, busy, async move {
            api::delete(&format!("/ui/api/machines/{n}")).await?;
            load();
            Ok(())
        });
    };
    // The machine being renamed, and the name typed so far.
    let editing = RwSignal::new(None::<String>);
    let new_name = RwSignal::new(String::new());
    let save_name = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let Some(old) = editing.get_untracked() else { return };
        let body = json!({ "name": new_name.get_untracked().trim() });
        run(error, busy, async move {
            api::patch::<Value>(&format!("/ui/api/machines/{old}"), &body).await?;
            editing.set(None);
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
                {admin.then(|| view! {
                    <label class="check">
                        <input type="checkbox" prop:checked=move || all.get() on:change=move |ev| { all.set(event_target_checked(&ev)); load(); } />
                        "Everyone's"
                    </label>
                })}
            </div>
            <ErrorBox error=error />
            <div class="grid2">
                <div class="card stack">
                    <h2>"Connect a machine"</h2>
                    <p class="muted small">"On the machine, run this and approve it in your browser:"</p>
                    <Copy value=Signal::derive(move || login_cmd.clone()) label="Login command" />
                    <p class="small"><a href="/cli" on:click=move |ev| { ev.prevent_default(); navigate("/cli"); }>"Install the CLI first"</a></p>
                </div>
                <form class="card stack" on:submit=add>
                    <h2>"Add a headless machine"</h2>
                    <p class="muted small">"For servers without a browser: a one-time login code, valid 15 minutes."</p>
                    <div class="row">
                        <label class="sr-only" for="machine-name">"Name"</label>
                        <input id="machine-name" class="input grow" placeholder="name, e.g. ci-runner" required
                            prop:value=move || name.get() on:input=move |ev| name.set(value(&ev)) />
                        <button class="btn" type="submit" disabled=move || busy.get()>"Create code"</button>
                    </div>
                    <Show when=move || needs_code.get()>
                        <div class="field">
                            <label for="machine-code">"Code from your authenticator app"</label>
                            <input id="machine-code" class="input" autocomplete="one-time-code"
                                prop:value=move || code.get() on:input=move |ev| code.set(value(&ev)) />
                        </div>
                    </Show>
                    {move || login_code.get().map(|c| view! {
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
                    <div class="card card-tight table-wrap"><table class="table">
                        <thead><tr><th>"Name"</th><th>"Account"</th><th>"Status"</th><th>"Last used"</th><th>"Tunnels"</th><th></th></tr></thead>
                        <tbody>
                        {list.into_iter().map(|m| {
                            let n = m.name.clone();
                            let (n_edit, n_row) = (m.name.clone(), m.name.clone());
                            let is_editing = move || editing.get().as_deref() == Some(n_row.as_str());
                            let shown_name = m.name.clone();
                            view! { <tr>
                                <td>{move || if is_editing() {
                                    view! {
                                        <form class="row" on:submit=save_name>
                                            <label class="sr-only" for="rename-machine">"New name"</label>
                                            <input id="rename-machine" class="input input-sm" required maxlength="64"
                                                pattern="[A-Za-z0-9._\\-]+" title="letters, digits, '.', '_', '-'"
                                                prop:value=move || new_name.get() on:input=move |ev| new_name.set(value(&ev)) />
                                            <button class="btn btn-sm" type="submit" disabled=move || busy.get()>"Save"</button>
                                            <button class="btn btn-ghost btn-sm" type="button" on:click=move |_| editing.set(None)>"Cancel"</button>
                                        </form>
                                    }.into_any()
                                } else {
                                    view! { <span>{shown_name.clone()}</span> }.into_any()
                                }}</td>
                                <td>{m.user.clone()}</td>
                                <td>{if m.enrolled { view!{ <span class="badge badge-success">"signed in"</span> }.into_any() } else { view!{ <span class="badge badge-warning">"code not used"</span> }.into_any() }}</td>
                                <td>{m.last_used_at.map(relative).unwrap_or_else(|| "never".into())}</td>
                                <td>{m.tunnels}</td>
                                <td class="actions">
                                    <button class="btn btn-outline btn-sm" on:click=move |_| { new_name.set(n_edit.clone()); editing.set(Some(n_edit.clone())); }>"Rename"</button>
                                    <button class="btn btn-destructive btn-sm" on:click=move |_| remove(n.clone())>"Remove"</button>
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
    let totp = RwSignal::new(String::new());
    let request = RwSignal::new(None::<DeviceRequest>);
    let needs_code = RwSignal::new(false);
    let done = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let lookup = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "user_code": code.get() });
        run(error, busy, async move {
            let v = api::post::<Value>("/ui/api/device/lookup", &body).await?;
            request.set(serde_json::from_value(v["request"].clone()).ok());
            needs_code.set(v["needs_code"].as_bool().unwrap_or(false));
            Ok(())
        });
    };
    let decide = move |approve: bool| {
        let Some(r) = request.get() else { return };
        let mut body = json!({ "user_code": r.user_code, "approve": approve });
        if approve && needs_code.get() {
            body["code"] = json!(totp.get());
        }
        run(error, busy, async move {
            let v = match api::post::<Value>("/ui/api/device/decide", &body).await {
                Ok(v) => v,
                // The last check went stale while the page was open: ask for a code.
                Err(e) if e.code == "code_required" => {
                    needs_code.set(true);
                    return Err(e);
                }
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
            request.set(None);
            Ok(())
        });
    };
    view! {
        <div class="narrow">
            <div class="card stack">
                <h1>"Approve a machine"</h1>
                <ErrorBox error=error />
                {move || done.get().map(|d| view! { <div class="alert alert-success">{d}</div> })}
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
                        <table class="table">
                            <tr><th>"Machine"</th><td>{r.client_name.clone()}</td></tr>
                            <tr><th>"Address"</th><td>{r.ip.clone().unwrap_or_else(|| "unknown".into())}</td></tr>
                            <tr><th>"Requested"</th><td>{relative(r.created_at)}</td></tr>
                        </table>
                        <p class="muted small">"If you did not start this login, deny it."</p>
                        <Show when=move || needs_code.get()>
                            <div class="field">
                                <label for="approve-code">"Code from your authenticator app"</label>
                                <input id="approve-code" class="input" autocomplete="one-time-code"
                                    prop:value=move || totp.get() on:input=move |ev| totp.set(value(&ev)) />
                            </div>
                        </Show>
                        <div class="row">
                            <button class="btn" disabled=move || busy.get() on:click=move |_| decide(true)>"Approve"</button>
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
        info.set(Some(api::get::<Value>("/ui/api/cli").await?));
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

// ------------------------------------------------------------------ account

#[component]
fn Account() -> impl IntoView {
    let c = ctx();
    let user = move || c.session.get().and_then(|s| s.user);
    let error = RwSignal::new(None::<String>);
    let notice = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let current = RwSignal::new(String::new());
    let new_pw = RwSignal::new(String::new());
    let totp_pw = RwSignal::new(String::new());
    let totp_code = RwSignal::new(String::new());
    let setup = RwSignal::new(None::<Value>);
    let recovery = RwSignal::new(None::<Vec<String>>);
    let sessions = RwSignal::new(Vec::<SessionRow>::new());
    // The session carries this month's traffic: fetch it fresh on every visit.
    spawn_local(async move { refresh_session().await });
    let load_sessions = move || {
        spawn_local(async move {
            if let Ok(v) = api::get::<Value>("/ui/api/account/sessions").await {
                sessions.set(serde_json::from_value(v["sessions"].clone()).unwrap_or_default());
            }
        });
    };
    load_sessions();
    let change_password = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "current": current.get(), "new": new_pw.get() });
        run(error, busy, async move {
            api::post::<Value>("/ui/api/account/password", &body).await?;
            current.set(String::new());
            new_pw.set(String::new());
            refresh_session().await;
            notice.set(Some("Password changed. Your other sessions were signed out.".into()));
            load_sessions();
            Ok(())
        });
    };
    let start_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "password": totp_pw.get() });
        run(error, busy, async move {
            setup.set(Some(api::post::<Value>("/ui/api/account/totp/setup", &body).await?));
            totp_pw.set(String::new());
            Ok(())
        });
    };
    let confirm_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "code": totp_code.get() });
        run(error, busy, async move {
            let v = api::post::<Value>("/ui/api/account/totp/enable", &body).await?;
            recovery.set(serde_json::from_value(v["recovery_codes"].clone()).ok());
            setup.set(None);
            totp_code.set(String::new());
            refresh_session().await;
            load_sessions();
            Ok(())
        });
    };
    let disable_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "password": totp_pw.get() });
        run(error, busy, async move {
            api::post::<Value>("/ui/api/account/totp/disable", &body).await?;
            totp_pw.set(String::new());
            refresh_session().await;
            notice.set(Some("Two-factor sign-in is off.".into()));
            Ok(())
        });
    };
    let revoke = move |id: String| {
        run(error, busy, async move {
            api::post::<Value>("/ui/api/account/sessions/revoke", &json!({ "id": id })).await?;
            load_sessions();
            Ok(())
        });
    };
    view! {
        <div class="page">
            <div class="page-head"><div>
                <h1>"Account"</h1>
                <p class="muted">{move || user().map(|u| format!("Signed in as {} ({}).", u.username, u.role)).unwrap_or_default()}</p>
            </div></div>
            <ErrorBox error=error />
            {move || notice.get().map(|n| view! { <div class="alert alert-success">{n}</div> })}
            {move || c.session.get().and_then(|s| s.traffic).map(|t| view! {
                <div class="card stack">
                    <h2>"Traffic this month"</h2>
                    <p>{traffic_text(t.used_bytes, t.cap_bytes)}" in " {t.month.clone()} " (UTC)."</p>
                    {t.limited.then(|| view! {
                        <div class="alert alert-warning">"Your monthly traffic limit is reached: visitors of your tunnels see \"Traffic limit reached\" until next month or until an admin raises the limit."</div>
                    })}
                    <p class="muted small">"Counts what your tunnels relay in both directions (request and response bodies, WebSocket messages)."</p>
                </div>
            })}
            <div class="grid2">
                <form class="card stack" on:submit=change_password>
                    <h2>"Password"</h2>
                    <div class="field">
                        <label for="cur-pw">"Current password"</label>
                        <input id="cur-pw" class="input" type="password" autocomplete="current-password" required
                            prop:value=move || current.get() on:input=move |ev| current.set(value(&ev)) />
                    </div>
                    <div class="field">
                        <label for="new-pw">"New password"</label>
                        <input id="new-pw" class="input" type="password" autocomplete="new-password" required minlength="10"
                            prop:value=move || new_pw.get() on:input=move |ev| new_pw.set(value(&ev)) />
                    </div>
                    <div class="field"><button class="btn" type="submit" disabled=move || busy.get()>"Change password"</button></div>
                </form>
                <div class="card stack">
                    <h2>"Two-factor sign-in"</h2>
                    {move || recovery.get().map(|codes| view! {
                        <div class="alert alert-warning">"Save these recovery codes now; each works once and they are not shown again."</div>
                        <div class="codes">{codes.into_iter().map(|c| view! { <span>{c}</span> }).collect_view()}</div>
                    })}
                    <Show when=move || user().is_some_and(|u| u.totp) fallback=move || view! {
                        {move || match setup.get() {
                            None => view! {
                                <form on:submit=start_totp>
                                    <p class="muted small">"Use an authenticator app for a code at every sign-in."</p>
                                    <div class="field">
                                        <label for="totp-pw">"Password"</label>
                                        <input id="totp-pw" class="input" type="password" autocomplete="current-password" required
                                            prop:value=move || totp_pw.get() on:input=move |ev| totp_pw.set(value(&ev)) />
                                    </div>
                                    <div class="field"><button class="btn" type="submit">"Set up"</button></div>
                                </form>
                            }.into_any(),
                            Some(v) => {
                                let qr = v["qr"].as_str().unwrap_or_default().to_string();
                                let secret = v["secret"].as_str().unwrap_or_default().to_string();
                                view! {
                                    <form class="stack" on:submit=confirm_totp>
                                        <p class="small">"Scan this with your authenticator app, or enter the key by hand."</p>
                                        <img class="qr" src=qr alt="QR code for the authenticator app" />
                                        <Copy value=Signal::derive(move || secret.clone()) label="Setup key" />
                                        <div class="field">
                                            <label for="totp-code">"Code from the app"</label>
                                            <input id="totp-code" class="input" autocomplete="one-time-code" required
                                                prop:value=move || totp_code.get() on:input=move |ev| totp_code.set(value(&ev)) />
                                        </div>
                                        <button class="btn" type="submit">"Turn on"</button>
                                    </form>
                                }.into_any()
                            }
                        }}
                    }>
                        <form on:submit=disable_totp>
                            <p><span class="badge badge-success">"On"</span></p>
                            <div class="field">
                                <label for="totp-off-pw">"Password, to turn it off"</label>
                                <input id="totp-off-pw" class="input" type="password" autocomplete="current-password" required
                                    prop:value=move || totp_pw.get() on:input=move |ev| totp_pw.set(value(&ev)) />
                            </div>
                            <div class="field"><button class="btn btn-destructive" type="submit">"Turn off"</button></div>
                        </form>
                    </Show>
                </div>
            </div>
            <div class="card card-tight table-wrap">
                <div class="row card-head"><h2 class="grow">"Sessions"</h2>
                    <button class="btn btn-outline btn-sm" on:click=move |_| revoke("others".into())>"Sign out other sessions"</button></div>
                <table class="table">
                    <thead><tr><th>"Device"</th><th>"Address"</th><th>"Last active"</th><th></th></tr></thead>
                    <tbody>
                    {move || sessions.get().into_iter().map(|s| {
                        let id = s.id.clone();
                        view! { <tr>
                            <td>{s.user_agent.clone().unwrap_or_default()}{s.current.then(|| view! { " " <span class="badge badge-info">"this one"</span> })}</td>
                            <td>{s.ip.clone().unwrap_or_default()}</td>
                            <td>{relative(s.last_seen_at)}</td>
                            <td class="actions">{(!s.current).then(|| view! {
                                <button class="btn btn-outline btn-sm" on:click=move |_| revoke(id.clone())>"Sign out"</button>
                            })}</td>
                        </tr> }
                    }).collect_view()}
                    </tbody>
                </table>
            </div>
        </div>
    }
}

// -------------------------------------------------------------------- admin

#[component]
fn Users(me: User) -> impl IntoView {
    let users = RwSignal::new(Vec::<UserRow>::new());
    let invites = RwSignal::new(Vec::<Invite>::new());
    let services = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let role = RwSignal::new("member".to_string());
    let new_url = RwSignal::new(None::<String>);
    let month = RwSignal::new(String::new());
    // Loading the lists does not disable the invite button (only a submit in flight does).
    let loading = RwSignal::new(false);
    let load = move || {
        run(error, loading, async move {
            let u = api::get::<Value>("/ui/api/users").await?;
            users.set(serde_json::from_value(u["users"].clone()).unwrap_or_default());
            month.set(u["month"].as_str().unwrap_or_default().to_string());
            let i = api::get::<Value>("/ui/api/invites").await?;
            invites.set(serde_json::from_value(i["invites"].clone()).unwrap_or_default());
            let s = api::get::<Value>("/ui/api/services").await?;
            services.set(serde_json::from_value(s["services"].clone()).unwrap_or_default());
            Ok(())
        });
    };
    load();
    let invite = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "role": role.get() });
        run(error, busy, async move {
            let v = api::post::<Value>("/ui/api/invites", &body).await?;
            new_url.set(v["url"].as_str().map(str::to_string));
            load();
            Ok(())
        });
    };
    let update = move |id: String, body: Value| {
        run(error, busy, async move {
            api::patch::<Value>(&format!("/ui/api/users/{id}"), &body).await?;
            load();
            Ok(())
        });
    };
    let reset_traffic = move |id: String| {
        run(error, busy, async move {
            api::post::<Value>(&format!("/ui/api/users/{id}/traffic/reset"), &json!({})).await?;
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
        <div class="page">
            <div class="page-head"><div>
                <h1>"Users"</h1>
                <p class="muted">"Invite people with a single-use link. Members see only their own machines and tunnels."</p>
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
                    <button class="btn" type="submit" disabled=move || busy.get()>"Create invite link"</button>
                </div>
                {move || new_url.get().map(|u| view! {
                    <p class="small">"Send this link to the person you invite; it works once, for 7 days."</p>
                    <Copy value=Signal::derive(move || u.clone()) label="Invite link" />
                })}
            </form>
            <div class="card card-tight table-wrap">
                <table class="table">
                    <thead><tr><th>"User"</th><th>"Role"</th><th>"Machines"</th><th>"Tunnels"</th>
                        <th>{move || format!("Traffic {}", month.get())}</th><th>"Public previews"</th><th>"2FA"</th><th></th></tr></thead>
                    <tbody>
                    {move || users.get().into_iter().map(|row| {
                        let u = row.user.clone();
                        let editable = u.role != "owner" && u.id != me_id && (owner || u.role == "member");
                        let (id1, id2, id3, id4) = (u.id.clone(), u.id.clone(), u.id.clone(), u.id.clone());
                        let (id5, id6) = (u.id.clone(), u.id.clone());
                        let cap_input_id = format!("cap-{}", u.id);
                        let cap = u.traffic_cap;
                        let limited = cap.is_some_and(|c| row.traffic_bytes >= c);
                        // The cap in GB as typed; empty: no cap.
                        let cap_gb = RwSignal::new(cap.map(gb_text).unwrap_or_default());
                        let set_cap = move |ev: leptos::ev::SubmitEvent| {
                            ev.prevent_default();
                            let typed = cap_gb.get_untracked();
                            let typed = typed.trim();
                            let cap = if typed.is_empty() {
                                Value::Null
                            } else {
                                match parse_gb(typed) {
                                    Some(b) => json!(b),
                                    None => { error.set(Some("Enter the cap in GB, e.g. 50 or 0.5, or leave it empty for no cap.".into())); return; }
                                }
                            };
                            update(id5.clone(), json!({ "traffic_cap": cap }));
                        };
                        let can_public = u.can_public;
                        let disabled = u.disabled;
                        let is_admin = u.role == "admin";
                        view! { <tr>
                            <td>{u.username.clone()}{disabled.then(|| view! { " " <span class="badge badge-danger">"disabled"</span> })}</td>
                            <td>{u.role.clone()}</td>
                            <td>{format!("{} / {}", row.clients, u.max_clients)}</td>
                            <td>{format!("{} / {}", row.tunnels, u.max_tunnels)}</td>
                            <td>
                                <div>{traffic_text(row.traffic_bytes, cap)}
                                    {limited.then(|| view! { " " <span class="badge badge-danger">"limit reached"</span> })}</div>
                                {editable.then(|| view! {
                                    <form class="row" on:submit=set_cap>
                                        <label class="sr-only" for=cap_input_id.clone()>"Monthly traffic cap (GB)"</label>
                                        <input id=cap_input_id.clone() class="input input-sm input-num" inputmode="decimal" placeholder="no cap"
                                            prop:value=move || cap_gb.get() on:input=move |ev| cap_gb.set(value(&ev)) />
                                        <span class="muted small">"GB"</span>
                                        <button class="btn btn-outline btn-sm" type="submit" disabled=move || busy.get()>"Set cap"</button>
                                        <button class="btn btn-ghost btn-sm" type="button" disabled=move || busy.get()
                                            on:click=move |_| reset_traffic(id6.clone())>"Reset month"</button>
                                    </form>
                                })}
                            </td>
                            <td>{if u.role == "member" {
                                if editable { view! {
                                    <label class="check"><input type="checkbox" prop:checked=can_public
                                        on:change=move |ev| update(id1.clone(), json!({ "can_public": event_target_checked(&ev) })) />"allowed"</label>
                                }.into_any() } else { view! { {if can_public { "allowed" } else { "no" }} }.into_any() }
                            } else { view! { "admin" }.into_any() }}</td>
                            <td>{if u.totp { "on" } else { "off" }}</td>
                            <td class="actions">{editable.then(|| view! {
                                {(owner && !disabled).then(|| view! {
                                    <button class="btn btn-outline btn-sm" on:click=move |_| update(id2.clone(), json!({ "role": if is_admin { "member" } else { "admin" } }))>
                                        {if is_admin { "Make member" } else { "Make admin" }}
                                    </button>" "
                                })}
                                <button class=if disabled { "btn btn-outline btn-sm" } else { "btn btn-destructive btn-sm" }
                                    on:click=move |_| update(id3.clone(), json!({ "disabled": !disabled }))>
                                    {if disabled { "Enable" } else { "Disable" }}
                                </button>
                                <span class="sr-only">{id4.clone()}</span>
                            })}</td>
                        </tr> }
                    }).collect_view()}
                    </tbody>
                </table>
            </div>
            <div class="card card-tight table-wrap">
                <h2 class="card-head">"Invites"</h2>
                <table class="table">
                    <thead><tr><th>"Role"</th><th>"By"</th><th>"Created"</th><th>"Status"</th><th></th></tr></thead>
                    <tbody>
                    {move || invites.get().into_iter().map(|i| {
                        let id = i.id.clone();
                        let open = i.used_at.is_none() && i.expires_at > (js_sys::Date::now() / 1000.0) as i64;
                        let status = match (&i.used_by, open) {
                            (Some(u), _) => format!("used by {u}"),
                            (None, true) => format!("open, expires {}", relative(i.expires_at)),
                            (None, false) => "expired".into(),
                        };
                        view! { <tr>
                            <td>{i.role.clone()}</td>
                            <td>{i.created_by.clone().unwrap_or_default()}</td>
                            <td>{relative(i.created_at)}</td>
                            <td>{status}</td>
                            <td class="actions">{open.then(|| view! {
                                <button class="btn btn-outline btn-sm" on:click=move |_| revoke_invite(id.clone())>"Revoke"</button>
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
                        view! { <table class="table">
                            <thead><tr><th>"Name"</th><th>"Tunnels"</th><th>"Last used"</th></tr></thead>
                            <tbody>{list.into_iter().map(|s| view! { <tr>
                                <td>{s["name"].as_str().unwrap_or_default().to_string()}</td>
                                <td>{format!("{} / {}", s["tunnels"], s["max_tunnels"])}</td>
                                <td>{s["last_used_at"].as_i64().map(relative).unwrap_or_else(|| "never".into())}</td>
                            </tr> }).collect_view()}</tbody>
                        </table> }.into_any()
                    }
                }}
            </div>
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
        status.set(Some(api::get::<Value>("/ui/api/status").await?));
        let a = api::get::<Value>("/ui/api/audit").await?;
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
                    <table class="table">
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
                    <table class="table">
                        <tr><th>"Connected tunnels"</th><td>{field(&["connected_tunnels"])}</td></tr>
                        <tr><th>"Tunnels"</th><td>{field(&["counts", "tunnels"])}</td></tr>
                        <tr><th>"Access links"</th><td>{field(&["counts", "access_links"])}</td></tr>
                        <tr><th>"Member tunnels / machines"</th><td>{move || format!("{} / {}", field(&["limits", "member_max_tunnels"])(), field(&["limits", "member_max_clients"])())}</td></tr>
                        <tr><th>"Public previews for everyone"</th><td>{field(&["limits", "allow_public_for_clients"])}</td></tr>
                        <tr><th>"New members' monthly traffic"</th><td>{move || status.get()
                            .and_then(|s| s["limits"]["member_monthly_traffic_gb"].as_u64())
                            .map(|gb| format!("{gb} GB"))
                            .unwrap_or_else(|| "no cap".into())}</td></tr>
                    </table>
                </div>
            </div>
            <div class="card card-tight table-wrap">
                <h2 class="card-head">"Audit log"</h2>
                <table class="table">
                    <thead><tr><th>"When"</th><th>"Who"</th><th>"What"</th><th>"Target"</th><th>"Address"</th></tr></thead>
                    <tbody>
                    {move || audit.get().into_iter().map(|e| view! { <tr>
                        <td>{when(e.at)}</td>
                        <td>{e.user.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{e.action.replace('_', " ")}</td>
                        <td class="mono small">{e.target.clone().unwrap_or_default()}</td>
                        <td>{e.ip.clone().unwrap_or_default()}</td>
                    </tr> }).collect_view()}
                    </tbody>
                </table>
            </div>
        </div>
    }
}
