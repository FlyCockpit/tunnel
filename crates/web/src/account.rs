//! Account security and usage: password, two-factor setup and sessions.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::device::device_name;
use crate::email::AddressCard;
use crate::types::SessionRow;
use crate::ui::{
    CodeField, Copy, ErrorBox, bytes, duration_text, focus_later, relative, run, run_code, traffic_text, used_of,
    value, when,
};
use crate::{ctx, refresh_session};

// ------------------------------------------------------------------ account

#[component]
pub fn Account() -> impl IntoView {
    let c = ctx();
    let user = move || c.session.get().and_then(|s| s.user);
    let error = RwSignal::new(None::<String>);
    let notice = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let current = RwSignal::new(String::new());
    let new_pw = RwSignal::new(String::new());
    let totp_pw = RwSignal::new(String::new());
    let totp_code = RwSignal::new(String::new());
    // A refused code is said at the code field, not at the top of the page.
    let code_error = RwSignal::new(None::<String>);
    let setup = RwSignal::new(None::<Value>);
    let recovery = RwSignal::new(None::<Vec<String>>);
    let sessions = RwSignal::new(Vec::<SessionRow>::new());
    // The session carries this month's traffic: fetch it fresh on every visit.
    spawn_local(async move { refresh_session().await });
    let load_sessions = move || {
        spawn_local(async move {
            if let Ok(v) = api::get("/ui/api/account/sessions").await {
                sessions.set(serde_json::from_value(v["sessions"].clone()).unwrap_or_default());
            }
        });
    };
    load_sessions();
    let change_password = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "current": current.get(), "new": new_pw.get() });
        run(error, busy, async move {
            api::post("/ui/api/account/password", &body).await?;
            current.set(String::new());
            new_pw.set(String::new());
            refresh_session().await;
            notice.set(Some("Password changed. Your other sessions were signed out.".into()));
            load_sessions();
            Ok(())
        });
    };
    // A setup request in flight: its own flag (other Account calls clear
    // `busy`), so a late second answer can never reopen setup after Not now.
    let starting = RwSignal::new(false);
    let start_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if starting.get_untracked() {
            return;
        }
        let body = json!({ "password": totp_pw.get() });
        notice.set(None);
        run(error, starting, async move {
            setup.set(Some(api::post("/ui/api/account/totp/setup", &body).await?));
            totp_pw.set(String::new());
            focus_later(starting, "totp-code".into());
            Ok(())
        });
    };
    // Turning two-factor on, in flight: its own flag (not `busy`, which every
    // Account call clears), so Turn on and Not now wait for this answer.
    let enabling = RwSignal::new(false);
    let confirm_totp = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if enabling.get_untracked() {
            return;
        }
        let body = json!({ "code": totp_code.get() });
        run_code(error, enabling, code_error, "totp-code", async move {
            let v = api::post("/ui/api/account/totp/enable", &body).await?;
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
            api::post("/ui/api/account/totp/disable", &body).await?;
            totp_pw.set(String::new());
            // The recovery codes shown after turning it on no longer work.
            recovery.set(None);
            setup.set(None);
            refresh_session().await;
            notice.set(Some("Two-factor sign-in is off.".into()));
            Ok(())
        });
    };
    // What the last sign-out here did, said in the Sessions card itself.
    let signed_out = RwSignal::new(None::<String>);
    let revoke = move |id: String, what: String| {
        signed_out.set(None);
        run(error, busy, async move {
            api::post("/ui/api/account/sessions/revoke", &json!({ "id": id })).await?;
            signed_out.set(Some(what));
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
            <div role="status">{move || notice.get().map(|n| view! { <div class="alert alert-success">{n}</div> })}</div>
            {move || c.session.get().and_then(|s| s.user.map(|u| (u, s.usage.unwrap_or_default()))).map(|(u, usage)| view! {
                <div class="card stack">
                    <h2>"Your limits"</h2>
                    {if u.role == "owner" {
                        view! { <p>"You are the server's owner: no limits apply to you."</p> }.into_any()
                    } else {
                        let l = u.limits.clone();
                        view! {
                            <table class="table table-kv">
                                <tbody>
                                    <tr><th>"Live tunnels (across your machines)"</th><td>{used_of(usage.tunnels, l.tunnels.effective)}</td></tr>
                                    <tr><th>"Machines"</th><td>{used_of(usage.machines, l.machines.effective)}</td></tr>
                                    <tr><th>"Longest tunnel lifetime"</th><td>{l.tunnel_ttl_s.effective.map(duration_text)
                                        .unwrap_or_else(|| "unlimited (tunnels may never expire: tunnel share --ttl never)".into())}</td></tr>
                                    <tr><th>"Monthly traffic"</th><td>{l.traffic_bytes.effective.map(bytes).unwrap_or_else(|| "unlimited".into())}</td></tr>
                                </tbody>
                            </table>
                            <p class="muted small">{format!(
                                "Set by {}. At a limit, new tunnels or machines are refused and longer lifetimes are refused; what already runs keeps running.",
                                if u.role == "admin" { "the server's owner" } else { "an admin" })}</p>
                        }.into_any()
                    }}
                </div>
            })}
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
            <Show when=move || c.session.get().is_some_and(|s| s.server.mail)><AddressCard /></Show>
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
                                        <CodeField id="totp-code" label="Code from the app" value=totp_code error=code_error />
                                        <div class="row">
                                            <button class="btn" type="submit" disabled=move || enabling.get()>"Turn on"</button>
                                            // Not while Turn on is on its way: it could still turn it on.
                                            <button class="btn btn-ghost" type="button" disabled=move || enabling.get() on:click=move |_| {
                                                setup.set(None);
                                                totp_code.set(String::new());
                                                error.set(None);
                                                code_error.set(None);
                                                // Its form is gone: the focus goes to the one drawn instead.
                                                focus_later(busy, "totp-pw".into());
                                            }>"Not now"</button>
                                        </div>
                                    </form>
                                }.into_any()
                            }
                        }}
                    }>
                        <form on:submit=disable_totp>
                            <p><span class="badge badge-success">"On"</span></p>
                            <p class="muted small">{move || recovery_left(user().map(|u| u.recovery_codes_left).unwrap_or(0))}</p>
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
                <div class="row card-head card-head-actions"><h2 class="grow">"Sessions"</h2>
                    <button class="btn btn-outline btn-sm" on:click=move |_| revoke("others".into(), "Signed out every other session.".into())>"Sign out other sessions"</button></div>
                <div class="card-note" role="status">{move || signed_out.get().map(|n| view! { <div class="alert alert-success">{n}</div> })}</div>
                <table class="table table-stack">
                    <thead><tr><th>"Device"</th><th>"Address"</th><th>"Signed in"</th><th>"Last active"</th><th><span class="sr-only">"Actions"</span></th></tr></thead>
                    <tbody>
                    {move || sessions.get().into_iter().map(|s| {
                        let id = s.id.clone();
                        let raw = s.user_agent.clone().filter(|ua| !ua.trim().is_empty());
                        let device = device_name(raw.as_deref());
                        let (sign_out_label, done) = (format!("Sign out {device}"), format!("Signed out {device}."));
                        view! { <tr>
                            <td class="cell-main">
                                <span class="name" title=raw.clone()>{device.clone()}</span>
                                {s.current.then(|| view! { " " <span class="badge badge-info">"this one"</span> })}
                                {raw.map(|ua| view! {
                                    <details class="ua-raw">
                                        <summary class="muted small">"Browser details"</summary>
                                        <div class="mono small break">{ua}</div>
                                    </details>
                                })}
                            </td>
                            <td data-label="Address">{s.ip.clone().unwrap_or_default()}</td>
                            <td data-label="Signed in" title=when(s.created_at)>{relative(s.created_at)}</td>
                            <td data-label="Last active">{relative(s.last_seen_at)}</td>
                            <td class="actions">{(!s.current).then(|| view! {
                                <button class="btn btn-outline btn-sm" aria-label=sign_out_label
                                    on:click=move |_| revoke(id.clone(), done.clone())>"Sign out"</button>
                            })}</td>
                        </tr> }
                    }).collect_view()}
                    </tbody>
                </table>
            </div>
        </div>
    }
}

fn recovery_left(n: u64) -> String {
    match n {
        0 => "No recovery codes left: turn two-factor sign-in off and on again to get new ones.".into(),
        1 => "1 recovery code left".into(),
        _ => format!("{n} recovery codes left"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::source_body as body;

    fn source() -> &'static str {
        include_str!("account.rs").split("#[cfg(test)]").next().unwrap()
    }

    #[test]
    fn two_factor_setup_has_a_way_back() {
        let src = source();
        let setup = &src[src.find(r#""Turn on""#).unwrap()..];
        let not_now = &setup[..setup.find(r#""Not now""#).expect("a Not now button")];
        assert!(not_now.contains("setup.set(None)") && not_now.contains("totp_code.set(String::new())"));
        assert!(not_now.contains("disabled=move || enabling.get()"), "not while Turn on is on its way");
        assert!(src.contains(r#"type="submit" disabled=move || enabling.get()>"Turn on""#));
        // One setup request at a time: a late second answer would reopen it.
        let start = &src[src.find("let start_totp").unwrap()..src.find("let confirm_totp").unwrap()];
        assert!(start.contains("if starting.get_untracked() {\n            return;"), "{start}");
        assert!(start.contains("run(error, starting, async move {"), "its own in-flight flag");
        assert!(not_now.contains(r#"focus_later(busy, "totp-pw".into())"#), "the focus is not dropped");
        assert!(
            src.contains(r#"run_code(error, enabling, code_error, "totp-code", async move {"#),
            "its own in-flight flag"
        );
    }

    #[test]
    fn recovery_counts_and_the_sign_in_notice_survive_routing() {
        assert_eq!(recovery_left(1), "1 recovery code left");
        assert_eq!(recovery_left(3), "3 recovery codes left");
        assert_eq!(
            recovery_left(0),
            "No recovery codes left: turn two-factor sign-in off and on again to get new ones."
        );
        assert!(body(source(), "Account").contains("u.recovery_codes_left"));
        assert!(body(include_str!("auth.rs"), "SignIn").contains("recovery_notice(&v)"));
        let invite = body(include_str!("auth.rs"), "InvitePage");
        assert!(invite.find("navigate(\"/account\")").unwrap() < invite.find("recovery_notice(&v)").unwrap());
        let ui = include_str!("ui.rs");
        assert!(ui.contains("Signed in with a recovery code; {left} left."));
        assert!(ui.contains(r#"v["recovery_code"].as_bool() == Some(true)"#));
        assert!(ui.contains(r#"<div role="status">{move || c.notice.get()"#));
        assert!(include_str!("main.rs").contains("ctx().notice.set(None)"));
    }
}
