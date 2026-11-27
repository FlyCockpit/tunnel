//! Email in the UI, shown only when the server sends mail
//! (`server.mail` in the session): "Forgot password?", the account's own
//! address, confirming an address from its mail, and the Status card.

use leptos::prelude::*;
use serde_json::{Value, json};

use crate::api;
use crate::ui::{Copy, ErrorBox, run, value};
use crate::{ctx, refresh_session};

/// The sign-in page's "Forgot password?" form. The answer never says
/// whether an account matched.
#[component]
pub fn ForgotPassword<F>(back: F) -> impl IntoView
where
    F: Fn() + Copy + Send + Sync + 'static,
{
    let login = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let sent = RwSignal::new(false);
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "login": login.get() });
        run(error, busy, async move {
            api::post::<Value>("/ui/api/password/forgot", &body).await?;
            sent.set(true);
            Ok(())
        });
    };
    view! {
        <div class="narrow">
            <div class="card stack">
                <h1>"Reset your password"</h1>
                <ErrorBox error=error />
                <Show when=move || sent.get() fallback=move || view! {
                    <form class="stack" on:submit=submit>
                        <p class="muted">"Enter your username or your account's email address. If the account has a confirmed address, a link to choose a new password is mailed there."</p>
                        <div class="field">
                            <label for="forgot-login">"Username or email"</label>
                            <input id="forgot-login" class="input" autocomplete="username" required maxlength="254"
                                prop:value=move || login.get() on:input=move |ev| login.set(value(&ev)) />
                        </div>
                        <div class="field row">
                            <button class="btn" type="submit" disabled=move || busy.get()>"Send link"</button>
                            <button class="btn btn-ghost" type="button" on:click=move |_| back()>"Back to sign-in"</button>
                        </div>
                    </form>
                }>
                    <div class="alert alert-success" role="status">
                        "If an account matches, a link is on its way. It works once, for 30 minutes. Check the spam folder too."
                    </div>
                    <p class="muted small">"No mail? The account may have no confirmed address: ask an admin of this server to reset your sign-in."</p>
                    <div><button class="btn btn-outline" type="button" on:click=move |_| back()>"Back to sign-in"</button></div>
                </Show>
            </div>
        </div>
    }
}

/// The invite page for an address confirmation link.
#[component]
pub fn ConfirmAddress(token: String, info: Value) -> impl IntoView {
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let done = RwSignal::new(None::<String>);
    let email = info["email"].as_str().unwrap_or_default().to_string();
    let username = info["username"].as_str().unwrap_or_default().to_string();
    let confirm = move |_| {
        let body = json!({ "token": token.clone() });
        run(error, busy, async move {
            let v = api::post::<Value>("/ui/api/email/verify", &body).await?;
            if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
                let _ = h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/invite"));
            }
            done.set(v["email"].as_str().map(str::to_string));
            refresh_session().await;
            Ok(())
        });
    };
    view! {
        <ErrorBox error=error />
        {move || match done.get() {
            Some(e) => view! {
                <div class="alert alert-success" role="status">{format!("Your account's address is now {e}.")}</div>
                <div><a class="btn btn-outline" href="/account">"Go to your account"</a></div>
            }.into_any(),
            None => view! {
                <p>"Confirm " <strong>{email.clone()}</strong> " as the email address of the account " <strong>{username.clone()}</strong> "."</p>
                <p class="muted small">"Password resets and security notices will go there."</p>
                <div><button class="btn" type="button" disabled=move || busy.get() on:click=confirm.clone()>"Confirm address"</button></div>
            }.into_any(),
        }}
    }
}

/// Account: the confirmed address, one waiting for confirmation, and the
/// forms to change or remove it (each with the current password).
#[component]
pub fn AddressCard() -> impl IntoView {
    let c = ctx();
    let email = move || c.session.get().and_then(|s| s.user).and_then(|u| u.email);
    let pending = move || c.session.get().and_then(|s| s.email_pending);
    let error = RwSignal::new(None::<String>);
    let notice = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let new_email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let remove_pw = RwSignal::new(String::new());
    let needs_code = RwSignal::new(false);
    let code = RwSignal::new(String::new());
    let set = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let mut body = json!({ "email": new_email.get(), "password": password.get() });
        if needs_code.get() {
            body["code"] = json!(code.get());
        }
        busy.set(true);
        error.set(None);
        notice.set(None);
        leptos::task::spawn_local(async move {
            match api::post::<Value>("/ui/api/account/email", &body).await {
                Ok(v) => {
                    password.set(String::new());
                    new_email.set(String::new());
                    code.set(String::new());
                    needs_code.set(false);
                    notice.set(Some(format!(
                        "A confirmation link is on its way to {}; the address changes when you open it (within an hour).",
                        v["pending"].as_str().unwrap_or_default()
                    )));
                    refresh_session().await;
                }
                // Two-factor sign-in with a stale session: ask for a code and try again.
                Err(e) if e.code == "code_required" => {
                    needs_code.set(true);
                    error.set(Some(e.message));
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };
    let remove = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "password": remove_pw.get() });
        run(error, busy, async move {
            api::post::<Value>("/ui/api/account/email/remove", &body).await?;
            remove_pw.set(String::new());
            notice.set(Some("The address was removed; a notice went to it.".into()));
            refresh_session().await;
            Ok(())
        });
    };
    view! {
        <div class="card stack">
            <h2>"Email"</h2>
            <ErrorBox error=error />
            {move || notice.get().map(|n| view! { <div class="alert alert-success" role="status">{n}</div> })}
            <p>{move || match email() {
                Some(e) => view! { <span>{e}</span> " " <span class="badge badge-success">"confirmed"</span> }.into_any(),
                None => view! { <span class="muted">"No address yet. Add one to reset a forgotten password by mail and to get security notices."</span> }.into_any(),
            }}</p>
            {move || pending().map(|p| view! {
                <p class="small">{format!("Waiting for confirmation: {p} (open the link mailed there).")}</p>
            })}
            <form class="stack" on:submit=set>
                <div class="field">
                    <label for="new-email">{move || if email().is_some() { "New address" } else { "Address" }}</label>
                    <input id="new-email" class="input" type="email" autocomplete="email" required maxlength="254"
                        prop:value=move || new_email.get() on:input=move |ev| new_email.set(value(&ev)) />
                </div>
                <div class="field">
                    <label for="email-pw">"Current password"</label>
                    <input id="email-pw" class="input" type="password" autocomplete="current-password" required
                        prop:value=move || password.get() on:input=move |ev| password.set(value(&ev)) />
                </div>
                <Show when=move || needs_code.get()>
                    <div class="field">
                        <label for="email-code">"Code from your authenticator app (or a recovery code)"</label>
                        <input id="email-code" class="input code-input" autocomplete="one-time-code" inputmode="text" required
                            prop:value=move || code.get() on:input=move |ev| code.set(value(&ev)) />
                    </div>
                </Show>
                <div class="field"><button class="btn" type="submit" disabled=move || busy.get()>"Send confirmation link"</button></div>
            </form>
            <Show when=move || email().is_some()>
                <details>
                    <summary class="small">"Remove the address"</summary>
                    <form class="stack" on:submit=remove>
                        <div class="field">
                            <label for="remove-email-pw">"Current password"</label>
                            <input id="remove-email-pw" class="input" type="password" autocomplete="current-password" required
                                prop:value=move || remove_pw.get() on:input=move |ev| remove_pw.set(value(&ev)) />
                        </div>
                        <div class="field"><button class="btn btn-destructive" type="submit" disabled=move || busy.get()>"Remove"</button></div>
                    </form>
                </details>
            </Show>
        </div>
    }
}

/// Status: whether the server sends mail, and how to set it up when not.
#[component]
pub fn MailStatus(status: RwSignal<Option<Value>>) -> impl IntoView {
    let mail = move || status.get().map(|s| s["mail"].clone()).unwrap_or(Value::Null);
    view! {
        <div class="card stack">
            <h2>"Email"</h2>
            {move || {
                let m = mail();
                if m["enabled"].as_bool() == Some(true) {
                    let text = |k: &str| m[k].as_str().map(str::to_string).unwrap_or_else(|| m[k].to_string());
                    view! {
                        <table class="table table-kv">
                            <tr><th>"Status"</th><td><span class="badge badge-success">"on"</span></td></tr>
                            <tr><th>"Mail server"</th><td>{format!("{}:{} ({})", text("host"), text("port"), text("security"))}</td></tr>
                            <tr><th>"Sender"</th><td>{text("from")}</td></tr>
                        </table>
                        <p class="muted small">"Invites, password resets and security notices can be mailed. Test it on the server with " <code>{text("test")}</code> "."</p>
                    }.into_any()
                } else {
                    let setup = m["setup"].as_str().unwrap_or("tunnel-server mail setup").to_string();
                    view! {
                        <p><span class="badge">"off"</span> " Everything works without it: invite and reset links are copied and handed over."</p>
                        <p class="small">"To mail invites, password resets and security notices, run on the server:"</p>
                        <Copy value=Signal::derive(move || setup.clone()) label="Mail setup command" />
                        <p class="muted small">"It asks for the SMTP server (587 STARTTLS or 465 TLS), user, password and sender, sends a test mail and restarts the service."</p>
                    }.into_any()
                }
            }}
        </div>
    }
}
