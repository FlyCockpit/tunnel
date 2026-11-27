//! Sign-in and invitation links: credentials, second-factor steps and
//! the account switch made by accepting an invite or password reset.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::email::{ConfirmAddress, ForgotPassword};
use crate::limits::FocusAt;
use crate::ui::{CodeField, ErrorBox, focus_id, recovery_notice, run, run_code, value};
use crate::{ctx, navigate, refresh_session};

/// Under the sign-in heading, when the page asked for explains why: `/device`
/// opened from `tunnel login` while signed out comes back to its code form.
fn sign_in_purpose(path: &str) -> Option<&'static str> {
    (path == "/device").then_some("Sign in to approve the machine, then enter the code from its terminal.")
}

// ------------------------------------------------------------------ sign in

/// Called by the code-step view, including a reload with a pending session.
/// The password submit's owner is replaced when the session becomes pending.
fn focus_code_step() {
    let alive = RwSignal::new(false);
    set_timeout(
        move || {
            if !alive.is_disposed() && FocusAt::now("sign-in-form").needs_a_place() {
                focus_id("code");
            }
        },
        std::time::Duration::ZERO,
    );
}

#[component]
pub fn SignIn() -> impl IntoView {
    let c = ctx();
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let code_error = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let pending = move || c.session.get().is_some_and(|s| s.pending);
    let owner_missing = move || c.session.get().is_some_and(|s| !s.owner_exists);
    let mail = move || c.session.get().is_some_and(|s| s.server.mail);
    let forgot = RwSignal::new(false);
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "username": username.get(), "password": password.get() });
        run(error, busy, async move {
            api::post("/ui/api/login", &body).await?;
            password.set(String::new());
            refresh_session().await;
            Ok(())
        });
    };
    let submit_code = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let body = json!({ "code": code.get() });
        run_code(error, busy, code_error, "code", async move {
            let v = api::post("/ui/api/login/totp", &body).await?;
            recovery_notice(&v);
            refresh_session().await;
            Ok(())
        });
    };
    let cancel = move |_| {
        spawn_local(async move {
            let _ = api::post("/ui/api/logout", &json!({})).await;
            refresh_session().await;
        });
    };
    let back = move || forgot.set(false);
    view! {
        <Show when=move || !forgot.get() fallback=move || view! { <ForgotPassword back=back /> }>
        <div class="narrow">
            <div class="card stack">
                <h1>"Sign in"</h1>
                {sign_in_purpose(&c.path.get_untracked()).map(|p| view! { <p class="muted">{p}</p> })}
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
                        <form id="sign-in-form" on:submit=submit>
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
                            <div class="field row">
                                <button class="btn" type="submit" disabled=move || busy.get()>"Sign in"</button>
                                <Show when=mail>
                                    <button class="btn btn-ghost" type="button" on:click=move |_| forgot.set(true)>"Forgot password?"</button>
                                </Show>
                            </div>
                        </form>
                    }
                >
                    {move || {
                        focus_code_step();
                        view! {
                            <form id="sign-in-form" on:submit=submit_code>
                                <p class="muted">"Enter the 6-digit code from your authenticator app, or a recovery code."</p>
                                <CodeField id="code" label="Code" value=code error=code_error />
                                <div class="field row">
                                    <button class="btn" type="submit" disabled=move || busy.get()>"Continue"</button>
                                    <button class="btn btn-ghost" type="button" on:click=cancel>"Use another account"</button>
                                </div>
                            </form>
                        }
                    }}
                </Show>
            </div>
        </div>
        </Show>
    }
}

// ------------------------------------------------------------------ invite

#[component]
pub fn InvitePage() -> impl IntoView {
    let token = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .map(|h| h.trim_start_matches('#').to_string())
        .unwrap_or_default();
    let info = RwSignal::new(None::<Value>);
    let code_error = RwSignal::new(None::<String>);
    let error = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    // The server refused the link itself (not a connection problem).
    let invalid = RwSignal::new(false);
    {
        let token = token.clone();
        run(error, busy, async move {
            let v = api::post("/ui/api/invite/info", &json!({ "token": token })).await.inspect_err(|e| {
                invalid.set(e.code == "invalid_invite");
            })?;
            info.set(Some(v));
            Ok(())
        });
    }
    let kind = move || info.get().and_then(|v| v["kind"].as_str().map(str::to_string)).unwrap_or_default();
    let is_reset = move || matches!(kind().as_str(), "owner_reset" | "account_reset" | "password_reset");
    let field = move |k: &'static str| info.get().and_then(|v| v[k].as_str().map(str::to_string));
    let needs_code = move || info.get().is_some_and(|v| v["needs_code"].as_bool() == Some(true));
    let title = move || {
        let info = info.get();
        invite_title(info.as_ref().map(|v| (v["kind"].as_str().unwrap_or_default(), v["role"].as_str())), invalid.get())
    };
    // Stored, so the form's closures stay `Copy` inside nested views.
    let stored_token = StoredValue::new(token.clone());
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if password.get() != confirm.get() {
            error.set(Some("The passwords do not match.".into()));
            return;
        }
        let mut body = json!({ "token": stored_token.get_value(), "password": password.get() });
        if is_reset() {
            if needs_code() {
                body["code"] = json!(code.get());
            }
        } else {
            body["username"] = json!(username.get());
        }
        run_code(error, busy, code_error, "reset-code", async move {
            let v = api::post("/ui/api/invite/accept", &body).await?;
            // Drop the token from the address bar and history.
            if let Some(h) = web_sys::window().and_then(|w| w.history().ok()) {
                let _ = h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some("/account"));
            }
            refresh_session().await;
            navigate("/account");
            recovery_notice(&v);
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
                    <Show when=move || kind() != "email_verify" fallback=move || view! {
                        <ConfirmAddress token=stored_token.get_value() info=info.get().unwrap_or_default() />
                    }>
                    {move || {
                        let current = ctx().session.get().and_then(|s| s.user)?;
                        let target = field("username").unwrap_or_default();
                        if is_reset() && current.username == target {
                            return None;
                        }
                        Some(view! { <p class="muted">{if is_reset() {
                            format!("You are signed in as {}; accepting signs you in as {target}.", current.username)
                        } else {
                            format!("You are signed in as {}; accepting switches to the new account.", current.username)
                        }}</p> })
                    }}
                    <form on:submit=submit>
                        <Show when=is_reset fallback=move || view! {
                            <div class="field">
                                <label for="new-username">"Username"</label>
                                <input id="new-username" class="input" autocomplete="username" required maxlength="32"
                                    prop:value=move || username.get() on:input=move |ev| username.set(value(&ev)) />
                                <p class="muted small">"Letters, digits, '.', '_' and '-'."</p>
                            </div>
                            {move || field("email").map(|e| view! {
                                <p class="muted small">{format!("Signing up confirms {e} as your account's email address.")}</p>
                            })}
                        }>
                            <p class="muted">
                                "Signing in as " <strong>{move || field("username").unwrap_or_default()}</strong>
                                {move || if kind() == "password_reset" {
                                    ". Every session ends, all machines are signed out and their tunnels end. Sign machines in again with tunnel login. Two-factor sign-in stays as it is."
                                } else {
                                    ". Every session ends, all machines are signed out and their tunnels end. Sign machines in again with tunnel login. Two-factor sign-in and recovery codes are turned off; turn two-factor sign-in on again under Account."
                                }}
                            </p>
                            <Show when=needs_code>
                                <CodeField id="reset-code" label="Code from your authenticator app (or a recovery code)" value=code error=code_error />
                            </Show>
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
                </Show>
            </div>
        </div>
    }
}

/// The invite page's heading: what the link does once the server has said
/// (`(kind, role)`), else whether it was refused or is still being checked.
/// Never a role the page cannot know yet.
fn invite_title(info: Option<(&str, Option<&str>)>, invalid: bool) -> String {
    match info {
        None if invalid => "Link not valid".into(),
        None => "Opening your link".into(),
        Some(("owner_setup", _)) => "Create the owner account".into(),
        Some(("owner_reset", _)) => "Reset the owner's password".into(),
        Some(("account_reset" | "password_reset", _)) => "Set a new password".into(),
        Some(("email_verify", _)) => "Confirm your email address".into(),
        Some((_, role)) => format!("Join as {}", role.unwrap_or("member")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::source_body as body;

    fn source() -> &'static str {
        include_str!("auth.rs").split("#[cfg(test)]").next().unwrap()
    }

    #[test]
    fn signing_in_from_the_machine_approval_link_says_why() {
        assert!(sign_in_purpose("/device").is_some_and(|p| p.contains("approve the machine") && p.contains("code")));
        for path in ["/", "/tunnels", "/account", "/devices"] {
            assert_eq!(sign_in_purpose(path), None, "{path}");
        }
        // Untracked: a new path draws the page anew.
        assert!(source().contains("sign_in_purpose(&c.path.get_untracked())"), "the sign-in card shows it");
    }

    #[test]
    fn the_invite_heading_never_claims_a_role_it_does_not_know() {
        assert_eq!(invite_title(None, false), "Opening your link");
        assert_eq!(invite_title(None, true), "Link not valid");
        assert_eq!(invite_title(Some(("invite", Some("admin"))), false), "Join as admin");
        assert_eq!(invite_title(Some(("invite", None)), false), "Join as member");
        assert_eq!(invite_title(Some(("owner_setup", None)), false), "Create the owner account");
        assert_eq!(invite_title(Some(("password_reset", None)), false), "Set a new password");
        assert_eq!(invite_title(Some(("email_verify", None)), false), "Confirm your email address");
    }

    #[test]
    fn resets_always_sign_machines_out_and_explain_account_switching() {
        let invite = body(source(), "InvitePage");
        assert!(!invite.contains("revoke_machines") && !invite.contains("Also remove"));
        assert!(!invite.contains("let revoke"));
        assert_eq!(invite.matches("Sign machines in again with tunnel login.").count(), 2);
        assert!(invite.contains("Two-factor sign-in stays as it is."));
        assert!(invite.contains("Two-factor sign-in and recovery codes are turned off"));
        assert!(invite.contains("current.username == target"));
        assert!(invite.contains("accepting signs you in as {target}."));
        assert!(invite.contains("accepting switches to the new account."));
    }

    #[test]
    fn code_step_mount_schedules_focus_for_both_sign_in_and_pending_reload() {
        let signin = body(source(), "SignIn");
        let submit = &signin[signin.find("let submit =").unwrap()..signin.find("let submit_code").unwrap()];
        assert!(submit.contains("refresh_session().await"));
        assert!(!submit.contains("focus_") && !submit.contains("set_timeout("));
        // Schedule as the new route's code view is built, even if the page
        // first loads pending and no password has been submitted here.
        let schedule = signin.find("focus_code_step();").unwrap();
        assert!(signin[..schedule].trim_end().ends_with("{move || {"));
        let code_view = &signin[schedule..];
        assert!(code_view["focus_code_step();".len()..].trim_start().starts_with("view! {"));
        assert!(code_view.contains(r#"<form id="sign-in-form" on:submit=submit_code>"#));
        assert!(signin.find("when=pending").unwrap() < schedule);
        assert!(signin.find(r#"on:submit=submit>"#).unwrap() < schedule);
        assert_eq!(signin.matches("focus_code_step();").count(), 1);
        assert_eq!(signin.matches(r#"id="sign-in-form""#).count(), 2);

        let focus = body(source(), "focus_code_step");
        assert!(focus.find("let alive = RwSignal::new(false)").unwrap() < focus.find("set_timeout(").unwrap());
        assert!(focus.contains("std::time::Duration::ZERO"));
        // Check lifetime and current focus when the timer runs: navigation
        // cancels it, and an open user/theme menu keeps its focus.
        assert!(focus.contains(r#"if !alive.is_disposed() && FocusAt::now("sign-in-form").needs_a_place()"#));
        assert!(focus.contains(r#"focus_id("code")"#));
    }
}
