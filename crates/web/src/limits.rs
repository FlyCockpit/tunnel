//! The Users page's limits editor: one row per limit (Server default, a
//! custom number with its unit inline, or Unlimited), what each change does
//! under its row, errors next to the field. The pure part says how a
//! setting is shown in the form and what a filled-in form sends
//! (`PATCH /ui/api/users/{id}`).

use leptos::prelude::*;
use serde_json::{Map, Value, json};

use crate::api;
use crate::types::{Limit, Limits, User, UserRow};
use crate::ui::{ErrorBox, bytes, duration_text, focus_id as focus, gb_text, parse_gb, run, value};

/// A limit's number as the form shows it: the amount and, for lifetimes,
/// its unit (`s`, `m`, `h`, `d`; the largest that is exact).
pub fn form_value(key: &str, n: Option<u64>) -> (String, String) {
    match (key, n) {
        ("traffic_bytes", Some(b)) => (gb_text(b), String::new()),
        ("tunnel_ttl_s", Some(s)) => {
            let (size, unit) = [(86_400, "d"), (3600, "h"), (60, "m"), (1, "s")]
                .into_iter()
                .find(|(size, _)| s % size == 0)
                .unwrap_or((1, "s"));
            ((s / size).to_string(), unit.to_string())
        }
        ("tunnel_ttl_s", None) => (String::new(), "d".into()),
        (_, n) => (n.map(|n| n.to_string()).unwrap_or_default(), String::new()),
    }
}

/// The setting a field asks for: `"default"`, `"unlimited"` or the number
/// (lifetimes in seconds, traffic in bytes), or what is wrong with it (shown
/// under the field, so it does not repeat the field's name).
pub fn wanted(key: &str, mode: &str, typed: &str, unit: &str) -> Result<Value, String> {
    let typed = typed.trim();
    match mode {
        "default" => return Ok(json!("default")),
        "unlimited" => return Ok(json!("unlimited")),
        _ => {}
    }
    let n = match key {
        "traffic_bytes" => parse_gb(typed),
        "tunnel_ttl_s" => typed.parse::<u64>().ok().filter(|n| *n > 0).and_then(|n| {
            n.checked_mul(match unit {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                _ => 86_400,
            })
        }),
        _ => typed.parse::<u64>().ok(),
    };
    n.map(|n| json!(n)).ok_or_else(|| {
        match key {
            "traffic_bytes" => "Enter the traffic in GB, more than 0, e.g. 50 or 0.5.",
            "tunnel_ttl_s" => "Enter a whole number above 0 and pick its unit.",
            _ => "Enter a whole number, 0 or more.",
        }
        .to_string()
    })
}

/// Whether `wanted` differs from the setting the form was opened with.
pub fn changed(initial: &Value, wanted: &Value) -> bool {
    initial != wanted
}

/// The request body for the changed limits.
pub fn patch_body(changed: Map<String, Value>) -> Value {
    json!({ "limits": changed })
}

/// What changing a limit does, shown under its row.
pub fn hint(key: &str) -> &'static str {
    match key {
        "tunnels" => "Lowering it stops nothing that runs; new tunnels over the limit are refused.",
        "machines" => "Lowering it signs no machine out; new machines over the limit are refused.",
        "tunnel_ttl_s" => {
            "For new tunnels and renewals; their tunnels that would outlive it now end at most this long from now. Unlimited lets tunnels never expire."
        }
        _ => "Applies at once: at the limit, visitors of their tunnels see \"Traffic limit reached\" until next month.",
    }
}

/// The word after a custom number (lifetimes pick their unit instead).
fn unit_word(key: &str) -> &'static str {
    match key {
        "tunnels" => "tunnels",
        "machines" => "machines",
        "traffic_bytes" => "GB",
        _ => "",
    }
}

/// The server default as the mode select names it: `10`, `7 d`, `50 GB`, `unlimited`.
pub fn default_text(key: &str, default: Option<u64>) -> String {
    match (key, default) {
        (_, None) => "unlimited".to_string(),
        ("tunnel_ttl_s", Some(s)) => duration_text(s),
        ("traffic_bytes", Some(b)) => bytes(b),
        (_, Some(n)) => n.to_string(),
    }
}

/// One limit in the editor: Server default, a custom number or Unlimited.
#[derive(Clone, Copy)]
struct LimitField {
    key: &'static str,
    label: &'static str,
    mode: RwSignal<String>,
    /// As typed: a count, GB for traffic, an amount of `unit` for lifetimes.
    value: RwSignal<String>,
    unit: RwSignal<String>,
    /// What is wrong with what was typed, shown under the row.
    error: RwSignal<Option<String>>,
    /// The setting the form was opened with.
    initial: StoredValue<Value>,
    /// The server default it follows in "Server default" mode.
    default: Option<u64>,
}

impl LimitField {
    fn new(key: &'static str, label: &'static str, l: &Limit) -> Self {
        let (value, unit) = form_value(key, l.setting.as_u64());
        Self {
            key,
            label,
            mode: RwSignal::new(l.mode().to_string()),
            value: RwSignal::new(value),
            unit: RwSignal::new(unit),
            error: RwSignal::new(None),
            initial: StoredValue::new(l.setting.clone()),
            default: l.default,
        }
    }

    /// The id of the number input (unique per user: several editors may be open).
    fn value_id(&self, user: &str) -> String {
        format!("limit-{}-{user}-value", self.key)
    }

    /// Puts the setting into `body` when it changed. When what was typed is
    /// wrong, shows why under the row and returns the number field's id.
    fn collect(&self, user: &str, body: &mut Map<String, Value>) -> Option<String> {
        let typed =
            wanted(self.key, &self.mode.get_untracked(), &self.value.get_untracked(), &self.unit.get_untracked());
        match typed {
            Ok(v) => {
                self.error.set(None);
                if changed(&self.initial.get_value(), &v) {
                    body.insert(self.key.to_string(), v);
                }
                None
            }
            Err(e) => {
                self.error.set(Some(e));
                Some(self.value_id(user))
            }
        }
    }

    /// Switches the mode. Custom starts from the server default (when it is
    /// a number), so the admin edits a known value instead of an empty box.
    fn choose(&self, mode: String) {
        if mode == "number" && self.value.get_untracked().trim().is_empty() && self.default.is_some() {
            let (value, unit) = form_value(self.key, self.default);
            self.value.set(value);
            self.unit.set(unit);
        }
        self.mode.set(mode);
        self.error.set(None);
    }

    /// The row: label, mode select, the number with its unit inline, the
    /// hint, and the field's error.
    fn view(self, user: &str) -> impl IntoView + use<> {
        let select_id = format!("limit-{}-{user}", self.key);
        let value_id = self.value_id(user);
        let (hint_id, error_id) = (format!("{select_id}-hint"), format!("{select_id}-error"));
        let described = format!("{hint_id} {error_id}");
        let number_label = format!("{}, custom limit", self.label);
        let default_text = default_text(self.key, self.default);
        let unit_word = unit_word(self.key);
        let invalid = move || self.error.get().is_some().to_string();
        view! {
            <div class="limit-row">
                <label class="limit-label" for=select_id.clone()>{self.label}</label>
                <div class="limit-controls">
                    <select id=select_id class="input input-sm limit-mode" aria-describedby=hint_id.clone()
                        on:change=move |ev| self.choose(value(&ev))>
                        <option value="default" selected=move || self.mode.get() == "default">{format!("Server default ({default_text})")}</option>
                        <option value="number" selected=move || self.mode.get() == "number">"Custom"</option>
                        <option value="unlimited" selected=move || self.mode.get() == "unlimited">"Unlimited"</option>
                    </select>
                    <Show when=move || self.mode.get() == "number">
                        <span class="limit-number">
                            <input id=value_id.clone() class="input input-sm input-num" aria-label=number_label.clone()
                                aria-describedby=described.clone() aria-invalid=invalid
                                inputmode=if self.key == "traffic_bytes" { "decimal" } else { "numeric" }
                                prop:value=move || self.value.get()
                                on:input=move |ev| { self.value.set(value(&ev)); self.error.set(None); } />
                            {if self.key == "tunnel_ttl_s" {
                                view! {
                                    <select class="input input-sm w-auto" aria-label=format!("{}, unit", self.label)
                                        on:change=move |ev| self.unit.set(value(&ev))>
                                        <option value="s" selected=move || self.unit.get() == "s">"seconds"</option>
                                        <option value="m" selected=move || self.unit.get() == "m">"minutes"</option>
                                        <option value="h" selected=move || self.unit.get() == "h">"hours"</option>
                                        <option value="d" selected=move || self.unit.get() == "d">"days"</option>
                                    </select>
                                }.into_any()
                            } else {
                                view! { <span class="limit-unit">{unit_word}</span> }.into_any()
                            }}
                        </span>
                    </Show>
                </div>
                <p id=hint_id class="muted small limit-hint">{hint(self.key)}</p>
                <p id=error_id class="field-error limit-error" aria-live="polite">{move || self.error.get()}</p>
            </div>
        }
    }
}

/// The id of a user row's Limits button, where the focus returns when the
/// editor is cancelled.
pub fn opener_id(user: &str) -> String {
    format!("limits-open-{user}")
}

/// The id of a user's editor form.
fn form_id(user: &str) -> String {
    format!("limits-{user}")
}

/// Where the keyboard focus is when a save comes back.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FocusAt {
    /// In the editor that saved (on its Save button, or a field).
    Editor,
    /// Nowhere (`<body>`): the editor it was in is gone.
    Nowhere,
    /// Somewhere the user moved to: another editor, a link, the invite form.
    Elsewhere,
}

impl FocusAt {
    /// Whether the page should give the focus a place after the save (the
    /// editor closes, taking the focused element with it). Focus the user
    /// moved elsewhere stays there.
    pub fn needs_a_place(self) -> bool {
        self != FocusAt::Elsewhere
    }

    /// The focus now, relative to `user`'s editor.
    pub fn in_editor(user: &str) -> Self {
        Self::now(&form_id(user))
    }

    /// The focus now, relative to the form with `form` as its id.
    fn now(form: &str) -> Self {
        let Some(doc) = web_sys::window().and_then(|w| w.document()) else { return FocusAt::Nowhere };
        match doc.active_element() {
            None => FocusAt::Nowhere,
            Some(el) if doc.body().is_some_and(|b| *b == el) => FocusAt::Nowhere,
            Some(el) if doc.get_element_by_id(form).is_some_and(|f| f.contains(Some(&el))) => FocusAt::Editor,
            Some(_) => FocusAt::Elsewhere,
        }
    }
}

/// An admin's editor for a user's four limits. After a save, `saved` runs
/// with the username, the saved user as the server sent it back and where
/// the focus was when the save came back (the page closes the panel, says
/// so, shows the user, gives the focus a stable place if it was in the
/// panel, and reloads the lists);
/// Cancel closes it unchanged and focuses the row's Limits button. `saving`
/// is the page's lock for limits saves only: it outlives a closed editor and
/// nothing else clears it, so a save still in flight blocks the next one and
/// cannot land after it. Nothing owned by the
/// editor is read once the request is sent (the editor may be gone by then).
#[component]
pub fn LimitsEditor<F>(
    id: String,
    username: String,
    limits: Limits,
    open: RwSignal<bool>,
    saving: RwSignal<bool>,
    saved: F,
) -> impl IntoView
where
    F: Fn(String, Option<User>, FocusAt) + Copy + 'static,
{
    let fields = [
        LimitField::new("tunnels", "Live tunnels (across their machines)", &limits.tunnels),
        LimitField::new("machines", "Machines", &limits.machines),
        LimitField::new("tunnel_ttl_s", "Longest tunnel lifetime", &limits.tunnel_ttl_s),
        LimitField::new("traffic_bytes", "Monthly traffic", &limits.traffic_bytes),
    ];
    let error = RwSignal::new(None::<String>);
    let user = StoredValue::new(id);
    let name = StoredValue::new(username);
    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if saving.get_untracked() {
            return;
        }
        error.set(None);
        let mut body = Map::new();
        // Every row shows its own error; the focus goes to the first.
        let invalid: Vec<String> = fields.iter().filter_map(|f| f.collect(&user.get_value(), &mut body)).collect();
        if let Some(id) = invalid.first() {
            focus(id);
            return;
        }
        if body.is_empty() {
            error.set(Some("Nothing changed: pick a different setting, or Cancel.".into()));
            return;
        }
        let path = format!("/ui/api/users/{}", user.get_value());
        let body = patch_body(body);
        let name = name.get_value();
        let form = form_id(&user.get_value());
        run(error, saving, async move {
            let v = api::patch::<Value>(&path, &body).await?;
            // As a list row (the same decoding the list uses, so no extra code).
            let user = serde_json::from_value::<UserRow>(v["user"].clone()).ok().map(|r| r.user);
            saved(name, user, FocusAt::now(&form));
            Ok(())
        });
    };
    let user_id = user.get_value();
    view! {
        <form id=form_id(&user_id) class="limits stack" on:submit=submit novalidate>
            <div class="limits-list">
                {fields.into_iter().map(|f| f.view(&user_id)).collect_view()}
            </div>
            <ErrorBox error=error />
            <div class="row limits-actions">
                <button class="btn btn-sm" type="submit" disabled=move || saving.get()>"Save limits"</button>
                <button class="btn btn-outline btn-sm" type="button" on:click=move |_| {
                    open.set(false);
                    focus(&opener_id(&user.get_value()));
                }>"Cancel"</button>
                <span class="muted small">"Changing the role resets all four to the server default."</span>
            </div>
        </form>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the form sends back for a setting nobody touched.
    fn untouched(key: &str, setting: Value) -> Value {
        let mode = if setting.is_u64() { "number" } else { setting.as_str().unwrap() };
        let (typed, unit) = form_value(key, setting.as_u64());
        wanted(key, mode, &typed, &unit).unwrap()
    }

    #[test]
    fn an_untouched_form_sends_nothing() {
        for (key, setting) in [
            ("tunnels", json!(0)),
            ("tunnels", json!(3)),
            ("machines", json!("unlimited")),
            ("tunnel_ttl_s", json!(90)),
            ("tunnel_ttl_s", json!(3600)),
            ("tunnel_ttl_s", json!(7 * 86_400)),
            ("tunnel_ttl_s", json!(5400)),
            ("tunnel_ttl_s", json!("default")),
            ("traffic_bytes", json!(1_500_000)),
            ("traffic_bytes", json!(5_000_000_000u64)),
        ] {
            assert!(!changed(&setting, &untouched(key, setting.clone())), "{key} {setting}");
        }
        assert_eq!(form_value("tunnel_ttl_s", Some(90)), ("90".into(), "s".into()));
        assert_eq!(form_value("tunnel_ttl_s", Some(5400)), ("90".into(), "m".into()));
    }

    #[test]
    fn typed_values_become_settings() {
        assert_eq!(wanted("tunnel_ttl_s", "number", "8", "h"), Ok(json!(28_800)));
        assert_eq!(wanted("tunnel_ttl_s", "number", "2", "d"), Ok(json!(172_800)));
        assert_eq!(wanted("traffic_bytes", "number", "0.5", ""), Ok(json!(500_000_000)));
        assert_eq!(wanted("machines", "number", " 0 ", ""), Ok(json!(0)));
        assert_eq!(wanted("tunnels", "unlimited", "abc", ""), Ok(json!("unlimited")));
        assert_eq!(wanted("tunnels", "default", "", ""), Ok(json!("default")));
        for (key, typed) in [("tunnels", "abc"), ("tunnels", "-1"), ("tunnel_ttl_s", "0"), ("traffic_bytes", "0")] {
            assert!(wanted(key, "number", typed, "h").unwrap_err().starts_with("Enter "), "{key} {typed}");
        }
        assert!(changed(&json!(3), &json!(4)) && changed(&json!("default"), &json!(10)));
    }

    #[test]
    fn custom_starts_from_the_server_default_and_keeps_it() {
        // Choosing Custom fills in the default (form_value of it); saving that
        // unchanged pins exactly the default, in the field's own units.
        for (key, default, shown, label) in [
            ("tunnels", 10, ("10", ""), "10"),
            ("tunnel_ttl_s", 7 * 86_400, ("7", "d"), "7 d"),
            ("tunnel_ttl_s", 5400, ("90", "m"), "1 h 30 min"),
            ("traffic_bytes", 50_000_000_000, ("50", ""), "50.0 GB"),
        ] {
            let (typed, unit) = form_value(key, Some(default));
            assert_eq!((typed.as_str(), unit.as_str()), shown, "{key}");
            assert_eq!(wanted(key, "number", &typed, &unit), Ok(json!(default)), "{key}");
            assert_eq!(default_text(key, Some(default)), label, "{key}");
        }
        assert_eq!(default_text("machines", None), "unlimited");
        assert!(["tunnels", "machines", "tunnel_ttl_s", "traffic_bytes"].iter().all(|k| !hint(k).is_empty()));
    }

    #[test]
    fn a_save_moves_the_focus_only_when_it_was_in_the_editor_or_lost() {
        // Saving from the editor (or after a reload removed it) gives the
        // focus a place; a user who moved on keeps theirs.
        assert!(FocusAt::Editor.needs_a_place());
        assert!(FocusAt::Nowhere.needs_a_place());
        assert!(!FocusAt::Elsewhere.needs_a_place());
        assert_ne!(form_id("u1"), opener_id("u1"));
    }

    #[test]
    fn the_body_wraps_the_changes_in_limits() {
        let mut m = Map::new();
        m.insert("tunnels".into(), json!(3));
        assert_eq!(patch_body(m), json!({ "limits": { "tunnels": 3 } }));
    }
}
