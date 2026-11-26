//! The first paint's shell (`static/shell.html`, `static/shell.js`): index.html
//! draws a copy of the header, nav and footer before this UI starts, so a
//! reload never shows a page without its frame. Here: keep the hint it
//! draws from current, and remove the copy once the real shell is in place.

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

use crate::types::SessionInfo;

#[wasm_bindgen(js_namespace = tunnelShell)]
extern "C" {
    #[wasm_bindgen(catch, js_name = remember)]
    fn js_remember(role: &str, username: &str) -> Result<(), JsValue>;
    #[wasm_bindgen(catch, js_name = forget)]
    fn js_forget() -> Result<(), JsValue>;
}

/// Records who is signed in (role and username, nothing secret) for the
/// next first paint, or that nobody is.
pub fn remember(session: Option<&SessionInfo>) {
    let _ = match session.and_then(|s| s.user.as_ref()) {
        Some(u) => js_remember(&u.role, &u.username),
        None => js_forget(),
    };
}

/// Removes the first paint's copy of the shell. Called right after the real
/// shell renders, in the same task, so no frame shows both or neither.
pub fn remove() {
    let Some(doc) = web_sys::window().and_then(|w| w.document()) else { return };
    let copies = doc.get_elements_by_class_name("boot");
    while let Some(el) = copies.item(0) {
        el.remove();
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::NAV;

    const SHELL_HTML: &str = include_str!("../static/shell.html");
    const SHELL_JS: &str = include_str!("../static/shell.js");

    /// The links in the copy's nav, as `(href, text)`.
    fn copied_nav() -> Vec<(String, String)> {
        let nav = SHELL_HTML.split("<nav").nth(1).and_then(|n| n.split("</nav>").next()).expect("a nav in shell.html");
        nav.split("<a ")
            .skip(1)
            .map(|a| {
                let href = a.split("href=\"").nth(1).and_then(|h| h.split('"').next()).unwrap_or_default();
                let text = a.split('>').nth(1).and_then(|t| t.split('<').next()).unwrap_or_default();
                (href.to_string(), text.to_string())
            })
            .collect()
    }

    #[test]
    fn the_first_paint_nav_is_the_apps_nav() {
        let want: Vec<(String, String)> =
            NAV.iter().map(|(href, text, _)| (href.to_string(), text.to_string())).collect();
        assert_eq!(copied_nav(), want);
        // Admin-only links are hidden in the copy unless the hint says admin.
        for (href, _, admin) in NAV {
            let tag = SHELL_HTML.split(&format!("href=\"{href}\"")).next().unwrap().rsplit("<a").next().unwrap();
            assert_eq!(tag.contains("boot-admin"), admin, "{href}");
        }
        // Every element of the copy is removed by class when the app renders.
        for tag in ["<header class=\"header boot\"", "<main class=\"main boot\"", "<footer class=\"footer boot\""] {
            assert!(SHELL_HTML.contains(tag), "{tag}");
        }
    }

    #[test]
    fn the_hint_names_the_roles_the_app_writes() {
        assert!(SHELL_JS.contains("\"tunnel-shell\""));
        for role in ["owner", "admin", "member"] {
            assert!(SHELL_JS.contains(role), "{role}");
        }
        // Each page the nav highlights has its key in the CSS.
        let css = include_str!("../style/app.css");
        for (href, _, _) in NAV {
            let page = href.rsplit('/').next().unwrap();
            assert!(css.contains(&format!("html[data-boot-page=\"{page}\"] .boot .nav a[href=\"{href}\"]")), "{href}");
        }
    }
}
