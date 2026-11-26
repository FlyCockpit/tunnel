//! The first paint's shell (`static/shell.html`, `static/shell.js`): index.html
//! draws a copy of the header, nav and footer before this UI starts, so a
//! reload never shows a page without its frame. Here: keep the hint it
//! draws from current, and remove the copy once the real shell is in place.
//! shell.js also draws the header's user menu button into the real shell's
//! slot (`#menu-wrap`, as soon as it is there) from what `remember` tells it; the menu itself is
//! `static/menu.js`, loaded on first use, which keeps it out of the first
//! load's size budget (build.sh).

use wasm_bindgen::prelude::{JsValue, wasm_bindgen};

use crate::types::SessionInfo;

#[wasm_bindgen(js_namespace = tunnelShell)]
extern "C" {
    #[wasm_bindgen(catch, js_name = remember)]
    fn js_remember(role: &str, username: &str, email: &str) -> Result<(), JsValue>;
    #[wasm_bindgen(catch, js_name = forget)]
    fn js_forget() -> Result<(), JsValue>;
}

/// Tells shell.js who is signed in, or that nobody is: it keeps role and
/// username (nothing secret) for the next first paint, and the user menu
/// shows them with the email.
pub fn remember(session: Option<&SessionInfo>) {
    let _ = match session.and_then(|s| s.user.as_ref()) {
        Some(u) => js_remember(&u.role, &u.username, u.email.as_deref().unwrap_or_default()),
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
        let want: Vec<(String, String)> = NAV.iter().map(|(href, text)| (href.to_string(), text.to_string())).collect();
        assert_eq!(copied_nav(), want);
        // Signed in (the hint), the copy shows the nav and the user menu
        // button with the name; signed out, the theme button.
        for tag in [
            "<nav class=\"nav boot-in\"",
            "user-menu-btn boot-in",
            "<span class=\"user-menu-name boot-account\">",
            "theme-btn boot-out",
        ] {
            assert!(SHELL_HTML.contains(tag), "{tag}");
        }
        let css = include_str!("../style/app.css");
        assert!(css.contains("html:not([data-boot-nav=\"in\"]) .boot .boot-in, html[data-boot-nav=\"in\"] .boot .boot-out { display: none; }"));
        assert!(SHELL_JS.contains("root.dataset.bootNav = signedIn ? \"in\" : \"none\";"));
        // Every element of the copy is removed by class when the app renders;
        // it carries the markers the shell loading check measures (the same
        // as the template's: header, main, route skeleton), as does ui::Shell.
        for tag in [
            "<header class=\"header boot\" data-app-header",
            "<main class=\"main boot\" id=\"main-content\"",
            "<footer class=\"footer boot\"",
            "data-route-skeleton",
            "data-slot=\"skeleton\"",
        ] {
            assert!(SHELL_HTML.contains(tag), "{tag}");
        }
        let shell = include_str!("ui.rs");
        assert!(shell.contains("<header class=\"header\" data-app-header>") && shell.contains("id=\"main-content\""));
    }

    /// `src` without its test module, so a check cannot match its own assertion.
    fn code(src: &'static str) -> &'static str {
        src.split("#[cfg(test)]").next().unwrap()
    }

    #[test]
    fn the_header_has_the_user_menu_instead_of_the_old_controls() {
        let ui = code(include_str!("ui.rs"));
        assert!(ui.contains("<div class=\"menu-wrap\" id=\"menu-wrap\"></div>"));
        for gone in ["ThemeToggle", "account-link", "Sign out", "logout", "/admin/"] {
            assert!(!ui.contains(gone), "ui.rs still has {gone}");
        }
        // The UI hands shell.js the session (with the email, which is not
        // stored); shell.js draws the button once the slot is rendered.
        let boot = code(include_str!("boot.rs"));
        assert!(boot.contains("js_remember(&u.role, &u.username, u.email.as_deref().unwrap_or_default())"));
        assert!(SHELL_JS.contains("remember: (role, name, email) => {"));
        assert!(SHELL_JS.contains("localStorage.setItem(key, `${role}:${name}`);"));
        assert!(SHELL_JS.contains("waiting ??= new MutationObserver(() => {"));
        // A press opens the menu once it has loaded, unless dismissed first;
        // a failed load says so and offers a reload.
        for part in [
            "const press = {};\n    pending = press;",
            "const live = () => pending === press && button.isConnected;",
            "(m) => live() && act(m),",
            "if (ev.key === \"Escape\" || ev.key === \"Tab\") {\n      pending = null;",
            "addEventListener(\"popstate\", () => (pending = null));",
            "The menu did not load. Reload the page to try again.",
            "addEventListener(\"click\", () => location.reload());",
        ] {
            assert!(SHELL_JS.contains(part), "{part}");
        }
    }

    #[test]
    fn the_menu_loads_on_first_use_outside_the_first_load_budget() {
        let build = include_str!("../build.sh");
        assert!(SHELL_JS.contains("const menuJs = \"/assets/menu.js\";") && SHELL_JS.contains("import(menuJs)"));
        assert!(build.contains("menu=\"menu-$(hash static/menu.js).js\""));
        assert!(build.contains("sed \"s#\\\"/assets/menu.js\\\"#\\\"/assets/$menu\\\"#\" static/shell.js"));
        let budget = build.lines().find(|l| l.starts_with("for f in dist/index.html dist/assets/$js")).unwrap();
        assert!(!budget.contains("menu"), "{budget}");
        let index = build.split("cat > dist/index.html <<HTML").nth(1).unwrap().split("\nHTML\n").next().unwrap();
        assert!(!index.contains("menu"), "index.html must not load the menu up front");
        // The menu button pattern and the items.
        for part in ["aria-haspopup=\"menu\" aria-expanded=\"false\"", "<span class=\"sr-only\"> account menu</span>"] {
            assert!(SHELL_JS.contains(part), "{part}");
        }
        let menu = include_str!("../static/menu.js");
        for part in [
            "menu.setAttribute(\"role\", \"menu\");",
            "role=\"menuitem\" tabindex=\"-1\"",
            "role=\"menuitemradio\" tabindex=\"-1\" aria-checked=\"false\"",
            "role=\"separator\"",
            "<span class=\"menu-who-title\">My account</span>",
            "link(\"/account\", \"Account\", icons.user)",
            "(admin ? group(\"admin\", \"Admin\", link(\"/admin/users\", \"Users\", icons.users) + link(\"/admin/status\", \"Server\", icons.server)) : \"\")",
            "<span>Sign out</span>",
            "span.textContent = span.title = text;",
            "if (key === \"Escape\") {",
            "if (refocus || inMenu) button.focus();",
        ] {
            assert!(menu.contains(part), "{part}");
        }
        // Same choices as theme.js.
        assert!(include_str!("../static/theme.js").contains(r#"t === "light" || t === "dark" ? t : "system""#));
        assert!(menu.contains("[\"light\", \"Light\"],\n  [\"dark\", \"Dark\"],\n  [\"system\", \"System\"],"));
    }

    #[test]
    fn the_first_paint_has_the_same_menu_buttons() {
        for (icon, class) in [
            (r#"<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>"#, "user-menu-btn"),
            (r#"<circle cx="12" cy="12" r="10"/><path d="M12 18a6 6 0 0 0 0-12v12z"/>"#, "theme-btn"),
        ] {
            assert!(SHELL_HTML.contains(icon) && SHELL_JS.contains(icon), "{icon}");
            assert!(SHELL_HTML.contains(&format!("class=\"btn btn-outline {class} boot-")), "{class}");
            assert!(SHELL_JS.contains(&format!("class=\"btn btn-outline {class}\"")), "{class}");
        }
    }

    /// A PNG's `(width, height)` from its IHDR chunk.
    fn png_size(png: &[u8]) -> (u32, u32) {
        let be = |at: usize| u32::from_be_bytes(png[at..at + 4].try_into().unwrap());
        (be(16), be(20))
    }

    #[test]
    fn the_logo_slot_is_the_same_in_the_first_paint_and_crisp_at_every_density() {
        let shell = include_str!("ui.rs");
        // 32px box declared up front, 32/64/128w files chosen by drawn size
        // (sizes=48px, the largest drawn width: the root scales up to 150% and
        // `sizes` resolves rem against the initial font size, not that root), named once: the image
        // is the link's name and the visible text is aria-hidden.
        for attr in [
            "src=\"/assets/favicon-32.png\"",
            "srcset=\"/assets/favicon-32.png 32w, /assets/logo-64.png 64w, /assets/logo-128.png 128w\"",
            "sizes=\"48px\"",
            "alt=\"Tunnel\"",
            "width=\"32\"",
            "height=\"32\"",
            "<span class=\"brand-text\" aria-hidden=\"true\">",
        ] {
            assert!(SHELL_HTML.contains(attr), "shell.html: {attr}");
            assert!(shell.contains(attr), "ui.rs: {attr}");
        }
        assert_eq!(png_size(include_bytes!("../static/favicon-32.png")), (32, 32));
        assert_eq!(png_size(include_bytes!("../static/logo-64.png")), (64, 64));
        assert_eq!(png_size(include_bytes!("../static/logo-128.png")), (128, 128));
        let build = include_str!("../build.sh");
        for file in ["static/favicon-32.png", "static/logo-64.png", "static/logo-128.png"] {
            assert!(build.contains(file), "build.sh copies {file}");
        }
        // The first-paint logo counts against the first-load budget.
        assert!(
            build.contains("for f in dist/assets/logo-64.png dist/assets/logo-128.png; do")
                && build.contains("total=$((total + logo + $(wc -c < dist/assets/favicon-32.png)))"),
            "build.sh counts the largest logo file (by bytes) and the favicon in the first-load budget"
        );
        assert!(include_str!("../style/app.css").contains(".brand img { width: 2rem; height: 2rem;"));
    }

    #[test]
    fn the_hint_names_the_roles_the_app_writes() {
        assert!(SHELL_JS.contains("\"tunnel-shell\""));
        for role in ["owner", "admin", "member"] {
            assert!(SHELL_JS.contains(role), "{role}");
        }
        // Each page the nav highlights has its key in the CSS.
        let css = include_str!("../style/app.css");
        for (href, _) in NAV {
            let page = href.rsplit('/').next().unwrap();
            assert!(css.contains(&format!("html[data-boot-page=\"{page}\"] .boot .nav a[href=\"{href}\"]")), "{href}");
        }
    }
}
