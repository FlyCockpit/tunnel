// The header's user menu, as in the suite's template apps: who is signed in,
// Account, the admin pages (admins only), the theme and Sign out; signed
// out, the theme only. static/shell.js draws its button and imports this
// module on first use, so it is not part of the first load (build.sh).
//
// A WAI-ARIA menu button: Enter, Space or ArrowDown open the menu on its
// first item, ArrowUp on its last; the arrows (wrapping), Home, End and
// type-ahead move; Enter or Space pick; Escape closes it with focus back on
// the button; Tab closes it and moves on from the button; a press outside,
// focus moving out and back/forward close it. The menu is built on each
// open from constants, so its checked theme and current page are fresh;
// names and emails only ever go in as text.

// Lucide's paths (ISC), drawn by `.icon` in app.css.
const icons = {
  user: '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  users:
    '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
};
const svg = (paths) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
const separator = '<div class="menu-sep" role="separator"></div>';
const group = (id, label, items) =>
  `<div role="group" aria-labelledby="menu-${id}"><div class="menu-label" id="menu-${id}" role="presentation">${label}</div>${items}</div>`;
const link = (href, text, icon) =>
  `<a class="menu-item" role="menuitem" tabindex="-1" href="${href}" data-act="go">${svg(icon)}<span>${text}</span></a>`;

/** The theme choices static/theme.js knows. */
export const THEMES = [
  ["light", "Light"],
  ["dark", "Dark"],
  ["system", "System"],
];

/**
 * The menu's items, from constants only. `admin`: null signed out (the
 * theme only), else whether the user is an admin (members get no Admin
 * group at all). `data-act` says what a click does.
 */
export function markup(admin) {
  const themes = group(
    "theme",
    "Theme",
    THEMES.map(
      ([value, text]) =>
        `<button type="button" class="menu-item" role="menuitemradio" tabindex="-1" aria-checked="false" data-act="theme" data-theme="${value}"><span class="menu-check">${svg(icons.check)}</span><span>${text}</span></button>`,
    ).join(""),
  );
  if (admin === null) return themes;
  return (
    '<div class="menu-who" role="presentation"><span class="menu-who-title">My account</span><span class="menu-who-name"></span><span class="menu-who-email"></span></div>' +
    separator +
    link("/account", "Account", icons.user) +
    (admin ? group("admin", "Admin", link("/admin/users", "Users", icons.users) + link("/admin/status", "Server", icons.server)) : "") +
    separator +
    themes +
    separator +
    '<button type="button" class="menu-item menu-item-danger" role="menuitem" tabindex="-1" data-act="sign-out"><span class="menu-check"></span><span>Sign out</span></button>'
  );
}

/** The item that gets focus for `key`, from item `at` (null: none has it) among `n`. */
export function step(key, at, n) {
  if (!n) return null;
  if (key === "ArrowDown") return at === null ? 0 : (at + 1) % n;
  if (key === "ArrowUp") return at === null ? n - 1 : (at + n - 1) % n;
  if (key === "Home" || key === "PageUp") return 0;
  if (key === "End" || key === "PageDown") return n - 1;
  return null;
}

/** Type-ahead: the next item after `at` whose text starts with `typed`. */
export function typeahead(texts, at, typed) {
  const want = typed.toLowerCase();
  for (let k = 1; k <= texts.length; k++) {
    const i = ((at ?? -1) + k) % texts.length;
    if (texts[i].trim().toLowerCase().startsWith(want)) return i;
  }
  return null;
}

/** Whether `href` is the page at `path` or one below it; / is the tunnels list (as src/ui.rs `is_current`). */
export function isCurrent(path, href) {
  const at = path === "/" ? "/tunnels" : path;
  return at === href || at.startsWith(`${href}/`);
}

const byId = (id) => document.getElementById(id);
const items = () => [...document.querySelectorAll("#user-menu .menu-item")];
const inSlot = (node) => node instanceof Node && !!byId("menu-wrap")?.contains(node);

/** Opens the menu for `who` ({ role, name, email } or null) with focus on its first (or last) item. */
export function open(who, first) {
  listen();
  const button = byId("menu-button");
  if (!button || byId("user-menu")) return;
  const menu = document.createElement("div");
  menu.className = "menu";
  menu.id = "user-menu";
  menu.setAttribute("role", "menu");
  menu.setAttribute("aria-labelledby", "menu-button");
  // Focusable, so a click on its labels keeps focus in it.
  menu.tabIndex = -1;
  menu.innerHTML = markup(who ? who.role !== "member" : null);
  if (who) {
    for (const [cls, text] of [
      ["menu-who-name", who.name],
      ["menu-who-email", who.email],
    ]) {
      const span = menu.querySelector(`.${cls}`);
      span.textContent = span.title = text;
      span.hidden = !text;
    }
  }
  const theme = globalThis.tunnelTheme?.choice?.() ?? "system";
  for (const el of menu.querySelectorAll(".menu-item")) {
    if (el.dataset.theme) el.setAttribute("aria-checked", String(el.dataset.theme === theme));
    if (el.dataset.act === "go" && isCurrent(location.pathname, el.getAttribute("href"))) el.setAttribute("aria-current", "page");
  }
  button.after(menu);
  button.setAttribute("aria-expanded", "true");
  button.setAttribute("aria-controls", "user-menu");
  const list = items();
  list[first ? 0 : list.length - 1]?.focus();
}

/** Closes it. Focus goes back to the button when `refocus`, and always when it was in the menu. */
export function close(refocus) {
  const menu = byId("user-menu");
  if (!menu) return;
  const inMenu = menu.contains(document.activeElement);
  menu.remove();
  const button = byId("menu-button");
  if (!button) return;
  button.setAttribute("aria-expanded", "false");
  button.removeAttribute("aria-controls");
  if (refocus || inMenu) button.focus();
}

/** The button's press. */
export function toggle(who) {
  if (byId("user-menu")) close(true);
  else open(who, true);
}

// The app routes on popstate (src/main.rs), as for back/forward.
function go(href) {
  history.pushState(null, "", href);
  dispatchEvent(new PopStateEvent("popstate"));
  scrollTo(0, 0);
}

// As the reference apps do: sign out, then load the start page afresh.
async function signOut() {
  try {
    const session = await (await fetch("/ui/api/session", { headers: { "X-Tunnel-CSRF": "1" } })).json();
    await fetch("/ui/api/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Tunnel-CSRF": session.csrf || "1" },
      body: "{}",
    });
  } catch {}
  globalThis.tunnelShell?.forget();
  location.assign("/");
}

function onClick(ev) {
  const el = byId("user-menu")?.contains(ev.target) && ev.target.closest("[data-act]");
  if (!el) return;
  const act = el.dataset.act;
  if (act === "theme") {
    globalThis.tunnelTheme?.set?.(el.dataset.theme);
    close(true);
  } else if (act === "sign-out") {
    close(true);
    signOut();
  } else if (ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.altKey || ev.button !== 0) {
    close(false); // a new tab or window: this page stays as it is
  } else {
    ev.preventDefault();
    close(true);
    go(el.getAttribute("href"));
  }
}

function onKey(ev) {
  if (!byId("user-menu") || !inSlot(ev.target)) return;
  const list = items();
  const index = list.indexOf(document.activeElement);
  const at = index < 0 ? null : index;
  const key = ev.key;
  if (key === "Escape") {
    ev.preventDefault();
    close(true);
  } else if (key === "Tab") {
    close(true); // focus moves on from the button: the items are not in the tab order
  } else if (key === " ") {
    if (at !== null && list[at].tagName === "A") {
      ev.preventDefault();
      list[at].click(); // Space picks a link as Enter does
    }
  } else if (!ev.target.closest("#menu-button")) {
    const typed = key.length === 1 && !ev.ctrlKey && !ev.metaKey && !ev.altKey;
    let next = step(key, at, list.length);
    if (next === null && typed) next = typeahead(list.map((el) => el.textContent), at, key);
    if (next !== null) {
      ev.preventDefault();
      list[next].focus();
    }
  }
}

let listening = false;
function listen() {
  if (listening) return;
  listening = true;
  document.addEventListener("click", onClick);
  document.addEventListener("keydown", onKey);
  // A press anywhere else, focus moving out of the menu and its button, and
  // back/forward close it.
  document.addEventListener("pointerdown", (ev) => {
    if (!inSlot(ev.target)) close(false);
  });
  document.addEventListener("focusout", (ev) => {
    if (inSlot(ev.target) && ev.relatedTarget && !inSlot(ev.relatedTarget)) close(false);
  });
  addEventListener("popstate", () => close(false));
}
