// The first paint's shell. index.html already holds a copy of the app's
// header, nav and footer (static/shell.html), so a reload shows the real
// frame at once and only the content area waits for the wasm UI. This
// script runs before that first paint and tells the CSS what to show:
// - the nav and the user menu button when the last visit here was signed
//   in, else the theme button.
//   "tunnel-shell" holds "<role>:<username>" (src/boot.rs keeps it current;
//   signing out clears it). It only shapes the placeholder: the UI checks
//   the session before it shows anything of the account.
// - the current page's link and the content's shape (a page or a narrow card).
// It also draws the header's user menu button (below).
(() => {
  const key = "tunnel-shell";
  const root = document.documentElement;
  let hint = "";
  try {
    hint = localStorage.getItem(key) || "";
  } catch {}
  const signedIn = /^(owner|admin|member):([A-Za-z0-9._-]{1,32})$/.exec(hint);
  const path = location.pathname;
  const page = path.split("/").filter(Boolean).pop() || "tunnels";
  root.dataset.bootNav = signedIn ? "in" : "none";
  root.dataset.bootPage = page;
  root.dataset.bootShape = !signedIn || page === "device" || path.startsWith("/invite") ? "narrow" : "page";
  if (signedIn) root.style.setProperty("--boot-user", `"${signedIn[2]}"`);

  // The user menu button, drawn into the UI's slot (#menu-wrap). The menu
  // is static/menu.js, imported on first use (build.sh names the file), as
  // the reference apps load theirs: it is not part of the first load.
  // Names only ever go in as text.
  const menuJs = "/assets/menu.js";
  let menu = null;
  let who = null;
  let drawn = null;
  let waiting = null;
  let pending = null;
  const load = () => (menu ??= import(menuJs).catch((e) => ((menu = null), Promise.reject(e))));
  const draw = () => {
    const slot = document.getElementById("menu-wrap");
    if (!slot) {
      // The UI renders its shell just after telling us who is signed in:
      // draw as soon as the slot is there (still before that frame paints).
      waiting ??= new MutationObserver(() => {
        if (!document.getElementById("menu-wrap")) return;
        waiting.disconnect();
        waiting = null;
        draw();
      });
      waiting.observe(document.documentElement, { childList: true, subtree: true });
      return;
    }
    const id = who && `${who.role}\n${who.name}\n${who.email}`;
    if (drawn?.[0] === slot && drawn[1] === id) return;
    drawn = [slot, id];
    pending = null;
    const focused = slot.contains(document.activeElement);
    const svg = (paths) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
    const attrs = 'type="button" id="menu-button" aria-haspopup="menu" aria-expanded="false"';
    slot.innerHTML = who
      ? `<button class="btn btn-outline user-menu-btn" ${attrs}>${svg('<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>')}<span class="user-menu-name"></span><span class="sr-only"> account menu</span></button>`
      : `<button class="btn btn-outline theme-btn" ${attrs} aria-label="Theme" title="Theme">${svg('<circle cx="12" cy="12" r="10"/><path d="M12 18a6 6 0 0 0 0-12v12z"/>')}</button>`;
    const button = slot.firstChild;
    if (who) button.title = button.children[1].textContent = who.name;
    if (focused) button.focus();
  };
  // Hover or focus fetches the menu; a press or ArrowDown/ArrowUp opens it,
  // unless Escape, Tab, a press elsewhere, back/forward or a redraw comes
  // first. If it cannot load (offline, or this tab predates an update),
  // its place says so and offers a reload.
  const onButton = (ev) => ev.target.closest?.("#menu-button");
  const fetchMenu = (ev) => onButton(ev) && load().catch(() => {});
  const note = () => {
    const el = document.getElementById("user-menu");
    return el?.getAttribute("role") === "alert" ? el : null;
  };
  const failed = (button) => {
    const el = document.createElement("div");
    el.className = "menu";
    el.id = "user-menu";
    el.setAttribute("role", "alert");
    el.innerHTML =
      '<p class="menu-label">The menu did not load. Reload the page to try again.</p><button type="button" class="menu-item">Reload</button>';
    el.lastChild.addEventListener("click", () => location.reload());
    button.after(el);
    el.lastChild.focus();
  };
  const want = (button, act) => {
    if (note()) return note().remove();
    // Each press is its own request: a dismissed one never acts later.
    const press = {};
    pending = press;
    const live = () => pending === press && button.isConnected;
    load()
      .then(
        (m) => live() && act(m),
        () => live() && !document.getElementById("user-menu") && failed(button),
      )
      .finally(() => {
        if (pending === press) pending = null;
      });
  };
  document.addEventListener("pointerover", fetchMenu);
  document.addEventListener("focusin", fetchMenu);
  document.addEventListener("pointerdown", (ev) => {
    if (ev.target.closest?.("#menu-wrap")) return;
    pending = null;
    note()?.remove();
  });
  addEventListener("popstate", () => (pending = null));
  document.addEventListener("click", (ev) => {
    const button = onButton(ev);
    if (button) want(button, (m) => m.toggle(who));
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" || ev.key === "Tab") {
      pending = null;
      if (ev.key === "Escape" && note()) {
        note().remove();
        document.getElementById("menu-button")?.focus();
      }
      return;
    }
    const button = onButton(ev);
    if (!button || button.getAttribute("aria-expanded") === "true" || (ev.key !== "ArrowDown" && ev.key !== "ArrowUp")) return;
    ev.preventDefault();
    want(button, (m) => m.open(who, ev.key === "ArrowDown"));
  });
  // data-confirm (src/pages.rs): ask before the UI's click handler; Cancel stops it.
  addEventListener(
    "click",
    (ev) => {
      const b = ev.target.closest?.("[data-confirm]");
      if (b && !confirm(b.dataset.confirm)) {
        ev.preventDefault();
        ev.stopImmediatePropagation();
      }
    },
    true,
  );
  globalThis.tunnelShell = {
    // Who is signed in (src/boot.rs): role and name are kept for the next
    // first paint, the menu also shows the email.
    remember: (role, name, email) => {
      try {
        localStorage.setItem(key, `${role}:${name}`);
      } catch {}
      who = { role, name, email };
      draw();
    },
    forget: () => {
      try {
        localStorage.removeItem(key);
      } catch {}
      who = null;
      draw();
    },
  };
})();
