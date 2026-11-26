// The first paint's shell. index.html already holds a copy of the app's
// header, nav and footer (static/shell.html), so a reload shows the real
// frame at once and only the content area waits for the wasm UI. This
// script runs before that first paint and tells the CSS what to show:
// - the nav and the account link when the last visit here was signed in.
//   "tunnel-shell" holds "<role>:<username>" (src/boot.rs keeps it current;
//   signing out clears it). It only shapes the placeholder: the UI checks
//   the session before it shows anything of the account.
// - the current page's link and the content's shape (a page or a narrow card).
// - the theme button's label (theme.js, loaded first, has the choice).
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
  root.dataset.bootNav = signedIn ? (signedIn[1] === "member" ? "member" : "admin") : "none";
  root.dataset.bootPage = page;
  root.dataset.bootShape = !signedIn || page === "device" || path.startsWith("/invite") ? "narrow" : "page";
  if (signedIn) root.style.setProperty("--boot-user", `"${signedIn[2]}"`);
  const theme = globalThis.tunnelTheme?.choice?.() ?? "system";
  root.style.setProperty("--boot-theme", theme === "light" ? '"Light"' : theme === "dark" ? '"Dark"' : '"Auto"');
  globalThis.tunnelShell = {
    remember: (role, name) => {
      try {
        localStorage.setItem(key, `${role}:${name}`);
      } catch {}
    },
    forget: () => {
      try {
        localStorage.removeItem(key);
      } catch {}
    },
  };
})();
