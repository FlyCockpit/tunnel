// The one place that picks the theme: the user's choice ("light" or "dark",
// stored under "tunnel-theme"), else the system's. index.html loads this as a
// blocking script before the stylesheet, so the first paint is already right;
// the user menu (static/menu.js) calls tunnelTheme.choice/set for its theme choices.
// The backgrounds are --background in style/tokens.css (src/theme.rs tests).
(() => {
  const key = "tunnel-theme";
  const valid = (t) => (t === "light" || t === "dark" ? t : "system");
  let choice = "system";
  try {
    choice = valid(localStorage.getItem(key));
  } catch {}
  const system = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  const apply = () => {
    const dark = choice === "dark" || (choice === "system" && !!system?.matches);
    const root = document.documentElement;
    root.classList.toggle("dark", dark);
    root.classList.toggle("light", !dark);
    root.style.colorScheme = dark ? "dark" : "light";
    root.style.backgroundColor = dark ? "oklch(0.148 0.004 228.8)" : "oklch(1 0 0)";
  };
  globalThis.tunnelTheme = {
    choice: () => choice,
    // Applies even when storage is unavailable; then it lasts for this page.
    set: (t) => {
      choice = valid(t);
      try {
        localStorage.setItem(key, choice);
      } catch {}
      apply();
    },
  };
  apply();
  // "Auto" follows the system while the tab is open.
  system?.addEventListener?.("change", apply);
})();
