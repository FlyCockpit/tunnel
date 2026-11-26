# tunnel-web

Tunnel's web UI: Leptos rendered in the browser, styled with plain CSS
(`style/tokens.css` from the FlyCockpit template, `style/app.css` with the
template's component class strings). `build.sh` writes `dist/`, which
`tunnel-server --features ui` embeds; the [README](../../README.md#development)
covers the build.

## Edge lines

These are the horizontal edges every container sits on. They follow the
FlyCockpit template's edge lines (`patterns/design-system.md` § Edge lines
there):
the same 16px app frame, page and card lines, applied to this UI's own
containers. Lines are measured on ink (glyph bounds, or a boxed control's box)
from the container's outer edge, so a bordered card's 16px padding puts its
text 17px from the outer edge. Change a value only with the owner's approval,
and record the new value here. The same numbers hold at 390px and 1440px.
The values are written in rem (16px = 1rem), so above a 1920px long side
they grow with the root's viewport scale (up to 150% at 3840px, the
template's rule V1) and keep their proportions.

The **text line** is where headings, labels and table text start. The **box
line** is where buttons, inputs, selects, alerts and copy fields start. The
**trailing line** is where the last item in a row ends.

| Container | Text line | Box line | Trailing line |
|---|---|---|---|
| Header (`.header`) | 16px from the window edge: the brand | Same as the text line | 16px from the window edge: the last control's box ends here |
| Page (`.page`; `.page-wide` for the Users table, 90rem instead of 65rem) | 16px inside the page box (`padding: … 16px`): `h1`, the intro line, the alert boxes | Same as the text line: cards, alerts and the page-head controls start on it | 16px inside the page box: the page-head controls and the cards end here |
| Card (`.card`) | 16px inside the card | Same as the text line: inputs, buttons, copy fields, alerts | 16px inside the card |
| Table card (`.card-tight`, the table is the card's edge) | 16px: the heading (`.card-head`) and the table's first and last cells (`--table-inset: 16px`) | — | 16px: row actions and the heading's button end here |
| Table inside a padded card or panel (`.table` default) | The card's text line: the edge cells are flush (`--table-inset: 0`) | — | The card's trailing line |
| Links panel (`td.links-panel`, inside the tunnels table) | The table card's text line (16px): the form, the minted link and the nested links table (flush cells) | Same as the text line | The table card's trailing line: Revoke ends under Delete |
| Footer (`.footer`) | Centred | — | — |
| Narrow column (`.narrow`: sign-in, invite, machine approval) | No padding of its own: the card inside it takes the card's lines; centred between header and footer on screens at least 1300px tall and 761px wide (at a 16px browser default; the breakpoints are em) | — | — |

Two rules decide the cases the table does not list:

- **Boxes share the text line inside pages, cards and panels**, as in the
  template: a button, input or alert starts where the text above it starts.
  Table cells keep their 12px inner padding between columns; only the edge
  cells take `--table-inset`.
- **Fix a miss in the container**: its padding, or `--table-inset`. Never
  nudge one item with its own margin.

Unlike the template, this UI has no dialogs, sheets or side navigation, so
their lines do not apply here. Its one dropdown is the header's user menu
(`static/shell.js` draws its button, `static/menu.js` the menu, loaded on
first use so it stays out of the first load's budget), on the template's lines: at least 224px wide (14rem, the
template's `min-w-56`), its trailing edge on its button's (the header's
trailing line), the name and email truncated (full text in `title`), and
44px items on touch screens.

## Forms

Forms follow the template's form-surface rule (`patterns/design-system.md`
§ Form surfaces there): short inline forms in cards or table panels, every
control labelled, safe defaults, human labels for every choice, the unit
next to the number it belongs to, and errors under the field they are about,
with the focus moved to the first one (see `src/limits.rs`). This UI has no
dialogs. If one is added, it holds about six controls at most, must fit
without inner scrolling at 1280×800 and 390×844, and gets the template's
dialog-fits check; anything longer is a page.

A one-click destructive action (Delete a tunnel, Revoke a link or an
invite, Remove a machine) asks first with the browser's own confirm: the
button carries the question in `data-confirm`, and `static/shell.js` asks it
in the capture phase, before the UI's click handler, which never sees the
click on Cancel. It lives in the shell rather than the wasm because an
inline question cost several kilobytes of the first-load budget.

## First paint

`index.html` holds a copy of the shell (`static/shell.html`: header, nav,
user menu button (the theme button when signed out), footer, and a content placeholder shaped like a page or a
narrow card), so a reload never shows a page without its frame while the
wasm loads. `static/shell.js` runs before the first paint and picks what the
copy shows from the `tunnel-shell` hint (`<role>:<username>`, nothing
secret; `src/boot.rs` writes it on every session check and clears it on
sign-out). The app removes the copy in the same task in which it renders the
real shell. `src/boot.rs` tests that the copy's nav is `ui::NAV`, which the
real shell renders from; change both together. The font is preloaded and
`font-display: optional`, so text never reflows under the reader.

`checks/reload-shell.mjs` checks it in a browser, with the rules and markers
of the template's `check:shell-loading` (patterns/agent-ui-testing.md §
Shell loading check there: `[data-app-header]`, `#main-content`,
`[data-route-skeleton]`, `[data-slot="skeleton"]`): hard reloads of
/ (the tunnels list), /tunnels, /admin/users, /machines and /account at 1280 and 390 px, in light,
dark and a stored dark over a light system, on a slow link and a 4× slower
CPU, recording the shell on every frame. It fails when a painted frame lacks
the header or `<main>`, is not the placeholder first, shows other nav links,
moves the header, a nav link, the user menu button or the top of `<main>`, is in
the other theme, or when the layout shift exceeds 0.05 (pages that load
several lists show them together, as the Users page does), or when content
that fits the viewport ends without the footer in it. On a page whose
content does not fit, a shift that only pushes the footer below the first
screen does not count (it is logged as "below the fold"). The Users page
fills the screen while its lists load (as its placeholder does), so the
footer starts below the fold; there every shift counts, as a browser's own
layout-shift score would. The template's
script cannot run here as is (it drives a pnpm/Vite app and the template's
theme key), so this is its port:

```sh
node crates/web/checks/reload-shell.mjs <cdp-ws-url> https://<ui_host> <out-dir> [path=ready-selector ...]
```

The browser must be signed in as an admin (for the Users page). The rules are
tested apart from a browser with `node --test crates/web/checks/`.
