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

The **text line** is where headings, labels and table text start. The **box
line** is where buttons, inputs, selects, alerts and copy fields start. The
**trailing line** is where the last item in a row ends.

| Container | Text line | Box line | Trailing line |
|---|---|---|---|
| Header (`.header`) | 16px from the window edge: the brand | Same as the text line | 16px from the window edge: the last control's box ends here |
| Page (`.page`) | 16px inside the page box (`padding: … 16px`): `h1`, the intro line, the alert boxes | Same as the text line: cards, alerts and the page-head controls start on it | 16px inside the page box: the page-head controls and the cards end here |
| Card (`.card`) | 16px inside the card | Same as the text line: inputs, buttons, copy fields, alerts | 16px inside the card |
| Table card (`.card-tight`, the table is the card's edge) | 16px: the heading (`.card-head`) and the table's first and last cells (`--table-inset: 16px`) | — | 16px: row actions and the heading's button end here |
| Table inside a padded card or panel (`.table` default) | The card's text line: the edge cells are flush (`--table-inset: 0`) | — | The card's trailing line |
| Links panel (`td.links-panel`, inside the tunnels table) | The table card's text line (16px): the form, the minted link and the nested links table (flush cells) | Same as the text line | The table card's trailing line: Revoke ends under Delete |
| Footer (`.footer`) | Centred | — | — |
| Narrow column (`.narrow`: sign-in, invite, machine approval) | No padding of its own: the card inside it takes the card's lines | — | — |

Two rules decide the cases the table does not list:

- **Boxes share the text line inside pages, cards and panels**, as in the
  template: a button, input or alert starts where the text above it starts.
  Table cells keep their 12px inner padding between columns; only the edge
  cells take `--table-inset`.
- **Fix a miss in the container**: its padding, or `--table-inset`. Never
  nudge one item with its own margin.

Unlike the template, this UI has no dialogs, sheets, dropdown menus or side
navigation, so their lines do not apply here. The account is a header link,
not a menu. If one is added, it takes the template's lines: an account menu at
least 224px wide (`min-w-56`) with the email truncated (full address in
`title`), and close buttons with a 44px target on mobile.

## Forms

Forms follow the template's form-surface rule (`patterns/design-system.md`
§ Form surfaces there): short inline forms in cards or table panels, every
control labelled, safe defaults, human labels for every choice, the unit
next to the number it belongs to, and errors under the field they are about,
with the focus moved to the first one (see `src/limits.rs`). This UI has no
dialogs. If one is added, it holds about six controls at most, must fit
without inner scrolling at 1280×800 and 390×844, and gets the template's
dialog-fits check; anything longer is a page.

## First paint

`index.html` holds a copy of the shell (`static/shell.html`: header, nav,
account link, footer, and a content placeholder shaped like a page or a
narrow card), so a reload never shows a page without its frame while the
wasm loads. `static/shell.js` runs before the first paint and picks what the
copy shows from the `tunnel-shell` hint (`<role>:<username>`, nothing
secret; `src/boot.rs` writes it on every session check and clears it on
sign-out). The app removes the copy in the same task in which it renders the
real shell. `src/boot.rs` tests that the copy's nav is `ui::NAV`, which the
real shell renders from; change both together. The font is preloaded and
`font-display: optional`, so text never reflows under the reader.

`checks/reload-shell.mjs` checks it in a browser: hard reloads of two
signed-in pages at 390 and 1280 px, light and dark, on a slow link, comparing
the first painted frame's header, nav and account link with the loaded page:

```sh
node crates/web/checks/reload-shell.mjs <cdp-ws-url> https://<ui_host> <out-dir> [path...]
```

The browser must be signed in as an admin (for the Users page) and have
visited the UI once.
