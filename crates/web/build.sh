#!/bin/sh
# Build the web UI into crates/web/dist, which `cargo build -p tunnel-server
# --features ui` embeds. Needs the wasm32-unknown-unknown target, wasm-bindgen
# (exactly the version in Cargo.lock) and, optionally, binaryen's wasm-opt:
#   WASM_BINDGEN=/path/to/wasm-bindgen WASM_OPT=/path/to/wasm-opt crates/web/build.sh
# The CI `web` job pins and checksums both tools. Output file names carry a
# content hash, so the server can cache them as immutable.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
WASM_BINDGEN=${WASM_BINDGEN:-wasm-bindgen}
WASM_OPT=${WASM_OPT:-wasm-opt}
# Total gzip size budget for everything the browser downloads (bytes).
BUDGET=${TUNNEL_UI_BUDGET:-400000}

want=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/"/, "", $3); print $3; exit }' Cargo.lock)
have=$("$WASM_BINDGEN" --version | awk '{ print $2 }')
[ "$want" = "$have" ] || { echo "build.sh: wasm-bindgen $have does not match Cargo.lock ($want)" >&2; exit 1; }

cargo build --locked --release --target wasm32-unknown-unknown ${CARGO_BUILD_JOBS:+-j "$CARGO_BUILD_JOBS"}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$WASM_BINDGEN" --target web --no-typescript --out-dir "$out" --out-name app "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/tunnel-web.wasm"
if command -v "$WASM_OPT" >/dev/null 2>&1; then
  "$WASM_OPT" -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext --enable-mutable-globals \
    --enable-reference-types --enable-multivalue --strip-debug --strip-producers -o "$out/app_bg.opt.wasm" "$out/app_bg.wasm"
  mv "$out/app_bg.opt.wasm" "$out/app_bg.wasm"
else
  echo "build.sh: $WASM_OPT not found; the wasm stays unoptimized" >&2
fi

hash() { sha256sum "$1" | cut -c1-16; }
rm -rf dist
mkdir -p dist/assets
wasm="app-$(hash "$out/app_bg.wasm")_bg.wasm"
cp "$out/app_bg.wasm" "dist/assets/$wasm"
js="app-$(hash "$out/app.js").js"
cp "$out/app.js" "dist/assets/$js"
# The CSP allows no inline script, so the loader is a file too.
printf 'import init from "/assets/%s";\ninit({ module_or_path: "/assets/%s" });\n' "$js" "$wasm" > "$out/boot.js"
boot="boot-$(hash "$out/boot.js").js"
cp "$out/boot.js" "dist/assets/$boot"
# Whole-line // comments in theme.js and shell.js are for readers of
# static/: no browser needs them, and they counted in the first-load budget.
# (No string or template literal in either file spans lines.)
strip_comments() { sed '/^[[:space:]]*\/\//d'; }
strip_comments < static/theme.js > "$out/theme.js"
theme="theme-$(hash "$out/theme.js").js"
cp "$out/theme.js" "dist/assets/$theme"
# The user menu loads on first use (shell.js imports it), so it is not part
# of the first load counted below; shell.js gets its hashed name.
menu="menu-$(hash static/menu.js).js"
cp static/menu.js "dist/assets/$menu"
sed "s#\"/assets/menu.js\"#\"/assets/$menu\"#" static/shell.js | strip_comments > "$out/shell.js"
grep -q "\"/assets/$menu\"" "$out/shell.js" || { echo "build.sh: static/shell.js does not import /assets/menu.js" >&2; exit 1; }
shell="shell-$(hash "$out/shell.js").js"
cp "$out/shell.js" "dist/assets/$shell"
# Until theme.js has set .light or .dark (it is still loading, or scripts are
# off), follow the system: the .dark token blocks again, under the media query.
# The comments stay in the sources and out of the shipped sheet (about a third
# of its gzip bytes). CSS comments do not nest, and the sheets hold no comment
# marks inside strings; an unclosed comment fails the build.
{
  cat style/tokens.css
  printf '@media (prefers-color-scheme: dark) {\n:root:not(.light) {\n'
  awk '/^\.dark \{$/ { on = 1; next } on && /^\}$/ { on = 0; next } on' style/tokens.css
  printf '}\n}\n'
  cat style/app.css
} | awk '
  {
    line = $0; kept = ""
    while (line != "") {
      if (inside) {
        i = index(line, "*/"); if (!i) break
        line = substr(line, i + 2); inside = 0
      } else {
        i = index(line, "/*"); if (!i) { kept = kept line; break }
        kept = kept substr(line, 1, i - 1); line = substr(line, i + 2); inside = 1
      }
    }
    if (kept ~ /[^ \t]/) print kept
  }
  END { if (inside) { print "build.sh: a style sheet has an unclosed comment" > "/dev/stderr"; exit 1 } }
' > "$out/app.css"
css="app-$(hash "$out/app.css").css"
cp "$out/app.css" "dist/assets/$css"
# Stable names: referenced from CSS and the shell; small and rarely changed.
cp static/roboto-latin-wght-normal.woff2 static/logo-64.png static/logo-128.png static/favicon-32.png static/ROBOTO-LICENSE.txt dist/assets/

cat > dist/index.html <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Tunnel</title>
<link rel="icon" type="image/png" href="/assets/favicon-32.png">
<script src="/assets/$theme"></script>
<script src="/assets/$shell"></script>
<link rel="preload" href="/assets/roboto-latin-wght-normal.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/assets/$css">
<link rel="modulepreload" href="/assets/$js">
<link rel="preload" href="/assets/$wasm" as="fetch" type="application/wasm" crossorigin>
<script type="module" src="/assets/$boot"></script>
</head>
<body>
$(cat static/shell.html)
</body>
</html>
HTML

total=0
for f in dist/index.html dist/assets/*; do
  case "$f" in *.woff2 | *.png | *.txt) ;; *) gzip -9 -n -k "$f" ;; esac
done
for f in dist/index.html dist/assets/$js dist/assets/$wasm dist/assets/$boot dist/assets/$theme dist/assets/$shell dist/assets/$css; do
  total=$((total + $(wc -c < "$f.gz")))
done
total=$((total + $(wc -c < dist/assets/roboto-latin-wght-normal.woff2)))
# The header logo is on the first paint too (static/shell.html). A screen
# fetches one of its srcset files: count the largest in bytes (not the widest:
# logo-128.png is a palette PNG and can be smaller than logo-64.png; PNGs are
# not gzipped), plus the favicon, which every load fetches (it is also the 1x).
logo=0
for f in dist/assets/logo-64.png dist/assets/logo-128.png; do
  n=$(wc -c < "$f"); [ "$n" -gt "$logo" ] && logo=$n
done
total=$((total + logo + $(wc -c < dist/assets/favicon-32.png)))
echo "build.sh: dist/ ready; first load is $total bytes gzip (budget $BUDGET)"
ls -l dist/assets
[ "$total" -le "$BUDGET" ] || { echo "build.sh: over the size budget" >&2; exit 1; }
