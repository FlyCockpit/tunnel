// Reload check: a hard reload of a signed-in page must paint the app's real
// shell first (header, nav, account link, footer, in the right theme), with
// only the content area waiting, and the shell must not move when the app
// has loaded.
//
//   node crates/web/checks/reload-shell.mjs <cdp-ws-url> <ui-origin> <out-dir> [path...]
//
// <cdp-ws-url> is a Chromium's browser websocket (agent-browser: `get
// cdp-url`) whose profile is signed in to <ui-origin>, after one normal visit
// (that visit writes the hint the first paint uses). For each path (default
// /tunnels and /admin/users) at 390x844 and 1280x800, with the system in
// light and in dark (it clears the stored theme choice), it reloads with the
// cache off on a slow link (150 ms RTT, 1.6 Mbit/s), screenshots the first
// painted frame and the loaded page, and compares the boxes of the header,
// brand, nav links and account link and the page background. Needs Node 22+
// (global WebSocket). Exit 0 when every case passes.
import fs from "node:fs";

const [, , cdp, origin, out, ...args] = process.argv;
if (!cdp || !origin || !out) {
  console.error("usage: reload-shell.mjs <cdp-ws-url> <ui-origin> <out-dir> [path...]");
  process.exit(64);
}
const paths = args.length ? args : ["/tunnels", "/admin/users"];
fs.mkdirSync(out, { recursive: true });

const ws = new WebSocket(cdp);
let seq = 0;
const pending = new Map();
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) {
    pending.get(d.id)(d);
    pending.delete(d.id);
  }
};
await new Promise((r) => (ws.onopen = r));
const send = (method, params = {}, sessionId) =>
  new Promise((r) => {
    const id = ++seq;
    pending.set(id, r);
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const { result: { targetId } } = await send("Target.createTarget", { url: "about:blank" });
const { result: { sessionId: s } } = await send("Target.attachToTarget", { targetId, flatten: true });
await send("Page.enable", {}, s);
await send("Network.enable", {}, s);
const evaluate = async (expression) =>
  (await send("Runtime.evaluate", { expression, returnByValue: true }, s)).result?.result?.value;
const shot = async (file) => {
  const r = await send("Page.captureScreenshot", { format: "png" }, s);
  fs.writeFileSync(file, Buffer.from(r.result.data, "base64"));
};

// What the shell looks like now: boxes of its parts and the background.
const MEASURE = `(() => {
  const box = (el) => { if (!el) return null; const r = el.getBoundingClientRect();
    return r.width || r.height ? [r.x, r.y, r.width, r.height].map(Math.round) : null; };
  const header = document.querySelector(".header");
  return JSON.stringify({
    fresh: !window.__reloadShellOld,
    path: location.pathname,
    painted: performance.getEntriesByType("paint").length > 0,
    boot: !!document.querySelector(".boot"),
    header: box(header),
    brand: box(header && header.querySelector(".brand")),
    nav: header ? [...header.querySelectorAll(".nav a")].filter((a) => box(a)).map((a) => [a.textContent, box(a)]) : [],
    current: header ? [...header.querySelectorAll(".nav a")].filter((a) => getComputedStyle(a).boxShadow !== "none").map((a) => a.textContent) : [],
    account: box(header && header.querySelector(".account-link")),
    background: getComputedStyle(document.body || document.documentElement).backgroundColor,
  });
})()`;

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
let failed = 0;
for (const scheme of ["light", "dark"])
for (const [w, h, mobile] of [[390, 844, true], [1280, 800, false]]) {
  await send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile }, s);
  await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: scheme }] }, s);
  for (const path of paths) {
    // One normal visit first: it signs the hint in and warms nothing (the cache is off below).
    await send("Network.setCacheDisabled", { cacheDisabled: false }, s);
    await send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, s);
    await send("Page.navigate", { url: origin + path }, s);
    await sleep(2500);
    await evaluate(`localStorage.removeItem("tunnel-theme")`);
    // Marks this document, so samples from it (before the reload lands) are skipped.
    await evaluate("window.__reloadShellOld = true");
    await send("Network.setCacheDisabled", { cacheDisabled: true }, s);
    await send("Network.emulateNetworkConditions", { offline: false, latency: 150, downloadThroughput: 1.6e6 / 8, uploadThroughput: 750e3 / 8 }, s);
    await send("Page.reload", { ignoreCache: true }, s);
    const name = `${path.replace(/\//g, "-").replace(/^-/, "") || "root"}-${scheme}-${w}`;
    let first = null;
    const start = Date.now();
    while (Date.now() - start < 20000) {
      const m = JSON.parse((await evaluate(MEASURE)) || "{}");
      if (m.fresh && m.painted && m.path === path) {
        first = m;
        await shot(`${out}/first-${name}.png`);
        break;
      }
      await sleep(20);
    }
    let loaded = null;
    while (Date.now() - start < 40000) {
      const m = JSON.parse((await evaluate(MEASURE)) || "{}");
      if (m.fresh && m.path === path && !m.boot && m.header) {
        loaded = m;
        break;
      }
      await sleep(100);
    }
    await sleep(600);
    if (loaded) loaded = JSON.parse(await evaluate(MEASURE));
    await shot(`${out}/loaded-${name}.png`);
    const problems = [];
    if (!first) problems.push("no first paint seen");
    if (!loaded) problems.push("the app never loaded");
    // The first frame must be index.html's copy of the shell, not the app
    // already loaded (then this run measured nothing).
    if (first && !first.boot) problems.push("the first painted frame was not the boot shell");
    if (first && loaded) {
      for (const k of ["header", "brand", "nav", "current", "account", "background"]) {
        if (!same(first[k], loaded[k])) problems.push(`${k}: first ${JSON.stringify(first[k])} loaded ${JSON.stringify(loaded[k])}`);
      }
      if (!loaded.nav.length) problems.push("the loaded page has no nav (signed out?)");
    }
    failed += problems.length ? 1 : 0;
    console.log(`${problems.length ? "FAIL" : "ok  "} ${path} ${w}x${h} ${scheme}${problems.map((p) => "\n     " + p).join("")}`);
  }
}
await send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, s);
await send("Target.closeTarget", { targetId });
ws.close();
process.exit(failed ? 1 : 0);
