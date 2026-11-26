// Shell loading check: a hard reload of a signed-in page must paint the
// app's real shell first (header with the nav and user menu button, `<main>`, in
// the right theme), with only the content area as a placeholder, and nothing
// outside the content may move until the page has loaded.
//
//   node crates/web/checks/reload-shell.mjs <cdp-ws-url> <ui-origin> <out-dir> [path=ready-selector ...]
//
// The rules are the FlyCockpit template's `check:shell-loading`
// (scripts/check-shell-loading.ts there; patterns/agent-ui-testing.md §
// Shell loading check) with the same markers (`[data-app-header]`,
// `#main-content`, `[data-route-skeleton]`, `[data-slot="skeleton"]`). The
// template's script itself cannot run here: it drives a pnpm/Vite app and
// stores the theme under the template's key. This one adds tun's nav check:
// every painted frame shows the loaded page's nav links, current link and
// user menu button in the same places.
//
// <cdp-ws-url> is a Chromium's browser websocket (agent-browser: `get
// cdp-url`) whose profile is signed in to <ui-origin> as an admin. For each
// page (default /, /tunnels, /admin/users, /machines, /account) at 1280x800 and 390x844, with the
// system light and no stored theme, the system dark and no stored theme, and
// the system light with "dark" stored, it loads the page once normally (that
// visit writes the hint the first paint uses), then reloads it with the cache
// off on a slow link and a 4x slower CPU (150 ms RTT, 4 Mbit/s) while a
// script recorded from document start notes the shell on every animation
// frame. It fails when:
// - the first painted frame has no header or `<main>`, or is not the content
//   placeholder; any later frame loses the header or `<main>`;
// - the header, any nav link, the current link or the user menu button moves by
//   more than 1px, or the top of `<main>` moves, between a painted frame and
//   the loaded page; a nav link is missing or extra in any frame;
// - a painted frame is in the other theme; the page goes back to the
//   placeholder after it had loaded; cumulative layout shift exceeds 0.05;
//   the loaded content fits the viewport but the footer is not in it.
// Layout shift counts the shell and the first screen. On a page whose content
// does not fit the viewport, a shift whose every moved box is the footer
// pushed below the first screen does not count: a long list pushing the
// footer below the fold moves nothing the reader sees (it is reported as
// "below the fold"). Any other shift counts in full. /admin/users fills the
// screen while its lists load, so there every shift counts.
// It clears the profile's stored theme choice. Screenshots of the loaded
// pages go to <out-dir>. Needs Node 22+ (global WebSocket). Exit 0 when
// every case passes.
import fs from "node:fs";
import { footerPushedBelow, judge, shiftScore } from "./reload-shell-judge.mjs";

const [, , cdp, origin, out, ...args] = process.argv;
if (!cdp || !origin || !out) {
  console.error("usage: reload-shell.mjs <cdp-ws-url> <ui-origin> <out-dir> [path=ready-selector ...]");
  process.exit(64);
}
// A selector that exists only once the page's real content is there.
const PAGES = args.length
  ? args.map((a) => a.split(/=(.*)/s).slice(0, 2))
  : [
      ["/", "#main-content :is(.tunnels-table, .empty)"],
      ["/tunnels", "#main-content :is(.tunnels-table, .empty)"],
      ["/admin/users", "#main-content table thead", true],
      ["/machines", "#main-content :is(table thead, .empty)"],
      ["/account", "#main-content .ua-raw"],
    ];
fs.mkdirSync(out, { recursive: true });

// Runs at document start in the page; records the shell on every frame.
const INIT = `(() => {
  if (window.top !== window) return;
  const box = (el) => {
    if (!el) return null;
    const r = el.getBoundingClientRect();
    return r.width || r.height ? [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)] : null;
  };
  const seen = (sel) => [...document.querySelectorAll(sel)].find((el) => box(el) && getComputedStyle(el).visibility === "visible") || null;
  const snap = () => {
    const body = document.body;
    const painted = !!body && [...body.querySelectorAll("*")].some((el) => {
      if (el.tagName === "SCRIPT" || el.tagName === "STYLE") return false;
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
    });
    const header = seen("[data-app-header]");
    const visible = (el) => !!el && !!box(el) && getComputedStyle(el).visibility === "visible";
    const links = header ? [...header.querySelectorAll(".nav a")].filter(visible) : [];
    const account = header && header.querySelector(".user-menu-btn");
    const footer = seen("body > footer");
    const main = document.getElementById("main-content");
    // Where the content ends: the lowest visible box without children, plus
    // the page's bottom padding (not a min-height that holds it taller).
    let end = 0;
    if (main) for (const el of main.querySelectorAll("*")) {
      if (el.children.length || getComputedStyle(el).visibility !== "visible") continue;
      const r = el.getBoundingClientRect();
      if (r.width || r.height) end = Math.max(end, r.bottom);
    }
    const last = main && main.lastElementChild;
    return {
      t: performance.now(),
      painted,
      header: box(header),
      main: box(seen("#main-content")),
      nav: links.map((a) => [a.textContent, box(a)]),
      current: links.filter((a) => getComputedStyle(a).boxShadow !== "none").map((a) => a.textContent),
      account: visible(account) ? box(account) : null,
      footer: box(footer),
      vh: innerHeight,
      contentEnd: Math.round(end + (last ? parseFloat(getComputedStyle(last).paddingBottom) || 0 : 0)),
      dark: document.documentElement.classList.contains("dark"),
      skeleton: !!seen("#main-content [data-route-skeleton]"),
      loading: !!seen('#main-content [data-slot="skeleton"]'),
    };
  };
  const frames = [];
  window.__shellFrames = frames;
  window.__shellSnap = snap;
  // Each shift, and whether it only pushed the footer below the first screen.
  const shifts = [];
  window.__shellShifts = shifts;
  const footerPushedBelow = ${footerPushedBelow.toString()};
  try {
    new PerformanceObserver((list) => {
      for (const e of list.getEntries())
        if (!e.hadRecentInput) {
          const sources = (e.sources || []).map((s) => {
            const live = s.node && s.node.nodeType === 1 && s.node.isConnected ? s.node : null;
            return { footer: !!live && live.matches("body > footer"), top: live ? live.getBoundingClientRect().top : null, rect: s.currentRect };
          });
          shifts.push({ t: e.startTime, v: e.value, below: footerPushedBelow(sources, innerHeight) });
        }
    }).observe({ type: "layout-shift", buffered: true });
  } catch {}
  const tick = () => {
    if (frames.length < 20000) frames.push(snap());
    else window.__shellTruncated = true;
    if (!window.__shellDone) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
})()`;
const READ = `(() => {
  window.__shellDone = true;
  return JSON.stringify({ fresh: !window.__reloadShellOld, frames: window.__shellFrames || [], final: window.__shellSnap(), shifts: window.__shellShifts || [], truncated: !!window.__shellTruncated });
})()`;


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
await send("Page.addScriptToEvaluateOnNewDocument", { source: INIT }, s);
const evaluate = async (expression) =>
  (await send("Runtime.evaluate", { expression, returnByValue: true }, s)).result?.result?.value;
const fast = async () => {
  await send("Network.setCacheDisabled", { cacheDisabled: false }, s);
  await send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, s);
  await send("Emulation.setCPUThrottlingRate", { rate: 1 }, s);
};

let failed = 0;
const MODES = [
  ["light", null, false],
  ["dark", null, true],
  ["light", "dark", true],
];
for (const [system, stored, expectDark] of MODES)
  for (const [w, h, mobile] of [[1280, 800, false], [390, 844, true]]) {
    await send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile }, s);
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: system }] }, s);
    for (const [path, ready, strict = false] of PAGES) {
      const label = `${path} ${w}x${h} system ${system}${stored ? `, stored ${stored}` : ""}`;
      await fast();
      await send("Page.navigate", { url: origin + path }, s);
      await sleep(2500);
      await evaluate(stored ? `localStorage.setItem("tunnel-theme", "${stored}")` : `localStorage.removeItem("tunnel-theme")`);
      await send("Network.setCacheDisabled", { cacheDisabled: true }, s);
      await send("Network.emulateNetworkConditions", { offline: false, latency: 150, downloadThroughput: (4 * 1024 * 1024) / 8, uploadThroughput: (1024 * 1024) / 8 }, s);
      await send("Emulation.setCPUThrottlingRate", { rate: 4 }, s);
      // Marks the warm-up document: only the new one counts.
      await evaluate("window.__reloadShellOld = true");
      const nav = await send("Page.navigate", { url: origin + path }, s);
      const navError = nav.error?.message || nav.result?.errorText;
      // The ready element must be on screen: a list can be rendered but hidden until its data is in.
      const done = `!window.__reloadShellOld && [...document.querySelectorAll(${JSON.stringify(ready)})].some((el) => el.getClientRects().length > 0) && !document.querySelector('#main-content [data-slot="skeleton"], #main-content [data-route-skeleton]')`;
      const until = Date.now() + 60_000;
      let loaded = false;
      while (Date.now() < until && !(loaded = (await evaluate(done)) === true)) await sleep(250);
      await sleep(1000);
      const recording = !navError && loaded ? JSON.parse(await evaluate(READ)) : null;
      const problems = navError
        ? [`${label}: the reload failed: ${navError}`]
        : recording
          ? judge(label, recording, expectDark, strict)
          : [`${label}: still loading after 60s (waiting for ${ready})`];
      const score = recording?.final ? shiftScore(recording.shifts, recording.final) : null;
      const cls = score ? ` (CLS ${score.cls}${score.belowFold ? `, ${score.belowFold} below the fold` : ""}, all ${score.all})` : "";
      const shot = await send("Page.captureScreenshot", { format: "png" }, s);
      const name = `${path.replace(/\//g, "-").replace(/^-/, "") || "root"}-${w}-${system}${stored ? `-stored-${stored}` : ""}`;
      fs.writeFileSync(`${out}/loaded-${name}.png`, Buffer.from(shot.result.data, "base64"));
      failed += problems.length ? 1 : 0;
      console.log(`${problems.length ? "FAIL" : "ok  "} ${label}${cls}${problems.map((p) => "\n     " + p).join("")}`);
    }
  }
await fast();
await evaluate(`localStorage.removeItem("tunnel-theme")`);
await send("Target.closeTarget", { targetId });
ws.close();
process.exit(failed ? 1 : 0);
