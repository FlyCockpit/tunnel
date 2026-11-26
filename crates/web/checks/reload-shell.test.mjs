// node --test crates/web/checks/
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fits, footerPushedBelow, judge, sessionProblem, shiftScore } from "./reload-shell-judge.mjs";

const frame = (over = {}) => ({
  t: 100,
  painted: true,
  header: [0, 0, 1280, 52],
  main: [0, 52, 1280, 698],
  nav: [["Tunnels", [100, 10, 60, 30]]],
  current: ["Tunnels"],
  account: [1100, 10, 80, 30],
  dark: false,
  skeleton: false,
  loading: false,
  footer: [0, 750, 1280, 50],
  vh: 800,
  contentEnd: 400,
  ...over,
});
const recording = (final, shifts) => ({
  fresh: true,
  truncated: false,
  frames: [frame({ skeleton: true, loading: true }), final],
  final,
  shifts,
});
// The Users page's lists push the footer out of the first screen (e2e5-tun follow-up 01).
const footerLeaves = { t: 2600, v: 0.063, below: true };
const long = frame({ footer: [0, 2173, 1280, 50], contentEnd: 2173 });
const short = frame();
const empty = { top: 0, left: 0, width: 0, height: 0 };

test("only the footer pushed below the first screen is below the fold", () => {
  const footer = (top, rect = empty) => ({ footer: true, top, rect });
  assert.equal(footerPushedBelow([footer(2173)], 800), true);
  assert.equal(footerPushedBelow([footer(800)], 800), true);
  // Gone up, not down: the clipped rect is empty either way; its live position tells.
  assert.equal(footerPushedBelow([footer(-60)], 800), false);
  // Still (partly) on screen.
  assert.equal(footerPushedBelow([footer(780, { top: 780, left: 0, width: 1280, height: 20 })], 800), false);
  // No longer in the page: direction unknown, so it counts.
  assert.equal(footerPushedBelow([footer(null)], 800), false);
  // Any other moved box makes the whole entry count.
  assert.equal(footerPushedBelow([footer(2173), { footer: false, top: 900, rect: empty }], 800), false);
  assert.equal(footerPushedBelow([], 800), false);
});

test("the footer leaving the first screen of a long page does not count", () => {
  assert.deepEqual(shiftScore([footerLeaves], long), { cls: 0, belowFold: 0.063, all: 0.063 });
  assert.deepEqual(judge("users", recording(long, [footerLeaves]), false), []);
});

test("a strict page counts every shift", () => {
  assert.match(judge("users", recording(long, [footerLeaves]), false, true).join("\n"), /0.063 \(all of it counts here\)/);
  assert.deepEqual(judge("users", recording(long, [{ t: 1, v: 0.004, below: true }]), false, true), []);
});

test("on a page that fits the viewport every shift counts", () => {
  assert.deepEqual(shiftScore([footerLeaves], short), { cls: 0.063, belowFold: 0, all: 0.063 });
  assert.match(judge("p", recording(short, [footerLeaves]), false).join("\n"), /cumulative layout shift 0.063/);
});

test("shifts in the first screen count on long pages too", () => {
  const seen = { t: 2600, v: 0.04, below: false };
  assert.deepEqual(shiftScore([seen, footerLeaves, seen], long), { cls: 0.08, belowFold: 0.063, all: 0.143 });
  assert.equal(judge("users", recording(long, [seen, footerLeaves, seen]), false).length, 1);
});

test("content that fits the viewport ends with the footer in it", () => {
  assert.equal(fits(short), true);
  assert.equal(fits(frame({ contentEnd: 760 })), false);
  // Held taller than its content (a min-height left on): still short, so the
  // footer below the fold fails, and shifts pushing it there count.
  const held = frame({ footer: [0, 852, 1280, 50] });
  assert.match(judge("p", recording(held, []), false).join("\n"), /content fits the viewport, but the footer .* is not in it/);
  assert.equal(shiftScore([footerLeaves], held).cls, 0.063);
  // Above the viewport is not in it either.
  assert.match(judge("p", recording(frame({ footer: [0, -60, 1280, 50] }), []), false).join("\n"), /footer/);
  assert.match(judge("p", recording(frame({ footer: null }), []), false).join("\n"), /footer/);
  assert.deepEqual(judge("p", recording(short, []), false), []);
  // A long page may have its footer below the fold.
  assert.deepEqual(judge("p", recording(long, []), false), []);
});

test("the profile must be signed in, as an admin for /admin/users", () => {
  const o = "https://tunnel.example";
  assert.equal(sessionProblem(o, { user: { role: "owner" } }, true), null);
  assert.equal(sessionProblem(o, { user: { role: "admin" } }, true), null);
  assert.equal(sessionProblem(o, { user: { role: "member" } }, false), null);
  assert.match(sessionProblem(o, { user: { role: "member" } }, true), /as a member; \/admin\/users needs an admin/);
  assert.match(sessionProblem(o, { user: null, pending: true }, false), /not signed in to https:\/\/tunnel.example; sign in there first/);
  assert.match(sessionProblem(o, { user: null }, true), /sign in there as an admin first/);
  assert.match(sessionProblem(o, { error: "HTTP 502" }, true), /could not read .*\/ui\/api\/session \(HTTP 502\)/);
  assert.match(sessionProblem(o, undefined, true), /\(no reply\)/);
});

test("the session probe sends the header every /ui/api request needs", () => {
  const check = fs.readFileSync(new URL("./reload-shell.mjs", import.meta.url), "utf8");
  assert.match(check, /fetch\("\/ui\/api\/session", \{[^}]*headers: \{ "X-Tunnel-CSRF": "1" \}/);
});
