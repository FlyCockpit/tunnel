// node --test crates/web/checks/
// The user menu's markup and keyboard rules (static/menu.js); the browser
// behaviour is covered by the e2e walk.
import assert from "node:assert/strict";
import test from "node:test";
import { isCurrent, markup, step, THEMES, typeahead } from "../static/menu.js";

/** `[role, text]` of each item, in order. */
const items = (html) =>
  [...html.matchAll(/class="menu-item[^"]*" role="(menuitem|menuitemradio)"[^>]*>.*?<span>([^<]*)<\/span><\/(?:a|button)>/g)].map((m) => [m[1], m[2]]);

test("admins get Account, the Admin group, the theme and Sign out", () => {
  const html = markup(true);
  assert.deepEqual(items(html), [
    ["menuitem", "Account"],
    ["menuitem", "Users"],
    ["menuitem", "Server"],
    ["menuitemradio", "Light"],
    ["menuitemradio", "Dark"],
    ["menuitemradio", "System"],
    ["menuitem", "Sign out"],
  ]);
  for (const part of [
    '<span class="menu-who-title">My account</span><span class="menu-who-name"></span><span class="menu-who-email"></span>',
    'href="/account" data-act="go"',
    'href="/admin/users" data-act="go"',
    'href="/admin/status" data-act="go"',
    'role="group" aria-labelledby="menu-admin"',
    'role="group" aria-labelledby="menu-theme"',
    'data-act="sign-out"',
  ])
    assert.ok(html.includes(part), part);
});

test("members get no Admin group; signed out, only the theme", () => {
  const member = markup(false);
  assert.deepEqual(items(member).map((i) => i[1]), ["Account", "Light", "Dark", "System", "Sign out"]);
  assert.ok(!member.includes("Admin") && !member.includes("/admin/"));
  const out = markup(null);
  assert.deepEqual(items(out).map((i) => i[1]), ["Light", "Dark", "System"]);
  assert.ok(!out.includes("menu-who") && !out.includes("separator"));
});

test("every item is out of the tab order and starts unchecked; no user data is markup", () => {
  for (const admin of [true, false, null]) {
    const html = markup(admin);
    const n = (html.match(/class="menu-item/g) || []).length;
    assert.equal((html.match(/tabindex="-1"/g) || []).length, n);
    assert.equal((html.match(/aria-checked="false"/g) || []).length, THEMES.length);
    assert.ok(!html.includes("undefined") && !html.includes("null"));
  }
  assert.deepEqual(THEMES.map((t) => t[0]), ["light", "dark", "system"]);
});

test("the arrows wrap, Home and End jump", () => {
  assert.equal(step("ArrowDown", null, 5), 0);
  assert.equal(step("ArrowUp", null, 5), 4);
  assert.equal(step("ArrowDown", 4, 5), 0);
  assert.equal(step("ArrowUp", 0, 5), 4);
  assert.equal(step("ArrowDown", 1, 5), 2);
  assert.equal(step("Home", 3, 5), 0);
  assert.equal(step("End", 1, 5), 4);
  assert.equal(step("x", 1, 5), null);
  assert.equal(step("ArrowDown", null, 0), null);
});

test("typing a letter moves to the next item that starts with it", () => {
  const texts = ["Account", "Users", "Server", "Light", "Dark", "System", "Sign out"];
  assert.equal(typeahead(texts, null, "s"), 2);
  assert.equal(typeahead(texts, 2, "S"), 5);
  assert.equal(typeahead(texts, 6, "s"), 2);
  assert.equal(typeahead(texts, 0, "a"), 0);
  assert.equal(typeahead(texts, 0, "q"), null);
});

test("the current page: itself or below it, / is the tunnels list", () => {
  assert.ok(isCurrent("/", "/tunnels"));
  assert.ok(isCurrent("/account/sessions", "/account"));
  assert.ok(isCurrent("/admin/users", "/admin/users"));
  assert.ok(!isCurrent("/admin/users", "/admin/status"));
  assert.ok(!isCurrent("/accounting", "/account"));
});
