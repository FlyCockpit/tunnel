// The rules of reload-shell.mjs (see there), apart from the browser so
// they can be tested: `node --test crates/web/checks/`.

export const MAX_CLS = 0.05;

const round = (n) => Math.round(n * 1000) / 1000;

/**
 * Whether a layout-shift entry only pushed the footer below the first screen.
 * `sources` are the entry's moved boxes as the page saw them when the entry
 * arrived: `footer` (it is the page's footer), `top` (its top in the viewport
 * then, null when it was no longer in the page) and `rect` (the entry's
 * `currentRect`, clipped to the viewport). Anything else, or a footer that may
 * have gone up instead (no live position, or not below), counts. Runs in the
 * page too (reload-shell.mjs embeds its source): self-contained.
 */
export function footerPushedBelow(sources, vh) {
  return (
    sources.length > 0 &&
    sources.every((s) => s.footer && s.top !== null && s.top >= vh && (!(s.rect.width || s.rect.height) || s.rect.top >= vh))
  );
}

/**
 * Whether the loaded page's content fits the first screen with its footer:
 * `contentEnd` is where the content ends (the lowest visible box without
 * children plus the page's bottom padding), so a page held taller than its
 * content (a min-height) still counts as short.
 */
export function fits(final) {
  return final.contentEnd + (final.footer?.[3] ?? 0) <= final.vh + 1;
}

/**
 * The layout shift that counts, and what was below the fold of a long page:
 * on a page that does not fit, shifts that only pushed the footer below the
 * first screen. `all` counts every shift (what a browser reports as CLS).
 */
export function shiftScore(shifts, final) {
  const long = !fits(final);
  const counted = shifts.filter((s) => !(long && s.below));
  const sum = (list) => round(list.reduce((n, s) => n + s.v, 0));
  return { cls: sum(counted), belowFold: sum(shifts.filter((s) => !counted.includes(s))), all: sum(shifts) };
}

const moved = (a, b) => (!a || !b ? a !== b : a.some((v, i) => Math.abs(v - (b[i] ?? 0)) > 1));

/**
 * One message per broken rule; empty means the page loads inside its shell.
 * `strict`: every shift counts, below the fold too (a page that reserves the
 * screen while it loads, so its real layout shift stays under the limit).
 */
export function judge(label, { fresh, frames, final, shifts, truncated }, expectDark, strict = false) {
  if (!fresh) return [`${label}: measured the page before the reload (the reload did not replace it)`];
  // Every frame from the first paint on, blank ones included (a blank flash
  // is a frame without the header).
  const from = frames.findIndex((f) => f.painted);
  if (from < 0) return [`${label}: no painted frame was recorded`];
  if (truncated) return [`${label}: the load took too many frames to record`];
  const painted = frames.slice(from);
  const first = painted[0];
  if (final.skeleton || final.loading) return [`${label}: the page never finished loading`];
  if (!final.header || !final.main) return [`${label}: the loaded page has no ${final.header ? "<main>" : "header"}`];
  if (!final.nav.length || !final.account) return [`${label}: the loaded page has no nav or account link (not signed in?)`];
  const bad = [];
  const at = (f) => `${Math.round(f.t)}ms`;
  if (!first.header) bad.push(`${label}: the first painted frame has no header`);
  if (!first.main) bad.push(`${label}: the first painted frame has no <main>`);
  if (!first.skeleton) bad.push(`${label}: the first painted frame is not the content placeholder`);
  const lost = painted.find((f) => !f.header || !f.main);
  if (lost) bad.push(`${label}: the ${lost.header ? "<main>" : "header"} is missing ${at(lost)} into the load`);
  const jump = painted.find((f) => f.header && moved(f.header, final.header));
  if (jump) bad.push(`${label}: the header moves (${jump.header} at ${at(jump)}, ${final.header} loaded)`);
  const names = (f) => JSON.stringify(f.nav.map((n) => n[0]));
  const navOff = painted.find((f) => f.header && names(f) !== names(final));
  if (navOff) bad.push(`${label}: the nav shows ${names(navOff)} at ${at(navOff)}, ${names(final)} loaded`);
  const linkJump = painted.find((f) => f.nav.some(([text, b]) => moved(b, final.nav.find((n) => n[0] === text)?.[1] ?? null)));
  if (linkJump) bad.push(`${label}: a nav link moves at ${at(linkJump)}: ${JSON.stringify(linkJump.nav)} vs ${JSON.stringify(final.nav)}`);
  const current = painted.find((f) => f.header && JSON.stringify(f.current) !== JSON.stringify(final.current));
  if (current) bad.push(`${label}: the current link is ${JSON.stringify(current.current)} at ${at(current)}, ${JSON.stringify(final.current)} loaded`);
  const account = painted.find((f) => f.header && moved(f.account, final.account));
  if (account) bad.push(`${label}: the account link is ${account.account} at ${at(account)}, ${final.account} loaded`);
  const mainTop = painted.find((f) => f.main && Math.abs(f.main[1] - final.main[1]) > 1);
  if (mainTop) bad.push(`${label}: the content starts at ${mainTop.main[1]}px at ${at(mainTop)}, ${final.main[1]}px loaded`);
  const loadedAt = painted.findIndex((f) => !f.skeleton && !f.loading);
  const relapse = loadedAt >= 0 ? painted.slice(loadedAt).find((f) => f.skeleton) : undefined;
  if (relapse) bad.push(`${label}: back to the placeholder ${at(relapse)} into the load`);
  const theme = painted.find((f) => f.dark !== expectDark);
  if (theme) bad.push(`${label}: a frame at ${at(theme)} is ${theme.dark ? "dark" : "light"}, expected ${expectDark ? "dark" : "light"}`);
  const score = shiftScore(shifts, final);
  const cls = strict ? score.all : score.cls;
  if (cls > MAX_CLS) bad.push(`${label}: cumulative layout shift ${cls}${strict ? " (all of it counts here)" : ""} exceeds ${MAX_CLS}`);
  // A page whose content fits the viewport ends with its footer on screen.
  const { footer, vh } = final;
  if (fits(final) && !(footer && footer[1] >= 0 && footer[1] + footer[3] <= vh + 1))
    bad.push(`${label}: the content fits the viewport, but the footer (${footer}) is not in it`);
  return bad;
}
