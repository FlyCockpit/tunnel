#!/usr/bin/env python3
"""Regenerate gate-icon.svg and gate-icon-32.png: the Tunnel logo
(crates/web/static/logo-64.png) with a padlock badge, for the sign-in pages
the gate serves. Run from the repository root: python3 -I crates/server/assets/make-gate-icon.py
(needs Pillow)."""
import base64
import pathlib

from PIL import Image, ImageDraw

root = pathlib.Path(__file__).resolve().parents[3]
logo = root / "crates/web/static/logo-64.png"
out = root / "crates/server/assets"

# Badge geometry on a 64x64 canvas: a dark disc with a white padlock.
BADGE = (47, 47, 17)  # cx, cy, r
RING = 2.5
BODY = (38.5, 44, 55.5, 57, 2.5)  # x0, y0, x1, y1, corner radius
SHACKLE = (42, 36, 52, 46)  # x0, y0, x1, y1 of the arc's box (top half drawn)
STROKE = 3
KEYHOLE = (47, 50, 1.8)
DARK, LIGHT = "#1f1f1f", "#ffffff"

png64 = base64.b64encode(logo.read_bytes()).decode()
cx, cy, r = BADGE
x0, y0, x1, y1, rr = BODY
sx0, sy0, sx1, sy1 = SHACKLE
sr = (sx1 - sx0) / 2
kx, ky, kr = KEYHOLE
svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
<image width="64" height="64" href="data:image/png;base64,{png64}"/>
<circle cx="{cx}" cy="{cy}" r="{r}" fill="{DARK}" stroke="{LIGHT}" stroke-width="{RING}"/>
<path d="M{sx0} {sy0 + sr + 5}V{sy0 + sr}a{sr} {sr} 0 0 1 {2 * sr} 0V{sy0 + sr + 5}" fill="none" stroke="{LIGHT}" stroke-width="{STROKE}"/>
<rect x="{x0}" y="{y0}" width="{x1 - x0}" height="{y1 - y0}" rx="{rr}" fill="{LIGHT}"/>
<circle cx="{kx}" cy="{ky}" r="{kr}" fill="{DARK}"/>
</svg>
"""
(out / "gate-icon.svg").write_text(svg)

# The PNG fallback: the same drawing at 8x, scaled down to 32px.
S = 8
img = Image.open(logo).convert("RGBA").resize((64 * S, 64 * S), Image.LANCZOS)
d = ImageDraw.Draw(img)
R = r + RING / 2
d.ellipse([(cx - R) * S, (cy - R) * S, (cx + R) * S, (cy + R) * S], fill=LIGHT)
R = r - RING / 2
d.ellipse([(cx - R) * S, (cy - R) * S, (cx + R) * S, (cy + R) * S], fill=DARK)
h = STROKE / 2
d.arc([(sx0 - h) * S, (sy0 - h) * S, (sx1 + h) * S, (sy1 + h) * S], 180, 360, fill=LIGHT, width=STROKE * S)
d.rectangle([(sx0 - h) * S, (sy0 + sr) * S, (sx0 + h) * S, (y0 + 1) * S], fill=LIGHT)
d.rectangle([(sx1 - h) * S, (sy0 + sr) * S, (sx1 + h) * S, (y0 + 1) * S], fill=LIGHT)
d.rounded_rectangle([x0 * S, y0 * S, x1 * S, y1 * S], radius=rr * S, fill=LIGHT)
d.ellipse([(kx - kr) * S, (ky - kr) * S, (kx + kr) * S, (ky + kr) * S], fill=DARK)
img.resize((32, 32), Image.LANCZOS).save(out / "gate-icon-32.png", optimize=True)
