#!/usr/bin/env python3
"""Derive the header logo sizes from the Tunnel artwork (.github/assets/logo.png,
512px, the largest copy in the repository) and check that the favicon and
logo-64.png are the same artwork. Run from the repository root:
python3 -I crates/web/make-logos.py (needs Pillow).

The header draws the logo at 32 CSS px (src/ui.rs `Shell`, static/shell.html):
favicon-32.png is its 1x source (the same file as the tab icon, so already
fetched), logo-64.png 2x and logo-128.png 4x (a 3x screen picks 4x and scales
it down, never a smaller file up). Only logo-128.png is written; logo-64.png
and favicon-32.png are checked, never rewritten: the gate icon embeds
logo-64.png's exact bytes (crates/server/assets/make-gate-icon.py)."""
import pathlib
import sys

from PIL import Image, ImageChops

root = pathlib.Path(__file__).resolve().parents[2]
source = Image.open(root / ".github/assets/logo.png").convert("RGBA")
static = root / "crates/web/static"


def sized(px):
    return source.resize((px, px), Image.LANCZOS)


# A 256-colour palette PNG, like the artwork itself (an 8-bit palette image):
# ~7 KB instead of ~28 KB as RGBA, visually identical (mean channel error < 2),
# and the logo counts against build.sh's first-load budget.
sized(128).quantize(colors=256, method=Image.Quantize.FASTOCTREE).save(
    static / "logo-128.png", optimize=True
)

drift = []
for name, px in (("logo-64.png", 64), ("favicon-32.png", 32)):
    have = Image.open(static / name).convert("RGBA")
    if have.size != (px, px) or ImageChops.difference(have, sized(px)).getbbox(alpha_only=False):
        drift.append(name)
if drift:
    sys.exit(f"not derived from .github/assets/logo.png: {', '.join(drift)}; regenerate them from it")
print("logo-128.png written; logo-64.png and favicon-32.png match the artwork")
