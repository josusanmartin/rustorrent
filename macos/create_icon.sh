#!/bin/bash
# Builds macos/AppIcon.icns from macos/AppIcon.svg, the Rustorrent mark on the
# macOS icon grid (the same mark as docs/assets/logo.svg and the web UI).
#
# Needs python3 with Pillow, plus one SVG renderer: rsvg-convert, or a
# Chromium-based browser (set CHROME=/path/to/chrome, otherwise Google
# Chrome.app or chromium on PATH). The SVG is rendered once at 1024 px and
# scaled down; large sizes are palette-quantized to keep the DMG small.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVG="$SCRIPT_DIR/AppIcon.svg"
OUTPUT="$SCRIPT_DIR/AppIcon.icns"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

find_chrome() {
  if [[ -n "${CHROME:-}" ]]; then echo "$CHROME"; return; fi
  local app="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
  if [[ -x "$app" ]]; then echo "$app"; return; fi
  command -v chromium || command -v chromium-browser || command -v google-chrome || true
}

if command -v rsvg-convert >/dev/null; then
  rsvg-convert -w 1024 -h 1024 "$SVG" -o "$WORK/master.png"
else
  chrome="$(find_chrome)"
  if [[ -z "$chrome" ]]; then
    echo "install rsvg-convert (brew install librsvg) or set CHROME" >&2
    exit 1
  fi
  { printf '<html><style>body{margin:0}svg{display:block;width:1024px;height:1024px}</style><body>'
    cat "$SVG"; } > "$WORK/page.html"
  sandbox=()
  [[ "$(id -u)" == 0 ]] && sandbox=(--no-sandbox)
  # Headless viewports are shorter than the window, so leave room and crop.
  "$chrome" --headless "${sandbox[@]}" --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --default-background-color=00000000 --window-size=1024,1280 \
    --screenshot="$WORK/master.png" "file://$WORK/page.html" >/dev/null 2>&1
fi

# An .icns file is a list of (type, length, PNG) records.
python3 - "$WORK/master.png" "$OUTPUT" <<'PYTHON'
import io, struct, sys
from PIL import Image, ImageChops

master = Image.open(sys.argv[1]).convert('RGBA').crop((0, 0, 1024, 1024))

def dithered(image):
    # A light 4x4 ordered dither hides palette banding in the gradient.
    bayer = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5]
    cell = Image.new('L', (4, 4))
    cell.putdata([int(128 + (v - 7.5) * 0.6) for v in bayer])
    noise = Image.new('L', image.size)
    for y in range(0, image.height, 4):
        for x in range(0, image.width, 4):
            noise.paste(cell, (x, y))
    r, g, b, a = image.split()
    shift = lambda band: ImageChops.add(band, noise, 1, -128)
    return Image.merge('RGBA', (shift(r), shift(g), shift(b), a))

def png(size):
    image = master.resize((size, size), Image.LANCZOS)
    if size >= 256:
        image = dithered(image).quantize(256, method=Image.Quantize.FASTOCTREE)
    out = io.BytesIO()
    image.save(out, 'PNG', optimize=True)
    return out.getvalue()

types = [('icp4', 16), ('icp5', 32), ('ic11', 32), ('icp6', 64), ('ic12', 64),
         ('ic07', 128), ('ic08', 256), ('ic13', 256), ('ic09', 512), ('ic14', 512), ('ic10', 1024)]
cache = {}
body = b''
for kind, size in types:
    data = cache.setdefault(size, png(size))
    body += kind.encode() + struct.pack('>I', len(data) + 8) + data
open(sys.argv[2], 'wb').write(b'icns' + struct.pack('>I', len(body) + 8) + body)
PYTHON

echo "wrote $OUTPUT ($(wc -c < "$OUTPUT") bytes)"
