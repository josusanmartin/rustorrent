#!/bin/bash
# Creates a simple app icon for Rustorrent using ImageMagick or a fallback

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ICONSET_DIR="$SCRIPT_DIR/AppIcon.iconset"
ICON_OUTPUT="$SCRIPT_DIR/AppIcon.icns"

mkdir -p "$ICONSET_DIR"

# Function to create icon using Python (available on macOS)
create_icon_python() {
    python3 << 'PYTHON_SCRIPT'
import os
import struct
import zlib

def create_png(width, height, filename):
    """Create a simple PNG icon with 'R' letter and gradient background"""

    def write_chunk(f, chunk_type, data):
        chunk = chunk_type + data
        f.write(struct.pack('>I', len(data)))
        f.write(chunk)
        f.write(struct.pack('>I', zlib.crc32(chunk) & 0xffffffff))

    # Create pixel data with gradient and 'R' letter
    pixels = []
    for y in range(height):
        row = [0]  # Filter byte
        for x in range(width):
            # Gradient background (orange to red)
            r = min(255, 200 + int(55 * x / width))
            g = max(0, 100 - int(100 * y / height))
            b = 50

            # Draw 'R' letter in white
            cx, cy = x - width//4, y - height//4
            w, h = width//2, height//2
            in_letter = False

            # Vertical bar of R
            if 0.15*w <= cx <= 0.35*w and 0.1*h <= cy <= 0.9*h:
                in_letter = True
            # Top curve of R
            elif 0.35*w <= cx <= 0.7*w and 0.1*h <= cy <= 0.25*h:
                in_letter = True
            elif 0.35*w <= cx <= 0.7*w and 0.4*h <= cy <= 0.55*h:
                in_letter = True
            elif 0.6*w <= cx <= 0.75*w and 0.2*h <= cy <= 0.45*h:
                in_letter = True
            # Diagonal leg of R
            elif 0.35*w <= cx <= 0.75*w and 0.5*h <= cy <= 0.9*h:
                diag = (cy - 0.5*h) / (0.4*h)
                if 0.35*w + diag*0.25*w <= cx <= 0.55*w + diag*0.25*w:
                    in_letter = True

            if in_letter:
                r, g, b = 255, 255, 255

            row.extend([r, g, b, 255])
        pixels.append(bytes(row))

    raw_data = b''.join(pixels)
    compressed = zlib.compress(raw_data, 9)

    with open(filename, 'wb') as f:
        # PNG signature
        f.write(b'\x89PNG\r\n\x1a\n')
        # IHDR
        ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
        write_chunk(f, b'IHDR', ihdr_data)
        # IDAT
        write_chunk(f, b'IDAT', compressed)
        # IEND
        write_chunk(f, b'IEND', b'')

sizes = [16, 32, 64, 128, 256, 512, 1024]
iconset_dir = os.environ.get('ICONSET_DIR', 'AppIcon.iconset')

for size in sizes:
    create_png(size, size, f'{iconset_dir}/icon_{size}x{size}.png')
    if size <= 512:
        create_png(size*2, size*2, f'{iconset_dir}/icon_{size}x{size}@2x.png')

print("Icon PNGs created successfully")
PYTHON_SCRIPT
}

echo "Creating icon images..."
ICONSET_DIR="$ICONSET_DIR" create_icon_python

echo "Converting to icns..."
iconutil -c icns "$ICONSET_DIR" -o "$ICON_OUTPUT"

echo "Cleaning up..."
rm -rf "$ICONSET_DIR"

echo "Icon created: $ICON_OUTPUT"
