#!/bin/bash
# Build a self-contained Rustorrent macOS .app bundle and compressed share artifact.
# Default output is a small .app.zip built for the current CPU architecture.
#
# Usage:
#   ./macos/package_app.sh
#   ./macos/package_app.sh --universal
#   ./macos/package_app.sh --dmg
#   ./macos/package_app.sh --output /path/to/outdir

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APP_NAME="Rustorrent"

VERSION="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "$PROJECT_DIR/Cargo.toml" | head -n 1
)"
if [[ -z "$VERSION" ]]; then
  VERSION="0.0.0"
fi

UNIVERSAL=false
CREATE_DMG=false
OUTPUT_DIR="$PROJECT_DIR/target/macos-app/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --universal)
      UNIVERSAL=true
      shift
      ;;
    --dmg)
      CREATE_DMG=true
      shift
      ;;
    --output)
      OUTPUT_DIR="${2:-}"
      if [[ -z "$OUTPUT_DIR" ]]; then
        echo "missing value for --output" >&2
        exit 1
      fi
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

BUILD_DIR="$PROJECT_DIR/target/macos-app/build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

echo "==> Building release binary"
cd "$PROJECT_DIR"

if $UNIVERSAL; then
  echo "==> Building universal binary (arm64 + x86_64)"
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
  cargo build --release --target aarch64-apple-darwin
  cargo build --release --target x86_64-apple-darwin

  UNIVERSAL_BIN="$BUILD_DIR/rustorrent-universal"
  lipo -create \
    "$PROJECT_DIR/target/aarch64-apple-darwin/release/rustorrent" \
    "$PROJECT_DIR/target/x86_64-apple-darwin/release/rustorrent" \
    -output "$UNIVERSAL_BIN"
  BINARY_PATH="$UNIVERSAL_BIN"
  ARCH_TAG="universal"
else
  cargo build --release
  BINARY_PATH="$PROJECT_DIR/target/release/rustorrent"
  ARCH_TAG="$(uname -m)"
fi

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$BINARY_PATH" "$APP_BUNDLE/Contents/MacOS/rustorrent-bin"
cp "$SCRIPT_DIR/rustorrent-launcher" "$APP_BUNDLE/Contents/MacOS/rustorrent"
chmod +x "$APP_BUNDLE/Contents/MacOS/rustorrent"
cp "$SCRIPT_DIR/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
echo -n "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

if [[ -f "$SCRIPT_DIR/AppIcon.icns" ]]; then
  cp "$SCRIPT_DIR/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
fi

# Avoid leaking host metadata into shared archives.
xattr -cr "$APP_BUNDLE" 2>/dev/null || true

ARTIFACT_BASE="${APP_NAME}-${VERSION}-${ARCH_TAG}"
ZIP_PATH="$OUTPUT_DIR/${ARTIFACT_BASE}.app.zip"
rm -f "$ZIP_PATH"

echo "==> Creating ZIP artifact"
ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ZIP_PATH"

echo ""
echo "App bundle: $APP_BUNDLE"
echo "ZIP artifact: $ZIP_PATH"
echo "Binary size: $(du -h "$APP_BUNDLE/Contents/MacOS/rustorrent-bin" | cut -f1)"
echo "ZIP size: $(du -h "$ZIP_PATH" | cut -f1)"

if $CREATE_DMG; then
  DMG_TEMP="$BUILD_DIR/dmg-contents"
  DMG_PATH="$OUTPUT_DIR/${ARTIFACT_BASE}.dmg"
  rm -rf "$DMG_TEMP"
  mkdir -p "$DMG_TEMP"
  cp -R "$APP_BUNDLE" "$DMG_TEMP/"
  ln -s /Applications "$DMG_TEMP/Applications"
  rm -f "$DMG_PATH"

  echo "==> Creating DMG artifact"
  hdiutil create -volname "$APP_NAME" \
    -srcfolder "$DMG_TEMP" \
    -ov -format UDZO \
    "$DMG_PATH" >/dev/null
  rm -rf "$DMG_TEMP"
  echo "DMG artifact: $DMG_PATH"
  echo "DMG size: $(du -h "$DMG_PATH" | cut -f1)"
fi

echo ""
echo "Done."
