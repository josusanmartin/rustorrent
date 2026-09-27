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
MACOS_MIN_VERSION="11.0"
export MACOSX_DEPLOYMENT_TARGET="$MACOS_MIN_VERSION"

VERSION="$(
  sed -n 's/^version = "\(.*\)"/\1/p' "$PROJECT_DIR/Cargo.toml" | head -n 1
)"
if [[ -z "$VERSION" ]]; then
  VERSION="0.0.0"
fi
BUNDLE_VERSION="${VERSION%%-*}"

UNIVERSAL=false
CREATE_DMG=false
OUTPUT_DIR="$PROJECT_DIR/target/macos-app/dist"
SIGN_IDENTITY="${APP_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${APP_NOTARY_PROFILE:-}"

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

if [[ -n "$NOTARY_PROFILE" && -z "$SIGN_IDENTITY" ]]; then
  echo "APP_NOTARY_PROFILE requires APP_SIGN_IDENTITY" >&2
  exit 1
fi

BUILD_DIR="$PROJECT_DIR/target/macos-app/build"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"

mkdir -p "$BUILD_DIR"
mkdir -p "$OUTPUT_DIR"

echo "==> Building release binary"
cd "$PROJECT_DIR"

if $UNIVERSAL; then
  echo "==> Building universal binary (arm64 + x86_64)"
  rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null 2>&1 || true
  cargo build --locked --release --target aarch64-apple-darwin
  cargo build --locked --release --target x86_64-apple-darwin

  UNIVERSAL_BIN="$BUILD_DIR/rustorrent-universal"
  lipo -create \
    "$PROJECT_DIR/target/aarch64-apple-darwin/release/rustorrent" \
    "$PROJECT_DIR/target/x86_64-apple-darwin/release/rustorrent" \
    -output "$UNIVERSAL_BIN"
  BINARY_PATH="$UNIVERSAL_BIN"
  ARCH_TAG="universal"
else
  cargo build --locked --release
  BINARY_PATH="$PROJECT_DIR/target/release/rustorrent"
  ARCH_TAG="$(uname -m)"
fi

rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

cp "$BINARY_PATH" "$APP_BUNDLE/Contents/MacOS/rustorrent-bin"

LAUNCHER_SRC="$SCRIPT_DIR/Launcher.swift"
if [[ -f "$LAUNCHER_SRC" ]] && command -v xcrun >/dev/null 2>&1; then
  echo "==> Building native macOS launcher"
  if $UNIVERSAL; then
    xcrun --sdk macosx swiftc -parse-as-library -Osize -target "arm64-apple-macos$MACOS_MIN_VERSION" \
      "$LAUNCHER_SRC" -o "$BUILD_DIR/rustorrent-launcher-arm64"
    xcrun --sdk macosx swiftc -parse-as-library -Osize -target "x86_64-apple-macos$MACOS_MIN_VERSION" \
      "$LAUNCHER_SRC" -o "$BUILD_DIR/rustorrent-launcher-x86_64"
    lipo -create \
      "$BUILD_DIR/rustorrent-launcher-arm64" \
      "$BUILD_DIR/rustorrent-launcher-x86_64" \
      -output "$APP_BUNDLE/Contents/MacOS/rustorrent"
  else
    SWIFT_ARCH="$(uname -m)"
    xcrun --sdk macosx swiftc -parse-as-library -Osize \
      -target "$SWIFT_ARCH-apple-macos$MACOS_MIN_VERSION" \
      "$LAUNCHER_SRC" -o "$APP_BUNDLE/Contents/MacOS/rustorrent"
  fi
else
  echo "==> Native launcher unavailable, using shell launcher fallback"
  cp "$SCRIPT_DIR/rustorrent-launcher" "$APP_BUNDLE/Contents/MacOS/rustorrent"
fi
chmod +x "$APP_BUNDLE/Contents/MacOS/rustorrent"
if file "$APP_BUNDLE/Contents/MacOS/rustorrent" | grep -q 'Mach-O'; then
  /usr/bin/strip -S -x "$APP_BUNDLE/Contents/MacOS/rustorrent"
fi
cp "$SCRIPT_DIR/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $BUNDLE_VERSION" \
  "$APP_BUNDLE/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUNDLE_VERSION" \
    "$APP_BUNDLE/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Add :CFBundleGetInfoString string Rustorrent $VERSION" \
    "$APP_BUNDLE/Contents/Info.plist"
echo -n "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

if [[ ! -f "$SCRIPT_DIR/AppIcon.icns" ]]; then
  echo "missing required application icon: $SCRIPT_DIR/AppIcon.icns" >&2
  exit 1
fi
cp "$SCRIPT_DIR/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"

for notice in LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.html; do
  if [[ ! -f "$PROJECT_DIR/$notice" ]]; then
    echo "missing required distribution notice: $PROJECT_DIR/$notice" >&2
    exit 1
  fi
  cp "$PROJECT_DIR/$notice" "$APP_BUNDLE/Contents/Resources/$notice"
done

# Avoid leaking host metadata into shared archives.
xattr -cr "$APP_BUNDLE" 2>/dev/null || true

if [[ -n "$SIGN_IDENTITY" ]]; then
  echo "==> Code signing app bundle"
  codesign --force --sign "$SIGN_IDENTITY" --timestamp --options runtime \
    "$APP_BUNDLE/Contents/MacOS/rustorrent-bin"
  codesign --force --sign "$SIGN_IDENTITY" --timestamp --options runtime \
    "$APP_BUNDLE/Contents/MacOS/rustorrent"
  codesign --force --sign "$SIGN_IDENTITY" --timestamp --options runtime \
    "$APP_BUNDLE"
  codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
else
  # Apple Silicon executables receive linker-generated ad-hoc signatures, but
  # those do not seal the surrounding app bundle. Sign the helper and then
  # the bundle for local integrity verification. Ad-hoc signatures alone do
  # not guarantee stable Local Network permission across rebuilds, nor replace
  # Developer ID signing or notarization.
  echo "==> Ad-hoc signing app bundle"
  codesign --force --sign - --identifier "com.rustorrent.app.backend" \
    "$APP_BUNDLE/Contents/MacOS/rustorrent-bin"
  codesign --force --sign - --identifier "com.rustorrent.app.launcher" \
    "$APP_BUNDLE/Contents/MacOS/rustorrent"
  codesign --force --sign - "$APP_BUNDLE"
  codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
fi

ARTIFACT_BASE="${APP_NAME}-${VERSION}-${ARCH_TAG}"
ZIP_PATH="$OUTPUT_DIR/${ARTIFACT_BASE}.app.zip"
rm -f "$ZIP_PATH"

echo "==> Creating ZIP artifact"
ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ZIP_PATH"

if [[ -n "$NOTARY_PROFILE" ]]; then
  echo "==> Submitting app for notarization using keychain profile '$NOTARY_PROFILE'"
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "==> Stapling app bundle"
  xcrun stapler staple "$APP_BUNDLE"
  xcrun stapler validate "$APP_BUNDLE"

  # Rebuild the distributable archive so it contains the stapled app rather
  # than the pre-notarization bundle that was submitted to Apple.
  rm -f "$ZIP_PATH"
  ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ZIP_PATH"
fi

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
  # LZMA (ULMO, macOS 10.15+) packs the app noticeably tighter than bzip2,
  # which keeps the Apple silicon DMG under 1 MB.
  hdiutil create -volname "$APP_NAME" \
    -srcfolder "$DMG_TEMP" \
    -fs HFS+ -ov -format ULMO \
    "$DMG_PATH" >/dev/null
  rm -rf "$DMG_TEMP"
  echo "DMG artifact: $DMG_PATH"
  echo "DMG size: $(du -h "$DMG_PATH" | cut -f1)"

  if [[ -n "$SIGN_IDENTITY" ]]; then
    echo "==> Code signing DMG artifact"
    codesign --force --sign "$SIGN_IDENTITY" --timestamp "$DMG_PATH"
  fi
fi

if [[ -n "$NOTARY_PROFILE" && "$CREATE_DMG" == true ]]; then
  echo "==> Submitting DMG for notarization using keychain profile '$NOTARY_PROFILE'"
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "==> Stapling DMG artifact"
  xcrun stapler staple "$DMG_PATH"
  xcrun stapler validate "$DMG_PATH"
fi

echo ""
echo "Done."
