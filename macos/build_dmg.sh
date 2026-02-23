#!/bin/bash
# Build script to create Rustorrent.app and package it into a DMG
# Usage: ./macos/build_dmg.sh [--universal]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/target/macos-app"
APP_NAME="Rustorrent"
APP_BUNDLE="$BUILD_DIR/$APP_NAME.app"
DMG_NAME="Rustorrent-0.1.0"
DMG_PATH="$PROJECT_DIR/$DMG_NAME.dmg"

UNIVERSAL=false
if [[ "$1" == "--universal" ]]; then
    UNIVERSAL=true
fi

echo "=== Building Rustorrent macOS Application ==="
echo ""

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build the release binary
echo "Building release binary..."
cd "$PROJECT_DIR"

if $UNIVERSAL; then
    echo "Building universal binary (x86_64 + arm64)..."

    # Ensure both targets are installed
    rustup target add x86_64-apple-darwin aarch64-apple-darwin 2>/dev/null || true

    # Build for both architectures
    cargo build --release --target x86_64-apple-darwin
    cargo build --release --target aarch64-apple-darwin

    # Create universal binary
    mkdir -p "$BUILD_DIR/bin"
    lipo -create \
        "target/x86_64-apple-darwin/release/rustorrent" \
        "target/aarch64-apple-darwin/release/rustorrent" \
        -output "$BUILD_DIR/bin/rustorrent"

    BINARY_PATH="$BUILD_DIR/bin/rustorrent"
else
    cargo build --release
    BINARY_PATH="$PROJECT_DIR/target/release/rustorrent"
fi

echo "Binary built successfully!"
echo "Binary size: $(du -h "$BINARY_PATH" | cut -f1)"

# Create app bundle structure
echo ""
echo "Creating app bundle..."
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy binary (as rustorrent-bin, the launcher script will call it)
cp "$BINARY_PATH" "$APP_BUNDLE/Contents/MacOS/rustorrent-bin"

# Build native launcher as the main executable (fallback to shell script).
LAUNCHER_SRC="$SCRIPT_DIR/Launcher.swift"
if [[ -f "$LAUNCHER_SRC" ]] && command -v xcrun >/dev/null 2>&1; then
    echo "Building native macOS launcher..."
    if $UNIVERSAL; then
        xcrun --sdk macosx swiftc -parse-as-library -O -target arm64-apple-macos11.0 \
            "$LAUNCHER_SRC" -o "$BUILD_DIR/rustorrent-launcher-arm64"
        xcrun --sdk macosx swiftc -parse-as-library -O -target x86_64-apple-macos10.13 \
            "$LAUNCHER_SRC" -o "$BUILD_DIR/rustorrent-launcher-x86_64"
        lipo -create \
            "$BUILD_DIR/rustorrent-launcher-arm64" \
            "$BUILD_DIR/rustorrent-launcher-x86_64" \
            -output "$APP_BUNDLE/Contents/MacOS/rustorrent"
    else
        xcrun --sdk macosx swiftc -parse-as-library -O \
            "$LAUNCHER_SRC" -o "$APP_BUNDLE/Contents/MacOS/rustorrent"
    fi
else
    echo "Native launcher unavailable, using shell launcher fallback..."
    cp "$SCRIPT_DIR/rustorrent-launcher" "$APP_BUNDLE/Contents/MacOS/rustorrent"
fi
chmod +x "$APP_BUNDLE/Contents/MacOS/rustorrent"

# Copy Info.plist
cp "$SCRIPT_DIR/Info.plist" "$APP_BUNDLE/Contents/"

# Create or copy icon
if [[ -f "$SCRIPT_DIR/AppIcon.icns" ]]; then
    cp "$SCRIPT_DIR/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/"
else
    echo "Creating app icon..."
    bash "$SCRIPT_DIR/create_icon.sh"
    cp "$SCRIPT_DIR/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/"
fi

# Create PkgInfo
echo -n "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

echo "App bundle created: $APP_BUNDLE"

# Create DMG
echo ""
echo "Creating DMG..."

# Remove old DMG if exists
rm -f "$DMG_PATH"

# Create a temporary directory for DMG contents
DMG_TEMP="$BUILD_DIR/dmg-contents"
mkdir -p "$DMG_TEMP"

# Copy app to temp directory
cp -R "$APP_BUNDLE" "$DMG_TEMP/"

# Create Applications symlink
ln -s /Applications "$DMG_TEMP/Applications"

# Create DMG
hdiutil create -volname "$APP_NAME" \
    -srcfolder "$DMG_TEMP" \
    -ov -format UDZO \
    "$DMG_PATH"

# Clean up
rm -rf "$DMG_TEMP"

echo ""
echo "=== Build Complete ==="
echo "App bundle: $APP_BUNDLE"
echo "DMG file: $DMG_PATH"
echo "DMG size: $(du -h "$DMG_PATH" | cut -f1)"
echo ""
echo "To install: Open the DMG and drag Rustorrent to Applications"
