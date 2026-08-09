#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "Building VOID P2P Messenger for Linux..."
cargo tauri build

echo "Build succeeded."
echo "Copying application and installers to target/ ..."
mkdir -p target

# Binary
if [ -f src-tauri/target/release/app ]; then
  cp -f src-tauri/target/release/app target/VOID-P2P-Messenger
  chmod +x target/VOID-P2P-Messenger
fi

# Packages
cp -f src-tauri/target/release/bundle/deb/*.deb target/ 2>/dev/null || true
cp -f src-tauri/target/release/bundle/appimage/*.AppImage target/ 2>/dev/null || true
cp -f src-tauri/target/release/bundle/rpm/*.rpm target/ 2>/dev/null || true
cp -f src-tauri/target/release/bundle/tar.xz/*.tar.xz target/ 2>/dev/null || true

echo
echo "Artifacts in target/:"
ls -la target/ || true
echo "Done."
