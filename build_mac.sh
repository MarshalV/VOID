#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

ensure_tauri_cli() {
  if cargo tauri --version >/dev/null 2>&1; then
    echo "tauri-cli: $(cargo tauri --version)"
    return 0
  fi
  echo "cargo-tauri not found — installing tauri-cli (v2)..."
  cargo install tauri-cli --locked --version "^2.0.0"
}

echo "Building VOID P2P Messenger for macOS..."
ensure_tauri_cli
cargo tauri build

echo "Build succeeded."
echo "Copying application and installers to target/ ..."
mkdir -p target

# App binary
if [ -f src-tauri/target/release/app ]; then
  cp -f src-tauri/target/release/app target/VOID-P2P-Messenger
  chmod +x target/VOID-P2P-Messenger
fi

# macOS bundles
cp -f src-tauri/target/release/bundle/dmg/*.dmg target/ 2>/dev/null || true
if ls src-tauri/target/release/bundle/macos/*.app >/dev/null 2>&1; then
  for appdir in src-tauri/target/release/bundle/macos/*.app; do
    base="$(basename "$appdir")"
    rm -rf "target/$base"
    cp -R "$appdir" "target/$base"
  done
fi
cp -f src-tauri/target/release/bundle/zip/*.zip target/ 2>/dev/null || true
cp -f src-tauri/target/release/bundle/pkg/*.pkg target/ 2>/dev/null || true

echo
echo "Artifacts in target/:"
ls -la target/ || true
echo "Done."
