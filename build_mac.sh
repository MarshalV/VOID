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

# .app is the real artifact. DMG runs bundle_dmg.sh → osascript/Finder;
# without Automation permission that step fails even though .app is ready.
# CI=true skips Finder window layout and still produces a working DMG.
echo "Bundling .app ..."
cargo tauri build --bundles app

echo "Bundling .dmg (skip Finder layout) ..."
set +e
CI=true cargo tauri build --bundles dmg
dmg_status=$?
set -e
if [ "$dmg_status" -ne 0 ]; then
  echo
  echo "WARNING: DMG не собран (bundle_dmg.sh / Finder AppleScript)."
  echo "  .app уже готов — его достаточно, чтобы запустить VOID."
  echo "  Если нужен .dmg: System Settings → Privacy & Security → Automation"
  echo "  → разрешите Terminal (или Cursor) управлять Finder, затем повторите."
  echo "  Либо: CI=true ./build_mac.sh"
  echo
fi

echo "Build succeeded."
echo "Copying application and installers to target/ ..."
mkdir -p target

# Prefer the .app bundle (GUI, no Terminal console).
if ls src-tauri/target/release/bundle/macos/*.app >/dev/null 2>&1; then
  for appdir in src-tauri/target/release/bundle/macos/*.app; do
    base="$(basename "$appdir")"
    rm -rf "target/$base"
    cp -R "$appdir" "target/$base"
  done
fi

cp -f src-tauri/target/release/bundle/dmg/*.dmg target/ 2>/dev/null || true
cp -f src-tauri/target/release/bundle/zip/*.zip target/ 2>/dev/null || true
cp -f src-tauri/target/release/bundle/pkg/*.pkg target/ 2>/dev/null || true

# Bare binary is for debugging only — launching it from Terminal keeps a console.
if [ -f src-tauri/target/release/app ]; then
  cp -f src-tauri/target/release/app target/VOID-P2P-Messenger-cli
  chmod +x target/VOID-P2P-Messenger-cli
fi

echo
echo "Artifacts in target/:"
ls -la target/ || true
echo
APP="$(ls -d target/*.app 2>/dev/null | head -n1 || true)"
if [ -n "${APP}" ]; then
  echo "GUI (без консоли): open \"${APP}\""
else
  echo "WARNING: .app bundle not found — check tauri bundle macos target"
fi
echo "Done."
