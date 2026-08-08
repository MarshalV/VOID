#!/usr/bin/env bash
# Build dist/VOID.app - Finder launch WITHOUT Terminal.
# On Mac: chmod +x scripts/package-macos.sh && ./scripts/package-macos.sh && open dist/VOID.app
# Do NOT open target/release/p2p-messenger (always opens Terminal).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
APP_NAME="VOID"
BIN_NAME="p2p-messenger"
BUNDLE="${ROOT}/dist/${APP_NAME}.app"
CONTENTS="${BUNDLE}/Contents"
MACOS_DIR="${CONTENTS}/MacOS"
RES_DIR="${CONTENTS}/Resources"
EXE="${MACOS_DIR}/${APP_NAME}"

echo "==> cargo build --release"
cargo build --release
rm -rf "${BUNDLE}"
mkdir -p "${MACOS_DIR}" "${RES_DIR}"
cp "${ROOT}/target/release/${BIN_NAME}" "${EXE}"
chmod 755 "${EXE}"
if [[ -f "${ROOT}/static/ico.png" ]]; then
  cp "${ROOT}/static/ico.png" "${RES_DIR}/ico.png"
fi
VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
cat > "${CONTENTS}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key><string>app.void.messenger</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key><string>${APP_NAME}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSMicrophoneUsageDescription</key>
  <string>VOID needs the microphone for voice messages.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>VOID uses the local network for peer-to-peer messaging.</string>
  <key>NSBonjourServices</key>
  <array><string>_void._udp</string><string>_void._tcp</string></array>
</dict>
</plist>
PLIST
if command -v xattr >/dev/null 2>&1; then
  xattr -cr "${BUNDLE}" 2>/dev/null || true
fi
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "${BUNDLE}" 2>/dev/null || true
fi
echo ""
echo "OK: ${BUNDLE}"
echo "Launch: open \"${BUNDLE}\""
echo "Wrong: double-click target/release/p2p-messenger (opens Terminal)"
