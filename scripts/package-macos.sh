#!/usr/bin/env bash
# Build VOID.app so macOS Finder does not open Terminal on launch.
# Usage (on a Mac):
#   chmod +x scripts/package-macos.sh
#   ./scripts/package-macos.sh
#   open dist/VOID.app
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

cat > "${CONTENTS}/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>VOID</string>
  <key>CFBundleIdentifier</key>
  <string>app.void.messenger</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>VOID</string>
  <key>CFBundleDisplayName</key>
  <string>VOID</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>VERSION_PLACEHOLDER</string>
  <key>CFBundleVersion</key>
  <string>VERSION_PLACEHOLDER</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSMicrophoneUsageDescription</key>
  <string>VOID needs the microphone for voice messages.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>VOID uses the local network for peer-to-peer messaging.</string>
  <key>NSBonjourServices</key>
  <array>
    <string>_void._udp</string>
    <string>_void._tcp</string>
  </array>
</dict>
</plist>
PLIST

# Inject version into plist
sed -i.bak "s/VERSION_PLACEHOLDER/${VERSION}/g" "${CONTENTS}/Info.plist"
rm -f "${CONTENTS}/Info.plist.bak"

# Clear quarantine + ensure executable (fixes os error 13 / Permission denied)
chmod 755 "${EXE}"
if command -v xattr >/dev/null 2>&1; then
  xattr -cr "${BUNDLE}" 2>/dev/null || true
fi
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "${BUNDLE}" 2>/dev/null || true
fi

echo ""
echo "OK: ${BUNDLE}"
echo "Launch: open \"${BUNDLE}\""
echo "If Permission denied (os error 13):"
echo "  xattr -cr \"${BUNDLE}\" && chmod +x \"${EXE}\""
