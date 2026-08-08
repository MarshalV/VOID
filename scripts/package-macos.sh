#!/usr/bin/env bash
# Build VOID.app so macOS Finder does not open Terminal on launch.
# Usage (on a Mac):
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

echo "==> cargo build --release"
cargo build --release

rm -rf "${BUNDLE}"
mkdir -p "${MACOS_DIR}" "${RES_DIR}"

cp "${ROOT}/target/release/${BIN_NAME}" "${MACOS_DIR}/${APP_NAME}"
chmod +x "${MACOS_DIR}/${APP_NAME}"

if [[ -f "${ROOT}/static/ico.png" ]]; then
  cp "${ROOT}/static/ico.png" "${RES_DIR}/ico.png"
  if command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
    TMP_ICON="$(mktemp -d)"
    ICONSET="${TMP_ICON}/AppIcon.iconset"
    mkdir -p "${ICONSET}"
    for sz in 16 32 128 256 512; do
      sips -z "${sz}" "${sz}" "${ROOT}/static/ico.png" --out "${ICONSET}/icon_${sz}x${sz}.png" >/dev/null
      sips -z "$((sz * 2))" "$((sz * 2))" "${ROOT}/static/ico.png" --out "${ICONSET}/icon_${sz}x${sz}@2x.png" >/dev/null
    done
    iconutil -c icns "${ICONSET}" -o "${RES_DIR}/AppIcon.icns" || true
    rm -rf "${TMP_ICON}"
  fi
fi

ICON_PLIST=""
if [[ -f "${RES_DIR}/AppIcon.icns" ]]; then
  ICON_PLIST="  <key>CFBundleIconFile</key>
  <string>AppIcon</string>"
fi

VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"

cat > "${CONTENTS}/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>app.void.messenger</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleDisplayName</key>
  <string>${APP_NAME}</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSMicrophoneUsageDescription</key>
  <string>VOID needs the microphone for voice messages.</string>
${ICON_PLIST}
</dict>
</plist>
PLIST

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "${BUNDLE}" 2>/dev/null || true
fi

echo ""
echo "OK: ${BUNDLE}"
echo "Launch without Terminal:"
echo "  open \"${BUNDLE}\""
echo "Or drag VOID.app into Applications / Dock."
