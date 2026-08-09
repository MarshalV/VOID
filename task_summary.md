# Task Summary: VOID P2P Messenger (Tauri + beacon + vault bootstrap)

## Done

1. **Beacon (Telegram-style background)** — closing the window hides it; libp2p keeps running. Tray: «Открыть VOID» / «Выйти».
2. **Tauri UI** — vault unlock, chats, network panel, settings, files, voice, groups; icons from `frontend/static/` (copied from `static/`).
3. **Bridge** — `p2p_messenger::bridge::VoidRuntime` links frontend to vault/network without egui.
4. **Bootstrap in vault.bin** — learned nodes merged and saved; dial failure rotates to the next bootstrap.
5. **Build scripts** — `build.bat` / `build.sh` / `build_mac.sh` run `cargo tauri build` and copy app + installers into root `target/`.

## Run

- Dev UI: `cd src-tauri && cargo tauri dev`
- egui fallback: `cargo run --features egui-ui`
- Release packages: `build.bat` (Windows), `./build.sh` (Linux), `./build_mac.sh` (macOS)
