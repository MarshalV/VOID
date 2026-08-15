use std::sync::Mutex;

use p2p_messenger::bridge::{
    BridgeEvent, SnapshotDto, VaultStatusDto, VoidRuntime,
};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, RunEvent, State, WindowEvent,
};

struct AppState {
    runtime: VoidRuntime,
    /// Keeps the tokio runtime alive for libp2p / VoidRuntime tasks.
    _tokio: tokio::runtime::Runtime,
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
    if let Some(st) = app.try_state::<Mutex<AppState>>() {
        if let Ok(g) = st.lock() {
            g.runtime.set_beacon_active(false);
        }
    }
}

fn hide_to_beacon(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    if let Some(st) = app.try_state::<Mutex<AppState>>() {
        if let Ok(g) = st.lock() {
            g.runtime.set_beacon_active(true);
        }
    }
}

fn quit_app(app: &AppHandle) {
    if let Some(st) = app.try_state::<Mutex<AppState>>() {
        if let Ok(g) = st.lock() {
            g.runtime.prepare_quit();
        }
    }
    app.exit(0);
}

#[tauri::command]
fn vault_status(state: State<'_, Mutex<AppState>>) -> Result<VaultStatusDto, String> {
    state.lock().map_err(|e| e.to_string())?.runtime.vault_status()
}

#[tauri::command]
fn vault_unlock(
    state: State<'_, Mutex<AppState>>,
    password: String,
    password_confirm: Option<String>,
    remember: bool,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .unlock(password, password_confirm, remember)
}

#[tauri::command]
fn try_auto_unlock(state: State<'_, Mutex<AppState>>) -> Result<Option<SnapshotDto>, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .try_auto_unlock()
}

#[tauri::command]
fn get_snapshot(state: State<'_, Mutex<AppState>>) -> SnapshotDto {
    state
        .lock()
        .map(|g| g.runtime.get_snapshot())
        .unwrap_or_else(|p| p.into_inner().runtime.get_snapshot())
}

#[tauri::command]
fn select_chat(state: State<'_, Mutex<AppState>>, chat_id: String) -> SnapshotDto {
    state
        .lock()
        .map(|g| g.runtime.select_chat(chat_id.clone()))
        .unwrap_or_else(|p| p.into_inner().runtime.select_chat(chat_id))
}

#[tauri::command]
fn send_message(state: State<'_, Mutex<AppState>>, text: String) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .send_message(text)
}

#[tauri::command]
fn add_contact(
    state: State<'_, Mutex<AppState>>,
    peer_or_addr: String,
    name: String,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .add_contact(peer_or_addr, name)
}

#[tauri::command]
fn remove_contact(
    state: State<'_, Mutex<AppState>>,
    peer_id: String,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .remove_contact(peer_id)
}

#[tauri::command]
fn rename_contact(
    state: State<'_, Mutex<AppState>>,
    peer_id: String,
    name: String,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .rename_contact(peer_id, name)
}

#[tauri::command]
fn clear_chat(
    state: State<'_, Mutex<AppState>>,
    peer_id: String,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .clear_chat(peer_id)
}

#[tauri::command]
fn join_via_node(
    state: State<'_, Mutex<AppState>>,
    input: String,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .join_via_node(input)
}

#[tauri::command]
fn reload_bootstraps(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .reload_bootstraps()
}

#[tauri::command]
fn snapshot_dht(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .snapshot_dht()
}

#[tauri::command]
fn set_nickname(state: State<'_, Mutex<AppState>>, nickname: String) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .set_nickname(nickname)
}

#[tauri::command]
fn send_file(state: State<'_, Mutex<AppState>>, path: String) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .send_file(path)
}

#[tauri::command]
fn save_file_to_downloads(
    state: State<'_, Mutex<AppState>>,
    transfer_id: String,
) -> Result<String, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .save_file_to_downloads(transfer_id)
}

#[tauri::command]
fn delete_message(
    state: State<'_, Mutex<AppState>>,
    message_id: String,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .delete_message(message_id)
}

#[tauri::command]
fn accept_file(
    state: State<'_, Mutex<AppState>>,
    transfer_id: String,
    save_dir: Option<String>,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .accept_file(transfer_id, save_dir)
}

#[tauri::command]
fn reject_file(state: State<'_, Mutex<AppState>>, transfer_id: String) -> Result<(), String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .reject_file(transfer_id)
}

#[tauri::command]
fn downloads_path() -> String {
    p2p_messenger::downloads_dir().display().to_string()
}

#[tauri::command]
fn open_downloads() -> Result<(), String> {
    let dir = p2p_messenger::downloads_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    open_in_file_manager(&dir)
}

#[tauri::command]
fn reveal_path(path: String) -> Result<(), String> {
    let p = std::path::PathBuf::from(path.trim());
    if p2p_messenger::is_file_cache_path(&p) {
        return Err("внутренний кэш не открывается".into());
    }
    if p.is_file() {
        if let Some(parent) = p.parent() {
            if p2p_messenger::is_file_cache_path(parent) {
                return Err("внутренний кэш не открывается".into());
            }
            return open_in_file_manager(parent);
        }
    }
    if p.is_dir() {
        return open_in_file_manager(&p);
    }
    Err(format!("Путь не найден: {}", p.display()))
}

fn open_in_file_manager(dir: &std::path::Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(dir)
            .spawn()
            .map_err(|e| format!("explorer: {e}"))?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(dir)
            .spawn()
            .map_err(|e| format!("open: {e}"))?;
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(dir)
            .spawn()
            .map_err(|e| format!("xdg-open: {e}"))?;
        Ok(())
    }
}

#[tauri::command]
fn start_voice(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .start_voice()
}

#[tauri::command]
fn stop_voice_preview(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .stop_voice_preview()
}

#[tauri::command]
fn send_voice_preview(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .send_voice_preview()
}

#[tauri::command]
fn cancel_voice_preview(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .cancel_voice_preview()
}

#[tauri::command]
fn stop_voice_send(state: State<'_, Mutex<AppState>>) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .stop_voice_send()
}

#[tauri::command]
fn create_group(
    state: State<'_, Mutex<AppState>>,
    name: String,
    member_peer_ids: Vec<String>,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .create_group(name, member_peer_ids)
}

#[tauri::command]
fn join_group(state: State<'_, Mutex<AppState>>, link: String) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .join_group(link)
}

#[tauri::command]
fn invite_to_group(
    state: State<'_, Mutex<AppState>>,
    group_id: String,
    member_peer_ids: Vec<String>,
) -> Result<SnapshotDto, String> {
    state
        .lock()
        .map_err(|e| e.to_string())?
        .runtime
        .invite_to_group(group_id, member_peer_ids)
}

#[tauri::command]
fn quit_application(app: AppHandle) {
    quit_app(&app);
}

#[tauri::command]
fn show_window(app: AppHandle) {
    show_main(&app);
}

fn load_tray_icon(app: &AppHandle) -> Option<Image<'static>> {
    let candidates = [
        "icons/32x32.png",
        "icons/128x128.png",
        "icons/icon.png",
    ];
    for rel in candidates {
        if let Ok(p) = app.path().resolve(rel, tauri::path::BaseDirectory::Resource) {
            if let Ok(bytes) = std::fs::read(&p) {
                if let Ok(img) = Image::from_bytes(&bytes) {
                    return Some(img);
                }
            }
        }
    }
    // Fallback: bundled tauri icons next to exe / resource
    let fallbacks = [
        std::path::PathBuf::from("icons/32x32.png"),
        std::path::PathBuf::from("../static/Image_programm.png"),
        std::path::PathBuf::from("static/Image_programm.png"),
    ];
    for p in fallbacks {
        if let Ok(bytes) = std::fs::read(&p) {
            if let Ok(img) = Image::from_bytes(&bytes) {
                return Some(img);
            }
        }
    }
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if let Some(code) = p2p_messenger::run_cli_if_requested() {
        std::process::exit(code);
    }

    let _ = p2p_messenger::init_paths();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let tokio_rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("void-tokio")
                .build()
                .expect("tokio runtime");
            let runtime = {
                let _enter = tokio_rt.enter();
                VoidRuntime::new()
            };
            let bridge_events = runtime.bridge_events.clone();
            app.manage(Mutex::new(AppState {
                runtime,
                _tokio: tokio_rt,
            }));

            let handle = app.handle().clone();
            std::thread::Builder::new()
                .name("void-bridge-emit".into())
                .spawn(move || loop {
                    let ev = {
                        let rx = bridge_events.lock().unwrap_or_else(|p| p.into_inner());
                        rx.recv()
                    };
                    match ev {
                        Ok(BridgeEvent::Snapshot(s)) => {
                            let _ = handle.emit("void://snapshot", s);
                        }
                        Ok(BridgeEvent::Status { text }) => {
                            let _ = handle.emit("void://status", text);
                        }
                        Ok(BridgeEvent::Message { chat_id }) => {
                            let _ = handle.emit("void://message", chat_id);
                        }
                        Ok(BridgeEvent::Peer { peer_id, online }) => {
                            let _ = handle.emit(
                                "void://peer",
                                serde_json::json!({ "peer_id": peer_id, "online": online }),
                            );
                        }
                        Ok(BridgeEvent::Bootstraps { addrs }) => {
                            let _ = handle.emit("void://bootstraps", addrs);
                        }
                        Ok(BridgeEvent::FileOffer(f)) => {
                            let _ = handle.emit("void://file", f);
                        }
                        Ok(BridgeEvent::FileComplete {
                            transfer_id,
                            filename,
                            saved_to,
                        }) => {
                            let _ = handle.emit(
                                "void://file-complete",
                                serde_json::json!({
                                    "transfer_id": transfer_id,
                                    "filename": filename,
                                    "saved_to": saved_to,
                                }),
                            );
                        }
                        Ok(BridgeEvent::FileProgress {
                            transfer_id,
                            sent_chunks,
                            total_chunks,
                            filename,
                        }) => {
                            let _ = handle.emit(
                                "void://file-progress",
                                serde_json::json!({
                                    "transfer_id": transfer_id,
                                    "sent_chunks": sent_chunks,
                                    "total_chunks": total_chunks,
                                    "filename": filename,
                                }),
                            );
                        }
                        Err(_) => break,
                    }
                })?;

            let show_i = MenuItem::with_id(app, "show", "Открыть VOID", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("VOID P2P Messenger")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main(app),
                    "quit" => quit_app(app),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                });

            if let Some(icon) = load_tray_icon(app.handle()) {
                tray = tray.icon(icon);
            }
            let _ = tray.build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Beacon: hide instead of quit (Telegram-style).
                api.prevent_close();
                hide_to_beacon(window.app_handle());
            }
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            vault_unlock,
            try_auto_unlock,
            get_snapshot,
            select_chat,
            send_message,
            add_contact,
            remove_contact,
            rename_contact,
            clear_chat,
            join_via_node,
            reload_bootstraps,
            snapshot_dht,
            set_nickname,
            send_file,
            save_file_to_downloads,
            delete_message,
            accept_file,
            reject_file,
            downloads_path,
            open_downloads,
            reveal_path,
            start_voice,
            stop_voice_preview,
            send_voice_preview,
            cancel_voice_preview,
            stop_voice_send,
            create_group,
            join_group,
            invite_to_group,
            quit_application,
            show_window,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { api, .. } = event {
                let beacon = app_handle
                    .try_state::<Mutex<AppState>>()
                    .map(|st| {
                        st.lock()
                            .map(|g| g.runtime.get_snapshot().beacon_active)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if beacon {
                    api.prevent_exit();
                }
            }
        });
}
