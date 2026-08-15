//! VOID P2P Messenger library — networking, vault, and optional egui desktop UI.
//! Tauri uses [`bridge::VoidRuntime`] without the `egui-ui` feature.

pub mod bridge;

pub(crate) mod bootstrap;
pub(crate) mod chat_store;
pub(crate) mod crypto;
pub(crate) mod file_transfer;
pub(crate) mod group;
pub(crate) mod metadata_strip;
pub(crate) mod network;
pub(crate) mod offline_mail;
pub(crate) mod offline_publish;
pub(crate) mod outbox;
pub(crate) mod paths;
pub(crate) mod protocol;
pub(crate) mod relay_mailbox;
pub(crate) mod shared_chat;
pub(crate) mod vault;
pub(crate) mod voice;

#[cfg(feature = "egui-ui")]
pub(crate) mod app;
#[cfg(feature = "egui-ui")]
pub(crate) mod tray_bg;
#[cfg(feature = "egui-ui")]
pub(crate) mod ui;

#[cfg(feature = "egui-ui")]
pub(crate) use app::{App, PendingGroupSend, PendingSend, RESEND_GRACE};
#[cfg(feature = "egui-ui")]
pub(crate) use bootstrap::parse_seed_input;
#[cfg(feature = "egui-ui")]
pub(crate) use network::{NetworkEvent, UICommand};
#[cfg(feature = "egui-ui")]
pub(crate) use protocol::{new_message_id, FileTransferProgress, OutgoingDeliveryStatus};

/// Initialize data directory (vault, journal, outbox).
pub fn init_paths() -> Result<(), String> {
    paths::init_storage_paths()
}

/// Absolute path to incoming files (`Downloads/VOID Messenger`).
pub fn downloads_dir() -> std::path::PathBuf {
    file_transfer::user_file_downloads_dir()
}

/// Handle `--voice-record` / `--voice-probe` CLI before starting any UI.
/// Returns `Some(exit_code)` if the process should exit.
pub fn run_cli_if_requested() -> Option<i32> {
    voice::run_cli_mode()
}

/// Native egui desktop entry (used by the `p2p-messenger` binary).
#[cfg(feature = "egui-ui")]
pub fn run_native() -> Result<(), Box<dyn std::error::Error>> {
    desktop::run()
}

#[cfg(feature = "egui-ui")]
mod desktop {
    use std::collections::{HashMap, HashSet};
    use std::error::Error;

    use eframe::egui;
    use libp2p::PeerId;
    use tokio::sync::mpsc;
    use tracing::info;

    use crate::app::{App, DeferredNetworkSpawn};
    use crate::shared_chat::SharedChatMessages;
    use crate::crypto;
    use crate::network::env_flag_true;
    use crate::paths::init_storage_paths;
    use crate::vault::{
        detect_vault_unlock_kind, load_remembered_password, VaultUnlockKind, VaultUnlockState,
    };
    use crate::voice;

    #[tokio::main]
    pub async fn run() -> Result<(), Box<dyn Error>> {
        if let Some(code) = voice::run_cli_mode() {
            std::process::exit(code);
        }

        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("warn")
                }),
            )
            .try_init();

        if let Err(e) = init_storage_paths() {
            eprintln!("VOID: не удалось инициализировать каталог данных: {e}");
        }

        let exe_path = std::env::current_exe().unwrap_or_default();
        #[allow(unused_variables)]
        let exe = exe_path.display().to_string();

        #[cfg(target_os = "windows")]
        if env_flag_true("VOID_APPLY_FIREWALL_RULE") {
            let is_admin = std::process::Command::new("net")
                .args(["session"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if is_admin {
                info!("Настраиваю файрвол Windows (Admin Mode)...");
                let _ = std::process::Command::new("netsh")
                    .args(["advfirewall", "firewall", "delete", "rule", "name=VOID P2P"])
                    .output();
                let tcp_r = std::process::Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=VOID P2P",
                        "dir=in",
                        "action=allow",
                        "protocol=TCP",
                        "localport=50001",
                        "profile=any",
                        "enable=yes",
                    ])
                    .output();
                let udp_r = std::process::Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=VOID P2P",
                        "dir=in",
                        "action=allow",
                        "protocol=UDP",
                        "localport=50001",
                        "profile=any",
                        "edge=yes",
                        "enable=yes",
                    ])
                    .output();
                match (tcp_r, udp_r) {
                    (Ok(t), Ok(u)) if t.status.success() && u.status.success() => {
                        info!("✅ Файрвол настроен (TCP + UDP разрешены)")
                    }
                    _ => info!("⚠ Не удалось настроить файрвол"),
                }
            } else {
                let bat = format!(
                    "@echo off\r\n\
                     netsh advfirewall firewall delete rule name=\"VOID P2P\"\r\n\
                     netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=TCP localport=50001 profile=any enable=yes\r\n\
                     netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=UDP localport=50001 profile=any edge=yes enable=yes\r\n"
                );
                let bat_path = std::env::temp_dir().join("void_p2p_firewall.bat");
                if std::fs::write(&bat_path, bat).is_ok() {
                    info!("Настраиваю файрвол (запрос UAC)...");
                    let result = std::process::Command::new("powershell")
                        .args([
                            "-NoProfile",
                            "-Command",
                            &format!(
                                "Start-Process -FilePath '{}' -Verb RunAs -Wait",
                                bat_path.display()
                            ),
                        ])
                        .status();
                    match result {
                        Ok(s) if s.success() => info!("✅ Файрвол настроен"),
                        _ => {
                            info!("⚠ UAC отклонён. Запустите вручную от Админастратора:");
                            info!("  {}", bat_path.display());
                        }
                    }
                }
            }
        } else {
            info!(
                "VOID: автонастройка файрвола отключена. Для входящих TCP/UDP 50001 задайте VOID_APPLY_FIREWALL_RULE=1 или откройте порты вручную."
            );
        }

        #[cfg(target_os = "macos")]
        if env_flag_true("VOID_APPLY_FIREWALL_RULE") {
            info!("Настраиваю файрвол macOS...");
            let _ = std::process::Command::new("sudo")
                .args([
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
                    "--add",
                    &exe,
                ])
                .output();
            let _ = std::process::Command::new("sudo")
                .args([
                    "/usr/libexec/ApplicationFirewall/socketfilterfw",
                    "--unblockapp",
                    &exe,
                ])
                .output();
            info!("✅ Файрвол macOS настроен");
        } else {
            let _ = exe;
            info!(
                "VOID: автонастройка файрвола macOS отключена (VOID_APPLY_FIREWALL_RULE=1 — включить)."
            );
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        let _ = (exe, env_flag_true("VOID_APPLY_FIREWALL_RULE"));

        let vault_unlock_kind =
            detect_vault_unlock_kind().map_err(|m| Box::<dyn Error>::from(m))?;

        info!("🌐 VOID bootstrap: загрузка из vault.bin после разблокировки.");

        let (event_tx, event_rx) = mpsc::channel(1024);
        let (command_tx, command_rx) = mpsc::channel(1024);
        let command_tx_for_mdns = command_tx.clone();

        let chat_messages = SharedChatMessages::new();

        let deferred_network_spawn = DeferredNetworkSpawn {
            event_tx: event_tx.clone(),
            command_rx,
            command_tx_for_mdns,
            chat_messages: chat_messages.clone(),
        };

        let mut pending_unlock_state = VaultUnlockState::new(vault_unlock_kind.clone());
        if matches!(vault_unlock_kind, VaultUnlockKind::OpenWrappedKey) {
            if let Some(saved) = load_remembered_password() {
                pending_unlock_state.password = saved;
                pending_unlock_state.remember_password = true;
                pending_unlock_state.try_auto_unlock = true;
            }
        }
        pending_unlock_state.kind = vault_unlock_kind;

        let placeholder_kp = libp2p::identity::Keypair::generate_ed25519();
        let placeholder_peer_id = PeerId::from(placeholder_kp.public());
        let placeholder_static_secret =
            crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);

        let viewport = egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([820.0, 540.0])
            .with_title(concat!(
                "VOID — пароль vault [build ",
                env!("CARGO_PKG_VERSION"),
                "-2026-07-30]"
            ));

        eframe::run_native(
            "VOID P2P",
            eframe::NativeOptions {
                viewport,
                ..Default::default()
            },
            Box::new(move |cc| {
                Ok(Box::new(App::new(
                    cc,
                    Some(pending_unlock_state),
                    Some(deferred_network_spawn),
                    None,
                    placeholder_peer_id,
                    "Разблокировка…".into(),
                    placeholder_static_secret,
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::new(),
                    HashSet::new(),
                    command_tx,
                    event_rx,
                    chat_messages,
                )))
            }),
        )
        .map_err(|e| Box::new(e) as Box<dyn Error>)
    }
}
