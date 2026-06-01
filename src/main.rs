mod chat_store;
mod crypto;
mod file_transfer;
mod ui;

mod app;
mod bootstrap;
mod network;
mod protocol;
mod vault;

pub(crate) use app::{App, PendingSend, RESEND_GRACE, SharedChatMessages};
pub(crate) use bootstrap::parse_seed_input;
pub(crate) use protocol::{ChatMessage, new_message_id};
pub(crate) use network::{NetworkEvent, UICommand};
pub(crate) use protocol::FileTransferProgress;

use std::collections::HashMap;
use std::error::Error;

use eframe::egui;
use libp2p::PeerId;
use tokio::sync::mpsc;
use tracing::info;

use bootstrap::void_bootstrap_multiaddrs;
use network::env_flag_true;
use app::DeferredNetworkSpawn;
use vault::{detect_vault_unlock_kind, VaultUnlockState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn")
            }),
        )
        .try_init();

    // === Правила файрвола: только по явному согласию (VOID_APPLY_FIREWALL_RULE=1) ===
    #[allow(unused_variables)]
    let exe_path = std::env::current_exe().unwrap_or_default();
    #[allow(unused_variables)]
    let exe = exe_path.display().to_string();

    #[cfg(target_os = "windows")]
    if env_flag_true("VOID_APPLY_FIREWALL_RULE") {
        // Проверяем, запущены ли мы уже от Администратора
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
            // Пишем команды в временный .bat файл, запускаем от админа через UAC
            let bat = format!(
                "@echo off\r\n\
                 netsh advfirewall firewall delete rule name=\"VOID P2P\"\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=TCP localport=50001 profile=any enable=yes\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=UDP localport=50001 profile=any edge=yes enable=yes\r\n"
            );
            let bat_path = std::env::temp_dir().join("void_p2p_firewall.bat");
            if std::fs::write(&bat_path, bat).is_ok() {
                info!("Настраиваю файрвол (запрос UAC)...");
                // ShellExecute runas — самый надёжный способ UAC-элевации
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
        info!(
            "VOID: автонастройка файрвола macOS отключена (VOID_APPLY_FIREWALL_RULE=1 — включить)."
        );
    }

    let vault_unlock_kind =
        detect_vault_unlock_kind().map_err(|m| Box::<dyn Error>::from(m))?;

    let void_bootstraps = void_bootstrap_multiaddrs();
    if void_bootstraps.is_empty() {
        info!(
            "🌐 Глобально: нет seed для DHT — задайте BUILTIN_VOID_BOOTSTRAP / VOID_BOOTSTRAP_PUBLIC_LIST_URL в коде, VOID_BOOTSTRAP_URL, VOID_BOOTSTRAP, void-bootstrap.txt, либо полный multiaddr собеседника. LAN: mDNS (отключить: VOID_DISABLE_MDNS)."
        );
    } else {
        info!(
            "🌐 VOID bootstrap: {} multiaddr → заполнение DHT /void/kad/1.0.0 (без IPFS).",
            void_bootstraps.len()
        );
    }

    let (event_tx, event_rx) = mpsc::channel(256);
    let (command_tx, command_rx) = mpsc::channel(256);
    let command_tx_for_mdns = command_tx.clone();

    let chat_messages = SharedChatMessages::new();

    let deferred_network_spawn = DeferredNetworkSpawn {
        event_tx: event_tx.clone(),
        command_rx,
        command_tx_for_mdns,
        void_bootstraps,
        chat_messages: chat_messages.clone(),
    };

    let pending_unlock_state = VaultUnlockState {
        kind: vault_unlock_kind,
        password: String::new(),
        password_confirm: String::new(),
        error: None,
    };

    let placeholder_kp = libp2p::identity::Keypair::generate_ed25519();
    let placeholder_peer_id = PeerId::from(placeholder_kp.public());
    let placeholder_static_secret =
        crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);

    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([820.0, 540.0])
        .with_title("VOID — пароль vault");

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
                command_tx,
                event_rx,
                chat_messages,
            )))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
