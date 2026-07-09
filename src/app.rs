//! Состояние приложения, vault unlock и логика повторной отправки.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::RngCore;
use tokio::sync::mpsc;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::bootstrap::{
    merge_bootstrap_string_lists, migrate_void_bootstrap_txt, void_bootstrap_multiaddrs,
};
use crate::chat_store::ChatJournal;
use crate::crypto;
use crate::file_transfer;
use crate::group::{
    self, build_invite_link, extract_invite_links, group_thread_key, is_group_thread,
    parse_group_thread_key, parse_invite_link, GroupChat, GroupMember,
};
use crate::network::{run_chat_network, NetworkEvent, UICommand};
use crate::outbox::{Outbox, OutboxEntry};
use crate::protocol::{
    new_message_id, transfer_id_from_hex, transfer_id_to_hex, ChatMessage, FileTransferProgress,
    OutgoingDeliveryStatus, VoiceMeta,
};
use crate::ui::{setup_custom_style, Toast, ToastKind, TOAST_TTL_LONG, TOAST_TTL_SHORT};
use crate::vault::{
    clear_remembered_password, save_remembered_password, AddressBookEntry, Storage,
    VaultUnlockKind, VaultUnlockState,
};
use crate::voice::{VoicePlayer, VoiceRecorder};

/// Переписки, доступные и UI, и сетевому таску (входящее удаление без roundtrip через egui).
#[derive(Clone)]
pub(crate) struct SharedChatMessages {
    inner: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    journal_dirty: Arc<AtomicBool>,
}

impl SharedChatMessages {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            journal_dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<ChatMessage>>> {
        self.inner
            .lock()
            .unwrap_or_else(| poisoned| poisoned.into_inner())
    }

    pub(crate) fn mark_dirty(&self) {
        self.journal_dirty.store(true, Ordering::Release);
    }

    pub(crate) fn take_dirty(&self) -> bool {
        self.journal_dirty.swap(false, Ordering::AcqRel)
    }

    /// Применяет входящую delete-команду от собеседника (только его сообщения).
    pub(crate) fn apply_incoming_delete(
        &self,
        from: PeerId,
        message_ids: &[String],
    ) -> (Vec<String>, Vec<String>) {
        let peer_str = from.to_string();
        let from_str = from.to_string();
        let mut deleted = Vec::new();
        let mut missing = Vec::new();

        let mut messages = self.lock();
        if let Some(msgs) = messages.get_mut(&peer_str) {
            for id in message_ids {
                if msgs
                    .iter()
                    .any(|m| m.id == *id && m.sender_id == from_str)
                {
                    deleted.push(id.clone());
                } else {
                    missing.push(id.clone());
                }
            }
            if !deleted.is_empty() {
                msgs.retain(|m| !(deleted.contains(&m.id) && m.sender_id == from_str));
                drop(messages);
                self.mark_dirty();
            }
        } else {
            missing.extend(message_ids.iter().cloned());
        }

        (deleted, missing)
    }
}

/// Параметры отложенного запуска сетевого таска после разблокировки vault.
pub(crate) struct DeferredNetworkSpawn {
    pub event_tx: mpsc::Sender<NetworkEvent>,
    pub command_rx: mpsc::Receiver<UICommand>,
    pub command_tx_for_mdns: mpsc::Sender<UICommand>,
    pub chat_messages: SharedChatMessages,
}

/// Сообщение в очереди ожидания доставки. Если в течение `RESEND_GRACE` после
/// последней попытки прилетел `SendFailedDial` (или просто прошло столько же
/// времени без подтверждения), запускаем DHT-lookup и через `resend_delay_for_attempt`
/// отправляем повторно. Очередь не сбрасывается, пока сообщение не доставлено
/// или контакт не признан не-VOID.
pub(crate) struct PendingSend {
    pub(crate) peer: PeerId,
    pub(crate) text: String,
    pub(crate) message_id: String,
    pub(crate) last_send_at: Instant,
    pub(crate) dht_kicked: bool,
    pub(crate) dht_kicked_at: Option<Instant>,
    pub(crate) attempts: u32,
    /// Сообщение ждёт E2EE-хендшейк — не запускаем таймаут доставки.
    pub(crate) awaiting_session: bool,
}

/// Файл в очереди до появления E2EE-сессии или сети.
pub(crate) struct PendingFileSend {
    pub(crate) peer: PeerId,
    pub(crate) path: String,
    pub(crate) kind: file_transfer::FileKind,
    pub(crate) last_attempt: Instant,
}

/// Голосовое сообщение в очереди до E2EE-сессии.
#[derive(Clone)]
pub(crate) struct PendingVoiceSend {
    pub(crate) peer: PeerId,
    pub(crate) path: String,
    pub(crate) duration_secs: f32,
    pub(crate) message_id: String,
    pub(crate) transfer_id: [u8; 16],
    pub(crate) last_attempt: Instant,
}

/// Сообщение группового чата в очереди повторной отправки.
#[derive(Clone)]
pub(crate) struct PendingGroupSend {
    pub(crate) group_id: String,
    pub(crate) members: Vec<PeerId>,
    pub(crate) text: String,
    pub(crate) message_id: String,
    pub(crate) last_send_at: Instant,
    pub(crate) attempts: u32,
    /// Подтверждённые доставки (по одному на каждого участника, кроме себя).
    pub(crate) delivered_to: HashSet<PeerId>,
}

pub(crate) const RESEND_GRACE: Duration = Duration::from_secs(1);
/// Базовая задержка перед повтором после DHT-поиска (растёт с числом попыток).
pub(crate) const RESEND_DELAY_BASE: Duration = Duration::from_secs(2);
pub(crate) const RESEND_DELAY_MAX: Duration = Duration::from_secs(300);
/// Сколько ждём E2EE-хендшейк, прежде чем снова разрешить DHT-ретрай.
pub(crate) const SESSION_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
/// Журнал переписок пишем на диск не чаще этого интервала (не блокируем отправку).
pub(crate) const JOURNAL_PERSIST_DEBOUNCE: Duration = Duration::from_secs(2);

pub(crate) fn resend_delay_for_attempt(attempts: u32) -> Duration {
    let exp = attempts.min(6);
    let secs = RESEND_DELAY_BASE.as_secs().saturating_mul(1u64 << exp);
    Duration::from_secs(secs.min(RESEND_DELAY_MAX.as_secs()))
}

pub(crate) struct App {
    pub(crate) local_peer_id: PeerId,
    pub(crate) local_nickname: String,
    pub(crate) listen_addrs: Vec<String>,
    pub(crate) connected_peers: usize,
    pub(crate) connected_peer_ids: HashSet<PeerId>,
    pub(crate) dial_address: String,
    pub(crate) chat_input: String,
    pub(crate) messages: SharedChatMessages,
    pub(crate) known_peers: HashMap<PeerId, String>,
    /// Известные multiaddr контактов из зашифрованного vault. При старте
    /// подаются в Kademlia; при добавлении контакта — сразу Dial + Kad.
    pub(crate) contact_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    pub(crate) selected_chat: String,
    pub(crate) status_log: Vec<String>,
    pub(crate) show_logs: bool,
    pub(crate) show_sidebar: bool,
    pub(crate) sidebar_width: f32,
    pub(crate) public_ip: Option<String>,
    pub(crate) add_contact_peer: String,
    pub(crate) add_contact_name: String,
    pub(crate) peer_name_edits: HashMap<PeerId, String>,
    pub(crate) void_bootstrap_draft: String,
    /// Bootstrap-ноды VOID из vault.bin (полные multiaddr).
    pub(crate) void_bootstrap_strings: Vec<String>,
    pub(crate) dht_routing_lines: Vec<String>,
    pub(crate) dht_routing_total: usize,
    pub(crate) command_tx: mpsc::Sender<UICommand>,
    pub(crate) event_rx: mpsc::Receiver<NetworkEvent>,
    pub(crate) _sessions: HashMap<libp2p::PeerId, crypto::SecureSession>,
    pub(crate) _local_static: crypto::StaticSecret,
    pub(crate) pending_sends: Vec<PendingSend>,
    pub(crate) pending_file_sends: Vec<PendingFileSend>,
    /// Прочитанные входящие — read receipt уже отправлен (не персистится).
    pub(crate) read_receipts_sent: HashSet<(String, String)>,
    pub(crate) toasts: Vec<Toast>,
    pub(crate) chat_bg_texture: Option<egui::TextureHandle>,
    pub(crate) star_texture: Option<egui::TextureHandle>,
    // ─── Файловый sub-протокол ──────────────────────────────────────────────
    /// Входящие предложения файлов, ожидающие ответа пользователя.
    pub(crate) incoming_file_offers: Vec<file_transfer::PendingFileOffer>,
    /// Активные передачи (исходящие и входящие).
    pub(crate) active_file_transfers: HashMap<[u8; 16], FileTransferProgress>,
    /// Флаг: показывать popup-меню выбора типа вложения.
    pub(crate) show_attach_menu: bool,
    /// Запись голосовых с системного микрофона.
    pub(crate) voice_recorder: VoiceRecorder,
    pub(crate) voice_probe_done: bool,
    /// Воспроизведение голосовых в чате.
    pub(crate) voice_player: VoicePlayer,
    /// Локальные пути WAV по transfer_id (hex).
    pub(crate) voice_audio_paths: HashMap<String, String>,
    pub(crate) pending_voice_sends: Vec<PendingVoiceSend>,
    pub(crate) pending_group_sends: Vec<PendingGroupSend>,
    /// Групповые чаты (id → метаданные).
    pub(crate) groups: HashMap<String, GroupChat>,
    /// Группы, из которых вышли — не показывать и не принимать новые сообщения.
    pub(crate) left_groups: HashSet<String>,
    pub(crate) show_create_group: bool,
    pub(crate) create_group_name: String,
    pub(crate) create_group_pick: HashSet<PeerId>,
    pub(crate) join_group_link: String,
    pub(crate) show_group_panel: bool,
    pub(crate) add_group_member_peer: String,
    /// Недоставленное: быстрый `outbox.bin` (переживает выход из приложения).
    pub(crate) outbox_entries: Vec<OutboxEntry>,
    /// Пиры, которым уже отправили group_sync в этой сессии (до disconnect).
    pub(crate) group_synced_peers: HashSet<PeerId>,
    journal_persist_after: Option<Instant>,
    /// Ожидаемый результат выбора папки сохранения: `(rx, transfer_id, from_peer)`.
    /// Поллим `try_recv()` каждый кадр; `None` = выбор не идёт.
    pub(crate) pending_accept: Option<(
        std::sync::mpsc::Receiver<Option<String>>,
        [u8; 16],
        PeerId,
    )>,
    /// Экран ввода пароля до расшифровки `void.key` / создания профиля.
    pub(crate) pending_unlock: Option<VaultUnlockState>,
    pub(crate) deferred_network_spawn: Option<DeferredNetworkSpawn>,
    pub(crate) vault_master_key: Option<Zeroizing<[u8; 32]>>,
}

// ─── Функции создания и инициализации ──────────────────────────────────────

fn resolve_vault_bootstraps(
    storage: &crate::vault::StorageData,
    master_arr: &[u8; 32],
    nickname: &str,
) -> Vec<String> {
    let mut bootstraps = storage.void_bootstraps.clone();
    if bootstraps.is_empty() {
        let migrated = migrate_void_bootstrap_txt();
        if !migrated.is_empty() {
            bootstraps = migrated;
            if let Err(e) = Storage::save(
                master_arr,
                nickname,
                None,
                None,
                None,
                Some(&bootstraps),
                None,
                None,
            ) {
                warn!("VOID: импорт void-bootstrap.txt → vault: {}", e);
            } else {
                info!("VOID: bootstrap из void-bootstrap.txt перенесены в vault.bin");
            }
        }
    }
    bootstraps
}

impl App {
    pub(crate) fn new(
        cc: &eframe::CreationContext<'_>,
        pending_unlock: Option<VaultUnlockState>,
        deferred_network_spawn: Option<DeferredNetworkSpawn>,
        vault_master_key: Option<Zeroizing<[u8; 32]>>,
        local_peer_id: PeerId,
        local_nickname: String,
        local_static: crypto::StaticSecret,
        initial_address_book: HashMap<PeerId, String>,
        initial_contact_addrs: HashMap<PeerId, Vec<Multiaddr>>,
        initial_groups: HashMap<String, GroupChat>,
        initial_left_groups: HashSet<String>,
        command_tx: mpsc::Sender<UICommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
        chat_messages: SharedChatMessages,
    ) -> Self {
        setup_custom_style(&cc.egui_ctx);

        Self {
            local_peer_id,
            local_nickname,
            listen_addrs: Vec::new(),
            connected_peers: 0,
            connected_peer_ids: HashSet::new(),
            dial_address: String::new(),
            chat_input: String::new(),
            messages: chat_messages,
            known_peers: initial_address_book,
            contact_addrs: initial_contact_addrs,
            selected_chat: String::new(),
            status_log: Vec::new(),
            show_logs: false,
            show_sidebar: true,
            sidebar_width: 300.0,
            public_ip: None,
            add_contact_peer: String::new(),
            add_contact_name: String::new(),
            peer_name_edits: HashMap::new(),
            void_bootstrap_draft: String::new(),
            void_bootstrap_strings: Vec::new(),
            dht_routing_lines: Vec::new(),
            dht_routing_total: 0,
            command_tx,
            event_rx,
            _sessions: HashMap::new(),
            _local_static: local_static,
            pending_sends: Vec::new(),
            pending_file_sends: Vec::new(),
            read_receipts_sent: HashSet::new(),
            toasts: Vec::new(),
            chat_bg_texture: None,
            star_texture: None,
            incoming_file_offers: Vec::new(),
            active_file_transfers: HashMap::new(),
            show_attach_menu: false,
            voice_recorder: VoiceRecorder::new(),
            voice_probe_done: false,
            voice_player: VoicePlayer::new(),
            voice_audio_paths: HashMap::new(),
            pending_voice_sends: Vec::new(),
            pending_group_sends: Vec::new(),
            groups: initial_groups,
            left_groups: initial_left_groups,
            show_create_group: false,
            create_group_name: String::new(),
            create_group_pick: HashSet::new(),
            join_group_link: String::new(),
            show_group_panel: false,
            add_group_member_peer: String::new(),
            outbox_entries: Vec::new(),
            group_synced_peers: HashSet::new(),
            journal_persist_after: None,
            pending_accept: None,
            pending_unlock,
            deferred_network_spawn,
            vault_master_key,
        }
    }

    // ─── Основные экраны приложения ──────────────────────────────────────────

    /// Экран разблокировки vault. Возвращает `true`, пока нужно блокировать основной UI.
    pub(crate) fn vault_unlock_gate(&mut self, ctx: &egui::Context) -> bool {
        if self
            .pending_unlock
            .as_ref()
            .is_some_and(|p| p.try_auto_unlock && !p.password.is_empty())
        {
            self.pending_unlock.as_mut().unwrap().try_auto_unlock = false;
            self.submit_vault_unlock(ctx);
            return true;
        }

        let kind = match self.pending_unlock.as_ref() {
            Some(p) => p.kind.clone(),
            None => return false,
        };

        #[derive(Clone, Copy)]
        enum Act {
            Unlock,
        }
        let mut act = None::<Act>;

        let subtitle = match &kind {
            VaultUnlockKind::CreateProfile => "Задайте пароль vault (AES-ключ будет защищён Argon2id).",
            VaultUnlockKind::OpenWrappedKey => "Введите пароль vault.",
            VaultUnlockKind::MigratePlainMaster(_) => {
                "Старый void.key без пароля: задаётесь пароль (Argon2id + AES), vault не меняется."
            }
        };
        let need_confirm = matches!(
            &kind,
            VaultUnlockKind::CreateProfile | VaultUnlockKind::MigratePlainMaster(_),
        );

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(56.0);
                ui.label(egui::RichText::new("VOID").size(36.0).strong());
                ui.add_space(12.0);
                ui.label(egui::RichText::new(subtitle).weak());
                ui.add_space(24.0);
                ui.set_max_width(420.0);

                if let Some(p) = self.pending_unlock.as_mut() {
                    ui.label("Пароль:");
                    ui.add(
                        egui::TextEdit::singleline(&mut p.password)
                            .desired_width(320.0)
                            .password(true)
                            .hint_text("Не короче 8 символов"),
                    );

                    if need_confirm {
                        ui.add_space(8.0);
                        ui.label("Пароль ещё раз:");
                        ui.add(
                            egui::TextEdit::singleline(&mut p.password_confirm)
                                .desired_width(320.0)
                                .password(true),
                        );
                    }

                    ui.add_space(8.0);
                    ui.checkbox(
                        &mut p.remember_password,
                        "Запомнить пароль на этом устройстве",
                    )
                    .on_hover_text(
                        "Пароль сохраняется в системном хранилище (Windows / macOS / Linux) \
                         и подставляется при следующем запуске.",
                    );

                    if let Some(err) = &p.error {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(220, 100, 100), err);
                    }

                    ui.add_space(24.0);
                    if ui
                        .add_sized([180.0, 36.0], egui::Button::new("Продолжить"))
                        .clicked()
                    {
                        act = Some(Act::Unlock);
                    }
                }
                ui.add_space(12.0);
                ui.small(
                    "Мастер-ключ vault зашифрован в void.key паролем (Argon2id + AES-GCM).",
                );
            });
        });

        if matches!(act, Some(Act::Unlock)) {
            self.submit_vault_unlock(ctx);
        }
        ctx.request_repaint_after(Duration::from_millis(200));
        true
    }

    // ─── Действия по событиям ──────────────────────────────────────────────────
    fn submit_vault_unlock(&mut self, ctx: &egui::Context) {
        let Some(mut pending) = self.pending_unlock.take() else {
            return;
        };
        pending.error = None;
        let remember_password = pending.remember_password;
        let pwd_owned = pending.password.clone();
        let pwd = pwd_owned.trim();
        let pwd2 = pending.password_confirm.trim();
        let require_confirm = matches!(
            pending.kind,
            VaultUnlockKind::CreateProfile | VaultUnlockKind::MigratePlainMaster(_),
        );

        if pwd.len() < 8 {
            pending.error = Some("Укажите пароль не короче 8 символов.".into());
            pending.try_auto_unlock = false;
            self.pending_unlock = Some(pending);
            return;
        }
        if require_confirm && pwd != pwd2 {
            pending.error = Some("Пароли не совпадают.".into());
            pending.try_auto_unlock = false;
            self.pending_unlock = Some(pending);
            return;
        }

        let kind_followup = match &pending.kind {
            VaultUnlockKind::CreateProfile => VaultUnlockKind::CreateProfile,
            VaultUnlockKind::OpenWrappedKey => VaultUnlockKind::OpenWrappedKey,
            VaultUnlockKind::MigratePlainMaster(z) => {
                VaultUnlockKind::MigratePlainMaster(z.clone())
            }
        };

        let master_arr: Zeroizing<[u8; 32]> = match &pending.kind {
            VaultUnlockKind::OpenWrappedKey => match Storage::unwrap_master_key_file(pwd) {
                Ok(m) => Zeroizing::new(m),
                Err(e) => {
                    clear_remembered_password();
                    pending.password.zeroize();
                    pending.password_confirm.zeroize();
                    pending.try_auto_unlock = false;
                    pending.remember_password = false;
                    pending.error = Some(format!("{e}"));
                    self.pending_unlock = Some(pending);
                    return;
                }
            },
            VaultUnlockKind::MigratePlainMaster(leg) => {
                let plain = **leg;
                if let Err(e) = Storage::write_wrapped_master_key_file(&plain, pwd) {
                    pending.password.zeroize();
                    pending.password_confirm.zeroize();
                    pending.error = Some(format!("{}", e));
                    self.pending_unlock = Some(pending);
                    return;
                }
                Zeroizing::new(plain)
            }
            VaultUnlockKind::CreateProfile => {
                let mut plain = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut plain);
                if let Err(e) = Storage::write_wrapped_master_key_file(&plain, pwd) {
                    pending.password.zeroize();
                    pending.password_confirm.zeroize();
                    pending.error = Some(format!("{}", e));
                    self.pending_unlock = Some(pending);
                    return;
                }
                Zeroizing::new(plain)
            }
        };

        if remember_password {
            if let Err(e) = save_remembered_password(pwd) {
                warn!("VOID: не удалось сохранить пароль в системном хранилище: {}", e);
            }
        } else {
            clear_remembered_password();
        }

        pending.password.zeroize();
        pending.password_confirm.zeroize();
        drop(pending);

        let Some(dn_sp) = self.deferred_network_spawn.take() else {
            self.pending_unlock = Some(VaultUnlockState {
                kind: kind_followup,
                password: String::new(),
                password_confirm: String::new(),
                error: Some("Внутренняя ошибка: параметры сети недоступны.".into()),
                remember_password,
                try_auto_unlock: false,
            });
            return;
        };

        match kind_followup {
            VaultUnlockKind::OpenWrappedKey | VaultUnlockKind::MigratePlainMaster(_) => {
                let storage = match Storage::load(&master_arr) {
                    Ok(s) => s,
                    Err(e) => {
                        self.pending_unlock = Some(VaultUnlockState {
                            kind: VaultUnlockKind::OpenWrappedKey,
                            password: String::new(),
                            password_confirm: String::new(),
                            error: Some(format!("Не удалось прочитать vault.bin: {}", e)),
                            remember_password,
                            try_auto_unlock: false,
                        });
                        self.deferred_network_spawn = Some(dn_sp);
                        return;
                    }
                };
                let local_key = match libp2p::identity::Keypair::from_protobuf_encoding(
                    &storage.keypair_bytes,
                ) {
                    Ok(k) => k,
                    Err(e) => {
                        self.pending_unlock = Some(VaultUnlockState {
                            kind: VaultUnlockKind::OpenWrappedKey,
                            password: String::new(),
                            password_confirm: String::new(),
                            error: Some(format!("Не удалось восстановить ключи: {}", e)),
                            remember_password,
                            try_auto_unlock: false,
                        });
                        self.deferred_network_spawn = Some(dn_sp);
                        return;
                    }
                };
                let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
                let my_id = PeerId::from(local_key.public());
                let void_bootstrap_strings =
                    resolve_vault_bootstraps(&storage, &master_arr, &storage.nickname);
                let network_bootstraps = void_bootstrap_multiaddrs(&void_bootstrap_strings);
                self.void_bootstrap_strings = void_bootstrap_strings;
                let mut book = HashMap::new();
                let mut addrs_map: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
                for entry in storage.address_book {
                    if let Ok(pid) = entry.peer_id.parse::<PeerId>() {
                        if pid != my_id {
                            book.insert(pid, entry.display_name);
                            let mut parsed: Vec<Multiaddr> = entry
                                .addrs
                                .iter()
                                .filter_map(|s| s.parse::<Multiaddr>().ok())
                                .collect();
                            if !parsed.is_empty() {
                                addrs_map.entry(pid).or_default().append(&mut parsed);
                            }
                        }
                    }
                }
                let contact_addrs_flat: Vec<(PeerId, Multiaddr)> = addrs_map
                    .iter()
                    .flat_map(|(pid, addrs)| addrs.iter().cloned().map(move |a| (*pid, a)))
                    .collect();
                let mut groups_map: HashMap<String, GroupChat> = HashMap::new();
                let left_groups: HashSet<String> =
                    storage.left_groups.into_iter().collect();
                for g in storage.groups {
                    if !left_groups.contains(&g.id) {
                        groups_map.insert(g.id.clone(), g);
                    }
                }
                tokio::spawn(run_chat_network(
                    dn_sp.command_rx,
                    dn_sp.event_tx,
                    dn_sp.command_tx_for_mdns,
                    local_key.clone(),
                    static_secret.clone(),
                    network_bootstraps,
                    contact_addrs_flat,
                    dn_sp.chat_messages.clone(),
                ));
                self.apply_unlock_success(
                    ctx,
                    local_key,
                    storage.nickname,
                    static_secret,
                    book,
                    addrs_map,
                    groups_map,
                    left_groups,
                    master_arr,
                );
            }
            VaultUnlockKind::CreateProfile => {
                let local_key = libp2p::identity::Keypair::generate_ed25519();
                let static_secret =
                    crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                let nickname = format!(
                    "User_{}",
                    &PeerId::from(local_key.public()).to_string()[..4]
                );
                if let Err(e) = Storage::save(
                    &master_arr,
                    &nickname,
                    Some(&local_key),
                    Some(&static_secret),
                    None,
                    None,
                    None,
                    None,
                ) {
                    let _ = std::fs::remove_file(Storage::KEY_FILE);
                    self.pending_unlock = Some(VaultUnlockState {
                        kind: VaultUnlockKind::CreateProfile,
                        password: String::new(),
                        password_confirm: String::new(),
                        error: Some(format!("Не удалось создать vault: {}", e)),
                        remember_password,
                        try_auto_unlock: false,
                    });
                    self.deferred_network_spawn = Some(dn_sp);
                    return;
                }

                self.void_bootstrap_strings = Vec::new();
                tokio::spawn(run_chat_network(
                    dn_sp.command_rx,
                    dn_sp.event_tx,
                    dn_sp.command_tx_for_mdns,
                    local_key.clone(),
                    static_secret.clone(),
                    Vec::new(),
                    Vec::new(),
                    dn_sp.chat_messages.clone(),
                ));

                self.apply_unlock_success(
                    ctx,
                    local_key,
                    nickname,
                    static_secret,
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::new(),
                    HashSet::new(),
                    master_arr,
                );
            }
        }
    }

    // ─── Действия по разблокировке vault ──────────────────────────────────────
    fn apply_unlock_success(
        &mut self,
        ctx: &egui::Context,
        local_key: libp2p::identity::Keypair,
        nickname: String,
        static_secret: crypto::StaticSecret,
        book: HashMap<PeerId, String>,
        addrs_map: HashMap<PeerId, Vec<Multiaddr>>,
        groups: HashMap<String, GroupChat>,
        left_groups: HashSet<String>,
        master_arr: Zeroizing<[u8; 32]>,
    ) {
        self.local_peer_id = PeerId::from(local_key.public());
        self.local_nickname = nickname;
        self.known_peers = book;
        self.contact_addrs = addrs_map;
        self.groups = groups;
        self.left_groups = left_groups;
        self._local_static = static_secret;
        self.pending_unlock = None;
        self.vault_master_key = Some(master_arr.clone());

        match ChatJournal::load(&master_arr) {
            Ok(loaded) => {
                *self.messages.lock() = loaded;
                self.ensure_message_ids();
                info!(
                    "Загружено {} переписок из chat_journal.bin",
                    self.messages.lock().len()
                );
            }
            Err(e) => {
                warn!("VOID: не удалось загрузить chat_journal.bin: {}", e);
            }
        }

        match Outbox::load(&master_arr) {
            Ok(entries) => {
                self.outbox_entries = entries;
                info!("Загружено {} записей из outbox.bin", self.outbox_entries.len());
            }
            Err(e) => warn!("VOID: не удалось загрузить outbox.bin: {}", e),
        }
        self.restore_pending_outgoing();
        self.scan_chat_journal_for_group_invites();
        self.dispatch_outbox();

        info!("=== VOID P2P Chat ===");
        info!("Ваш Peer ID: {}", self.local_peer_id);
        info!("Ваш никнейм: {}", self.local_nickname);

        let pid = self.local_peer_id.to_string();
        let tit = pid
            .as_str()
            .get(..8)
            .map(str::to_string)
            .unwrap_or_else(|| pid.clone());
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("VOID Chat [{}]", tit)));

        self.add_status("Vault разблокирован, сеть запущена.".into());
    }

    fn ensure_message_ids(&self) {
        let mut messages = self.messages.lock();
        for msgs in messages.values_mut() {
            for msg in msgs.iter_mut() {
                if msg.id.is_empty() {
                    msg.id = new_message_id();
                }
            }
        }
    }

    /// Сохраняет переписки в `chat_journal.bin` (AES-GCM под мастер-ключом vault).
    pub(crate) fn persist_chat_journal(&self) {
        let Some(ref vault_master_key) = self.vault_master_key else {
            return;
        };
        if let Err(e) = ChatJournal::save(vault_master_key, &*self.messages.lock()) {
            warn!("VOID: не удалось сохранить chat_journal.bin: {}", e);
        }
    }

    pub(crate) fn mark_chat_journal_dirty(&self) {
        self.messages.mark_dirty();
    }

    pub(crate) fn flush_chat_journal_if_dirty(&self) {
        if self.messages.take_dirty() {
            self.persist_chat_journal();
        }
    }

    /// Сохраняет исходящее в память + outbox (быстро), журнал — с debounce.
    pub(crate) fn stage_outgoing_message(&mut self, msg: ChatMessage) {
        self.ingest_chat_message(msg);
        self.schedule_journal_persist();
    }

    pub(crate) fn schedule_journal_persist(&mut self) {
        self.journal_persist_after =
            Some(Instant::now() + JOURNAL_PERSIST_DEBOUNCE);
    }

    pub(crate) fn tick_journal_persist(&mut self) {
        if let Some(deadline) = self.journal_persist_after {
            if Instant::now() >= deadline {
                self.journal_persist_after = None;
                self.persist_chat_journal();
            }
        }
    }

    pub(crate) fn persist_all_before_exit(&self) {
        self.persist_chat_journal();
        self.persist_outbox();
    }

    fn persist_outbox(&self) {
        let Some(ref key) = self.vault_master_key else {
            return;
        };
        if let Err(e) = Outbox::save(key, &self.outbox_entries) {
            warn!("VOID: не удалось сохранить outbox.bin: {}", e);
        }
    }

    fn push_outbox(&mut self, entry: OutboxEntry) {
        self.outbox_entries.retain(|e| !outbox_same_slot(e, &entry));
        self.outbox_entries.push(entry);
        self.persist_outbox();
    }

    fn remove_outbox_direct(&mut self, peer: &str, message_id: &str) {
        let before = self.outbox_entries.len();
        self.outbox_entries.retain(|e| {
            !matches!(
                e,
                OutboxEntry::DirectMessage { peer: p, message_id: id, .. }
                    if p == peer && id == message_id
            )
        });
        if self.outbox_entries.len() != before {
            self.persist_outbox();
        }
    }

    fn remove_outbox_group_message(&mut self, message_id: &str) {
        let before = self.outbox_entries.len();
        self.outbox_entries.retain(|e| {
            !matches!(
                e,
                OutboxEntry::GroupMessage { message_id: id, .. } if id == message_id
            )
        });
        if self.outbox_entries.len() != before {
            self.persist_outbox();
        }
    }

    fn remove_outbox_group_sync(&mut self, group_id: &str, recipient: &str) {
        let before = self.outbox_entries.len();
        self.outbox_entries.retain(|e| {
            !matches!(
                e,
                OutboxEntry::GroupSync { group_id: g, recipient: r, .. }
                    if g == group_id && r == recipient
            )
        });
        if self.outbox_entries.len() != before {
            self.persist_outbox();
        }
    }

    pub(crate) fn outbox_track_direct(&mut self, peer: PeerId, message_id: String, text: String) {
        self.push_outbox(OutboxEntry::DirectMessage {
            peer: peer.to_string(),
            message_id,
            text,
        });
    }

    pub(crate) fn outbox_track_group_message(
        &mut self,
        group_id: String,
        message_id: String,
        text: String,
        members: Vec<PeerId>,
    ) {
        self.push_outbox(OutboxEntry::GroupMessage {
            group_id,
            message_id,
            text,
            members: members.iter().map(|p| p.to_string()).collect(),
        });
    }

    fn queue_outbox_group_sync(&mut self, group: &GroupChat, recipient: PeerId) {
        self.push_outbox(OutboxEntry::GroupSync {
            group_id: group.id.clone(),
            group_name: group.name.clone(),
            creator_id: group.creator_id.clone(),
            members: group.members.clone(),
            recipient: recipient.to_string(),
        });
    }

    /// Отправляет всё из outbox после старта (пережившее выход из приложения).
    pub(crate) fn dispatch_outbox(&mut self) {
        let entries = self.outbox_entries.clone();
        for entry in entries {
            match entry {
                OutboxEntry::DirectMessage {
                    peer,
                    message_id,
                    text,
                } => {
                    let Ok(pid) = peer.parse::<PeerId>() else {
                        continue;
                    };
                    if !self
                        .pending_sends
                        .iter()
                        .any(|p| p.message_id == message_id)
                    {
                        self.pending_sends.push(PendingSend {
                            peer: pid,
                            text: text.clone(),
                            message_id: message_id.clone(),
                            last_send_at: Instant::now(),
                            dht_kicked: false,
                            dht_kicked_at: None,
                            attempts: 0,
                            awaiting_session: false,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendMessage {
                        sender_name: self.local_nickname.clone(),
                        text,
                        recipient: Some(pid),
                        message_id: Some(message_id),
                        is_retry: true,
                    });
                }
                OutboxEntry::GroupMessage {
                    group_id,
                    message_id,
                    text,
                    members,
                } => {
                    if self.left_groups.contains(&group_id)
                        || !self.is_active_group_member(&group_id)
                    {
                        continue;
                    }
                    let member_pids: Vec<PeerId> = members
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    let targets: Vec<PeerId> = member_pids
                        .iter()
                        .copied()
                        .filter(|p| *p != self.local_peer_id)
                        .collect();
                    if targets.is_empty() {
                        continue;
                    }
                    if !self
                        .pending_group_sends
                        .iter()
                        .any(|p| p.message_id == message_id)
                    {
                        self.pending_group_sends.push(PendingGroupSend {
                            group_id: group_id.clone(),
                            members: member_pids,
                            text: text.clone(),
                            message_id: message_id.clone(),
                            last_send_at: Instant::now(),
                            attempts: 0,
                            delivered_to: HashSet::new(),
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                        sender_name: self.local_nickname.clone(),
                        text,
                        group_id,
                        members: targets,
                        message_id: Some(message_id),
                        is_retry: true,
                    });
                }
                OutboxEntry::GroupSync {
                    group_id,
                    group_name,
                    creator_id,
                    members,
                    recipient,
                } => {
                    if self.left_groups.contains(&group_id) {
                        continue;
                    }
                    let Ok(pid) = recipient.parse::<PeerId>() else {
                        continue;
                    };
                    if pid == self.local_peer_id {
                        continue;
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupSync {
                        group_id,
                        group_name,
                        creator_id,
                        members,
                        recipients: vec![pid],
                    });
                }
            }
        }
        let groups: Vec<GroupChat> = self.groups.values().cloned().collect();
        for group in groups {
            self.dial_group_members(&group);
        }
    }

    /// Проходит журнал и подхватывает invite-ссылки (если пир был офлайн при приглашении).
    fn scan_chat_journal_for_group_invites(&mut self) {
        let texts: Vec<String> = self
            .messages
            .lock()
            .values()
            .flatten()
            .filter(|m| m.sender_id != self.local_peer_id.to_string())
            .map(|m| m.text.clone())
            .collect();
        for text in texts {
            self.try_join_groups_from_invite_text(&text);
        }
    }

    pub(crate) fn ingest_chat_message(&mut self, mut msg: ChatMessage) {
        if msg.id.is_empty() {
            msg.id = new_message_id();
        }

        if !msg.text.is_empty() && msg.sender_id != self.local_peer_id.to_string() {
            self.try_join_groups_from_invite_text(&msg.text);
        }

        let voice_tid = msg.voice.as_ref().map(|v| v.transfer_id.clone());

        let bucket = if let Some(ref gid) = msg.group_id {
            if group::validate_group_id(gid) && self.is_active_group_member(gid) {
                Some(group_thread_key(gid))
            } else {
                None
            }
        } else if let Some(ref target) = msg.recipient_id {
            if target == &self.local_peer_id.to_string() {
                Some(msg.sender_id.clone())
            } else if msg.sender_id == self.local_peer_id.to_string() {
                Some(target.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(b) = bucket {
            let mut messages = self.messages.lock();
            let entry = messages.entry(b).or_default();
            if entry.iter().any(|m| m.id == msg.id) {
                return;
            }
            entry.push(msg);
            self.mark_chat_journal_dirty();
        }
        if let Some(tid) = voice_tid {
            self.link_voice_file_if_present(&tid);
        }
    }

    /// Отправляет готовое голосовое, если выбран контакт. Иначе оставляет `Ready`.
    pub(crate) fn try_dispatch_ready_voice(&mut self) -> Option<String> {
        if !self.voice_recorder.has_ready() {
            return None;
        }
        let peer = self.selected_chat.parse::<PeerId>().ok()?;
        let (path, duration) = self.voice_recorder.take_ready()?;
        let dur = crate::voice::fmt_duration(duration);
        match self.send_voice_message(peer, path, duration) {
            Ok(()) => Some(format!("🎤 Голосовое {dur} отправлено")),
            Err(e) => {
                self.add_status(format!("⚠ {}", e));
                None
            }
        }
    }

    /// Обновляет статус доставки исходящего сообщения в журнале.
    pub(crate) fn set_outgoing_delivery(
        &mut self,
        peer: PeerId,
        message_id: &str,
        status: OutgoingDeliveryStatus,
    ) {
        let peer_str = peer.to_string();
        let me = self.local_peer_id.to_string();
        let mut changed = false;
        {
            let mut messages = self.messages.lock();
            for (thread_key, msgs) in messages.iter_mut() {
                let is_direct = thread_key == &peer_str;
                let is_group = is_group_thread(thread_key);
                if !is_direct && !is_group {
                    continue;
                }
                for msg in msgs.iter_mut() {
                    if msg.id == message_id && msg.sender_id == me {
                        if status == OutgoingDeliveryStatus::Read
                            || (status == OutgoingDeliveryStatus::Delivered
                                && msg.delivery != OutgoingDeliveryStatus::Read)
                        {
                            msg.delivery = status;
                            changed = true;
                        }
                    }
                }
            }
        }
        if changed {
            self.mark_chat_journal_dirty();
        }
    }

    /// Помечает несколько исходящих сообщений как прочитанные собеседником.
    pub(crate) fn mark_outgoing_read(&mut self, peer: PeerId, message_ids: &[String]) {
        let peer_str = peer.to_string();
        let me = self.local_peer_id.to_string();
        let mut changed = false;
        if let Some(msgs) = self.messages.lock().get_mut(&peer_str) {
            for msg in msgs.iter_mut() {
                if message_ids.contains(&msg.id) && msg.sender_id == me {
                    if msg.delivery != OutgoingDeliveryStatus::Read {
                        msg.delivery = OutgoingDeliveryStatus::Read;
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.mark_chat_journal_dirty();
        }
    }

    /// Снимает сообщение из очереди повторной отправки после подтверждения доставки.
    pub(crate) fn complete_pending_send(&mut self, peer: PeerId, message_id: &str) {
        self.pending_sends
            .retain(|p| !(p.peer == peer && p.message_id == message_id));
        self.remove_outbox_direct(&peer.to_string(), message_id);
    }

    /// Восстанавливает очередь недоставленных исходящих из журнала после рестарта.
    pub(crate) fn restore_pending_outgoing(&mut self) {
        let me = self.local_peer_id.to_string();
        let outbox_msg_ids: HashSet<String> = self
            .outbox_entries
            .iter()
            .filter_map(|e| match e {
                OutboxEntry::DirectMessage { message_id, .. }
                | OutboxEntry::GroupMessage { message_id, .. } => Some(message_id.clone()),
                _ => None,
            })
            .collect();
        let snapshot: Vec<(PeerId, ChatMessage)> = {
            let messages = self.messages.lock();
            let mut out = Vec::new();
            for (peer_str, msgs) in messages.iter() {
                let Ok(peer) = peer_str.parse::<PeerId>() else {
                    continue;
                };
                for msg in msgs {
                    if msg.sender_id == me && msg.delivery == OutgoingDeliveryStatus::Pending {
                        if outbox_msg_ids.contains(&msg.id) {
                            continue;
                        }
                        out.push((peer, msg.clone()));
                    }
                }
            }
            out
        };

        let group_snapshot: Vec<(String, ChatMessage)> = {
            let messages = self.messages.lock();
            let mut out = Vec::new();
            for (thread_key, msgs) in messages.iter() {
                let Some(gid) = parse_group_thread_key(thread_key) else {
                    continue;
                };
                for msg in msgs {
                    if msg.sender_id == me
                        && msg.delivery == OutgoingDeliveryStatus::Pending
                        && !msg.text.is_empty()
                        && !outbox_msg_ids.contains(&msg.id)
                    {
                        out.push((gid.to_string(), msg.clone()));
                    }
                }
            }
            out
        };

        for (peer, msg) in snapshot {
            if let Some(voice) = msg.voice.clone() {
                let Some(transfer_id) = transfer_id_from_hex(&voice.transfer_id) else {
                    continue;
                };
                if self
                    .pending_voice_sends
                    .iter()
                    .any(|p| p.message_id == msg.id)
                {
                    continue;
                }
                let Some(path) = self.resolve_voice_path(&voice.transfer_id) else {
                    continue;
                };
                self.pending_voice_sends.push(PendingVoiceSend {
                    peer,
                    path: path.display().to_string(),
                    duration_secs: voice.duration_secs.max(0.1),
                    message_id: msg.id.clone(),
                    transfer_id,
                    last_attempt: Instant::now(),
                });
                let _ = self.command_tx.try_send(UICommand::SendVoiceMessage {
                    sender_name: self.local_nickname.clone(),
                    recipient: peer,
                    path: path.display().to_string(),
                    duration_secs: voice.duration_secs.max(0.1),
                    message_id: msg.id,
                    transfer_id,
                    is_retry: true,
                });
                continue;
            }
            if msg.text.is_empty() {
                continue;
            }
            if self
                .pending_sends
                .iter()
                .any(|p| p.message_id == msg.id)
            {
                continue;
            }
            self.pending_sends.push(PendingSend {
                peer,
                text: msg.text.clone(),
                message_id: msg.id.clone(),
                last_send_at: Instant::now(),
                dht_kicked: false,
                dht_kicked_at: None,
                attempts: 0,
                awaiting_session: false,
            });
            let _ = self.command_tx.try_send(UICommand::SendMessage {
                sender_name: self.local_nickname.clone(),
                text: msg.text,
                recipient: Some(peer),
                message_id: Some(msg.id),
                is_retry: true,
            });
        }

        for (gid, msg) in group_snapshot {
            if self
                .pending_group_sends
                .iter()
                .any(|p| p.message_id == msg.id)
            {
                continue;
            }
            let members = self
                .groups
                .get(&gid)
                .map(|g| g.member_peer_ids())
                .unwrap_or_default();
            let targets: Vec<PeerId> = members
                .iter()
                .copied()
                .filter(|p| *p != self.local_peer_id)
                .collect();
            if targets.is_empty() {
                continue;
            }
            self.pending_group_sends.push(PendingGroupSend {
                group_id: gid.clone(),
                members,
                text: msg.text.clone(),
                message_id: msg.id.clone(),
                last_send_at: Instant::now(),
                attempts: 0,
                delivered_to: HashSet::new(),
            });
            let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                sender_name: self.local_nickname.clone(),
                text: msg.text,
                group_id: gid,
                members: targets,
                message_id: Some(msg.id),
                is_retry: true,
            });
        }
    }

    /// Повторяет недоставленные групповые сообщения при появлении пира в сети.
    pub(crate) fn retry_pending_group_sends_for_peer(&mut self, peer: PeerId) {
        if peer == self.local_peer_id {
            return;
        }
        let due: Vec<PendingGroupSend> = self
            .pending_group_sends
            .iter()
            .filter(|p| p.members.contains(&peer) && !p.delivered_to.contains(&peer))
            .cloned()
            .collect();
        for item in due {
            let targets: Vec<PeerId> = item
                .members
                .iter()
                .copied()
                .filter(|m| *m != self.local_peer_id && !item.delivered_to.contains(m))
                .collect();
            if targets.is_empty() {
                continue;
            }
            let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                sender_name: self.local_nickname.clone(),
                text: item.text.clone(),
                group_id: item.group_id.clone(),
                members: targets,
                message_id: Some(item.message_id.clone()),
                is_retry: true,
            });
        }
    }

    /// Отправляет read receipt для непрочитанных входящих в открытом чате.
    pub(crate) fn flush_read_receipts_for_open_chat(&mut self) {
        if self.selected_chat.is_empty() {
            return;
        }
        let Ok(peer) = self.selected_chat.parse::<PeerId>() else {
            return;
        };
        let peer_str = peer.to_string();
        let me = self.local_peer_id.to_string();
        let unread: Vec<String> = {
            let msgs = self.messages.lock();
            msgs.get(&peer_str)
                .map(|thread| {
                    thread
                        .iter()
                        .filter(|m| m.sender_id != me)
                        .filter(|m| {
                            !self
                                .read_receipts_sent
                                .contains(&(peer_str.clone(), m.id.clone()))
                        })
                        .map(|m| m.id.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        if unread.is_empty() {
            return;
        }
        let _ = self.command_tx.try_send(UICommand::SendReadReceipt {
            peer,
            message_ids: unread,
        });
    }

    pub(crate) fn mark_read_receipts_sent(&mut self, peer: PeerId, message_ids: &[String]) {
        let peer_str = peer.to_string();
        for id in message_ids {
            self.read_receipts_sent
                .insert((peer_str.clone(), id.clone()));
        }
    }

    pub(crate) fn tick_pending_file_sends(&mut self) {
        const RETRY: Duration = Duration::from_secs(10);
        let now = Instant::now();
        let due: Vec<(PeerId, String, file_transfer::FileKind)> = self
            .pending_file_sends
            .iter()
            .filter(|p| now.duration_since(p.last_attempt) >= RETRY)
            .map(|p| (p.peer, p.path.clone(), p.kind))
            .collect();
        for (peer, path, kind) in due {
            if let Some(slot) = self
                .pending_file_sends
                .iter_mut()
                .find(|p| p.peer == peer && p.path == path)
            {
                slot.last_attempt = now;
            }
            let _ = self.command_tx.try_send(UICommand::SendFile {
                recipient: peer,
                path,
                kind,
            });
        }
    }

    pub(crate) fn complete_pending_file_send(&mut self, peer: PeerId, path: &str) {
        self.pending_file_sends
            .retain(|p| !(p.peer == peer && p.path == path));
    }

    pub(crate) fn register_voice_path(&mut self, transfer_id_hex: &str, path: String) {
        if path.trim().is_empty() {
            return;
        }
        let mut p = std::path::PathBuf::from(&path);
        if p.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                p = cwd.join(p);
            }
        }
        if let Ok(abs) = std::fs::canonicalize(&p) {
            p = abs;
        }
        if !p.is_file() {
            return;
        }
        self.voice_audio_paths
            .insert(transfer_id_hex.to_ascii_lowercase(), p.display().to_string());
        crate::voice::voice_log(&format!(
            "registered {} -> {}",
            transfer_id_hex.to_ascii_lowercase(),
            p.display()
        ));
    }

    /// Ищет WAV на диске и привязывает к transfer_id (после приёма или загрузки журнала).
    pub(crate) fn link_voice_file_if_present(&mut self, transfer_id_hex: &str) {
        let tid = transfer_id_hex.to_ascii_lowercase();
        if let Some(p) = self.voice_audio_paths.get(&tid) {
            if std::path::Path::new(p).is_file() {
                return;
            }
            self.voice_audio_paths.remove(&tid);
        }
        if let Some(path) = self.lookup_voice_file_on_disk(&tid) {
            self.register_voice_path(&tid, path.display().to_string());
        }
    }

    fn lookup_voice_file_on_disk(&self, tid: &str) -> Option<std::path::PathBuf> {
        let name = format!("{}{}.wav", file_transfer::VOICE_FILENAME_PREFIX, tid);
        let direct = file_transfer::voice_dir_absolute().join(&name);
        if direct.is_file() {
            return Some(direct);
        }
        let dir = file_transfer::voice_dir_absolute();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let prefix = format!("{}{}", file_transfer::VOICE_FILENAME_PREFIX, tid);
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().into_owned();
                if fname.starts_with(&prefix) && fname.ends_with(".wav") {
                    return Some(entry.path());
                }
            }
        }
        None
    }

    pub(crate) fn relink_voice_messages_in_chat(&mut self, peer_str: &str) {
        let tids: Vec<String> = self
            .messages
            .lock()
            .get(peer_str)
            .map(|msgs| {
                msgs.iter()
                    .filter_map(|m| m.voice.as_ref().map(|v| v.transfer_id.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for tid in tids {
            self.link_voice_file_if_present(&tid);
        }
    }

    pub(crate) fn apply_voice_click(
        &mut self,
        ctx: &egui::Context,
        transfer_id: String,
        toggle: bool,
        seek_ratio: Option<f32>,
    ) {
        if toggle {
            crate::voice::voice_log(&format!("toggle {transfer_id}"));
        } else if let Some(ratio) = seek_ratio {
            crate::voice::voice_log(&format!("seek {transfer_id} at {ratio:.2}"));
        }
        self.link_voice_file_if_present(&transfer_id);
        match self.resolve_voice_path(&transfer_id) {
            Some(path) => {
                if toggle {
                    match self.voice_player.toggle(&transfer_id, &path) {
                        Ok(true) => {
                            self.push_toast(
                                "▶ Воспроизведение…".into(),
                                ToastKind::Info,
                                TOAST_TTL_SHORT,
                            );
                            ctx.request_repaint();
                        }
                        Ok(false) => {
                            self.push_toast(
                                "⏹ Остановлено".into(),
                                ToastKind::Info,
                                TOAST_TTL_SHORT,
                            );
                            ctx.request_repaint();
                        }
                        Err(err) => {
                            self.push_toast(err, ToastKind::Error, TOAST_TTL_LONG);
                        }
                    }
                } else if let Some(ratio) = seek_ratio {
                    if let Err(err) =
                        self.voice_player.play_from(&transfer_id, &path, ratio)
                    {
                        self.push_toast(err, ToastKind::Error, TOAST_TTL_LONG);
                    } else {
                        ctx.request_repaint();
                    }
                }
            }
            None => {
                crate::voice::voice_log(&format!("resolve miss: {transfer_id}"));
                self.push_toast(
                    format!("Аудиофайл не найден ({transfer_id})"),
                    ToastKind::Error,
                    TOAST_TTL_LONG,
                );
            }
        }
    }

    pub(crate) fn resolve_voice_path(&self, transfer_id_hex: &str) -> Option<std::path::PathBuf> {
        let tid = transfer_id_hex.to_ascii_lowercase();
        if let Some(p) = self.voice_audio_paths.get(&tid) {
            let path = std::path::PathBuf::from(p);
            if path.is_file() {
                return Some(path);
            }
        }
        self.lookup_voice_file_on_disk(&tid)
    }

    pub(crate) fn send_voice_message(
        &mut self,
        peer: PeerId,
        path: std::path::PathBuf,
        duration_secs: f32,
    ) -> Result<(), &'static str> {
        let duration_secs = duration_secs.max(0.1);
        let mut tid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut tid);
        let message_id = new_message_id();
        let transfer_hex = transfer_id_to_hex(&tid);
        let voice_name = file_transfer::voice_filename(&tid);
        let local_copy = file_transfer::unique_download_path_in(
            file_transfer::voice_dir_absolute()
                .to_str()
                .unwrap_or(file_transfer::VOICE_DIR),
            &voice_name,
        );
        let path_str = if std::fs::copy(&path, &local_copy).is_ok() {
            local_copy.display().to_string()
        } else {
            path.display().to_string()
        };
        self.register_voice_path(&transfer_hex, path_str.clone());
        self.ingest_chat_message(ChatMessage {
            id: message_id.clone(),
            sender_id: self.local_peer_id.to_string(),
            sender_name: self.local_nickname.clone(),
            recipient_id: Some(peer.to_string()),
            text: String::new(),
            timestamp: chrono::Local::now().format("%H:%M").to_string(),
            delivery: OutgoingDeliveryStatus::Pending,
            voice: Some(VoiceMeta {
                transfer_id: transfer_hex.clone(),
                duration_secs,
            }),
            group_id: None,
        });
        match self.command_tx.try_send(UICommand::SendVoiceMessage {
            sender_name: self.local_nickname.clone(),
            recipient: peer,
            path: path_str.clone(),
            duration_secs,
            message_id: message_id.clone(),
            transfer_id: tid,
            is_retry: false,
        }) {
            Ok(()) => {
                self.pending_voice_sends.push(PendingVoiceSend {
                    peer,
                    path: path_str,
                    duration_secs,
                    message_id: message_id.clone(),
                    transfer_id: tid,
                    last_attempt: Instant::now(),
                });
                Ok(())
            }
            Err(_) => Err("Очередь к сети переполнена"),
        }
    }

    pub(crate) fn complete_pending_voice_send_by_transfer(&mut self, transfer_id: &[u8; 16]) {
        self.pending_voice_sends
            .retain(|p| p.transfer_id != *transfer_id);
    }

    pub(crate) fn tick_pending_voice_sends(&mut self) {
        const RETRY: Duration = Duration::from_secs(3);
        let now = Instant::now();
        let due: Vec<PendingVoiceSend> = self
            .pending_voice_sends
            .iter()
            .filter(|p| now.duration_since(p.last_attempt) >= RETRY)
            .cloned()
            .collect();
        for item in due {
            if !std::path::Path::new(&item.path).exists() {
                continue;
            }
            if let Some(slot) = self.pending_voice_sends.iter_mut().find(|p| {
                p.peer == item.peer && p.message_id == item.message_id
            }) {
                slot.last_attempt = now;
            }
            let _ = self.command_tx.try_send(UICommand::SendVoiceMessage {
                sender_name: self.local_nickname.clone(),
                recipient: item.peer,
                path: item.path,
                duration_secs: item.duration_secs,
                message_id: item.message_id,
                transfer_id: item.transfer_id,
                is_retry: true,
            });
        }
    }

    /// Удаляет сообщения только в локальном диалоге (свои и чужие).
    pub(crate) fn delete_messages(&mut self, peer: PeerId, message_ids: &[String]) {
        if message_ids.is_empty() {
            return;
        }
        let peer_str = peer.to_string();
        if let Some(msgs) = self.messages.lock().get_mut(&peer_str) {
            msgs.retain(|m| !message_ids.contains(&m.id));
        }
        self.mark_chat_journal_dirty();
    }

    pub(crate) fn clear_conversation(&mut self, peer: PeerId) {
        let peer_str = peer.to_string();
        self.delete_conversation_local(peer);
        self.pending_sends.retain(|p| p.peer != peer);
        self.pending_file_sends.retain(|p| p.peer != peer);
        self.pending_voice_sends.retain(|p| p.peer != peer);
        self.read_receipts_sent
            .retain(|(p, _)| p != &peer_str);
    }

    pub(crate) fn delete_conversation_local(&mut self, peer: PeerId) {
        let peer_str = peer.to_string();
        self.messages.lock().remove(&peer_str);
        self.mark_chat_journal_dirty();
    }

    pub(crate) fn merge_learned_bootstraps(&mut self, learned: Vec<String>) {
        let before = self.void_bootstrap_strings.len();
        let merged = merge_bootstrap_string_lists(&self.void_bootstrap_strings, &learned);
        if merged.len() != before {
            self.void_bootstrap_strings = merged;
            self.persist_vault();
            self.add_status(format!(
                "🌐 Vault: {} bootstrap-узл(ов) (+{})",
                self.void_bootstrap_strings.len(),
                self.void_bootstrap_strings.len().saturating_sub(before)
            ));
        }
    }

    pub(crate) fn reload_bootstraps_from_vault(&mut self) {
        let parsed = void_bootstrap_multiaddrs(&self.void_bootstrap_strings);
        let _ = self
            .command_tx
            .try_send(UICommand::ReloadBootstraps(self.void_bootstrap_strings.clone()));
        if parsed.is_empty() && self.void_bootstrap_strings.is_empty() {
            self.add_status(
                "Нет bootstrap в vault — войдите в сеть через IP другой ноды.".into(),
            );
        }
    }

    /// Сохраняет ник и записную книгу в `vault.bin` (AES-GCM под мастер-ключом).
    pub(crate) fn persist_vault(&self) {
        let Some(ref vault_master_key) = self.vault_master_key else {
            return;
        };

        let mut entries: Vec<AddressBookEntry> = self
            .known_peers
            .iter()
            .map(|(pid, name)| {
                let addrs = self
                    .contact_addrs
                    .get(pid)
                    .map(|v| v.iter().map(|a| a.to_string()).collect::<Vec<_>>())
                    .unwrap_or_default();
                AddressBookEntry {
                    peer_id: pid.to_string(),
                    display_name: name.clone(),
                    addrs,
                }
            })
            .collect();
        entries.sort_by(|a, b| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        });
        if let Err(e) = Storage::save(
            vault_master_key,
            &self.local_nickname,
            None,
            None,
            Some(&entries),
            Some(&self.void_bootstrap_strings),
            Some(&self.groups_vec()),
            Some(&self.left_groups_vec()),
        ) {
            warn!("VOID: не удалось сохранить vault (записная книга): {}", e);
        }
    }

    fn groups_vec(&self) -> Vec<GroupChat> {
        let mut v: Vec<GroupChat> = self.groups.values().cloned().collect();
        v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        v
    }

    fn left_groups_vec(&self) -> Vec<String> {
        let mut v: Vec<String> = self.left_groups.iter().cloned().collect();
        v.sort();
        v
    }

    pub(crate) fn is_active_group_member(&self, group_id: &str) -> bool {
        !self.left_groups.contains(group_id)
            && self
                .groups
                .get(group_id)
                .is_some_and(|g| g.includes_peer(&self.local_peer_id))
    }

    pub(crate) fn selected_group_id(&self) -> Option<&str> {
        parse_group_thread_key(&self.selected_chat)
    }

    pub(crate) fn create_group(&mut self, name: String, member_pids: Vec<PeerId>) -> Option<String> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return None;
        }
        let id = group::new_group_id();
        let me = self.local_peer_id.to_string();
        let mut members = vec![GroupMember {
            peer_id: me.clone(),
            display_name: self.local_nickname.clone(),
        }];
        for pid in member_pids {
            if pid == self.local_peer_id {
                continue;
            }
            let display_name = self
                .known_peers
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| format!("Peer {}", &pid.to_string()[..8.min(pid.to_string().len())]));
            members.push(GroupMember {
                peer_id: pid.to_string(),
                display_name,
            });
        }
        let group = GroupChat {
            id: id.clone(),
            name,
            creator_id: me,
            members,
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        };
        if !group::validate_group_chat(&group) {
            return None;
        }
        self.groups.insert(id.clone(), group.clone());
        self.selected_chat = group_thread_key(&id);
        self.messages
            .lock()
            .entry(self.selected_chat.clone())
            .or_default();
        self.persist_vault();
        self.broadcast_group_sync(&group);
        self.dial_group_members(&group);
        for pid in group.member_peer_ids() {
            if pid != self.local_peer_id {
                self.send_group_invite_dm(pid, &group);
            }
        }
        Some(id)
    }

    /// Автоматически вступает в группу, если в тексте есть invite-ссылка.
    pub(crate) fn try_join_groups_from_invite_text(&mut self, text: &str) {
        for link in extract_invite_links(text) {
            let Some(parsed) = parse_invite_link(&link) else {
                continue;
            };
            if self.groups.contains_key(&parsed.id) && !self.left_groups.contains(&parsed.id) {
                continue;
            }
            match self.join_group_from_invite(&link) {
                Ok(()) => {
                    info!("Группа «{}» добавлена из invite", parsed.name);
                    self.push_toast(
                        format!("Группа «{}» добавлена", parsed.name),
                        ToastKind::Info,
                        TOAST_TTL_SHORT,
                    );
                }
                Err(e) => warn!("VOID: invite не принят: {e}"),
            }
        }
    }

    fn send_group_invite_dm(&mut self, peer: PeerId, group: &GroupChat) {
        let link = build_invite_link(group);
        let text = format!(
            "📎 Приглашение в группу «{}»:\n{}",
            group.name, link
        );
        let message_id = new_message_id();
        self.stage_outgoing_message(ChatMessage {
            id: message_id.clone(),
            sender_id: self.local_peer_id.to_string(),
            sender_name: self.local_nickname.clone(),
            recipient_id: Some(peer.to_string()),
            text: text.clone(),
            timestamp: chrono::Local::now().format("%H:%M").to_string(),
            delivery: OutgoingDeliveryStatus::Pending,
            voice: None,
            group_id: None,
        });
        self.outbox_track_direct(peer, message_id.clone(), text.clone());
        self.pending_sends.push(PendingSend {
            peer,
            text: text.clone(),
            message_id: message_id.clone(),
            last_send_at: Instant::now(),
            dht_kicked: false,
            dht_kicked_at: None,
            attempts: 0,
            awaiting_session: false,
        });
        let _ = self.command_tx.try_send(UICommand::SendMessage {
            sender_name: self.local_nickname.clone(),
            text,
            recipient: Some(peer),
            message_id: Some(message_id),
            is_retry: false,
        });
        let _ = self.command_tx.try_send(UICommand::SearchPeer(peer));
    }

    pub(crate) fn join_group_from_invite(&mut self, link: &str) -> Result<(), &'static str> {
        let mut group = parse_invite_link(link).ok_or("Некорректная invite-ссылка")?;
        self.left_groups.remove(&group.id);
        self.ensure_self_in_group(&mut group);
        let thread = group_thread_key(&group.id);
        self.groups.insert(group.id.clone(), group.clone());
        self.selected_chat = thread.clone();
        self.messages.lock().entry(thread).or_default();
        self.dial_group_members(&group);
        self.broadcast_group_sync(&group);
        self.persist_vault();
        Ok(())
    }

    pub(crate) fn add_member_to_selected_group(&mut self, peer: PeerId) -> Result<(), &'static str> {
        if peer == self.local_peer_id {
            return Err("Нельзя добавить себя");
        }
        let group_id = self
            .selected_group_id()
            .ok_or("Выберите групповой чат")?
            .to_string();
        let display_name = self
            .known_peers
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| format!("Peer {}", &peer.to_string()[..8.min(peer.to_string().len())]));
        let group = self.groups.get_mut(&group_id).ok_or("Группа не найдена")?;
        if group.members.iter().any(|m| m.peer_id == peer.to_string()) {
            return Err("Участник уже в группе");
        }
        group.members.push(GroupMember {
            peer_id: peer.to_string(),
            display_name,
        });
        let group = group.clone();
        self.persist_vault();
        self.broadcast_group_sync(&group);
        self.send_group_invite_dm(peer, &group);
        let _ = self.command_tx.try_send(UICommand::SearchPeer(peer));
        Ok(())
    }

    pub(crate) fn leave_selected_group(&mut self) {
        let Some(gid) = self.selected_group_id().map(str::to_string) else {
            return;
        };
        self.leave_group(&gid, true);
    }

    pub(crate) fn delete_selected_group(&mut self) {
        let Some(gid) = self.selected_group_id().map(str::to_string) else {
            return;
        };
        let me = self.local_peer_id.to_string();
        let is_creator = self
            .groups
            .get(&gid)
            .map(|g| g.creator_id == me)
            .unwrap_or(false);
        if is_creator {
            self.dissolve_group(&gid);
        } else {
            self.leave_group(&gid, true);
        }
    }

    fn leave_group(&mut self, gid: &str, clear_chat: bool) {
        let Some(group) = self.groups.get(gid).cloned() else {
            return;
        };
        let me = self.local_peer_id.to_string();
        let notify: Vec<PeerId> = group
            .member_peer_ids()
            .into_iter()
            .filter(|p| *p != self.local_peer_id)
            .collect();

        let mut updated = group.clone();
        updated.members.retain(|m| m.peer_id != me);

        let _ = self.command_tx.try_send(UICommand::SendGroupLeave {
            group_id: gid.to_string(),
            peer_id: me.clone(),
            recipients: notify.clone(),
        });
        if !updated.members.is_empty() {
            self.broadcast_group_sync(&updated);
        }

        self.left_groups.insert(gid.to_string());
        self.groups.remove(gid);
        self.group_synced_peers.clear();
        self.purge_group_outbox(gid);
        self.pending_group_sends
            .retain(|p| p.group_id != gid);

        if clear_chat {
            self.messages.lock().remove(&group_thread_key(gid));
            self.mark_chat_journal_dirty();
        }
        if self.selected_chat == group_thread_key(gid) {
            self.selected_chat.clear();
        }
        self.persist_vault();
    }

    fn dissolve_group(&mut self, gid: &str) {
        let Some(group) = self.groups.get(gid).cloned() else {
            return;
        };
        let notify: Vec<PeerId> = group
            .member_peer_ids()
            .into_iter()
            .filter(|p| *p != self.local_peer_id)
            .collect();
        let _ = self.command_tx.try_send(UICommand::SendGroupDelete {
            group_id: gid.to_string(),
            recipients: notify,
        });

        self.left_groups.insert(gid.to_string());
        self.groups.remove(gid);
        self.group_synced_peers.clear();
        self.purge_group_outbox(gid);
        self.pending_group_sends
            .retain(|p| p.group_id != gid);
        self.messages.lock().remove(&group_thread_key(gid));
        self.mark_chat_journal_dirty();
        if self.selected_chat == group_thread_key(gid) {
            self.selected_chat.clear();
        }
        self.persist_vault();
    }

    fn purge_group_outbox(&mut self, gid: &str) {
        let before = self.outbox_entries.len();
        self.outbox_entries.retain(|e| match e {
            OutboxEntry::GroupMessage { group_id, .. }
            | OutboxEntry::GroupSync { group_id, .. } => group_id != gid,
            _ => true,
        });
        if self.outbox_entries.len() != before {
            self.persist_outbox();
        }
    }

    pub(crate) fn handle_incoming_group_leave(&mut self, group_id: String, peer_id: String) {
        if self.left_groups.contains(&group_id) {
            return;
        }
        let me = self.local_peer_id.to_string();
        if peer_id == me {
            self.left_groups.insert(group_id.clone());
            self.groups.remove(&group_id);
            self.purge_group_outbox(&group_id);
            self.pending_group_sends
                .retain(|p| p.group_id != group_id);
            if self.selected_chat == group_thread_key(&group_id) {
                self.selected_chat.clear();
            }
            self.persist_vault();
            return;
        }
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.members.retain(|m| m.peer_id != peer_id);
            if group.members.is_empty() {
                self.groups.remove(&group_id);
            }
            self.persist_vault();
        }
    }

    pub(crate) fn handle_incoming_group_delete(&mut self, group_id: String) {
        self.left_groups.insert(group_id.clone());
        self.groups.remove(&group_id);
        self.purge_group_outbox(&group_id);
        self.pending_group_sends
            .retain(|p| p.group_id != group_id);
        if self.selected_chat == group_thread_key(&group_id) {
            self.selected_chat.clear();
        }
        self.persist_vault();
        self.mark_chat_journal_dirty();
    }

    pub(crate) fn merge_incoming_group_sync(
        &mut self,
        from: PeerId,
        group_id: String,
        group_name: String,
        creator_id: String,
        members: Vec<GroupMember>,
    ) {
        if self.left_groups.contains(&group_id) {
            return;
        }
        let me = self.local_peer_id.to_string();
        if !members.iter().any(|m| m.peer_id == me) {
            return;
        }
        let creator_id = if creator_id.is_empty() {
            from.to_string()
        } else {
            creator_id
        };
        let mut members = members;
        for m in &mut members {
            if m.display_name.is_empty() {
                m.display_name = m
                    .peer_id
                    .parse::<PeerId>()
                    .ok()
                    .and_then(|pid| self.known_peers.get(&pid).cloned())
                    .unwrap_or_else(|| {
                        let n = m.peer_id.len().min(8);
                        format!("Peer {}", &m.peer_id[..n])
                    });
            }
        }
        let created_at = self
            .groups
            .get(&group_id)
            .map(|g| g.created_at.clone())
            .unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d %H:%M").to_string());
        let group = GroupChat {
            id: group_id.clone(),
            name: group_name,
            creator_id,
            members,
            created_at,
        };
        if group::validate_group_chat(&group) {
            self.groups.insert(group_id, group);
            self.persist_vault();
        } else {
            warn!("VOID: group_sync отклонён (некорректные данные)");
        }
    }

    fn ensure_self_in_group(&self, group: &mut GroupChat) {
        let me = self.local_peer_id.to_string();
        if !group.members.iter().any(|m| m.peer_id == me) {
            group.members.push(GroupMember {
                peer_id: me,
                display_name: self.local_nickname.clone(),
            });
        }
    }

    fn broadcast_group_sync(&mut self, group: &GroupChat) {
        if self.left_groups.contains(&group.id) {
            return;
        }
        let recipients: Vec<PeerId> = group
            .member_peer_ids()
            .into_iter()
            .filter(|p| *p != self.local_peer_id)
            .collect();
        if recipients.is_empty() {
            return;
        }
        for pid in &recipients {
            self.queue_outbox_group_sync(group, *pid);
        }
        let _ = self.command_tx.try_send(UICommand::SendGroupSync {
            group_id: group.id.clone(),
            group_name: group.name.clone(),
            creator_id: group.creator_id.clone(),
            members: group.members.clone(),
            recipients,
        });
    }

    /// Отправляет group_sync пиру при подключении (повторяет при каждом reconnect).
    pub(crate) fn sync_groups_to_peer(&mut self, peer: PeerId) {
        if peer == self.local_peer_id {
            return;
        }
        let peer_str = peer.to_string();
        let group_ids: Vec<String> = self
            .groups
            .values()
            .filter(|g| {
                !self.left_groups.contains(&g.id)
                    && g.members.iter().any(|m| m.peer_id == peer_str)
            })
            .map(|g| g.id.clone())
            .collect();
        for gid in group_ids {
            let Some(group) = self.groups.get(&gid).cloned() else {
                continue;
            };
            self.queue_outbox_group_sync(&group, peer);
            let _ = self.command_tx.try_send(UICommand::SendGroupSync {
                group_id: group.id.clone(),
                group_name: group.name.clone(),
                creator_id: group.creator_id.clone(),
                members: group.members.clone(),
                recipients: vec![peer],
            });
        }
    }

    /// Повторно отправляет outbox-записи конкретному пиру после подключения.
    pub(crate) fn dispatch_outbox_for_peer(&mut self, peer: PeerId) {
        let peer_str = peer.to_string();
        let entries = self.outbox_entries.clone();
        for entry in entries {
            match entry {
                OutboxEntry::DirectMessage {
                    peer: p,
                    message_id,
                    text,
                } if p == peer_str => {
                    if !self
                        .pending_sends
                        .iter()
                        .any(|x| x.message_id == message_id)
                    {
                        self.pending_sends.push(PendingSend {
                            peer,
                            text: text.clone(),
                            message_id: message_id.clone(),
                            last_send_at: Instant::now(),
                            dht_kicked: false,
                            dht_kicked_at: None,
                            attempts: 0,
                            awaiting_session: false,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendMessage {
                        sender_name: self.local_nickname.clone(),
                        text,
                        recipient: Some(peer),
                        message_id: Some(message_id),
                        is_retry: true,
                    });
                }
                OutboxEntry::GroupSync {
                    group_id,
                    group_name,
                    creator_id,
                    members,
                    recipient,
                } if recipient == peer_str => {
                    if self.left_groups.contains(&group_id) {
                        continue;
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupSync {
                        group_id,
                        group_name,
                        creator_id,
                        members,
                        recipients: vec![peer],
                    });
                }
                _ => {}
            }
        }
    }

    pub(crate) fn on_peer_disconnected(&mut self, peer: PeerId) {
        self.group_synced_peers.remove(&peer);
    }

    fn dial_group_members(&mut self, group: &GroupChat) {
        for pid in group.member_peer_ids() {
            if pid == self.local_peer_id {
                continue;
            }
            let _ = self.command_tx.try_send(UICommand::SearchPeer(pid));
        }
    }

    pub(crate) fn invite_link_for_selected_group(&self) -> Option<String> {
        let gid = self.selected_group_id()?;
        let group = self.groups.get(gid)?;
        Some(build_invite_link(group))
    }

    pub(crate) fn mark_group_message_delivered(&mut self, peer: PeerId, message_id: &str) {
        self.set_outgoing_delivery(
            peer,
            message_id,
            OutgoingDeliveryStatus::Delivered,
        );
        let me = self.local_peer_id;
        let mut remove = false;
        if let Some(idx) = self
            .pending_group_sends
            .iter()
            .position(|p| p.message_id == message_id)
        {
            self.pending_group_sends[idx].delivered_to.insert(peer);
            let needed: HashSet<PeerId> = self.pending_group_sends[idx]
                .members
                .iter()
                .copied()
                .filter(|p| *p != me)
                .collect();
            remove = needed.is_subset(&self.pending_group_sends[idx].delivered_to);
        }
        if remove {
            self.pending_group_sends
                .retain(|p| p.message_id != message_id);
            self.remove_outbox_group_message(message_id);
        }
    }

    pub(crate) fn tick_pending_group_sends(&mut self) {
        let now = Instant::now();
        let due: Vec<PendingGroupSend> = self
            .pending_group_sends
            .iter()
            .filter(|p| {
                now.duration_since(p.last_send_at)
                    >= resend_delay_for_attempt(p.attempts)
            })
            .cloned()
            .collect();
        for item in due {
            let targets: Vec<PeerId> = item
                .members
                .iter()
                .copied()
                .filter(|m| *m != self.local_peer_id && !item.delivered_to.contains(m))
                .collect();
            if targets.is_empty() {
                continue;
            }
            if let Some(slot) = self
                .pending_group_sends
                .iter_mut()
                .find(|p| p.message_id == item.message_id)
            {
                slot.last_send_at = now;
                slot.attempts = slot.attempts.saturating_add(1);
            }
            let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                sender_name: self.local_nickname.clone(),
                text: item.text.clone(),
                group_id: item.group_id.clone(),
                members: targets,
                message_id: Some(item.message_id.clone()),
                is_retry: true,
            });
        }
    }

    /// Машина состояний для повторных отправок: `RESEND_GRACE` → DHT-lookup →
    /// повтор с нарастающей задержкой. Очередь держится, пока сообщение не
    /// доставлено или контакт не признан не-VOID.
    pub(crate) fn tick_pending_sends(&mut self) {
        let now = Instant::now();
        let mut search_cmds: Vec<PeerId> = Vec::new();
        let mut resend_cmds: Vec<(PeerId, String, String)> = Vec::new();
        let mut toasts: Vec<(String, ToastKind, Duration)> = Vec::new();

        for p in self.pending_sends.iter_mut() {
            if p.awaiting_session {
                if now.duration_since(p.last_send_at) >= SESSION_WAIT_TIMEOUT {
                    p.awaiting_session = false;
                    p.last_send_at = now
                        .checked_sub(RESEND_GRACE + Duration::from_millis(50))
                        .unwrap_or(now);
                } else {
                    continue;
                }
            }

            // Фаза 1: ждём `RESEND_GRACE` после последней попытки, потом дёргаем DHT.
            if !p.dht_kicked && now.duration_since(p.last_send_at) >= RESEND_GRACE {
                let name_short = format!("{}…", &p.peer.to_string()[..10]);
                toasts.push((
                    format!("⏳ Ищу пира {} через DHT…", name_short),
                    ToastKind::Info,
                    TOAST_TTL_SHORT,
                ));
                search_cmds.push(p.peer);
                p.dht_kicked = true;
                p.dht_kicked_at = Some(now);
            }

            // Фаза 2: после DHT-поиска ждём backoff и шлём повторно.
            if let Some(kicked_at) = p.dht_kicked_at {
                let delay = resend_delay_for_attempt(p.attempts);
                if now.duration_since(kicked_at) >= delay {
                    resend_cmds.push((p.peer, p.text.clone(), p.message_id.clone()));
                    p.attempts = p.attempts.saturating_add(1);
                    p.last_send_at = now;
                    p.dht_kicked = false;
                    p.dht_kicked_at = None;

                    if p.attempts <= 3 || p.attempts.is_multiple_of(6) {
                        let name_short = format!("{}…", &p.peer.to_string()[..10]);
                        toasts.push((
                            format!("↻ Повтор #{} → {}", p.attempts, name_short),
                            ToastKind::Warn,
                            TOAST_TTL_SHORT,
                        ));
                    }
                }
            }
        }

        for (text, kind, ttl) in toasts {
            self.push_toast(text, kind, ttl);
        }
        for peer in search_cmds {
            let _ = self.command_tx.try_send(UICommand::SearchPeer(peer));
        }
        for (peer, text, message_id) in resend_cmds {
            let _ = self.command_tx.try_send(UICommand::SendMessage {
                sender_name: self.local_nickname.clone(),
                text,
                recipient: Some(peer),
                message_id: Some(message_id),
                is_retry: true,
            });
        }
    }

    pub(crate) fn add_status(&mut self, msg: String) {
        let ts = chrono::Local::now().format("%H:%M").to_string();
        self.status_log.push(format!("[{}] {}", ts, msg));
        if self.status_log.len() > 30 {
            self.status_log.remove(0);
        }
    }

    /// Личный чат не выбран, пока пользователь не нажмёт 💬. Если чат пуст — открываем первого пира (mDNS / входящее).
    pub(crate) fn select_peer_if_no_chat(&mut self, peer_id: PeerId) {
        if !self.selected_chat.is_empty() {
            return;
        }
        let s = peer_id.to_string();
        self.selected_chat = s.clone();
        self.messages.lock().entry(s).or_default();
        self.add_status(format!(
            "Открыт чат с {} — можно отправлять сообщения.",
            &peer_id.to_string()[..8]
        ));
    }

}

fn outbox_same_slot(a: &OutboxEntry, b: &OutboxEntry) -> bool {
    match (a, b) {
        (
            OutboxEntry::DirectMessage {
                peer: p1,
                message_id: id1,
                ..
            },
            OutboxEntry::DirectMessage {
                peer: p2,
                message_id: id2,
                ..
            },
        ) => p1 == p2 && id1 == id2,
        (
            OutboxEntry::GroupMessage {
                message_id: id1, ..
            },
            OutboxEntry::GroupMessage {
                message_id: id2, ..
            },
        ) => id1 == id2,
        (
            OutboxEntry::GroupSync {
                group_id: g1,
                recipient: r1,
                ..
            },
            OutboxEntry::GroupSync {
                group_id: g2,
                recipient: r2,
                ..
            },
        ) => g1 == g2 && r1 == r2,
        _ => false,
    }
}
