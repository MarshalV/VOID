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
    self, build_invite_link, dedupe_members, extract_invite_links, group_thread_key,
    is_group_thread, parse_group_thread_key, parse_invite_link, GroupChat, GroupMember,
};
use crate::network::{run_chat_network, NetworkEvent, OfflineOutboxItem, UICommand};
use crate::offline_mail::{
    assemble_voice_chunks, decode_voice_chunk_payload, open_envelope, split_voice_for_offline,
    OfflineEnvelope, OFFLINE_VOICE_CHUNK_KIND,
};
use crate::outbox::{Outbox, OutboxEntry};
use crate::protocol::{
    build_group_sync_json, new_message_id, parse_decrypted_chat_frame,
    per_peer_voice_transfer_id, transfer_id_from_hex, transfer_id_to_hex, ChatMessage,
    DecryptedChatFrame, FileTransferProgress, OutgoingDeliveryStatus, VoiceMeta,
};
use crate::ui::{setup_custom_style, Toast, ToastKind, TOAST_TTL_LONG, TOAST_TTL_SHORT};
use crate::vault::{
    clear_remembered_password, save_remembered_password, AddressBookEntry, Storage,
    VaultUnlockKind, VaultUnlockState,
};
use crate::voice::{VoicePlayer, VoiceRecorder};

/// Ограниченный по размеру набор id удалённых сообщений («надгробия»). Без
/// него ретраи/offline-мейлбокс/повторная доставка от собеседника воскрешают
/// уже удалённое локально сообщение — `ingest_chat_message` дедуплицирует
/// только по присутствию в текущем списке, а после удаления его там уже нет.
#[derive(Default)]
struct DeletedTombstones {
    order: std::collections::VecDeque<String>,
    set: HashSet<String>,
}

impl DeletedTombstones {
    const MAX: usize = 20_000;

    fn insert(&mut self, id: String) {
        if id.is_empty() {
            return;
        }
        if self.set.insert(id.clone()) {
            self.order.push_back(id);
            while self.order.len() > Self::MAX {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }

    fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    fn from_vec(ids: Vec<String>) -> Self {
        let mut t = Self::default();
        for id in ids {
            t.insert(id);
        }
        t
    }

    fn to_vec(&self) -> Vec<String> {
        self.order.iter().cloned().collect()
    }
}

/// Переписки, доступные и UI, и сетевому таску (входящее удаление без roundtrip через egui).
#[derive(Clone)]
pub(crate) struct SharedChatMessages {
    inner: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    deleted: Arc<Mutex<DeletedTombstones>>,
    journal_dirty: Arc<AtomicBool>,
}

impl SharedChatMessages {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            deleted: Arc::new(Mutex::new(DeletedTombstones::default())),
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

    /// Помечает id как удалённые — `ingest_chat_message` больше не даст им
    /// снова попасть в чат (ретрай, offline-мейлбокс, повтор от собеседника).
    pub(crate) fn mark_deleted<I: IntoIterator<Item = String>>(&self, ids: I) {
        let mut t = self
            .deleted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for id in ids {
            t.insert(id);
        }
    }

    pub(crate) fn is_deleted(&self, id: &str) -> bool {
        self.deleted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(id)
    }

    pub(crate) fn deleted_snapshot(&self) -> Vec<String> {
        self.deleted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .to_vec()
    }

    /// Восстанавливает надгробия из журнала при старте приложения.
    pub(crate) fn load_deleted(&self, ids: Vec<String>) {
        let mut t = self
            .deleted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *t = DeletedTombstones::from_vec(ids);
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
                self.mark_deleted(deleted.iter().cloned());
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

/// Голосовое сообщение в очереди до E2EE-сессии / живой file-transfer.
/// Само сообщение уже в чате (как у текста): живой VoiceAck только обновляет
/// статус доставки; офлайн-доставка аудио идёт через outbox → voice_chunk.
#[derive(Clone)]
pub(crate) struct PendingVoiceSend {
    pub(crate) peer: PeerId,
    pub(crate) path: String,
    pub(crate) duration_secs: f32,
    pub(crate) message_id: String,
    pub(crate) transfer_id: [u8; 16],
    pub(crate) last_attempt: Instant,
    /// Сохраняем для восстановления UI/журнала при ретраях.
    #[allow(dead_code)]
    pub(crate) chat_message: ChatMessage,
}

/// Сборка WAV из офлайн-чанков (`voice_chunk`), пока не пришли все куски.
struct OfflineVoiceAssembly {
    total: u32,
    total_size: u32,
    chunks: HashMap<u32, Vec<u8>>,
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
    /// Подтверждённые доставки метаданных (по одному на каждого участника, кроме себя).
    pub(crate) delivered_to: HashSet<PeerId>,
    /// Подтверждённая доставка WAV-файла (для голосовых в группе).
    pub(crate) voice_delivered_to: HashSet<PeerId>,
    /// Голосовое: локальный WAV и base transfer_id (в UI один id на всю группу).
    pub(crate) voice_path: Option<String>,
    pub(crate) voice_duration_secs: f32,
    pub(crate) voice_transfer_id: Option<[u8; 16]>,
    /// Для голосовых: сообщение уже показано отправителю сразу (как текст);
    /// флаг `voice_shown` остаётся для совместимости с живым VoiceAck-путём.
    pub(crate) chat_message: Option<ChatMessage>,
    /// `true` — голосовое уже в чате отправителя.
    pub(crate) voice_shown: bool,
}

pub(crate) const RESEND_GRACE: Duration = Duration::from_secs(1);
/// Базовая задержка перед повтором после DHT-поиска (растёт с числом попыток).
pub(crate) const RESEND_DELAY_BASE: Duration = Duration::from_secs(2);
pub(crate) const RESEND_DELAY_MAX: Duration = Duration::from_secs(300);
/// Сколько ждём E2EE-хендшейк, прежде чем снова разрешить DHT-ретрай.
pub(crate) const SESSION_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
/// Журнал переписок пишем на диск не чаще этого интервала (не блокируем отправку).
pub(crate) const JOURNAL_PERSIST_DEBOUNCE: Duration = Duration::from_secs(2);
pub(crate) const OFFLINE_DHT_PUBLISH_DEBOUNCE: Duration = Duration::from_millis(200);

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
    /// Входящие голосовые, JSON которых уже пришёл, но файл ещё не на диске —
    /// в чат не показываем, пока WAV не собран (живой transfer или offline chunks).
    pub(crate) pending_incoming_voice: Vec<ChatMessage>,
    /// Файл пришёл и проверен раньше самого JSON-сообщения (переупорядочивание
    /// сети) — показываем сообщение немедленно, как только оно прилетит.
    pub(crate) pending_incoming_voice_ready: HashSet<String>,
    /// Сборка офлайн voice_chunk по transfer_id (hex).
    pending_offline_voice: HashMap<String, OfflineVoiceAssembly>,
    /// Групповые чаты (id → метаданные).
    pub(crate) groups: HashMap<String, GroupChat>,
    /// Группы, из которых вышли — не показывать и не принимать новые сообщения.
    pub(crate) left_groups: HashSet<String>,
    pub(crate) show_create_group: bool,
    pub(crate) create_group_name: String,
    pub(crate) create_group_pick: HashSet<PeerId>,
    pub(crate) join_group_link: String,
    /// Invite-ссылка, по которой нужно вступить (ставится из UI, обрабатывается в update).
    pub(crate) pending_invite_join: Option<String>,
    pub(crate) show_group_panel: bool,
    pub(crate) add_group_member_peer: String,
    /// Недоставленное: быстрый `outbox.bin` (переживает выход из приложения).
    pub(crate) outbox_entries: Vec<OutboxEntry>,
    /// X25519 prekey контактов (для DHT офлайн-почты).
    pub(crate) peer_prekeys: HashMap<PeerId, [u8; 32]>,
    offline_dht_publish_after: Option<Instant>,
    offline_mail_processed: HashSet<String>,
    /// Пиры, которым уже отправили group_sync в этой сессии (до disconnect).
    pub(crate) group_synced_peers: HashSet<PeerId>,
    /// Пиры, покинувшие группу (не возвращать через устаревший group_sync).
    pub(crate) group_departed_peers: HashMap<String, HashSet<String>>,
    /// Сообщения, по которым уже обработан auto-join по invite (не повторять).
    invite_join_processed: HashSet<String>,
    journal_persist_after: Option<Instant>,
    /// Выход уже обработан (не повторять сохранение / flush).
    exit_prepared: bool,
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
            pending_incoming_voice: Vec::new(),
            pending_incoming_voice_ready: HashSet::new(),
            pending_offline_voice: HashMap::new(),
            groups: initial_groups,
            left_groups: initial_left_groups,
            show_create_group: false,
            create_group_name: String::new(),
            create_group_pick: HashSet::new(),
            join_group_link: String::new(),
            pending_invite_join: None,
            show_group_panel: false,
            add_group_member_peer: String::new(),
            outbox_entries: Vec::new(),
            peer_prekeys: HashMap::new(),
            offline_dht_publish_after: None,
            offline_mail_processed: HashSet::new(),
            group_synced_peers: HashSet::new(),
            group_departed_peers: HashMap::new(),
            invite_join_processed: HashSet::new(),
            journal_persist_after: None,
            exit_prepared: false,
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
                let mut peer_prekeys = HashMap::new();
                for entry in storage.address_book {
                    if let Ok(pid) = entry.peer_id.parse::<PeerId>() {
                        if pid != my_id {
                            book.insert(pid, entry.display_name);
                            if let Some(pk) = entry.x25519_public {
                                peer_prekeys.insert(pid, pk);
                            }
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
                self.peer_prekeys = peer_prekeys;
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
            Ok((loaded, deleted_ids)) => {
                *self.messages.lock() = loaded;
                self.messages.load_deleted(deleted_ids);
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
        self.prune_auto_discovered_contacts();
        self.refresh_outbox_group_sync_snapshots();
        // Не авто-вступаем по старым invite в журнале — только кнопка/вставка ссылки.
        // self.scan_chat_journal_for_group_invites();
        self.index_voice_files_on_disk();
        self.relink_all_voice_files();
        self.dispatch_outbox();
        self.bootstrap_offline_mail();

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
        let deleted_ids = self.messages.deleted_snapshot();
        if let Err(e) = ChatJournal::save(vault_master_key, &*self.messages.lock(), &deleted_ids) {
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

    pub(crate) fn persist_all_before_exit(&mut self) {
        if self.exit_prepared {
            self.persist_chat_journal();
            self.persist_outbox();
            return;
        }
        self.exit_prepared = true;
        self.persist_chat_journal();
        self.persist_outbox();
        // Ждём handoff (см. flush_outbox_to_dht_on_exit): текст ~8с, голос до 30с.
        self.flush_outbox_to_dht_on_exit();
    }

    fn bootstrap_offline_mail(&mut self) {
        let keys: Vec<(PeerId, [u8; 32])> = self
            .peer_prekeys
            .iter()
            .map(|(p, k)| (*p, *k))
            .collect();
        if !keys.is_empty() {
            let _ = self.command_tx.try_send(UICommand::CachePeerPrekeys(keys));
        }
        self.schedule_offline_dht_publish();
        let _ = self.command_tx.try_send(UICommand::FetchOfflineMailbox);
    }

    pub(crate) fn cache_peer_prekey(&mut self, peer: PeerId, public_key: [u8; 32]) {
        if self.peer_prekeys.get(&peer) != Some(&public_key) {
            self.peer_prekeys.insert(peer, public_key);
            self.persist_vault();
            self.accelerate_offline_dht_publish();
        }
    }

    fn schedule_offline_dht_publish(&mut self) {
        if self.outbox_entries.is_empty() {
            return;
        }
        self.offline_dht_publish_after =
            Some(Instant::now() + OFFLINE_DHT_PUBLISH_DEBOUNCE);
    }

    pub(crate) fn accelerate_offline_dht_publish(&mut self) {
        if !self.outbox_entries.is_empty() {
            self.offline_dht_publish_after = Some(Instant::now());
        }
    }

    pub(crate) fn tick_offline_dht_publish(&mut self) {
        if let Some(deadline) = self.offline_dht_publish_after {
            if Instant::now() >= deadline {
                self.offline_dht_publish_after = None;
                self.publish_outbox_to_dht();
            }
        }
    }

    /// Неблокирующая публикация outbox в DHT/relay (из UI-потока).
    pub(crate) fn publish_outbox_to_dht(&self) {
        let items = self.build_offline_publish_items();
        if items.is_empty() {
            return;
        }
        if let Err(e) = self.command_tx.try_send(UICommand::PublishOfflineOutbox {
            items,
            ack: None,
        }) {
            warn!("VOID: PublishOfflineOutbox не встал в очередь: {e}");
        }
    }

    /// При выходе: публикуем outbox в relay/DHT и ждём durable handoff.
    /// Голосовые = много Store Ack (по чанку) + возможный dial bootstrap — 6с мало.
    fn flush_outbox_to_dht_on_exit(&self) {
        let items = self.build_offline_publish_items();
        if items.is_empty() {
            return;
        }
        let n = items.len();
        let has_voice = items
            .iter()
            .any(|i| i.kind == OFFLINE_VOICE_CHUNK_KIND || i.message_id.starts_with("vchunk:"));
        // Текст/инвайт: несколько секунд. Голос: чанки по одному RR + dial.
        let wait = if has_voice {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(8)
        };
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        match self.command_tx.blocking_send(UICommand::PublishOfflineOutbox {
            items,
            ack: Some(ack_tx),
        }) {
            Ok(()) => match ack_rx.recv_timeout(wait) {
                Ok(true) => info!("VOID: exit — outbox ({n}) сдан в relay/DHT"),
                Ok(false) => warn!(
                    "VOID: exit — handoff outbox ({n}) не подтверждён, останется в outbox.bin"
                ),
                Err(_) => warn!(
                    "VOID: exit — timeout {}s ожидания handoff outbox ({n}), останется в outbox.bin",
                    wait.as_secs()
                ),
            },
            Err(e) => warn!(
                "VOID: exit — сеть не приняла outbox ({e}), останется в outbox.bin"
            ),
        }
    }

    fn build_offline_publish_items(&self) -> Vec<OfflineOutboxItem> {
        let me = self.local_peer_id;
        let mut items = Vec::new();
        for entry in &self.outbox_entries {
            match entry {
                OutboxEntry::DirectMessage {
                    peer,
                    message_id,
                    text,
                } => {
                    let Ok(recipient) = peer.parse::<PeerId>() else {
                        continue;
                    };
                    let msg = ChatMessage {
                        id: message_id.clone(),
                        sender_id: me.to_string(),
                        sender_name: self.local_nickname.clone(),
                        recipient_id: Some(peer.clone()),
                        text: text.clone(),
                        timestamp: chrono::Local::now().format("%H:%M").to_string(),
                        delivery: OutgoingDeliveryStatus::Pending,
                        voice: None,
                        group_id: None,
                    };
                    if let Ok(payload) = serde_json::to_vec(&msg) {
                        items.push(OfflineOutboxItem {
                            recipient,
                            message_id: message_id.clone(),
                            kind: "dm".into(),
                            payload,
                        });
                    }
                }
                OutboxEntry::DirectVoice {
                    peer,
                    message_id,
                    transfer_id,
                    duration_secs,
                    voice_path,
                } => {
                    let Ok(recipient) = peer.parse::<PeerId>() else {
                        continue;
                    };
                    let Some(tid) = transfer_id_from_hex(transfer_id) else {
                        continue;
                    };
                    // Без чанков не публикуем «пустой» voice-meta — иначе у
                    // получателя пузырь без аудио.
                    let before = items.len();
                    if !Self::push_offline_voice_chunks(&mut items, recipient, &tid, voice_path) {
                        warn!(
                            "VOID: offline voice без чанков ({transfer_id}) — пропуск meta"
                        );
                        continue;
                    }
                    let _ = before;
                    let msg = ChatMessage {
                        id: message_id.clone(),
                        sender_id: me.to_string(),
                        sender_name: self.local_nickname.clone(),
                        recipient_id: Some(peer.clone()),
                        text: String::new(),
                        timestamp: chrono::Local::now().format("%H:%M").to_string(),
                        delivery: OutgoingDeliveryStatus::Pending,
                        voice: Some(VoiceMeta {
                            transfer_id: transfer_id.clone(),
                            duration_secs: *duration_secs,
                        }),
                        group_id: None,
                    };
                    if let Ok(payload) = serde_json::to_vec(&msg) {
                        items.push(OfflineOutboxItem {
                            recipient,
                            message_id: message_id.clone(),
                            kind: "dm".into(),
                            payload,
                        });
                    }
                }
                OutboxEntry::GroupMessage {
                    group_id,
                    message_id,
                    text,
                    members,
                } => {
                    for peer_str in members {
                        let Ok(recipient) = peer_str.parse::<PeerId>() else {
                            continue;
                        };
                        if recipient == me {
                            continue;
                        }
                        let msg = ChatMessage {
                            id: message_id.clone(),
                            sender_id: me.to_string(),
                            sender_name: self.local_nickname.clone(),
                            recipient_id: None,
                            text: text.clone(),
                            timestamp: chrono::Local::now().format("%H:%M").to_string(),
                            delivery: OutgoingDeliveryStatus::Pending,
                            voice: None,
                            group_id: Some(group_id.clone()),
                        };
                        if let Ok(payload) = serde_json::to_vec(&msg) {
                            items.push(OfflineOutboxItem {
                                recipient,
                                message_id: format!("{}:{}", message_id, peer_str),
                                kind: "group".into(),
                                payload,
                            });
                        }
                    }
                }
                OutboxEntry::GroupVoice {
                    group_id,
                    message_id,
                    transfer_id,
                    duration_secs,
                    voice_path,
                    members,
                } => {
                    for peer_str in members {
                        let Ok(recipient) = peer_str.parse::<PeerId>() else {
                            continue;
                        };
                        if recipient == me {
                            continue;
                        }
                        let base_tid = transfer_id_from_hex(transfer_id).unwrap_or([0u8; 16]);
                        let peer_tid = per_peer_voice_transfer_id(&base_tid, recipient);
                        if !Self::push_offline_voice_chunks(
                            &mut items,
                            recipient,
                            &peer_tid,
                            voice_path,
                        ) {
                            warn!(
                                "VOID: group offline voice без чанков ({transfer_id}) — пропуск"
                            );
                            continue;
                        }
                        let msg = ChatMessage {
                            id: message_id.clone(),
                            sender_id: me.to_string(),
                            sender_name: self.local_nickname.clone(),
                            recipient_id: None,
                            text: String::new(),
                            timestamp: chrono::Local::now().format("%H:%M").to_string(),
                            delivery: OutgoingDeliveryStatus::Pending,
                            voice: Some(VoiceMeta {
                                transfer_id: transfer_id_to_hex(&peer_tid),
                                duration_secs: *duration_secs,
                            }),
                            group_id: Some(group_id.clone()),
                        };
                        if let Ok(payload) = serde_json::to_vec(&msg) {
                            items.push(OfflineOutboxItem {
                                recipient,
                                message_id: format!("{}:{}", message_id, peer_str),
                                kind: "group".into(),
                                payload,
                            });
                        }
                    }
                }
                OutboxEntry::GroupSync {
                    group_id,
                    group_name,
                    creator_id,
                    members,
                    recipient,
                } => {
                    let Ok(pid) = recipient.parse::<PeerId>() else {
                        continue;
                    };
                    if let Some(payload) = build_group_sync_json(
                        group_id,
                        group_name,
                        creator_id,
                        members,
                    ) {
                        items.push(OfflineOutboxItem {
                            recipient: pid,
                            message_id: format!("gsync:{}:{}", group_id, recipient),
                            kind: "group_sync".into(),
                            payload,
                        });
                    }
                }
            }
        }
        items
    }

    /// Кладёт куски WAV в offline-очередь. `false` = файла нет/слишком большой.
    fn push_offline_voice_chunks(
        items: &mut Vec<OfflineOutboxItem>,
        recipient: PeerId,
        transfer_id: &[u8; 16],
        voice_path: &str,
    ) -> bool {
        let Ok(bytes) = std::fs::read(voice_path) else {
            crate::voice::voice_log(&format!(
                "offline voice: не прочитать {} для {}",
                voice_path,
                transfer_id_to_hex(transfer_id)
            ));
            return false;
        };
        let Some(chunks) = split_voice_for_offline(transfer_id, &bytes) else {
            crate::voice::voice_log(&format!(
                "offline voice: слишком большой/пустой {} ({})",
                transfer_id_to_hex(transfer_id),
                bytes.len()
            ));
            return false;
        };
        let tid_hex = transfer_id_to_hex(transfer_id);
        for (i, payload) in chunks.into_iter().enumerate() {
            items.push(OfflineOutboxItem {
                recipient,
                message_id: format!("vchunk:{tid_hex}:{i}"),
                kind: OFFLINE_VOICE_CHUNK_KIND.into(),
                payload,
            });
        }
        true
    }

    pub(crate) fn ingest_offline_mailbox(&mut self, envelopes: Vec<OfflineEnvelope>) {
        if envelopes.is_empty() {
            return;
        }
        let mut any = false;
        let mut decrypt_failed = 0u32;
        for env in envelopes {
            if self.offline_mail_processed.contains(&env.message_id) {
                continue;
            }
            let plaintext = match open_envelope(&self._local_static, &env) {
                Ok(p) => p,
                Err(_) => {
                    decrypt_failed += 1;
                    continue;
                }
            };
            match env.kind.as_str() {
                "dm" => {
                    if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                        self.ingest_offline_chat_with_voice(msg);
                        self.offline_mail_processed.insert(env.message_id.clone());
                        any = true;
                    }
                }
                "group" => {
                    if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                        self.ingest_offline_chat_with_voice(msg);
                        self.offline_mail_processed.insert(env.message_id.clone());
                        any = true;
                    }
                }
                k if k == OFFLINE_VOICE_CHUNK_KIND => {
                    if self.ingest_offline_voice_chunk(&plaintext) {
                        self.offline_mail_processed.insert(env.message_id.clone());
                        any = true;
                    }
                }
                "group_sync" => {
                    if let Some(DecryptedChatFrame::GroupSync {
                        group_id,
                        group_name,
                        creator_id,
                        members,
                    }) = parse_decrypted_chat_frame(&plaintext)
                    {
                        if let Some(from) = env.sender.parse::<PeerId>().ok() {
                            self.merge_incoming_group_sync(
                                from,
                                group_id,
                                group_name,
                                creator_id,
                                members,
                            );
                        }
                        self.offline_mail_processed.insert(env.message_id.clone());
                        any = true;
                    }
                }
                _ => {}
            }
        }
        if any {
            self.persist_vault();
            self.mark_chat_journal_dirty();
            // НЕ чистим DHT-ящик здесь: take_batch отдаёт порциями, а Clear
            // убивал оставшийся текст/чанки, которые ещё не пришли с relay/DHT.
            // Дедуп по message_id защищает от повторов.
            self.add_status("📬 Получена офлайн-почта".into());
        } else if decrypt_failed > 0 {
            self.add_status(format!(
                "⚠ {decrypt_failed} офлайн-конвертов не удалось расшифровать"
            ));
        }
    }

    /// Офлайн DM/group: голосовое в чат только когда WAV уже на диске (как live).
    fn ingest_offline_chat_with_voice(&mut self, msg: ChatMessage) {
        if let Some(ref voice) = msg.voice {
            let tid = voice.transfer_id.to_ascii_lowercase();
            self.link_voice_file_if_present(&tid);
            if self.resolve_voice_path(&tid).is_some()
                || self.pending_incoming_voice_ready.contains(&tid)
            {
                self.ingest_chat_message(msg.clone());
                if !msg.text.is_empty() {
                    self.try_process_invite_message(&msg.id, &msg.text);
                }
            } else if !self.pending_incoming_voice.iter().any(|m| m.id == msg.id) {
                self.pending_incoming_voice.push(msg);
            }
        } else {
            self.ingest_chat_message(msg.clone());
            if !msg.text.is_empty() {
                self.try_process_invite_message(&msg.id, &msg.text);
            }
        }
    }

    /// Принимает один `voice_chunk`; при полной сборке пишет WAV и открывает
    /// отложенные голосовые сообщения с этим transfer_id.
    fn ingest_offline_voice_chunk(&mut self, plaintext: &[u8]) -> bool {
        let Some(chunk) = decode_voice_chunk_payload(plaintext) else {
            return false;
        };
        let tid_hex = transfer_id_to_hex(&chunk.transfer_id);
        if self.resolve_voice_path(&tid_hex).is_some() {
            return true;
        }
        let entry = self
            .pending_offline_voice
            .entry(tid_hex.clone())
            .or_insert_with(|| OfflineVoiceAssembly {
                total: chunk.total,
                total_size: chunk.total_size,
                chunks: HashMap::new(),
            });
        if entry.total != chunk.total || entry.total_size != chunk.total_size {
            crate::voice::voice_log(&format!(
                "offline voice_chunk: конфликт метаданных {tid_hex}"
            ));
            return false;
        }
        entry.chunks.insert(chunk.index, chunk.data);
        let have = entry.chunks.len();
        let need = entry.total as usize;
        if have < need {
            return true;
        }
        let Some(wav) =
            assemble_voice_chunks(entry.total, entry.total_size, &entry.chunks)
        else {
            crate::voice::voice_log(&format!(
                "offline voice_chunk: не собрался {tid_hex} ({have}/{need})"
            ));
            return false;
        };
        self.pending_offline_voice.remove(&tid_hex);
        let tid = chunk.transfer_id;
        let dir = file_transfer::voice_dir_absolute();
        let dest = dir.join(file_transfer::voice_filename(&tid));
        if let Err(e) = std::fs::write(&dest, &wav) {
            crate::voice::voice_log(&format!(
                "offline voice: запись {}: {e}",
                dest.display()
            ));
            return false;
        }
        self.register_voice_path(&tid_hex, dest.display().to_string());
        self.pending_incoming_voice_ready.insert(tid_hex.clone());
        crate::voice::voice_log(&format!(
            "offline voice assembled {tid_hex} → {} ({} байт)",
            dest.display(),
            wav.len()
        ));
        self.promote_pending_incoming_voice(&tid_hex);
        true
    }

    fn promote_pending_incoming_voice(&mut self, transfer_id_hex: &str) {
        let tid = transfer_id_hex.to_ascii_lowercase();
        let ready: Vec<ChatMessage> = self
            .pending_incoming_voice
            .iter()
            .filter(|m| {
                m.voice
                    .as_ref()
                    .is_some_and(|v| v.transfer_id.eq_ignore_ascii_case(&tid))
            })
            .cloned()
            .collect();
        self.pending_incoming_voice.retain(|m| {
            !m.voice
                .as_ref()
                .is_some_and(|v| v.transfer_id.eq_ignore_ascii_case(&tid))
        });
        for msg in ready {
            self.ingest_chat_message(msg.clone());
            if !msg.text.is_empty() {
                self.try_process_invite_message(&msg.id, &msg.text);
            }
        }
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
        self.accelerate_offline_dht_publish();
    }

    fn remove_outbox_direct(&mut self, peer: &str, message_id: &str) {
        let before = self.outbox_entries.len();
        self.outbox_entries.retain(|e| {
            !matches!(
                e,
                OutboxEntry::DirectMessage { peer: p, message_id: id, .. }
                    | OutboxEntry::DirectVoice { peer: p, message_id: id, .. }
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
                OutboxEntry::GroupMessage { message_id: id, .. }
                    | OutboxEntry::GroupVoice { message_id: id, .. }
                    if id == message_id
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

    pub(crate) fn outbox_track_direct_voice(
        &mut self,
        peer: PeerId,
        message_id: String,
        transfer_id: String,
        duration_secs: f32,
        voice_path: String,
    ) {
        self.push_outbox(OutboxEntry::DirectVoice {
            peer: peer.to_string(),
            message_id,
            transfer_id,
            duration_secs,
            voice_path,
        });
    }

    pub(crate) fn outbox_track_group_voice(
        &mut self,
        group_id: String,
        message_id: String,
        transfer_id: String,
        duration_secs: f32,
        voice_path: String,
        members: Vec<PeerId>,
    ) {
        self.push_outbox(OutboxEntry::GroupVoice {
            group_id,
            message_id,
            transfer_id,
            duration_secs,
            voice_path,
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
                OutboxEntry::DirectVoice {
                    peer,
                    message_id,
                    transfer_id,
                    duration_secs,
                    voice_path,
                } => {
                    let Ok(pid) = peer.parse::<PeerId>() else {
                        continue;
                    };
                    let Some(tid) = transfer_id_from_hex(&transfer_id) else {
                        continue;
                    };
                    if !std::path::Path::new(&voice_path).is_file() {
                        self.add_status(format!(
                            "⚠ Голосовое {}: файл не найден, удалено из outbox ({})",
                            &message_id[..8.min(message_id.len())],
                            voice_path
                        ));
                        self.outbox_entries.retain(|e| !matches!(
                            e,
                            OutboxEntry::DirectVoice { message_id: id, .. } if id == &message_id
                        ));
                        self.persist_outbox();
                        continue;
                    }
                    if !self.pending_voice_sends.iter().any(|p| p.message_id == message_id) {
                        let chat_message = self.build_voice_chat_message(
                            &message_id,
                            Some(peer.clone()),
                            None,
                            &transfer_id,
                            duration_secs,
                        );
                        self.pending_voice_sends.push(PendingVoiceSend {
                            peer: pid,
                            path: voice_path.clone(),
                            duration_secs,
                            message_id: message_id.clone(),
                            transfer_id: tid,
                            last_attempt: Instant::now(),
                            chat_message,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendVoiceMessage {
                        sender_name: self.local_nickname.clone(),
                        recipient: pid,
                        path: voice_path,
                        duration_secs,
                        message_id,
                        transfer_id: tid,
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
                            voice_delivered_to: HashSet::new(),
                            voice_path: None,
                            voice_duration_secs: 0.0,
                            voice_transfer_id: None,
                            chat_message: None,
                            voice_shown: false,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                        sender_name: self.local_nickname.clone(),
                        text,
                        group_id,
                        members: targets,
                        message_id: Some(message_id),
                        is_retry: true,
                        voice_path: None,
                        voice_duration_secs: 0.0,
                        voice_transfer_id: None,
                        voice_only_members: vec![],
                    });
                }
                OutboxEntry::GroupVoice {
                    group_id,
                    message_id,
                    transfer_id,
                    duration_secs,
                    voice_path,
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
                    if !std::path::Path::new(&voice_path).is_file() {
                        self.add_status(format!(
                            "⚠ Групповое голосовое {}: файл не найден, удалено из outbox ({})",
                            &message_id[..8.min(message_id.len())],
                            voice_path
                        ));
                        self.outbox_entries.retain(|e| !matches!(
                            e,
                            OutboxEntry::GroupVoice { message_id: id, .. } if id == &message_id
                        ));
                        self.persist_outbox();
                        continue;
                    }
                    let Some(tid) = transfer_id_from_hex(&transfer_id) else {
                        continue;
                    };
                    if !self
                        .pending_group_sends
                        .iter()
                        .any(|p| p.message_id == message_id)
                    {
                        let chat_message = self.build_voice_chat_message(
                            &message_id,
                            None,
                            Some(group_id.clone()),
                            &transfer_id,
                            duration_secs,
                        );
                        self.pending_group_sends.push(PendingGroupSend {
                            group_id: group_id.clone(),
                            members: member_pids,
                            text: String::new(),
                            message_id: message_id.clone(),
                            last_send_at: Instant::now(),
                            attempts: 0,
                            delivered_to: HashSet::new(),
                            voice_delivered_to: HashSet::new(),
                            voice_path: Some(voice_path.clone()),
                            voice_duration_secs: duration_secs,
                            voice_transfer_id: Some(tid),
                            chat_message: Some(chat_message),
                            voice_shown: false,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                        sender_name: self.local_nickname.clone(),
                        text: String::new(),
                        group_id,
                        members: targets,
                        message_id: Some(message_id),
                        is_retry: true,
                        voice_path: Some(voice_path),
                        voice_duration_secs: duration_secs,
                        voice_transfer_id: Some(tid),
                        voice_only_members: vec![],
                    });
                }
                OutboxEntry::GroupSync {
                    group_id,
                    group_name: _,
                    creator_id: _,
                    members: _,
                    recipient,
                } => {
                    if self.left_groups.contains(&group_id)
                        || !self.is_active_group_member(&group_id)
                    {
                        continue;
                    }
                    let Ok(pid) = recipient.parse::<PeerId>() else {
                        continue;
                    };
                    if pid == self.local_peer_id {
                        continue;
                    }
                    let Some(group) = self.groups.get(&group_id) else {
                        continue;
                    };
                    let members = self.members_for_sync(group);
                    if members.is_empty() {
                        continue;
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupSync {
                        group_id: group.id.clone(),
                        group_name: group.name.clone(),
                        creator_id: group.creator_id.clone(),
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

    /// Проходит журнал и подхватывает invite-ссылки (только новые, не из покинутых групп).
    fn scan_chat_journal_for_group_invites(&mut self) {
        let msgs: Vec<(String, String)> = self
            .messages
            .lock()
            .values()
            .flatten()
            .filter(|m| m.sender_id != self.local_peer_id.to_string())
            .map(|m| (m.id.clone(), m.text.clone()))
            .collect();
        for (id, text) in msgs {
            if self.invite_join_processed.contains(&id) {
                continue;
            }
            let joined = self.try_join_groups_from_invite_text(&text, &id);
            if joined || self.invite_links_handled(&text) {
                self.invite_join_processed.insert(id);
            }
        }
    }

    fn invite_links_handled(&self, text: &str) -> bool {
        let links = extract_invite_links(text);
        links.is_empty()
            || links.iter().all(|link| {
                parse_invite_link(link).is_some_and(|g| {
                    self.left_groups.contains(&g.id) || self.is_active_group_member(&g.id)
                })
            })
    }

    /// Строит голосовое сообщение для очереди отправки. В чат оно попадёт
    /// только после `voice_ack(ok: true)` — см. `apply_voice_ack`.
    pub(crate) fn build_voice_chat_message(
        &self,
        message_id: &str,
        recipient_id: Option<String>,
        group_id: Option<String>,
        transfer_hex: &str,
        duration_secs: f32,
    ) -> ChatMessage {
        ChatMessage {
            id: message_id.to_string(),
            sender_id: self.local_peer_id.to_string(),
            sender_name: self.local_nickname.clone(),
            recipient_id,
            text: String::new(),
            timestamp: chrono::Local::now().format("%H:%M").to_string(),
            delivery: OutgoingDeliveryStatus::Pending,
            voice: Some(VoiceMeta {
                transfer_id: transfer_hex.to_string(),
                duration_secs: duration_secs.max(0.1),
            }),
            group_id,
        }
    }

    pub(crate) fn ingest_chat_message(&mut self, mut msg: ChatMessage) {
        if msg.id.is_empty() {
            msg.id = new_message_id();
        }
        // Сообщение удалено локально ранее — не даём ретраю/offline-мейлоксу/
        // повтору от собеседника воскресить его (см. `DeletedTombstones`).
        if self.messages.is_deleted(&msg.id) {
            return;
        }

        let voice_tid = msg.voice.as_ref().map(|v| v.transfer_id.clone());

        let bucket = if let Some(ref gid) = msg.group_id {
            if group::validate_group_id(gid) {
                if self.is_active_group_member(gid) {
                    Some(group_thread_key(gid))
                } else if msg.voice.is_some() {
                    // Голосовое может прийти до group_sync — сохраняем в поток группы.
                    Some(group_thread_key(gid))
                } else {
                    None
                }
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

    /// Отправляет готовое голосовое в выбранный чат (DM или группа).
    pub(crate) fn try_dispatch_ready_voice(&mut self) -> Option<String> {
        if !self.voice_recorder.has_ready() {
            return None;
        }
        let (path, duration) = self.voice_recorder.take_ready()?;
        let dur = crate::voice::fmt_duration(duration);
        if let Some(gid) = self.selected_group_id().map(str::to_string) {
            return match self.send_group_voice_message(gid, path, duration) {
                Ok(()) => Some(format!("🎤 Голосовое {dur} отправлено в группу")),
                Err(e) => {
                    self.add_status(format!("⚠ {}", e));
                    None
                }
            };
        }
        let peer = self.selected_chat.parse::<PeerId>().ok()?;
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
        // Голосовое: outbox снимаем только после завершения file-transfer.
        let voice_still_pending = self.pending_voice_sends.iter().any(|p| {
            p.peer == peer && p.message_id == message_id
        });
        if !voice_still_pending {
            self.remove_outbox_direct(&peer.to_string(), message_id);
        }
    }

    /// Восстанавливает очередь недоставленных исходящих из журнала после рестарта.
    pub(crate) fn restore_pending_outgoing(&mut self) {
        let me = self.local_peer_id.to_string();
        let outbox_msg_ids: HashSet<String> = self
            .outbox_entries
            .iter()
            .filter_map(|e| match e {
                OutboxEntry::DirectMessage { message_id, .. }
                | OutboxEntry::DirectVoice { message_id, .. }
                | OutboxEntry::GroupMessage { message_id, .. }
                | OutboxEntry::GroupVoice { message_id, .. } => Some(message_id.clone()),
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
                        && (!msg.text.is_empty() || msg.voice.is_some())
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
                    // Совместимость со старым журналом, где голосовые уже были в
                    // чате как Pending (до появления атомарного voice_ack).
                    chat_message: msg.clone(),
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
            let voice_path = msg.voice.as_ref().and_then(|v| {
                self.resolve_voice_path(&v.transfer_id)
                    .map(|p| p.display().to_string())
            });
            let voice_duration_secs = msg.voice.as_ref().map(|v| v.duration_secs).unwrap_or(0.0);
            let voice_transfer_id = msg
                .voice
                .as_ref()
                .and_then(|v| transfer_id_from_hex(&v.transfer_id));
            // Совместимость со старым журналом (голосовое уже было Pending в чате
            // до появления voice_ack) — новые голосовые сюда не попадают вовсе.
            let chat_message_for_pending = if msg.voice.is_some() {
                Some(msg.clone())
            } else {
                None
            };
            self.pending_group_sends.push(PendingGroupSend {
                group_id: gid.clone(),
                members,
                text: msg.text.clone(),
                message_id: msg.id.clone(),
                last_send_at: Instant::now(),
                attempts: 0,
                delivered_to: HashSet::new(),
                voice_delivered_to: HashSet::new(),
                voice_path: voice_path.clone(),
                voice_duration_secs,
                voice_transfer_id,
                // Легаси-запись уже была показана в чате как Pending — не переигрываем.
                voice_shown: chat_message_for_pending.is_some(),
                chat_message: chat_message_for_pending,
            });
            let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                sender_name: self.local_nickname.clone(),
                text: msg.text,
                group_id: gid,
                members: targets,
                message_id: Some(msg.id),
                is_retry: true,
                voice_path,
                voice_duration_secs,
                voice_transfer_id,
                voice_only_members: vec![],
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
            .filter(|p| {
                p.members.contains(&peer)
                    && Self::group_peer_needs_resend(p, peer, self.local_peer_id)
            })
            .cloned()
            .collect();
        for item in due {
            let targets: Vec<PeerId> = item
                .members
                .iter()
                .copied()
                .filter(|m| Self::group_peer_needs_resend(&item, *m, self.local_peer_id))
                .collect();
            if targets.is_empty() {
                continue;
            }
            let voice_only_members: Vec<PeerId> = targets
                .iter()
                .copied()
                .filter(|p| {
                    item.delivered_to.contains(p)
                        && item.voice_transfer_id.is_some()
                        && !item.voice_delivered_to.contains(p)
                })
                .collect();
            let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                sender_name: self.local_nickname.clone(),
                text: item.text.clone(),
                group_id: item.group_id.clone(),
                members: targets,
                message_id: Some(item.message_id.clone()),
                is_retry: true,
                voice_path: item.voice_path.clone(),
                voice_duration_secs: item.voice_duration_secs,
                voice_transfer_id: item.voice_transfer_id,
                voice_only_members,
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
        let key_probe = transfer_id_hex.to_ascii_lowercase();
        // Этот путь дёргается из цикла отрисовки чата на КАЖДЫЙ кадр для каждого
        // голосового пузыря (пока играет прогресс-бар — сотни раз в секунду).
        // Без этой проверки тут на каждый кадр летит canonicalize() + запись в
        // лог — это грузит диск/CPU настолько, что может мешать самому
        // воспроизведению звука. Файл после скачивания не переезжает, поэтому
        // раз найденный путь можно просто закэшировать и не перепроверять.
        if self.voice_audio_paths.contains_key(&key_probe) {
            return;
        }
        let mut p = std::path::PathBuf::from(&path);
        if p.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                p = cwd.join(p);
            }
        }
        let canonical = std::fs::canonicalize(&p).unwrap_or(p.clone());
        if !canonical.is_file() {
            if p.is_file() {
                // canonicalize может падать на symlink/tmp — используем исходный путь
            } else {
                crate::voice::voice_log(&format!(
                    "register miss {} -> {} (файл не найден)",
                    transfer_id_hex.to_ascii_lowercase(),
                    p.display()
                ));
                return;
            }
        }
        let stored = if canonical.is_file() {
            canonical.display().to_string()
        } else {
            p.display().to_string()
        };
        let key = transfer_id_hex.to_ascii_lowercase();
        self.voice_audio_paths.insert(key.clone(), stored.clone());
        crate::voice::voice_log(&format!("registered {key} -> {stored}"));
    }

    /// Дополнительные transfer_id для группового голосового (base ↔ per-peer).
    pub(crate) fn voice_transfer_aliases(&self, transfer_id_hex: &str) -> Vec<String> {
        let tid = transfer_id_hex.to_ascii_lowercase();
        let mut out = vec![tid.clone()];
        let Some(base) = transfer_id_from_hex(&tid) else {
            return out;
        };
        let peer_tid = per_peer_voice_transfer_id(&base, self.local_peer_id);
        let peer_hex = transfer_id_to_hex(&peer_tid);
        if peer_hex != tid {
            out.push(peer_hex);
        }
        // Входящее групповое: в журнале base id, на диске per-peer (и наоборот).
        let messages = self.messages.lock();
        for msgs in messages.values() {
            for msg in msgs.iter() {
                let Some(ref voice) = msg.voice else {
                    continue;
                };
                let vtid = voice.transfer_id.to_ascii_lowercase();
                if vtid != tid {
                    continue;
                }
                if msg.group_id.is_some() {
                    if let Some(vbase) = transfer_id_from_hex(&vtid) {
                        let alt = transfer_id_to_hex(&per_peer_voice_transfer_id(
                            &vbase,
                            self.local_peer_id,
                        ));
                        if !out.contains(&alt) {
                            out.push(alt);
                        }
                    }
                }
            }
        }
        out
    }

    pub(crate) fn relink_voice_transfer_candidates(&mut self, transfer_id_hex: &str) {
        for alias in self.voice_transfer_aliases(transfer_id_hex) {
            self.link_voice_file_if_present(&alias);
        }
        self.index_voice_files_on_disk();
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
        let prefix = format!("{}{}", file_transfer::VOICE_FILENAME_PREFIX, tid);
        for dir in file_transfer::voice_search_dirs() {
            let direct = dir.join(&name);
            if direct.is_file() {
                return Some(direct);
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let fname = entry.file_name().to_string_lossy().into_owned();
                    if fname.starts_with(&prefix) && fname.ends_with(".wav") {
                        return Some(entry.path());
                    }
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

    /// Индексирует все WAV в каталоге голосовых (после рестарта / миграции).
    pub(crate) fn index_voice_files_on_disk(&mut self) {
        for dir in file_transfer::voice_search_dirs() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().into_owned();
                if let Some(tid) = file_transfer::voice_transfer_hex_from_filename(&fname) {
                    if entry.path().is_file() {
                        self.register_voice_path(&tid, entry.path().display().to_string());
                    }
                }
            }
        }
    }

    /// Привязывает WAV ко всем голосовым из журнала.
    pub(crate) fn relink_all_voice_files(&mut self) {
        let tids: Vec<String> = {
            let messages = self.messages.lock();
            messages
                .values()
                .flat_map(|msgs| {
                    msgs.iter()
                        .filter_map(|m| m.voice.as_ref().map(|v| v.transfer_id.clone()))
                })
                .collect()
        };
        for tid in tids {
            self.link_voice_file_if_present(&tid);
        }
    }

    pub(crate) fn resolve_voice_path(&self, transfer_id_hex: &str) -> Option<std::path::PathBuf> {
        for alias in self.voice_transfer_aliases(transfer_id_hex) {
            if let Some(p) = self.voice_audio_paths.get(&alias) {
                let path = std::path::PathBuf::from(p);
                if path.is_file() {
                    return Some(path);
                }
            }
            if let Some(path) = self.lookup_voice_file_on_disk(&alias) {
                return Some(path);
            }
        }
        let tid = transfer_id_hex.to_ascii_lowercase();
        for pending in &self.pending_voice_sends {
            if transfer_id_to_hex(&pending.transfer_id) == tid {
                let path = std::path::PathBuf::from(&pending.path);
                if path.is_file() {
                    return Some(path);
                }
            }
        }
        for pending in &self.pending_group_sends {
            if let Some(vtid) = pending.voice_transfer_id {
                if transfer_id_to_hex(&vtid) == tid {
                    if let Some(ref p) = pending.voice_path {
                        let path = std::path::PathBuf::from(p);
                        if path.is_file() {
                            return Some(path);
                        }
                    }
                }
            }
        }
        None
    }

    fn voice_message_context(
        &self,
        transfer_id_hex: &str,
    ) -> Option<(String, Option<String>, bool)> {
        let tid = transfer_id_hex.to_ascii_lowercase();
        let me = self.local_peer_id.to_string();
        let messages = self.messages.lock();
        for msgs in messages.values() {
            for msg in msgs.iter() {
                if msg
                    .voice
                    .as_ref()
                    .is_some_and(|v| v.transfer_id.to_ascii_lowercase() == tid)
                {
                    return Some((
                        msg.sender_id.clone(),
                        msg.group_id.clone(),
                        msg.sender_id == me,
                    ));
                }
            }
        }
        None
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
        self.relink_voice_transfer_candidates(&transfer_id);
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
                let hint = match self.voice_message_context(&transfer_id) {
                    Some((_, _, false)) => {
                        "Голосовое ещё не загружено — дождитесь передачи или попросите отправить снова"
                    }
                    _ => "Файл не найден на диске — попробуйте отправить голосовое заново",
                };
                self.push_toast(
                    format!("Аудиофайл не найден ({transfer_id}). {hint}"),
                    ToastKind::Error,
                    TOAST_TTL_LONG,
                );
            }
        }
    }

    pub(crate) fn send_voice_message(
        &mut self,
        peer: PeerId,
        path: std::path::PathBuf,
        duration_secs: f32,
    ) -> Result<(), &'static str> {
        let duration_secs = duration_secs.max(0.1);
        // Условие 2 атомарности: сообщение должно нести реальные аудио-данные,
        // а не пустой/битый WAV (44 байта — только заголовок, без сэмплов).
        let recorded_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if recorded_len <= 44 {
            self.add_status("⚠ Голосовое пустое — запись не содержит аудио".into());
            return Err("Голосовое сообщение пустое");
        }
        let mut tid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut tid);
        let message_id = new_message_id();
        let transfer_hex = transfer_id_to_hex(&tid);
        let path_str = match file_transfer::stage_voice_wav(&path, &tid) {
            Ok(dest) => dest.display().to_string(),
            Err(e) => {
                crate::voice::voice_log(&format!("stage voice {transfer_hex}: {e}"));
                if path.is_file() {
                    path.display().to_string()
                } else {
                    self.add_status(format!("⚠ Не удалось сохранить голосовое: {e}"));
                    return Err("Не удалось сохранить голосовое");
                }
            }
        };
        self.register_voice_path(&transfer_hex, path_str.clone());
        self.outbox_track_direct_voice(
            peer,
            message_id.clone(),
            transfer_hex.clone(),
            duration_secs,
            path_str.clone(),
        );
        // Сразу в relay: иначе при быстром выходе чанки не успевают уйти
        // (tick debounce + короткое окно до close).
        self.publish_outbox_to_dht();
        // Как у текста/инвайтов: сразу в чат + outbox (offline voice_chunk через
        // relay). Живой VoiceAck только ставит Delivered, если собеседник онлайн.
        let chat_message = self.build_voice_chat_message(
            &message_id,
            Some(peer.to_string()),
            None,
            &transfer_hex,
            duration_secs,
        );
        self.ingest_chat_message(chat_message.clone());
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
                    chat_message,
                });
                Ok(())
            }
            Err(_) => Err("Очередь к сети переполнена"),
        }
    }

    pub(crate) fn send_group_voice_message(
        &mut self,
        group_id: String,
        path: std::path::PathBuf,
        duration_secs: f32,
    ) -> Result<(), &'static str> {
        let duration_secs = duration_secs.max(0.1);
        // Условие 2 атомарности: сообщение должно нести реальные аудио-данные.
        let recorded_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if recorded_len <= 44 {
            self.add_status("⚠ Голосовое пустое — запись не содержит аудио".into());
            return Err("Голосовое сообщение пустое");
        }
        let group = self.groups.get(&group_id).ok_or("Группа не найдена")?;
        let members = group.member_peer_ids();
        let targets: Vec<PeerId> = members
            .iter()
            .copied()
            .filter(|p| *p != self.local_peer_id)
            .collect();
        if targets.is_empty() {
            return Err("Нет участников для отправки");
        }
        let mut tid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut tid);
        let message_id = new_message_id();
        let transfer_hex = transfer_id_to_hex(&tid);
        let path_str = match file_transfer::stage_voice_wav(&path, &tid) {
            Ok(dest) => dest.display().to_string(),
            Err(e) => {
                crate::voice::voice_log(&format!("stage group voice {transfer_hex}: {e}"));
                if path.is_file() {
                    path.display().to_string()
                } else {
                    self.add_status(format!("⚠ Не удалось сохранить голосовое: {e}"));
                    return Err("Не удалось сохранить голосовое");
                }
            }
        };
        self.register_voice_path(&transfer_hex, path_str.clone());
        self.outbox_track_group_voice(
            group_id.clone(),
            message_id.clone(),
            transfer_hex.clone(),
            duration_secs,
            path_str.clone(),
            members.clone(),
        );
        self.publish_outbox_to_dht();
        // Как у текста: сразу в чат; offline chunks на каждого члена + живые ретраи.
        let chat_message = self.build_voice_chat_message(
            &message_id,
            None,
            Some(group_id.clone()),
            &transfer_hex,
            duration_secs,
        );
        self.ingest_chat_message(chat_message.clone());
        match self.command_tx.try_send(UICommand::SendGroupMessage {
            sender_name: self.local_nickname.clone(),
            text: String::new(),
            group_id: group_id.clone(),
            members: targets,
            message_id: Some(message_id.clone()),
            is_retry: false,
            voice_path: Some(path_str.clone()),
            voice_duration_secs: duration_secs,
            voice_transfer_id: Some(tid),
            voice_only_members: vec![],
        }) {
            Ok(()) => {
                self.pending_group_sends.push(PendingGroupSend {
                    group_id,
                    members,
                    text: String::new(),
                    message_id,
                    last_send_at: Instant::now(),
                    attempts: 0,
                    delivered_to: HashSet::new(),
                    voice_delivered_to: HashSet::new(),
                    voice_path: Some(path_str),
                    voice_duration_secs: duration_secs,
                    voice_transfer_id: Some(tid),
                    chat_message: Some(chat_message),
                    voice_shown: true,
                });
                Ok(())
            }
            Err(_) => Err("Очередь к сети переполнена"),
        }
    }

    pub(crate) fn complete_pending_voice_send_by_transfer(&mut self, transfer_id: &[u8; 16]) {
        let completed: Vec<(PeerId, String)> = self
            .pending_voice_sends
            .iter()
            .filter(|p| p.transfer_id == *transfer_id)
            .map(|p| (p.peer, p.message_id.clone()))
            .collect();
        for (peer, message_id) in completed {
            self.remove_outbox_direct(&peer.to_string(), &message_id);
        }
        self.pending_voice_sends
            .retain(|p| p.transfer_id != *transfer_id);
    }

    fn voice_send_retry_delay(path: &str) -> Duration {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let bps = file_transfer::RELAY_RATE_LIMIT_BPS;
        let secs = size.saturating_mul(2) / bps;
        Duration::from_secs(secs.max(5).min(300))
    }

    pub(crate) fn tick_pending_voice_sends(&mut self) {
        let now = Instant::now();
        let due: Vec<PendingVoiceSend> = self
            .pending_voice_sends
            .iter()
            .filter(|p| now.duration_since(p.last_attempt) >= Self::voice_send_retry_delay(&p.path))
            .cloned()
            .collect();
        for item in due {
            if !std::path::Path::new(&item.path).exists() {
                self.add_status(format!(
                    "⚠ Голосовое {}: файл не найден ({})",
                    &item.message_id[..8.min(item.message_id.len())],
                    item.path
                ));
                self.pending_voice_sends.retain(|p| {
                    !(p.peer == item.peer && p.message_id == item.message_id)
                });
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
        // Надгробие: без него ретрай/offline-мейлбокс воскресит удалённое.
        self.messages.mark_deleted(message_ids.iter().cloned());
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
        let ids: Vec<String> = self
            .messages
            .lock()
            .get(&peer_str)
            .map(|v| v.iter().map(|m| m.id.clone()).collect())
            .unwrap_or_default();
        self.messages.lock().remove(&peer_str);
        self.messages.mark_deleted(ids);
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
                    x25519_public: self.peer_prekeys.get(pid).copied(),
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
        let mut selected: Vec<PeerId> = Vec::new();
        let mut seen = HashSet::new();
        for pid in member_pids {
            if pid == self.local_peer_id {
                continue;
            }
            if seen.insert(pid) {
                selected.push(pid);
            }
        }
        if selected.is_empty() {
            self.add_status("⚠ Выберите хотя бы одного участника группы".into());
            return None;
        }
        let id = group::new_group_id();
        let me = self.local_peer_id.to_string();
        let invitee_ids: Vec<String> = selected.iter().map(|p| p.to_string()).collect();
        // В составе только создатель. Выбранные получают invite-ссылку и
        // попадают в группу ТОЛЬКО после явного перехода/клика по ссылке.
        let group = GroupChat {
            id: id.clone(),
            name,
            creator_id: me,
            members: group::members_on_group_create(
                &self.local_peer_id.to_string(),
                &self.local_nickname,
                &invitee_ids,
            ),
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        };
        if !group::validate_group_chat(&group) {
            return None;
        }
        info!(
            "Создана группа «{}» id={} — инвайт {} чел.",
            group.name,
            &id[..8.min(id.len())],
            selected.len()
        );
        self.groups.insert(id.clone(), group.clone());
        self.selected_chat = group_thread_key(&id);
        self.messages
            .lock()
            .entry(self.selected_chat.clone())
            .or_default();
        self.persist_vault();
        for pid in &selected {
            self.send_group_invite_dm(*pid, &group);
            let _ = self.command_tx.try_send(UICommand::SearchPeer(*pid));
        }
        Some(id)
    }

    /// Больше не вступаем автоматически по тексту сообщения — только по клику
    /// на ссылку (см. `join_group_from_invite` / кнопка «Вступить» в UI).
    pub(crate) fn try_join_groups_from_invite_text(
        &mut self,
        _text: &str,
        _message_id: &str,
    ) -> bool {
        group::auto_join_from_invite_message()
    }

    /// Invite-ссылки в чате, в которые локальный пир ещё не входит.
    pub(crate) fn joinable_invites_for_chat(&self, chat_key: &str) -> Vec<(String, String)> {
        let messages = self
            .messages
            .lock()
            .get(chat_key)
            .cloned()
            .unwrap_or_default();
        Self::collect_joinable_invites(self, messages.iter().map(|m| m.text.as_str()))
    }

    fn collect_joinable_invites<'a>(
        &self,
        texts: impl Iterator<Item = &'a str>,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for text in texts {
            for link in extract_invite_links(text) {
                let Some(parsed) = parse_invite_link(&link) else {
                    continue;
                };
                if self.is_active_group_member(&parsed.id) {
                    continue;
                }
                if seen.insert(parsed.id.clone()) {
                    out.push((link, parsed.name));
                }
            }
        }
        out
    }

    /// Вступает по ссылке и возвращает имя группы при успехе.
    pub(crate) fn join_group_from_invite(&mut self, link: &str) -> Result<(), &'static str> {
        let group = parse_invite_link(link.trim()).ok_or("Некорректная invite-ссылка")?;
        info!(
            "Вступление в группу по invite: «{}» id={}",
            group.name,
            &group.id[..8.min(group.id.len())]
        );
        self.left_groups.remove(&group.id);
        self.group_departed_peers
            .entry(group.id.clone())
            .or_default()
            .remove(&self.local_peer_id.to_string());
        self.install_group(group, true)
    }

    /// Обрабатывает `pending_invite_join` (результат клика из UI).
    pub(crate) fn drain_pending_invite_join(&mut self) -> Option<Result<String, &'static str>> {
        let link = self.pending_invite_join.take()?;
        Some(match self.join_group_from_invite(&link) {
            Ok(()) => {
                let name = parse_invite_link(&link)
                    .map(|g| g.name)
                    .unwrap_or_else(|| "группу".into());
                Ok(name)
            }
            Err(e) => Err(e),
        })
    }

    fn install_group(&mut self, mut group: GroupChat, select: bool) -> Result<(), &'static str> {
        group.members = dedupe_members(group.members);
        if group.creator_id.is_empty() {
            group.creator_id = group
                .members
                .first()
                .map(|m| m.peer_id.clone())
                .unwrap_or_else(|| self.local_peer_id.to_string());
        }
        self.ensure_self_in_group(&mut group);
        if !group::validate_group_chat(&group) {
            return Err("некорректные данные группы");
        }
        let was_active = self.is_active_group_member(&group.id);
        let thread = group_thread_key(&group.id);
        self.groups.insert(group.id.clone(), group.clone());
        if select {
            self.selected_chat = thread.clone();
        }
        self.messages.lock().entry(thread).or_default();
        if !was_active {
            self.dial_group_members(&group);
            self.broadcast_group_sync(&group);
        }
        self.persist_vault();
        Ok(())
    }

    fn send_group_invite_dm(&mut self, peer: PeerId, group: &GroupChat) {
        if self.left_groups.contains(&group.id) {
            return;
        }
        let peer_str = peer.to_string();
        if self
            .group_departed_peers
            .get(&group.id)
            .is_some_and(|d| d.contains(&peer_str))
        {
            return;
        }
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
        // Сразу в relay/DHT — не ждать tick: иначе при быстром выходе инвайт
        // остаётся только в outbox.bin у отправителя.
        self.publish_outbox_to_dht();
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

    fn record_group_departure(&mut self, group_id: &str, peer_id: &str) {
        self.group_departed_peers
            .entry(group_id.to_string())
            .or_default()
            .insert(peer_id.to_string());
    }

    fn members_for_sync(&self, group: &GroupChat) -> Vec<GroupMember> {
        let departed = self
            .group_departed_peers
            .get(&group.id)
            .cloned()
            .unwrap_or_default();
        dedupe_members(
            group
                .members
                .iter()
                .filter(|m| !departed.contains(&m.peer_id))
                .cloned()
                .collect(),
        )
    }

    /// Раньше авто-вступал по тексту invite. Теперь только кнопка / вставка ссылки.
    pub(crate) fn try_process_invite_message(&mut self, _message_id: &str, _text: &str) {}

    fn refresh_outbox_group_sync_snapshots(&mut self) {
        let snapshots: Vec<(String, String, String, Vec<GroupMember>)> = self
            .outbox_entries
            .iter()
            .filter_map(|e| {
                let OutboxEntry::GroupSync { group_id, .. } = e else {
                    return None;
                };
                if self.left_groups.contains(group_id) {
                    return None;
                }
                let group = self.groups.get(group_id)?;
                let members = self.members_for_sync(group);
                if members.is_empty() {
                    return None;
                }
                Some((
                    group_id.clone(),
                    group.name.clone(),
                    group.creator_id.clone(),
                    members,
                ))
            })
            .collect();
        if snapshots.is_empty() {
            return;
        }
        let mut changed = false;
        for entry in &mut self.outbox_entries {
            let OutboxEntry::GroupSync {
                group_id,
                group_name,
                creator_id,
                members,
                ..
            } = entry
            else {
                continue;
            };
            if let Some((_, name, creator, synced)) =
                snapshots.iter().find(|(gid, _, _, _)| gid == group_id)
            {
                *group_name = name.clone();
                *creator_id = creator.clone();
                *members = synced.clone();
                changed = true;
            }
        }
        if changed {
            self.persist_outbox();
        }
    }

    pub(crate) fn add_member_to_selected_group(&mut self, peer: PeerId) -> Result<(), &'static str> {
        if peer == self.local_peer_id {
            return Err("Нельзя добавить себя");
        }
        let group_id = self
            .selected_group_id()
            .ok_or("Выберите групповой чат")?
            .to_string();
        let group = self.groups.get(&group_id).ok_or("Группа не найдена")?.clone();
        if group.members.iter().any(|m| m.peer_id == peer.to_string()) {
            return Err("Участник уже в группе");
        }
        // Не добавляем в members и не шлём group_sync — иначе пир
        // окажется в группе без перехода по ссылке. Только invite-DM.
        self.group_departed_peers
            .entry(group_id)
            .or_default()
            .remove(&peer.to_string());
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
            | OutboxEntry::GroupVoice { group_id, .. }
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
            group.members = dedupe_members(group.members.clone());
            let g = group.clone();
            let empty = g.members.is_empty();
            if empty {
                self.groups.remove(&group_id);
            }
            self.record_group_departure(&group_id, &peer_id);
            self.purge_group_outbox(&group_id);
            self.persist_vault();
            if !empty && self.is_active_group_member(&group_id) {
                self.broadcast_group_sync(&g);
            }
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
        // Sync не создаёт группу с нуля — иначе invitee попадал бы в группу
        // без клика по ссылке. Вступление только через join_group_from_invite.
        if !group::may_install_group_from_sync(self.groups.contains_key(&group_id)) {
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
        let mut members = dedupe_members(members);
        if let Some(departed) = self.group_departed_peers.get(&group_id) {
            members.retain(|m| !departed.contains(&m.peer_id));
        }
        if !members.iter().any(|m| m.peer_id == me) {
            return;
        }

        // Только создатель может расширять состав. Чужой sync не должен
        // подмешивать в группу лишних людей («добавляет абсолютно всех»).
        members = self.sanitize_group_sync_members(&group_id, from, &creator_id, members);
        if !members.iter().any(|m| m.peer_id == me) {
            return;
        }

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
        let from_str = from.to_string();
        let name = self
            .groups
            .get(&group_id)
            .map(|g| {
                if from_str == g.creator_id || from_str == creator_id {
                    group_name.clone()
                } else {
                    g.name.clone()
                }
            })
            .unwrap_or(group_name);
        let group = GroupChat {
            id: group_id.clone(),
            name,
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

    /// Не-создатель не может добавлять участников через group_sync.
    fn sanitize_group_sync_members(
        &self,
        group_id: &str,
        from: PeerId,
        creator_id: &str,
        incoming: Vec<GroupMember>,
    ) -> Vec<GroupMember> {
        let me = self.local_peer_id.to_string();
        let from_str = from.to_string();
        let Some(existing) = self.groups.get(group_id) else {
            return incoming;
        };
        let am_creator = existing.creator_id == me;
        let from_is_creator = from_str == existing.creator_id || from_str == creator_id;
        if !am_creator || from_is_creator {
            return incoming;
        }
        // Принявший invite может добавить только себя; чужих из его sync не берём.
        group::sanitize_sync_members_for_creator(&existing.members, &from_str, &incoming)
    }

    fn ensure_self_in_group(&self, group: &mut GroupChat) {
        let me = self.local_peer_id.to_string();
        if !group.members.iter().any(|m| m.peer_id == me) {
            let display_name = if self.local_nickname.trim().is_empty() {
                let n = me.len().min(8);
                format!("Peer {}", &me[..n])
            } else {
                self.local_nickname.clone()
            };
            group.members.push(GroupMember {
                peer_id: me,
                display_name,
            });
        } else if let Some(m) = group.members.iter_mut().find(|m| m.peer_id == me) {
            if m.display_name.trim().is_empty() {
                m.display_name = if self.local_nickname.trim().is_empty() {
                    let n = me.len().min(8);
                    format!("Peer {}", &me[..n])
                } else {
                    self.local_nickname.clone()
                };
            }
        }
    }

    fn broadcast_group_sync(&mut self, group: &GroupChat) {
        if self.left_groups.contains(&group.id) {
            return;
        }
        let members = self.members_for_sync(group);
        if members.is_empty() {
            return;
        }
        let mut sync_group = group.clone();
        sync_group.members = members.clone();
        let recipients: Vec<PeerId> = sync_group
            .member_peer_ids()
            .into_iter()
            .filter(|p| *p != self.local_peer_id)
            .collect();
        if recipients.is_empty() {
            return;
        }
        for pid in &recipients {
            self.queue_outbox_group_sync(&sync_group, *pid);
        }
        let _ = self.command_tx.try_send(UICommand::SendGroupSync {
            group_id: sync_group.id.clone(),
            group_name: sync_group.name.clone(),
            creator_id: sync_group.creator_id.clone(),
            members,
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
            let members = self.members_for_sync(&group);
            if members.is_empty() {
                continue;
            }
            let mut sync_group = group.clone();
            sync_group.members = members.clone();
            self.queue_outbox_group_sync(&sync_group, peer);
            let _ = self.command_tx.try_send(UICommand::SendGroupSync {
                group_id: sync_group.id.clone(),
                group_name: sync_group.name.clone(),
                creator_id: sync_group.creator_id.clone(),
                members,
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
                OutboxEntry::DirectVoice {
                    peer: p,
                    message_id,
                    transfer_id,
                    duration_secs,
                    voice_path,
                } if p == peer_str => {
                    let Some(tid) = transfer_id_from_hex(&transfer_id) else {
                        continue;
                    };
                    if !std::path::Path::new(&voice_path).is_file() {
                        self.add_status(format!(
                            "⚠ Голосовое {}: файл не найден, удалено из outbox ({})",
                            &message_id[..8.min(message_id.len())],
                            voice_path
                        ));
                        self.outbox_entries.retain(|e| !matches!(
                            e,
                            OutboxEntry::DirectVoice { message_id: id, .. } if id == &message_id
                        ));
                        self.persist_outbox();
                        continue;
                    }
                    if !self.pending_voice_sends.iter().any(|x| x.message_id == message_id) {
                        let chat_message = self.build_voice_chat_message(
                            &message_id,
                            Some(peer.to_string()),
                            None,
                            &transfer_id,
                            duration_secs,
                        );
                        self.pending_voice_sends.push(PendingVoiceSend {
                            peer,
                            path: voice_path.clone(),
                            duration_secs,
                            message_id: message_id.clone(),
                            transfer_id: tid,
                            last_attempt: Instant::now(),
                            chat_message,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendVoiceMessage {
                        sender_name: self.local_nickname.clone(),
                        recipient: peer,
                        path: voice_path,
                        duration_secs,
                        message_id,
                        transfer_id: tid,
                        is_retry: true,
                    });
                }
                OutboxEntry::GroupSync {
                    group_id,
                    group_name: _,
                    creator_id: _,
                    members: _,
                    recipient,
                } if recipient == peer_str => {
                    if self.left_groups.contains(&group_id)
                        || !self.is_active_group_member(&group_id)
                    {
                        continue;
                    }
                    let Some(group) = self.groups.get(&group_id) else {
                        continue;
                    };
                    let members = self.members_for_sync(group);
                    if members.is_empty() {
                        continue;
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupSync {
                        group_id: group.id.clone(),
                        group_name: group.name.clone(),
                        creator_id: group.creator_id.clone(),
                        members,
                        recipients: vec![peer],
                    });
                }
                OutboxEntry::GroupMessage {
                    group_id,
                    message_id,
                    text,
                    members,
                } if members.iter().any(|m| m == &peer_str) => {
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
                        .filter(|p| *p != self.local_peer_id && *p == peer)
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
                            voice_delivered_to: HashSet::new(),
                            voice_path: None,
                            voice_duration_secs: 0.0,
                            voice_transfer_id: None,
                            chat_message: None,
                            voice_shown: false,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                        sender_name: self.local_nickname.clone(),
                        text,
                        group_id,
                        members: targets,
                        message_id: Some(message_id),
                        is_retry: true,
                        voice_path: None,
                        voice_duration_secs: 0.0,
                        voice_transfer_id: None,
                        voice_only_members: vec![],
                    });
                }
                OutboxEntry::GroupVoice {
                    group_id,
                    message_id,
                    transfer_id,
                    duration_secs,
                    voice_path,
                    members,
                } if members.iter().any(|m| m == &peer_str) => {
                    if self.left_groups.contains(&group_id)
                        || !self.is_active_group_member(&group_id)
                    {
                        continue;
                    }
                    if !std::path::Path::new(&voice_path).is_file() {
                        self.add_status(format!(
                            "⚠ Групповое голосовое {}: файл не найден, удалено из outbox ({})",
                            &message_id[..8.min(message_id.len())],
                            voice_path
                        ));
                        self.outbox_entries.retain(|e| !matches!(
                            e,
                            OutboxEntry::GroupVoice { message_id: id, .. } if id == &message_id
                        ));
                        self.persist_outbox();
                        continue;
                    }
                    let member_pids: Vec<PeerId> = members
                        .iter()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    let targets: Vec<PeerId> = member_pids
                        .iter()
                        .copied()
                        .filter(|p| *p != self.local_peer_id && *p == peer)
                        .collect();
                    if targets.is_empty() {
                        continue;
                    }
                    let Some(tid) = transfer_id_from_hex(&transfer_id) else {
                        continue;
                    };
                    if !self
                        .pending_group_sends
                        .iter()
                        .any(|p| p.message_id == message_id)
                    {
                        let chat_message = self.build_voice_chat_message(
                            &message_id,
                            None,
                            Some(group_id.clone()),
                            &transfer_id,
                            duration_secs,
                        );
                        self.pending_group_sends.push(PendingGroupSend {
                            group_id: group_id.clone(),
                            members: member_pids,
                            text: String::new(),
                            message_id: message_id.clone(),
                            last_send_at: Instant::now(),
                            attempts: 0,
                            delivered_to: HashSet::new(),
                            voice_delivered_to: HashSet::new(),
                            voice_path: Some(voice_path.clone()),
                            voice_duration_secs: duration_secs,
                            voice_transfer_id: Some(tid),
                            chat_message: Some(chat_message),
                            voice_shown: false,
                        });
                    }
                    let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                        sender_name: self.local_nickname.clone(),
                        text: String::new(),
                        group_id,
                        members: targets,
                        message_id: Some(message_id),
                        is_retry: true,
                        voice_path: Some(voice_path),
                        voice_duration_secs: duration_secs,
                        voice_transfer_id: Some(tid),
                        voice_only_members: vec![],
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
        let mut show_voice: Option<ChatMessage> = None;
        let mut mark_delivered_id: Option<String> = None;
        if let Some(idx) = self
            .pending_group_sends
            .iter()
            .position(|p| p.message_id == message_id)
        {
            self.pending_group_sends[idx].delivered_to.insert(peer);
            let pending = &mut self.pending_group_sends[idx];
            let needed: HashSet<PeerId> = pending
                .members
                .iter()
                .copied()
                .filter(|p| *p != me)
                .collect();
            let has_voice = pending.voice_transfer_id.is_some();
            // Голосовое уже в чате с момента отправки; при первом живом ack —
            // только Delivered. Старый путь (voice_shown=false) остаётся для
            // pending, восстановленных из журнала до этого изменения.
            if has_voice
                && !pending.voice_shown
                && needed
                    .iter()
                    .any(|p| pending.delivered_to.contains(p) && pending.voice_delivered_to.contains(p))
            {
                pending.voice_shown = true;
                show_voice = pending.chat_message.clone();
            } else if has_voice
                && pending.voice_shown
                && needed
                    .iter()
                    .any(|p| pending.delivered_to.contains(p) && pending.voice_delivered_to.contains(p))
            {
                mark_delivered_id = Some(pending.message_id.clone());
            }
            remove = if has_voice {
                needed.is_subset(&pending.delivered_to)
                    && needed.is_subset(&pending.voice_delivered_to)
            } else {
                needed.is_subset(&pending.delivered_to)
            };
        }
        if let Some(mut msg) = show_voice {
            msg.delivery = OutgoingDeliveryStatus::Delivered;
            self.ingest_chat_message(msg);
        }
        if let Some(mid) = mark_delivered_id {
            self.set_outgoing_delivery(peer, &mid, OutgoingDeliveryStatus::Delivered);
        }
        if remove {
            self.pending_group_sends
                .retain(|p| p.message_id != message_id);
            self.remove_outbox_group_message(message_id);
        }
    }

    /// Вызывается по `voice_ack(ok=true)` конкретного участника. Снимает из
    /// очереди только когда подтвердили все; Delivered — при первом ack.
    pub(crate) fn mark_group_voice_file_delivered(
        &mut self,
        peer: PeerId,
        transfer_id: &[u8; 16],
    ) {
        let me = self.local_peer_id;
        let mut show: Option<ChatMessage> = None;
        let mut mark_delivered: Option<(PeerId, String)> = None;
        let mut done: Vec<String> = Vec::new();
        for pending in &mut self.pending_group_sends {
            let Some(base_tid) = pending.voice_transfer_id else {
                continue;
            };
            let peer_tid = per_peer_voice_transfer_id(&base_tid, peer);
            if peer_tid != *transfer_id {
                continue;
            }
            pending.voice_delivered_to.insert(peer);
            let needed: HashSet<PeerId> = pending
                .members
                .iter()
                .copied()
                .filter(|p| *p != me)
                .collect();
            crate::voice::voice_log(&format!(
                "voice_ack(true) group {} msg={} от {} — voice_delivered_to {}/{}, delivered_to {}/{}",
                transfer_id_to_hex(transfer_id),
                &pending.message_id[..8.min(pending.message_id.len())],
                &peer.to_string()[..8.min(peer.to_string().len())],
                pending.voice_delivered_to.len(),
                needed.len(),
                pending.delivered_to.len(),
                needed.len(),
            ));
            if !pending.voice_shown
                && needed
                    .iter()
                    .any(|p| pending.delivered_to.contains(p) && pending.voice_delivered_to.contains(p))
            {
                pending.voice_shown = true;
                show = pending.chat_message.clone();
            } else if pending.voice_shown
                && needed
                    .iter()
                    .any(|p| pending.delivered_to.contains(p) && pending.voice_delivered_to.contains(p))
            {
                mark_delivered = Some((peer, pending.message_id.clone()));
            }
            if needed.is_subset(&pending.delivered_to)
                && needed.is_subset(&pending.voice_delivered_to)
            {
                done.push(pending.message_id.clone());
            }
        }
        if let Some(mut msg) = show {
            msg.delivery = OutgoingDeliveryStatus::Delivered;
            self.ingest_chat_message(msg);
        }
        if let Some((p, mid)) = mark_delivered {
            self.set_outgoing_delivery(p, &mid, OutgoingDeliveryStatus::Delivered);
        }
        for message_id in done {
            self.pending_group_sends
                .retain(|p| p.message_id != message_id);
            self.remove_outbox_group_message(&message_id);
        }
    }

    /// Живой VoiceAck: обновляет Delivered / снимает pending. Сообщение уже в чате.
    pub(crate) fn apply_voice_ack(&mut self, peer: PeerId, transfer_id: [u8; 16], ok: bool) {
        if let Some(idx) = self
            .pending_voice_sends
            .iter()
            .position(|p| p.peer == peer && p.transfer_id == transfer_id)
        {
            if ok {
                let message_id = self.pending_voice_sends[idx].message_id.clone();
                crate::voice::voice_log(&format!(
                    "voice_ack(true) direct {} от {} — Delivered",
                    transfer_id_to_hex(&transfer_id),
                    &peer.to_string()[..8.min(peer.to_string().len())]
                ));
                self.set_outgoing_delivery(
                    peer,
                    &message_id,
                    OutgoingDeliveryStatus::Delivered,
                );
                self.complete_pending_voice_send_by_transfer(&transfer_id);
            } else {
                // Целостность не подтвердилась (или сбой записи у получателя) —
                // форсируем скорый повтор вместо ожидания обычного интервала.
                let accel = Instant::now() - Duration::from_secs(3600);
                if let Some(p) = self.pending_voice_sends.get_mut(idx) {
                    p.last_attempt = accel;
                }
                crate::voice::voice_log(&format!(
                    "voice_ack(false) direct {} — форсирую повтор",
                    transfer_id_to_hex(&transfer_id)
                ));
            }
            return;
        }
        if ok {
            self.mark_group_voice_file_delivered(peer, &transfer_id);
        } else {
            let accel = Instant::now() - Duration::from_secs(3600);
            let mut hit = false;
            for p in self.pending_group_sends.iter_mut() {
                if let Some(base) = p.voice_transfer_id {
                    if per_peer_voice_transfer_id(&base, peer) == transfer_id {
                        p.last_send_at = accel;
                        hit = true;
                    }
                }
            }
            if hit {
                crate::voice::voice_log(&format!(
                    "voice_ack(false) group {} от {} — форсирую повтор",
                    transfer_id_to_hex(&transfer_id),
                    &peer.to_string()[..8]
                ));
            }
        }
    }

    pub(crate) fn tick_pending_group_sends(&mut self) {
        let now = Instant::now();
        let me = self.local_peer_id;
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
                .filter(|m| Self::group_peer_needs_resend(&item, *m, me))
                .collect();
            if targets.is_empty() {
                continue;
            }
            let voice_only_members: Vec<PeerId> = targets
                .iter()
                .copied()
                .filter(|p| {
                    item.delivered_to.contains(p)
                        && item.voice_transfer_id.is_some()
                        && !item.voice_delivered_to.contains(p)
                })
                .collect();
            let voice_path = item.voice_path.clone().or_else(|| {
                item.voice_transfer_id.and_then(|vtid| {
                    self.resolve_voice_path(&transfer_id_to_hex(&vtid))
                        .map(|p| p.display().to_string())
                })
            });
            if let Some(slot) = self
                .pending_group_sends
                .iter_mut()
                .find(|p| p.message_id == item.message_id)
            {
                slot.last_send_at = now;
                slot.attempts = slot.attempts.saturating_add(1);
                if slot.voice_path.is_none() {
                    slot.voice_path = voice_path.clone();
                }
            }
            let _ = self.command_tx.try_send(UICommand::SendGroupMessage {
                sender_name: self.local_nickname.clone(),
                text: item.text.clone(),
                group_id: item.group_id.clone(),
                members: targets,
                message_id: Some(item.message_id.clone()),
                is_retry: true,
                voice_path,
                voice_duration_secs: item.voice_duration_secs,
                voice_transfer_id: item.voice_transfer_id,
                voice_only_members,
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

    /// Убирает из контактов автоматически обнаруженные DHT/mDNS-узлы без переписки.
    fn prune_auto_discovered_contacts(&mut self) {
        let me = self.local_peer_id.to_string();
        let msgs = self.messages.lock();
        let to_remove: Vec<PeerId> = self
            .known_peers
            .iter()
            .filter_map(|(pid, name)| {
                if *pid == self.local_peer_id {
                    return Some(*pid);
                }
                let pid_str = pid.to_string();
                let auto_name = format!("Peer_{}", &pid_str[..8.min(pid_str.len())]);
                if name != &auto_name {
                    return None;
                }
                if msgs.contains_key(&pid_str) && msgs.get(&pid_str).is_some_and(|v| !v.is_empty()) {
                    return None;
                }
                let in_group = self.groups.values().any(|g| {
                    g.members.iter().any(|m| m.peer_id == pid_str)
                });
                if in_group {
                    return None;
                }
                Some(*pid)
            })
            .collect();
        drop(msgs);
        if to_remove.is_empty() {
            return;
        }
        for pid in to_remove {
            if pid.to_string() == me {
                continue;
            }
            self.known_peers.remove(&pid);
            self.contact_addrs.remove(&pid);
        }
        self.persist_vault();
    }

    /// Личный чат не выбран — открываем только существующий контакт.
    pub(crate) fn select_peer_if_no_chat(&mut self, peer_id: PeerId) {
        if !self.selected_chat.is_empty() {
            return;
        }
        if !self.known_peers.contains_key(&peer_id) {
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

    fn group_peer_needs_resend(p: &PendingGroupSend, peer: PeerId, me: PeerId) -> bool {
        if peer == me || !p.members.contains(&peer) {
            return false;
        }
        if !p.delivered_to.contains(&peer) {
            return true;
        }
        p.voice_transfer_id.is_some() && !p.voice_delivered_to.contains(&peer)
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
            OutboxEntry::DirectVoice {
                peer: p1,
                message_id: id1,
                ..
            },
            OutboxEntry::DirectVoice {
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
            OutboxEntry::GroupVoice {
                message_id: id1, ..
            },
            OutboxEntry::GroupVoice {
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
