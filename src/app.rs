//! Состояние приложения, vault unlock и логика повторной отправки.

use std::collections::HashMap;
use std::path::Path;
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

use crate::chat_store::ChatJournal;
use crate::crypto;
use crate::file_transfer;
use crate::network::{run_chat_network, NetworkEvent, UICommand};
use crate::protocol::{new_message_id, ChatMessage, FileTransferProgress};
use crate::ui::{setup_custom_style, truncate_text, Toast, ToastKind, TOAST_TTL_LONG, TOAST_TTL_SHORT};
use crate::vault::{AddressBookEntry, Storage, VaultUnlockKind, VaultUnlockState};

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

/// Синхронное уведомление UI о missing в delete_ack (минуя tokio — надёжно на Windows).
#[derive(Clone, Debug)]
pub(crate) struct DeleteNotify {
    pub peer: PeerId,
    pub missing: Vec<String>,
}

/// Параметры отложенного запуска сетевого таска после разблокировки vault.
pub(crate) struct DeferredNetworkSpawn {
    pub event_tx: mpsc::Sender<NetworkEvent>,
    pub command_rx: mpsc::Receiver<UICommand>,
    pub command_tx_for_mdns: mpsc::Sender<UICommand>,
    pub void_bootstraps: Vec<Multiaddr>,
    pub chat_messages: SharedChatMessages,
    pub delete_notify_tx: std::sync::mpsc::Sender<DeleteNotify>,
}

/// Сообщение в очереди ожидания доставки. Если в течение `RESEND_GRACE` после
/// последней попытки прилетел `SendFailedDial` (или просто прошло столько же
/// времени без подтверждения), запускаем DHT-lookup и через `RESEND_DELAY`
/// отправляем повторно. После `MAX_ATTEMPTS` попыток сдаёмся с toast'ом.
pub(crate) struct PendingSend {
    pub(crate) peer: PeerId,
    pub(crate) text: String,
    pub(crate) message_id: String,
    pub(crate) last_send_at: Instant,
    pub(crate) dht_kicked: bool,
    pub(crate) dht_kicked_at: Option<Instant>,
    pub(crate) attempts: u8,
    /// Сообщение ждёт E2EE-хендшейк — не запускаем таймаут доставки.
    pub(crate) awaiting_session: bool,
}

pub(crate) const RESEND_GRACE: Duration = Duration::from_secs(3);
pub(crate) const RESEND_DELAY: Duration = Duration::from_secs(5);
pub(crate) const MAX_ATTEMPTS: u8 = 2;

/// Область удаления. Для чужих сообщений допустим только `LocalOnly`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeleteScope {
    LocalOnly,
    RemoteOnly,
    Both,
}

pub(crate) struct App {
    pub(crate) local_peer_id: PeerId,
    pub(crate) local_nickname: String,
    pub(crate) listen_addrs: Vec<String>,
    pub(crate) connected_peers: usize,
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
    pub(crate) dht_routing_lines: Vec<String>,
    pub(crate) dht_routing_total: usize,
    pub(crate) command_tx: mpsc::Sender<UICommand>,
    pub(crate) event_rx: mpsc::Receiver<NetworkEvent>,
    pub(crate) delete_notify_rx: std::sync::mpsc::Receiver<DeleteNotify>,
    /// Короткие баннеры в чате (надёжнее toast на Windows).
    pub(crate) delete_banners: Vec<(Instant, String)>,
    pub(crate) _sessions: HashMap<libp2p::PeerId, crypto::SecureSession>,
    pub(crate) _local_static: crypto::StaticSecret,
    pub(crate) pending_sends: Vec<PendingSend>,
    pub(crate) toasts: Vec<Toast>,
    pub(crate) chat_bg_texture: Option<egui::TextureHandle>,
    // ─── Файловый sub-протокол ──────────────────────────────────────────────
    /// Входящие предложения файлов, ожидающие ответа пользователя.
    pub(crate) incoming_file_offers: Vec<file_transfer::PendingFileOffer>,
    /// Активные передачи (исходящие и входящие).
    pub(crate) active_file_transfers: HashMap<[u8; 16], FileTransferProgress>,
    /// Флаг: показывать popup-меню выбора типа вложения.
    pub(crate) show_attach_menu: bool,
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
        command_tx: mpsc::Sender<UICommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
        delete_notify_rx: std::sync::mpsc::Receiver<DeleteNotify>,
        chat_messages: SharedChatMessages,
    ) -> Self {
        setup_custom_style(&cc.egui_ctx);

        Self {
            local_peer_id,
            local_nickname,
            listen_addrs: Vec::new(),
            connected_peers: 0,
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
            void_bootstrap_draft: std::fs::read_to_string(Path::new("void-bootstrap.txt"))
                .unwrap_or_default(),
            dht_routing_lines: Vec::new(),
            dht_routing_total: 0,
            command_tx,
            event_rx,
            delete_notify_rx,
            delete_banners: Vec::new(),
            _sessions: HashMap::new(),
            _local_static: local_static,
            pending_sends: Vec::new(),
            toasts: Vec::new(),
            chat_bg_texture: None,
            incoming_file_offers: Vec::new(),
            active_file_transfers: HashMap::new(),
            show_attach_menu: false,
            pending_accept: None,
            pending_unlock,
            deferred_network_spawn,
            vault_master_key,
        }
    }

    /// Экран разблокировки vault. Возвращает `true`, пока нужно блокировать основной UI.
    pub(crate) fn vault_unlock_gate(&mut self, ctx: &egui::Context) -> bool {
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

    fn submit_vault_unlock(&mut self, ctx: &egui::Context) {
        let Some(mut pending) = self.pending_unlock.take() else {
            return;
        };
        pending.error = None;
        let pwd = pending.password.trim();
        let pwd2 = pending.password_confirm.trim();
        let require_confirm = matches!(
            pending.kind,
            VaultUnlockKind::CreateProfile | VaultUnlockKind::MigratePlainMaster(_),
        );

        if pwd.len() < 8 {
            pending.error = Some("Укажите пароль не короче 8 символов.".into());
            self.pending_unlock = Some(pending);
            return;
        }
        if require_confirm && pwd != pwd2 {
            pending.error = Some("Пароли не совпадают.".into());
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
                    pending.password.zeroize();
                    pending.password_confirm.zeroize();
                    pending.error = Some(format!("{}", e));
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

        pending.password.zeroize();
        pending.password_confirm.zeroize();
        drop(pending);

        let Some(dn_sp) = self.deferred_network_spawn.take() else {
            self.pending_unlock = Some(VaultUnlockState {
                kind: kind_followup,
                password: String::new(),
                password_confirm: String::new(),
                error: Some("Внутренняя ошибка: параметры сети недоступны.".into()),
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
                        });
                        self.deferred_network_spawn = Some(dn_sp);
                        return;
                    }
                };
                let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
                let my_id = PeerId::from(local_key.public());
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
                tokio::spawn(run_chat_network(
                    dn_sp.command_rx,
                    dn_sp.event_tx,
                    dn_sp.command_tx_for_mdns,
                    local_key.clone(),
                    static_secret.clone(),
                    dn_sp.void_bootstraps,
                    contact_addrs_flat,
                    dn_sp.chat_messages.clone(),
                    dn_sp.delete_notify_tx.clone(),
                ));
                self.apply_unlock_success(
                    ctx,
                    local_key,
                    storage.nickname,
                    static_secret,
                    book,
                    addrs_map,
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
                ) {
                    let _ = std::fs::remove_file(Storage::KEY_FILE);
                    self.pending_unlock = Some(VaultUnlockState {
                        kind: VaultUnlockKind::CreateProfile,
                        password: String::new(),
                        password_confirm: String::new(),
                        error: Some(format!("Не удалось создать vault: {}", e)),
                    });
                    self.deferred_network_spawn = Some(dn_sp);
                    return;
                }

                tokio::spawn(run_chat_network(
                    dn_sp.command_rx,
                    dn_sp.event_tx,
                    dn_sp.command_tx_for_mdns,
                    local_key.clone(),
                    static_secret.clone(),
                    dn_sp.void_bootstraps,
                    Vec::new(),
                    dn_sp.chat_messages.clone(),
                    dn_sp.delete_notify_tx.clone(),
                ));

                self.apply_unlock_success(
                    ctx,
                    local_key,
                    nickname,
                    static_secret,
                    HashMap::new(),
                    HashMap::new(),
                    master_arr,
                );
            }
        }
    }

    fn apply_unlock_success(
        &mut self,
        ctx: &egui::Context,
        local_key: libp2p::identity::Keypair,
        nickname: String,
        static_secret: crypto::StaticSecret,
        book: HashMap<PeerId, String>,
        addrs_map: HashMap<PeerId, Vec<Multiaddr>>,
        master_arr: Zeroizing<[u8; 32]>,
    ) {
        self.local_peer_id = PeerId::from(local_key.public());
        self.local_nickname = nickname;
        self.known_peers = book;
        self.contact_addrs = addrs_map;
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

    pub(crate) fn ingest_chat_message(&mut self, mut msg: ChatMessage) {
        if msg.id.is_empty() {
            msg.id = new_message_id();
        }

        let bucket = if let Some(ref target) = msg.recipient_id {
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
            self.messages.lock().entry(b).or_default().push(msg);
            self.mark_chat_journal_dirty();
        }
    }

    pub(crate) fn delete_messages(
        &mut self,
        peer: PeerId,
        message_ids: &[String],
        scope: DeleteScope,
    ) {
        if message_ids.is_empty() {
            return;
        }
        let peer_str = peer.to_string();
        let me = self.local_peer_id.to_string();

        let remote_ids: Vec<String> = self
            .messages
            .lock()
            .get(&peer_str)
            .map(|msgs| {
                msgs.iter()
                    .filter(|m| message_ids.contains(&m.id) && m.sender_id == me)
                    .map(|m| m.id.clone())
                    .collect()
            })
            .unwrap_or_default();

        if matches!(scope, DeleteScope::LocalOnly | DeleteScope::Both) {
            if let Some(msgs) = self.messages.lock().get_mut(&peer_str) {
                msgs.retain(|m| !message_ids.contains(&m.id));
            }
            self.mark_chat_journal_dirty();
        }

        if matches!(scope, DeleteScope::RemoteOnly | DeleteScope::Both) && !remote_ids.is_empty() {
            let _ = self.command_tx.try_send(UICommand::DeleteMessages {
                recipient: peer,
                message_ids: remote_ids,
            });
        }
    }

    pub(crate) fn delete_conversation_local(&mut self, peer: PeerId) {
        let peer_str = peer.to_string();
        self.messages.lock().remove(&peer_str);
        self.mark_chat_journal_dirty();
    }

    pub(crate) fn delete_own_messages(&mut self, peer: PeerId, scope: DeleteScope) {
        let peer_str = peer.to_string();
        let me = self.local_peer_id.to_string();
        let ids: Vec<String> = self
            .messages
            .lock()
            .get(&peer_str)
            .map(|v| {
                v.iter()
                    .filter(|m| m.sender_id == me)
                    .map(|m| m.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        self.delete_messages(peer, &ids, scope);
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
        ) {
            warn!("VOID: не удалось сохранить vault (записная книга): {}", e);
        }
    }

    /// Машина состояний для повторных отправок: 3 сек ждём DialFailure / тишину →
    /// дёргаем `SearchPeer` (kad.get_closest_peers), 5 сек ждём → ретраим
    /// `SendMessage`. После `MAX_ATTEMPTS` попыток — toast и снимаем.
    pub(crate) fn tick_pending_sends(&mut self) {
        let now = Instant::now();
        let mut to_drop: Vec<usize> = Vec::new();
        let mut search_cmds: Vec<PeerId> = Vec::new();
        let mut resend_cmds: Vec<(PeerId, String, String)> = Vec::new();
        let mut toasts: Vec<(String, ToastKind, Duration)> = Vec::new();

        for (idx, p) in self.pending_sends.iter_mut().enumerate() {
            if p.awaiting_session {
                continue;
            }
            // Финальная сдача — после исчерпания попыток.
            if p.attempts >= MAX_ATTEMPTS {
                if let Some(kicked_at) = p.dht_kicked_at {
                    if now.duration_since(kicked_at) >= RESEND_DELAY {
                        let name_short = format!("{}…", &p.peer.to_string()[..10]);
                        toasts.push((
                            format!(
                                "✖ Не удалось доставить «{}» пиру {}",
                                truncate_text(&p.text, 32),
                                name_short
                            ),
                            ToastKind::Error,
                            TOAST_TTL_LONG,
                        ));
                        to_drop.push(idx);
                    }
                }
                continue;
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

            // Фаза 2: после DHT-поиска ждём `RESEND_DELAY` и шлём повторно.
            if let Some(kicked_at) = p.dht_kicked_at {
                if now.duration_since(kicked_at) >= RESEND_DELAY {
                    resend_cmds.push((p.peer, p.text.clone(), p.message_id.clone()));
                    p.attempts = p.attempts.saturating_add(1);
                    p.last_send_at = now;
                    p.dht_kicked = false;
                    p.dht_kicked_at = None;

                    if p.attempts >= MAX_ATTEMPTS {
                        // Сразу запустим финальный таймер «сдачи» (см. ветку выше
                        // — сработает, когда снова пройдёт RESEND_DELAY).
                        p.dht_kicked_at = Some(now);
                    } else {
                        let name_short = format!("{}…", &p.peer.to_string()[..10]);
                        toasts.push((
                            format!(
                                "↻ Повтор #{} → {}",
                                p.attempts,
                                name_short
                            ),
                            ToastKind::Warn,
                            TOAST_TTL_SHORT,
                        ));
                    }
                }
            }
        }

        // Удаляем сданные (с конца, чтобы индексы не съехали).
        for idx in to_drop.iter().rev() {
            self.pending_sends.swap_remove(*idx);
        }

        // Применяем накопленные команды и toast'ы (борем borrow checker).
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
