//! Headless runtime for Tauri (and other non-egui frontends).
//! Owns vault unlock, network spawn, journal/outbox, and UI snapshots.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self as std_mpsc, Receiver as StdReceiver, Sender as StdSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::bootstrap::{
    merge_bootstrap_string_lists, migrate_void_bootstrap_txt, parse_seed_input,
    peer_id_from_multiaddr, void_bootstrap_multiaddrs,
};
use crate::chat_store::ChatJournal;
use crate::crypto;
use crate::file_transfer;
use crate::group::{
    self, build_invite_link, dedupe_members, group_thread_key, parse_invite_link, GroupChat,
    GroupMember,
};
use crate::network::{run_chat_network, NetworkEvent, OfflineOutboxItem, UICommand};
use crate::offline_mail::open_envelope;
use crate::outbox::{Outbox, OutboxEntry};
use crate::protocol::{new_message_id, ChatMessage, OutgoingDeliveryStatus};
use crate::shared_chat::SharedChatMessages;
use crate::vault::{
    clear_remembered_password, detect_vault_unlock_kind, load_remembered_password,
    save_remembered_password, AddressBookEntry, Storage, VaultUnlockKind,
};
use crate::voice::VoiceRecorder;

const RESEND_GRACE: Duration = Duration::from_secs(1);
const RESEND_DELAY_BASE: Duration = Duration::from_secs(2);
const RESEND_DELAY_MAX: Duration = Duration::from_secs(300);
const SESSION_WAIT_TIMEOUT: Duration = Duration::from_secs(20);
const OFFLINE_DHT_PUBLISH_DEBOUNCE: Duration = Duration::from_millis(200);

fn resend_delay_for_attempt(attempts: u32) -> Duration {
    let exp = attempts.min(6);
    let secs = RESEND_DELAY_BASE.as_secs().saturating_mul(1u64 << exp);
    Duration::from_secs(secs.min(RESEND_DELAY_MAX.as_secs()))
}

/// Outgoing DM waiting for live delivery / DHT / offline handoff (egui parity).
struct PendingSend {
    peer: PeerId,
    text: String,
    message_id: String,
    last_send_at: Instant,
    dht_kicked: bool,
    dht_kicked_at: Option<Instant>,
    attempts: u32,
    awaiting_session: bool,
}

fn bootstrap_peer_ids(bootstraps: &[String]) -> HashSet<PeerId> {
    bootstraps
        .iter()
        .filter_map(|s| s.parse::<Multiaddr>().ok())
        .filter_map(|ma| peer_id_from_multiaddr(&ma))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKindDto {
    CreateProfile,
    OpenWrappedKey,
    MigratePlainMaster,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatusDto {
    pub kind: VaultKindDto,
    pub has_remembered_password: bool,
    pub unlocked: bool,
    pub beacon_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactDto {
    pub peer_id: String,
    pub display_name: String,
    pub online: bool,
    pub last_preview: String,
    pub is_group: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDto {
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub text: String,
    pub timestamp: String,
    pub delivery: String,
    pub outgoing: bool,
    pub voice_transfer_id: Option<String>,
    pub voice_duration_secs: Option<f32>,
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDto {
    pub id: String,
    pub name: String,
    pub creator_id: String,
    pub members: Vec<GroupMemberDto>,
    pub invite_link: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberDto {
    pub peer_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOfferDto {
    pub transfer_id: String,
    pub from: String,
    pub filename: String,
    pub total_size: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDto {
    pub unlocked: bool,
    pub nickname: String,
    pub peer_id: String,
    pub public_ip: Option<String>,
    /// Chat contacts currently connected (bootstrap nodes excluded).
    pub connected_peers: usize,
    /// How many configured VOID bootstrap nodes are currently connected.
    pub bootstrap_connected: usize,
    /// True if at least one bootstrap is up, or a chat peer is connected.
    pub network_ok: bool,
    pub listen_addrs: Vec<String>,
    pub selected_chat: String,
    pub contacts: Vec<ContactDto>,
    pub messages: Vec<MessageDto>,
    pub bootstraps: Vec<String>,
    pub groups: Vec<GroupDto>,
    pub status_log: Vec<String>,
    pub dht_lines: Vec<String>,
    pub dht_total: usize,
    pub beacon_active: bool,
    pub incoming_files: Vec<FileOfferDto>,
    pub voice_recording: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BridgeEvent {
    Snapshot(SnapshotDto),
    Status { text: String },
    Message { chat_id: String },
    Peer { peer_id: String, online: bool },
    Bootstraps { addrs: Vec<String> },
    FileOffer(FileOfferDto),
    FileProgress {
        transfer_id: String,
        sent_chunks: u32,
        total_chunks: u32,
        filename: String,
    },
    FileComplete {
        transfer_id: String,
        filename: String,
        saved_to: String,
    },
}

struct Inner {
    unlocked: bool,
    beacon_active: bool,
    local_peer_id: Option<PeerId>,
    local_nickname: String,
    vault_master_key: Option<Zeroizing<[u8; 32]>>,
    local_static: Option<crypto::StaticSecret>,
    command_tx: Option<mpsc::Sender<UICommand>>,
    messages: SharedChatMessages,
    known_peers: HashMap<PeerId, String>,
    contact_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    connected_peer_ids: HashSet<PeerId>,
    connected_peers: usize,
    listen_addrs: Vec<String>,
    public_ip: Option<String>,
    selected_chat: String,
    void_bootstrap_strings: Vec<String>,
    groups: HashMap<String, GroupChat>,
    left_groups: HashSet<String>,
    status_log: Vec<String>,
    dht_lines: Vec<String>,
    dht_total: usize,
    peer_prekeys: HashMap<PeerId, [u8; 32]>,
    outbox_entries: Vec<OutboxEntry>,
    incoming_file_offers: Vec<FileOfferDto>,
    voice_recorder: VoiceRecorder,
    voice_recording: bool,
    pending_sends: Vec<PendingSend>,
    offline_dht_publish_after: Option<Instant>,
    offline_mail_processed: HashSet<String>,
}

impl Inner {
    fn new(messages: SharedChatMessages) -> Self {
        Self {
            unlocked: false,
            beacon_active: false,
            local_peer_id: None,
            local_nickname: String::new(),
            vault_master_key: None,
            local_static: None,
            command_tx: None,
            messages,
            known_peers: HashMap::new(),
            contact_addrs: HashMap::new(),
            connected_peer_ids: HashSet::new(),
            connected_peers: 0,
            listen_addrs: Vec::new(),
            public_ip: None,
            selected_chat: String::new(),
            void_bootstrap_strings: Vec::new(),
            groups: HashMap::new(),
            left_groups: HashSet::new(),
            status_log: Vec::new(),
            dht_lines: Vec::new(),
            dht_total: 0,
            peer_prekeys: HashMap::new(),
            outbox_entries: Vec::new(),
            incoming_file_offers: Vec::new(),
            voice_recorder: VoiceRecorder::new(),
            voice_recording: false,
            pending_sends: Vec::new(),
            offline_dht_publish_after: None,
            offline_mail_processed: HashSet::new(),
        }
    }

    fn recount_connected(&mut self) {
        let boots = bootstrap_peer_ids(&self.void_bootstrap_strings);
        self.connected_peers = self
            .connected_peer_ids
            .iter()
            .filter(|p| !boots.contains(p))
            .count();
    }

    fn bootstrap_connected_count(&self) -> usize {
        let boots = bootstrap_peer_ids(&self.void_bootstrap_strings);
        self.connected_peer_ids
            .iter()
            .filter(|p| boots.contains(p))
            .count()
    }

    fn schedule_offline_publish(&mut self) {
        if self.outbox_entries.is_empty() {
            return;
        }
        self.offline_dht_publish_after =
            Some(Instant::now() + OFFLINE_DHT_PUBLISH_DEBOUNCE);
    }

    fn accelerate_offline_publish(&mut self) {
        if !self.outbox_entries.is_empty() {
            self.offline_dht_publish_after = Some(Instant::now());
        }
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

    fn complete_pending_send(&mut self, peer: PeerId, message_id: &str) {
        self.pending_sends
            .retain(|p| !(p.peer == peer && p.message_id == message_id));
        self.remove_outbox_direct(&peer.to_string(), message_id);
    }

    fn build_offline_publish_items(&self) -> Vec<OfflineOutboxItem> {
        let Some(me) = self.local_peer_id else {
            return Vec::new();
        };
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
                                message_id: format!("{message_id}:{peer_str}"),
                                kind: "group".into(),
                                payload,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        items
    }

    fn publish_outbox_to_dht(&self) {
        let items = self.build_offline_publish_items();
        if items.is_empty() {
            return;
        }
        if let Some(tx) = &self.command_tx {
            if let Err(e) = tx.try_send(UICommand::PublishOfflineOutbox {
                items,
                ack: None,
            }) {
                warn!("VOID: PublishOfflineOutbox queue full/closed: {e}");
            }
        }
    }

    fn ensure_peer_routed(&self, peer: PeerId) {
        let Some(tx) = &self.command_tx else {
            return;
        };
        let _ = tx.try_send(UICommand::SearchPeer(peer));
        if let Some(addrs) = self.contact_addrs.get(&peer) {
            if !addrs.is_empty() {
                let _ = tx.try_send(UICommand::DialPeer(peer, addrs.clone()));
            }
        }
    }

    fn push_pending_send(&mut self, peer: PeerId, text: String, message_id: String) {
        if self
            .pending_sends
            .iter()
            .any(|p| p.peer == peer && p.message_id == message_id)
        {
            return;
        }
        self.pending_sends.push(PendingSend {
            peer,
            text,
            message_id,
            last_send_at: Instant::now(),
            dht_kicked: false,
            dht_kicked_at: None,
            attempts: 0,
            awaiting_session: false,
        });
    }

    fn ingest_offline_mailbox(&mut self, envelopes: Vec<crate::offline_mail::OfflineEnvelope>) {
        let Some(ref secret) = self.local_static else {
            return;
        };
        let mut any = false;
        for env in envelopes {
            if self.offline_mail_processed.contains(&env.message_id) {
                continue;
            }
            let Ok(plaintext) = open_envelope(secret, &env) else {
                continue;
            };
            match env.kind.as_str() {
                "dm" | "group" => {
                    let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) else {
                        continue;
                    };
                    let chat_id = msg
                        .group_id
                        .as_ref()
                        .map(|id| group_thread_key(id))
                        .or_else(|| {
                            let local = self.local_peer_id.map(|p| p.to_string())?;
                            if msg.sender_id == local {
                                msg.recipient_id.clone()
                            } else {
                                Some(msg.sender_id.clone())
                            }
                        })
                        .unwrap_or_else(|| msg.sender_id.clone());
                    if !self.messages.is_deleted(&msg.id) {
                        let mut map = self.messages.lock();
                        let list = map.entry(chat_id).or_default();
                        if !list.iter().any(|m| m.id == msg.id) {
                            list.push(msg);
                            drop(map);
                            self.messages.mark_dirty();
                            self.persist_journal();
                            any = true;
                        }
                    }
                    self.offline_mail_processed.insert(env.message_id);
                }
                _ => {}
            }
        }
        if any {
            self.add_status("Получена офлайн-почта".into());
        }
    }

    fn tick_pending_sends(&mut self) {
        let now = Instant::now();
        let mut search_cmds: Vec<PeerId> = Vec::new();
        let mut resend_cmds: Vec<(PeerId, String, String)> = Vec::new();
        let nick = self.local_nickname.clone();

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

            if !p.dht_kicked && now.duration_since(p.last_send_at) >= RESEND_GRACE {
                search_cmds.push(p.peer);
                p.dht_kicked = true;
                p.dht_kicked_at = Some(now);
            }

            if let Some(kicked_at) = p.dht_kicked_at {
                let delay = resend_delay_for_attempt(p.attempts);
                if now.duration_since(kicked_at) >= delay {
                    resend_cmds.push((p.peer, p.text.clone(), p.message_id.clone()));
                    p.attempts = p.attempts.saturating_add(1);
                    p.last_send_at = now;
                    p.dht_kicked = false;
                    p.dht_kicked_at = None;
                }
            }
        }

        if let Some(tx) = &self.command_tx {
            for peer in search_cmds {
                let _ = tx.try_send(UICommand::SearchPeer(peer));
                if let Some(addrs) = self.contact_addrs.get(&peer) {
                    if !addrs.is_empty() {
                        let _ = tx.try_send(UICommand::DialPeer(peer, addrs.clone()));
                    }
                }
            }
            for (peer, text, message_id) in resend_cmds {
                let _ = tx.try_send(UICommand::SendMessage {
                    sender_name: nick.clone(),
                    text,
                    recipient: Some(peer),
                    message_id: Some(message_id),
                    is_retry: true,
                });
            }
        }

        if let Some(deadline) = self.offline_dht_publish_after {
            if Instant::now() >= deadline {
                self.offline_dht_publish_after = None;
                self.publish_outbox_to_dht();
            }
        }
    }

    fn add_status(&mut self, text: String) {
        info!("{text}");
        self.status_log.push(text);
        if self.status_log.len() > 200 {
            let drop_n = self.status_log.len() - 200;
            self.status_log.drain(0..drop_n);
        }
    }

    fn persist_vault(&self) {
        let Some(ref key) = self.vault_master_key else {
            return;
        };
        let mut entries: Vec<AddressBookEntry> = self
            .known_peers
            .iter()
            .map(|(pid, name)| {
                let addrs = self
                    .contact_addrs
                    .get(pid)
                    .map(|v| v.iter().map(|a| a.to_string()).collect())
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
        let groups: Vec<GroupChat> = self.groups.values().cloned().collect();
        let left: Vec<String> = self.left_groups.iter().cloned().collect();
        if let Err(e) = Storage::save(
            key,
            &self.local_nickname,
            None,
            None,
            Some(&entries),
            Some(&self.void_bootstrap_strings),
            Some(&groups),
            Some(&left),
        ) {
            warn!("VOID bridge: persist vault: {e}");
        }
    }

    fn persist_journal(&self) {
        let Some(ref key) = self.vault_master_key else {
            return;
        };
        let threads = self.messages.lock().clone();
        let deleted = self.messages.deleted_snapshot();
        if let Err(e) = ChatJournal::save(key, &threads, &deleted) {
            warn!("VOID bridge: persist journal: {e}");
        }
        let _ = self.messages.take_dirty();
    }

    fn persist_outbox(&self) {
        let Some(ref key) = self.vault_master_key else {
            return;
        };
        if let Err(e) = Outbox::save(key, &self.outbox_entries) {
            warn!("VOID bridge: persist outbox: {e}");
        }
    }

    fn merge_learned_bootstraps(&mut self, learned: Vec<String>) {
        let before = self.void_bootstrap_strings.len();
        let merged = merge_bootstrap_string_lists(&self.void_bootstrap_strings, &learned);
        if merged.len() != before {
            self.void_bootstrap_strings = merged;
            self.persist_vault();
            self.add_status(format!(
                "Vault: {} bootstrap-узл(ов)",
                self.void_bootstrap_strings.len()
            ));
        }
    }

    fn preview_for(&self, chat_id: &str) -> String {
        self.messages
            .lock()
            .get(chat_id)
            .and_then(|v| v.last())
            .map(|m| {
                if m.voice.is_some() {
                    "Голосовое сообщение".into()
                } else if m.text.chars().count() > 48 {
                    let t: String = m.text.chars().take(48).collect();
                    format!("{t}…")
                } else {
                    m.text.clone()
                }
            })
            .unwrap_or_default()
    }

    fn snapshot(&self) -> SnapshotDto {
        let mut contacts: Vec<ContactDto> = self
            .known_peers
            .iter()
            .map(|(pid, name)| {
                let id = pid.to_string();
                ContactDto {
                    peer_id: id.clone(),
                    display_name: name.clone(),
                    online: self.connected_peer_ids.contains(pid),
                    last_preview: self.preview_for(&id),
                    is_group: false,
                }
            })
            .collect();
        for g in self.groups.values() {
            let key = group_thread_key(&g.id);
            contacts.push(ContactDto {
                peer_id: key.clone(),
                display_name: g.name.clone(),
                online: false,
                last_preview: self.preview_for(&key),
                is_group: true,
            });
        }
        contacts.sort_by(|a, b| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        });

        let local_id = self
            .local_peer_id
            .map(|p| p.to_string())
            .unwrap_or_default();
        let messages = if self.selected_chat.is_empty() {
            Vec::new()
        } else {
            self.messages
                .lock()
                .get(&self.selected_chat)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|m| MessageDto {
                    outgoing: m.sender_id == local_id,
                    delivery: match m.delivery {
                        OutgoingDeliveryStatus::Pending => "pending".into(),
                        OutgoingDeliveryStatus::Delivered => "delivered".into(),
                        OutgoingDeliveryStatus::Read => "read".into(),
                    },
                    voice_transfer_id: m.voice.as_ref().map(|v| v.transfer_id.clone()),
                    voice_duration_secs: m.voice.as_ref().map(|v| v.duration_secs),
                    group_id: m.group_id.clone(),
                    id: m.id,
                    sender_id: m.sender_id,
                    sender_name: m.sender_name,
                    text: m.text,
                    timestamp: m.timestamp,
                })
                .collect()
        };

        let groups: Vec<GroupDto> = self
            .groups
            .values()
            .map(|g| GroupDto {
                invite_link: build_invite_link(g),
                members: g
                    .members
                    .iter()
                    .map(|m| GroupMemberDto {
                        peer_id: m.peer_id.clone(),
                        display_name: m.display_name.clone(),
                    })
                    .collect(),
                id: g.id.clone(),
                name: g.name.clone(),
                creator_id: g.creator_id.clone(),
            })
            .collect();

        SnapshotDto {
            unlocked: self.unlocked,
            nickname: self.local_nickname.clone(),
            peer_id: local_id,
            public_ip: self.public_ip.clone(),
            connected_peers: self.connected_peers,
            bootstrap_connected: {
                let n = self.bootstrap_connected_count();
                n
            },
            network_ok: self.bootstrap_connected_count() > 0 || self.connected_peers > 0,
            listen_addrs: self.listen_addrs.clone(),
            selected_chat: self.selected_chat.clone(),
            contacts,
            messages,
            bootstraps: self.void_bootstrap_strings.clone(),
            groups,
            status_log: self.status_log.clone(),
            dht_lines: self.dht_lines.clone(),
            dht_total: self.dht_total,
            beacon_active: self.beacon_active,
            incoming_files: self.incoming_file_offers.clone(),
            voice_recording: self.voice_recording,
        }
    }
}

/// Shared handle for Tauri commands.
#[derive(Clone)]
pub struct VoidRuntime {
    inner: Arc<Mutex<Inner>>,
    event_tx: mpsc::Sender<NetworkEvent>,
    /// Outbound bridge events for the frontend (optional consumer).
    pub bridge_events: Arc<Mutex<StdReceiver<BridgeEvent>>>,
    bridge_tx: StdSender<BridgeEvent>,
    network_started: Arc<AtomicBool>,
    tokio_handle: tokio::runtime::Handle,
}

impl VoidRuntime {
    pub fn new() -> Self {
        let handle = tokio::runtime::Handle::current();
        let (event_tx, event_rx) = mpsc::channel(1024);
        let (bridge_tx, bridge_rx) = std_mpsc::channel();
        let messages = SharedChatMessages::new();
        let inner = Arc::new(Mutex::new(Inner::new(messages.clone())));

        let rt = Self {
            inner: inner.clone(),
            event_tx: event_tx.clone(),
            bridge_events: Arc::new(Mutex::new(bridge_rx)),
            bridge_tx: bridge_tx.clone(),
            network_started: Arc::new(AtomicBool::new(false)),
            tokio_handle: handle.clone(),
        };

        // Event pump: NetworkEvent → state + BridgeEvent
        let pump_inner = inner.clone();
        let pump_bridge = bridge_tx;
        handle.spawn(async move {
            let mut event_rx = event_rx;
            while let Some(ev) = event_rx.recv().await {
                let mut emit_snapshot = false;
                let mut bridge_evs = Vec::new();
                {
                    let mut g = pump_inner.lock().unwrap_or_else(|p| p.into_inner());
                    match ev {
                        NetworkEvent::NewListenAddr(a) => {
                            let s = a.to_string();
                            if !g.listen_addrs.contains(&s) {
                                g.listen_addrs.push(s);
                            }
                            emit_snapshot = true;
                        }
                        NetworkEvent::Connected(pid) => {
                            g.connected_peer_ids.insert(pid);
                            g.recount_connected();
                            bridge_evs.push(BridgeEvent::Peer {
                                peer_id: pid.to_string(),
                                online: true,
                            });
                            emit_snapshot = true;
                        }
                        NetworkEvent::Disconnected(pid) | NetworkEvent::MdnsExpired(pid) => {
                            g.connected_peer_ids.remove(&pid);
                            g.recount_connected();
                            bridge_evs.push(BridgeEvent::Peer {
                                peer_id: pid.to_string(),
                                online: false,
                            });
                            emit_snapshot = true;
                        }
                        NetworkEvent::MdnsDiscovered(pid, addr) => {
                            g.contact_addrs.entry(pid).or_default().push(addr);
                        }
                        NetworkEvent::ChatMessage(msg) => {
                            let chat_id = msg
                                .group_id
                                .as_ref()
                                .map(|id| group_thread_key(id))
                                .or_else(|| {
                                    let local = g.local_peer_id.map(|p| p.to_string())?;
                                    if msg.sender_id == local {
                                        msg.recipient_id.clone()
                                    } else {
                                        Some(msg.sender_id.clone())
                                    }
                                })
                                .unwrap_or_else(|| msg.sender_id.clone());
                            if !g.messages.is_deleted(&msg.id) {
                                let mut map = g.messages.lock();
                                let list = map.entry(chat_id.clone()).or_default();
                                if !list.iter().any(|m| m.id == msg.id) {
                                    list.push(msg);
                                    drop(map);
                                    g.messages.mark_dirty();
                                    g.persist_journal();
                                }
                            }
                            bridge_evs.push(BridgeEvent::Message { chat_id });
                            emit_snapshot = true;
                        }
                        NetworkEvent::Status(text) => {
                            g.add_status(text.clone());
                            bridge_evs.push(BridgeEvent::Status { text });
                        }
                        NetworkEvent::PublicIpConfirmed(ip) => {
                            g.public_ip = Some(ip);
                            emit_snapshot = true;
                        }
                        NetworkEvent::DhtRoutingPeers { total, lines } => {
                            g.dht_total = total;
                            g.dht_lines = lines;
                            emit_snapshot = true;
                        }
                        NetworkEvent::PeerAddress(pid, addr) => {
                            let list = g.contact_addrs.entry(pid).or_default();
                            if !list.contains(&addr) {
                                list.push(addr);
                                g.persist_vault();
                            }
                        }
                        NetworkEvent::BootstrapsLearned(learned) => {
                            g.merge_learned_bootstraps(learned);
                            bridge_evs.push(BridgeEvent::Bootstraps {
                                addrs: g.void_bootstrap_strings.clone(),
                            });
                            emit_snapshot = true;
                        }
                        NetworkEvent::MessageDelivered { peer, message_id } => {
                            update_delivery(
                                &g.messages,
                                &peer.to_string(),
                                &message_id,
                                OutgoingDeliveryStatus::Delivered,
                            );
                            g.complete_pending_send(peer, &message_id);
                            emit_snapshot = true;
                        }
                        NetworkEvent::MessageAwaitingSession(peer) => {
                            for p in g.pending_sends.iter_mut().filter(|p| p.peer == peer) {
                                p.awaiting_session = true;
                                p.last_send_at = Instant::now();
                                p.dht_kicked = false;
                                p.dht_kicked_at = None;
                            }
                        }
                        NetworkEvent::MessageOnWire { peer, message_id } => {
                            if let Some(p) = g
                                .pending_sends
                                .iter_mut()
                                .find(|p| p.peer == peer && p.message_id == message_id)
                            {
                                p.awaiting_session = false;
                                p.last_send_at = Instant::now();
                            }
                        }
                        NetworkEvent::SendFailedDial(peer) => {
                            g.accelerate_offline_publish();
                            for p in g
                                .pending_sends
                                .iter_mut()
                                .filter(|p| p.peer == peer && !p.dht_kicked)
                            {
                                p.awaiting_session = false;
                                p.last_send_at = Instant::now()
                                    .checked_sub(RESEND_GRACE + Duration::from_millis(50))
                                    .unwrap_or_else(Instant::now);
                            }
                            if let Some(addrs) = g.contact_addrs.get(&peer) {
                                if !addrs.is_empty() {
                                    if let Some(tx) = &g.command_tx {
                                        let _ = tx.try_send(UICommand::DialPeer(
                                            peer,
                                            addrs.clone(),
                                        ));
                                    }
                                }
                            }
                            if let Some(tx) = &g.command_tx {
                                let _ = tx.try_send(UICommand::SearchPeer(peer));
                            }
                        }
                        NetworkEvent::OfflineMailbox(envelopes) => {
                            g.ingest_offline_mailbox(envelopes);
                            emit_snapshot = true;
                        }
                        NetworkEvent::MessageRead { peer, message_ids } => {
                            for id in message_ids {
                                update_delivery(
                                    &g.messages,
                                    &peer.to_string(),
                                    &id,
                                    OutgoingDeliveryStatus::Read,
                                );
                            }
                            emit_snapshot = true;
                        }
                        NetworkEvent::PeerPrekey { peer, public_key } => {
                            g.peer_prekeys.insert(peer, public_key);
                            g.persist_vault();
                        }
                        NetworkEvent::FileOffer {
                            transfer_id,
                            from,
                            filename,
                            total_size,
                            kind,
                        } => {
                            let dto = FileOfferDto {
                                transfer_id: hex::encode(transfer_id),
                                from: from.to_string(),
                                filename,
                                total_size,
                                kind: format!("{kind:?}"),
                            };
                            g.incoming_file_offers.push(dto.clone());
                            bridge_evs.push(BridgeEvent::FileOffer(dto));
                            emit_snapshot = true;
                        }
                        NetworkEvent::FileProgress {
                            transfer_id,
                            sent_chunks,
                            total_chunks,
                            filename,
                            ..
                        } => {
                            bridge_evs.push(BridgeEvent::FileProgress {
                                transfer_id: hex::encode(transfer_id),
                                sent_chunks,
                                total_chunks,
                                filename,
                            });
                        }
                        NetworkEvent::FileComplete {
                            transfer_id,
                            filename,
                            saved_to,
                            ..
                        } => {
                            let tid = hex::encode(transfer_id);
                            g.incoming_file_offers
                                .retain(|f| f.transfer_id != tid);
                            bridge_evs.push(BridgeEvent::FileComplete {
                                transfer_id: tid,
                                filename,
                                saved_to,
                            });
                            emit_snapshot = true;
                        }
                        NetworkEvent::FileError { reason, .. } => {
                            g.add_status(format!("Файл: {reason}"));
                            bridge_evs.push(BridgeEvent::Status {
                                text: reason,
                            });
                        }
                        NetworkEvent::PeerIsNotVoidChat(pid)
                        | NetworkEvent::SendFailedUnsupported(pid) => {
                            g.known_peers.remove(&pid);
                            g.contact_addrs.remove(&pid);
                            g.pending_sends.retain(|p| p.peer != pid);
                            g.persist_vault();
                            emit_snapshot = true;
                        }
                        NetworkEvent::GroupSync {
                            group_id,
                            group_name,
                            creator_id,
                            members,
                            ..
                        } => {
                            if !g.left_groups.contains(&group_id) {
                                g.groups.insert(
                                    group_id.clone(),
                                    GroupChat {
                                        id: group_id,
                                        name: group_name,
                                        creator_id,
                                        members,
                                        created_at: chrono::Local::now()
                                            .format("%Y-%m-%d %H:%M:%S")
                                            .to_string(),
                                    },
                                );
                                g.persist_vault();
                                emit_snapshot = true;
                            }
                        }
                        NetworkEvent::GroupLeave { group_id, peer_id, .. } => {
                            if let Some(gchat) = g.groups.get_mut(&group_id) {
                                gchat.members.retain(|m| m.peer_id != peer_id);
                                g.persist_vault();
                                emit_snapshot = true;
                            }
                        }
                        NetworkEvent::GroupDelete { group_id, .. } => {
                            g.groups.remove(&group_id);
                            g.left_groups.insert(group_id);
                            g.persist_vault();
                            emit_snapshot = true;
                        }
                        _ => {}
                    }
                    if emit_snapshot {
                        bridge_evs.push(BridgeEvent::Snapshot(g.snapshot()));
                    }
                }
                for ev in bridge_evs {
                    let _ = pump_bridge.send(ev);
                }
            }
        });

        // Delivery loop: DHT search → resend → offline outbox (egui parity).
        let tick_inner = inner.clone();
        handle.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(400));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let mut g = tick_inner.lock().unwrap_or_else(|p| p.into_inner());
                if g.unlocked && g.command_tx.is_some() {
                    g.tick_pending_sends();
                }
            }
        });

        rt
    }

    fn emit_snapshot(&self) {
        let snap = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshot();
        let _ = self.bridge_tx.send(BridgeEvent::Snapshot(snap));
    }

    pub fn vault_status(&self) -> Result<VaultStatusDto, String> {
        let kind = detect_vault_unlock_kind()?;
        let unlocked = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unlocked;
        let beacon = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .beacon_active;
        Ok(VaultStatusDto {
            kind: match kind {
                VaultUnlockKind::CreateProfile => VaultKindDto::CreateProfile,
                VaultUnlockKind::OpenWrappedKey => VaultKindDto::OpenWrappedKey,
                VaultUnlockKind::MigratePlainMaster(_) => VaultKindDto::MigratePlainMaster,
            },
            has_remembered_password: load_remembered_password().is_some(),
            unlocked,
            beacon_active: beacon,
        })
    }

    pub fn set_beacon_active(&self, active: bool) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .beacon_active = active;
        self.emit_snapshot();
    }

    pub fn get_snapshot(&self) -> SnapshotDto {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshot()
    }

    pub fn unlock(
        &self,
        password: String,
        password_confirm: Option<String>,
        remember: bool,
    ) -> Result<SnapshotDto, String> {
        let mut pwd = password;
        let kind = detect_vault_unlock_kind()?;
        let require_confirm = matches!(
            kind,
            VaultUnlockKind::CreateProfile | VaultUnlockKind::MigratePlainMaster(_)
        );
        if pwd.trim().len() < 8 {
            return Err("Укажите пароль не короче 8 символов.".into());
        }
        if require_confirm {
            let c = password_confirm.unwrap_or_default();
            if pwd.trim() != c.trim() {
                return Err("Пароли не совпадают.".into());
            }
        }

        let master_arr: Zeroizing<[u8; 32]> = match &kind {
            VaultUnlockKind::OpenWrappedKey => Storage::unwrap_master_key_file(pwd.trim())
                .map(Zeroizing::new)
                .map_err(|e| {
                    clear_remembered_password();
                    e.to_string()
                })?,
            VaultUnlockKind::MigratePlainMaster(leg) => {
                let plain = **leg;
                Storage::write_wrapped_master_key_file(&plain, pwd.trim())
                    .map_err(|e| e.to_string())?;
                Zeroizing::new(plain)
            }
            VaultUnlockKind::CreateProfile => {
                let mut plain = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut plain);
                Storage::write_wrapped_master_key_file(&plain, pwd.trim())
                    .map_err(|e| e.to_string())?;
                Zeroizing::new(plain)
            }
        };

        if remember {
            let _ = save_remembered_password(pwd.trim());
        } else {
            clear_remembered_password();
        }
        pwd.zeroize();

        let (command_tx, command_rx) = mpsc::channel(1024);
        let command_tx_mdns = command_tx.clone();
        let event_tx = self.event_tx.clone();

        let messages = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .messages
            .clone();

        match kind {
            VaultUnlockKind::OpenWrappedKey | VaultUnlockKind::MigratePlainMaster(_) => {
                let storage = Storage::load(&master_arr).map_err(|e| e.to_string())?;
                let local_key = libp2p::identity::Keypair::from_protobuf_encoding(
                    &storage.keypair_bytes,
                )
                .map_err(|e| e.to_string())?;
                let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
                let static_for_inner = crypto::StaticSecret::from(storage.static_secret_bytes);
                let my_id = PeerId::from(local_key.public());

                let mut bootstraps = storage.void_bootstraps.clone();
                if bootstraps.is_empty() {
                    let migrated = migrate_void_bootstrap_txt();
                    if !migrated.is_empty() {
                        bootstraps = migrated;
                        let _ = Storage::save(
                            &master_arr,
                            &storage.nickname,
                            None,
                            None,
                            None,
                            Some(&bootstraps),
                            None,
                            None,
                        );
                    }
                }
                let network_bootstraps = void_bootstrap_multiaddrs(&bootstraps);

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
                                .filter_map(|s| s.parse().ok())
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
                let left_groups: HashSet<String> = storage.left_groups.into_iter().collect();
                let mut groups_map = HashMap::new();
                for g in storage.groups {
                    if !left_groups.contains(&g.id) {
                        groups_map.insert(g.id.clone(), g);
                    }
                }

                if let Ok((loaded, deleted_ids)) = ChatJournal::load(&master_arr) {
                    *messages.lock() = loaded;
                    messages.load_deleted(deleted_ids);
                }
                let outbox = Outbox::load(&master_arr).unwrap_or_default();

                if !self.network_started.swap(true, Ordering::SeqCst) {
                    self.tokio_handle.spawn(run_chat_network(
                        command_rx,
                        event_tx,
                        command_tx_mdns,
                        local_key,
                        static_secret,
                        network_bootstraps,
                        contact_addrs_flat,
                        messages.clone(),
                    ));
                    let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                    g.unlocked = true;
                    g.local_peer_id = Some(my_id);
                    g.local_nickname = storage.nickname;
                    g.vault_master_key = Some(master_arr);
                    g.local_static = Some(static_for_inner);
                    g.command_tx = Some(command_tx);
                    g.known_peers = book;
                    g.contact_addrs = addrs_map;
                    g.void_bootstrap_strings = bootstraps;
                    g.groups = groups_map;
                    g.left_groups = left_groups;
                    g.peer_prekeys = peer_prekeys;
                    g.outbox_entries = outbox;
                    g.add_status("Vault разблокирован — сеть запущена".into());
                    if !g.peer_prekeys.is_empty() {
                        let cache: Vec<_> = g.peer_prekeys.iter().map(|(p, k)| (*p, *k)).collect();
                        if let Some(tx) = &g.command_tx {
                            let _ = tx.try_send(UICommand::CachePeerPrekeys(cache));
                        }
                    }
                    if let Some(tx) = &g.command_tx {
                        let _ = tx.try_send(UICommand::FetchOfflineMailbox);
                    }
                    g.schedule_offline_publish();
                    // Restore live-retry queue from durable outbox.
                    for entry in g.outbox_entries.clone() {
                        if let OutboxEntry::DirectMessage {
                            peer,
                            message_id,
                            text,
                        } = entry
                        {
                            if let Ok(pid) = peer.parse::<PeerId>() {
                                g.push_pending_send(pid, text, message_id);
                                g.ensure_peer_routed(pid);
                            }
                        }
                    }
                } else {
                    // Network already running — keep existing command_tx (do not orphan the swarm).
                    drop(command_rx);
                    let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                    g.unlocked = true;
                    g.local_peer_id = Some(my_id);
                    g.local_nickname = storage.nickname;
                    g.vault_master_key = Some(master_arr);
                    g.local_static = Some(static_for_inner);
                    g.known_peers = book;
                    g.contact_addrs = addrs_map;
                    g.void_bootstrap_strings = bootstraps;
                    g.groups = groups_map;
                    g.left_groups = left_groups;
                    g.peer_prekeys = peer_prekeys;
                    g.outbox_entries = outbox;
                }
            }
            VaultUnlockKind::CreateProfile => {
                let local_key = libp2p::identity::Keypair::generate_ed25519();
                let static_secret =
                    crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                let static_for_inner = crypto::StaticSecret::from(*static_secret.as_bytes());
                let my_id = PeerId::from(local_key.public());
                let nickname = format!("User_{}", &my_id.to_string()[..4]);
                Storage::save(
                    &master_arr,
                    &nickname,
                    Some(&local_key),
                    Some(&static_secret),
                    None,
                    None,
                    None,
                    None,
                )
                .map_err(|e| {
                    let _ = std::fs::remove_file(crate::paths::data_file(Storage::KEY_FILE));
                    e.to_string()
                })?;

                if !self.network_started.swap(true, Ordering::SeqCst) {
                    self.tokio_handle.spawn(run_chat_network(
                        command_rx,
                        event_tx,
                        command_tx_mdns,
                        local_key,
                        static_secret,
                        Vec::new(),
                        Vec::new(),
                        messages.clone(),
                    ));
                    let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                    g.unlocked = true;
                    g.local_peer_id = Some(my_id);
                    g.local_nickname = nickname;
                    g.vault_master_key = Some(master_arr);
                    g.local_static = Some(static_for_inner);
                    g.command_tx = Some(command_tx);
                    g.add_status("Профиль создан — войдите в сеть через IP ноды".into());
                } else {
                    drop(command_rx);
                    let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                    g.unlocked = true;
                    g.local_peer_id = Some(my_id);
                    g.local_nickname = nickname;
                    g.vault_master_key = Some(master_arr);
                    g.local_static = Some(static_for_inner);
                }
            }
        }

        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn try_auto_unlock(&self) -> Result<Option<SnapshotDto>, String> {
        let kind = detect_vault_unlock_kind()?;
        if !matches!(kind, VaultUnlockKind::OpenWrappedKey) {
            return Ok(None);
        }
        let Some(pwd) = load_remembered_password() else {
            return Ok(None);
        };
        Ok(Some(self.unlock(pwd, None, true)?))
    }

    pub fn select_chat(&self, chat_id: String) -> SnapshotDto {
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.selected_chat = chat_id.clone();
            if group::parse_group_thread_key(&chat_id).is_none() {
                if let Ok(pid) = chat_id.parse::<PeerId>() {
                    g.ensure_peer_routed(pid);
                }
            }
        }
        self.emit_snapshot();
        self.get_snapshot()
    }

    pub fn send_message(&self, text: String) -> Result<SnapshotDto, String> {
        let text = text.trim().to_string();
        if text.is_empty() {
            return Err("Пустое сообщение".into());
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !g.unlocked {
            return Err("Vault заблокирован".into());
        }
        let chat = g.selected_chat.clone();
        if chat.is_empty() {
            return Err("Выберите чат".into());
        }
        let local = g.local_peer_id.ok_or("Нет PeerId")?;
        let nick = g.local_nickname.clone();
        let mid = new_message_id();
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();

        if let Some(gid) = group::parse_group_thread_key(&chat) {
            let gid = gid.to_string();
            let Some(group) = g.groups.get(&gid).cloned() else {
                return Err("Группа не найдена".into());
            };
            let members = group.member_peer_ids();
            let msg = ChatMessage {
                id: mid.clone(),
                sender_id: local.to_string(),
                sender_name: nick.clone(),
                recipient_id: None,
                text: text.clone(),
                timestamp: ts,
                delivery: OutgoingDeliveryStatus::Pending,
                voice: None,
                group_id: Some(gid.clone()),
            };
            g.messages.lock().entry(chat).or_default().push(msg);
            g.messages.mark_dirty();
            g.persist_journal();
            if let Some(tx) = &g.command_tx {
                let _ = tx.try_send(UICommand::SendGroupMessage {
                    sender_name: nick,
                    text,
                    group_id: gid,
                    members,
                    message_id: Some(mid),
                    is_retry: false,
                    voice_path: None,
                    voice_duration_secs: 0.0,
                    voice_transfer_id: None,
                    voice_only_members: Vec::new(),
                });
            }
        } else {
            let peer: PeerId = chat.parse().map_err(|_| "Неверный PeerId чата")?;
            let msg = ChatMessage {
                id: mid.clone(),
                sender_id: local.to_string(),
                sender_name: nick.clone(),
                recipient_id: Some(chat.clone()),
                text: text.clone(),
                timestamp: ts,
                delivery: OutgoingDeliveryStatus::Pending,
                voice: None,
                group_id: None,
            };
            g.messages.lock().entry(chat).or_default().push(msg);
            g.messages.mark_dirty();
            g.persist_journal();
            g.outbox_entries.push(OutboxEntry::DirectMessage {
                peer: peer.to_string(),
                message_id: mid.clone(),
                text: text.clone(),
            });
            g.persist_outbox();
            g.push_pending_send(peer, text.clone(), mid.clone());
            g.ensure_peer_routed(peer);
            g.schedule_offline_publish();
            if let Some(tx) = &g.command_tx {
                let _ = tx.try_send(UICommand::SendMessage {
                    sender_name: nick,
                    text,
                    recipient: Some(peer),
                    message_id: Some(mid),
                    is_retry: false,
                });
            }
        }
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn add_contact(&self, peer_or_addr: String, name: String) -> Result<SnapshotDto, String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let input = peer_or_addr.trim().to_string();
        let display = if name.trim().is_empty() {
            input.chars().take(12).collect()
        } else {
            name.trim().to_string()
        };

        if let Ok(pid) = input.parse::<PeerId>() {
            g.known_peers.insert(pid, display);
            g.persist_vault();
            if let Some(tx) = &g.command_tx {
                let _ = tx.try_send(UICommand::SearchPeer(pid));
            }
        } else if let Some((ma, pid_opt)) = parse_seed_input(&input) {
            if let Some(pid) = pid_opt {
                g.known_peers.insert(pid, display);
                g.contact_addrs.entry(pid).or_default().push(ma.clone());
                g.persist_vault();
                if let Some(tx) = &g.command_tx {
                    let _ = tx.try_send(UICommand::DialPeer(pid, vec![ma]));
                }
            } else if let Some(tx) = &g.command_tx {
                let _ = tx.try_send(UICommand::Dial(ma.to_string()));
                g.add_status(format!("Звоним {input}…"));
            }
        } else {
            return Err("Укажите PeerId или multiaddr/IP".into());
        }
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn remove_contact(&self, peer_id: String) -> Result<SnapshotDto, String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            g.known_peers.remove(&pid);
            g.contact_addrs.remove(&pid);
            if g.selected_chat == peer_id {
                g.selected_chat.clear();
            }
            g.persist_vault();
        } else {
            return Err("Неверный PeerId".into());
        }
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn rename_contact(&self, peer_id: String, name: String) -> Result<SnapshotDto, String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let pid: PeerId = peer_id.parse().map_err(|_| "Неверный PeerId")?;
        if let Some(n) = g.known_peers.get_mut(&pid) {
            *n = name.trim().to_string();
            g.persist_vault();
        } else {
            return Err("Контакт не найден".into());
        }
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    fn send_cmd(&self, cmd: UICommand) -> Result<(), String> {
        let tx = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .command_tx
            .clone()
            .ok_or_else(|| "Сеть ещё не запущена".to_string())?;
        // Prefer async send so we don't silently drop under load (try_send).
        match self.tokio_handle.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), tx.send(cmd)).await
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err("Сетевой канал закрыт".into()),
            Err(_) => Err("Таймаут команды сети".into()),
        }
    }

    pub fn join_via_node(&self, input: String) -> Result<SnapshotDto, String> {
        let input = input.trim().to_string();
        if input.is_empty() {
            return Err("Укажите IP или multiaddr".into());
        }
        self.send_cmd(UICommand::JoinViaNode(input.clone()))?;
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.add_status(format!("Вход в сеть через {input}…"));
        }
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn reload_bootstraps(&self) -> Result<SnapshotDto, String> {
        let list = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .void_bootstrap_strings
            .clone();
        self.send_cmd(UICommand::ReloadBootstraps(list))?;
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn snapshot_dht(&self) -> Result<SnapshotDto, String> {
        self.send_cmd(UICommand::SnapshotDhtRoutingPeers)?;
        Ok(self.get_snapshot())
    }

    pub fn set_nickname(&self, nickname: String) -> Result<SnapshotDto, String> {
        let nick = nickname.trim().to_string();
        if nick.is_empty() {
            return Err("Пустой ник".into());
        }
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.local_nickname = nick;
            g.persist_vault();
        }
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn send_file(&self, path: String) -> Result<SnapshotDto, String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let chat = g.selected_chat.clone();
        let peer: PeerId = chat.parse().map_err(|_| "Выберите личный чат")?;
        let kind = file_transfer::FileKind::Other;
        if let Some(tx) = &g.command_tx {
            let _ = tx.try_send(UICommand::SendFile {
                recipient: peer,
                path,
                kind,
            });
            g.add_status("Отправка файла…".into());
        }
        drop(g);
        Ok(self.get_snapshot())
    }

    pub fn accept_file(&self, transfer_id_hex: String, save_dir: Option<String>) -> Result<(), String> {
        let tid = parse_transfer_id(&transfer_id_hex)?;
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let from = g
            .incoming_file_offers
            .iter()
            .find(|f| f.transfer_id == transfer_id_hex)
            .map(|f| f.from.clone())
            .ok_or("Предложение не найдено")?;
        let peer: PeerId = from.parse().map_err(|_| "bad peer")?;
        if let Some(tx) = &g.command_tx {
            let _ = tx.try_send(UICommand::AcceptFile {
                transfer_id: tid,
                from: peer,
                save_dir,
            });
        }
        Ok(())
    }

    pub fn reject_file(&self, transfer_id_hex: String) -> Result<(), String> {
        let tid = parse_transfer_id(&transfer_id_hex)?;
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let from = g
            .incoming_file_offers
            .iter()
            .find(|f| f.transfer_id == transfer_id_hex)
            .map(|f| f.from.clone())
            .ok_or("Предложение не найдено")?;
        let peer: PeerId = from.parse().map_err(|_| "bad peer")?;
        g.incoming_file_offers
            .retain(|f| f.transfer_id != transfer_id_hex);
        if let Some(tx) = &g.command_tx {
            let _ = tx.try_send(UICommand::RejectFile {
                transfer_id: tid,
                from: peer,
                reason: "rejected".into(),
            });
        }
        Ok(())
    }

    pub fn start_voice(&self) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match g.voice_recorder.handle_mic_click() {
            crate::voice::MicClick::Started => {
                g.voice_recording = true;
                Ok(())
            }
            crate::voice::MicClick::Error(e) => Err(e),
            crate::voice::MicClick::Busy => Err("Микрофон занят".into()),
            other => {
                g.voice_recording = g.voice_recorder.on_air();
                let _ = other;
                Ok(())
            }
        }
    }

    pub fn stop_voice_send(&self) -> Result<SnapshotDto, String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.voice_recorder.on_air() {
            let _ = g.voice_recorder.handle_mic_click();
        }
        for _ in 0..50 {
            let _ = g.voice_recorder.poll();
            if g.voice_recorder.has_ready() {
                break;
            }
            if let Some(e) = g.voice_recorder.take_error() {
                return Err(e);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        g.voice_recording = false;
        let (path, duration) = g
            .voice_recorder
            .take_ready()
            .ok_or_else(|| "Запись не готова".to_string())?;
        let chat = g.selected_chat.clone();
        let peer: PeerId = chat.parse().map_err(|_| "Выберите личный чат")?;
        let local = g.local_peer_id.ok_or("нет peer")?;
        let nick = g.local_nickname.clone();
        let mid = new_message_id();
        let mut tid = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut tid);
        let tid_hex = tid.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let msg = ChatMessage {
            id: mid.clone(),
            sender_id: local.to_string(),
            sender_name: nick.clone(),
            recipient_id: Some(chat.clone()),
            text: String::new(),
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            delivery: OutgoingDeliveryStatus::Pending,
            voice: Some(crate::protocol::VoiceMeta {
                transfer_id: tid_hex,
                duration_secs: duration,
            }),
            group_id: None,
        };
        g.messages.lock().entry(chat).or_default().push(msg);
        g.messages.mark_dirty();
        g.persist_journal();
        if let Some(tx) = &g.command_tx {
            let _ = tx.try_send(UICommand::SendVoiceMessage {
                sender_name: nick,
                recipient: peer,
                path: path.display().to_string(),
                duration_secs: duration,
                message_id: mid,
                transfer_id: tid,
                is_retry: false,
            });
        }
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn create_group(
        &self,
        name: String,
        member_peer_ids: Vec<String>,
    ) -> Result<SnapshotDto, String> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let local = g.local_peer_id.ok_or("нет peer")?;
        let mut members = vec![GroupMember {
            peer_id: local.to_string(),
            display_name: g.local_nickname.clone(),
        }];
        for pid in member_peer_ids {
            let name = pid
                .parse::<PeerId>()
                .ok()
                .and_then(|p| g.known_peers.get(&p).cloned())
                .unwrap_or_else(|| pid.chars().take(8).collect());
            members.push(GroupMember {
                peer_id: pid,
                display_name: name,
            });
        }
        members = dedupe_members(members);
        let id = group::new_group_id();
        let group = GroupChat {
            id: id.clone(),
            name: name.trim().to_string(),
            creator_id: local.to_string(),
            members: members.clone(),
            created_at: chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        };
        let recipients: Vec<PeerId> = members
            .iter()
            .filter_map(|m| m.peer_id.parse().ok())
            .filter(|p| *p != local)
            .collect();
        if let Some(tx) = &g.command_tx {
            let _ = tx.try_send(UICommand::SendGroupSync {
                group_id: id.clone(),
                group_name: group.name.clone(),
                creator_id: group.creator_id.clone(),
                members: members.clone(),
                recipients,
            });
        }
        g.groups.insert(id.clone(), group);
        g.selected_chat = group_thread_key(&id);
        g.persist_vault();
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn join_group(&self, link: String) -> Result<SnapshotDto, String> {
        let mut group = parse_invite_link(&link).ok_or("Неверная ссылка группы")?;
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let local = g.local_peer_id.ok_or("нет peer")?;
        if !group.members.iter().any(|m| m.peer_id == local.to_string()) {
            group.members.push(GroupMember {
                peer_id: local.to_string(),
                display_name: g.local_nickname.clone(),
            });
        }
        group.members = dedupe_members(group.members);
        g.left_groups.remove(&group.id);
        let recipients: Vec<PeerId> = group
            .members
            .iter()
            .filter_map(|m| m.peer_id.parse().ok())
            .filter(|p| *p != local)
            .collect();
        if let Some(tx) = &g.command_tx {
            let _ = tx.try_send(UICommand::SendGroupSync {
                group_id: group.id.clone(),
                group_name: group.name.clone(),
                creator_id: group.creator_id.clone(),
                members: group.members.clone(),
                recipients,
            });
        }
        g.selected_chat = group_thread_key(&group.id);
        g.groups.insert(group.id.clone(), group);
        g.persist_vault();
        drop(g);
        self.emit_snapshot();
        Ok(self.get_snapshot())
    }

    pub fn prepare_quit(&self) {
        let (items, tx_opt) = {
            let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.persist_journal();
            g.persist_outbox();
            g.persist_vault();
            (g.build_offline_publish_items(), g.command_tx.clone())
        };
        if items.is_empty() {
            return;
        }
        let Some(tx) = tx_opt else {
            return;
        };
        let n = items.len();
        let (ack_tx, ack_rx) = std_mpsc::channel();
        self.tokio_handle.spawn(async move {
            let _ = tx
                .send(UICommand::PublishOfflineOutbox {
                    items,
                    ack: Some(ack_tx),
                })
                .await;
        });
        match ack_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(true) => info!("VOID: exit — outbox ({n}) сдан в relay/DHT"),
            Ok(false) => warn!(
                "VOID: exit — handoff outbox ({n}) не подтверждён, останется в outbox.bin"
            ),
            Err(_) => warn!(
                "VOID: exit — timeout ожидания handoff outbox ({n}), останется в outbox.bin"
            ),
        }
    }

    pub fn has_pending_outbox(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .outbox_entries
            .is_empty()
    }
}

impl Default for VoidRuntime {
    fn default() -> Self {
        Self::new()
    }
}

fn update_delivery(
    messages: &SharedChatMessages,
    chat_id: &str,
    message_id: &str,
    status: OutgoingDeliveryStatus,
) {
    let mut map = messages.lock();
    if let Some(list) = map.get_mut(chat_id) {
        if let Some(m) = list.iter_mut().find(|m| m.id == message_id) {
            m.delivery = status;
            drop(map);
            messages.mark_dirty();
        }
    }
}

fn parse_transfer_id(hex: &str) -> Result<[u8; 16], String> {
    crate::protocol::transfer_id_from_hex(hex).ok_or_else(|| "Неверный transfer_id".into())
}

/// Tiny hex helper without extra crate.
mod hex {
    pub fn encode(bytes: [u8; 16]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
