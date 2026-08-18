//! Протокол чата `/void/chat/1.0.0`: Hello, E2EE-пакеты, лимиты JSON.

use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::file_transfer;
use crate::group::{self, GroupMember};

/// Статус доставки исходящего сообщения (галочки в UI).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutgoingDeliveryStatus {
    /// ○ — в очереди / ожидает подтверждения доставки.
    #[default]
    Pending,
    /// ✓ — доставлено на устройство собеседника.
    Delivered,
    /// ✓✓ — прочитано.
    Read,
}

/// Метаданные голосового сообщения (аудио передаётся отдельным file-transfer).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct VoiceMeta {
    /// 32 hex-символа (16 байт transfer_id).
    pub(crate) transfer_id: String,
    pub(crate) duration_secs: f32,
}

/// Файл в чате (байты идут file-transfer, в пузырьке — имя и локальный путь).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct FileMeta {
    pub(crate) transfer_id: String,
    pub(crate) filename: String,
    pub(crate) size: u64,
    /// Локальный путь после приёма/отправки. На провод не уходит (очищается при разборе).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_path: Option<String>,
}

pub(crate) fn transfer_id_to_hex(tid: &[u8; 16]) -> String {
    tid.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn transfer_id_from_hex(hex: &str) -> Option<[u8; 16]> {
    let hex = hex.trim();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = chunk[0] as char;
        let lo = chunk[1] as char;
        let byte = hi.to_digit(16)? as u8 * 16 + lo.to_digit(16)? as u8;
        out[i] = byte;
    }
    Some(out)
}

/// Уникальный transfer_id file-transfer для каждого участника группы (один base id в UI).
pub(crate) fn per_peer_voice_transfer_id(base: &[u8; 16], peer: PeerId) -> [u8; 16] {
    use blake2::digest::{Digest, FixedOutput};
    let mut h = blake2::Blake2b::<blake2::digest::consts::U16>::new();
    h.update(b"VOID_GROUP_VOICE_V1");
    h.update(base);
    h.update(peer.to_bytes());
    h.finalize_fixed().into()
}

fn validate_file_meta(f: &FileMeta) -> bool {
    f.transfer_id.len() == 32
        && f.transfer_id.chars().all(|c| c.is_ascii_hexdigit())
        && !f.filename.is_empty()
        && f.filename.len() <= 256
        && !f.filename.contains('/')
        && !f.filename.contains('\\')
        && f.size > 0
        && f.size <= file_transfer::MAX_FILE_SIZE
}

fn validate_voice_meta(v: &VoiceMeta) -> bool {
    v.transfer_id.len() == 32
        && v.transfer_id.chars().all(|c| c.is_ascii_hexdigit())
        && v.duration_secs > 0.0
        && v.duration_secs.is_finite()
        && v.duration_secs <= 3600.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChatMessage {
    #[serde(default)]
    pub(crate) id: String,
    pub(crate) sender_id: String,
    pub(crate) sender_name: String,
    pub(crate) recipient_id: Option<String>,
    pub(crate) text: String,
    pub(crate) timestamp: String,
    /// Только для исходящих: ○ / ✓ / ✓✓.
    #[serde(default)]
    pub(crate) delivery: OutgoingDeliveryStatus,
    /// Голосовое сообщение: аудио по `transfer_id` в file sub-протоколе.
    #[serde(default)]
    pub(crate) voice: Option<VoiceMeta>,
    /// Файл в ленте чата (как голосовое: пузырёк + file-transfer).
    #[serde(default)]
    pub(crate) file: Option<FileMeta>,
    /// Групповой чат: 32 hex-символа id группы.
    #[serde(default)]
    pub(crate) group_id: Option<String>,
}

pub(crate) fn new_message_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

const MAX_MESSAGE_ID_BYTES: usize = 64;
const MAX_DELETE_IDS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatDeleteCommand {
    kind: String,
    message_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatDeleteAck {
    kind: String,
    deleted: Vec<String>,
    missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatReadCommand {
    kind: String,
    message_ids: Vec<String>,
}

/// Подтверждение атомарной доставки голосового: получатель шлёт его ТОЛЬКО
/// после того, как файл полностью собран и его SHA-256 совпал с заявленным
/// (см. `apply_incoming_file_chunk`). Отправитель показывает голосовое в чате
/// не раньше, чем получит `ok: true` — без этого «доставлено» было фикцией
/// (чек-марка ставилась, как только сам отправитель дослал все чанки).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VoiceAckCommand {
    kind: String,
    transfer_id: String,
    ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupSyncCommand {
    kind: String,
    group_id: String,
    group_name: String,
    creator_id: String,
    members: Vec<GroupMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupLeaveCommand {
    kind: String,
    group_id: String,
    peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupDeleteCommand {
    kind: String,
    group_id: String,
}

pub(crate) enum DecryptedChatFrame {
    Message(ChatMessage),
    Delete { message_ids: Vec<String> },
    DeleteAck,
    Read { message_ids: Vec<String> },
    GroupSync {
        group_id: String,
        group_name: String,
        creator_id: String,
        members: Vec<GroupMember>,
    },
    GroupLeave {
        group_id: String,
        peer_id: String,
    },
    GroupDelete {
        group_id: String,
    },
    /// Итог проверки голосового файла на стороне получателя: `ok=true` — SHA-256
    /// совпал и файл сохранён; `ok=false` — целостность нарушена или сбой записи.
    VoiceAck {
        transfer_id: String,
        ok: bool,
    },
}

/// Лимиты JSON чата после `decrypt_payload` (защита от DoS по памяти).
const MAX_CHAT_JSON_BYTES: usize = 64 * 1024;
const MAX_CHAT_SENDER_ID_BYTES: usize = 512;
const MAX_CHAT_SENDER_NAME_BYTES: usize = 256;
const MAX_CHAT_TEXT_BYTES: usize = 16 * 1024;
const MAX_CHAT_TIMESTAMP_BYTES: usize = 64;

const VOID_HELLO_BIND_PREFIX: &[u8] = b"VOID_E2EE_HELLO_BIND_V1\0";

const MAX_HELLO_TRANSPORT_PUBKEY_PB: usize = 4096;

/// Inline multihash PeerId (Ed25519): извлечь транспортный `PublicKey` для проверки подписи Hello.
fn void_peer_transport_public_key(peer: PeerId) -> Option<libp2p::identity::PublicKey> {
    const CODE_IDENTITY: u64 = 0;
    let mh = peer.as_ref();
    if mh.code() != CODE_IDENTITY {
        return None;
    }
    libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()
}

/// Ключ для проверки `transport_sig`: из identity-multihash или из protobuf в Hello (hashed PeerId).
fn void_hello_signing_public_key(
    signer_peer_id: PeerId,
    transport_pubkey_pb: &[u8],
) -> Option<libp2p::identity::PublicKey> {
    if !transport_pubkey_pb.is_empty() {
        if transport_pubkey_pb.len() > MAX_HELLO_TRANSPORT_PUBKEY_PB {
            return None;
        }
        let pk = libp2p::identity::PublicKey::try_decode_protobuf(transport_pubkey_pb).ok()?;
        if PeerId::from_public_key(&pk) != signer_peer_id {
            return None;
        }
        return Some(pk);
    }
    void_peer_transport_public_key(signer_peer_id)
}

fn hello_bind_message(
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(96 + VOID_HELLO_BIND_PREFIX.len());
    v.extend_from_slice(VOID_HELLO_BIND_PREFIX);
    v.extend_from_slice(&signer_peer.to_bytes());
    v.extend_from_slice(&recipient_peer.to_bytes());
    v.extend_from_slice(x25519_static.as_slice());
    v.extend_from_slice(x25519_ephemeral.as_slice());
    v
}

pub(crate) fn verify_hello_transport_binding(
    signer_peer_id: PeerId,
    recipient_peer_id: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    transport_sig: &[u8],
    transport_pubkey_pb: &[u8],
) -> bool {
    const MAX_SIG: usize = 256;
    if transport_sig.is_empty() || transport_sig.len() > MAX_SIG {
        return false;
    }
    let Some(pubkey) = void_hello_signing_public_key(signer_peer_id, transport_pubkey_pb) else {
        return false;
    };
    let msg = hello_bind_message(
        signer_peer_id,
        recipient_peer_id,
        x25519_static,
        x25519_ephemeral,
    );
    pubkey.verify(&msg, transport_sig)
}

fn sign_hello_transport_binding(
    transport: &libp2p::identity::Keypair,
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
) -> Option<Vec<u8>> {
    let msg = hello_bind_message(signer_peer, recipient_peer, x25519_static, x25519_ephemeral);
    transport.sign(&msg).ok()
}

fn validate_message_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_MESSAGE_ID_BYTES
}

fn validate_delete_ids(ids: &[String]) -> bool {
    !ids.is_empty()
        && ids.len() <= MAX_DELETE_IDS
        && ids.iter().all(|id| validate_message_id(id))
}

pub(crate) fn is_delete_command_json(plaintext: &[u8]) -> bool {
    delete_command_message_ids(plaintext).is_some()
}

pub(crate) fn delete_command_message_ids(plaintext: &[u8]) -> Option<Vec<String>> {
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    let cmd = serde_json::from_slice::<ChatDeleteCommand>(plaintext).ok()?;
    if cmd.kind == "delete" && validate_delete_ids(&cmd.message_ids) {
        Some(cmd.message_ids)
    } else {
        None
    }
}

pub(crate) fn read_command_message_ids(plaintext: &[u8]) -> Option<Vec<String>> {
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    let cmd = serde_json::from_slice::<ChatReadCommand>(plaintext).ok()?;
    if cmd.kind == "read" && validate_delete_ids(&cmd.message_ids) {
        Some(cmd.message_ids)
    } else {
        None
    }
}

pub(crate) fn is_read_command_json(plaintext: &[u8]) -> bool {
    read_command_message_ids(plaintext).is_some()
}

pub(crate) fn build_read_receipt_json(message_ids: &[String]) -> Option<Vec<u8>> {
    if message_ids.is_empty() || !validate_delete_ids(message_ids) {
        return None;
    }
    let cmd = ChatReadCommand {
        kind: "read".into(),
        message_ids: message_ids.to_vec(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub(crate) fn build_voice_ack_json(transfer_id: &str, ok: bool) -> Option<Vec<u8>> {
    let tid = transfer_id_from_hex(transfer_id)?;
    let cmd = VoiceAckCommand {
        kind: "voice_ack".into(),
        transfer_id: transfer_id_to_hex(&tid),
        ok,
    };
    serde_json::to_vec(&cmd).ok()
}

pub(crate) fn chat_message_id_from_json(plaintext: &[u8]) -> Option<String> {
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    let msg: ChatMessage = serde_json::from_slice(plaintext).ok()?;
    if validate_message_id(&msg.id) {
        Some(msg.id)
    } else {
        None
    }
}

pub(crate) fn parse_decrypted_chat_frame(plaintext: &[u8]) -> Option<DecryptedChatFrame> {
    if plaintext.len() > MAX_CHAT_JSON_BYTES {
        return None;
    }
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    if let Ok(ack) = serde_json::from_slice::<ChatDeleteAck>(plaintext) {
        if ack.kind == "delete_ack"
            && ack.deleted.len() <= MAX_DELETE_IDS
            && ack.missing.len() <= MAX_DELETE_IDS
            && ack
                .deleted
                .iter()
                .chain(ack.missing.iter())
                .all(|id| validate_message_id(id))
        {
            return Some(DecryptedChatFrame::DeleteAck);
        }
    }
    if let Ok(cmd) = serde_json::from_slice::<ChatDeleteCommand>(plaintext) {
        if cmd.kind == "delete" && validate_delete_ids(&cmd.message_ids) {
            return Some(DecryptedChatFrame::Delete {
                message_ids: cmd.message_ids,
            });
        }
    }
    if let Ok(cmd) = serde_json::from_slice::<ChatReadCommand>(plaintext) {
        if cmd.kind == "read" && validate_delete_ids(&cmd.message_ids) {
            return Some(DecryptedChatFrame::Read {
                message_ids: cmd.message_ids,
            });
        }
    }
    if let Ok(cmd) = serde_json::from_slice::<VoiceAckCommand>(plaintext) {
        if cmd.kind == "voice_ack" && transfer_id_from_hex(&cmd.transfer_id).is_some() {
            return Some(DecryptedChatFrame::VoiceAck {
                transfer_id: cmd.transfer_id.to_ascii_lowercase(),
                ok: cmd.ok,
            });
        }
    }
    if let Ok(cmd) = serde_json::from_slice::<GroupSyncCommand>(plaintext) {
        if cmd.kind == "group_sync"
            && group::validate_group_id(&cmd.group_id)
            && !cmd.group_name.is_empty()
            && cmd.group_name.len() <= 128
            && !cmd.creator_id.is_empty()
            && cmd.members.len() <= 256
        {
            return Some(DecryptedChatFrame::GroupSync {
                group_id: cmd.group_id,
                group_name: cmd.group_name,
                creator_id: cmd.creator_id,
                members: cmd.members,
            });
        }
    }
    if let Ok(cmd) = serde_json::from_slice::<GroupLeaveCommand>(plaintext) {
        if cmd.kind == "group_leave"
            && group::validate_group_id(&cmd.group_id)
            && !cmd.peer_id.is_empty()
            && cmd.peer_id.len() <= MAX_CHAT_SENDER_ID_BYTES
        {
            return Some(DecryptedChatFrame::GroupLeave {
                group_id: cmd.group_id,
                peer_id: cmd.peer_id,
            });
        }
    }
    if let Ok(cmd) = serde_json::from_slice::<GroupDeleteCommand>(plaintext) {
        if cmd.kind == "group_delete" && group::validate_group_id(&cmd.group_id) {
            return Some(DecryptedChatFrame::GroupDelete {
                group_id: cmd.group_id,
            });
        }
    }
    parse_decrypted_chat_json(plaintext).map(DecryptedChatFrame::Message)
}

pub(crate) fn build_group_leave_json(group_id: &str, peer_id: &str) -> Option<Vec<u8>> {
    if !group::validate_group_id(group_id) || peer_id.is_empty() || peer_id.len() > 512 {
        return None;
    }
    let cmd = GroupLeaveCommand {
        kind: "group_leave".into(),
        group_id: group_id.to_string(),
        peer_id: peer_id.to_string(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub(crate) fn build_group_delete_json(group_id: &str) -> Option<Vec<u8>> {
    if !group::validate_group_id(group_id) {
        return None;
    }
    let cmd = GroupDeleteCommand {
        kind: "group_delete".into(),
        group_id: group_id.to_string(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub(crate) fn build_group_sync_json(
    group_id: &str,
    group_name: &str,
    creator_id: &str,
    members: &[GroupMember],
) -> Option<Vec<u8>> {
    if !group::validate_group_id(group_id)
        || group_name.is_empty()
        || group_name.len() > 128
        || creator_id.is_empty()
        || members.is_empty()
        || members.len() > 256
    {
        return None;
    }
    let cmd = GroupSyncCommand {
        kind: "group_sync".into(),
        group_id: group_id.to_string(),
        group_name: group_name.to_string(),
        creator_id: creator_id.to_string(),
        members: members.to_vec(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub(crate) fn build_delete_ack_json(
    deleted: &[String],
    missing: &[String],
) -> Option<Vec<u8>> {
    if deleted.len() + missing.len() > MAX_DELETE_IDS {
        return None;
    }
    if !deleted.iter().chain(missing.iter()).all(|id| validate_message_id(id)) {
        return None;
    }
    let ack = ChatDeleteAck {
        kind: "delete_ack".into(),
        deleted: deleted.to_vec(),
        missing: missing.to_vec(),
    };
    serde_json::to_vec(&ack).ok()
}

/// Разбор JSON чата после DR: верхняя граница буфера и длины полей.
pub(crate) fn parse_decrypted_chat_json(plaintext: &[u8]) -> Option<ChatMessage> {
    if plaintext.len() > MAX_CHAT_JSON_BYTES {
        return None;
    }
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    let mut msg: ChatMessage = serde_json::from_slice(plaintext).ok()?;
    if !msg.id.is_empty() && !validate_message_id(&msg.id) {
        return None;
    }
    if msg.sender_id.len() > MAX_CHAT_SENDER_ID_BYTES
        || msg.sender_name.len() > MAX_CHAT_SENDER_NAME_BYTES
        || msg.text.len() > MAX_CHAT_TEXT_BYTES
        || msg.timestamp.len() > MAX_CHAT_TIMESTAMP_BYTES
    {
        return None;
    }
    if let Some(ref voice) = msg.voice {
        if !validate_voice_meta(voice) {
            return None;
        }
    }
    if let Some(ref mut file) = msg.file {
        if !validate_file_meta(file) {
            return None;
        }
        // Чужой local_path с провода не принимаем.
        file.local_path = None;
    }
    if msg.text.is_empty() && msg.voice.is_none() && msg.file.is_none() {
        return None;
    }
    if let Some(ref r) = msg.recipient_id {
        if r.len() > MAX_CHAT_SENDER_ID_BYTES {
            return None;
        }
    }
    if let Some(ref gid) = msg.group_id {
        if !group::validate_group_id(gid) {
            return None;
        }
    }
    Some(msg)
}

const MAX_BOOTSTRAP_GOSSIP_ADDRS: usize = 32;
const MAX_BOOTSTRAP_ADDR_LEN: usize = 512;

/// Проверяет список bootstrap multiaddr из gossip-обмена между участниками.
pub(crate) fn validate_bootstrap_gossip_addrs(addrs: &[String]) -> Option<Vec<String>> {
    if addrs.is_empty() || addrs.len() > MAX_BOOTSTRAP_GOSSIP_ADDRS {
        return None;
    }
    let mut out = Vec::new();
    for s in addrs {
        let t = s.trim();
        if t.is_empty() || t.len() > MAX_BOOTSTRAP_ADDR_LEN {
            continue;
        }
        if let Ok(ma) = t.parse::<libp2p::Multiaddr>() {
            if let Some(c) = crate::bootstrap::canonicalize_bootstrap_ma(&ma) {
                let normalized = c.to_string();
                if !out.contains(&normalized) {
                    out.push(normalized);
                }
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Публичный onion-hop соседней VOID-ноды (gossip / каталог bootstrap).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct OnionHopHint {
    #[serde(default)]
    pub(crate) peer_id: String,
    #[serde(default)]
    pub(crate) pk_hex: String,
    #[serde(default)]
    pub(crate) addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum V1Packet {
    Hello {
        public_key: [u8; 32],
        ephemeral_key: [u8; 32],
        /// Подпись Ed25519 (libp2p identity) над `VOID_E2EE_HELLO_BIND_V1` + peerId||peerId||x25519||ephem.
        #[serde(default)]
        transport_sig: Vec<u8>,
        /// Если PeerId не identity-multihash: protobuf `PublicKey` для проверки подписи.
        #[serde(default)]
        transport_pubkey_pb: Vec<u8>,
    },
    /// Обмен известными VOID bootstrap-нодами между участниками (публичные multiaddr).
    BootstrapGossip {
        addrs: Vec<String>,
        /// Ключи onion hop'ов (`peer_id` + X25519 hex). Старые клиенты поле игнорируют.
        #[serde(default)]
        onion_keys: Vec<OnionHopHint>,
    },
    /// «Дозвонись ко мне через relay» — чинит асимметрию NAT (A→B есть, B→A нет).
    DialBack {
        /// Полные multiaddr вида `…/p2p/<relay>/p2p-circuit/p2p/<me>`.
        circuit_addrs: Vec<String>,
    },
    /// Store-and-forward: сохранить офлайн-почту для получателя (E2EE-конверты).
    OfflineMailboxStore {
        recipient: String,
        envelopes: Vec<crate::offline_mail::OfflineEnvelope>,
    },
    /// Запросить офлайн-почту для peer_id.
    OfflineMailboxQuery {
        recipient: String,
    },
    /// Ответ на OfflineMailboxQuery.
    OfflineMailboxDeliver {
        envelopes: Vec<crate::offline_mail::OfflineEnvelope>,
    },
    /// Опубликовать X25519 prekey на bootstrap (для офлайн-seal без DHT/Hello).
    PrekeyPut {
        peer_id: String,
        public_key: [u8; 32],
    },
    /// Запросить prekey контакта у bootstrap.
    PrekeyGet {
        peer_id: String,
    },
    /// Ответ на PrekeyGet (или push после Put соседу через gossip — не используется).
    PrekeyOffer {
        peer_id: String,
        public_key: [u8; 32],
    },
    Encrypted {
        header: crypto::MessageHeader,
        ciphertext: Vec<u8>,
    },
    /// One onion cell: sealed to the next hop's onion X25519 key.
    Onion {
        eph: [u8; 32],
        nonce: [u8; 12],
        ct: Vec<u8>,
    },
    /// Exit hop → recipient. `src` is the logical sender (E2EE Hello still binds identity).
    OnionDrop {
        src: String,
        packet: Box<V1Packet>,
    },
    Ack,
}

/// Wrap `inner` for `dest` through live onion hops:
/// 1 node → 1 hop, 2 nodes → both, 3+ → three random (entry is connected).
pub(crate) fn wrap_onion_packet(
    hops: &[(PeerId, [u8; 32])],
    src: PeerId,
    dest: PeerId,
    inner: V1Packet,
) -> Option<V1Packet> {
    if hops.is_empty() {
        return None;
    }
    let drop = V1Packet::OnionDrop {
        src: src.to_string(),
        packet: Box::new(inner),
    };
    let drop_val = serde_json::to_value(&drop).ok()?;
    let (eph, nonce, ct) = crate::onion::wrap_layers(hops, dest, drop_val).ok()?;
    Some(V1Packet::Onion { eph, nonce, ct })
}

pub(crate) fn build_v1_hello(
    transport: &libp2p::identity::Keypair,
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static_pubkey: crypto::PublicKey,
    x25519_ephem_pubkey: crypto::PublicKey,
) -> Option<V1Packet> {
    let static_b = x25519_static_pubkey.to_bytes();
    let ephem_b = x25519_ephem_pubkey.to_bytes();
    let transport_sig = sign_hello_transport_binding(
        transport,
        signer_peer,
        recipient_peer,
        &static_b,
        &ephem_b,
    )?;
    let transport_pubkey_pb = if void_peer_transport_public_key(signer_peer).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    };
    Some(V1Packet::Hello {
        public_key: static_b,
        ephemeral_key: ephem_b,
        transport_sig,
        transport_pubkey_pb,
    })
}

/// Прогресс активной передачи файла (для UI).
#[cfg(feature = "egui-ui")]
pub(crate) struct FileTransferProgress {
    pub filename: String,
    pub total_size: u64,
    pub sent_chunks: u32,
    pub total_chunks: u32,
    pub is_outgoing: bool,
    pub completed: bool,
    pub saved_to: String,
    pub peer: PeerId,
    pub kind: file_transfer::FileKind,
}
