//! Протокол чата `/void/chat/1.0.0`: Hello, E2EE-пакеты, лимиты JSON.

use libp2p_identity::PeerId;
use multiaddr::Multiaddr;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use void_session::crypto;
use void_session::group::{self, GroupMember};
use void_session::hello::sign_hello_transport_binding;

pub use void_session::hello::{
    hello_bind_ok, verify_hello_transport_binding, void_hello_signing_public_key,
    void_peer_transport_public_key, HelloBind, HELLO_CAP_HEADER_AAD, HELLO_CAPS,
    HELLO_FRESHNESS_SECS,
};

const MAX_CHAT_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Статус доставки исходящего сообщения (галочки в UI).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OutgoingDeliveryStatus {
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
pub struct VoiceMeta {
    /// 32 hex-символа (16 байт transfer_id).
    pub transfer_id: String,
    pub duration_secs: f32,
}

/// Файл в чате (байты идут file-transfer, в пузырьке — имя и локальный путь).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileMeta {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    /// Локальный путь после приёма/отправки. На провод не уходит (очищается при разборе).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
}

pub fn transfer_id_to_hex(tid: &[u8; 16]) -> String {
    tid.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn transfer_id_from_hex(hex: &str) -> Option<[u8; 16]> {
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
pub fn per_peer_voice_transfer_id(base: &[u8; 16], peer: PeerId) -> [u8; 16] {
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
        && f.size <= MAX_CHAT_FILE_BYTES
}

fn validate_voice_meta(v: &VoiceMeta) -> bool {
    v.transfer_id.len() == 32
        && v.transfer_id.chars().all(|c| c.is_ascii_hexdigit())
        && v.duration_secs > 0.0
        && v.duration_secs.is_finite()
        && v.duration_secs <= 3600.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    #[serde(default)]
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub recipient_id: Option<String>,
    pub text: String,
    pub timestamp: String,
    /// Только для исходящих: ○ / ✓ / ✓✓.
    #[serde(default)]
    pub delivery: OutgoingDeliveryStatus,
    /// Голосовое сообщение: аудио по `transfer_id` в file sub-протоколе.
    #[serde(default)]
    pub voice: Option<VoiceMeta>,
    /// Файл в ленте чата (как голосовое: пузырёк + file-transfer).
    #[serde(default)]
    pub file: Option<FileMeta>,
    /// Групповой чат: 32 hex-символа id группы.
    #[serde(default)]
    pub group_id: Option<String>,
}

pub fn new_message_id() -> String {
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
    /// Монотонная версия состава. Старые клиенты поле не шлют (0).
    #[serde(default)]
    version: u64,
    /// Подпись создателя над `group_id ‖ version ‖ name ‖ members`.
    #[serde(default)]
    sig: Vec<u8>,
    /// Protobuf identity, если PeerId создателя не identity-multihash.
    #[serde(default)]
    creator_pubkey_pb: Vec<u8>,
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

pub enum DecryptedChatFrame {
    Message(ChatMessage),
    Delete {
        message_ids: Vec<String>,
    },
    DeleteAck,
    Read {
        message_ids: Vec<String>,
    },
    Delivered {
        message_ids: Vec<String>,
    },
    GroupSync {
        group_id: String,
        group_name: String,
        creator_id: String,
        members: Vec<GroupMember>,
        version: u64,
        sig: Vec<u8>,
        creator_pubkey_pb: Vec<u8>,
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


fn wire_peer(peer: PeerId) -> void_onion::PeerId {
    void_onion::PeerId::from_bytes(&peer.to_bytes()).expect("peer id bytes")
}

fn wire_hops(hops: &[(PeerId, [u8; 32])]) -> Vec<(void_onion::PeerId, [u8; 32])> {
    hops.iter().map(|(p, k)| (wire_peer(*p), *k)).collect()
}

fn seal_onion_deliver(dest: PeerId, mail: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pk = void_envelope::offline_mail::identity_offline_public(&dest)
        .ok_or_else(|| anyhow::anyhow!("onion seal: no identity key"))?;
    void_onion::seal_deliver(pk.as_bytes(), mail)
}

fn validate_message_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_MESSAGE_ID_BYTES
}

fn validate_delete_ids(ids: &[String]) -> bool {
    !ids.is_empty() && ids.len() <= MAX_DELETE_IDS && ids.iter().all(|id| validate_message_id(id))
}

pub fn is_delete_command_json(plaintext: &[u8]) -> bool {
    delete_command_message_ids(plaintext).is_some()
}

pub fn delete_command_message_ids(plaintext: &[u8]) -> Option<Vec<String>> {
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

pub fn read_command_message_ids(plaintext: &[u8]) -> Option<Vec<String>> {
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

pub fn is_read_command_json(plaintext: &[u8]) -> bool {
    read_command_message_ids(plaintext).is_some()
}

pub fn build_read_receipt_json(message_ids: &[String]) -> Option<Vec<u8>> {
    if message_ids.is_empty() || !validate_delete_ids(message_ids) {
        return None;
    }
    let cmd = ChatReadCommand {
        kind: "read".into(),
        message_ids: message_ids.to_vec(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub fn delivered_command_message_ids(plaintext: &[u8]) -> Option<Vec<String>> {
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    let cmd = serde_json::from_slice::<ChatReadCommand>(plaintext).ok()?;
    if cmd.kind == "delivered" && validate_delete_ids(&cmd.message_ids) {
        Some(cmd.message_ids)
    } else {
        None
    }
}

pub fn is_delivered_command_json(plaintext: &[u8]) -> bool {
    delivered_command_message_ids(plaintext).is_some()
}

pub fn build_delivered_receipt_json(message_ids: &[String]) -> Option<Vec<u8>> {
    if message_ids.is_empty() || !validate_delete_ids(message_ids) {
        return None;
    }
    let cmd = ChatReadCommand {
        kind: "delivered".into(),
        message_ids: message_ids.to_vec(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub fn build_voice_ack_json(transfer_id: &str, ok: bool) -> Option<Vec<u8>> {
    let tid = transfer_id_from_hex(transfer_id)?;
    let cmd = VoiceAckCommand {
        kind: "voice_ack".into(),
        transfer_id: transfer_id_to_hex(&tid),
        ok,
    };
    serde_json::to_vec(&cmd).ok()
}

pub fn chat_message_id_from_json(plaintext: &[u8]) -> Option<String> {
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

pub fn parse_decrypted_chat_frame(plaintext: &[u8]) -> Option<DecryptedChatFrame> {
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
        if cmd.kind == "delivered" && validate_delete_ids(&cmd.message_ids) {
            return Some(DecryptedChatFrame::Delivered {
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
                version: cmd.version,
                sig: cmd.sig,
                creator_pubkey_pb: cmd.creator_pubkey_pb,
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

pub fn build_group_leave_json(group_id: &str, peer_id: &str) -> Option<Vec<u8>> {
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

pub fn build_group_delete_json(group_id: &str) -> Option<Vec<u8>> {
    if !group::validate_group_id(group_id) {
        return None;
    }
    let cmd = GroupDeleteCommand {
        kind: "group_delete".into(),
        group_id: group_id.to_string(),
    };
    serde_json::to_vec(&cmd).ok()
}

pub fn build_group_sync_json(
    transport: Option<&libp2p_identity::Keypair>,
    group_id: &str,
    group_name: &str,
    creator_id: &str,
    version: u64,
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
    let (sig, creator_pubkey_pb) = match transport {
        Some(kp) if kp.public().to_peer_id().to_string() == creator_id && version > 0 => {
            let msg = group::group_sync_message(group_id, version, group_name, members);
            let sig = kp.sign(&msg).ok()?;
            let pb = if void_peer_transport_public_key(kp.public().to_peer_id()).is_some() {
                Vec::new()
            } else {
                kp.public().encode_protobuf()
            };
            (sig, pb)
        }
        _ => (Vec::new(), Vec::new()),
    };
    let cmd = GroupSyncCommand {
        kind: "group_sync".into(),
        group_id: group_id.to_string(),
        group_name: group_name.to_string(),
        creator_id: creator_id.to_string(),
        members: members.to_vec(),
        version,
        sig,
        creator_pubkey_pb,
    };
    serde_json::to_vec(&cmd).ok()
}

pub fn verify_group_sync_signature(
    group_id: &str,
    creator_id: &str,
    version: u64,
    name: &str,
    members: &[GroupMember],
    sig: &[u8],
    creator_pubkey_pb: &[u8],
) -> bool {
    if sig.is_empty() || version == 0 || sig.len() > 256 || creator_pubkey_pb.len() > 4096 {
        return false;
    }
    let Ok(creator) = creator_id.parse::<PeerId>() else {
        return false;
    };
    let Some(pubkey) = void_hello_signing_public_key(creator, creator_pubkey_pb) else {
        return false;
    };
    let msg = group::group_sync_message(group_id, version, name, members);
    pubkey.verify(&msg, sig)
}

pub fn build_delete_ack_json(deleted: &[String], missing: &[String]) -> Option<Vec<u8>> {
    if deleted.len() + missing.len() > MAX_DELETE_IDS {
        return None;
    }
    if !deleted
        .iter()
        .chain(missing.iter())
        .all(|id| validate_message_id(id))
    {
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
pub fn parse_decrypted_chat_json(plaintext: &[u8]) -> Option<ChatMessage> {
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
pub fn validate_bootstrap_gossip_addrs(addrs: &[String]) -> Option<Vec<String>> {
    if addrs.is_empty() || addrs.len() > MAX_BOOTSTRAP_GOSSIP_ADDRS {
        return None;
    }
    let mut out = Vec::new();
    for s in addrs {
        let t = s.trim();
        if t.is_empty() || t.len() > MAX_BOOTSTRAP_ADDR_LEN {
            continue;
        }
        if let Ok(ma) = t.parse::<Multiaddr>() {
            if let Some(c) = canonicalize_bootstrap_ma(&ma) {
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
pub struct OnionHopHint {
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub pk_hex: String,
    #[serde(default)]
    pub addrs: Vec<String>,
    #[serde(default)]
    pub sig_hex: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub not_after: u64,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub sig2_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum V1Packet {
    Hello {
        public_key: [u8; 32],
        ephemeral_key: [u8; 32],
        /// Подпись Ed25519 (libp2p identity): v2 — bind + `ts` + `nonce`; v1 — без них (старые клиенты).
        #[serde(default)]
        transport_sig: Vec<u8>,
        /// Если PeerId не identity-multihash: protobuf `PublicKey` для проверки подписи.
        #[serde(default)]
        transport_pubkey_pb: Vec<u8>,
        /// Возможности клиента (`HELLO_CAP_*`). С v3 входят в подпись.
        #[serde(default)]
        caps: u32,
        /// Unix-секунды. Старые клиенты шлют 0 — принимается по подписи v1.
        #[serde(default)]
        ts: u64,
        /// Случайные 16 байт; вместе с `ts` входят в подпись v2.
        #[serde(default)]
        nonce: [u8; 16],
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
        envelopes: Vec<void_envelope::offline_mail::OfflineEnvelope>,
    },
    /// Запросить офлайн-почту для peer_id.
    OfflineMailboxQuery {
        recipient: String,
    },
    /// Ответ на OfflineMailboxQuery.
    OfflineMailboxDeliver {
        envelopes: Vec<void_envelope::offline_mail::OfflineEnvelope>,
    },
    /// Опубликовать X25519 prekey на bootstrap (для офлайн-seal без DHT/Hello).
    PrekeyPut {
        peer_id: String,
        public_key: [u8; 32],
        /// Unix-секунды, до которых prekey годен. 0 — старый клиент без срока.
        #[serde(default)]
        not_after: u64,
        /// Подпись identity над `VOID_PREKEY_SIG_V2`.
        #[serde(default)]
        sig: Vec<u8>,
    },
    /// Запросить prekey контакта у bootstrap.
    PrekeyGet {
        peer_id: String,
    },
    /// Ответ на PrekeyGet (или push после Put соседу через gossip — не используется).
    PrekeyOffer {
        peer_id: String,
        public_key: [u8; 32],
        #[serde(default)]
        not_after: u64,
        #[serde(default)]
        sig: Vec<u8>,
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
    /// Exit hop → recipient. `src` is the logical sender (v1 only).
    OnionDrop {
        src: String,
        packet: Box<V1Packet>,
    },
    /// Фиксированная ячейка v2 (base64). Нода снимает один слот и пересылает.
    Onion2 {
        cell_b64: String,
    },
    /// Тело после exit. Отправителя нет: печать на identity получателя.
    OnionDeliver {
        body_b64: String,
    },
    Ack,
}

/// Письмо внутри печати v2. Hello/Ack несут PeerId отправителя; Encrypted — только заголовок сессии.
pub enum V2Mail {
    Directed {
        from: PeerId,
        packet: V1Packet,
    },
    Encrypted {
        header: crypto::MessageHeader,
        ciphertext: Vec<u8>,
    },
}

fn encode_v2_mail(src: PeerId, packet: &V1Packet) -> Option<Vec<u8>> {
    match packet {
        V1Packet::Hello { .. } => {
            let id = src.to_bytes();
            if id.len() > 255 {
                return None;
            }
            let json = serde_json::to_vec(packet).ok()?;
            let mut v = Vec::with_capacity(2 + id.len() + json.len());
            v.push(1);
            v.push(id.len() as u8);
            v.extend_from_slice(&id);
            v.extend_from_slice(&json);
            Some(v)
        }
        V1Packet::Ack => {
            let id = src.to_bytes();
            if id.len() > 255 {
                return None;
            }
            let mut v = Vec::with_capacity(2 + id.len());
            v.push(3);
            v.push(id.len() as u8);
            v.extend_from_slice(&id);
            Some(v)
        }
        V1Packet::Encrypted { header, ciphertext } => {
            let mut v = Vec::with_capacity(41 + ciphertext.len());
            v.push(2);
            v.extend_from_slice(&header.dh_pub);
            v.extend_from_slice(&header.pn.to_le_bytes());
            v.extend_from_slice(&header.n.to_le_bytes());
            v.extend_from_slice(ciphertext);
            Some(v)
        }
        _ => None,
    }
}

pub fn decode_v2_mail(buf: &[u8]) -> Option<V2Mail> {
    let tag = *buf.first()?;
    match tag {
        1 | 3 => {
            let n = *buf.get(1)? as usize;
            if buf.len() < 2 + n {
                return None;
            }
            let from = PeerId::from_bytes(&buf[2..2 + n]).ok()?;
            if tag == 3 {
                if buf.len() != 2 + n {
                    return None;
                }
                return Some(V2Mail::Directed {
                    from,
                    packet: V1Packet::Ack,
                });
            }
            let packet: V1Packet = serde_json::from_slice(&buf[2 + n..]).ok()?;
            if !matches!(packet, V1Packet::Hello { .. }) {
                return None;
            }
            Some(V2Mail::Directed { from, packet })
        }
        2 => {
            if buf.len() < 41 {
                return None;
            }
            let mut dh_pub = [0u8; 32];
            dh_pub.copy_from_slice(&buf[1..33]);
            let pn = u32::from_le_bytes(buf[33..37].try_into().ok()?);
            let n = u32::from_le_bytes(buf[37..41].try_into().ok()?);
            Some(V2Mail::Encrypted {
                header: crypto::MessageHeader { dh_pub, pn, n },
                ciphertext: buf[41..].to_vec(),
            })
        }
        _ => None,
    }
}

/// Wrap `inner` for `dest` through live onion hops:
/// 1 node → 1 hop, 2 nodes → both, 3+ → three random (entry is connected).
pub fn wrap_onion_packet(
    hops: &[(PeerId, [u8; 32])],
    src: PeerId,
    dest: PeerId,
    inner: V1Packet,
    v2: bool,
) -> Option<V1Packet> {
    if hops.is_empty() {
        return None;
    }
    if v2 {
        if let Some(mail) = encode_v2_mail(src, &inner) {
            if let Ok(sealed) = seal_onion_deliver(dest, &mail) {
                if let Ok(cell) = void_onion::wrap_v2(&wire_hops(hops), wire_peer(dest), &sealed) {
                    return Some(V1Packet::Onion2 {
                        cell_b64: void_onion::b64_encode(&cell),
                    });
                }
            }
        }
    }
    let drop = V1Packet::OnionDrop {
        src: src.to_string(),
        packet: Box::new(inner),
    };
    let drop_val = serde_json::to_value(&drop).ok()?;
    let (eph, nonce, ct) = void_onion::wrap_layers(&wire_hops(hops), wire_peer(dest), drop_val).ok()?;
    Some(V1Packet::Onion { eph, nonce, ct })
}

pub fn build_v1_hello(
    transport: &libp2p_identity::Keypair,
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static_pubkey: crypto::PublicKey,
    x25519_ephem_pubkey: crypto::PublicKey,
) -> Option<V1Packet> {
    let static_b = x25519_static_pubkey.to_bytes();
    let ephem_b = x25519_ephem_pubkey.to_bytes();
    let ts = void_session::hello::hello_now_secs();
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let transport_sig = sign_hello_transport_binding(
        transport,
        signer_peer,
        recipient_peer,
        &static_b,
        &ephem_b,
        ts,
        &nonce,
        HELLO_CAPS,
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
        caps: HELLO_CAPS,
        ts,
        nonce,
    })
}


pub fn verify_onion_pk_sig(peer: PeerId, pk: &[u8; 32], sig: &[u8]) -> bool {
    let Some(pubk) = void_peer_transport_public_key(peer) else {
        return false;
    };
    pubk.verify(&void_onion::onion_pk_bind_message(wire_peer(peer), pk), sig)
}

pub fn onion_desc_fresh(epoch: u64, not_after: u64, now: u64) -> bool {
    epoch > 0 && not_after > now && not_after <= now.saturating_add(30 * 24 * 60 * 60)
}

pub fn verify_onion_desc(
    peer: PeerId,
    pk: &[u8; 32],
    epoch: u64,
    not_after: u64,
    operator: &str,
    sig: &[u8],
) -> bool {
    if operator.len() > 32 || operator.as_bytes().iter().any(|b| *b < 0x20 || *b == b';') {
        return false;
    }
    let Some(pubk) = void_peer_transport_public_key(peer) else {
        return false;
    };
    pubk.verify(
        &void_onion::desc_message(wire_peer(peer), pk, epoch, not_after, operator),
        sig,
    )
}

fn addr_is_quic_v1(ma: &Multiaddr) -> bool {
    use multiaddr::Protocol;
    ma.iter().any(|p| matches!(p, Protocol::Udp(_))) && ma.to_string().contains("quic-v1")
}

pub fn bootstrap_tcp_dial_addr(ma: &Multiaddr) -> Option<Multiaddr> {
    use multiaddr::Protocol;
    if addr_is_quic_v1(ma) {
        return None;
    }
    let mut out = Multiaddr::empty();
    let mut have_ip = false;
    let mut have_tcp = false;
    for p in ma.iter() {
        match p {
            Protocol::Ip4(_) | Protocol::Ip6(_) if !have_ip => {
                out.push(p);
                have_ip = true;
            }
            Protocol::Tcp(_) if !have_tcp => {
                out.push(p);
                have_tcp = true;
            }
            _ => {}
        }
    }
    if have_ip && have_tcp {
        Some(out)
    } else {
        None
    }
}

pub fn canonicalize_bootstrap_ma(ma: &Multiaddr) -> Option<Multiaddr> {
    use multiaddr::Protocol;
    let tcp = bootstrap_tcp_dial_addr(ma)?;
    let mut peer_before_circuit = None;
    let mut seen_circuit = false;
    let mut last_p2p = None;
    for p in ma.iter() {
        match p {
            Protocol::P2pCircuit => seen_circuit = true,
            Protocol::P2p(id) => {
                if !seen_circuit {
                    peer_before_circuit = Some(id);
                }
                last_p2p = Some(id);
            }
            _ => {}
        }
    }
    let pid = peer_before_circuit.or(last_p2p)?;
    let mut out = tcp;
    out.push(Protocol::P2p(pid));
    Some(out)
}

#[cfg(test)]
mod hello_freshness_tests {
    use super::*;
    use void_session::crypto::{PublicKey, StaticSecret};
    use libp2p_identity::Keypair;

    #[test]
    fn v2_signature_roundtrip() {
        let kp = Keypair::generate_ed25519();
        let signer = kp.public().to_peer_id();
        let recipient = Keypair::generate_ed25519().public().to_peer_id();
        let static_b =
            PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let ephem_b = PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let hello = build_v1_hello(
            &kp,
            signer,
            recipient,
            PublicKey::from(static_b),
            PublicKey::from(ephem_b),
        )
        .unwrap();
        let V1Packet::Hello {
            public_key,
            ephemeral_key,
            transport_sig,
            transport_pubkey_pb,
            caps,
            ts,
            nonce,
        } = hello
        else {
            panic!("not hello");
        };
        assert!(ts != 0);
        assert!(nonce.iter().any(|b| *b != 0));
        assert_eq!(
            verify_hello_transport_binding(
                signer,
                recipient,
                &public_key,
                &ephemeral_key,
                &transport_sig,
                &transport_pubkey_pb,
                ts,
                &nonce,
                caps,
            ),
            Some(HelloBind::V3)
        );
        assert!(verify_hello_transport_binding(
            signer,
            recipient,
            &public_key,
            &ephemeral_key,
            &transport_sig,
            &transport_pubkey_pb,
            ts.saturating_sub(HELLO_FRESHNESS_SECS + 1),
            &nonce,
            caps,
        )
        .is_none());
        assert!(verify_hello_transport_binding(
            signer,
            recipient,
            &public_key,
            &ephemeral_key,
            &transport_sig,
            &transport_pubkey_pb,
            ts,
            &nonce,
            caps ^ 1,
        )
        .is_none());
        assert!(hello_bind_ok(HelloBind::V3, caps, true));
        assert!(hello_bind_ok(HelloBind::V3, caps, false));
        assert!(!hello_bind_ok(HelloBind::V2, caps, true));
        assert!(!hello_bind_ok(HelloBind::V2, caps, false));
        assert!(!hello_bind_ok(HelloBind::V3, 0, true));
        assert!(!hello_bind_ok(HelloBind::V3, 0, false));
    }
}
