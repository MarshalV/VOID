//! Offline mail via DHT and peer relay.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use libp2p_identity::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use void_session::crypto::{PublicKey, StaticSecret};

pub fn peer_id_from_bytes(bytes: &[u8]) -> Option<PeerId> {
    PeerId::from_bytes(bytes).ok()
}

pub const PREKEY_PREFIX: &[u8] = b"/void/prekey/";
pub const OPK_PREFIX: &[u8] = b"/void/opk/";
pub const MAILBOX_PREFIX: &[u8] = b"/void/mailbox/";
/// Сколько одноразовых ключей держит получатель и сколько кладёт в DHT-список.
pub const OPK_POOL: usize = 16;
pub const MAILBOX_TTL_SECS: u64 = 60 * 60 * 24 * 7;

/// Offline-доставка голосовых: аудио режется на кусочки и уходит через тот же
/// relay/bootstrap store-and-forward канал, что и офлайн-почта для текста
/// (DHT-запись мимо — там жёсткий лимит 64 КБ на весь ящик, см. mailbox_record_key).
pub const OFFLINE_VOICE_CHUNK_SIZE: usize = 24 * 1024;
/// Максимальный размер WAV, который мы согласны прогонять через offline-очередь
/// целиком (иначе — только метаданные, аудио дождётся живой передачи).
pub const OFFLINE_VOICE_MAX_BYTES: u64 = 3 * 1024 * 1024;
pub const OFFLINE_VOICE_CHUNK_KIND: &str = "voice_chunk";
/// Тот же рез, что у голоса: один кусок после печати v3 (и с ML-KEM) помещается
/// в бакет очереди 64 КиБ. Файл крупнее этого потолка остаётся на живом `VfC1`.
pub const OFFLINE_FILE_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const OFFLINE_FILE_CHUNK_KIND: &str = "file_chunk";

/// Плейнтекст одного чанка (до шифрования в `seal_for_recipient`):
/// `[transfer_id:16][index:u32 LE][total:u32 LE][total_size:u32 LE][bytes...]`.
pub fn encode_voice_chunk_payload(
    transfer_id: &[u8; 16],
    index: u32,
    total: u32,
    total_size: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(28 + data.len());
    out.extend_from_slice(transfer_id);
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(data);
    out
}

pub struct VoiceChunk {
    pub transfer_id: [u8; 16],
    pub index: u32,
    pub total: u32,
    pub total_size: u32,
    pub data: Vec<u8>,
}

pub fn decode_voice_chunk_payload(bytes: &[u8]) -> Option<VoiceChunk> {
    if bytes.len() < 28 {
        return None;
    }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[0..16]);
    let index = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
    let total = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
    let total_size = u32::from_le_bytes(bytes[24..28].try_into().ok()?);
    if total == 0 || index >= total {
        return None;
    }
    Some(VoiceChunk {
        transfer_id,
        index,
        total,
        total_size,
        data: bytes[28..].to_vec(),
    })
}

/// Режет байты на куски того же формата, что `voice_chunk`. `None`, если пусто
/// или длиннее `max_bytes`.
pub fn split_capped_for_offline(
    transfer_id: &[u8; 16],
    bytes: &[u8],
    max_bytes: u64,
) -> Option<Vec<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return None;
    }
    let total_size = bytes.len() as u32;
    let total = bytes.len().div_ceil(OFFLINE_VOICE_CHUNK_SIZE).max(1) as u32;
    let mut out = Vec::with_capacity(total as usize);
    for (i, chunk) in bytes.chunks(OFFLINE_VOICE_CHUNK_SIZE).enumerate() {
        out.push(encode_voice_chunk_payload(
            transfer_id,
            i as u32,
            total,
            total_size,
            chunk,
        ));
    }
    Some(out)
}

/// Режет байты WAV на чанки для offline-доставки. Возвращает `None`, если файл
/// больше `OFFLINE_VOICE_MAX_BYTES` — в этом случае аудио дождётся живой передачи.
pub fn split_voice_for_offline(transfer_id: &[u8; 16], bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    split_capped_for_offline(transfer_id, bytes, OFFLINE_VOICE_MAX_BYTES)
}

/// Режет файл для offline-доставки. Крупнее `OFFLINE_FILE_MAX_BYTES` не режется:
/// такой файл ждёт живой `VfC1`, чтобы одна передача не забила очередь.
pub fn split_file_for_offline(transfer_id: &[u8; 16], bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    split_capped_for_offline(transfer_id, bytes, OFFLINE_FILE_MAX_BYTES)
}

/// Собирает WAV из набора чанков (индекс → данные). `None`, если набор неполный
/// или суммарный размер не совпал с `total_size`.
pub fn assemble_voice_chunks(
    total: u32,
    total_size: u32,
    chunks: &std::collections::HashMap<u32, Vec<u8>>,
) -> Option<Vec<u8>> {
    if total == 0 || chunks.len() != total as usize {
        return None;
    }
    let mut out = Vec::with_capacity(total_size as usize);
    for i in 0..total {
        out.extend_from_slice(chunks.get(&i)?);
    }
    if out.len() as u32 != total_size {
        return None;
    }
    Some(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineEnvelope {
    pub v: u8,
    pub sender: String,
    pub sender_pk: [u8; 32],
    pub message_id: String,
    pub kind: String,
    pub eph: [u8; 32],
    pub nonce: [u8; 12],
    /// CBOR: байтовая строка. JSON и bincode ящика — как у `Vec<u8>`.
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
    /// Настоящий `kind` у отправителя (в v3 снаружи пусто); в сеть не уходит.
    #[serde(skip)]
    pub local_kind: String,
}

impl OfflineEnvelope {
    pub fn is_voice_chunk(&self) -> bool {
        self.local_kind == OFFLINE_VOICE_CHUNK_KIND || self.kind == OFFLINE_VOICE_CHUNK_KIND
    }

    pub fn is_file_chunk(&self) -> bool {
        self.local_kind == OFFLINE_FILE_CHUNK_KIND || self.kind == OFFLINE_FILE_CHUNK_KIND
    }

    /// Кусок файла или голоса: в DHT-запись ящика его не кладут.
    pub fn is_offline_blob(&self) -> bool {
        self.is_voice_chunk() || self.is_file_chunk()
    }
}

pub fn mailbox_value_is_v3(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 64 * 1024 {
        return false;
    }
    let Ok(envs) = decode_mailbox(value) else {
        return false;
    };
    !envs.is_empty()
        && envs.len() <= 64
        && envs.iter().all(|e| {
            e.v == ENVELOPE_VERSION
                && e.sender.is_empty()
                && e.kind.is_empty()
                && !e.message_id.is_empty()
                && e.message_id.len() <= 128
                && !e.ct.is_empty()
                && e.ct.len() <= 64 * 1024
                && e.eph != [0u8; 32]
        })
}

pub fn encode_mailbox(envelopes: &[OfflineEnvelope]) -> Result<Vec<u8>> {
    // bincode вместо JSON: `ct`/`sender_pk`/`eph`/`nonce` — бинарные поля, JSON
    // раздувает Vec<u8> в массив чисел (~3-4x) — критично, когда в конвертах
    // может лежать аудио голосового (voice_chunk).
    bincode::serialize(envelopes).map_err(|e| anyhow!("mailbox bincode: {e}"))
}

pub fn decode_mailbox(bytes: &[u8]) -> Result<Vec<OfflineEnvelope>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // Обратная совместимость: старые mailbox-записи/файлы могли быть в JSON.
    if let Ok(envs) = bincode::deserialize::<Vec<OfflineEnvelope>>(bytes) {
        return Ok(envs);
    }
    serde_json::from_slice(bytes).map_err(|e| anyhow!("mailbox decode: {e}"))
}

/// v3: отправитель, `kind` и `message_id` только внутри `ct`, снаружи — непрозрачный id.
/// v2 (подписан, поля открыты) ещё принимается; v1 (без подписи) — нет.
pub const ENVELOPE_VERSION: u8 = 3;
const ENVELOPE_V2: u8 = 2;
const OFFLINE_SIG_PREFIX: &[u8] = b"VOID_OFFLINE_SIG_V2\0";
const OFFLINE_AAD_PREFIX: &[u8] = b"VOID_OFFLINE_AAD_V2\0";
const OFFLINE_SIG_PREFIX_V3: &[u8] = b"VOID_OFFLINE_SIG_V3\0";
const OFFLINE_AAD_PREFIX_V3: &[u8] = b"VOID_OFFLINE_AAD_V3\0";
const OFFLINE_ID_PREFIX_V3: &[u8] = b"VOID_OFFLINE_ID_V3\0";
const MAX_OFFLINE_SIG: usize = 256;
const MAX_OFFLINE_PUBKEY_PB: usize = 4096;
/// Тело v3 выравнивается до степени двойки (не меньше `MIN_PADDED_BODY`),
/// крупнее `PAD_STEP` — до кратного `PAD_STEP` (голосовые чанки 24 КБ).
const MIN_PADDED_BODY: usize = 512;
const PAD_STEP: usize = 4096;

/// Вскрытый и проверенный конверт.
#[derive(Debug)]
pub struct OpenedEnvelope {
    pub sender: PeerId,
    pub message_id: String,
    pub kind: String,
    pub body: Vec<u8>,
}

/// Внешний id v3: нода дедуплицирует повторы, но не видит настоящий `message_id`
/// (`vchunk:<transfer>:<i>` и т.п.) и не связывает конверты разных получателей.
fn outer_message_id(recipient: &PeerId, message_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(OFFLINE_ID_PREFIX_V3);
    h.update(recipient.to_bytes());
    h.update(message_id.as_bytes());
    h.finalize()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn padded_len(n: usize) -> usize {
    if n <= PAD_STEP {
        n.max(MIN_PADDED_BODY).next_power_of_two()
    } else {
        n.div_ceil(PAD_STEP) * PAD_STEP
    }
}

fn read_lp<'a>(b: &mut &'a [u8], max: usize) -> Option<&'a [u8]> {
    let n = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?) as usize;
    if n > max || b.len() < 4 + n {
        return None;
    }
    let out = &b[4..4 + n];
    *b = &b[4 + n..];
    Some(out)
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Заголовок конверта и получатель: AAD шифра и часть подписанного сообщения.
/// Нода не может переписать `sender`/`kind`/`message_id` или перенаправить конверт другому.
#[allow(clippy::too_many_arguments)]
fn envelope_header_bytes(
    prefix: &[u8],
    version: u8,
    sender: &PeerId,
    recipient: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    eph: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(prefix.len() + 192 + message_id.len() + kind.len());
    v.extend_from_slice(prefix);
    v.push(version);
    push_lp(&mut v, &sender.to_bytes());
    push_lp(&mut v, &recipient.to_bytes());
    v.extend_from_slice(sender_pk);
    push_lp(&mut v, message_id.as_bytes());
    push_lp(&mut v, kind.as_bytes());
    v.extend_from_slice(eph);
    v
}

fn signed_message(header: &[u8], body: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut v = header.to_vec();
    v.extend_from_slice(&Sha256::digest(body));
    v
}

/// Плейнтекст v2: `[sig_len:u16][sig][pb_len:u16][pubkey_pb][body]`.
fn encode_signed_inner(sig: &[u8], pubkey_pb: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + sig.len() + pubkey_pb.len() + body.len());
    out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    out.extend_from_slice(sig);
    out.extend_from_slice(&(pubkey_pb.len() as u16).to_le_bytes());
    out.extend_from_slice(pubkey_pb);
    out.extend_from_slice(body);
    out
}

fn decode_signed_inner(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let take = |b: &[u8], max: usize| -> Option<(usize, usize)> {
        let n = u16::from_le_bytes(b.get(0..2)?.try_into().ok()?) as usize;
        if n > max || b.len() < 2 + n {
            return None;
        }
        Some((2, 2 + n))
    };
    let (s0, s1) = take(bytes, MAX_OFFLINE_SIG)?;
    let sig = &bytes[s0..s1];
    let rest = &bytes[s1..];
    let (p0, p1) = take(rest, MAX_OFFLINE_PUBKEY_PB)?;
    Some((sig, &rest[p0..p1], &rest[p1..]))
}

const PREKEY_SIG_PREFIX: &[u8] = b"VOID_PREKEY_SIG_V1\0";
const PREKEY_SIG_PREFIX_V2: &[u8] = b"VOID_PREKEY_SIG_V2\0";
const PREKEY_SIG_PREFIX_V3: &[u8] = b"VOID_PREKEY_SIG_V3\0";
const PREKEY_V2_MARK: u8 = 2;
const PREKEY_V3_MARK: u8 = 3;
/// Срок ротируемого prekey. Дольше этого DHT и нода запись не держат.
pub const PREKEY_TTL_SECS: u64 = 7 * 24 * 3600;
pub const PREKEY_MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// Подписанный X25519 prekey. `not_after == 0` — старый формат без срока:
/// для запечатывания не годится (это не PFS), identity остаётся запасным.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedPrekey {
    pub pk: [u8; 32],
    pub not_after: u64,
    /// ML-KEM-768 encapsulation key. Нули — запись v1/v2, только X25519.
    pub kem_ek: [u8; void_session::kem::EK_LEN],
}

impl SignedPrekey {
    pub fn x25519(pk: [u8; 32], not_after: u64) -> Self {
        Self {
            pk,
            not_after,
            kem_ek: [0u8; void_session::kem::EK_LEN],
        }
    }
}

fn prekey_signed_message(owner: &PeerId, pk: &[u8; 32]) -> Vec<u8> {
    let mut v = PREKEY_SIG_PREFIX.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(pk);
    v
}

fn prekey_signed_message_v2(owner: &PeerId, pk: &[u8; 32], not_after: u64) -> Vec<u8> {
    let mut v = PREKEY_SIG_PREFIX_V2.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(pk);
    v.extend_from_slice(&not_after.to_le_bytes());
    v
}

fn prekey_signed_message_v3(owner: &PeerId, pk: &[u8; 32], not_after: u64, kem_ek: &[u8]) -> Vec<u8> {
    let mut v = PREKEY_SIG_PREFIX_V3.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(pk);
    v.extend_from_slice(&not_after.to_le_bytes());
    v.extend_from_slice(kem_ek);
    v
}

/// Готовый к публикации prekey: DHT-значение и поля `PrekeyPut`.
#[derive(Clone)]
pub struct PublishedPrekey {
    pub pk: [u8; 32],
    pub not_after: u64,
    pub sig: Vec<u8>,
    pub dht_value: Vec<u8>,
    pub kem_ek: Vec<u8>,
}

/// DHT `/void/prekey/<owner>` v2: `pk[32] || 0x02 || not_after[8] || sig_inner`.
/// v1 (без срока) ещё проверяется, но [`prekey_is_sealable`] его отвергает.
pub fn encode_signed_prekey(
    transport: &libp2p_identity::Keypair,
    owner: &PeerId,
    pk: &[u8; 32],
    not_after: u64,
) -> Option<PublishedPrekey> {
    if PeerId::from_public_key(&transport.public()) != *owner || not_after == 0 {
        return None;
    }
    let sig = transport
        .sign(&prekey_signed_message_v2(owner, pk, not_after))
        .ok()?;
    let pubkey_pb = if void_session::hello::void_peer_transport_public_key(*owner).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    };
    let mut dht_value = pk.to_vec();
    dht_value.push(PREKEY_V2_MARK);
    dht_value.extend_from_slice(&not_after.to_le_bytes());
    dht_value.extend_from_slice(&encode_signed_inner(&sig, &pubkey_pb, &[]));
    Some(PublishedPrekey {
        pk: *pk,
        not_after,
        sig,
        dht_value,
        kem_ek: Vec::new(),
    })
}

/// DHT v3: `pk[32] || 0x03 || not_after[8] || kem_ek[1184] || sig_inner`.
/// Подпись покрывает оба ключа. v2 остаётся для старых записей.
pub fn encode_signed_prekey_v3(
    transport: &libp2p_identity::Keypair,
    owner: &PeerId,
    pk: &[u8; 32],
    not_after: u64,
    kem_ek: &[u8],
) -> Option<PublishedPrekey> {
    if PeerId::from_public_key(&transport.public()) != *owner
        || not_after == 0
        || kem_ek.len() != void_session::kem::EK_LEN
    {
        return None;
    }
    let sig = transport
        .sign(&prekey_signed_message_v3(owner, pk, not_after, kem_ek))
        .ok()?;
    let pubkey_pb = if void_session::hello::void_peer_transport_public_key(*owner).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    };
    let mut dht_value = pk.to_vec();
    dht_value.push(PREKEY_V3_MARK);
    dht_value.extend_from_slice(&not_after.to_le_bytes());
    dht_value.extend_from_slice(kem_ek);
    dht_value.extend_from_slice(&encode_signed_inner(&sig, &pubkey_pb, &[]));
    Some(PublishedPrekey {
        pk: *pk,
        not_after,
        sig,
        dht_value,
        kem_ek: kem_ek.to_vec(),
    })
}

/// Prekey из DHT-записи, только если её подписал владелец `owner`.
pub fn verify_signed_prekey(owner: &PeerId, value: &[u8]) -> Option<SignedPrekey> {
    let pk: [u8; 32] = value.get(..32)?.try_into().ok()?;
    if pk == [0u8; 32] {
        return None;
    }
    if value.get(32) == Some(&PREKEY_V2_MARK) {
        let not_after = u64::from_le_bytes(value.get(33..41)?.try_into().ok()?);
        let (sig, pubkey_pb, rest) = decode_signed_inner(value.get(41..)?)?;
        if sig.is_empty() || !rest.is_empty() {
            return None;
        }
        let signer = void_session::hello::void_hello_signing_public_key(*owner, pubkey_pb)?;
        if !signer.verify(&prekey_signed_message_v2(owner, &pk, not_after), sig) {
            return None;
        }
        return Some(SignedPrekey {
            pk,
            not_after,
            kem_ek: [0u8; void_session::kem::EK_LEN],
        });
    }
    if value.get(32) == Some(&PREKEY_V3_MARK) {
        let not_after = u64::from_le_bytes(value.get(33..41)?.try_into().ok()?);
        let ek_end = 41 + void_session::kem::EK_LEN;
        let kem_ek: [u8; void_session::kem::EK_LEN] = value.get(41..ek_end)?.try_into().ok()?;
        let (sig, pubkey_pb, rest) = decode_signed_inner(value.get(ek_end..)?)?;
        if sig.is_empty() || !rest.is_empty() {
            return None;
        }
        let signer = void_session::hello::void_hello_signing_public_key(*owner, pubkey_pb)?;
        if !signer.verify(
            &prekey_signed_message_v3(owner, &pk, not_after, &kem_ek),
            sig,
        ) {
            return None;
        }
        return Some(SignedPrekey {
            pk,
            not_after,
            kem_ek,
        });
    }
    let (sig, pubkey_pb, rest) = decode_signed_inner(value.get(32..)?)?;
    if sig.is_empty() || !rest.is_empty() {
        return None;
    }
    let signer = void_session::hello::void_hello_signing_public_key(*owner, pubkey_pb)?;
    signer
        .verify(&prekey_signed_message(owner, &pk), sig)
        .then_some(SignedPrekey::x25519(pk, 0))
}

/// Подпись `PrekeyPut` / `PrekeyOffer` (сырой sig, не DHT-блоб).
pub fn verify_prekey_offer(
    owner: &PeerId,
    pk: &[u8; 32],
    not_after: u64,
    sig: &[u8],
    kem_ek: &[u8],
) -> bool {
    if *pk == [0u8; 32] || sig.is_empty() || not_after == 0 {
        return false;
    }
    let Some(signer) = void_session::hello::void_peer_transport_public_key(*owner) else {
        return false;
    };
    if kem_ek.len() == void_session::kem::EK_LEN {
        return signer.verify(&prekey_signed_message_v3(owner, pk, not_after, kem_ek), sig);
    }
    signer.verify(&prekey_signed_message_v2(owner, pk, not_after), sig)
}

pub fn prekey_is_sealable(prekey: SignedPrekey, now: u64) -> bool {
    prekey.not_after > now && prekey.not_after <= now.saturating_add(PREKEY_MAX_TTL_SECS)
}

pub fn prekey_unix_now() -> u64 {
    prekey_now()
}

fn prekey_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// X25519-ключ офлайн-почты, выведенный из Ed25519-ключа внутри PeerId
/// (как `crypto_sign_ed25519_pk_to_curve25519`). Его не раздаёт ни нода, ни DHT —
/// подменить нечего.
pub fn identity_offline_public(peer: &PeerId) -> Option<PublicKey> {
    let ed = void_session::hello::void_peer_transport_public_key(*peer)?
        .try_into_ed25519()
        .ok()?;
    let point = curve25519_dalek::edwards::CompressedEdwardsY(ed.to_bytes()).decompress()?;
    if point.is_small_order() {
        return None;
    }
    Some(PublicKey::from(point.to_montgomery().to_bytes()))
}

/// Секрет к [`identity_offline_public`]: скаляр Ed25519 (первая половина SHA-512 от seed).
pub fn identity_offline_secret(key: &libp2p_identity::Keypair) -> Option<StaticSecret> {
    use sha2::{Digest, Sha512};
    let ed = key.clone().try_into_ed25519().ok()?;
    let pair = zeroize::Zeroizing::new(ed.to_bytes());
    let mut h = Sha512::digest(&pair[..32]);
    let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&h[..32]);
    h.as_mut_slice().fill(0);
    Some(StaticSecret::from(*scalar))
}

/// Ключ запечатывания нового письма: только проверенный prekey.
/// X25519 из PeerId сюда не подставляется. Им открывают старые конверты.
pub fn offline_seal_key(
    _recipient: &PeerId,
    verified_prekey: Option<[u8; 32]>,
) -> Option<PublicKey> {
    let pk = verified_prekey?;
    if pk == [0u8; 32] {
        return None;
    }
    Some(PublicKey::from(pk))
}

const OPK_SIG_PREFIX: &[u8] = b"VOID_OPK_SIG_V1\0";

/// Один одноразовый X25519. `id` уходит внутрь печати, не на ноду отдельным полем конверта.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub id: [u8; 16],
    pub pk: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Секрет одноразового ключа на диске получателя.
#[derive(Clone)]
pub struct OpkSecret {
    pub id: [u8; 16],
    pub secret: StaticSecret,
}

/// Что нужно, чтобы закрыть новое письмо. Пустой набор одноразовых — `None`, письмо ждёт.
pub struct SealMaterial {
    pub spk: [u8; 32],
    pub opk_id: [u8; 16],
    pub opk_pk: [u8; 32],
    pub kem_ek: Vec<u8>,
}

pub fn seal_material(
    spk: Option<SignedPrekey>,
    opk: Option<&OneTimePrekey>,
    now: u64,
) -> Option<SealMaterial> {
    let spk = spk.filter(|p| prekey_is_sealable(*p, now))?;
    let opk = opk.filter(|o| o.id != [0u8; 16] && o.pk != [0u8; 32] && !o.sig.is_empty())?;
    let kem_ek = if spk.kem_ek.iter().any(|b| *b != 0) {
        spk.kem_ek.to_vec()
    } else {
        Vec::new()
    };
    Some(SealMaterial {
        spk: spk.pk,
        opk_id: opk.id,
        opk_pk: opk.pk,
        kem_ek,
    })
}

fn opk_signed_message(owner: &PeerId, id: &[u8; 16], pk: &[u8; 32]) -> Vec<u8> {
    let mut v = OPK_SIG_PREFIX.to_vec();
    push_lp(&mut v, &owner.to_bytes());
    v.extend_from_slice(id);
    v.extend_from_slice(pk);
    v
}

pub fn encode_one_time_prekey(
    transport: &libp2p_identity::Keypair,
    owner: &PeerId,
    id: &[u8; 16],
    pk: &[u8; 32],
) -> Option<OneTimePrekey> {
    if PeerId::from_public_key(&transport.public()) != *owner
        || *id == [0u8; 16]
        || *pk == [0u8; 32]
    {
        return None;
    }
    let sig = transport.sign(&opk_signed_message(owner, id, pk)).ok()?;
    Some(OneTimePrekey { id: *id, pk: *pk, sig })
}

pub fn verify_opk(owner: &PeerId, id: &[u8; 16], pk: &[u8; 32], sig: &[u8]) -> bool {
    if *id == [0u8; 16] || *pk == [0u8; 32] || sig.is_empty() {
        return false;
    }
    let Some(signer) = void_session::hello::void_peer_transport_public_key(*owner) else {
        return false;
    };
    signer.verify(&opk_signed_message(owner, id, pk), sig)
}

/// DHT `/void/opk/<owner>`: `0x01 || u16le count || (id[16] || pk[32] || lp(sig))*`.
pub fn encode_opk_bundle(opks: &[OneTimePrekey]) -> Vec<u8> {
    let n = opks.len().min(OPK_POOL);
    let mut v = Vec::with_capacity(3 + n * 80);
    v.push(1);
    v.extend_from_slice(&(n as u16).to_le_bytes());
    for o in opks.iter().take(n) {
        v.extend_from_slice(&o.id);
        v.extend_from_slice(&o.pk);
        push_lp(&mut v, &o.sig);
    }
    v
}

pub fn decode_opk_bundle(owner: &PeerId, bytes: &[u8]) -> Option<Vec<OneTimePrekey>> {
    if bytes.first() != Some(&1) {
        return None;
    }
    let n = u16::from_le_bytes(bytes.get(1..3)?.try_into().ok()?) as usize;
    if n == 0 || n > OPK_POOL {
        return None;
    }
    let mut rest = &bytes[3..];
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let id: [u8; 16] = rest.get(..16)?.try_into().ok()?;
        rest = &rest[16..];
        let pk: [u8; 32] = rest.get(..32)?.try_into().ok()?;
        rest = &rest[32..];
        let sig = read_lp(&mut rest, 256)?.to_vec();
        if !verify_opk(owner, &id, &pk, &sig) {
            return None;
        }
        out.push(OneTimePrekey { id, pk, sig });
    }
    if !rest.is_empty() {
        return None;
    }
    Some(out)
}

/// Каталог ноды: `PrekeyOffer` отдаёт signed-prekey и один одноразовый, затем стирает его.
#[derive(Default)]
pub struct NodePrekeys {
    records: HashMap<String, NodePrekey>,
}

struct NodePrekey {
    pk: [u8; 32],
    not_after: u64,
    sig: Vec<u8>,
    opks: Vec<OneTimePrekey>,
    spent: Vec<[u8; 16]>,
}

pub struct PrekeyOfferParts {
    pub public_key: [u8; 32],
    pub not_after: u64,
    pub sig: Vec<u8>,
    pub opk: OneTimePrekey,
}

impl NodePrekeys {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Кладёт signed-prekey и дописывает новые одноразовые. Уже выданные id не возвращаются.
    pub fn put(
        &mut self,
        peer: &str,
        pk: [u8; 32],
        not_after: u64,
        sig: Vec<u8>,
        kem_ek: &[u8],
        opks: Vec<OneTimePrekey>,
        now: u64,
    ) -> bool {
        let Ok(owner) = peer.parse::<PeerId>() else {
            return false;
        };
        if !verify_prekey_offer(&owner, &pk, not_after, &sig, kem_ek)
            || !prekey_is_sealable(SignedPrekey::x25519(pk, not_after), now)
        {
            return false;
        }
        let entry = self.records.entry(peer.to_string()).or_insert(NodePrekey {
            pk,
            not_after,
            sig: sig.clone(),
            opks: Vec::new(),
            spent: Vec::new(),
        });
        entry.pk = pk;
        entry.not_after = not_after;
        entry.sig = sig;
        for opk in opks {
            if entry.opks.len() >= OPK_POOL {
                break;
            }
            if entry.spent.contains(&opk.id) || entry.opks.iter().any(|o| o.id == opk.id) {
                continue;
            }
            if verify_opk(&owner, &opk.id, &opk.pk, &opk.sig) {
                entry.opks.push(opk);
            }
        }
        true
    }

    /// Один одноразовый на выдачу. Пустой набор — `None`, письмо у отправителя ждёт.
    pub fn take_offer(&mut self, peer: &str) -> Option<PrekeyOfferParts> {
        let entry = self.records.get_mut(peer)?;
        if entry.opks.is_empty() {
            return None;
        }
        let opk = entry.opks.remove(0);
        entry.spent.push(opk.id);
        if entry.spent.len() > 256 {
            let drop_n = entry.spent.len() - 256;
            entry.spent.drain(0..drop_n);
        }
        Some(PrekeyOfferParts {
            public_key: entry.pk,
            not_after: entry.not_after,
            sig: entry.sig.clone(),
            opk,
        })
    }

    pub fn export(&self) -> Vec<u8> {
        let items: Vec<StoredNodePrekey> = self
            .records
            .iter()
            .map(|(peer, entry)| StoredNodePrekey {
                peer: peer.clone(),
                pk: entry.pk,
                not_after: entry.not_after,
                sig: entry.sig.clone(),
                opks: entry.opks.clone(),
                spent: entry.spent.clone(),
            })
            .collect();
        bincode::serialize(&items).unwrap_or_default()
    }

    pub fn import(bytes: &[u8]) -> Self {
        let items: Vec<StoredNodePrekey> = bincode::deserialize(bytes).unwrap_or_default();
        let mut records = HashMap::new();
        for item in items {
            records.insert(
                item.peer,
                NodePrekey {
                    pk: item.pk,
                    not_after: item.not_after,
                    sig: item.sig,
                    opks: item.opks,
                    spent: item.spent,
                },
            );
        }
        Self { records }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredNodePrekey {
    peer: String,
    pk: [u8; 32],
    not_after: u64,
    sig: Vec<u8>,
    opks: Vec<OneTimePrekey>,
    spent: Vec<[u8; 16]>,
}

pub const PREKEY_FILE: &str = "offline_prekey.bin";
const PREKEY_ROTATE_MARGIN: u64 = 24 * 3600;

#[derive(Serialize, Deserialize)]
struct OpkDisk {
    id: [u8; 16],
    secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct OfflinePrekeyDisk {
    secret: [u8; 32],
    not_after: u64,
    #[serde(default)]
    prev_secret: Option<[u8; 32]>,
    #[serde(default)]
    prev_not_after: u64,
    #[serde(default)]
    opks: Vec<OpkDisk>,
    #[serde(default)]
    spent_opk: Vec<[u8; 16]>,
}

/// Файл с seed ML-KEM. Старый `OfflinePrekeyDisk` читается, если этих полей ещё нет.
#[derive(Serialize, Deserialize)]
struct OfflinePrekeyDiskKem {
    secret: [u8; 32],
    not_after: u64,
    #[serde(default)]
    prev_secret: Option<[u8; 32]>,
    #[serde(default)]
    prev_not_after: u64,
    #[serde(default)]
    opks: Vec<OpkDisk>,
    #[serde(default)]
    spent_opk: Vec<[u8; 16]>,
    kem_dk: Vec<u8>,
    prev_kem_dk: Vec<u8>,
}
#[derive(Deserialize)]
struct OfflinePrekeyDiskV0 {
    secret: [u8; 32],
    not_after: u64,
    #[serde(default)]
    prev_secret: Option<[u8; 32]>,
    #[serde(default)]
    prev_not_after: u64,
}

/// Секреты, которыми ещё можно вскрыть почту, запечатанную к нашему prekey.
pub struct LocalPrekeys {
    pub published: PublishedPrekey,
    pub secrets: Vec<StaticSecret>,
    pub opks: Vec<OneTimePrekey>,
    pub opk_secrets: Vec<OpkSecret>,
    pub spent_opk: Vec<[u8; 16]>,
    pub kem_dks: Vec<Vec<u8>>,
}

fn read_prekey_disk(bytes: &[u8]) -> Option<OfflinePrekeyDiskKem> {
    if let Ok(disk) = bincode::deserialize::<OfflinePrekeyDiskKem>(bytes) {
        return Some(disk);
    }
    if let Ok(old) = bincode::deserialize::<OfflinePrekeyDisk>(bytes) {
        return Some(OfflinePrekeyDiskKem {
            secret: old.secret,
            not_after: old.not_after,
            prev_secret: old.prev_secret,
            prev_not_after: old.prev_not_after,
            opks: old.opks,
            spent_opk: old.spent_opk,
            kem_dk: Vec::new(),
            prev_kem_dk: Vec::new(),
        });
    }
    let old: OfflinePrekeyDiskV0 = bincode::deserialize(bytes).ok()?;
    Some(OfflinePrekeyDiskKem {
        secret: old.secret,
        not_after: old.not_after,
        prev_secret: old.prev_secret,
        prev_not_after: old.prev_not_after,
        opks: Vec::new(),
        spent_opk: Vec::new(),
        kem_dk: Vec::new(),
        prev_kem_dk: Vec::new(),
    })
}

fn write_prekey_disk(path: &Path, disk: &OfflinePrekeyDiskKem) {
    let Ok(bytes) = bincode::serialize(disk) else {
        return;
    };
    let tmp = path.with_extension("bin.tmp");
    if std::fs::write(&tmp, &bytes).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn empty_prekey_disk() -> OfflinePrekeyDiskKem {
    OfflinePrekeyDiskKem {
        secret: [0u8; 32],
        not_after: 0,
        prev_secret: None,
        prev_not_after: 0,
        opks: Vec::new(),
        spent_opk: Vec::new(),
        kem_dk: Vec::new(),
        prev_kem_dk: Vec::new(),
    }
}

/// Загружает или ротирует signed-prekey и пачку одноразовых, подписывает identity-ключом.
pub fn load_local_prekeys(
    transport: &libp2p_identity::Keypair,
    path: &Path,
) -> Option<LocalPrekeys> {
    let owner = PeerId::from_public_key(&transport.public());
    let now = prekey_now();
    let mut disk = std::fs::read(path)
        .ok()
        .and_then(|b| read_prekey_disk(&b))
        .unwrap_or_else(empty_prekey_disk);
    let stale = disk.not_after == 0 || now.saturating_add(PREKEY_ROTATE_MARGIN) >= disk.not_after;
    if stale {
        if disk.not_after > now && disk.secret != [0u8; 32] {
            disk.prev_secret = Some(disk.secret);
            disk.prev_not_after = disk.not_after;
            if disk.kem_dk.len() == void_session::kem::DK_LEN {
                disk.prev_kem_dk = disk.kem_dk.clone();
            }
        }
        disk.secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng).to_bytes();
        disk.not_after = now.saturating_add(PREKEY_TTL_SECS);
        disk.kem_dk = void_session::kem::generate().0.as_bytes().to_vec();
    }
    if disk.kem_dk.len() != void_session::kem::DK_LEN {
        disk.kem_dk = void_session::kem::generate().0.as_bytes().to_vec();
    }
    if disk.prev_not_after <= now {
        disk.prev_secret = None;
        disk.prev_not_after = 0;
    }
    let spk_secret = StaticSecret::from(disk.secret);
    let pk = PublicKey::from(&spk_secret).to_bytes();
    let kem_dk = void_session::kem::KemDk::from_bytes(&disk.kem_dk)?;
    let kem_ek = kem_dk.encapsulation_key()?;
    let published = encode_signed_prekey_v3(transport, &owner, &pk, disk.not_after, &kem_ek)?;
    disk.opks.retain(|o| o.id != [0u8; 16] && o.secret != [0u8; 32]);
    while disk.opks.len() < OPK_POOL {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        if id == [0u8; 16] || disk.spent_opk.contains(&id) || disk.opks.iter().any(|o| o.id == id)
        {
            continue;
        }
        let secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng).to_bytes();
        disk.opks.push(OpkDisk { id, secret });
    }
    let mut opks = Vec::with_capacity(disk.opks.len());
    let mut opk_secrets = Vec::with_capacity(disk.opks.len());
    for o in &disk.opks {
        let secret = StaticSecret::from(o.secret);
        let public = PublicKey::from(&secret).to_bytes();
        let signed = encode_one_time_prekey(transport, &owner, &o.id, &public)?;
        opk_secrets.push(OpkSecret { id: o.id, secret });
        opks.push(signed);
    }
    write_prekey_disk(path, &disk);
    let mut secrets = vec![spk_secret];
    let mut kem_dks = vec![disk.kem_dk.clone()];
    if let Some(prev) = disk.prev_secret {
        secrets.push(StaticSecret::from(prev));
    }
    if disk.prev_kem_dk.len() == void_session::kem::DK_LEN {
        kem_dks.push(disk.prev_kem_dk.clone());
    }
    Some(LocalPrekeys {
        published,
        secrets,
        opks,
        opk_secrets,
        spent_opk: disk.spent_opk,
        kem_dks,
    })
}

/// После успешного open: секрет этого id больше не открывает второй конверт.
pub fn consume_opk(path: &Path, id: &[u8; 16]) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let Some(mut disk) = read_prekey_disk(&bytes) else {
        return false;
    };
    let before = disk.opks.len();
    disk.opks.retain(|o| o.id != *id);
    if !disk.spent_opk.contains(id) {
        disk.spent_opk.push(*id);
        if disk.spent_opk.len() > 64 {
            let drop_n = disk.spent_opk.len() - 64;
            disk.spent_opk.drain(0..drop_n);
        }
    }
    write_prekey_disk(path, &disk);
    disk.opks.len() != before || disk.spent_opk.contains(id)
}

fn transport_pubkey_pb(transport: &libp2p_identity::Keypair, sender: &PeerId) -> Vec<u8> {
    if void_session::hello::void_peer_transport_public_key(*sender).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    }
}

fn v3_aad(recipient: &PeerId, outer_id: &str, eph: &[u8; 32]) -> Vec<u8> {
    let mut v = OFFLINE_AAD_PREFIX_V3.to_vec();
    v.push(ENVELOPE_VERSION);
    push_lp(&mut v, &recipient.to_bytes());
    push_lp(&mut v, outer_id.as_bytes());
    v.extend_from_slice(eph);
    v
}

/// Пробует каждый наш секрет: identity-ключ (новые письма) и static prekey (старые).
fn decrypt_envelope(
    recipient_secrets: &[&StaticSecret],
    env: &OfflineEnvelope,
    aad: &[u8],
    kem_dks: &[&[u8]],
) -> Result<Vec<u8>> {
    recipient_secrets
        .iter()
        .find_map(|secret| {
            let recipient_pk = PublicKey::from(*secret);
            let shared = secret.diffie_hellman(&PublicKey::from(env.eph));
            let classic = hkdf_offline(shared.as_bytes(), &env.eph, recipient_pk.as_bytes());
            if let Some(pt) = aead_open(&classic, &env.nonce, aad, &env.ct) {
                return Some(pt);
            }
            let (kct, aead_ct) = split_kem_ct(&env.ct)?;
            for dk in kem_dks {
                let dk = void_session::kem::KemDk::from_bytes(dk)?;
                let ss = void_session::kem::decapsulate(&dk, kct)?;
                let key = hkdf_offline_pq(shared.as_bytes(), &ss, &env.eph, recipient_pk.as_bytes());
                if let Some(pt) = aead_open(&key, &env.nonce, aad, aead_ct) {
                    return Some(pt);
                }
            }
            None
        })
        .ok_or_else(|| anyhow!("offline open failed"))
}

fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(key.as_slice().into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

fn split_kem_ct(ct: &[u8]) -> Option<(&[u8], &[u8])> {
    let rest = ct.strip_prefix(b"VQK1")?;
    if rest.len() < void_session::kem::CT_LEN {
        return None;
    }
    Some(rest.split_at(void_session::kem::CT_LEN))
}

fn verify_sender(
    sender: PeerId,
    pubkey_pb: &[u8],
    header: &[u8],
    body: &[u8],
    sig: &[u8],
) -> Result<()> {
    let signer = void_session::hello::void_hello_signing_public_key(sender, pubkey_pb)
        .ok_or_else(|| anyhow!("offline envelope: no signer key"))?;
    if sig.is_empty() || !signer.verify(&signed_message(header, body), sig) {
        return Err(anyhow!("offline envelope: bad sender signature"));
    }
    Ok(())
}

/// Запечатывает `plaintext` получателю (конверт v3) и подписывает libp2p-ключом отправителя.
/// Нода видит только получателя (в `OfflineMailboxStore`), непрозрачный id и размер бакета.
#[allow(clippy::too_many_arguments)]
pub fn seal_for_recipient(
    transport: &libp2p_identity::Keypair,
    recipient: &PeerId,
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
) -> Result<OfflineEnvelope> {
    if PeerId::from_public_key(&transport.public()) != *sender {
        return Err(anyhow!("offline seal: transport key ≠ sender"));
    }
    let eph_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    seal_for_recipient_parts(
        transport,
        recipient,
        recipient_pk,
        sender,
        sender_pk,
        message_id,
        kind,
        plaintext,
        eph_secret,
        nonce,
        &[],
    )
}

/// То же, но общий секрет мешается с ML-KEM, если `kem_ek` не пуст.
#[allow(clippy::too_many_arguments)]
pub fn seal_for_recipient_kem(
    transport: &libp2p_identity::Keypair,
    recipient: &PeerId,
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
    kem_ek: &[u8],
) -> Result<OfflineEnvelope> {
    if PeerId::from_public_key(&transport.public()) != *sender {
        return Err(anyhow!("offline seal: transport key ≠ sender"));
    }
    let eph_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    seal_for_recipient_parts(
        transport,
        recipient,
        recipient_pk,
        sender,
        sender_pk,
        message_id,
        kind,
        plaintext,
        eph_secret,
        nonce,
        kem_ek,
    )
}

#[doc(hidden)]
pub fn seal_for_recipient_fixed(
    transport: &libp2p_identity::Keypair,
    recipient: &PeerId,
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
    eph_secret: StaticSecret,
    nonce: [u8; 12],
) -> Result<OfflineEnvelope> {
    seal_for_recipient_parts(
        transport,
        recipient,
        recipient_pk,
        sender,
        sender_pk,
        message_id,
        kind,
        plaintext,
        eph_secret,
        nonce,
        &[],
    )
}

fn seal_for_recipient_parts(
    transport: &libp2p_identity::Keypair,
    recipient: &PeerId,
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
    eph_secret: StaticSecret,
    nonce: [u8; 12],
    kem_ek: &[u8],
) -> Result<OfflineEnvelope> {
    if PeerId::from_public_key(&transport.public()) != *sender {
        return Err(anyhow!("offline seal: transport key ≠ sender"));
    }
    let eph = PublicKey::from(&eph_secret).to_bytes();
    let shared = eph_secret.diffie_hellman(recipient_pk);
    let (key, kem_ct) = if kem_ek.is_empty() {
        (
            hkdf_offline(shared.as_bytes(), &eph, recipient_pk.as_bytes()),
            Vec::new(),
        )
    } else {
        let (ct, ss) = void_session::kem::encapsulate(kem_ek)
            .ok_or_else(|| anyhow!("offline seal: kem"))?;
        (
            hkdf_offline_pq(shared.as_bytes(), &ss, &eph, recipient_pk.as_bytes()),
            ct,
        )
    };

    let header = envelope_header_bytes(
        OFFLINE_SIG_PREFIX_V3,
        ENVELOPE_VERSION,
        sender,
        recipient,
        sender_pk,
        message_id,
        kind,
        &eph,
    );
    let sig = transport
        .sign(&signed_message(&header, plaintext))
        .map_err(|e| anyhow!("offline sign: {e}"))?;

    let mut fields = Vec::with_capacity(plaintext.len() + 128);
    push_lp(&mut fields, &sender.to_bytes());
    fields.extend_from_slice(sender_pk);
    push_lp(&mut fields, message_id.as_bytes());
    push_lp(&mut fields, kind.as_bytes());
    push_lp(&mut fields, plaintext);
    fields.resize(padded_len(fields.len()), 0);
    let inner = encode_signed_inner(&sig, &transport_pubkey_pb(transport, sender), &fields);

    let outer_id = outer_message_id(recipient, message_id);
    let aad = v3_aad(recipient, &outer_id, &eph);
    let ct = ChaCha20Poly1305::new(key.as_slice().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("offline seal failed"))?;
    let ct = prefix_kem_ct(&kem_ct, ct);
    Ok(OfflineEnvelope {
        v: ENVELOPE_VERSION,
        sender: String::new(),
        sender_pk: [0u8; 32],
        message_id: outer_id,
        kind: String::new(),
        eph,
        nonce,
        ct,
        local_kind: kind.to_string(),
    })
}

/// Вскрывает конверт (v3 или v2) и проверяет подпись отправителя.
/// `recipient_secrets`: identity-секрет ([`identity_offline_secret`]) и static prekey.
pub fn open_envelope(
    recipient_secrets: &[&StaticSecret],
    recipient: &PeerId,
    env: &OfflineEnvelope,
) -> Result<OpenedEnvelope> {
    match env.v {
        ENVELOPE_VERSION => open_v3(recipient_secrets, recipient, env, &[]),
        ENVELOPE_V2 => open_v2(recipient_secrets, recipient, env),
        v => Err(anyhow!("offline envelope v{v} без подписи отправителя")),
    }
}

fn open_v3(
    recipient_secrets: &[&StaticSecret],
    recipient: &PeerId,
    env: &OfflineEnvelope,
    kem_dks: &[&[u8]],
) -> Result<OpenedEnvelope> {
    let bad = || anyhow!("offline envelope: bad inner");
    let inner = decrypt_envelope(
        recipient_secrets,
        env,
        &v3_aad(recipient, &env.message_id, &env.eph),
        kem_dks,
    )?;
    let (sig, pubkey_pb, mut rest) = decode_signed_inner(&inner).ok_or_else(bad)?;
    let sender = PeerId::from_bytes(read_lp(&mut rest, 128).ok_or_else(bad)?).map_err(|_| bad())?;
    let sender_pk: [u8; 32] = rest
        .get(..32)
        .ok_or_else(bad)?
        .try_into()
        .map_err(|_| bad())?;
    rest = &rest[32..];
    let message_id = std::str::from_utf8(read_lp(&mut rest, 1024).ok_or_else(bad)?)
        .map_err(|_| bad())?
        .to_string();
    let kind = std::str::from_utf8(read_lp(&mut rest, 64).ok_or_else(bad)?)
        .map_err(|_| bad())?
        .to_string();
    let body = read_lp(&mut rest, usize::MAX).ok_or_else(bad)?;
    if env.message_id != outer_message_id(recipient, &message_id) {
        return Err(anyhow!("offline envelope: outer id mismatch"));
    }
    let header = envelope_header_bytes(
        OFFLINE_SIG_PREFIX_V3,
        ENVELOPE_VERSION,
        &sender,
        recipient,
        &sender_pk,
        &message_id,
        &kind,
        &env.eph,
    );
    verify_sender(sender, pubkey_pb, &header, body, sig)?;
    Ok(OpenedEnvelope {
        sender,
        message_id,
        kind,
        body: body.to_vec(),
    })
}

fn open_v2(
    recipient_secrets: &[&StaticSecret],
    recipient: &PeerId,
    env: &OfflineEnvelope,
) -> Result<OpenedEnvelope> {
    let sender: PeerId = env
        .sender
        .parse()
        .map_err(|_| anyhow!("offline envelope: bad sender"))?;
    let header_for = |prefix| {
        envelope_header_bytes(
            prefix,
            ENVELOPE_V2,
            &sender,
            recipient,
            &env.sender_pk,
            &env.message_id,
            &env.kind,
            &env.eph,
        )
    };
    let inner = decrypt_envelope(recipient_secrets, env, &header_for(OFFLINE_AAD_PREFIX), &[])?;
    let (sig, pubkey_pb, body) =
        decode_signed_inner(&inner).ok_or_else(|| anyhow!("offline envelope: bad inner"))?;
    verify_sender(
        sender,
        pubkey_pb,
        &header_for(OFFLINE_SIG_PREFIX),
        body,
        sig,
    )?;
    Ok(OpenedEnvelope {
        sender,
        message_id: env.message_id.clone(),
        kind: env.kind.clone(),
        body: body.to_vec(),
    })
}

fn prefix_kem_ct(kem_ct: &[u8], aead: Vec<u8>) -> Vec<u8> {
    if kem_ct.is_empty() {
        return aead;
    }
    let mut out = b"VQK1".to_vec();
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(&aead);
    out
}

fn hkdf_offline_pq(
    shared: &[u8],
    kem_ss: &[u8],
    eph: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut ikm = Vec::with_capacity(shared.len() + kem_ss.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(kem_ss);
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_OFFLINE_PQ"), &ikm);
    let mut info = Vec::with_capacity(4 + 64);
    info.extend_from_slice(b"mail");
    info.extend_from_slice(eph);
    info.extend_from_slice(recipient_pk);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("hkdf offline pq key len");
    okm
}

fn hkdf_offline(shared: &[u8], eph: &[u8; 32], recipient_pk: &[u8; 32]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_OFFLINE_V2"), shared);
    let mut info = Vec::with_capacity(4 + 64);
    info.extend_from_slice(b"mail");
    info.extend_from_slice(eph);
    info.extend_from_slice(recipient_pk);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("hkdf offline key len");
    okm
}

fn hkdf_x3dh(
    dh_spk: &[u8],
    dh_opk: &[u8],
    eph: &[u8; 32],
    spk: &[u8; 32],
    opk_id: &[u8; 16],
    opk_pk: &[u8; 32],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut ikm = Vec::with_capacity(dh_spk.len() + dh_opk.len());
    ikm.extend_from_slice(dh_spk);
    ikm.extend_from_slice(dh_opk);
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_OFFLINE_X3DH"), &ikm);
    let mut info = Vec::with_capacity(4 + 32 + 32 + 16 + 32);
    info.extend_from_slice(b"mail");
    info.extend_from_slice(eph);
    info.extend_from_slice(spk);
    info.extend_from_slice(opk_id);
    info.extend_from_slice(opk_pk);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("hkdf x3dh key len");
    okm
}

fn x3dh_aad(recipient: &PeerId, outer_id: &str, eph: &[u8; 32], opk_id: &[u8; 16]) -> Vec<u8> {
    let mut v = v3_aad(recipient, outer_id, eph);
    v.extend_from_slice(opk_id);
    v
}

/// Новое письмо: DH(eph, signed-prekey) и DH(eph, одноразовый). `opk_id` внутри AAD и `ct`.
#[allow(clippy::too_many_arguments)]
pub fn seal_with_opk(
    transport: &libp2p_identity::Keypair,
    recipient: &PeerId,
    spk: &PublicKey,
    opk_id: [u8; 16],
    opk_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
) -> Result<OfflineEnvelope> {
    if PeerId::from_public_key(&transport.public()) != *sender {
        return Err(anyhow!("offline seal: transport key ≠ sender"));
    }
    if opk_id == [0u8; 16] {
        return Err(anyhow!("offline seal: empty one-time prekey"));
    }
    let eph_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let eph = PublicKey::from(&eph_secret).to_bytes();
    let dh_spk = eph_secret.diffie_hellman(spk);
    let dh_opk = eph_secret.diffie_hellman(opk_pk);
    let key = hkdf_x3dh(
        dh_spk.as_bytes(),
        dh_opk.as_bytes(),
        &eph,
        spk.as_bytes(),
        &opk_id,
        opk_pk.as_bytes(),
    );
    let mut header = envelope_header_bytes(
        OFFLINE_SIG_PREFIX_V3,
        ENVELOPE_VERSION,
        sender,
        recipient,
        sender_pk,
        message_id,
        kind,
        &eph,
    );
    header.extend_from_slice(&opk_id);
    let sig = transport
        .sign(&signed_message(&header, plaintext))
        .map_err(|e| anyhow!("offline sign: {e}"))?;
    let mut fields = Vec::with_capacity(plaintext.len() + 144);
    push_lp(&mut fields, &sender.to_bytes());
    fields.extend_from_slice(sender_pk);
    push_lp(&mut fields, message_id.as_bytes());
    push_lp(&mut fields, kind.as_bytes());
    fields.extend_from_slice(&opk_id);
    push_lp(&mut fields, plaintext);
    fields.resize(padded_len(fields.len()), 0);
    let inner = encode_signed_inner(&sig, &transport_pubkey_pb(transport, sender), &fields);
    let outer_id = outer_message_id(recipient, message_id);
    let aad = x3dh_aad(recipient, &outer_id, &eph, &opk_id);
    let ct = ChaCha20Poly1305::new(key.as_slice().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("offline seal failed"))?;
    Ok(OfflineEnvelope {
        v: ENVELOPE_VERSION,
        sender: String::new(),
        sender_pk: [0u8; 32],
        message_id: outer_id,
        kind: String::new(),
        eph,
        nonce,
        ct,
        local_kind: kind.to_string(),
    })
}

/// Вскрытый конверт. `spent_opk` — id, который надо стереть и больше не принимать.
pub struct OpenOutcome {
    pub mail: OpenedEnvelope,
    pub spent_opk: Option<[u8; 16]>,
}

/// Сначала одноразовый ключ вместе со signed-prekey. Иначе старый конверт (один DH, в том числе identity).
pub fn open_with_opks(
    legacy_secrets: &[&StaticSecret],
    spk_secrets: &[&StaticSecret],
    opks: &[OpkSecret],
    spent: &[[u8; 16]],
    recipient: &PeerId,
    env: &OfflineEnvelope,
    kem_dks: &[&[u8]],
) -> Result<OpenOutcome> {
    if env.v == ENVELOPE_VERSION {
        if let Some(mail) = open_x3dh(spk_secrets, opks, spent, recipient, env)? {
            return Ok(mail);
        }
        if !kem_dks.is_empty() {
            if let Ok(mail) = open_v3(legacy_secrets, recipient, env, kem_dks) {
                return Ok(OpenOutcome {
                    mail,
                    spent_opk: None,
                });
            }
        }
    }
    let mail = open_envelope(legacy_secrets, recipient, env)?;
    Ok(OpenOutcome {
        mail,
        spent_opk: None,
    })
}

fn open_x3dh(
    spk_secrets: &[&StaticSecret],
    opks: &[OpkSecret],
    spent: &[[u8; 16]],
    recipient: &PeerId,
    env: &OfflineEnvelope,
) -> Result<Option<OpenOutcome>> {
    let eph_pk = PublicKey::from(env.eph);
    for spk_sk in spk_secrets {
        let spk_pk = PublicKey::from(*spk_sk);
        let dh_spk = spk_sk.diffie_hellman(&eph_pk);
        for opk in opks {
            if spent.iter().any(|id| id == &opk.id) {
                continue;
            }
            let opk_pk = PublicKey::from(&opk.secret);
            let dh_opk = opk.secret.diffie_hellman(&eph_pk);
            let key = hkdf_x3dh(
                dh_spk.as_bytes(),
                dh_opk.as_bytes(),
                &env.eph,
                spk_pk.as_bytes(),
                &opk.id,
                opk_pk.as_bytes(),
            );
            let aad = x3dh_aad(recipient, &env.message_id, &env.eph, &opk.id);
            let Ok(inner) = ChaCha20Poly1305::new(key.as_slice().into()).decrypt(
                Nonce::from_slice(&env.nonce),
                Payload {
                    msg: env.ct.as_ref(),
                    aad: &aad,
                },
            ) else {
                continue;
            };
            let Some(mail) = parse_x3dh_inner(recipient, env, &inner, &opk.id)? else {
                continue;
            };
            return Ok(Some(OpenOutcome {
                mail,
                spent_opk: Some(opk.id),
            }));
        }
    }
    Ok(None)
}

fn parse_x3dh_inner(
    recipient: &PeerId,
    env: &OfflineEnvelope,
    inner: &[u8],
    expect_opk: &[u8; 16],
) -> Result<Option<OpenedEnvelope>> {
    let bad = || anyhow!("offline envelope: bad inner");
    let Some((sig, pubkey_pb, mut rest)) = decode_signed_inner(inner) else {
        return Ok(None);
    };
    let Ok(sender) = PeerId::from_bytes(read_lp(&mut rest, 128).ok_or_else(bad)?) else {
        return Ok(None);
    };
    let Some(sender_pk_bytes) = rest.get(..32) else {
        return Ok(None);
    };
    let sender_pk: [u8; 32] = sender_pk_bytes.try_into().map_err(|_| bad())?;
    rest = &rest[32..];
    let Some(message_id_b) = read_lp(&mut rest, 1024) else {
        return Ok(None);
    };
    let Ok(message_id) = std::str::from_utf8(message_id_b) else {
        return Ok(None);
    };
    let Some(kind_b) = read_lp(&mut rest, 64) else {
        return Ok(None);
    };
    let Ok(kind) = std::str::from_utf8(kind_b) else {
        return Ok(None);
    };
    let Some(opk_bytes) = rest.get(..16) else {
        return Ok(None);
    };
    let opk_id: [u8; 16] = opk_bytes.try_into().map_err(|_| bad())?;
    if opk_id != *expect_opk {
        return Ok(None);
    }
    rest = &rest[16..];
    let Some(body) = read_lp(&mut rest, usize::MAX) else {
        return Ok(None);
    };
    if env.message_id != outer_message_id(recipient, message_id) {
        return Err(anyhow!("offline envelope: outer id mismatch"));
    }
    let mut header = envelope_header_bytes(
        OFFLINE_SIG_PREFIX_V3,
        ENVELOPE_VERSION,
        &sender,
        recipient,
        &sender_pk,
        message_id,
        kind,
        &env.eph,
    );
    header.extend_from_slice(&opk_id);
    verify_sender(sender, pubkey_pb, &header, body, sig)?;
    Ok(Some(OpenedEnvelope {
        sender,
        message_id: message_id.to_string(),
        kind: kind.to_string(),
        body: body.to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// `serde_bytes` на `ct` не должен сдвинуть bincode ящика: у `Vec<u8>` тот же префикс длины.
    #[test]
    fn envelope_ct_bincode_matches_plain_vec() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Plain {
            ct: Vec<u8>,
        }
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Bytes {
            #[serde(with = "serde_bytes")]
            ct: Vec<u8>,
        }
        let ct = vec![1u8, 2, 3, 255, 0, 9];
        let plain = bincode::serialize(&Plain { ct: ct.clone() }).unwrap();
        let bytes = bincode::serialize(&Bytes { ct: ct.clone() }).unwrap();
        assert_eq!(plain, bytes);
        let back: Bytes = bincode::deserialize(&plain).unwrap();
        assert_eq!(back.ct, ct);
    }

    #[test]
    fn voice_chunk_roundtrip() {
        let tid = [7u8; 16];
        let bytes: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
        let parts = split_voice_for_offline(&tid, &bytes).expect("split");
        assert!(parts.len() > 1);
        let mut map = HashMap::new();
        let mut total = 0u32;
        let mut total_size = 0u32;
        for p in &parts {
            let c = decode_voice_chunk_payload(p).expect("decode");
            assert_eq!(c.transfer_id, tid);
            total = c.total;
            total_size = c.total_size;
            map.insert(c.index, c.data);
        }
        let assembled = assemble_voice_chunks(total, total_size, &map).expect("assemble");
        assert_eq!(assembled, bytes);
    }

    struct Party {
        key: libp2p_identity::Keypair,
        pid: PeerId,
        static_sk: StaticSecret,
        offline_sk: StaticSecret,
    }

    impl Party {
        fn secrets(&self) -> [&StaticSecret; 2] {
            [&self.offline_sk, &self.static_sk]
        }
    }

    fn party() -> Party {
        let key = libp2p_identity::Keypair::generate_ed25519();
        let pid = PeerId::from(key.public());
        let offline_sk = identity_offline_secret(&key).expect("ed25519");
        Party {
            key,
            pid,
            static_sk: StaticSecret::random_from_rng(rand::rngs::OsRng),
            offline_sk,
        }
    }

    #[test]
    fn identity_offline_key_matches_secret() {
        for _ in 0..16 {
            let p = party();
            let derived = identity_offline_public(&p.pid).expect("derive");
            assert_eq!(
                derived.as_bytes(),
                PublicKey::from(&p.offline_sk).as_bytes()
            );
        }
    }

    #[test]
    fn seal_key_requires_verified_prekey() {
        let bob = party();
        let pre = [9u8; 32];
        let key = offline_seal_key(&bob.pid, Some(pre)).unwrap();
        assert_eq!(key.as_bytes(), &pre);
        assert!(offline_seal_key(&bob.pid, None).is_none());
        assert!(offline_seal_key(&bob.pid, Some([0u8; 32])).is_none());
    }

    #[test]
    fn prekey_sealed_mail_does_not_open_with_identity_alone() {
        let (alice, bob) = (party(), party());
        let pre = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let sender_pk = PublicKey::from(&alice.static_sk).to_bytes();
        let env = seal_for_recipient(
            &alice.key,
            &bob.pid,
            &PublicKey::from(&pre),
            &alice.pid,
            &sender_pk,
            "m-pfs",
            "dm",
            b"secret",
        )
        .unwrap();
        assert!(open_envelope(&[&bob.offline_sk], &bob.pid, &env).is_err());
        assert_eq!(
            open_envelope(&[&pre], &bob.pid, &env).unwrap().body,
            b"secret"
        );
    }

    #[test]
    fn envelope_only_opens_for_identity_owner() {
        let (alice, bob, mallory) = (party(), party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        assert!(open_envelope(&[&bob.static_sk], &bob.pid, &env).is_err());
        assert!(open_envelope(&mallory.secrets(), &bob.pid, &env).is_err());
        assert!(open_envelope(&[&bob.offline_sk], &bob.pid, &env).is_ok());
    }

    #[test]
    fn legacy_static_prekey_envelope_still_opens() {
        let (alice, bob) = (party(), party());
        let sender_pk = PublicKey::from(&alice.static_sk).to_bytes();
        let env = seal_for_recipient(
            &alice.key,
            &bob.pid,
            &PublicKey::from(&bob.static_sk),
            &alice.pid,
            &sender_pk,
            "m1",
            "dm",
            b"old",
        )
        .unwrap();
        assert_eq!(
            open_envelope(&bob.secrets(), &bob.pid, &env).unwrap().body,
            b"old"
        );
    }

    fn seal_from(from: &Party, to: &Party, body: &[u8]) -> OfflineEnvelope {
        let sender_pk = PublicKey::from(&from.static_sk).to_bytes();
        seal_for_recipient(
            &from.key,
            &to.pid,
            &identity_offline_public(&to.pid).expect("ed25519 pid"),
            &from.pid,
            &sender_pk,
            "m1",
            "dm",
            body,
        )
        .expect("seal")
    }

    #[test]
    fn envelope_roundtrip_returns_signed_sender() {
        let (alice, bob) = (party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        let opened = open_envelope(&bob.secrets(), &bob.pid, &env).expect("open");
        assert_eq!(opened.sender, alice.pid);
        assert_eq!(opened.message_id, "m1");
        assert_eq!(opened.kind, "dm");
        assert_eq!(opened.body, b"hi");
    }

    #[test]
    fn envelope_hides_metadata_from_node() {
        let (alice, bob, carol) = (party(), party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        assert!(env.sender.is_empty() && env.kind.is_empty());
        assert_eq!(env.sender_pk, [0u8; 32]);
        assert_ne!(env.message_id, "m1");
        assert_eq!(env.local_kind, "dm");
        // Тот же id для другого получателя не связывается.
        assert_ne!(env.message_id, seal_from(&alice, &carol, b"hi").message_id);
        // Повтор того же сообщения — тот же внешний id (дедуп на ноде).
        assert_eq!(env.message_id, seal_from(&alice, &bob, b"hi").message_id);
        // Размер скрыт бакетом.
        assert_eq!(env.ct.len(), seal_from(&alice, &bob, &[7u8; 300]).ct.len());
        // `local_kind` не сериализуется.
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("local_kind") && !json.contains("\"dm\""));
    }

    #[test]
    fn envelope_rejects_rewritten_outer_id() {
        let (alice, bob) = (party(), party());
        let mut env = seal_from(&alice, &bob, b"hi");
        env.message_id = outer_message_id(&bob.pid, "m2");
        assert!(open_envelope(&bob.secrets(), &bob.pid, &env).is_err());
    }

    #[test]
    fn envelope_rejects_tampered_ct() {
        let (alice, bob) = (party(), party());
        let mut env = seal_from(&alice, &bob, b"hi");
        env.ct[0] ^= 1;
        assert!(open_envelope(&bob.secrets(), &bob.pid, &env).is_err());
    }

    #[test]
    fn envelope_rejects_wrong_recipient_id() {
        let (alice, bob, carol) = (party(), party(), party());
        let env = seal_from(&alice, &bob, b"hi");
        assert!(open_envelope(&bob.secrets(), &carol.pid, &env).is_err());
    }

    #[test]
    fn envelope_rejects_unsigned_v1() {
        let (alice, bob) = (party(), party());
        let mut env = seal_from(&alice, &bob, b"hi");
        env.v = 1;
        assert!(open_envelope(&bob.secrets(), &bob.pid, &env).is_err());
    }

    #[test]
    fn seal_rejects_foreign_sender_id() {
        let (alice, bob, mallory) = (party(), party(), party());
        let sender_pk = PublicKey::from(&mallory.static_sk).to_bytes();
        let res = seal_for_recipient(
            &mallory.key,
            &bob.pid,
            &PublicKey::from(&bob.static_sk),
            &alice.pid,
            &sender_pk,
            "m1",
            "dm",
            b"x",
        );
        assert!(res.is_err());
    }

    #[test]
    fn signed_prekey_roundtrip() {
        let alice = party();
        let pk = PublicKey::from(&alice.static_sk).to_bytes();
        let not_after = prekey_now().saturating_add(3600);
        let published =
            encode_signed_prekey(&alice.key, &alice.pid, &pk, not_after).expect("encode");
        assert_eq!(&published.dht_value[..32], &pk);
        let got = verify_signed_prekey(&alice.pid, &published.dht_value).unwrap();
        assert_eq!(got.pk, pk);
        assert_eq!(got.not_after, not_after);
        assert!(prekey_is_sealable(got, prekey_now()));
        assert!(verify_prekey_offer(
            &alice.pid,
            &pk,
            not_after,
            &published.sig,
            &[],
        ));
    }

    #[test]
    fn signed_prekey_rejects_forgery() {
        let (alice, mallory) = (party(), party());
        let evil_pk = PublicKey::from(&mallory.static_sk).to_bytes();
        let not_after = prekey_now().saturating_add(3600);
        assert!(verify_signed_prekey(&alice.pid, &evil_pk).is_none());
        let forged = encode_signed_prekey(&mallory.key, &mallory.pid, &evil_pk, not_after).unwrap();
        assert!(verify_signed_prekey(&alice.pid, &forged.dht_value).is_none());
        let pk = PublicKey::from(&alice.static_sk).to_bytes();
        let mut value = encode_signed_prekey(&alice.key, &alice.pid, &pk, not_after)
            .unwrap()
            .dht_value;
        value[..32].copy_from_slice(&evil_pk);
        assert!(verify_signed_prekey(&alice.pid, &value).is_none());
        let expired = SignedPrekey::x25519(pk, prekey_now().saturating_sub(1));
        assert!(!prekey_is_sealable(expired, prekey_now()));
    }

    fn fresh_opk(owner: &Party) -> (OpkSecret, OneTimePrekey) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let pk = PublicKey::from(&secret).to_bytes();
        let signed = encode_one_time_prekey(&owner.key, &owner.pid, &id, &pk).unwrap();
        (OpkSecret { id, secret }, signed)
    }

    fn seal_x3dh(from: &Party, to: &Party, spk: &StaticSecret, opk: &OneTimePrekey, body: &[u8], mid: &str) -> OfflineEnvelope {
        let sender_pk = PublicKey::from(&from.static_sk).to_bytes();
        seal_with_opk(
            &from.key,
            &to.pid,
            &PublicKey::from(spk),
            opk.id,
            &PublicKey::from(opk.pk),
            &from.pid,
            &sender_pk,
            mid,
            "dm",
            body,
        )
        .unwrap()
    }

    #[test]
    fn empty_opk_bundle_does_not_seal() {
        let now = prekey_now();
        let spk = SignedPrekey::x25519([9u8; 32], now + 3600);
        assert!(seal_material(Some(spk), None, now).is_none());
        assert!(seal_material(None, None, now).is_none());
        let (secret, opk) = fresh_opk(&party());
        let _ = secret;
        let ready = seal_material(Some(spk), Some(&opk), now).unwrap();
        assert_eq!(ready.opk_id, opk.id);
        assert_eq!(ready.spk, spk.pk);
    }

    #[test]
    fn spent_opk_does_not_open_a_second_envelope() {
        let (alice, bob) = (party(), party());
        let spk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let (opk_secret, opk) = fresh_opk(&bob);
        let first = seal_x3dh(&alice, &bob, &spk, &opk, b"one", "m-1");
        let second = seal_x3dh(&alice, &bob, &spk, &opk, b"two", "m-2");
        let opened = open_with_opks(&[], &[&spk], &[opk_secret.clone()], &[], &bob.pid, &first, &[])
            .unwrap();
        assert_eq!(opened.mail.body, b"one");
        assert_eq!(opened.spent_opk, Some(opk.id));
        let spent = [opk.id];
        assert!(open_with_opks(&[], &[&spk], &[opk_secret], &spent, &bob.pid, &second, &[]).is_err());
    }

    #[test]
    fn leaked_old_opk_does_not_open_a_new_one() {
        let (alice, bob) = (party(), party());
        let spk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let (old_secret, _old) = fresh_opk(&bob);
        let (new_secret, new_opk) = fresh_opk(&bob);
        let env = seal_x3dh(&alice, &bob, &spk, &new_opk, b"fresh", "m-new");
        assert!(open_with_opks(&[], &[&spk], &[old_secret], &[], &bob.pid, &env, &[]).is_err());
        let opened = open_with_opks(&[], &[&spk], &[new_secret], &[], &bob.pid, &env, &[]).unwrap();
        assert_eq!(opened.mail.body, b"fresh");
        assert_eq!(opened.spent_opk, Some(new_opk.id));
    }

    #[test]
    fn node_offer_drops_the_issued_opk() {
        let bob = party();
        let spk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = PublicKey::from(&spk).to_bytes();
        let not_after = prekey_now() + 3600;
        let published = encode_signed_prekey(&bob.key, &bob.pid, &pk, not_after).unwrap();
        let (_a, opk_a) = fresh_opk(&bob);
        let (_b, opk_b) = fresh_opk(&bob);
        let mut dir = NodePrekeys::new();
        assert!(dir.put(
            &bob.pid.to_string(),
            pk,
            not_after,
            published.sig.clone(),
            &[],
            vec![opk_a.clone(), opk_b.clone()],
            prekey_now(),
        ));
        let first = dir.take_offer(&bob.pid.to_string()).unwrap();
        let second = dir.take_offer(&bob.pid.to_string()).unwrap();
        assert_ne!(first.opk.id, second.opk.id);
        assert!(dir.take_offer(&bob.pid.to_string()).is_none());
        assert!(dir.put(
            &bob.pid.to_string(),
            pk,
            not_after,
            published.sig.clone(),
            &[],
            vec![opk_a, opk_b],
            prekey_now(),
        ));
        assert!(dir.take_offer(&bob.pid.to_string()).is_none());
    }

    #[test]
    fn voice_chunk_rejects_oversized() {
        let tid = [1u8; 16];
        let big = vec![0u8; (OFFLINE_VOICE_MAX_BYTES as usize) + 1];
        assert!(split_voice_for_offline(&tid, &big).is_none());
    }

    #[test]
    fn file_chunk_rejects_oversized_and_roundtrips() {
        let tid = [2u8; 16];
        let big = vec![0u8; (OFFLINE_FILE_MAX_BYTES as usize) + 1];
        assert!(split_file_for_offline(&tid, &big).is_none());
        let bytes = vec![9u8; OFFLINE_VOICE_CHUNK_SIZE + 10];
        let parts = split_file_for_offline(&tid, &bytes).expect("split");
        assert_eq!(parts.len(), 2);
        let mut map = std::collections::HashMap::new();
        let mut total = 0u32;
        let mut total_size = 0u32;
        for part in &parts {
            let chunk = decode_voice_chunk_payload(part).expect("decode");
            total = chunk.total;
            total_size = chunk.total_size;
            map.insert(chunk.index, chunk.data);
        }
        assert_eq!(
            assemble_voice_chunks(total, total_size, &map).expect("assemble"),
            bytes
        );
    }

    #[test]
    fn sealed_chunk_fits_queue_bucket_with_and_without_kem() {
        let (alice, bob) = (party(), party());
        let tid = [3u8; 16];
        let payload = encode_voice_chunk_payload(
            &tid,
            0,
            1,
            OFFLINE_VOICE_CHUNK_SIZE as u32,
            &[7u8; OFFLINE_VOICE_CHUNK_SIZE],
        );
        let sender_pk = PublicKey::from(&alice.static_sk).to_bytes();
        let env = seal_for_recipient(
            &alice.key,
            &bob.pid,
            &identity_offline_public(&bob.pid).expect("ed25519 pid"),
            &alice.pid,
            &sender_pk,
            "vchunk:test:0",
            OFFLINE_VOICE_CHUNK_KIND,
            &payload,
        )
        .expect("seal");
        assert!(crate::queue_mail::pad_queue_blob(&env).is_ok(), "identity");
        let (_, ek) = void_session::kem::generate();
        let hybrid = seal_for_recipient_kem(
            &alice.key,
            &bob.pid,
            &identity_offline_public(&bob.pid).expect("ed25519 pid"),
            &alice.pid,
            &sender_pk,
            "fchunk:test:0",
            OFFLINE_FILE_CHUNK_KIND,
            &payload,
            &ek,
        )
        .expect("seal kem");
        assert!(
            crate::queue_mail::pad_queue_blob(&hybrid).is_ok(),
            "kem ct {}",
            hybrid.ct.len()
        );
    }

    #[test]
    fn hybrid_letter_needs_the_kem_seed() {
        let alice = party();
        let bob = party();
        let (dk, ek) = void_session::kem::generate();
        let sender_pk = PublicKey::from(&alice.static_sk).to_bytes();
        let env = seal_for_recipient_kem(
            &alice.key,
            &bob.pid,
            &PublicKey::from(&bob.static_sk),
            &alice.pid,
            &sender_pk,
            "m-pq",
            "dm",
            b"hybrid",
            &ek,
        )
        .unwrap();
        assert!(env.ct.starts_with(b"VQK1"));
        assert!(open_envelope(&[&bob.static_sk], &bob.pid, &env).is_err());
        let seed = dk.as_bytes();
        let opened = open_with_opks(
            &[&bob.static_sk],
            &[],
            &[],
            &[],
            &bob.pid,
            &env,
            &[seed],
        )
        .unwrap();
        assert_eq!(opened.mail.body, b"hybrid");
    }
}
