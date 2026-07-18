//! Offline mail via DHT and peer relay.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use libp2p::kad;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, StaticSecret};

const PREKEY_PREFIX: &[u8] = b"/void/prekey/";
const MAILBOX_PREFIX: &[u8] = b"/void/mailbox/";
pub(crate) const MAILBOX_TTL_SECS: u64 = 60 * 60 * 24 * 7;

/// Offline-доставка голосовых: аудио режется на кусочки и уходит через тот же
/// relay/bootstrap store-and-forward канал, что и офлайн-почта для текста
/// (DHT-запись мимо — там жёсткий лимит 64 КБ на весь ящик, см. mailbox_record_key).
pub(crate) const OFFLINE_VOICE_CHUNK_SIZE: usize = 24 * 1024;
/// Максимальный размер WAV, который мы согласны прогонять через offline-очередь
/// целиком (иначе — только метаданные, аудио дождётся живой передачи).
pub(crate) const OFFLINE_VOICE_MAX_BYTES: u64 = 3 * 1024 * 1024;
pub(crate) const OFFLINE_VOICE_CHUNK_KIND: &str = "voice_chunk";

/// Плейнтекст одного чанка (до шифрования в `seal_for_recipient`):
/// `[transfer_id:16][index:u32 LE][total:u32 LE][total_size:u32 LE][bytes...]`.
pub(crate) fn encode_voice_chunk_payload(
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

pub(crate) struct VoiceChunk {
    pub(crate) transfer_id: [u8; 16],
    pub(crate) index: u32,
    pub(crate) total: u32,
    pub(crate) total_size: u32,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn decode_voice_chunk_payload(bytes: &[u8]) -> Option<VoiceChunk> {
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

/// Режет байты WAV на чанки для offline-доставки. Возвращает `None`, если файл
/// больше `OFFLINE_VOICE_MAX_BYTES` — в этом случае аудио дождётся живой передачи.
pub(crate) fn split_voice_for_offline(
    transfer_id: &[u8; 16],
    bytes: &[u8],
) -> Option<Vec<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() as u64 > OFFLINE_VOICE_MAX_BYTES {
        return None;
    }
    let total_size = bytes.len() as u32;
    let total = bytes
        .len()
        .div_ceil(OFFLINE_VOICE_CHUNK_SIZE)
        .max(1) as u32;
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

/// Собирает WAV из набора чанков (индекс → данные). `None`, если набор неполный
/// или суммарный размер не совпал с `total_size`.
pub(crate) fn assemble_voice_chunks(
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
pub(crate) struct OfflineEnvelope {
    pub(crate) v: u8,
    pub(crate) sender: String,
    pub(crate) sender_pk: [u8; 32],
    pub(crate) message_id: String,
    pub(crate) kind: String,
    pub(crate) eph: [u8; 32],
    pub(crate) nonce: [u8; 12],
    pub(crate) ct: Vec<u8>,
}

pub(crate) fn prekey_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = PREKEY_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub(crate) fn mailbox_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = MAILBOX_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub(crate) fn encode_mailbox(envelopes: &[OfflineEnvelope]) -> Result<Vec<u8>> {
    // bincode вместо JSON: `ct`/`sender_pk`/`eph`/`nonce` — бинарные поля, JSON
    // раздувает Vec<u8> в массив чисел (~3-4x) — критично, когда в конвертах
    // может лежать аудио голосового (voice_chunk).
    bincode::serialize(envelopes).map_err(|e| anyhow!("mailbox bincode: {e}"))
}

pub(crate) fn decode_mailbox(bytes: &[u8]) -> Result<Vec<OfflineEnvelope>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    // Обратная совместимость: старые mailbox-записи/файлы могли быть в JSON.
    if let Ok(envs) = bincode::deserialize::<Vec<OfflineEnvelope>>(bytes) {
        return Ok(envs);
    }
    serde_json::from_slice(bytes).map_err(|e| anyhow!("mailbox decode: {e}"))
}

pub(crate) fn seal_for_recipient(
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
) -> Result<OfflineEnvelope> {
    let eph_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(recipient_pk);
    let key = hkdf_offline(shared.as_bytes());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("offline seal failed"))?;
    Ok(OfflineEnvelope {
        v: 1,
        sender: sender.to_string(),
        sender_pk: *sender_pk,
        message_id: message_id.to_string(),
        kind: kind.to_string(),
        eph: eph_pub.to_bytes(),
        nonce,
        ct,
    })
}

pub(crate) fn open_envelope(
    recipient_secret: &StaticSecret,
    env: &OfflineEnvelope,
) -> Result<Vec<u8>> {
    let eph_pub = PublicKey::from(env.eph);
    let shared = recipient_secret.diffie_hellman(&eph_pub);
    let key = hkdf_offline(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    cipher
        .decrypt(Nonce::from_slice(&env.nonce), env.ct.as_ref())
        .map_err(|_| anyhow!("offline open failed"))
}

fn hkdf_offline(shared: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_OFFLINE_V1"), shared);
    let mut okm = [0u8; 32];
    hk.expand(b"mail", &mut okm)
        .expect("hkdf offline key len");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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

    #[test]
    fn voice_chunk_rejects_oversized() {
        let tid = [1u8; 16];
        let big = vec![0u8; (OFFLINE_VOICE_MAX_BYTES as usize) + 1];
        assert!(split_voice_for_offline(&tid, &big).is_none());
    }
}