//! Очередь на контакт: нода индексирует `queue_id`, не PeerId получателя.

use anyhow::{anyhow, Result};
use libp2p_identity::Keypair;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::offline_mail::OfflineEnvelope;

pub const QUEUE_TTL_SECS: u64 = 14 * 24 * 3600;
pub const QUEUE_ROTATE_MARGIN: u64 = 24 * 3600;
/// После стольких писем владелец заводит новую очередь. Старая ещё выдаётся до `expiry`.
pub const QUEUE_ROTATE_AFTER: u32 = 64;
/// Все письма очереди занимают один бакет, голос и текст снаружи одной длины.
pub const QUEUE_BUCKET: u32 = 64 * 1024;

const CREATE_PREFIX: &[u8] = b"VOID_QUEUE_CREATE_V1\0";
const WRITE_PREFIX: &[u8] = b"VOID_QUEUE_WRITE_V1\0";
const QUERY_PREFIX: &[u8] = b"VOID_QUEUE_QUERY_V1\0";

/// Что хранит получатель. `owner` подписывает CreateQueue и Query. На ноду PeerId не уходит.
#[derive(Clone)]
pub struct OwnedQueue {
    pub queue_id: [u8; 32],
    pub write_token: [u8; 32],
    pub expiry: u64,
    pub owner: Keypair,
    pub stored: u32,
}

/// Что отправитель получает внутри E2EE. Секрета владельца здесь нет.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueGrant {
    pub queue_id: [u8; 32],
    pub write_token: [u8; 32],
    pub expiry: u64,
}

#[derive(Clone)]
struct QueueBox {
    owner_pk: Vec<u8>,
    write_token: [u8; 32],
    expiry: u64,
    blobs: Vec<Vec<u8>>,
    challenges: HashMap<[u8; 32], u64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredQueue {
    queue_id: [u8; 32],
    owner_pk: Vec<u8>,
    write_token: [u8; 32],
    expiry: u64,
    blobs: Vec<Vec<u8>>,
}

/// Индекс ноды: ключ — `queue_id`.
#[derive(Default)]
pub struct QueueDir {
    boxes: HashMap<[u8; 32], QueueBox>,
}

pub struct QueueStored {
    pub queue_id: [u8; 32],
    pub bucket: u32,
}

impl OwnedQueue {
    pub fn create(now: u64) -> Self {
        let mut queue_id = [0u8; 32];
        let mut write_token = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut queue_id);
        rand::rngs::OsRng.fill_bytes(&mut write_token);
        Self {
            queue_id,
            write_token,
            expiry: now.saturating_add(QUEUE_TTL_SECS),
            owner: Keypair::generate_ed25519(),
            stored: 0,
        }
    }

    pub fn grant(&self) -> QueueGrant {
        QueueGrant {
            queue_id: self.queue_id,
            write_token: self.write_token,
            expiry: self.expiry,
        }
    }

    pub fn should_rotate(&self, now: u64) -> bool {
        self.stored >= QUEUE_ROTATE_AFTER || now.saturating_add(QUEUE_ROTATE_MARGIN) >= self.expiry
    }

    pub fn open(
        queue_id: [u8; 32],
        write_token: [u8; 32],
        expiry: u64,
        owner_secret: &[u8],
        stored: u32,
    ) -> Option<Self> {
        if queue_id == [0u8; 32] || write_token == [0u8; 32] || owner_secret.is_empty() {
            return None;
        }
        let owner = Keypair::from_protobuf_encoding(owner_secret).ok()?;
        Some(Self {
            queue_id,
            write_token,
            expiry,
            owner,
            stored,
        })
    }

    pub fn owner_secret(&self) -> Vec<u8> {
        self.owner.to_protobuf_encoding().unwrap_or_default()
    }
}

/// Секреты очереди одного контакта. Лежит в vault, не на ноде.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactQueueRecord {
    #[serde(default)]
    pub queue_id: [u8; 32],
    #[serde(default)]
    pub write_token: [u8; 32],
    #[serde(default)]
    pub expiry: u64,
    #[serde(default)]
    pub stored: u32,
    #[serde(default)]
    pub owner_secret: Vec<u8>,
    #[serde(default)]
    pub prev_queue_id: [u8; 32],
    #[serde(default)]
    pub prev_write_token: [u8; 32],
    #[serde(default)]
    pub prev_expiry: u64,
    #[serde(default)]
    pub prev_stored: u32,
    #[serde(default)]
    pub prev_owner_secret: Vec<u8>,
    #[serde(default)]
    pub grant_queue_id: [u8; 32],
    #[serde(default)]
    pub grant_write_token: [u8; 32],
    #[serde(default)]
    pub grant_expiry: u64,
}

impl ContactQueueRecord {
    pub fn is_empty(&self) -> bool {
        self.queue_id == [0u8; 32] && self.grant_queue_id == [0u8; 32]
    }

    pub fn owned(&self) -> Option<OwnedQueue> {
        OwnedQueue::open(
            self.queue_id,
            self.write_token,
            self.expiry,
            &self.owner_secret,
            self.stored,
        )
    }

    pub fn previous(&self) -> Option<OwnedQueue> {
        OwnedQueue::open(
            self.prev_queue_id,
            self.prev_write_token,
            self.prev_expiry,
            &self.prev_owner_secret,
            self.prev_stored,
        )
    }

    pub fn grant(&self) -> Option<QueueGrant> {
        if self.grant_queue_id == [0u8; 32] || self.grant_write_token == [0u8; 32] {
            return None;
        }
        Some(QueueGrant {
            queue_id: self.grant_queue_id,
            write_token: self.grant_write_token,
            expiry: self.grant_expiry,
        })
    }

    pub fn assemble(
        owned: Option<&OwnedQueue>,
        prev: Option<&OwnedQueue>,
        grant: Option<&QueueGrant>,
    ) -> Self {
        let mut rec = Self::default();
        if let Some(q) = owned {
            rec.queue_id = q.queue_id;
            rec.write_token = q.write_token;
            rec.expiry = q.expiry;
            rec.stored = q.stored;
            rec.owner_secret = q.owner_secret();
        }
        if let Some(q) = prev {
            rec.prev_queue_id = q.queue_id;
            rec.prev_write_token = q.write_token;
            rec.prev_expiry = q.expiry;
            rec.prev_stored = q.stored;
            rec.prev_owner_secret = q.owner_secret();
        }
        if let Some(g) = grant {
            rec.grant_queue_id = g.queue_id;
            rec.grant_write_token = g.write_token;
            rec.grant_expiry = g.expiry;
        }
        rec
    }
}

pub fn create_message(queue_id: &[u8; 32], write_token: &[u8; 32], expiry: u64) -> Vec<u8> {
    let mut v = CREATE_PREFIX.to_vec();
    v.extend_from_slice(queue_id);
    v.extend_from_slice(write_token);
    v.extend_from_slice(&expiry.to_le_bytes());
    v
}

pub fn sign_create(queue: &OwnedQueue) -> Option<Vec<u8>> {
    queue
        .owner
        .sign(&create_message(&queue.queue_id, &queue.write_token, queue.expiry))
        .ok()
}

pub fn verify_create(
    owner_pk: &[u8],
    queue_id: &[u8; 32],
    write_token: &[u8; 32],
    expiry: u64,
    sig: &[u8],
    now: u64,
) -> bool {
    if sig.is_empty() || expiry <= now || write_token == &[0u8; 32] || queue_id == &[0u8; 32] {
        return false;
    }
    let Ok(pk) = libp2p_identity::PublicKey::try_decode_protobuf(owner_pk) else {
        return false;
    };
    pk.verify(
        &create_message(queue_id, write_token, expiry),
        sig,
    )
}

pub fn write_proof(token: &[u8; 32], queue_id: &[u8; 32], blob: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(WRITE_PREFIX);
    h.update(token);
    h.update(queue_id);
    h.update(blob);
    let dig = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

/// Конверт + случайный хвост ровно [`QUEUE_BUCKET`] байт. Голос и текст снаружи одной длины.
pub fn pad_queue_blob(envelope: &OfflineEnvelope) -> Result<Vec<u8>> {
    let raw = bincode::serialize(envelope).map_err(|e| anyhow!("queue blob: {e}"))?;
    if raw.len() + 4 > QUEUE_BUCKET as usize {
        return Err(anyhow!("queue blob exceeds bucket"));
    }
    let mut out = Vec::with_capacity(QUEUE_BUCKET as usize);
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&raw);
    out.resize(QUEUE_BUCKET as usize, 0);
    Ok(out)
}

pub fn unpad_queue_blob(blob: &[u8]) -> Option<OfflineEnvelope> {
    if blob.len() != QUEUE_BUCKET as usize {
        return None;
    }
    let n = u32::from_le_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    if n == 0 || n > QUEUE_BUCKET as usize - 4 {
        return None;
    }
    bincode::deserialize(&blob[4..4 + n]).ok()
}

pub fn query_message(queue_id: &[u8; 32], ts: u64, nonce: &[u8; 32]) -> Vec<u8> {
    let mut v = QUERY_PREFIX.to_vec();
    v.extend_from_slice(queue_id);
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(nonce);
    v
}

pub fn sign_queue_query(queue: &OwnedQueue, ts: u64, nonce: &[u8; 32]) -> Option<Vec<u8>> {
    queue.owner.sign(&query_message(&queue.queue_id, ts, nonce)).ok()
}

/// Строка для лога Store. PeerId получателя в неё не входит.
pub fn queue_store_log(queue_id: &[u8; 32], bucket: u32) -> String {
    let hex: String = queue_id.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("queue={hex} bucket={bucket}")
}

impl QueueDir {
    pub fn new() -> Self {
        Self {
            boxes: HashMap::new(),
        }
    }

    pub fn create(
        &mut self,
        queue_id: [u8; 32],
        owner_pk: Vec<u8>,
        write_token: [u8; 32],
        expiry: u64,
        sig: &[u8],
        now: u64,
    ) -> bool {
        if !verify_create(&owner_pk, &queue_id, &write_token, expiry, sig, now) {
            return false;
        }
        self.boxes.insert(
            queue_id,
            QueueBox {
                owner_pk,
                write_token,
                expiry,
                blobs: Vec::new(),
                challenges: HashMap::new(),
            },
        );
        true
    }

    /// Кладёт письмо. В результате только `queue_id` и бакет.
    pub fn store(
        &mut self,
        queue_id: [u8; 32],
        proof: &[u8; 32],
        blob: Vec<u8>,
        now: u64,
    ) -> Option<QueueStored> {
        if blob.len() != QUEUE_BUCKET as usize {
            return None;
        }
        let expected = {
            let box_ = self.boxes.get(&queue_id)?;
            if now >= box_.expiry {
                return None;
            }
            write_proof(&box_.write_token, &queue_id, &blob)
        };
        if proof != &expected {
            return None;
        }
        let box_ = self.boxes.get_mut(&queue_id)?;
        if !box_.blobs.iter().any(|b| b == &blob) {
            box_.blobs.push(blob);
            if box_.blobs.len() > 1024 {
                let drop_n = box_.blobs.len() - 1024;
                box_.blobs.drain(0..drop_n);
            }
        }
        Some(QueueStored {
            queue_id,
            bucket: QUEUE_BUCKET,
        })
    }

    pub fn challenge(&mut self, queue_id: [u8; 32], now: u64) -> Option<([u8; 32], u64)> {
        let box_ = self.boxes.get_mut(&queue_id)?;
        if now >= box_.expiry {
            return None;
        }
        if box_.challenges.len() >= 64 {
            box_.challenges.clear();
        }
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        box_.challenges.insert(nonce, now);
        Some((nonce, now))
    }

    pub fn take(
        &mut self,
        queue_id: [u8; 32],
        ts: u64,
        nonce: &[u8; 32],
        sig: &[u8],
        now: u64,
    ) -> Vec<Vec<u8>> {
        let Some(box_) = self.boxes.get_mut(&queue_id) else {
            return Vec::new();
        };
        if now >= box_.expiry || ts.abs_diff(now) > 120 {
            return Vec::new();
        }
        let Some(issued) = box_.challenges.remove(nonce) else {
            return Vec::new();
        };
        if issued.abs_diff(now) > 120 {
            return Vec::new();
        }
        let Ok(pk) = libp2p_identity::PublicKey::try_decode_protobuf(&box_.owner_pk) else {
            return Vec::new();
        };
        if !pk.verify(&query_message(&queue_id, ts, nonce), sig) {
            return Vec::new();
        }
        std::mem::take(&mut box_.blobs)
    }

    pub fn export(&self) -> Vec<u8> {
        let items: Vec<StoredQueue> = self
            .boxes
            .iter()
            .map(|(id, box_)| StoredQueue {
                queue_id: *id,
                owner_pk: box_.owner_pk.clone(),
                write_token: box_.write_token,
                expiry: box_.expiry,
                blobs: box_.blobs.clone(),
            })
            .collect();
        bincode::serialize(&items).unwrap_or_default()
    }

    pub fn import(bytes: &[u8]) -> Self {
        let items: Vec<StoredQueue> = bincode::deserialize(bytes).unwrap_or_default();
        let mut boxes = HashMap::new();
        for item in items {
            boxes.insert(
                item.queue_id,
                QueueBox {
                    owner_pk: item.owner_pk,
                    write_token: item.write_token,
                    expiry: item.expiry,
                    blobs: item.blobs,
                    challenges: HashMap::new(),
                },
            );
        }
        Self { boxes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_mail::OfflineEnvelope;

    fn env(n: usize) -> OfflineEnvelope {
        OfflineEnvelope {
            v: 3,
            sender: String::new(),
            sender_pk: [0u8; 32],
            message_id: "abc".into(),
            kind: String::new(),
            eph: [1u8; 32],
            nonce: [2u8; 12],
            ct: vec![7u8; n],
            local_kind: String::new(),
        }
    }

    #[test]
    fn store_log_has_queue_and_bucket_only() {
        let peer = "12D3KooWCAH8ykDMThNRRVLAM6LnuVrJeoZrQADzHC2x6ddhZxyG";
        let queue = OwnedQueue::create(1_700_000_000);
        let line = queue_store_log(&queue.queue_id, QUEUE_BUCKET);
        assert!(line.contains("bucket=65536"));
        assert!(line.contains("queue="));
        assert!(!line.contains(peer));
        assert!(!line.contains("recipient"));
    }

    #[test]
    fn text_and_voice_blobs_are_the_same_length() {
        let text = pad_queue_blob(&env(40)).unwrap();
        let voice = pad_queue_blob(&env(24 * 1024)).unwrap();
        assert_eq!(text.len(), QUEUE_BUCKET as usize);
        assert_eq!(voice.len(), text.len());
        assert_eq!(unpad_queue_blob(&text).unwrap().ct.len(), 40);
        assert_eq!(unpad_queue_blob(&voice).unwrap().ct.len(), 24 * 1024);
    }

    #[test]
    fn node_store_log_is_queue_id_not_peer() {
        let now = 1_700_000_000u64;
        let queue = OwnedQueue::create(now);
        let sig = sign_create(&queue).unwrap();
        let mut dir = QueueDir::new();
        let owner_pk = queue.owner.public().encode_protobuf();
        assert!(dir.create(
            queue.queue_id,
            owner_pk,
            queue.write_token,
            queue.expiry,
            &sig,
            now,
        ));
        let blob = pad_queue_blob(&env(8)).unwrap();
        let proof = write_proof(&queue.write_token, &queue.queue_id, &blob);
        let stored = dir.store(queue.queue_id, &proof, blob, now).unwrap();
        let line = queue_store_log(&stored.queue_id, stored.bucket);
        assert_eq!(stored.bucket, QUEUE_BUCKET);
        assert!(!line.contains("12D3Koo"));
        let (nonce, ts) = dir.challenge(queue.queue_id, now).unwrap();
        let qsig = sign_queue_query(&queue, ts, &nonce).unwrap();
        let got = dir.take(queue.queue_id, ts, &nonce, &qsig, now);
        assert_eq!(got.len(), 1);
        assert!(dir.take(queue.queue_id, ts, &nonce, &qsig, now).is_empty());
    }

    #[test]
    fn foreign_proof_does_not_store() {
        let now = 1_700_000_000u64;
        let queue = OwnedQueue::create(now);
        let sig = sign_create(&queue).unwrap();
        let mut dir = QueueDir::new();
        assert!(dir.create(
            queue.queue_id,
            queue.owner.public().encode_protobuf(),
            queue.write_token,
            queue.expiry,
            &sig,
            now,
        ));
        let blob = pad_queue_blob(&env(8)).unwrap();
        assert!(dir.store(queue.queue_id, &[9u8; 32], blob, now).is_none());
    }
}
