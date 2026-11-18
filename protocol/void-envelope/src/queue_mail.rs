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
/// Сколько очередей держит диспетчер. Новый id сверх этого не создаётся.
pub const MAX_QUEUES: usize = 4096;
/// Сколько блобов в одной очереди. Полная очередь снимает самый старый.
pub const MAX_BLOBS: usize = 1024;
/// Сколько диспетчеров держат одну и ту же запись. Нода чужой `queue_id` не копирует.
pub const QUEUE_REPLICAS: usize = 3;

/// 32 байта `PeerId`, с которыми XOR-ится `queue_id`.
/// Хвост `PeerId::to_bytes()`, если байт больше 32. Короче — нули слева.
pub fn queue_peer_material(peer_bytes: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    if peer_bytes.len() >= 32 {
        key.copy_from_slice(&peer_bytes[peer_bytes.len() - 32..]);
    } else if !peer_bytes.is_empty() {
        let start = 32 - peer_bytes.len();
        key[start..].copy_from_slice(peer_bytes);
    }
    key
}

/// Побайтовый XOR `queue_id` и [`queue_peer_material`]. Меньший результат
/// как беззнаковое 256-битное число (с первого байта) — ближе.
pub fn queue_xor_distance(queue_id: &[u8; 32], peer_bytes: &[u8]) -> [u8; 32] {
    let mut key = queue_peer_material(peer_bytes);
    for (byte, q) in key.iter_mut().zip(queue_id.iter()) {
        *byte ^= *q;
    }
    key
}

/// Bytes of a swarm id or of [`void_session::PeerId`]. Distance uses only these.
pub trait QueuePeerBytes {
    fn queue_peer_bytes(&self) -> Vec<u8>;
}

impl QueuePeerBytes for void_session::PeerId {
    fn queue_peer_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl QueuePeerBytes for libp2p_identity::PeerId {
    fn queue_peer_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

/// До [`QUEUE_REPLICAS`] нод с наименьшим XOR. Равные расстояния — меньшие байты `PeerId`.
pub fn closest_queue_peers<P>(queue_id: &[u8; 32], peers: impl IntoIterator<Item = P>) -> Vec<P>
where
    P: Clone + PartialEq,
    P: QueuePeerBytes,
{
    let mut peers: Vec<P> = peers.into_iter().collect();
    peers.sort_by(|a, b| {
        queue_xor_distance(queue_id, &a.queue_peer_bytes())
            .cmp(&queue_xor_distance(queue_id, &b.queue_peer_bytes()))
            .then_with(|| a.queue_peer_bytes().cmp(&b.queue_peer_bytes()))
    });
    peers.dedup();
    peers.truncate(QUEUE_REPLICAS);
    peers
}

const MAX_OWNER_PK: usize = 4096;
const MAX_SIG: usize = 256;
const CHALLENGE_TTL_SECS: u64 = 120;

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
    /// `false` — тот же блоб или тот же внешний id. Слот не вырос.
    pub fresh: bool,
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

    pub fn len(&self) -> usize {
        self.boxes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty()
    }

    pub fn contains(&self, queue_id: &[u8; 32]) -> bool {
        self.boxes.contains_key(queue_id)
    }

    /// Уже принятая очередь (старый файл). Подпись при загрузке не проверяется повторно.
    pub fn adopt(
        &mut self,
        queue_id: [u8; 32],
        owner_pk: Vec<u8>,
        write_token: [u8; 32],
        expiry: u64,
        blobs: Vec<Vec<u8>>,
    ) {
        self.boxes.entry(queue_id).or_insert(QueueBox {
            owner_pk,
            write_token,
            expiry,
            blobs,
            challenges: HashMap::new(),
        });
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
        if owner_pk.len() > MAX_OWNER_PK
            || sig.len() > MAX_SIG
            || expiry > now.saturating_add(QUEUE_TTL_SECS)
            || !verify_create(&owner_pk, &queue_id, &write_token, expiry, sig, now)
        {
            return false;
        }
        if !self.boxes.contains_key(&queue_id) && self.boxes.len() >= MAX_QUEUES {
            return false;
        }
        let blobs = self
            .boxes
            .get(&queue_id)
            .map(|box_| box_.blobs.clone())
            .unwrap_or_default();
        self.boxes.insert(
            queue_id,
            QueueBox {
                owner_pk,
                write_token,
                expiry,
                blobs,
                challenges: HashMap::new(),
            },
        );
        true
    }

    /// Кладёт письмо. В результате только `queue_id` и бакет. Чужой proof слот не растит.
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
        if self
            .boxes
            .get(&queue_id)
            .is_some_and(|box_| now >= box_.expiry)
        {
            self.boxes.remove(&queue_id);
            return None;
        }
        let expected = {
            let box_ = self.boxes.get(&queue_id)?;
            write_proof(&box_.write_token, &queue_id, &blob)
        };
        if proof != &expected {
            return None;
        }
        let same_letter = unpad_queue_blob(&blob)
            .filter(|incoming| !incoming.message_id.is_empty())
            .and_then(|incoming| {
                let box_ = self.boxes.get(&queue_id)?;
                let dup = box_.blobs.iter().any(|old| {
                    unpad_queue_blob(old).is_some_and(|prev| prev.message_id == incoming.message_id)
                });
                Some(dup)
            })
            .unwrap_or(false);
        let box_ = self.boxes.get_mut(&queue_id)?;
        let mut fresh = false;
        if !same_letter && !box_.blobs.iter().any(|have| have == &blob) {
            box_.blobs.push(blob);
            fresh = true;
            if box_.blobs.len() > MAX_BLOBS {
                let drop_n = box_.blobs.len() - MAX_BLOBS;
                box_.blobs.drain(0..drop_n);
            }
        }
        Some(QueueStored {
            queue_id,
            bucket: QUEUE_BUCKET,
            fresh,
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

    pub fn owner_pk(&self, queue_id: &[u8; 32], now: u64) -> Option<&[u8]> {
        let box_ = self.boxes.get(queue_id)?;
        if now >= box_.expiry {
            return None;
        }
        Some(box_.owner_pk.as_slice())
    }

    /// Снимает nonce, который выдала эта очередь. Подпись владельца проверяет вызывающий.
    pub fn take_challenge(&mut self, queue_id: &[u8; 32], nonce: &[u8; 32], now: u64) -> bool {
        let Some(box_) = self.boxes.get_mut(queue_id) else {
            return false;
        };
        if now >= box_.expiry {
            return false;
        }
        let Some(issued) = box_.challenges.remove(nonce) else {
            return false;
        };
        issued.abs_diff(now) <= CHALLENGE_TTL_SECS
    }

    /// Снимает пачку. Подпись сюда не входит: её проверяют до вызова.
    pub fn take_batch(
        &mut self,
        queue_id: [u8; 32],
        max_plain_bytes: usize,
        now: u64,
    ) -> Vec<Vec<u8>> {
        if self
            .boxes
            .get(&queue_id)
            .is_some_and(|box_| now >= box_.expiry)
        {
            self.boxes.remove(&queue_id);
            return Vec::new();
        }
        let Some(box_) = self.boxes.get_mut(&queue_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(blob) = box_.blobs.first() {
            let n = blob.len();
            if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                break;
            }
            out.push(box_.blobs.remove(0));
            used = used.saturating_add(n);
            if used >= max_plain_bytes {
                break;
            }
        }
        out
    }

    pub fn restore(&mut self, queue_id: [u8; 32], blobs: Vec<Vec<u8>>) {
        let Some(box_) = self.boxes.get_mut(&queue_id) else {
            return;
        };
        for blob in blobs.into_iter().rev() {
            box_.blobs.insert(0, blob);
        }
    }

    /// Стирает очереди, у которых вышел `expiry`. До этого срока старый id ещё выдаётся.
    pub fn purge_expired(&mut self, now: u64) -> bool {
        let before = self.boxes.len();
        self.boxes.retain(|_, box_| now < box_.expiry);
        self.boxes.len() != before
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
        let before = dir.take_batch(queue.queue_id, usize::MAX, now);
        assert!(before.is_empty());
        assert!(dir.store(queue.queue_id, &[9u8; 32], blob.clone(), now).is_none());
        let proof = write_proof(&queue.write_token, &queue.queue_id, &blob);
        let stored = dir.store(queue.queue_id, &proof, blob.clone(), now).unwrap();
        assert!(stored.fresh);
        assert!(dir.store(queue.queue_id, &[9u8; 32], blob.clone(), now).is_none());
        let again = dir.store(queue.queue_id, &proof, blob, now).unwrap();
        assert!(!again.fresh);
        assert_eq!(dir.take_batch(queue.queue_id, usize::MAX, now).len(), 1);
    }

    #[test]
    fn expiry_longer_than_14_days_is_refused() {
        let now = 1_700_000_000u64;
        let queue = OwnedQueue::create(now);
        let expiry = now + QUEUE_TTL_SECS + 1;
        let owner_pk = queue.owner.public().encode_protobuf();
        let sig = queue
            .owner
            .sign(&create_message(&queue.queue_id, &queue.write_token, expiry))
            .unwrap();
        let mut dir = QueueDir::new();
        assert!(!dir.create(
            queue.queue_id,
            owner_pk,
            queue.write_token,
            expiry,
            &sig,
            now,
        ));
        assert!(dir.is_empty());
    }

    #[test]
    fn unsigned_query_is_empty_and_deliver_unpads() {
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
        let proof = write_proof(&queue.write_token, &queue.queue_id, &blob);
        dir.store(queue.queue_id, &proof, blob, now).unwrap();
        assert!(dir.take(queue.queue_id, now, &[0u8; 32], &[], now).is_empty());
        let (nonce, ts) = dir.challenge(queue.queue_id, now).unwrap();
        assert!(dir
            .take(queue.queue_id, ts, &nonce, &[], now)
            .is_empty());
        let (nonce, ts) = dir.challenge(queue.queue_id, now).unwrap();
        assert!(dir.take_challenge(&queue.queue_id, &nonce, now));
        let got = dir.take_batch(queue.queue_id, 512 * 1024, now);
        assert_eq!(unpad_queue_blob(&got[0]).unwrap().ct.len(), 8);
        assert!(dir.take_batch(queue.queue_id, 512 * 1024, now).is_empty());
    }

    #[test]
    fn previous_queue_lasts_until_expiry() {
        let now = 1_700_000_000u64;
        let queue = OwnedQueue::create(now);
        let mut short = queue.clone();
        short.expiry = now + 100;
        let sig = short
            .owner
            .sign(&create_message(&short.queue_id, &short.write_token, short.expiry))
            .unwrap();
        let mut dir = QueueDir::new();
        assert!(dir.create(
            short.queue_id,
            short.owner.public().encode_protobuf(),
            short.write_token,
            short.expiry,
            &sig,
            now,
        ));
        let blob = pad_queue_blob(&env(4)).unwrap();
        let proof = write_proof(&short.write_token, &short.queue_id, &blob);
        dir.store(short.queue_id, &proof, blob, now).unwrap();
        assert!(!dir.purge_expired(short.expiry - 1));
        assert!(dir.contains(&short.queue_id));
        let (nonce, ts) = dir.challenge(short.queue_id, short.expiry - 1).unwrap();
        let qsig = sign_queue_query(&short, ts, &nonce).unwrap();
        assert_eq!(
            dir.take(short.queue_id, ts, &nonce, &qsig, short.expiry - 1).len(),
            1
        );
        assert!(dir.purge_expired(short.expiry));
        assert!(!dir.contains(&short.queue_id));
        assert!(dir.take_batch(short.queue_id, usize::MAX, short.expiry).is_empty());
    }

    #[test]
    fn xor_distance_keeps_three_closest_nodes() {
        let queue_id = [0x11u8; 32];
        let peers: Vec<libp2p_identity::PeerId> = (0..5)
            .map(|_| Keypair::generate_ed25519().public().to_peer_id())
            .collect();
        let mut ranked = peers.clone();
        ranked.sort_by(|a, b| {
            queue_xor_distance(&queue_id, &a.to_bytes())
                .cmp(&queue_xor_distance(&queue_id, &b.to_bytes()))
                .then_with(|| a.to_bytes().cmp(&b.to_bytes()))
        });
        let closest = closest_queue_peers(&queue_id, peers.iter().copied().rev());
        assert_eq!(closest, ranked[..QUEUE_REPLICAS]);
        assert!(!closest.contains(&ranked[4]));
        let only = closest_queue_peers(&queue_id, std::iter::once(peers[0]));
        assert_eq!(only, vec![peers[0]]);
        let material = queue_peer_material(&peers[0].to_bytes());
        let distance = queue_xor_distance(&queue_id, &peers[0].to_bytes());
        assert!(distance.iter().zip(material).all(|(d, m)| *d == m ^ 0x11));
    }
}
