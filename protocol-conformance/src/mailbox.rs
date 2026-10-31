//! Ящик диспетчера в памяти.
//!
//! Потолок — 4096 ящиков, как у ноды. Зеркало LAN в клиенте режет свои 256
//! и на диск пишет само; сюда это не входит. Время приёма задаёт тест через
//! [`MailboxNode::set_now`], на провод оно не попадает.

use std::collections::HashMap;

use libp2p::PeerId;
use void_protocol::offline_mail::{OfflineEnvelope, ENVELOPE_VERSION, MAILBOX_TTL_SECS};
use void_protocol::protocol::ChallengeBook;

const MAX_MAILBOXES: usize = 4096;
const MAX_PER_MAILBOX: usize = 1024;
const MAX_BYTES_PER_MAILBOX: usize = 32 * 1024 * 1024;
const MAX_PER_UPLOADER: usize = 256;
const MAX_BYTES_PER_UPLOADER: usize = 8 * 1024 * 1024;
const MAX_CT: usize = 64 * 1024;
const BATCH_BYTES: usize = 512 * 1024;
const STORE_WINDOW_SECS: u64 = 60;
const STORE_MAX_REQUESTS: u32 = 600;
const STORE_MAX_ENVELOPES: usize = 600;
const STORE_MAX_CT_BYTES: usize = 48 * 1024 * 1024;

/// `Ack`: диспетчер принял ответственность.
/// `Refused`: непустой `Store` не принят, отправитель оставляет письмо у себя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOutcome {
    Ack,
    Refused,
}

/// Пустой ящик и `Query` без свежей подписи получателя — `Ack`. Иначе пачка, уже стёртая из ящика.
#[derive(Debug, Clone)]
pub enum QueryOutcome {
    Ack,
    Deliver(Vec<OfflineEnvelope>),
}

/// Echo of `MailboxChallenge` plus the recipient's signature.
#[derive(Debug, Clone)]
pub struct SignedMailboxQuery {
    pub recipient: String,
    pub ts: u64,
    pub nonce: [u8; 32],
    pub sig: Vec<u8>,
}

#[derive(Clone)]
struct Stored {
    env: OfflineEnvelope,
    accepted_at: u64,
    uploader: String,
    bytes: usize,
}

struct Window {
    start: u64,
    requests: u32,
    envelopes: usize,
    ct_bytes: usize,
}

/// In-memory mailbox. `uploader` — Noise-`PeerId` стороны `Store`.
pub struct MailboxNode {
    now: u64,
    boxes: HashMap<String, Vec<Stored>>,
    rate: HashMap<String, Window>,
    challenges: ChallengeBook,
}

impl Default for MailboxNode {
    fn default() -> Self {
        Self::new()
    }
}

impl MailboxNode {
    pub fn new() -> Self {
        Self {
            now: 0,
            boxes: HashMap::new(),
            rate: HashMap::new(),
            challenges: ChallengeBook::new(),
        }
    }

    /// Nonce for `recipient`. Anyone may ask. The signature still has to be theirs.
    pub fn challenge(&mut self, recipient: &str) -> Option<([u8; 32], u64)> {
        let id = recipient.parse().ok()?;
        Some(self.challenges.issue(id, self.now))
    }

    pub fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    pub fn store(
        &mut self,
        uploader: PeerId,
        recipient: &str,
        envelopes: &[OfflineEnvelope],
    ) -> StoreOutcome {
        let Ok(recipient_peer) = recipient.parse::<PeerId>() else {
            return StoreOutcome::Refused;
        };
        let key = recipient_peer.to_string();
        if envelopes.is_empty() {
            return if self.charge(&uploader, 0, 0) {
                StoreOutcome::Ack
            } else {
                StoreOutcome::Refused
            };
        }
        let fresh: Vec<OfflineEnvelope> = envelopes
            .iter()
            .filter(|e| is_v3_outer(e))
            .cloned()
            .collect();
        if fresh.is_empty() {
            let _ = self.charge(&uploader, 0, 0);
            return StoreOutcome::Refused;
        }
        let ct_bytes: usize = fresh.iter().map(|e| e.ct.len()).sum();
        if !self.charge(&uploader, fresh.len(), ct_bytes) {
            return StoreOutcome::Refused;
        }
        self.purge_expired();
        if !self.boxes.contains_key(&key) && self.boxes.len() >= MAX_MAILBOXES {
            return StoreOutcome::Refused;
        }
        let admitted = self.prefix(&key, &uploader, &fresh);
        if admitted.is_empty() {
            return StoreOutcome::Refused;
        }
        let slot = self.boxes.entry(key.clone()).or_default();
        for env in admitted {
            if slot.iter().any(|s| s.env.message_id == env.message_id) {
                continue;
            }
            let bytes = quota_bytes(&env);
            slot.push(Stored {
                env,
                accepted_at: self.now,
                uploader: uploader.to_string(),
                bytes,
            });
        }
        self.trim(&key);
        StoreOutcome::Ack
    }

    pub fn query(&mut self, q: &SignedMailboxQuery) -> QueryOutcome {
        let Ok(who) = q.recipient.parse::<PeerId>() else {
            return QueryOutcome::Ack;
        };
        if !self
            .challenges
            .authorize(&who, q.ts, &q.nonce, &q.sig, self.now)
        {
            return QueryOutcome::Ack;
        }
        self.purge_expired();
        let key = who.to_string();
        let Some(slot) = self.boxes.get_mut(&key) else {
            return QueryOutcome::Ack;
        };
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(item) = slot.first() {
            if !out.is_empty() && used.saturating_add(item.bytes) > BATCH_BYTES {
                break;
            }
            used = used.saturating_add(item.bytes);
            out.push(slot.remove(0).env);
            if used >= BATCH_BYTES {
                break;
            }
        }
        if slot.is_empty() {
            self.boxes.remove(&key);
        }
        if out.is_empty() {
            QueryOutcome::Ack
        } else {
            QueryOutcome::Deliver(out)
        }
    }

    /// Сколько конвертов лежит сейчас, после стирания просроченных.
    pub fn stored(&mut self, recipient: &str) -> usize {
        self.purge_expired();
        let Ok(who) = recipient.parse::<PeerId>() else {
            return 0;
        };
        self.boxes
            .get(&who.to_string())
            .map(|s| s.len())
            .unwrap_or(0)
    }

    pub fn mailboxes(&mut self) -> usize {
        self.purge_expired();
        self.boxes.len()
    }

    fn charge(&mut self, uploader: &PeerId, envelopes: usize, ct_bytes: usize) -> bool {
        let now = self.now;
        let window = self.rate.entry(uploader.to_string()).or_insert(Window {
            start: now,
            requests: 0,
            envelopes: 0,
            ct_bytes: 0,
        });
        if now.saturating_sub(window.start) >= STORE_WINDOW_SECS {
            *window = Window {
                start: now,
                requests: 0,
                envelopes: 0,
                ct_bytes: 0,
            };
        }
        if window.requests >= STORE_MAX_REQUESTS
            || window.envelopes.saturating_add(envelopes) > STORE_MAX_ENVELOPES
            || window.ct_bytes.saturating_add(ct_bytes) > STORE_MAX_CT_BYTES
        {
            return false;
        }
        window.requests += 1;
        window.envelopes += envelopes;
        window.ct_bytes += ct_bytes;
        true
    }

    fn prefix(
        &self,
        recipient: &str,
        uploader: &PeerId,
        fresh: &[OfflineEnvelope],
    ) -> Vec<OfflineEnvelope> {
        let up = uploader.to_string();
        let slot = self.boxes.get(recipient);
        let mut count = 0usize;
        let mut bytes = 0usize;
        if let Some(slot) = slot {
            for item in slot.iter().filter(|s| s.uploader == up) {
                count += 1;
                bytes += item.bytes;
            }
        }
        let mut out = Vec::new();
        for env in fresh {
            let dup = slot
                .map(|s| s.iter().any(|item| item.env.message_id == env.message_id))
                .unwrap_or(false)
                || out
                    .iter()
                    .any(|e: &OfflineEnvelope| e.message_id == env.message_id);
            if dup {
                out.push(env.clone());
                continue;
            }
            let n = quota_bytes(env);
            if count >= MAX_PER_UPLOADER || bytes.saturating_add(n) > MAX_BYTES_PER_UPLOADER {
                break;
            }
            count += 1;
            bytes += n;
            out.push(env.clone());
        }
        out
    }

    fn trim(&mut self, recipient: &str) {
        let Some(slot) = self.boxes.get_mut(recipient) else {
            return;
        };
        if slot.len() > MAX_PER_MAILBOX {
            let drop_n = slot.len() - MAX_PER_MAILBOX;
            slot.drain(0..drop_n);
        }
        let mut total: usize = slot.iter().map(|s| s.bytes).sum();
        while total > MAX_BYTES_PER_MAILBOX && !slot.is_empty() {
            total -= slot.remove(0).bytes;
        }
        if slot.is_empty() {
            self.boxes.remove(recipient);
        }
    }

    fn purge_expired(&mut self) {
        let now = self.now;
        self.boxes.retain(|_, slot| {
            slot.retain(|s| now.saturating_sub(s.accepted_at) < MAILBOX_TTL_SECS);
            !slot.is_empty()
        });
    }
}

fn quota_bytes(env: &OfflineEnvelope) -> usize {
    env.ct.len() + 96
}

fn is_v3_outer(env: &OfflineEnvelope) -> bool {
    env.v == ENVELOPE_VERSION
        && env.sender.is_empty()
        && env.kind.is_empty()
        && env.sender_pk == [0u8; 32]
        && !env.message_id.is_empty()
        && env.message_id.len() <= 128
        && env.eph != [0u8; 32]
        && !env.ct.is_empty()
        && env.ct.len() <= MAX_CT
}
