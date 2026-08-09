//! Shared chat journal state for network task and UI/bridge.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use libp2p::PeerId;

use crate::protocol::ChatMessage;

/// Bounded set of locally deleted message ids (tombstones).
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

/// Conversations shared by UI/bridge and the network task.
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
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn mark_dirty(&self) {
        self.journal_dirty.store(true, Ordering::Release);
    }

    pub(crate) fn take_dirty(&self) -> bool {
        self.journal_dirty.swap(false, Ordering::AcqRel)
    }

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

    pub(crate) fn load_deleted(&self, ids: Vec<String>) {
        let mut t = self
            .deleted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *t = DeletedTombstones::from_vec(ids);
    }

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
