//! Эфемерные ключи уже принятых `Hello` (persisted on disk).
//!
//! Подпись `Hello` не содержит времени, а каждый настоящий `Hello` несёт свежий
//! эфемерный ключ. Повтор того же ключа от того же `PeerId` — это переигранный
//! пакет (например, onion-hop'ом), он не должен сбрасывать живую сессию.

use std::collections::{HashMap, VecDeque};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::paths;

const FILE: &str = "hello_seen.bin";
const PER_PEER: usize = 64;
const MAX_PEERS: usize = 4096;

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct HelloReplayCache {
    by_peer: HashMap<String, VecDeque<[u8; 32]>>,
}

impl HelloReplayCache {
    pub(crate) fn load() -> Self {
        std::fs::read(paths::data_file(FILE))
            .ok()
            .and_then(|b| bincode::deserialize(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        let Ok(bytes) = bincode::serialize(self) else {
            return;
        };
        let path = paths::data_file(FILE);
        let tmp = paths::data_file(format!("{FILE}.tmp"));
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
    }

    /// `true` — ключ новый и запомнен; `false` — повтор.
    pub(crate) fn note_fresh(&mut self, peer: PeerId, ephemeral: &[u8; 32]) -> bool {
        let fresh = self.insert(peer, ephemeral);
        if fresh {
            self.save();
        }
        fresh
    }

    fn insert(&mut self, peer: PeerId, ephemeral: &[u8; 32]) -> bool {
        let key = peer.to_string();
        if !self.by_peer.contains_key(&key) && self.by_peer.len() >= MAX_PEERS {
            if let Some(evict) = self.by_peer.keys().next().cloned() {
                self.by_peer.remove(&evict);
            }
        }
        let seen = self.by_peer.entry(key).or_default();
        if seen.contains(ephemeral) {
            return false;
        }
        seen.push_back(*ephemeral);
        while seen.len() > PER_PEER {
            seen.pop_front();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_ephemeral_is_replay() {
        let mut c = HelloReplayCache::default();
        let a = PeerId::random();
        let b = PeerId::random();
        assert!(c.insert(a, &[1; 32]));
        assert!(!c.insert(a, &[1; 32]));
        assert!(c.insert(a, &[2; 32]));
        assert!(c.insert(b, &[1; 32]));
    }

    #[test]
    fn per_peer_window_is_bounded() {
        let mut c = HelloReplayCache::default();
        let a = PeerId::random();
        for i in 0..(PER_PEER as u8 + 1) {
            assert!(c.insert(a, &[i; 32]));
        }
        assert_eq!(c.by_peer[&a.to_string()].len(), PER_PEER);
    }
}
