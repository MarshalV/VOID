//! Offline outbox publish policy: durable handoff requires every envelope
//! to get a relay Store Ack (voice cannot rely on DHT meta Put alone).

use std::collections::{HashMap, HashSet};

use libp2p::PeerId;

use crate::offline_mail::{OfflineEnvelope, OFFLINE_VOICE_CHUNK_KIND};

/// Per-recipient publish outcome for exit flush / ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishHandoff {
    Ok,
    Failed,
    Pending,
}

/// DHT Put Ok is enough only when there are no voice_chunk envelopes.
pub(crate) fn accept_dht_as_full_handoff(envelopes: &[OfflineEnvelope]) -> bool {
    !envelopes
        .iter()
        .any(|e| e.kind == OFFLINE_VOICE_CHUNK_KIND)
}

/// Unique message_ids that must each receive at least one Store Ack.
pub(crate) fn required_store_message_ids(envelopes: &[OfflineEnvelope]) -> HashSet<String> {
    envelopes.iter().map(|e| e.message_id.clone()).collect()
}

/// Tracks which envelopes still need a relay Store Ack.
#[derive(Debug, Clone)]
pub(crate) struct EnvelopeHandoffState {
    pending: HashSet<String>,
    accept_dht: bool,
    settled: Option<bool>,
}

impl EnvelopeHandoffState {
    pub(crate) fn new(message_ids: HashSet<String>, accept_dht: bool) -> Self {
        Self {
            pending: message_ids,
            accept_dht,
            settled: None,
        }
    }

    pub(crate) fn from_envelopes(envelopes: &[OfflineEnvelope]) -> Self {
        Self::new(
            required_store_message_ids(envelopes),
            accept_dht_as_full_handoff(envelopes),
        )
    }

    pub(crate) fn verdict(&self) -> PublishHandoff {
        match self.settled {
            Some(true) => PublishHandoff::Ok,
            Some(false) => PublishHandoff::Failed,
            None => {
                if self.pending.is_empty() {
                    PublishHandoff::Ok
                } else {
                    PublishHandoff::Pending
                }
            }
        }
    }

    /// Returns Some(ok) when this event settles the handoff.
    pub(crate) fn on_store_ack(&mut self, message_id: &str) -> Option<bool> {
        if self.settled.is_some() {
            return None;
        }
        self.pending.remove(message_id);
        if self.pending.is_empty() {
            self.settled = Some(true);
            Some(true)
        } else {
            None
        }
    }

    /// DHT Put Ok: settles only when accept_dht (no voice chunks).
    pub(crate) fn on_dht_ok(&mut self) -> Option<bool> {
        if self.settled.is_some() {
            return None;
        }
        if self.accept_dht {
            self.pending.clear();
            self.settled = Some(true);
            Some(true)
        } else {
            None
        }
    }

    pub(crate) fn on_fail(&mut self) -> Option<bool> {
        if self.settled.is_some() {
            return None;
        }
        self.settled = Some(false);
        Some(false)
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

pub(crate) fn exit_flush_ok(results: &[PublishHandoff]) -> bool {
    !results.is_empty() && results.iter().all(|r| *r == PublishHandoff::Ok)
}

/// Queue of OfflineMailboxStore for a relay peer while it is offline.
#[derive(Debug, Default, Clone)]
pub(crate) struct PendingRelayQueue {
    by_relay: HashMap<PeerId, Vec<(PeerId, Vec<OfflineEnvelope>)>>,
}

impl PendingRelayQueue {
    pub(crate) fn enqueue(
        &mut self,
        relay: PeerId,
        recipient: PeerId,
        envelopes: Vec<OfflineEnvelope>,
    ) {
        if envelopes.is_empty() {
            return;
        }
        let slot = self.by_relay.entry(relay).or_default();
        if let Some((_, existing)) = slot.iter_mut().find(|(r, _)| *r == recipient) {
            for env in envelopes {
                if existing.iter().any(|e| e.message_id == env.message_id) {
                    continue;
                }
                existing.push(env);
            }
        } else {
            slot.push((recipient, envelopes));
        }
    }

    pub(crate) fn take_for(&mut self, relay: &PeerId) -> Vec<(PeerId, Vec<OfflineEnvelope>)> {
        self.by_relay.remove(relay).unwrap_or_default()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_relay.is_empty()
    }

    pub(crate) fn queued_relays(&self) -> usize {
        self.by_relay.len()
    }
}

pub(crate) fn must_queue_when_disconnected(connected: bool) -> bool {
    !connected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(id: &str, kind: &str) -> OfflineEnvelope {
        OfflineEnvelope {
            v: 1,
            sender: "a".into(),
            sender_pk: [0u8; 32],
            message_id: id.to_string(),
            kind: kind.into(),
            eph: [0u8; 32],
            nonce: [0u8; 12],
            ct: vec![1, 2, 3],
        }
    }

    #[test]
    fn voice_rejects_dht_only_handoff() {
        let sealed = vec![
            env("meta", "dm"),
            env("c0", OFFLINE_VOICE_CHUNK_KIND),
            env("c1", OFFLINE_VOICE_CHUNK_KIND),
        ];
        assert!(!accept_dht_as_full_handoff(&sealed));
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed);
        assert_eq!(st.on_dht_ok(), None);
        assert_eq!(st.verdict(), PublishHandoff::Pending);
        assert_eq!(st.on_store_ack("meta"), None);
        assert_eq!(st.on_store_ack("c0"), None);
        assert_eq!(st.on_store_ack("c1"), Some(true));
        assert_eq!(st.verdict(), PublishHandoff::Ok);
    }

    #[test]
    fn text_accepts_dht_or_single_store_ack() {
        let sealed = vec![env("m1", "dm")];
        assert!(accept_dht_as_full_handoff(&sealed));
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed);
        assert_eq!(st.on_dht_ok(), Some(true));

        let mut st2 = EnvelopeHandoffState::from_envelopes(&sealed);
        assert_eq!(st2.on_store_ack("m1"), Some(true));
    }

    #[test]
    fn duplicate_store_ack_for_same_id_does_not_double_settle() {
        let sealed = vec![env("m1", "dm"), env("m2", "dm")];
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed);
        assert_eq!(st.on_store_ack("m1"), None);
        assert_eq!(st.on_store_ack("m1"), None);
        assert_eq!(st.on_store_ack("m2"), Some(true));
        assert_eq!(st.on_store_ack("m2"), None);
    }

    #[test]
    fn first_wins_bug_would_pass_with_one_of_many_voice_acks() {
        // Documents the old once_gate bug: one Ack must NOT complete voice.
        let sealed = vec![
            env("c0", OFFLINE_VOICE_CHUNK_KIND),
            env("c1", OFFLINE_VOICE_CHUNK_KIND),
            env("c2", OFFLINE_VOICE_CHUNK_KIND),
        ];
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed);
        assert_eq!(st.on_store_ack("c0"), None);
        assert_eq!(st.pending_count(), 2);
    }

    #[test]
    fn exit_flush_ok_all_or_nothing() {
        assert!(!exit_flush_ok(&[]));
        assert!(!exit_flush_ok(&[PublishHandoff::Ok, PublishHandoff::Failed]));
        assert!(exit_flush_ok(&[PublishHandoff::Ok, PublishHandoff::Ok]));
    }

    #[test]
    fn pending_queue_merges_and_drains() {
        let r1 = PeerId::random();
        let recip = PeerId::random();
        let mut q = PendingRelayQueue::default();
        q.enqueue(r1, recip, vec![env("m1", "dm")]);
        q.enqueue(r1, recip, vec![env("m2", "dm"), env("m1", "dm")]);
        let got = q.take_for(&r1);
        assert_eq!(got[0].1.len(), 2);
        assert!(q.is_empty());
    }
}
