//! Offline outbox publish policy: durable handoff.
//!
//! When VOID bootstrap nodes are configured, durable handoff requires a
//! Store Ack from a bootstrap (voice chunks always do — DHT mailbox is too small).
//! DHT Put Ok / Ack from ephemeral peers is only a fallback when there are no
//! bootstraps (LAN-only mode).

use std::collections::{HashMap, HashSet};
use libp2p::PeerId;
use crate::offline_mail::{OfflineEnvelope, OFFLINE_VOICE_CHUNK_KIND};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishHandoff {
    Ok,
    Failed,
    Pending,
}

/// DHT Put Ok may settle handoff only for text-only batches in LAN-only mode
/// (no bootstrap nodes). With bootstraps configured, DHT is best-effort only.
pub(crate) fn accept_dht_as_full_handoff(
    envelopes: &[OfflineEnvelope],
    allow_dht_fallback: bool,
) -> bool {
    allow_dht_fallback
        && !envelopes.is_empty()
        && envelopes
            .iter()
            .all(|e| e.kind != OFFLINE_VOICE_CHUNK_KIND)
}

pub(crate) fn required_store_message_ids(envelopes: &[OfflineEnvelope]) -> HashSet<String> {
    envelopes.iter().map(|e| e.message_id.clone()).collect()
}

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

    pub(crate) fn from_envelopes(
        envelopes: &[OfflineEnvelope],
        allow_dht_fallback: bool,
    ) -> Self {
        Self::new(
            required_store_message_ids(envelopes),
            accept_dht_as_full_handoff(envelopes, allow_dht_fallback),
        )
    }

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

    pub(crate) fn relay_peer_ids(&self) -> Vec<PeerId> {
        self.by_relay.keys().copied().collect()
    }
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
    fn text_dm_accepts_dht_only_without_bootstraps() {
        let sealed = vec![env("m1", "dm")];
        assert!(accept_dht_as_full_handoff(&sealed, true));
        assert!(!accept_dht_as_full_handoff(&sealed, false));
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed, true);
        assert_eq!(st.on_dht_ok(), Some(true));
        let mut st2 = EnvelopeHandoffState::from_envelopes(&sealed, false);
        assert_eq!(st2.on_dht_ok(), None);
    }

    #[test]
    fn voice_chunks_reject_dht_alone() {
        let sealed = vec![
            env("meta", "dm"),
            env("c0", OFFLINE_VOICE_CHUNK_KIND),
            env("c1", OFFLINE_VOICE_CHUNK_KIND),
        ];
        assert!(!accept_dht_as_full_handoff(&sealed, true));
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed, true);
        assert_eq!(st.on_dht_ok(), None);
        assert_eq!(st.on_store_ack("meta"), None);
        assert_eq!(st.on_store_ack("c0"), None);
        assert_eq!(st.on_store_ack("c1"), Some(true));
    }

    #[test]
    fn first_ack_does_not_complete_multi_envelope() {
        let sealed = vec![
            env("c0", OFFLINE_VOICE_CHUNK_KIND),
            env("c1", OFFLINE_VOICE_CHUNK_KIND),
            env("c2", OFFLINE_VOICE_CHUNK_KIND),
        ];
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed, false);
        assert_eq!(st.on_store_ack("c0"), None);
        assert_eq!(st.pending_count(), 2);
    }

    #[test]
    fn pending_queue_merges_and_drains() {
        let r1 = PeerId::random();
        let recip = PeerId::random();
        let mut q = PendingRelayQueue::default();
        q.enqueue(r1, recip, vec![env("m1", "dm")]);
        q.enqueue(r1, recip, vec![env("m2", "dm"), env("m1", "dm")]);
        assert_eq!(q.take_for(&r1)[0].1.len(), 2);
        assert!(q.is_empty());
    }

    #[test]
    fn bootstrap_mode_needs_store_ack_for_text() {
        let sealed = vec![env("invite", "dm")];
        let mut st = EnvelopeHandoffState::from_envelopes(&sealed, false);
        assert_eq!(st.on_dht_ok(), None);
        assert_eq!(st.on_store_ack("invite"), Some(true));
    }
}
