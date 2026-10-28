//! DHT key bytes for prekey and mailbox records.
//!
//! The value check is `void-kad-rules`. Building a `RecordKey` needs the
//! swarm's Kademlia types, so it stays on this facade.

use libp2p::kad;
use libp2p::PeerId;

use void_envelope::offline_mail::{MAILBOX_PREFIX, PREKEY_PREFIX};

pub fn prekey_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = PREKEY_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub fn mailbox_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = MAILBOX_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}
