//! Whether a Kademlia record value may be stored.
//!
//! The check looks at key and value bytes only. There is no swarm and no
//! `libp2p` `kad` feature here. The store that calls [`dht_record_allowed`]
//! sits next to the node's swarm.

use void_envelope::offline_mail::{
    mailbox_value_is_v3, peer_id_from_bytes, prekey_is_sealable, prekey_unix_now,
    verify_signed_prekey, MAILBOX_PREFIX, PREKEY_PREFIX,
};

/// Запись, которую Kademlia имеет право положить в локальный store.
/// prekey — подпись владельца и срок; mailbox — слот PeerId и конверты v3.
pub fn dht_record_allowed(key: &[u8], value: &[u8]) -> bool {
    if let Some(rest) = key.strip_prefix(PREKEY_PREFIX) {
        let Some(owner) = peer_id_from_bytes(rest) else {
            return false;
        };
        return verify_signed_prekey(&owner, value)
            .is_some_and(|pk| prekey_is_sealable(pk, prekey_unix_now()));
    }
    if let Some(rest) = key.strip_prefix(MAILBOX_PREFIX) {
        if peer_id_from_bytes(rest).is_none() {
            return false;
        }
        return mailbox_value_is_v3(value);
    }
    false
}
