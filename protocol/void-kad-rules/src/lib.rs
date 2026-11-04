//! Whether a Kademlia record value may be stored.
//!
//! The check looks at key and value bytes only. There is no swarm and no
//! `libp2p` `kad` feature here. The store that calls [`dht_put_allowed`]
//! sits next to the node's swarm. [`dht_record_allowed`] still describes a
//! prekey and a v3 PeerId mailbox. A new mailbox put is refused while contact
//! queues are on; a record already stored is not deleted here.

use void_envelope::offline_mail::{
    mailbox_value_is_v3, peer_id_from_bytes, prekey_is_sealable, prekey_unix_now,
    decode_opk_bundle, verify_signed_prekey, MAILBOX_PREFIX, OPK_PREFIX, PREKEY_PREFIX,
};

/// Форма записи. prekey — подпись владельца и срок. Ящик — слот PeerId и
/// конверты v3. Это не разрешение нового `put`: его даёт [`dht_put_allowed`].
pub fn dht_record_allowed(key: &[u8], value: &[u8]) -> bool {
    if let Some(rest) = key.strip_prefix(PREKEY_PREFIX) {
        let Some(owner) = peer_id_from_bytes(rest) else {
            return false;
        };
        return verify_signed_prekey(&owner, value)
            .is_some_and(|pk| prekey_is_sealable(pk, prekey_unix_now()));
    }
    if let Some(rest) = key.strip_prefix(OPK_PREFIX) {
        let Some(owner) = peer_id_from_bytes(rest) else {
            return false;
        };
        return decode_opk_bundle(&owner, value).is_some();
    }
    if let Some(rest) = key.strip_prefix(MAILBOX_PREFIX) {
        if peer_id_from_bytes(rest).is_none() {
            return false;
        }
        return mailbox_value_is_v3(value);
    }
    false
}

/// Новый `put`, когда очередь контакта включена.
///
/// `/void/mailbox/` не пишется: это был бы второй ящик по PeerId. Уже лежащая
/// запись этой функцией не удаляется и доживает свой TTL. Ключа `/void/queue/`
/// нет. Одноразовый prekey в значение не входит: `/void/opk/` отклоняется.
pub fn dht_put_allowed(key: &[u8], value: &[u8]) -> bool {
    if key.starts_with(OPK_PREFIX) || key.starts_with(MAILBOX_PREFIX) {
        return false;
    }
    if key.starts_with(b"/void/queue/") {
        return false;
    }
    dht_record_allowed(key, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use void_envelope::offline_mail::{encode_mailbox, OfflineEnvelope, ENVELOPE_VERSION};

    fn peer_key(prefix: &[u8]) -> Vec<u8> {
        let id = libp2p_identity::PeerId::random();
        let mut key = prefix.to_vec();
        key.extend_from_slice(&id.to_bytes());
        key
    }

    fn mailbox_value() -> Vec<u8> {
        let env = OfflineEnvelope {
            v: ENVELOPE_VERSION,
            sender: String::new(),
            sender_pk: [0u8; 32],
            message_id: "m1".into(),
            kind: String::new(),
            eph: [1u8; 32],
            nonce: [0u8; 12],
            ct: vec![1, 2, 3],
            local_kind: String::new(),
        };
        encode_mailbox(&[env]).expect("mailbox")
    }

    #[test]
    fn shape_still_recognizes_a_mailbox_and_put_does_not() {
        let key = peer_key(MAILBOX_PREFIX);
        let value = mailbox_value();
        assert!(dht_record_allowed(&key, &value));
        assert!(!dht_put_allowed(&key, &value));
    }

    #[test]
    fn put_refuses_one_time_prekey_and_a_queue_key() {
        assert!(!dht_put_allowed(&peer_key(OPK_PREFIX), &[1, 0]));
        assert!(!dht_put_allowed(b"/void/queue/abcd", b"blob"));
    }
}
