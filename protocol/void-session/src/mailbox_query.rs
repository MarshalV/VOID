//! Signed mailbox fetch. The TCP peer is not the owner when the query
//! arrives from an onion exit, so the node asks for a one-time nonce and
//! checks an Ed25519 signature of the recipient PeerId.

use std::collections::HashMap;

use libp2p_identity::{Keypair, PeerId};
use rand::RngCore;

use crate::hello::void_peer_transport_public_key;

/// Domain separator. Bytes after it: recipient multihash, `ts` le, nonce.
pub const MAILBOX_QUERY_PREFIX: &[u8] = b"VOID_MAILBOX_QUERY_v1";
/// Challenge and the echoed `ts` must sit inside this window.
pub const MAILBOX_QUERY_FRESHNESS_SECS: u64 = 120;
const MAX_CHALLENGES: usize = 4096;

pub fn mailbox_query_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn mailbox_query_message(recipient: &PeerId, ts: u64, nonce: &[u8; 32]) -> Vec<u8> {
    let id = recipient.to_bytes();
    let mut v = Vec::with_capacity(MAILBOX_QUERY_PREFIX.len() + id.len() + 8 + 32);
    v.extend_from_slice(MAILBOX_QUERY_PREFIX);
    v.extend_from_slice(&id);
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(nonce);
    v
}

/// Signature of the local identity. `None` when `key` is not `recipient`.
pub fn sign_mailbox_query(
    key: &Keypair,
    recipient: &PeerId,
    ts: u64,
    nonce: &[u8; 32],
) -> Option<Vec<u8>> {
    if PeerId::from_public_key(&key.public()) != *recipient {
        return None;
    }
    key.sign(&mailbox_query_message(recipient, ts, nonce))
        .ok()
}

pub fn verify_mailbox_query(recipient: &PeerId, ts: u64, nonce: &[u8; 32], sig: &[u8]) -> bool {
    if sig.is_empty() {
        return false;
    }
    let Some(pk) = void_peer_transport_public_key(*recipient) else {
        return false;
    };
    pk.verify(&mailbox_query_message(recipient, ts, nonce), sig)
}

struct Issued {
    recipient: PeerId,
    ts: u64,
}

/// Nonces this process has handed out and not yet accepted.
#[derive(Default)]
pub struct ChallengeBook {
    by_nonce: HashMap<[u8; 32], Issued>,
}

impl ChallengeBook {
    pub fn new() -> Self {
        Self {
            by_nonce: HashMap::new(),
        }
    }

    /// Mint a nonce bound to `recipient` and `now`. The client must echo both.
    pub fn issue(&mut self, recipient: PeerId, now: u64) -> ([u8; 32], u64) {
        self.sweep(now);
        if self.by_nonce.len() >= MAX_CHALLENGES {
            if let Some(old) = self.by_nonce.keys().next().copied() {
                self.by_nonce.remove(&old);
            }
        }
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.by_nonce.insert(
            nonce,
            Issued {
                recipient,
                ts: now,
            },
        );
        (nonce, now)
    }

    /// Spend the nonce and return whether the recipient signed this echo.
    ///
    /// A matching nonce is one-time even when the signature is wrong.
    /// `ts` outside ±2 minutes does not spend a nonce and does not open the box.
    pub fn authorize(
        &mut self,
        recipient: &PeerId,
        ts: u64,
        nonce: &[u8; 32],
        sig: &[u8],
        now: u64,
    ) -> bool {
        self.sweep(now);
        if ts.abs_diff(now) > MAILBOX_QUERY_FRESHNESS_SECS {
            return false;
        }
        let Some(issued) = self.by_nonce.get(nonce) else {
            return false;
        };
        if issued.recipient != *recipient || issued.ts != ts {
            return false;
        }
        self.by_nonce.remove(nonce);
        verify_mailbox_query(recipient, ts, nonce, sig)
    }

    fn sweep(&mut self, now: u64) {
        self.by_nonce
            .retain(|_, issued| issued.ts.abs_diff(now) <= MAILBOX_QUERY_FRESHNESS_SECS);
    }
}

/// Take every letter only when [`ChallengeBook::authorize`] accepts the query.
pub fn take_if_authorized<T>(
    book: &mut ChallengeBook,
    mail: &mut Vec<T>,
    recipient: &PeerId,
    ts: u64,
    nonce: &[u8; 32],
    sig: &[u8],
    now: u64,
) -> Vec<T> {
    if book.authorize(recipient, ts, nonce, sig, now) {
        std::mem::take(mail)
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_bob() -> (Keypair, PeerId, Keypair, PeerId) {
        let alice = Keypair::generate_ed25519();
        let bob = Keypair::generate_ed25519();
        let alice_id = alice.public().to_peer_id();
        let bob_id = bob.public().to_peer_id();
        (alice, alice_id, bob, bob_id)
    }

    #[test]
    fn foreign_signature_leaves_mail() {
        let (alice, alice_id, bob, _) = alice_bob();
        let mut book = ChallengeBook::new();
        let now = 1_700_000_000u64;
        let (nonce, ts) = book.issue(alice_id, now);
        let msg = mailbox_query_message(&alice_id, ts, &nonce);
        let sig = bob.sign(&msg).expect("bob sign");
        assert!(sign_mailbox_query(&bob, &alice_id, ts, &nonce).is_none());
        let _ = alice;
        let mut mail = vec![b'a', b'b'];
        let got = take_if_authorized(&mut book, &mut mail, &alice_id, ts, &nonce, &sig, now);
        assert!(got.is_empty());
        assert_eq!(mail, vec![b'a', b'b']);
    }

    #[test]
    fn replayed_nonce_is_refused() {
        let (alice, alice_id, _, _) = alice_bob();
        let mut book = ChallengeBook::new();
        let now = 1_700_000_000u64;
        let (nonce, ts) = book.issue(alice_id, now);
        let sig = sign_mailbox_query(&alice, &alice_id, ts, &nonce).unwrap();
        let mut mail = vec![1u8];
        let got = take_if_authorized(&mut book, &mut mail, &alice_id, ts, &nonce, &sig, now);
        assert_eq!(got, vec![1]);
        assert!(mail.is_empty());
        mail.push(2);
        let again = take_if_authorized(&mut book, &mut mail, &alice_id, ts, &nonce, &sig, now);
        assert!(again.is_empty());
        assert_eq!(mail, vec![2]);
    }

    #[test]
    fn expired_ts_is_refused() {
        let (alice, alice_id, _, _) = alice_bob();
        let mut book = ChallengeBook::new();
        let now = 1_700_000_000u64;
        let (nonce, ts) = book.issue(alice_id, now);
        let sig = sign_mailbox_query(&alice, &alice_id, ts, &nonce).unwrap();
        let mut mail = vec![7u8];
        let later = now + MAILBOX_QUERY_FRESHNESS_SECS + 1;
        let got = take_if_authorized(&mut book, &mut mail, &alice_id, ts, &nonce, &sig, later);
        assert!(got.is_empty());
        assert_eq!(mail, vec![7]);
    }
}
