//! Ящик диспетчера: Query только по подписи владельца, TTL, квоты. Без ноды и без UI.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use protocol_conformance::mailbox::{MailboxNode, QueryOutcome, SignedMailboxQuery, StoreOutcome};
use void_protocol::offline_mail::{OfflineEnvelope, MAILBOX_TTL_SECS};
use void_protocol::protocol::{mailbox_query_message, sign_mailbox_query};

struct Who {
    kp: Keypair,
    pid: PeerId,
}

fn who() -> Who {
    let kp = Keypair::generate_ed25519();
    let pid = kp.public().to_peer_id();
    Who { kp, pid }
}

fn peer() -> PeerId {
    who().pid
}

fn fetch(node: &mut MailboxNode, owner: &Who) -> QueryOutcome {
    let key = owner.pid.to_string();
    let (nonce, ts) = node.challenge(&key).expect("challenge");
    let sig = sign_mailbox_query(&owner.kp, &owner.pid, ts, &nonce).expect("sign");
    node.query(&SignedMailboxQuery {
        recipient: key,
        ts,
        nonce,
        sig,
    })
}

fn env(id: &str, ct_len: usize) -> OfflineEnvelope {
    OfflineEnvelope {
        v: 3,
        sender: String::new(),
        sender_pk: [0u8; 32],
        message_id: id.into(),
        kind: String::new(),
        eph: [1u8; 32],
        nonce: [2u8; 12],
        ct: vec![3u8; ct_len],
        local_kind: String::new(),
    }
}

fn deliver_ids(outcome: QueryOutcome) -> Vec<String> {
    match outcome {
        QueryOutcome::Ack => Vec::new(),
        QueryOutcome::Deliver(v) => v.into_iter().map(|e| e.message_id).collect(),
    }
}

#[test]
fn query_only_owner_and_batch_is_deleted() {
    let mut node = MailboxNode::new();
    node.set_now(1_700_000_000);
    let owner = who();
    let stranger = who();
    let uploader = peer();
    let key = owner.pid.to_string();
    assert_eq!(
        node.store(uploader, &key, &[env("a", 8), env("b", 8)]),
        StoreOutcome::Ack
    );
    let (nonce, ts) = node.challenge(&key).unwrap();
    let msg = mailbox_query_message(&owner.pid, ts, &nonce);
    let sig = stranger.kp.sign(&msg).unwrap();
    assert!(matches!(
        node.query(&SignedMailboxQuery {
            recipient: key.clone(),
            ts,
            nonce,
            sig,
        }),
        QueryOutcome::Ack
    ));
    assert_eq!(node.stored(&key), 2);
    assert_eq!(deliver_ids(fetch(&mut node, &owner)), vec!["a", "b"]);
    assert_eq!(node.stored(&key), 0);
    assert!(matches!(fetch(&mut node, &owner), QueryOutcome::Ack));
}

#[test]
fn duplicate_id_is_kept_once() {
    let mut node = MailboxNode::new();
    let owner = peer();
    let uploader = peer();
    let key = owner.to_string();
    assert_eq!(
        node.store(uploader, &key, &[env("same", 4), env("same", 4)]),
        StoreOutcome::Ack
    );
    assert_eq!(node.stored(&key), 1);
}

#[test]
fn old_version_and_bad_recipient_are_refused() {
    let mut node = MailboxNode::new();
    let owner = peer();
    let uploader = peer();
    let mut old = env("x", 4);
    old.v = 1;
    assert_eq!(
        node.store(uploader, &owner.to_string(), &[old]),
        StoreOutcome::Refused
    );
    assert_eq!(node.stored(&owner.to_string()), 0);
    assert_eq!(
        node.store(uploader, "not-a-peer", &[env("y", 4)]),
        StoreOutcome::Refused
    );
    assert_eq!(
        node.store(uploader, &owner.to_string(), &[]),
        StoreOutcome::Ack
    );
}

#[test]
fn v3_is_kept_when_mixed_with_rejected() {
    let mut node = MailboxNode::new();
    let owner = who();
    let uploader = peer();
    let mut old = env("old", 4);
    old.v = 2;
    old.sender = owner.pid.to_string();
    assert_eq!(
        node.store(uploader, &owner.pid.to_string(), &[old, env("new", 4)]),
        StoreOutcome::Ack
    );
    assert_eq!(
        deliver_ids(fetch(&mut node, &owner)),
        vec!["new"]
    );
}

#[test]
fn ttl_drops_mail_before_query() {
    let mut node = MailboxNode::new();
    let t0 = 1_700_000_000u64;
    node.set_now(t0);
    let owner = who();
    let uploader = peer();
    let key = owner.pid.to_string();
    assert_eq!(
        node.store(uploader, &key, &[env("live", 4)]),
        StoreOutcome::Ack
    );
    node.set_now(t0 + MAILBOX_TTL_SECS - 1);
    assert_eq!(node.stored(&key), 1);
    node.set_now(t0 + MAILBOX_TTL_SECS);
    assert_eq!(node.stored(&key), 0);
    assert!(matches!(fetch(&mut node, &owner), QueryOutcome::Ack));
}

#[test]
fn uploader_quota_then_frees_after_delivery() {
    let mut node = MailboxNode::new();
    let owner = who();
    let uploader = peer();
    let key = owner.pid.to_string();
    let batch: Vec<_> = (0..256).map(|i| env(&format!("m{i}"), 4)).collect();
    assert_eq!(node.store(uploader, &key, &batch), StoreOutcome::Ack);
    assert_eq!(
        node.store(uploader, &key, &[env("overflow", 4)]),
        StoreOutcome::Refused
    );
    assert_eq!(node.stored(&key), 256);
    let _ = fetch(&mut node, &owner);
    assert_eq!(node.stored(&key), 0);
    assert_eq!(
        node.store(uploader, &key, &[env("again", 4)]),
        StoreOutcome::Ack
    );
}

#[test]
fn rate_window_blocks_then_resets() {
    let mut node = MailboxNode::new();
    node.set_now(1_000);
    let owner = peer();
    let other = peer();
    let uploader = peer();
    let batch: Vec<_> = (0..600).map(|i| env(&format!("r{i}"), 1)).collect();
    assert_eq!(
        node.store(uploader, &owner.to_string(), &batch),
        StoreOutcome::Ack
    );
    assert_eq!(
        node.store(uploader, &other.to_string(), &[env("late", 1)]),
        StoreOutcome::Refused
    );
    node.set_now(1_000 + 60);
    assert_eq!(
        node.store(uploader, &other.to_string(), &[env("late", 1)]),
        StoreOutcome::Ack
    );
}

#[test]
fn deliver_batch_stops_before_512kib() {
    let mut node = MailboxNode::new();
    let owner = who();
    let uploader = peer();
    let key = owner.pid.to_string();
    let ct = 64 * 1024;
    let batch: Vec<_> = (0..8).map(|i| env(&format!("c{i}"), ct)).collect();
    assert_eq!(node.store(uploader, &key, &batch), StoreOutcome::Ack);
    let first = deliver_ids(fetch(&mut node, &owner));
    let second = deliver_ids(fetch(&mut node, &owner));
    assert_eq!(first.len(), 7);
    assert_eq!(second, vec!["c7"]);
}

#[test]
fn mailbox_ceiling_is_4096() {
    let mut node = MailboxNode::new();
    let mut uploader = peer();
    let mut owners = Vec::with_capacity(4096);
    for i in 0..4096 {
        if i > 0 && i % 600 == 0 {
            uploader = peer();
        }
        let owner = who();
        assert_eq!(
            node.store(uploader, &owner.pid.to_string(), &[env(&format!("b{i}"), 1)]),
            StoreOutcome::Ack,
            "mailbox {i}"
        );
        owners.push(owner);
    }
    assert_eq!(node.mailboxes(), 4096);
    let extra = peer();
    assert_eq!(
        node.store(uploader, &extra.to_string(), &[env("nope", 1)]),
        StoreOutcome::Refused
    );
    assert_eq!(node.mailboxes(), 4096);
    let _ = fetch(&mut node, &owners[0]);
    assert_eq!(
        node.store(uploader, &extra.to_string(), &[env("nope", 1)]),
        StoreOutcome::Ack
    );
}

#[test]
fn head_drops_when_mailbox_exceeds_1024() {
    let mut node = MailboxNode::new();
    let owner = who();
    let key = owner.pid.to_string();
    for u in 0..4 {
        let uploader = peer();
        let batch: Vec<_> = (0..256).map(|i| env(&format!("u{u}-{i}"), 1)).collect();
        assert_eq!(node.store(uploader, &key, &batch), StoreOutcome::Ack);
    }
    assert_eq!(node.stored(&key), 1024);
    let fifth = peer();
    assert_eq!(
        node.store(fifth, &key, &[env("newest", 1)]),
        StoreOutcome::Ack
    );
    assert_eq!(node.stored(&key), 1024);
    let got = deliver_ids(fetch(&mut node, &owner));
    assert!(!got.iter().any(|id| id == "u0-0"));
    assert_eq!(got.last().map(String::as_str), Some("newest"));
}

#[test]
fn replayed_nonce_does_not_take_refilled_mail() {
    let mut node = MailboxNode::new();
    node.set_now(1_700_000_000);
    let owner = who();
    let key = owner.pid.to_string();
    assert_eq!(
        node.store(peer(), &key, &[env("a", 4)]),
        StoreOutcome::Ack
    );
    let (nonce, ts) = node.challenge(&key).unwrap();
    let sig = sign_mailbox_query(&owner.kp, &owner.pid, ts, &nonce).unwrap();
    let q = SignedMailboxQuery {
        recipient: key.clone(),
        ts,
        nonce,
        sig,
    };
    assert_eq!(deliver_ids(node.query(&q)), vec!["a"]);
    assert_eq!(
        node.store(peer(), &key, &[env("b", 4)]),
        StoreOutcome::Ack
    );
    assert!(matches!(node.query(&q), QueryOutcome::Ack));
    assert_eq!(node.stored(&key), 1);
}

#[test]
fn expired_challenge_leaves_mail() {
    let mut node = MailboxNode::new();
    let t0 = 1_700_000_000u64;
    node.set_now(t0);
    let owner = who();
    let key = owner.pid.to_string();
    assert_eq!(
        node.store(peer(), &key, &[env("a", 4)]),
        StoreOutcome::Ack
    );
    let (nonce, ts) = node.challenge(&key).unwrap();
    let sig = sign_mailbox_query(&owner.kp, &owner.pid, ts, &nonce).unwrap();
    node.set_now(t0 + 121);
    assert!(matches!(
        node.query(&SignedMailboxQuery {
            recipient: key.clone(),
            ts,
            nonce,
            sig,
        }),
        QueryOutcome::Ack
    ));
    assert_eq!(node.stored(&key), 1);
}
