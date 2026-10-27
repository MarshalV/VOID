//! Ящик диспетчера: Query только владельцу, TTL, квоты. Без ноды и без UI.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use protocol_conformance::mailbox::{MailboxNode, QueryOutcome, StoreOutcome};
use void_protocol::offline_mail::{OfflineEnvelope, MAILBOX_TTL_SECS};

fn peer() -> PeerId {
    let kp = Keypair::generate_ed25519();
    PeerId::from_public_key(&kp.public())
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
    let owner = peer();
    let stranger = peer();
    let uploader = peer();
    let key = owner.to_string();
    assert_eq!(
        node.store(uploader, &key, &[env("a", 8), env("b", 8)]),
        StoreOutcome::Ack
    );
    assert!(matches!(node.query(stranger, &key), QueryOutcome::Ack));
    assert_eq!(node.stored(&key), 2);
    assert_eq!(deliver_ids(node.query(owner, &key)), vec!["a", "b"]);
    assert_eq!(node.stored(&key), 0);
    assert!(matches!(node.query(owner, &key), QueryOutcome::Ack));
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
    let owner = peer();
    let uploader = peer();
    let mut old = env("old", 4);
    old.v = 2;
    old.sender = owner.to_string();
    assert_eq!(
        node.store(uploader, &owner.to_string(), &[old, env("new", 4)]),
        StoreOutcome::Ack
    );
    assert_eq!(
        deliver_ids(node.query(owner, &owner.to_string())),
        vec!["new"]
    );
}

#[test]
fn ttl_drops_mail_before_query() {
    let mut node = MailboxNode::new();
    let t0 = 1_700_000_000u64;
    node.set_now(t0);
    let owner = peer();
    let uploader = peer();
    let key = owner.to_string();
    assert_eq!(
        node.store(uploader, &key, &[env("live", 4)]),
        StoreOutcome::Ack
    );
    node.set_now(t0 + MAILBOX_TTL_SECS - 1);
    assert_eq!(node.stored(&key), 1);
    node.set_now(t0 + MAILBOX_TTL_SECS);
    assert_eq!(node.stored(&key), 0);
    assert!(matches!(node.query(owner, &key), QueryOutcome::Ack));
}

#[test]
fn uploader_quota_then_frees_after_delivery() {
    let mut node = MailboxNode::new();
    let owner = peer();
    let uploader = peer();
    let key = owner.to_string();
    let batch: Vec<_> = (0..256).map(|i| env(&format!("m{i}"), 4)).collect();
    assert_eq!(node.store(uploader, &key, &batch), StoreOutcome::Ack);
    assert_eq!(
        node.store(uploader, &key, &[env("overflow", 4)]),
        StoreOutcome::Refused
    );
    assert_eq!(node.stored(&key), 256);
    let _ = node.query(owner, &key);
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
    let owner = peer();
    let uploader = peer();
    let key = owner.to_string();
    let ct = 64 * 1024;
    let batch: Vec<_> = (0..8).map(|i| env(&format!("c{i}"), ct)).collect();
    assert_eq!(node.store(uploader, &key, &batch), StoreOutcome::Ack);
    let first = deliver_ids(node.query(owner, &key));
    let second = deliver_ids(node.query(owner, &key));
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
        let owner = peer();
        assert_eq!(
            node.store(uploader, &owner.to_string(), &[env(&format!("b{i}"), 1)]),
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
    let _ = node.query(owners[0], &owners[0].to_string());
    assert_eq!(
        node.store(uploader, &extra.to_string(), &[env("nope", 1)]),
        StoreOutcome::Ack
    );
}

#[test]
fn head_drops_when_mailbox_exceeds_1024() {
    let mut node = MailboxNode::new();
    let owner = peer();
    let key = owner.to_string();
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
    let got = deliver_ids(node.query(owner, &key));
    assert!(!got.iter().any(|id| id == "u0-0"));
    assert_eq!(got.last().map(String::as_str), Some("newest"));
}
