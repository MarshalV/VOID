//! Очередь: чужая подпись Query не выдаёт блоб.
//! Ячейка v2: повтор через OnionReplay не форвардится.

use std::time::Instant;

use libp2p::identity::Keypair;
use void_envelope::queue_mail::{
    create_message, query_message, write_proof, OwnedQueue, QueueDir, QUEUE_BUCKET,
};
use void_onion::{peel_v2, wrap_v2, OnionReplay, PeerId, V2Peel};
use x25519_dalek::{PublicKey, StaticSecret};

/// Как нода: nonce снимается до проверки подписи. Чужой ключ — пустая выдача, блоб на месте.
fn query_queue(
    dir: &mut QueueDir,
    queue_id: [u8; 32],
    ts: u64,
    nonce: &[u8; 32],
    sig: &[u8],
    now: u64,
) -> Vec<Vec<u8>> {
    if sig.is_empty() || ts.abs_diff(now) > 120 {
        return Vec::new();
    }
    let Some(owner_pk) = dir.owner_pk(&queue_id, now).map(|pk| pk.to_vec()) else {
        return Vec::new();
    };
    if !dir.take_challenge(&queue_id, nonce, now) {
        return Vec::new();
    }
    let Ok(pk) = libp2p::identity::PublicKey::try_decode_protobuf(&owner_pk) else {
        return Vec::new();
    };
    if !pk.verify(&query_message(&queue_id, ts, nonce), sig) {
        return Vec::new();
    }
    dir.take_batch(queue_id, 512 * 1024, now)
}

/// Повтор уже снятой ячейки не даёт следующий кадр. Первая удачная склейка запоминается.
fn forward_once(
    cache: &mut OnionReplay,
    sk: &StaticSecret,
    cell: &[u8],
    now: Instant,
) -> Option<Vec<u8>> {
    if cache.is_replay(cell, now) {
        return None;
    }
    match peel_v2(sk, cell).ok()? {
        V2Peel::Forward { cell: next, .. } => {
            cache.note(cell, now);
            Some(next)
        }
        V2Peel::Deliver { .. } => {
            cache.note(cell, now);
            None
        }
    }
}

#[test]
fn queue_query_without_owner_key_returns_empty() {
    let now = 1_700_000_000u64;
    let queue = OwnedQueue::create(now);
    let stranger = Keypair::generate_ed25519();
    let mut dir = QueueDir::new();
    let create_sig = queue
        .owner
        .sign(&create_message(
            &queue.queue_id,
            &queue.write_token,
            queue.expiry,
        ))
        .expect("create sig");
    assert!(dir.create(
        queue.queue_id,
        queue.owner.public().encode_protobuf(),
        queue.write_token,
        queue.expiry,
        &create_sig,
        now,
    ));
    let blob = vec![9u8; QUEUE_BUCKET as usize];
    let proof = write_proof(&queue.write_token, &queue.queue_id, &blob);
    assert!(dir
        .store(queue.queue_id, &proof, blob.clone(), now)
        .is_some());

    let (nonce, ts) = dir.challenge(queue.queue_id, now).expect("challenge");
    let msg = query_message(&queue.queue_id, ts, &nonce);
    let bad = stranger.sign(&msg).expect("stranger sig");
    assert!(query_queue(&mut dir, queue.queue_id, ts, &nonce, &bad, now).is_empty());

    let (nonce, ts) = dir.challenge(queue.queue_id, now).expect("second challenge");
    let good = queue
        .owner
        .sign(&query_message(&queue.queue_id, ts, &nonce))
        .expect("owner sig");
    assert_eq!(
        query_queue(&mut dir, queue.queue_id, ts, &nonce, &good, now),
        vec![blob]
    );
}

#[test]
fn replayed_v2_cell_is_not_forwarded() {
    let sk0 = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let sk1 = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let hops = [
        (void_onion::PeerId::random(), PublicKey::from(&sk0).to_bytes()),
        (PeerId::random(), PublicKey::from(&sk1).to_bytes()),
    ];
    let dest = PeerId::random();
    let cell = wrap_v2(&hops, dest, b"letter").expect("cell");
    let other = wrap_v2(&hops, dest, b"letter").expect("other cell");
    assert_ne!(cell, other);

    let mut cache = OnionReplay::new();
    let now = Instant::now();
    let forwarded = forward_once(&mut cache, &sk0, &cell, now).expect("first peel forwards");
    assert!(!forwarded.is_empty());
    assert!(forward_once(&mut cache, &sk0, &cell, now).is_none());
    assert!(forward_once(&mut cache, &sk0, &other, now).is_some());
}
