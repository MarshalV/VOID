//! Каталог `spec/vectors/`. Обычный `cargo test` сверяет JSON.
//! `UPDATE_VECTORS=1` перезаписывает файлы текущим выводом.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

use libp2p::identity::Keypair;
use libp2p::PeerId;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{MessageHeader, SecureSession};
use crate::offline_mail::{
    encode_signed_prekey, identity_offline_public, identity_offline_secret, open_envelope,
    prekey_is_sealable, seal_for_recipient_fixed, verify_signed_prekey,
};
use crate::onion::{deliver_bytes, open_deliver, peel_v2, seal_deliver_rng, wrap_v2_rng, V2Peel};
use crate::protocol::{
    hello_bind_ok, sign_hello_transport_binding, verify_hello_transport_binding_at, HelloBind,
    HELLO_CAP_HEADER_AAD,
};

fn dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/vectors"))
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0xf) as usize] as char);
    }
    out
}

fn seed32(tag: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = tag.wrapping_mul(17).wrapping_add(i as u8);
    }
    s
}

fn keypair(tag: u8) -> Keypair {
    Keypair::ed25519_from_bytes(seed32(tag)).expect("ed25519 seed")
}

fn static_secret(tag: u8) -> StaticSecret {
    StaticSecret::from(seed32(tag))
}

fn check(name: &str, value: Value) {
    let path = dir().join(format!("{name}.json"));
    if std::env::var("UPDATE_VECTORS").ok().as_deref() == Some("1") {
        std::fs::create_dir_all(dir()).expect("spec/vectors");
        let text = serde_json::to_string_pretty(&value).expect("json") + "\n";
        std::fs::write(&path, text).expect("write vector");
        return;
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "нет {}. Сгенерируйте: $env:UPDATE_VECTORS='1'; cargo test -p void-protocol --lib vectors",
            path.display()
        )
    });
    let got: Value =
        serde_json::from_str(&existing).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(got, value, "{name}");
}

fn peer_of(kp: &Keypair) -> PeerId {
    PeerId::from_public_key(&kp.public())
}

#[test]
fn hello_v3_ok() {
    let signer = keypair(1);
    let recipient = keypair(2);
    let signer_peer = peer_of(&signer);
    let recipient_peer = peer_of(&recipient);
    let static_pk = PublicKey::from(&static_secret(3)).to_bytes();
    let eph = PublicKey::from(&static_secret(4)).to_bytes();
    let ts = 1_700_000_000u64;
    let nonce = [0x11u8; 16];
    let caps = HELLO_CAP_HEADER_AAD;
    let sig = sign_hello_transport_binding(
        &signer,
        signer_peer,
        recipient_peer,
        &static_pk,
        &eph,
        ts,
        &nonce,
        caps,
    )
    .expect("sign");
    let bind = verify_hello_transport_binding_at(
        signer_peer,
        recipient_peer,
        &static_pk,
        &eph,
        &sig,
        &[],
        ts,
        &nonce,
        caps,
        ts,
    );
    assert_eq!(bind, Some(HelloBind::V3));
    assert!(hello_bind_ok(bind.unwrap(), caps, false));
    check(
        "hello_v3_ok",
        json!({
            "signer_seed": hex(&seed32(1)),
            "recipient_seed": hex(&seed32(2)),
            "signer_peer_id": signer_peer.to_string(),
            "recipient_peer_id": recipient_peer.to_string(),
            "x25519_static": hex(&static_pk),
            "x25519_ephemeral": hex(&eph),
            "ts": ts,
            "nonce": hex(&nonce),
            "caps": caps,
            "transport_pubkey_pb": "",
            "now": ts,
            "signature": hex(&sig),
            "bind": "V3",
            "accepted": true
        }),
    );
}

#[test]
fn hello_v3_stale_ts() {
    let signer = keypair(1);
    let recipient = keypair(2);
    let signer_peer = peer_of(&signer);
    let recipient_peer = peer_of(&recipient);
    let static_pk = PublicKey::from(&static_secret(3)).to_bytes();
    let eph = PublicKey::from(&static_secret(4)).to_bytes();
    let now = 1_700_000_000u64;
    let ts = now - 601;
    let nonce = [0x11u8; 16];
    let caps = HELLO_CAP_HEADER_AAD;
    let sig = sign_hello_transport_binding(
        &signer,
        signer_peer,
        recipient_peer,
        &static_pk,
        &eph,
        ts,
        &nonce,
        caps,
    )
    .expect("sign");
    let bind = verify_hello_transport_binding_at(
        signer_peer,
        recipient_peer,
        &static_pk,
        &eph,
        &sig,
        &[],
        ts,
        &nonce,
        caps,
        now,
    );
    assert!(bind.is_none());
    check(
        "hello_v3_stale_ts",
        json!({
            "signer_seed": hex(&seed32(1)),
            "recipient_seed": hex(&seed32(2)),
            "signer_peer_id": signer_peer.to_string(),
            "recipient_peer_id": recipient_peer.to_string(),
            "x25519_static": hex(&static_pk),
            "x25519_ephemeral": hex(&eph),
            "ts": ts,
            "nonce": hex(&nonce),
            "caps": caps,
            "transport_pubkey_pb": "",
            "now": now,
            "freshness_window_secs": 600,
            "signature": hex(&sig),
            "accepted": false
        }),
    );
}

/// Кэш приёма эфемера: на одного подписавшего последние 256 ключей.
/// Потолок 4096 подписавших в клиенте сюда не входит — вытеснение пиров зависит от HashMap.
fn replay_accept(
    cache: &mut HashMap<String, VecDeque<[u8; 32]>>,
    peer: &str,
    eph: [u8; 32],
) -> bool {
    let q = cache.entry(peer.to_string()).or_default();
    if q.iter().any(|k| *k == eph) {
        return false;
    }
    if q.len() == 256 {
        q.pop_front();
    }
    q.push_back(eph);
    true
}

fn eph_n(n: u16) -> [u8; 32] {
    let mut e = [0xE1u8; 32];
    e[..2].copy_from_slice(&n.to_le_bytes());
    e
}

#[test]
fn hello_replay_eph() {
    let mut cache = HashMap::new();
    let mut steps = Vec::new();
    let script = [
        ("A", 1u16, true),
        ("A", 1, false),
        ("A", 2, true),
        ("B", 1, true),
    ];
    for (peer, n, expect) in script {
        let got = replay_accept(&mut cache, peer, eph_n(n));
        assert_eq!(got, expect);
        steps.push(json!({
            "peer": peer,
            "ephemeral": hex(&eph_n(n)),
            "accept": got
        }));
    }

    let mut window = HashMap::new();
    for n in 0..256u16 {
        assert!(replay_accept(&mut window, "A", eph_n(n)));
    }
    assert!(!replay_accept(&mut window, "A", eph_n(0)));
    assert!(replay_accept(&mut window, "A", eph_n(256)));
    assert!(replay_accept(&mut window, "A", eph_n(0)));

    check(
        "hello_replay_eph",
        json!({
            "rule": "На одного PeerId хранятся последние 256 эфемерных ключей. Повтор — отказ, сессия не сбрасывается. Чужой PeerId тот же ключ принимает. Потолок числа PeerId — локальный кэш клиента, в вектор не входит.",
            "steps": steps,
            "window": {
                "fill_distinct": 256,
                "repeat_oldest_while_full": false,
                "after_one_new_key_oldest_again": true
            }
        }),
    );
}

fn session_pair() -> (SecureSession, SecureSession, PeerId, PeerId) {
    let alice_kp = keypair(10);
    let bob_kp = keypair(11);
    let alice_peer = peer_of(&alice_kp);
    let bob_peer = peer_of(&bob_kp);
    let alice_static = static_secret(20);
    let bob_static = static_secret(21);
    let alice_eph = static_secret(22);
    let bob_eph = static_secret(23);
    let mut alice = SecureSession::new_initiator_seeded(
        &alice_static,
        &PublicKey::from(&bob_static),
        alice_eph,
        &PublicKey::from(&static_secret(23)),
        seed32(30),
    );
    let mut bob = SecureSession::new_responder_seeded(
        &bob_static,
        &PublicKey::from(&alice_static),
        &PublicKey::from(&static_secret(22)),
        bob_eph,
        seed32(31),
    );
    alice.bind_peers(&alice_peer.to_bytes(), &bob_peer.to_bytes());
    bob.bind_peers(&bob_peer.to_bytes(), &alice_peer.to_bytes());
    alice.enable_header_aad();
    bob.enable_header_aad();
    (alice, bob, alice_peer, bob_peer)
}

fn frame_json(from: &str, plain: &str, header: &MessageHeader, ct: &[u8]) -> Value {
    json!({
        "from": from,
        "plaintext": plain,
        "dh_pub": hex(&header.dh_pub),
        "pn": header.pn,
        "n": header.n,
        "ct": hex(ct)
    })
}

#[test]
fn ratchet_dh_step() {
    let (mut alice, mut bob, alice_peer, bob_peer) = session_pair();
    let mut messages = Vec::new();
    let mut alice_dh = Vec::new();
    let mut bob_dh = Vec::new();
    for i in 0..4 {
        let plain = format!("a{i}");
        let (h, ct) = alice.encrypt_payload(plain.as_bytes()).unwrap();
        alice_dh.push(h.dh_pub);
        let opened = bob.decrypt_payload(&h, &ct).unwrap();
        assert_eq!(opened, plain.as_bytes());
        messages.push(frame_json("alice", &plain, &h, &ct));

        let plain = format!("b{i}");
        let (h, ct) = bob.encrypt_payload(plain.as_bytes()).unwrap();
        bob_dh.push(h.dh_pub);
        let opened = alice.decrypt_payload(&h, &ct).unwrap();
        assert_eq!(opened, plain.as_bytes());
        messages.push(frame_json("bob", &plain, &h, &ct));
    }
    assert!(alice_dh.windows(2).all(|w| w[0] != w[1]));
    assert!(bob_dh.windows(2).all(|w| w[0] != w[1]));
    check(
        "ratchet_dh_step",
        json!({
            "alice_peer_id": alice_peer.to_string(),
            "bob_peer_id": bob_peer.to_string(),
            "alice_static_sk": hex(&static_secret(20).to_bytes()),
            "bob_static_sk": hex(&static_secret(21).to_bytes()),
            "alice_ephemeral_sk": hex(&static_secret(22).to_bytes()),
            "bob_ephemeral_sk": hex(&static_secret(23).to_bytes()),
            "alice_ratchet_seed": hex(&seed32(30)),
            "bob_ratchet_seed": hex(&seed32(31)),
            "header_aad": true,
            "round_trips": 4,
            "dh_pub_changes_each_turn": true,
            "messages": messages
        }),
    );
}

#[test]
fn ratchet_bad_aad() {
    let (mut alice, mut bob, _, _) = session_pair();
    let (header, ct) = alice.encrypt_payload(b"keep").unwrap();
    let mut bad = header.clone();
    bad.pn = bad.pn.wrapping_add(1);
    assert!(bob.decrypt_payload(&bad, &ct).is_err());
    let opened = bob.decrypt_payload(&header, &ct).unwrap();
    assert_eq!(opened, b"keep");
    let (h2, ct2) = bob.encrypt_payload(b"next").unwrap();
    let opened2 = alice.decrypt_payload(&h2, &ct2).unwrap();
    assert_eq!(opened2, b"next");
    check(
        "ratchet_bad_aad",
        json!({
            "alice_ratchet_seed": hex(&seed32(30)),
            "bob_ratchet_seed": hex(&seed32(31)),
            "frame": frame_json("alice", "keep", &header, &ct),
            "tampered_pn": bad.pn,
            "tampered_decrypt": false,
            "original_decrypt": "keep",
            "following": frame_json("bob", "next", &h2, &ct2)
        }),
    );
}

fn envelope_fixture() -> (
    crate::offline_mail::OfflineEnvelope,
    PeerId,
    PeerId,
    StaticSecret,
) {
    let sender_kp = keypair(40);
    let recipient_kp = keypair(41);
    let sender = peer_of(&sender_kp);
    let recipient = peer_of(&recipient_kp);
    let recipient_pk = identity_offline_public(&recipient).expect("identity pk");
    let sender_pk = identity_offline_public(&sender)
        .expect("identity pk")
        .to_bytes();
    let eph = static_secret(42);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&seed32(43)[..12]);
    let env = seal_for_recipient_fixed(
        &sender_kp,
        &recipient,
        &recipient_pk,
        &sender,
        &sender_pk,
        "m-vector",
        "dm",
        b"hello offline",
        eph,
        nonce,
    )
    .unwrap();
    let sk = identity_offline_secret(&recipient_kp).unwrap();
    (env, sender, recipient, sk)
}

fn envelope_json(env: &crate::offline_mail::OfflineEnvelope) -> Value {
    json!({
        "v": env.v,
        "sender": env.sender,
        "sender_pk": hex(&env.sender_pk),
        "message_id": env.message_id,
        "kind": env.kind,
        "eph": hex(&env.eph),
        "nonce": hex(&env.nonce),
        "ct": hex(&env.ct)
    })
}

#[test]
fn envelope_v3_roundtrip() {
    let (env, sender, recipient, sk) = envelope_fixture();
    let opened = open_envelope(&[&sk], &recipient, &env).unwrap();
    assert_eq!(opened.sender, sender);
    assert_eq!(opened.body, b"hello offline");
    assert_eq!(opened.kind, "dm");
    assert_eq!(opened.message_id, "m-vector");
    check(
        "envelope_v3_roundtrip",
        json!({
            "sender_seed": hex(&seed32(40)),
            "recipient_seed": hex(&seed32(41)),
            "eph_sk": hex(&static_secret(42).to_bytes()),
            "nonce": hex(&env.nonce),
            "plaintext": "hello offline",
            "inner_message_id": "m-vector",
            "inner_kind": "dm",
            "envelope": envelope_json(&env),
            "opened_sender": opened.sender.to_string(),
            "opened_message_id": opened.message_id,
            "opened_kind": opened.kind,
            "opened_body": hex(&opened.body)
        }),
    );
}

#[test]
fn envelope_v2_reject() {
    let (env, _, recipient, sk) = envelope_fixture();
    let mut as_v1 = env.clone();
    as_v1.v = 1;
    let mut as_v2 = env.clone();
    as_v2.v = 2;
    assert!(open_envelope(&[&sk], &recipient, &as_v1).is_err());
    assert!(open_envelope(&[&sk], &recipient, &as_v2).is_err());
    assert!(open_envelope(&[&sk], &recipient, &env).is_ok());
    check(
        "envelope_v2_reject",
        json!({
            "note": "Отказ для v=1 и для конверта v3, у которого поле v переписано в 2. Отдельно собранный подписанный конверт v2 этот вектор не запрещает.",
            "v1": { "envelope": envelope_json(&as_v1), "open": false },
            "relabel_v3_as_v2": { "envelope": envelope_json(&as_v2), "open": false }
        }),
    );
}

#[test]
fn prekey_expired() {
    let owner_kp = keypair(50);
    let owner = peer_of(&owner_kp);
    let pk = PublicKey::from(&static_secret(51)).to_bytes();
    let now = 1_700_000_000u64;
    let not_after = now - 1;
    let published = encode_signed_prekey(&owner_kp, &owner, &pk, not_after).unwrap();
    let verified = verify_signed_prekey(&owner, &published.dht_value).unwrap();
    assert!(!prekey_is_sealable(verified, now));
    check(
        "prekey_expired",
        json!({
            "owner_seed": hex(&seed32(50)),
            "owner_peer_id": owner.to_string(),
            "pk": hex(&pk),
            "now": now,
            "not_after": not_after,
            "dht_value": hex(&published.dht_value),
            "verify_ok": true,
            "sealable": false
        }),
    );
}

struct Hop {
    peer: PeerId,
    sk: StaticSecret,
}

fn hop(tag: u8) -> Hop {
    Hop {
        peer: peer_of(&keypair(tag)),
        sk: static_secret(tag.wrapping_add(100)),
    }
}

fn onion_case(name: &str, n: usize) {
    let hops: Vec<Hop> = (0..n).map(|i| hop(60 + i as u8)).collect();
    let dest_kp = keypair(70);
    let dest = peer_of(&dest_kp);
    let dest_sk = identity_offline_secret(&dest_kp).unwrap();
    let payload = b"vector-body";
    let mut rng = StdRng::from_seed(seed32(80 + n as u8));
    let sealed = seal_deliver_rng(&mut rng, &dest, payload).unwrap();
    let hop_list: Vec<(PeerId, [u8; 32])> = hops
        .iter()
        .map(|h| (h.peer, PublicKey::from(&h.sk).to_bytes()))
        .collect();
    let cell = wrap_v2_rng(&mut rng, &hop_list, dest, &sealed).unwrap();

    let mut peels = Vec::new();
    let mut cur = cell.clone();
    for (i, h) in hops.iter().enumerate() {
        match peel_v2(&h.sk, &cur).unwrap() {
            V2Peel::Forward {
                next,
                cell: next_cell,
            } => {
                assert!(i + 1 < hops.len());
                assert_eq!(next, hops[i + 1].peer);
                peels.push(json!({ "kind": "forward", "next": next.to_string() }));
                cur = next_cell;
            }
            V2Peel::Deliver { next, body } => {
                assert_eq!(i + 1, hops.len());
                assert_eq!(next, dest);
                let sealed = deliver_bytes(&body).expect("deliver length");
                let plain = open_deliver(&dest_sk, sealed).unwrap();
                assert_eq!(plain, payload);
                peels.push(json!({
                    "kind": "deliver",
                    "next": next.to_string(),
                    "body": hex(&body),
                    "plaintext": hex(&plain)
                }));
            }
        }
    }
    check(
        name,
        json!({
            "hops": hops.iter().map(|h| json!({
                "peer_id": h.peer.to_string(),
                "x25519_sk": hex(&h.sk.to_bytes()),
                "x25519_pk": hex(&PublicKey::from(&h.sk).to_bytes())
            })).collect::<Vec<_>>(),
            "dest_peer_id": dest.to_string(),
            "dest_seed": hex(&seed32(70)),
            "dest_identity_sk": hex(&dest_sk.to_bytes()),
            "payload": hex(payload),
            "rng_seed": hex(&seed32(80 + n as u8)),
            "cell": hex(&cell),
            "peels": peels
        }),
    );
}

#[test]
fn onion_v2_hops() {
    onion_case("onion_v2_1hop", 1);
    onion_case("onion_v2_2hop", 2);
    onion_case("onion_v2_3hop", 3);
}

#[test]
fn onion_v2_wrong_sk() {
    let hop_a = hop(60);
    let hop_b = hop(61);
    let dest_kp = keypair(70);
    let dest = peer_of(&dest_kp);
    let mut rng = StdRng::from_seed(seed32(81));
    let sealed = seal_deliver_rng(&mut rng, &dest, b"vector-body").unwrap();
    let cell = wrap_v2_rng(
        &mut rng,
        &[(hop_a.peer, PublicKey::from(&hop_a.sk).to_bytes())],
        dest,
        &sealed,
    )
    .unwrap();
    assert!(peel_v2(&hop_b.sk, &cell).is_err());
    check(
        "onion_v2_wrong_sk",
        json!({
            "hop_peer_id": hop_a.peer.to_string(),
            "hop_sk": hex(&hop_a.sk.to_bytes()),
            "foreign_sk": hex(&hop_b.sk.to_bytes()),
            "dest_peer_id": dest.to_string(),
            "cell": hex(&cell),
            "open": false
        }),
    );
}
