//! Два сеанса в одном процессе. Общие только байты кадров, не состояние ratchet.
//! Окно, Tauri и egui этот тест не поднимает.

use libp2p::identity::Keypair;
use libp2p::PeerId;
use rand::rngs::OsRng;
use void_protocol::crypto::{PublicKey, SecureSession, StaticSecret};
use void_protocol::protocol::{
    build_v1_hello, hello_bind_ok, verify_hello_transport_binding, HelloBind, V1Packet,
    HELLO_CAP_CBOR, HELLO_CAP_HEADER_AAD,
};
fn peer() -> (Keypair, PeerId) {
    let kp = Keypair::generate_ed25519();
    let id = PeerId::from_public_key(&kp.public());
    (kp, id)
}

fn secret() -> StaticSecret {
    StaticSecret::random_from_rng(OsRng)
}

fn accept_hello(packet: &V1Packet, signer: PeerId, recipient: PeerId) {
    let V1Packet::Hello {
        public_key,
        ephemeral_key,
        transport_sig,
        transport_pubkey_pb,
        caps,
        ts,
        nonce,
    } = packet
    else {
        panic!("hello");
    };
    let bind = verify_hello_transport_binding(
        signer,
        recipient,
        public_key,
        ephemeral_key,
        transport_sig,
        transport_pubkey_pb,
        *ts,
        nonce,
        *caps,
    );
    assert_eq!(bind, Some(HelloBind::V3));
    assert!(hello_bind_ok(bind.unwrap(), *caps, false));
    assert_eq!(*caps & HELLO_CAP_HEADER_AAD, HELLO_CAP_HEADER_AAD);
    assert_eq!(*caps & HELLO_CAP_CBOR, HELLO_CAP_CBOR);
}

#[test]
fn two_sessions_roundtrip_and_bad_header_does_not_advance() {
    let (alice_kp, alice_peer) = peer();
    let (bob_kp, bob_peer) = peer();
    let alice_static = secret();
    let bob_static = secret();
    let alice_eph = secret();
    let bob_eph = secret();
    let alice_static_pk = PublicKey::from(&alice_static);
    let bob_static_pk = PublicKey::from(&bob_static);
    let alice_eph_pk = PublicKey::from(&alice_eph);
    let bob_eph_pk = PublicKey::from(&bob_eph);

    let alice_hello = build_v1_hello(
        &alice_kp,
        alice_peer,
        bob_peer,
        alice_static_pk,
        alice_eph_pk,
    )
    .expect("alice hello");
    let bob_hello = build_v1_hello(&bob_kp, bob_peer, alice_peer, bob_static_pk, bob_eph_pk)
        .expect("bob hello");
    accept_hello(&alice_hello, alice_peer, bob_peer);
    accept_hello(&bob_hello, bob_peer, alice_peer);

    let mut alice =
        SecureSession::new_initiator(&alice_static, &bob_static_pk, alice_eph, &bob_eph_pk);
    let mut bob =
        SecureSession::new_responder(&bob_static, &alice_static_pk, &alice_eph_pk, bob_eph);
    alice.bind_peers(&alice_peer.to_bytes(), &bob_peer.to_bytes());
    bob.bind_peers(&bob_peer.to_bytes(), &alice_peer.to_bytes());
    alice.enable_header_aad();
    bob.enable_header_aad();

    let (header, ct) = alice.encrypt_payload(b"ping").unwrap();
    let mut bad = header.clone();
    bad.pn = bad.pn.wrapping_add(1);
    assert!(bob.decrypt_payload(&bad, &ct).is_err());
    assert_eq!(bob.decrypt_payload(&header, &ct).unwrap(), b"ping");

    let (header, ct) = bob.encrypt_payload(b"pong").unwrap();
    assert_eq!(alice.decrypt_payload(&header, &ct).unwrap(), b"pong");
}
