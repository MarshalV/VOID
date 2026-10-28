//! Hello bind: transport signature, freshness, caps.
//!
//! `PeerId` is `libp2p_identity::PeerId`, the same type as `libp2p::PeerId`.
//! The signature is still the identity key. This crate does not enable libp2p `kad`.

use libp2p_identity::PeerId;

const VOID_HELLO_BIND_PREFIX: &[u8] = b"VOID_E2EE_HELLO_BIND_V1\0";
const VOID_HELLO_BIND_PREFIX_V2: &[u8] = b"VOID_E2EE_HELLO_BIND_V2\0";
const VOID_HELLO_BIND_PREFIX_V3: &[u8] = b"VOID_E2EE_HELLO_BIND_V3\0";
pub const HELLO_FRESHNESS_SECS: u64 = 10 * 60;

/// Какая подпись Hello сошлась. `V3` вяжет `caps` — hop не может вырезать флаг.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloBind {
    V1,
    V2,
    V3,
}

const MAX_HELLO_TRANSPORT_PUBKEY_PB: usize = 4096;

/// Inline multihash PeerId (Ed25519): извлечь транспортный `PublicKey` для проверки подписи Hello.
pub fn void_peer_transport_public_key(peer: PeerId) -> Option<libp2p_identity::PublicKey> {
    const CODE_IDENTITY: u64 = 0;
    let mh = peer.as_ref();
    if mh.code() != CODE_IDENTITY {
        return None;
    }
    libp2p_identity::PublicKey::try_decode_protobuf(mh.digest()).ok()
}

/// Ключ для проверки `transport_sig`: из identity-multihash или из protobuf в Hello (hashed PeerId).
pub fn void_hello_signing_public_key(
    signer_peer_id: PeerId,
    transport_pubkey_pb: &[u8],
) -> Option<libp2p_identity::PublicKey> {
    if !transport_pubkey_pb.is_empty() {
        if transport_pubkey_pb.len() > MAX_HELLO_TRANSPORT_PUBKEY_PB {
            return None;
        }
        let pk = libp2p_identity::PublicKey::try_decode_protobuf(transport_pubkey_pb).ok()?;
        if PeerId::from_public_key(&pk) != signer_peer_id {
            return None;
        }
        return Some(pk);
    }
    void_peer_transport_public_key(signer_peer_id)
}

fn hello_bind_message_v1(
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(96 + VOID_HELLO_BIND_PREFIX.len());
    v.extend_from_slice(VOID_HELLO_BIND_PREFIX);
    v.extend_from_slice(&signer_peer.to_bytes());
    v.extend_from_slice(&recipient_peer.to_bytes());
    v.extend_from_slice(x25519_static.as_slice());
    v.extend_from_slice(x25519_ephemeral.as_slice());
    v
}

fn hello_bind_message_v2(
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    ts: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(96 + VOID_HELLO_BIND_PREFIX_V2.len() + 24);
    v.extend_from_slice(VOID_HELLO_BIND_PREFIX_V2);
    v.extend_from_slice(&signer_peer.to_bytes());
    v.extend_from_slice(&recipient_peer.to_bytes());
    v.extend_from_slice(x25519_static.as_slice());
    v.extend_from_slice(x25519_ephemeral.as_slice());
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(nonce);
    v
}

fn hello_bind_message_v3(
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    ts: u64,
    nonce: &[u8; 16],
    caps: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(96 + VOID_HELLO_BIND_PREFIX_V3.len() + 28);
    v.extend_from_slice(VOID_HELLO_BIND_PREFIX_V3);
    v.extend_from_slice(&signer_peer.to_bytes());
    v.extend_from_slice(&recipient_peer.to_bytes());
    v.extend_from_slice(x25519_static.as_slice());
    v.extend_from_slice(x25519_ephemeral.as_slice());
    v.extend_from_slice(&ts.to_le_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(&caps.to_le_bytes());
    v
}

pub fn hello_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn verify_hello_transport_binding(
    signer_peer_id: PeerId,
    recipient_peer_id: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    transport_sig: &[u8],
    transport_pubkey_pb: &[u8],
    ts: u64,
    nonce: &[u8; 16],
    caps: u32,
) -> Option<HelloBind> {
    verify_hello_transport_binding_at(
        signer_peer_id,
        recipient_peer_id,
        x25519_static,
        x25519_ephemeral,
        transport_sig,
        transport_pubkey_pb,
        ts,
        nonce,
        caps,
        hello_now_secs(),
    )
}

/// То же, что [`verify_hello_transport_binding`], но `now` задан снаружи.
/// Векторы фиксируют окно свежести, не зависят от часов машины.
pub fn verify_hello_transport_binding_at(
    signer_peer_id: PeerId,
    recipient_peer_id: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    transport_sig: &[u8],
    transport_pubkey_pb: &[u8],
    ts: u64,
    nonce: &[u8; 16],
    caps: u32,
    now: u64,
) -> Option<HelloBind> {
    const MAX_SIG: usize = 256;
    if transport_sig.is_empty() || transport_sig.len() > MAX_SIG {
        return None;
    }
    let pubkey = void_hello_signing_public_key(signer_peer_id, transport_pubkey_pb)?;
    let fresh = ts != 0 || nonce.iter().any(|b| *b != 0);
    if fresh {
        if now.abs_diff(ts) > HELLO_FRESHNESS_SECS || nonce.iter().all(|b| *b == 0) {
            return None;
        }
        let v3 = hello_bind_message_v3(
            signer_peer_id,
            recipient_peer_id,
            x25519_static,
            x25519_ephemeral,
            ts,
            nonce,
            caps,
        );
        if pubkey.verify(&v3, transport_sig) {
            return Some(HelloBind::V3);
        }
        let v2 = hello_bind_message_v2(
            signer_peer_id,
            recipient_peer_id,
            x25519_static,
            x25519_ephemeral,
            ts,
            nonce,
        );
        if pubkey.verify(&v2, transport_sig) {
            return Some(HelloBind::V2);
        }
        return None;
    }
    let v1 = hello_bind_message_v1(
        signer_peer_id,
        recipient_peer_id,
        x25519_static,
        x25519_ephemeral,
    );
    pubkey.verify(&v1, transport_sig).then_some(HelloBind::V1)
}

/// Сессия открывается только с bind v3 и битом AAD внутри подписи.
/// Прямой Hello v1/v2 и onion-Hello без флага сессию не создают:
/// иначе собеседник или hop оставляет кадры без AAD.
pub fn hello_bind_ok(bind: HelloBind, caps: u32, _via_onion: bool) -> bool {
    bind == HelloBind::V3 && caps & HELLO_CAP_HEADER_AAD != 0
}

pub fn sign_hello_transport_binding(
    transport: &libp2p_identity::Keypair,
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    ts: u64,
    nonce: &[u8; 16],
    caps: u32,
) -> Option<Vec<u8>> {
    let msg = hello_bind_message_v3(
        signer_peer,
        recipient_peer,
        x25519_static,
        x25519_ephemeral,
        ts,
        nonce,
        caps,
    );
    transport.sign(&msg).ok()
}

/// Заголовок Double Ratchet (`dh_pub`, `pn`, `n`) входит в AAD.
pub const HELLO_CAP_HEADER_AAD: u32 = 1;
pub const HELLO_CAPS: u32 = HELLO_CAP_HEADER_AAD;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PublicKey, StaticSecret};
    use libp2p_identity::Keypair;

    #[test]
    fn legacy_hello_without_ts_still_verifies() {
        let kp = Keypair::generate_ed25519();
        let signer = kp.public().to_peer_id();
        let recipient = Keypair::generate_ed25519().public().to_peer_id();
        let static_b =
            PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let ephem_b = PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let msg = super::hello_bind_message_v1(signer, recipient, &static_b, &ephem_b);
        let sig = kp.sign(&msg).unwrap();
        assert_eq!(
            verify_hello_transport_binding(
                signer,
                recipient,
                &static_b,
                &ephem_b,
                &sig,
                &[],
                0,
                &[0u8; 16],
                0,
            ),
            Some(HelloBind::V1)
        );
        assert!(!hello_bind_ok(HelloBind::V1, 0, false));
        assert!(!hello_bind_ok(HelloBind::V1, 0, true));
    }

    #[test]
    fn v3_signature_roundtrip() {
        let kp = Keypair::generate_ed25519();
        let signer = kp.public().to_peer_id();
        let recipient = Keypair::generate_ed25519().public().to_peer_id();
        let static_b =
            PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let ephem_b = PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let ts = super::hello_now_secs();
        let nonce = [7u8; 16];
        let sig = sign_hello_transport_binding(
            &kp,
            signer,
            recipient,
            &static_b,
            &ephem_b,
            ts,
            &nonce,
            HELLO_CAPS,
        )
        .unwrap();
        assert_eq!(
            verify_hello_transport_binding(
                signer,
                recipient,
                &static_b,
                &ephem_b,
                &sig,
                &[],
                ts,
                &nonce,
                HELLO_CAPS,
            ),
            Some(HelloBind::V3)
        );
        assert!(verify_hello_transport_binding(
            signer,
            recipient,
            &static_b,
            &ephem_b,
            &sig,
            &[],
            ts.saturating_sub(HELLO_FRESHNESS_SECS + 1),
            &nonce,
            HELLO_CAPS,
        )
        .is_none());
        assert!(hello_bind_ok(HelloBind::V3, HELLO_CAPS, false));
        assert!(!hello_bind_ok(HelloBind::V3, 0, false));
    }
}
