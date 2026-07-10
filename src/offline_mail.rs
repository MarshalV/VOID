//! Offline mail via DHT.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use libp2p::kad;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, StaticSecret};

const PREKEY_PREFIX: &[u8] = b"/void/prekey/";
const MAILBOX_PREFIX: &[u8] = b"/void/mailbox/";
pub(crate) const MAILBOX_TTL_SECS: u64 = 60 * 60 * 24 * 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OfflineEnvelope {
    pub(crate) v: u8,
    pub(crate) sender: String,
    pub(crate) sender_pk: [u8; 32],
    pub(crate) message_id: String,
    pub(crate) kind: String,
    pub(crate) eph: [u8; 32],
    pub(crate) nonce: [u8; 12],
    pub(crate) ct: Vec<u8>,
}

pub(crate) fn prekey_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = PREKEY_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub(crate) fn mailbox_record_key(peer: PeerId) -> kad::RecordKey {
    let mut key = MAILBOX_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub(crate) fn encode_mailbox(envelopes: &[OfflineEnvelope]) -> Result<Vec<u8>> {
    serde_json::to_vec(envelopes).map_err(|e| anyhow!("mailbox json: {e}"))
}

pub(crate) fn decode_mailbox(bytes: &[u8]) -> Result<Vec<OfflineEnvelope>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(bytes).map_err(|e| anyhow!("mailbox decode: {e}"))
}

pub(crate) fn seal_for_recipient(
    recipient_pk: &PublicKey,
    sender: &PeerId,
    sender_pk: &[u8; 32],
    message_id: &str,
    kind: &str,
    plaintext: &[u8],
) -> Result<OfflineEnvelope> {
    let eph_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(recipient_pk);
    let key = hkdf_offline(shared.as_bytes());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("offline seal failed"))?;
    Ok(OfflineEnvelope {
        v: 1,
        sender: sender.to_string(),
        sender_pk: *sender_pk,
        message_id: message_id.to_string(),
        kind: kind.to_string(),
        eph: eph_pub.to_bytes(),
        nonce,
        ct,
    })
}

pub(crate) fn open_envelope(
    recipient_secret: &StaticSecret,
    env: &OfflineEnvelope,
) -> Result<Vec<u8>> {
    let eph_pub = PublicKey::from(env.eph);
    let shared = recipient_secret.diffie_hellman(&eph_pub);
    let key = hkdf_offline(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    cipher
        .decrypt(Nonce::from_slice(&env.nonce), env.ct.as_ref())
        .map_err(|_| anyhow!("offline open failed"))
}

fn hkdf_offline(shared: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_OFFLINE_V1"), shared);
    let mut okm = [0u8; 32];
    hk.expand(b"mail", &mut okm)
        .expect("hkdf offline key len");
    okm
}
