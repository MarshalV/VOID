//! Протокол чата `/void/chat/1.0.0`: Hello, E2EE-пакеты, лимиты JSON.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::file_transfer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChatMessage {
    pub(crate) sender_id: String,
    pub(crate) sender_name: String,
    pub(crate) recipient_id: Option<String>,
    pub(crate) text: String,
    pub(crate) timestamp: String,
}

/// Лимиты JSON чата после `decrypt_payload` (защита от DoS по памяти).
const MAX_CHAT_JSON_BYTES: usize = 64 * 1024;
const MAX_CHAT_SENDER_ID_BYTES: usize = 512;
const MAX_CHAT_SENDER_NAME_BYTES: usize = 256;
const MAX_CHAT_TEXT_BYTES: usize = 16 * 1024;
const MAX_CHAT_TIMESTAMP_BYTES: usize = 64;

const VOID_HELLO_BIND_PREFIX: &[u8] = b"VOID_E2EE_HELLO_BIND_V1\0";

const MAX_HELLO_TRANSPORT_PUBKEY_PB: usize = 4096;

/// Inline multihash PeerId (Ed25519): извлечь транспортный `PublicKey` для проверки подписи Hello.
fn void_peer_transport_public_key(peer: PeerId) -> Option<libp2p::identity::PublicKey> {
    const CODE_IDENTITY: u64 = 0;
    let mh = peer.as_ref();
    if mh.code() != CODE_IDENTITY {
        return None;
    }
    libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()
}

/// Ключ для проверки `transport_sig`: из identity-multihash или из protobuf в Hello (hashed PeerId).
fn void_hello_signing_public_key(
    signer_peer_id: PeerId,
    transport_pubkey_pb: &[u8],
) -> Option<libp2p::identity::PublicKey> {
    if !transport_pubkey_pb.is_empty() {
        if transport_pubkey_pb.len() > MAX_HELLO_TRANSPORT_PUBKEY_PB {
            return None;
        }
        let pk = libp2p::identity::PublicKey::try_decode_protobuf(transport_pubkey_pb).ok()?;
        if PeerId::from_public_key(&pk) != signer_peer_id {
            return None;
        }
        return Some(pk);
    }
    void_peer_transport_public_key(signer_peer_id)
}

fn hello_bind_message(
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

pub(crate) fn verify_hello_transport_binding(
    signer_peer_id: PeerId,
    recipient_peer_id: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
    transport_sig: &[u8],
    transport_pubkey_pb: &[u8],
) -> bool {
    const MAX_SIG: usize = 256;
    if transport_sig.is_empty() || transport_sig.len() > MAX_SIG {
        return false;
    }
    let Some(pubkey) = void_hello_signing_public_key(signer_peer_id, transport_pubkey_pb) else {
        return false;
    };
    let msg = hello_bind_message(
        signer_peer_id,
        recipient_peer_id,
        x25519_static,
        x25519_ephemeral,
    );
    pubkey.verify(&msg, transport_sig)
}

fn sign_hello_transport_binding(
    transport: &libp2p::identity::Keypair,
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static: &[u8; 32],
    x25519_ephemeral: &[u8; 32],
) -> Option<Vec<u8>> {
    let msg = hello_bind_message(signer_peer, recipient_peer, x25519_static, x25519_ephemeral);
    transport.sign(&msg).ok()
}

/// Разбор JSON чата после DR: верхняя граница буфера и длины полей.
pub(crate) fn parse_decrypted_chat_json(plaintext: &[u8]) -> Option<ChatMessage> {
    if plaintext.len() > MAX_CHAT_JSON_BYTES {
        return None;
    }
    if plaintext.first() != Some(&b'{') {
        return None;
    }
    let msg: ChatMessage = serde_json::from_slice(plaintext).ok()?;
    if msg.sender_id.len() > MAX_CHAT_SENDER_ID_BYTES
        || msg.sender_name.len() > MAX_CHAT_SENDER_NAME_BYTES
        || msg.text.len() > MAX_CHAT_TEXT_BYTES
        || msg.timestamp.len() > MAX_CHAT_TIMESTAMP_BYTES
    {
        return None;
    }
    if let Some(ref r) = msg.recipient_id {
        if r.len() > MAX_CHAT_SENDER_ID_BYTES {
            return None;
        }
    }
    Some(msg)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum V1Packet {
    Hello {
        public_key: [u8; 32],
        ephemeral_key: [u8; 32],
        /// Подпись Ed25519 (libp2p identity) над `VOID_E2EE_HELLO_BIND_V1` + peerId||peerId||x25519||ephem.
        #[serde(default)]
        transport_sig: Vec<u8>,
        /// Если PeerId не identity-multihash: protobuf `PublicKey` для проверки подписи.
        #[serde(default)]
        transport_pubkey_pb: Vec<u8>,
    },
    Encrypted {
        header: crypto::MessageHeader,
        ciphertext: Vec<u8>,
    },
    Ack,
}

pub(crate) fn build_v1_hello(
    transport: &libp2p::identity::Keypair,
    signer_peer: PeerId,
    recipient_peer: PeerId,
    x25519_static_pubkey: crypto::PublicKey,
    x25519_ephem_pubkey: crypto::PublicKey,
) -> Option<V1Packet> {
    let static_b = x25519_static_pubkey.to_bytes();
    let ephem_b = x25519_ephem_pubkey.to_bytes();
    let transport_sig = sign_hello_transport_binding(
        transport,
        signer_peer,
        recipient_peer,
        &static_b,
        &ephem_b,
    )?;
    let transport_pubkey_pb = if void_peer_transport_public_key(signer_peer).is_some() {
        Vec::new()
    } else {
        transport.public().encode_protobuf()
    };
    Some(V1Packet::Hello {
        public_key: static_b,
        ephemeral_key: ephem_b,
        transport_sig,
        transport_pubkey_pb,
    })
}

/// Прогресс активной передачи файла (для UI).
pub(crate) struct FileTransferProgress {
    pub filename: String,
    pub total_size: u64,
    pub sent_chunks: u32,
    pub total_chunks: u32,
    pub is_outgoing: bool,
    pub completed: bool,
    pub saved_to: String,
    pub peer: PeerId,
    pub kind: file_transfer::FileKind,
}
