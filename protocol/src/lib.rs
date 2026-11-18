//! VOID wire protocol facade.
//!
//! Frames, the session, offline envelopes, onion cells, and the Kademlia value
//! check live in `void-frames`, `void-session`, `void-envelope`, `void-onion`,
//! and `void-kad-rules`. The re-exports below are deprecated: call those crates
//! directly. `kad_store` stays here because it needs the libp2p `kad` feature.
//!
//! A node links `void-envelope`, `void-onion`, and `void-frames`, plus its own
//! swarm. `void-onion` does not depend on libp2p and does not enable `kad`.

#![allow(deprecated)]

#[deprecated(note = "use void_session::crypto")]
pub mod crypto {
    pub use void_session::crypto::*;
}

#[deprecated(note = "use void_session::kem")]
pub mod kem {
    pub use void_session::kem::*;
}

#[deprecated(note = "use void_session::group")]
pub mod group {
    pub use void_session::group::*;
}

#[deprecated(note = "use void_envelope::offline_mail; record keys stay on void_kad_rules")]
pub mod offline_mail {
    pub use void_envelope::offline_mail::*;
    pub use void_kad_rules::{dht_put_allowed, dht_record_allowed};

    pub use crate::record_keys::{mailbox_record_key, opk_record_key, prekey_record_key};
}

#[deprecated(note = "use void_onion; convert PeerId at the swarm edge")]
pub mod onion;

#[deprecated(note = "use void_envelope::queue_mail")]
pub mod queue_mail;

#[deprecated(note = "use void_mls")]
pub mod mls {
    pub use void_mls::*;
}

#[deprecated(note = "use void_frames::protocol and void_frames::wire")]
pub mod protocol {
    pub use void_frames::protocol::*;
    pub use void_frames::wire::{
        both_announce_cbor, decode_v1_packet, encode_v1_packet, WireEncoding, MAX_CIPHERTEXT_BYTES,
        MAX_CT_BYTES, MAX_DELIVER_ENVELOPES, MAX_STORE_ENVELOPES, REQUEST_MAX_BYTES,
        RESPONSE_MAX_BYTES,
    };
    #[cfg(test)]
    pub(crate) use void_session::hello::{
        sign_hello_transport_binding, verify_hello_transport_binding_at,
    };
}

pub mod kad_store;

#[cfg(test)]
mod vectors;

mod record_keys;
