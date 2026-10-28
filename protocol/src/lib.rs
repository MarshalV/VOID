//! VOID wire protocol facade.
//!
//! Frames, the session, offline envelopes, onion cells, and the Kademlia value
//! check live in `void-frames`, `void-session`, `void-envelope`, `void-onion`,
//! and `void-kad-rules`. This crate re-exports them for one release so
//! `void_protocol::…` paths keep working. Prefer those crates directly.
//!
//! A node links `void-envelope`, `void-onion`, and `void-frames`, plus its own
//! swarm. `void-onion` does not depend on libp2p and does not enable `kad`.

pub mod crypto {
    pub use void_session::crypto::*;
}

pub mod group {
    pub use void_session::group::*;
}

pub mod offline_mail {
    pub use void_envelope::offline_mail::*;
    pub use void_kad_rules::dht_record_allowed;

    pub use crate::record_keys::{mailbox_record_key, prekey_record_key};
}

pub mod onion;

pub mod protocol {
    pub use void_frames::protocol::*;
    #[cfg(test)]
    pub(crate) use void_session::hello::{
        sign_hello_transport_binding, verify_hello_transport_binding_at,
    };
}

pub mod kad_store;

#[cfg(test)]
mod vectors;

mod record_keys;
