//! Chat frames and the length-prefixed wire. The facade re-export is deprecated.

pub use void_frames::protocol::*;
#[allow(unused_imports)]
pub use void_frames::wire::{
    both_announce_cbor, decode_v1_packet, encode_v1_packet, WireEncoding, MAX_CIPHERTEXT_BYTES,
    MAX_CT_BYTES, MAX_DELIVER_ENVELOPES, MAX_STORE_ENVELOPES, REQUEST_MAX_BYTES,
    RESPONSE_MAX_BYTES,
};
