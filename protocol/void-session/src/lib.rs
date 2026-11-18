//! Hello bind, Double Ratchet session, capability bits, and groups.
//!
//! [`PeerId`] is a newtype over the multihash bytes, the same shape as
//! `void-onion`'s id. Identity signatures still use `libp2p-identity`.
//! Public functions also take that crate's `PeerId` through [`AsPeerId`],
//! so a swarm id does not have to be rebuilt at every call. Kademlia is not
//! a dependency. `group` stays here until a separate `void-groups` crate.

mod peer_id;

pub mod crypto;
pub mod group;
pub mod hello;
pub mod kem;
pub mod mailbox_query;

pub use peer_id::{AsPeerId, PeerId};
