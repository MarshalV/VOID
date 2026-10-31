//! Hello bind, Double Ratchet session, capability bits, and groups.
//!
//! `PeerId` on the public functions is `libp2p_identity::PeerId` (the same type
//! as `libp2p::PeerId`). Identity signatures stay on that crate. Kademlia is not
//! a dependency. `group` stays here until a separate `void-groups` crate.

pub mod crypto;
pub mod group;
pub mod hello;
pub mod mailbox_query;
