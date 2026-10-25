//! VOID wire protocol. The desktop in the repository root is one consumer.
//! Frames, the Double Ratchet session, offline envelopes, onion cells, and
//! the Kademlia record check live here. Vault, windows, and the swarm loop do not.

pub mod crypto;
pub mod group;
pub mod kad_store;
pub mod offline_mail;
pub mod onion;
pub mod protocol;
