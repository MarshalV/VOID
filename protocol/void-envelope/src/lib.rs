//! Offline envelope, prekey, seal and open.
//!
//! Record keys and the swarm store are not here. `dht_record_allowed` lives in
//! `void-kad-rules`. This crate depends on `libp2p-identity` for signatures,
//! not on libp2p Kademlia.

pub mod offline_mail;
