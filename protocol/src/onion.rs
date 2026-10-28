//! libp2p-facing onion API.
//!
//! `void-onion` speaks a byte [`void_onion::PeerId`] and does not link libp2p.
//! These wrappers keep `void_protocol::onion` on `libp2p::PeerId` for this release.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use libp2p::{Multiaddr, PeerId};
use rand::{CryptoRng, RngCore};

pub use void_onion::{
    agent_version_with_pk, b64_decode, b64_encode, deliver_bytes, hex32, hex_bytes, open,
    open_deliver, parse_epoch_from_agent, parse_hex32, parse_hex_bytes, parse_op_from_agent,
    parse_osig2_from_agent, parse_osig_from_agent, parse_pk_from_agent, parse_until_from_agent,
    seal, target_hop_count, HopDesc, OnionPayload, MAX_CT_BYTES, MAX_HOPS, V2_BUCKETS, V2_SLOT_LEN,
};

#[derive(Clone, Debug, Default)]
pub struct HopPolicy {
    pub guard: Option<PeerId>,
    pub operators: HashMap<PeerId, String>,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum V2Peel {
    Forward { next: PeerId, cell: Vec<u8> },
    Deliver { next: PeerId, body: Vec<u8> },
}

fn wire(peer: PeerId) -> void_onion::PeerId {
    void_onion::PeerId::from_bytes(&peer.to_bytes()).expect("libp2p peer id")
}

fn unwire(peer: void_onion::PeerId) -> Result<PeerId> {
    PeerId::from_bytes(&peer.to_bytes()).map_err(|e| anyhow::anyhow!("peer id: {e}"))
}

fn wire_hops(hops: &[(PeerId, [u8; 32])]) -> Vec<(void_onion::PeerId, [u8; 32])> {
    hops.iter().map(|(p, k)| (wire(*p), *k)).collect()
}

pub fn onion_pk_bind_message(peer: PeerId, pk: &[u8; 32]) -> Vec<u8> {
    void_onion::onion_pk_bind_message(wire(peer), pk)
}

pub fn select_hops(
    connected: impl Iterator<Item = PeerId>,
    bootstrap_ids: &HashSet<PeerId>,
    keys: &HashMap<PeerId, [u8; 32]>,
    addrs: &HashMap<PeerId, Vec<Multiaddr>>,
    policy: &HopPolicy,
) -> Vec<(PeerId, [u8; 32])> {
    let connected = connected.map(wire);
    let bootstrap_ids: HashSet<_> = bootstrap_ids.iter().copied().map(wire).collect();
    let keys: HashMap<_, _> = keys.iter().map(|(p, k)| (wire(*p), *k)).collect();
    let addrs: HashMap<_, _> = addrs.iter().map(|(p, a)| (wire(*p), a.clone())).collect();
    let policy = void_onion::HopPolicy {
        guard: policy.guard.map(wire),
        operators: policy
            .operators
            .iter()
            .map(|(p, op)| (wire(*p), op.clone()))
            .collect(),
    };
    void_onion::select_hops(connected, &bootstrap_ids, &keys, &addrs, &policy)
        .into_iter()
        .map(|(p, k)| (unwire(p).expect("wire peer id"), k))
        .collect()
}

pub fn wrap_layers(
    hops: &[(PeerId, [u8; 32])],
    dest: PeerId,
    innermost: serde_json::Value,
) -> Result<([u8; 32], [u8; 12], Vec<u8>)> {
    void_onion::wrap_layers(&wire_hops(hops), wire(dest), innermost)
}

pub fn wrap_v2(hops: &[(PeerId, [u8; 32])], dest: PeerId, body: &[u8]) -> Result<Vec<u8>> {
    void_onion::wrap_v2(&wire_hops(hops), wire(dest), body)
}

pub fn wrap_v2_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    hops: &[(PeerId, [u8; 32])],
    dest: PeerId,
    body: &[u8],
) -> Result<Vec<u8>> {
    void_onion::wrap_v2_rng(rng, &wire_hops(hops), wire(dest), body)
}

fn map_peel(peel: void_onion::V2Peel) -> Result<V2Peel> {
    match peel {
        void_onion::V2Peel::Forward { next, cell } => Ok(V2Peel::Forward {
            next: unwire(next)?,
            cell,
        }),
        void_onion::V2Peel::Deliver { next, body } => Ok(V2Peel::Deliver {
            next: unwire(next)?,
            body,
        }),
    }
}

pub fn peel_v2(sk: &x25519_dalek::StaticSecret, cell: &[u8]) -> Result<V2Peel> {
    map_peel(void_onion::peel_v2(sk, cell)?)
}

pub fn peel_v2_any(secrets: &[x25519_dalek::StaticSecret], cell: &[u8]) -> Result<V2Peel> {
    map_peel(void_onion::peel_v2_any(secrets, cell)?)
}

pub fn seal_deliver(recipient: &PeerId, payload: &[u8]) -> Result<Vec<u8>> {
    seal_deliver_rng(&mut rand::rngs::OsRng, recipient, payload)
}

pub fn seal_deliver_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient: &PeerId,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let pk = void_envelope::offline_mail::identity_offline_public(recipient)
        .ok_or_else(|| anyhow::anyhow!("onion seal: no identity key"))?;
    void_onion::seal_deliver_rng(rng, pk.as_bytes(), payload)
}

pub fn desc_message(
    peer: PeerId,
    pk: &[u8; 32],
    epoch: u64,
    not_after: u64,
    operator: &str,
) -> Vec<u8> {
    void_onion::desc_message(wire(peer), pk, epoch, not_after, operator)
}
