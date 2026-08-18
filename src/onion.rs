//! Application-level onion hops over `/void/chat` (VOID_ONION_v1).
//!
//! 1 live node → one hop (node sees Alice↔Bob after unwrap).
//! 2 nodes → both hops. 3 or more → three random; entry does not learn Bob,
//! exit does not see Alice's IP.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_HOPS: usize = 3;
pub const MAX_CT_BYTES: usize = 3 * 1024 * 1024;
const HKDF_SALT: &[u8] = b"VOID_ONION_SALT_v1";
const HKDF_INFO: &[u8] = b"VOID_ONION_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPayload {
    pub next: String,
    pub inner: serde_json::Value,
}

pub fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `void-bootstrap-node/0.4;onion=<64 hex>`
#[cfg_attr(not(test), allow(dead_code))]
pub fn agent_version_with_pk(base: &str, pk: &[u8; 32]) -> String {
    format!("{base};onion={}", hex32(pk))
}

pub fn parse_pk_from_agent(agent: &str) -> Option<[u8; 32]> {
    let rest = agent.split(";onion=").nth(1)?;
    let hex = rest.split(';').next()?.trim();
    parse_hex32(hex)
}

fn aead_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| anyhow!("onion hkdf"))?;
    Ok(okm)
}

pub fn seal(hop_pk: &PublicKey, payload: &OnionPayload) -> Result<([u8; 32], [u8; 12], Vec<u8>)> {
    let eph_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pk = PublicKey::from(&eph_sk);
    let shared = eph_sk.diffie_hellman(hop_pk);
    let key = aead_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = serde_json::to_vec(payload)?;
    let ct = cipher
        .encrypt(nonce, plain.as_ref())
        .map_err(|_| anyhow!("onion seal"))?;
    if ct.len() > MAX_CT_BYTES {
        return Err(anyhow!("onion cell too large"));
    }
    Ok((eph_pk.to_bytes(), nonce_bytes, ct))
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn open(
    hop_sk: &StaticSecret,
    eph: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
) -> Result<OnionPayload> {
    if ct.len() > MAX_CT_BYTES || ct.is_empty() {
        return Err(anyhow!("onion cell size"));
    }
    let eph_pk = PublicKey::from(*eph);
    let shared = hop_sk.diffie_hellman(&eph_pk);
    let key = aead_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
    let nonce = Nonce::from_slice(nonce);
    let plain = cipher
        .decrypt(nonce, ct)
        .map_err(|_| anyhow!("onion open"))?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Сколько hop'ов брать из пула известных onion-нод.
pub fn target_hop_count(available: usize) -> usize {
    match available {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => MAX_HOPS,
    }
}

/// Entry — живой bootstrap; остальные hop'ы могут быть только из каталога ключей.
/// 1 нода → 1 hop, 2 → обе, 3+ → три случайных.
pub fn select_hops(
    connected: impl Iterator<Item = PeerId>,
    bootstrap_ids: &HashSet<PeerId>,
    keys: &HashMap<PeerId, [u8; 32]>,
) -> Vec<(PeerId, [u8; 32])> {
    use rand::seq::SliceRandom;
    let connected: HashSet<PeerId> = connected.collect();
    let mut pool: Vec<(PeerId, [u8; 32])> = keys
        .iter()
        .filter(|(p, _)| bootstrap_ids.contains(p))
        .map(|(p, k)| (*p, *k))
        .collect();
    if pool.is_empty() {
        return Vec::new();
    }
    let mut entry_pool: Vec<(PeerId, [u8; 32])> = pool
        .iter()
        .filter(|(p, _)| connected.contains(p))
        .cloned()
        .collect();
    if entry_pool.is_empty() {
        return Vec::new();
    }
    entry_pool.shuffle(&mut rand::thread_rng());
    let entry = entry_pool[0].clone();
    let want = target_hop_count(pool.len());
    pool.retain(|(p, _)| *p != entry.0);
    pool.shuffle(&mut rand::thread_rng());
    let mut hops = vec![entry];
    for hop in pool {
        if hops.len() >= want {
            break;
        }
        hops.push(hop);
    }
    hops
}

/// Wrap `innermost` (typically OnionDrop JSON) in one cell per hop, dest-first.
/// Returns the outermost (eph, nonce, ct) to send to `hops[0]`.
pub fn wrap_layers(
    hops: &[(PeerId, [u8; 32])],
    dest: PeerId,
    innermost: serde_json::Value,
) -> Result<([u8; 32], [u8; 12], Vec<u8>)> {
    if hops.is_empty() {
        return Err(anyhow!("no onion hops"));
    }
    let mut current = innermost;
    let mut next = dest.to_string();
    let mut outer = None;
    for (hop_id, hop_pk) in hops.iter().rev() {
        let payload = OnionPayload {
            next: next.clone(),
            inner: current,
        };
        let pk = PublicKey::from(*hop_pk);
        let (eph, nonce, ct) = seal(&pk, &payload)?;
        outer = Some((eph, nonce, ct.clone()));
        current = serde_json::json!({
            "Onion": { "eph": eph, "nonce": nonce, "ct": ct }
        });
        next = hop_id.to_string();
    }
    outer.ok_or_else(|| anyhow!("onion wrap"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_one_hop() {
        let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pk = PublicKey::from(&sk);
        let payload = OnionPayload {
            next: "12D3KooWdest".into(),
            inner: serde_json::json!({"Ack": null}),
        };
        let (eph, nonce, ct) = seal(&pk, &payload).unwrap();
        let out = open(&sk, &eph, &nonce, &ct).unwrap();
        assert_eq!(out.next, payload.next);
        assert_eq!(out.inner, payload.inner);
    }

    #[test]
    fn agent_parse() {
        let pk = [0xab; 32];
        let agent = agent_version_with_pk("void-bootstrap-node/0.4", &pk);
        assert_eq!(parse_pk_from_agent(&agent), Some(pk));
        assert!(parse_pk_from_agent("void-bootstrap-node/0.3").is_none());
    }

    #[test]
    fn three_hops_unwrap() {
        let keys: Vec<StaticSecret> = (0..3)
            .map(|_| StaticSecret::random_from_rng(rand::rngs::OsRng))
            .collect();
        let hops: Vec<(PeerId, [u8; 32])> = keys
            .iter()
            .map(|sk| {
                let pid = PeerId::random();
                (pid, PublicKey::from(sk).to_bytes())
            })
            .collect();
        let dest = PeerId::random();
        let inner = serde_json::json!({"OnionDrop":{"src":"alice","packet":{"Ack":null}}});
        let (eph, nonce, ct) = wrap_layers(&hops, dest, inner.clone()).unwrap();

        let mut cell_eph = eph;
        let mut cell_nonce = nonce;
        let mut cell_ct = ct;
        let mut next_expected = hops[1].0.to_string();
        for (i, sk) in keys.iter().enumerate() {
            let p = open(sk, &cell_eph, &cell_nonce, &cell_ct).unwrap();
            if i + 1 < keys.len() {
                assert_eq!(p.next, next_expected);
                next_expected = if i + 2 < hops.len() {
                    hops[i + 2].0.to_string()
                } else {
                    dest.to_string()
                };
                let onion = p.inner.get("Onion").expect("inner onion");
                cell_eph = serde_json::from_value(onion["eph"].clone()).unwrap();
                cell_nonce = serde_json::from_value(onion["nonce"].clone()).unwrap();
                cell_ct = serde_json::from_value(onion["ct"].clone()).unwrap();
            } else {
                assert_eq!(p.next, dest.to_string());
                assert_eq!(p.inner, inner);
            }
        }
    }

    #[test]
    fn hop_count_follows_node_pool() {
        assert_eq!(target_hop_count(0), 0);
        assert_eq!(target_hop_count(1), 1);
        assert_eq!(target_hop_count(2), 2);
        assert_eq!(target_hop_count(3), 3);
        assert_eq!(target_hop_count(9), 3);
    }

    #[test]
    fn select_hops_two_nodes_uses_both_even_if_one_connected() {
        let a = PeerId::random();
        let b = PeerId::random();
        let mut keys = HashMap::new();
        keys.insert(a, [1u8; 32]);
        keys.insert(b, [2u8; 32]);
        let mut ids = HashSet::new();
        ids.insert(a);
        ids.insert(b);
        let hops = select_hops(std::iter::once(a), &ids, &keys);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].0, a);
        assert_eq!(hops[1].0, b);
    }

    #[test]
    fn select_hops_three_plus_caps_at_three() {
        let connected = PeerId::random();
        let mut keys = HashMap::new();
        let mut ids = HashSet::new();
        keys.insert(connected, [9u8; 32]);
        ids.insert(connected);
        for i in 0..4u8 {
            let p = PeerId::random();
            keys.insert(p, [i; 32]);
            ids.insert(p);
        }
        let hops = select_hops(std::iter::once(connected), &ids, &keys);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].0, connected);
    }

    #[test]
    fn select_hops_empty_without_live_entry() {
        let a = PeerId::random();
        let mut keys = HashMap::new();
        keys.insert(a, [1u8; 32]);
        let mut ids = HashSet::new();
        ids.insert(a);
        let hops = select_hops(std::iter::empty(), &ids, &keys);
        assert!(hops.is_empty());
    }

    #[test]
    fn two_hops_unwrap() {
        let keys: Vec<StaticSecret> = (0..2)
            .map(|_| StaticSecret::random_from_rng(rand::rngs::OsRng))
            .collect();
        let hops: Vec<(PeerId, [u8; 32])> = keys
            .iter()
            .map(|sk| {
                let pid = PeerId::random();
                (pid, PublicKey::from(sk).to_bytes())
            })
            .collect();
        let dest = PeerId::random();
        let inner = serde_json::json!({"OnionDrop":{"src":"alice","packet":{"Ack":null}}});
        let (eph, nonce, ct) = wrap_layers(&hops, dest, inner.clone()).unwrap();
        let p0 = open(&keys[0], &eph, &nonce, &ct).unwrap();
        assert_eq!(p0.next, hops[1].0.to_string());
        let onion = p0.inner.get("Onion").expect("inner onion");
        let eph1: [u8; 32] = serde_json::from_value(onion["eph"].clone()).unwrap();
        let nonce1: [u8; 12] = serde_json::from_value(onion["nonce"].clone()).unwrap();
        let ct1: Vec<u8> = serde_json::from_value(onion["ct"].clone()).unwrap();
        let p1 = open(&keys[1], &eph1, &nonce1, &ct1).unwrap();
        assert_eq!(p1.next, dest.to_string());
        assert_eq!(p1.inner, inner);
    }
}
