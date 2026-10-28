//! Application-level onion hops over `/void/chat`.
//!
//! v1: JSON cell, `OnionDrop.src` in the last layer. Still wrapped when a hop
//! has no v2 descriptor.
//! v2: fixed-size binary cell (2 / 16 / 64 KiB). Three header slots, so every
//! hop on a path sees the same length. The exit learns `next` (the recipient)
//! and an opaque body sealed to the recipient's identity key — not the sender.
//!
//! No libp2p and no `kad` feature. [`PeerId`] is the multihash bytes libp2p
//! uses (`to_bytes` / base58). `Multiaddr` comes from the `multiaddr` crate.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use multiaddr::{Multiaddr, Protocol};
use multihash::Multihash;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use x25519_dalek::{PublicKey, StaticSecret};

/// Peer id as libp2p stores it: a peer-id multihash, not a swarm handle.
///
/// `to_bytes` / `from_bytes` / Display (base58btc) match `libp2p::PeerId`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId {
    hash: Multihash<64>,
}

const PEER_CODE_IDENTITY: u64 = 0;
const PEER_CODE_SHA256: u64 = 0x12;
const PEER_MAX_INLINE: usize = 42;

impl PeerId {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let hash = Multihash::<64>::from_bytes(data).ok()?;
        match hash.code() {
            PEER_CODE_SHA256 => Some(Self { hash }),
            PEER_CODE_IDENTITY if hash.digest().len() <= PEER_MAX_INLINE => Some(Self { hash }),
            _ => None,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.hash.to_bytes()
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// Identity-multihash of 32 random bytes. Tests and hop selection only.
    pub fn random() -> Self {
        let mut digest = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut digest);
        Self {
            hash: Multihash::<64>::wrap(PEER_CODE_IDENTITY, &digest).expect("digest fits"),
        }
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PeerId").field(&self.to_base58()).finish()
    }
}

pub const MAX_HOPS: usize = 3;
pub const MAX_CT_BYTES: usize = 256 * 1024;
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

const ONION_PK_BIND: &[u8] = b"VOID_ONION_PK_BIND_V1\0";

pub fn onion_pk_bind_message(peer: PeerId, pk: &[u8; 32]) -> Vec<u8> {
    let id = peer.to_bytes();
    let mut msg = Vec::with_capacity(ONION_PK_BIND.len() + id.len() + 32);
    msg.extend_from_slice(ONION_PK_BIND);
    msg.extend_from_slice(&id);
    msg.extend_from_slice(pk);
    msg
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn parse_osig_from_agent(agent: &str) -> Option<Vec<u8>> {
    let rest = agent.split(";osig=").nth(1)?;
    parse_hex_bytes(rest.split(';').next()?.trim())
}

fn agent_value<'a>(agent: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!(";{key}=");
    let rest = agent.split(&pat).nth(1)?;
    Some(rest.split(';').next()?.trim())
}

pub fn parse_epoch_from_agent(agent: &str) -> Option<u64> {
    agent_value(agent, "epoch")?.parse().ok()
}

pub fn parse_until_from_agent(agent: &str) -> Option<u64> {
    agent_value(agent, "until")?.parse().ok()
}

pub fn parse_op_from_agent(agent: &str) -> Option<String> {
    Some(agent_value(agent, "op")?.to_string())
}

pub fn parse_osig2_from_agent(agent: &str) -> Option<Vec<u8>> {
    parse_hex_bytes(agent_value(agent, "osig2")?)
}

fn aead_key(shared: &[u8; 32]) -> Result<[u8; 32]> {
    if shared.iter().all(|&b| b == 0) {
        return Err(anyhow!("onion low-order point"));
    }
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

#[derive(Clone, Debug, Default)]
pub struct HopPolicy {
    pub guard: Option<PeerId>,
    pub operators: HashMap<PeerId, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum NetId {
    V4([u8; 2]),
    V6([u8; 4]),
}

fn ipv4_slash16(addr: &Multiaddr) -> Option<[u8; 2]> {
    for proto in addr.iter() {
        if let Protocol::Ip4(ip) = proto {
            let o = ip.octets();
            return Some([o[0], o[1]]);
        }
    }
    None
}

fn ipv6_slash32(addr: &Multiaddr) -> Option<[u8; 4]> {
    for proto in addr.iter() {
        if let Protocol::Ip6(ip) = proto {
            let o = ip.octets();
            return Some([o[0], o[1], o[2], o[3]]);
        }
    }
    None
}

fn hop_nets(pid: PeerId, addrs: &HashMap<PeerId, Vec<Multiaddr>>) -> HashSet<NetId> {
    let mut nets = HashSet::new();
    if let Some(list) = addrs.get(&pid) {
        for addr in list {
            if let Some(v4) = ipv4_slash16(addr) {
                nets.insert(NetId::V4(v4));
            }
            if let Some(v6) = ipv6_slash32(addr) {
                nets.insert(NetId::V6(v6));
            }
        }
    }
    nets
}

/// Entry — живой guard или живой bootstrap. Middle/exit предпочитают другой /16
/// (IPv6 /32) и другого непустого оператора. Одна и та же нода не бывает entry и exit.
pub fn select_hops(
    connected: impl Iterator<Item = PeerId>,
    bootstrap_ids: &HashSet<PeerId>,
    keys: &HashMap<PeerId, [u8; 32]>,
    addrs: &HashMap<PeerId, Vec<Multiaddr>>,
    policy: &HopPolicy,
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
    let entry = policy
        .guard
        .and_then(|g| entry_pool.iter().find(|(p, _)| *p == g).cloned())
        .unwrap_or_else(|| {
            entry_pool.shuffle(&mut rand::thread_rng());
            entry_pool[0].clone()
        });
    let want = target_hop_count(pool.len());
    pool.retain(|(p, _)| *p != entry.0);
    pool.shuffle(&mut rand::thread_rng());
    let mut hops = vec![entry];
    let mut used_nets = hop_nets(hops[0].0, addrs);
    let mut used_ops: HashSet<String> = policy
        .operators
        .get(&hops[0].0)
        .filter(|s| !s.is_empty())
        .cloned()
        .into_iter()
        .collect();
    let mut rest = pool;
    while hops.len() < want && !rest.is_empty() {
        let better = rest.iter().position(|(p, _)| {
            let nets = hop_nets(*p, addrs);
            let net_ok = nets.is_empty() || nets.is_disjoint(&used_nets);
            let op = policy.operators.get(p).map(String::as_str).unwrap_or("");
            let op_ok = op.is_empty() || !used_ops.contains(op);
            net_ok && op_ok
        });
        let net_only = rest.iter().position(|(p, _)| {
            let nets = hop_nets(*p, addrs);
            nets.is_empty() || nets.is_disjoint(&used_nets)
        });
        let take = better.or(net_only).unwrap_or(0);
        let hop = rest.remove(take);
        used_nets.extend(hop_nets(hop.0, addrs));
        if let Some(op) = policy.operators.get(&hop.0) {
            if !op.is_empty() {
                used_ops.insert(op.clone());
            }
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

// --- VOID_ONION_v2 -----------------------------------------------------------
//
// Cell is exactly one of BUCKETS. Three header slots (124 bytes each) sit in
// front of a body. Alice fills slot i for hop i. Each hop decrypts slot 0,
// XORs the body with its stream, and if it is not the exit shifts the
// remaining slots forward and pads the freed slot with random. Every hop
// therefore sees the same length, so position is not the size.

pub const V2_BUCKETS: [usize; 3] = [2 * 1024, 16 * 1024, 64 * 1024];
const V2_SLOTS: usize = 3;
const V2_SLOT_PLAIN: usize = 64;
const V2_SLOT_CT: usize = V2_SLOT_PLAIN + 16;
pub const V2_SLOT_LEN: usize = 32 + 12 + V2_SLOT_CT;
const V2_HEADER_LEN: usize = V2_SLOT_LEN * V2_SLOTS;
const V2_SALT: &[u8] = b"VOID_ONION_SALT_v2";
const V2_INFO: &[u8] = b"VOID_ONION_v2";

/// Signed hop descriptor. `not_after` is unix seconds.
#[derive(Clone, Debug)]
pub struct HopDesc {
    pub pk: [u8; 32],
    pub epoch: u64,
    pub not_after: u64,
    pub operator: String,
    pub sig2: Vec<u8>,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum V2Peel {
    Forward { next: PeerId, cell: Vec<u8> },
    Deliver { next: PeerId, body: Vec<u8> },
}

fn v2_okm(shared: &[u8; 32], eph: &[u8; 32], hop_pk: &[u8; 32], which: &[u8]) -> Result<[u8; 32]> {
    if shared.iter().all(|&b| b == 0) {
        return Err(anyhow!("onion low-order point"));
    }
    let mut info = Vec::with_capacity(V2_INFO.len() + 64 + which.len());
    info.extend_from_slice(V2_INFO);
    info.extend_from_slice(eph);
    info.extend_from_slice(hop_pk);
    info.extend_from_slice(which);
    let hk = Hkdf::<Sha256>::new(Some(V2_SALT), shared);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|_| anyhow!("onion v2 hkdf"))?;
    Ok(okm)
}

fn xor_stream(key: &[u8; 32], body: &mut [u8]) {
    let mut counter = 0u32;
    let mut off = 0;
    while off < body.len() {
        let hk = Hkdf::<Sha256>::new(Some(key), &counter.to_le_bytes());
        let mut block = [0u8; 32];
        if hk.expand(b"VOID_ONION_v2_STREAM", &mut block).is_err() {
            return;
        }
        let n = (body.len() - off).min(32);
        for i in 0..n {
            body[off + i] ^= block[i];
        }
        off += n;
        counter = counter.wrapping_add(1);
    }
}

fn write_peer(plain: &mut [u8], peer: PeerId) -> bool {
    let raw = peer.to_bytes();
    if raw.len() > 48 || plain.len() < 3 + raw.len() {
        return false;
    }
    plain[2] = raw.len() as u8;
    plain[3..3 + raw.len()].copy_from_slice(&raw);
    true
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_peer(plain: &[u8]) -> Option<PeerId> {
    let n = *plain.get(2)? as usize;
    if n == 0 || n > 48 || plain.len() < 3 + n {
        return None;
    }
    PeerId::from_bytes(&plain[3..3 + n])
}

fn seal_slot<R: RngCore + CryptoRng>(
    rng: &mut R,
    hop_pk: &[u8; 32],
    next: PeerId,
    deliver: bool,
) -> Result<([u8; V2_SLOT_LEN], [u8; 32])> {
    let hop = PublicKey::from(*hop_pk);
    let eph_sk = StaticSecret::random_from_rng(&mut *rng);
    let eph = PublicKey::from(&eph_sk).to_bytes();
    let shared = eph_sk.diffie_hellman(&hop);
    let hdr_key = v2_okm(shared.as_bytes(), &eph, hop_pk, b"HDR")?;
    let stream_key = v2_okm(shared.as_bytes(), &eph, hop_pk, b"STREAM")?;
    let mut plain = [0u8; V2_SLOT_PLAIN];
    rng.fill_bytes(&mut plain);
    plain[0] = 2;
    plain[1] = u8::from(deliver);
    if !write_peer(&mut plain, next) {
        return Err(anyhow!("onion v2 peer id"));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&hdr_key).map_err(|e| anyhow!("{e}"))?;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow!("onion v2 slot"))?;
    if ct.len() != V2_SLOT_CT {
        return Err(anyhow!("onion v2 slot len"));
    }
    let mut slot = [0u8; V2_SLOT_LEN];
    slot[..32].copy_from_slice(&eph);
    slot[32..44].copy_from_slice(&nonce);
    slot[44..].copy_from_slice(&ct);
    Ok((slot, stream_key))
}

fn bucket_for(body_payload: usize) -> Option<usize> {
    V2_BUCKETS
        .into_iter()
        .find(|b| b.saturating_sub(V2_HEADER_LEN) >= body_payload)
}

/// `body` is the opaque deliver blob (already sealed to the recipient).
pub fn wrap_v2(hops: &[(PeerId, [u8; 32])], dest: PeerId, body: &[u8]) -> Result<Vec<u8>> {
    wrap_v2_rng(&mut rand::rngs::OsRng, hops, dest, body)
}

pub fn wrap_v2_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    hops: &[(PeerId, [u8; 32])],
    dest: PeerId,
    body: &[u8],
) -> Result<Vec<u8>> {
    if hops.is_empty() || hops.len() > V2_SLOTS {
        return Err(anyhow!("onion v2 hops"));
    }
    let need = body
        .len()
        .checked_add(4)
        .ok_or_else(|| anyhow!("onion v2 too large"))?;
    let bucket = bucket_for(need).ok_or_else(|| anyhow!("onion v2 too large"))?;
    let body_len = bucket - V2_HEADER_LEN;
    let mut plain_body = vec![0u8; body_len];
    rng.fill_bytes(&mut plain_body);
    plain_body[..4].copy_from_slice(&(body.len() as u32).to_le_bytes());
    plain_body[4..4 + body.len()].copy_from_slice(body);
    let mut slots = vec![[0u8; V2_SLOT_LEN]; V2_SLOTS];
    for i in (0..hops.len()).rev() {
        let deliver = i + 1 == hops.len();
        let next = if deliver { dest } else { hops[i + 1].0 };
        let (slot, stream) = seal_slot(rng, &hops[i].1, next, deliver)?;
        xor_stream(&stream, &mut plain_body);
        slots[i] = slot;
    }
    for slot in slots.iter_mut().skip(hops.len()) {
        rng.fill_bytes(slot);
    }
    let mut cell = Vec::with_capacity(bucket);
    for slot in &slots {
        cell.extend_from_slice(slot);
    }
    cell.extend_from_slice(&plain_body);
    Ok(cell)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn peel_v2(sk: &StaticSecret, cell: &[u8]) -> Result<V2Peel> {
    if !V2_BUCKETS.contains(&cell.len()) || cell.len() < V2_HEADER_LEN {
        return Err(anyhow!("onion v2 size"));
    }
    let hop_pk = PublicKey::from(sk).to_bytes();
    let eph: [u8; 32] = cell[..32].try_into().unwrap();
    let nonce: [u8; 12] = cell[32..44].try_into().unwrap();
    let ct = &cell[44..V2_SLOT_LEN];
    let eph_pk = PublicKey::from(eph);
    let shared = sk.diffie_hellman(&eph_pk);
    let hdr_key = v2_okm(shared.as_bytes(), &eph, &hop_pk, b"HDR")?;
    let stream_key = v2_okm(shared.as_bytes(), &eph, &hop_pk, b"STREAM")?;
    let cipher = ChaCha20Poly1305::new_from_slice(&hdr_key).map_err(|e| anyhow!("{e}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ct)
        .map_err(|_| anyhow!("onion v2 open"))?;
    if plain.len() != V2_SLOT_PLAIN || plain[0] != 2 {
        return Err(anyhow!("onion v2 header"));
    }
    let next = read_peer(&plain).ok_or_else(|| anyhow!("onion v2 next"))?;
    let mut body = cell[V2_HEADER_LEN..].to_vec();
    xor_stream(&stream_key, &mut body);
    if plain[1] == 1 {
        return Ok(V2Peel::Deliver { next, body });
    }
    let mut forwarded = Vec::with_capacity(cell.len());
    forwarded.extend_from_slice(&cell[V2_SLOT_LEN..V2_HEADER_LEN]);
    let mut pad = vec![0u8; V2_SLOT_LEN];
    rand::thread_rng().fill_bytes(&mut pad);
    forwarded.extend_from_slice(&pad);
    forwarded.extend_from_slice(&body);
    if forwarded.len() != cell.len() {
        return Err(anyhow!("onion v2 forward len"));
    }
    Ok(V2Peel::Forward {
        next,
        cell: forwarded,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn peel_v2_any(secrets: &[StaticSecret], cell: &[u8]) -> Result<V2Peel> {
    let mut err = anyhow!("onion v2 open");
    for sk in secrets {
        match peel_v2(sk, cell) {
            Ok(p) => return Ok(p),
            Err(e) => err = e,
        }
    }
    Err(err)
}

const SEAL_INFO: &[u8] = b"VOID_ONION_SEALED_v2";

/// Body the exit forwards. Only the recipient's identity key opens it.
/// Длина печати в начале тела. Exit её видит; внутри бакета это не PeerId.
pub fn deliver_bytes(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 4 {
        return None;
    }
    let n = u32::from_le_bytes(body[..4].try_into().ok()?) as usize;
    body.get(4..4 + n)
}

/// Seal `payload` to the recipient's X25519 identity key (already derived).
pub fn seal_deliver(recipient_pk: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>> {
    seal_deliver_rng(&mut rand::rngs::OsRng, recipient_pk, payload)
}

pub fn seal_deliver_rng<R: RngCore + CryptoRng>(
    rng: &mut R,
    recipient_pk: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if *recipient_pk == [0u8; 32] {
        return Err(anyhow!("onion seal: no identity key"));
    }
    let bob = PublicKey::from(*recipient_pk);
    let eph_sk = StaticSecret::random_from_rng(&mut *rng);
    let eph = PublicKey::from(&eph_sk).to_bytes();
    let shared = eph_sk.diffie_hellman(&bob);
    let mut info = Vec::with_capacity(SEAL_INFO.len() + 64);
    info.extend_from_slice(SEAL_INFO);
    info.extend_from_slice(&eph);
    info.extend_from_slice(bob.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(V2_SALT), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| anyhow!("onion seal hkdf"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let mut plain = Vec::with_capacity(4 + payload.len());
    plain.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plain.extend_from_slice(payload);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| anyhow!("onion seal"))?;
    let mut out = Vec::with_capacity(44 + ct.len());
    out.extend_from_slice(&eph);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_deliver(recipient_sk: &StaticSecret, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 44 + 16 {
        return Err(anyhow!("onion deliver short"));
    }
    let eph: [u8; 32] = body[..32].try_into().unwrap();
    let nonce: [u8; 12] = body[32..44].try_into().unwrap();
    let ct = &body[44..];
    let bob_pk = PublicKey::from(recipient_sk);
    let shared = recipient_sk.diffie_hellman(&PublicKey::from(eph));
    let mut info = Vec::with_capacity(SEAL_INFO.len() + 64);
    info.extend_from_slice(SEAL_INFO);
    info.extend_from_slice(&eph);
    info.extend_from_slice(bob_pk.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(V2_SALT), shared.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| anyhow!("onion seal hkdf"))?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), ct)
        .map_err(|_| anyhow!("onion deliver open"))?;
    let n = u32::from_le_bytes(
        plain
            .get(..4)
            .ok_or_else(|| anyhow!("onion deliver len"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if plain.len() < 4 + n {
        return Err(anyhow!("onion deliver len"));
    }
    Ok(plain[4..4 + n].to_vec())
}

pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    if i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        } else {
            out.push('=');
            out.push('=');
        }
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let pad = (bytes[i + 2] == b'=') as usize + (bytes[i + 3] == b'=') as usize;
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = if bytes[i + 2] == b'=' {
            0
        } else {
            val(bytes[i + 2])?
        };
        let d = if bytes[i + 3] == b'=' {
            0
        } else {
            val(bytes[i + 3])?
        };
        let n = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | d as u32;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        i += 4;
    }
    Some(out)
}

pub fn desc_message(
    peer: PeerId,
    pk: &[u8; 32],
    epoch: u64,
    not_after: u64,
    operator: &str,
) -> Vec<u8> {
    let mut v = b"VOID_ONION_DESC_V2\0".to_vec();
    let id = peer.to_bytes();
    let n = id.len().min(u16::MAX as usize);
    v.extend_from_slice(&(n as u16).to_le_bytes());
    v.extend_from_slice(&id[..n]);
    v.extend_from_slice(pk);
    v.extend_from_slice(&epoch.to_le_bytes());
    v.extend_from_slice(&not_after.to_le_bytes());
    let op = operator.as_bytes();
    let m = op.len().min(32);
    v.extend_from_slice(&(m as u16).to_le_bytes());
    v.extend_from_slice(&op[..m]);
    v
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
        let hops = select_hops(
            std::iter::once(a),
            &ids,
            &keys,
            &HashMap::new(),
            &HopPolicy::default(),
        );
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
        let hops = select_hops(
            std::iter::once(connected),
            &ids,
            &keys,
            &HashMap::new(),
            &HopPolicy::default(),
        );
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
        let hops = select_hops(
            std::iter::empty(),
            &ids,
            &keys,
            &HashMap::new(),
            &HopPolicy::default(),
        );
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

    #[test]
    fn select_hops_prefers_other_slash16() {
        use multiaddr::{Multiaddr, Protocol};
        use std::net::Ipv4Addr;
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let pk = [7u8; 32];
        let keys = HashMap::from([(a, pk), (b, pk), (c, pk)]);
        let ids = HashSet::from([a, b, c]);
        let addr = |o0: u8, o1: u8| {
            let mut m = Multiaddr::empty();
            m.push(Protocol::Ip4(Ipv4Addr::new(o0, o1, 0, 1)));
            m.push(Protocol::Tcp(4001));
            vec![m]
        };
        let addrs = HashMap::from([(a, addr(1, 2)), (b, addr(1, 2)), (c, addr(9, 9))]);
        let hops = select_hops(
            std::iter::once(a),
            &ids,
            &keys,
            &addrs,
            &HopPolicy::default(),
        );
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].0, a);
        assert_eq!(hops[1].0, c);
    }

    #[test]
    fn select_hops_keeps_guard_and_splits_operator() {
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let pk = [7u8; 32];
        let keys = HashMap::from([(a, pk), (b, pk), (c, pk)]);
        let ids = HashSet::from([a, b, c]);
        let policy = HopPolicy {
            guard: Some(a),
            operators: HashMap::from([
                (a, "north".into()),
                (b, "north".into()),
                (c, "south".into()),
            ]),
        };
        let hops = select_hops(std::iter::once(a), &ids, &keys, &HashMap::new(), &policy);
        assert_eq!(hops[0].0, a);
        assert_eq!(hops[1].0, c);
    }

    #[test]
    fn v2_three_hops_keep_length_and_hide_sender() {
        let mut secrets = Vec::new();
        let mut hops = Vec::new();
        for _ in 0..3 {
            let sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
            hops.push((PeerId::random(), PublicKey::from(&sk).to_bytes()));
            secrets.push(sk);
        }
        let bob = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let dest = PeerId::random();
        let sender = PeerId::random();
        let mut payload = sender.to_bytes();
        payload.extend_from_slice(b"hello-v2");
        let sealed = seal_deliver(PublicKey::from(&bob).as_bytes(), &payload).unwrap();
        let cell = wrap_v2(&hops, dest, &sealed).unwrap();
        assert!(V2_BUCKETS.contains(&cell.len()));
        let sender_bytes = sender.to_bytes();
        assert!(!cell
            .windows(sender_bytes.len())
            .any(|w| w == sender_bytes.as_slice()));
        let mut cur = cell;
        for sk in secrets.iter().take(2) {
            match peel_v2(sk, &cur).unwrap() {
                V2Peel::Forward { cell: next, .. } => {
                    assert_eq!(next.len(), cur.len());
                    cur = next;
                }
                V2Peel::Deliver { .. } => panic!("deliver before the exit"),
            }
        }
        match peel_v2(secrets.last().unwrap(), &cur).unwrap() {
            V2Peel::Deliver { next, body } => {
                assert_eq!(next, dest);
                assert!(!body.windows(payload.len()).any(|w| w == payload.as_slice()));
                let opened = open_deliver(&bob, deliver_bytes(&body).unwrap())
                .unwrap();
                assert_eq!(opened, payload);
            }
            V2Peel::Forward { .. } => panic!("exit should deliver"),
        }
    }
}
