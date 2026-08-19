//! libp2p swarm, сетевой цикл и события UI ↔ сеть.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, kad, mdns, noise, ping, relay,
    swarm::{
        behaviour::toggle::Toggle,
        dial_opts::DialOpts,
        NetworkBehaviour, SwarmEvent,
    },
    core::transport::ListenerId,
    tcp, upnp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::bootstrap::{
    addr_endpoint_key, addr_is_quic_v1, addr_is_tcp, bootstrap_tcp_dial_addr,
    canonicalize_bootstrap_ma, expand_transport_variants, parse_seed_dial_addrs,
    peer_id_from_multiaddr, prefer_tcp_if_available, void_bootstrap_multiaddrs,
};
use crate::shared_chat::SharedChatMessages;
use crate::crypto;
use crate::file_transfer;
use crate::offline_mail::{
    decode_mailbox, encode_mailbox, mailbox_record_key, prekey_record_key, seal_for_recipient,
    OfflineEnvelope, MAILBOX_TTL_SECS, OFFLINE_VOICE_CHUNK_KIND,
};
use crate::relay_mailbox::RelayMailbox;
use crate::offline_publish::{
    accept_dht_as_full_handoff, EnvelopeHandoffState, PendingRelayQueue,
};
use crate::protocol::{
    build_delete_ack_json, build_v1_hello, build_voice_ack_json,
    chat_message_id_from_json,     delete_command_message_ids, is_delete_command_json,
    is_read_command_json, new_message_id, parse_decrypted_chat_frame,
    read_command_message_ids, verify_hello_transport_binding, validate_bootstrap_gossip_addrs,
    build_group_sync_json, build_group_leave_json, build_group_delete_json,
    transfer_id_to_hex, transfer_id_from_hex, per_peer_voice_transfer_id, ChatMessage,
    wrap_onion_packet, OnionHopHint,
    DecryptedChatFrame, FileMeta, OutgoingDeliveryStatus, VoiceMeta, V1Packet,
};

struct OnionRuntime {
    keys: HashMap<PeerId, [u8; 32]>,
    bootstraps: HashSet<PeerId>,
    local: PeerId,
    relay_peers: HashSet<PeerId>,
    traces: Vec<OnionTraceItem>,
    live_hops: Vec<String>,
    dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OnionTraceItem {
    pub dir: String,
    pub dest: String,
    pub hops: Vec<String>,
}

static ONION_RT: Mutex<Option<OnionRuntime>> = Mutex::new(None);

const ONION_TRACE_CAP: usize = 8;

fn onion_rt_set_keys(keys: HashMap<PeerId, [u8; 32]>, bootstraps: HashSet<PeerId>, local: PeerId) {
    if let Ok(mut g) = ONION_RT.lock() {
        let (relay_peers, traces, live_hops) = match g.as_ref() {
            Some(rt) => (rt.relay_peers.clone(), rt.traces.clone(), rt.live_hops.clone()),
            None => (HashSet::new(), Vec::new(), Vec::new()),
        };
        *g = Some(OnionRuntime {
            keys,
            bootstraps,
            local,
            relay_peers,
            traces,
            live_hops,
            dirty: true,
        });
    }
}

fn onion_rt_set_relay_peers(relay_peers: HashSet<PeerId>) {
    if let Ok(mut g) = ONION_RT.lock() {
        if let Some(rt) = g.as_mut() {
            rt.relay_peers = relay_peers;
        }
    }
}

fn onion_rt_note(dir: &str, dest: PeerId, hops: &[PeerId]) {
    let item = OnionTraceItem {
        dir: dir.to_string(),
        dest: dest.to_string(),
        hops: hops.iter().map(ToString::to_string).collect(),
    };
    if let Ok(mut g) = ONION_RT.lock() {
        if let Some(rt) = g.as_mut() {
            if rt.traces.last() == Some(&item) {
                return;
            }
            rt.traces.push(item);
            if rt.traces.len() > ONION_TRACE_CAP {
                let extra = rt.traces.len() - ONION_TRACE_CAP;
                rt.traces.drain(0..extra);
            }
            rt.dirty = true;
        }
    }
}

fn onion_rt_poll_ui(
    connected: impl Iterator<Item = PeerId>,
) -> Option<(Vec<String>, Vec<OnionTraceItem>)> {
    let connected: Vec<PeerId> = connected.collect();
    let mut g = ONION_RT.lock().ok()?;
    let rt = g.as_mut()?;
    let hops = crate::onion::select_hops(connected.into_iter(), &rt.bootstraps, &rt.keys);
    let live: Vec<String> = hops.iter().map(|(p, _)| p.to_string()).collect();
    let live_changed = live != rt.live_hops;
    if !rt.dirty && !live_changed {
        return None;
    }
    rt.live_hops = live.clone();
    rt.dirty = false;
    Some((live, rt.traces.clone()))
}

fn is_junk_addr(ma: &Multiaddr) -> bool {
    let ip = ma.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(v4) => Some(std::net::IpAddr::V4(v4)),
        libp2p::multiaddr::Protocol::Ip6(v6) => Some(std::net::IpAddr::V6(v6)),
        _ => None,
    });
    let ip = match ip {
        Some(x) => x,
        None => return false,
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() {
                return true;
            }
            let oct = v4.octets();
            // VirtualBox Host-Only
            if oct[0] == 192 && oct[1] == 168 && oct[2] == 56 {
                return true;
            }
            // Docker/Podman bridge'ы
            if oct[0] == 172 && (17..=25).contains(&oct[1]) {
                return true;
            }
            // Пользовательский список
            if let Ok(s) = std::env::var("VOID_SKIP_SUBNETS") {
                for part in s.split(',') {
                    if cidr_match_v4(part.trim(), v4) {
                        return true;
                    }
                }
            }
            false
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
        }
    }
}

/// Минимальная проверка IPv4 против CIDR-маски `a.b.c.d/nn`.
fn cidr_match_v4(cidr: &str, ip: std::net::Ipv4Addr) -> bool {
    let (addr, bits) = match cidr.split_once('/') {
        Some((a, b)) => (a, b.parse::<u32>().ok()),
        None => return false,
    };
    let Some(bits) = bits else { return false };
    if bits > 32 {
        return false;
    }
    let Ok(net) = addr.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    if bits == 0 {
        return true;
    }
    let mask: u32 = !0u32 << (32 - bits);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}
fn kad_local_addrs_for_peer(
    kad: &mut kad::Behaviour<kad::store::MemoryStore>,
    target: PeerId,
) -> Option<Vec<Multiaddr>> {
    for bucket in kad.kbuckets() {
        for ent in bucket.iter() {
            if *ent.node.key.preimage() == target {
                let v: Vec<Multiaddr> = ent.node.value.iter().cloned().collect();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Все PeerId из **локальной** таблицы Kademlia (маршрутизация XOR, не «все люди в мире»).
fn kad_routing_peer_ids(kad: &mut kad::Behaviour<kad::store::MemoryStore>) -> Vec<PeerId> {
    let mut set: HashSet<PeerId> = HashSet::new();
    for bucket in kad.kbuckets() {
        for ent in bucket.iter() {
            set.insert(*ent.node.key.preimage());
        }
    }
    let mut v: Vec<PeerId> = set.into_iter().collect();
    v.sort_by_key(|p| p.to_string());
    v
}

/// Ключ DHT для регистрации/поиска VOID-клиента по PeerId.
fn peer_dht_record_key(peer_id: PeerId) -> kad::RecordKey {
    kad::RecordKey::new(&peer_id.to_bytes())
}

fn peer_id_from_dht_key(key: &kad::RecordKey) -> Option<PeerId> {
    PeerId::from_bytes(key.as_ref()).ok()
}

/// Объявляем себя провайдером своего PeerId в DHT, чтобы другие клиенты
/// находили нас через `get_providers`, а не только через XOR-близость.
fn publish_self_in_dht(kad: &mut kad::Behaviour<kad::store::MemoryStore>, local_peer_id: PeerId) {
    let key = peer_dht_record_key(local_peer_id);
    if let Err(e) = kad.start_providing(key) {
        debug!("DHT start_providing: {:?}", e);
    }
}

/// Протокол identify у VOID-клиента (см. `identify::Config::new` в `build_void_swarm`).
const VOID_IDENTIFY_PROTOCOL: &str = "/void/v1";

fn peer_advertises_void_chat(info: &identify::Info) -> bool {
    info.protocols
        .iter()
        .any(|p| p.as_ref() == "/void/chat/1.0.0")
}

/// VOID bootstrap-node использует тот же `/void/v1`, но agent `void-bootstrap-node/*`.
fn peer_is_bootstrap_agent(info: &identify::Info) -> bool {
    info.agent_version.starts_with("void-bootstrap-node")
}

fn peer_offers_relay_hop(info: &identify::Info) -> bool {
    info.protocols.iter().any(|p| {
        let s = p.as_ref();
        s.contains("circuit/relay") && s.contains("/hop") && !s.contains("/stop")
    })
}

fn peer_is_void_bootstrap(info: &identify::Info) -> bool {
    peer_is_bootstrap_agent(info) || peer_offers_relay_hop(info)
}

/// Адреса для listen через relay v2: `<relay>/p2p/<relay_id>/p2p-circuit`.
fn relay_circuit_listen_addrs(relay_addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for addr in relay_addrs {
        if addr.to_string().contains("p2p-circuit") || addr_is_quic_v1(addr) || !addr_is_tcp(addr) {
            continue;
        }
        let mut a = addr.clone();
        a.push(libp2p::multiaddr::Protocol::P2pCircuit);
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Адреса для dial через relay: `<relay>/p2p-circuit/p2p/<target>`.
fn relay_circuit_dial_addrs(relay_addrs: &[Multiaddr], target: PeerId) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for addr in relay_addrs {
        if addr.to_string().contains("p2p-circuit") {
            continue;
        }
        let mut a = addr.clone();
        a.push(libp2p::multiaddr::Protocol::P2pCircuit);
        a.push(libp2p::multiaddr::Protocol::P2p(target));
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Адреса, по которым собеседник может набрать НАС через VOID relay.
fn our_circuit_dial_hints(
    local_peer_id: PeerId,
    void_bootstraps: &[Multiaddr],
    local_listen_addrs: &HashSet<Multiaddr>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ma in local_listen_addrs {
        let s = ma.to_string();
        if !s.contains("p2p-circuit") {
            continue;
        }
        let mut dial = ma.clone();
        let has_self = dial.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(pid) if pid == local_peer_id));
        if !has_self {
            dial.push(libp2p::multiaddr::Protocol::P2p(local_peer_id));
        }
        let ds = dial.to_string();
        if !out.contains(&ds) {
            out.push(ds);
        }
    }
    for circuit in relay_circuit_dial_addrs(void_bootstraps, local_peer_id) {
        let s = circuit.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn send_dial_back_hint(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer: PeerId,
    local_peer_id: PeerId,
    void_bootstraps: &[Multiaddr],
    local_listen_addrs: &HashSet<Multiaddr>,
) {
    let circuit_addrs =
        our_circuit_dial_hints(local_peer_id, void_bootstraps, local_listen_addrs);
    if circuit_addrs.is_empty() {
        return;
    }
    let _ = swarm.behaviour_mut().request_response.send_request(
        &peer,
        V1Packet::DialBack { circuit_addrs },
    );
}

fn bootstrap_peer_ids_from(void_bootstraps: &[Multiaddr]) -> HashSet<PeerId> {
    void_bootstraps
        .iter()
        .filter_map(|ma| peer_id_from_multiaddr(ma))
        .collect()
}

fn merge_bootstraps_into_swarm(
    _swarm: &mut libp2p::Swarm<ChatBehaviour>,
    void_bootstraps: &mut Vec<Multiaddr>,
    bootstrap_peer_ids: &mut HashSet<PeerId>,
    new_addrs: &[Multiaddr],
) -> usize {
    let mut added = 0usize;
    for ma in new_addrs {
        let Some(ma) = canonicalize_bootstrap_ma(ma) else {
            continue;
        };
        let key = addr_endpoint_key(&ma);
        if !key.is_empty() && !key.ends_with("//") {
            if let Some(pos) = void_bootstraps
                .iter()
                .position(|old| addr_endpoint_key(old) == key)
            {
                if void_bootstraps[pos] != ma {
                    void_bootstraps[pos] = ma;
                    added += 1;
                }
                continue;
            }
        }
        if !void_bootstraps.contains(&ma) {
            void_bootstraps.push(ma);
            added += 1;
        }
    }
    if added > 0 {
        void_bootstraps.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        void_bootstraps.dedup_by(|a, b| a == b);
        *bootstrap_peer_ids = bootstrap_peer_ids_from(void_bootstraps);
        // Не dial здесь: второй TCP к ноде (тот же host / другая нода)
        // рвёт HOP-стрим. Набор — через dial_missing_bootstraps после Hop.
    }
    added
}

fn bootstrap_gossip_strings(void_bootstraps: &[Multiaddr]) -> Vec<String> {
    void_bootstraps.iter().map(|a| a.to_string()).collect()
}

fn collect_onion_hints(
    keys: &HashMap<PeerId, [u8; 32]>,
    void_bootstraps: &[Multiaddr],
) -> Vec<OnionHopHint> {
    keys.iter()
        .take(32)
        .map(|(pid, pk)| OnionHopHint {
            peer_id: pid.to_string(),
            pk_hex: crate::onion::hex32(pk),
            addrs: void_bootstraps
                .iter()
                .filter(|ma| peer_id_from_multiaddr(ma) == Some(*pid))
                .map(|ma| ma.to_string())
                .collect(),
        })
        .collect()
}

fn ingest_onion_hints(
    hints: &[OnionHopHint],
    onion_keys: &mut HashMap<PeerId, [u8; 32]>,
    bootstrap_peer_ids: &mut HashSet<PeerId>,
    void_bootstraps: &mut Vec<Multiaddr>,
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
) -> usize {
    let mut added = 0usize;
    let mut extra_addrs: Vec<Multiaddr> = Vec::new();
    for hint in hints {
        let Ok(pid) = hint.peer_id.parse::<PeerId>() else {
            continue;
        };
        if pid == local_peer_id {
            continue;
        }
        let Some(pk) = crate::onion::parse_hex32(&hint.pk_hex) else {
            continue;
        };
        if onion_keys.insert(pid, pk).is_none() {
            added += 1;
        }
        bootstrap_peer_ids.insert(pid);
        for s in &hint.addrs {
            if let Ok(ma) = s.parse::<Multiaddr>() {
                extra_addrs.push(ma);
            }
        }
    }
    if !extra_addrs.is_empty() {
        added += merge_bootstraps_into_swarm(
            swarm,
            void_bootstraps,
            bootstrap_peer_ids,
            &extra_addrs,
        );
    }
    added
}

/// Эпидемический обмен bootstrap-нодами: рассылаем список всем подключённым VOID-клиентам.
fn fanout_bootstrap_gossip(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    bootstrap_peer_ids: &HashSet<PeerId>,
    addrs: Vec<String>,
    onion_keys: Vec<OnionHopHint>,
    exclude: Option<PeerId>,
) {
    if addrs.is_empty() && onion_keys.is_empty() {
        return;
    }
    let targets: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|p| {
            *p != local_peer_id
                && exclude != Some(*p)
                && !bootstrap_peer_ids.contains(p)
        })
        .collect();
    for peer in targets {
        let _ = swarm.behaviour_mut().request_response.send_request(
            &peer,
            V1Packet::BootstrapGossip {
                addrs: addrs.clone(),
                onion_keys: onion_keys.clone(),
            },
        );
    }
}

fn expand_dial_addrs(
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    bootstrap_addrs: &[Multiaddr],
) -> Vec<Multiaddr> {
    let mut direct: Vec<Multiaddr> = Vec::new();
    for a in addrs.into_iter().filter(|a| !is_junk_addr(a)) {
        for v in expand_transport_variants(&a) {
            if !is_junk_addr(&v) && !direct.contains(&v) {
                direct.push(v);
            }
        }
    }
    // Prefer LAN, then TCP. Never dial QUIC in the same attempt as TCP:
    // libp2p concurrent-dial aborts the TCP session when QUIC "wins".
    direct = prefer_tcp_if_available(direct);
    // Два TCP на тот же host:port (vault + Identify) → concurrent dial → оба Closed.
    {
        let mut seen: HashSet<String> = HashSet::new();
        direct.retain(|a| {
            let s = a.to_string();
            let base = s.split("/p2p/").next().unwrap_or(&s);
            seen.insert(base.to_string())
        });
    }
    direct.sort_by_key(|a| if is_likely_lan_addr(a) { 0u8 } else { 1u8 });
    let _ = (peer_id, bootstrap_addrs);
    // Circuit только через dial_peer_live_circuits. Иначе LAN/best-effort
    // шлёт STOP на том же TCP, что и Reserve → NoReservation пачками и Hop…
    direct
}

fn is_likely_lan_addr(ma: &Multiaddr) -> bool {
    let ip = ma.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(v4) => Some(v4),
        _ => None,
    });
    match ip {
        Some(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
        }
        None => false,
    }
}

fn is_circuit_addr(ma: &Multiaddr) -> bool {
    ma.iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
}

/// Прямой TCP к VOID-ноде. Circuit `/p2p-circuit/p2p/<контакт>` идёт через тот же
/// host:port, но это сессия с чат-пиром, не с bootstrap.
fn is_direct_bootstrap_tcp(address: &Multiaddr, void_bootstraps: &[Multiaddr]) -> bool {
    if is_void_bootstrap_host(address) {
        return true;
    }
    if is_circuit_addr(address) || addr_is_quic_v1(address) || !addr_is_tcp(address) {
        return false;
    }
    let ep = addr_endpoint_key(address);
    if ep.is_empty() || ep.ends_with("//") {
        return false;
    }
    void_bootstraps.iter().any(|b| addr_endpoint_key(b) == ep)
}

fn is_void_bootstrap_host(ma: &Multiaddr) -> bool {
    if is_circuit_addr(ma) || addr_is_quic_v1(ma) || !addr_is_tcp(ma) {
        return false;
    }
    ma.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => ip.octets() == [147, 78, 64, 22],
        _ => false,
    })
}

fn void_node_tcp_addr() -> Multiaddr {
    "/ip4/147.78.64.22/tcp/4001"
        .parse()
        .expect("static void node tcp")
}

fn connected_point_remote_tcp(
    endpoint: &libp2p::core::ConnectedPoint,
) -> Option<&Multiaddr> {
    match endpoint {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => Some(address),
        libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => Some(send_back_addr),
    }
}

fn connected_point_is_circuit(endpoint: &libp2p::core::ConnectedPoint) -> bool {
    match endpoint {
        libp2p::core::ConnectedPoint::Dialer { address, .. } => is_circuit_addr(address),
        libp2p::core::ConnectedPoint::Listener {
            local_addr,
            send_back_addr,
            ..
        } => is_circuit_addr(local_addr) || is_circuit_addr(send_back_addr),
    }
}

/// Адрес чат-контакта, по которому безопасно redial (LAN / circuit).
/// Публичные ephemeral NAT listen (Identify / Listener) — яд: dial к ним
/// висит и через NotDialing блокирует набор Windows↔Mac.
fn is_usable_contact_redial_addr(ma: &Multiaddr) -> bool {
    !is_junk_addr(ma) && (is_circuit_addr(ma) || is_likely_lan_addr(ma))
}

fn normalize_peer_addr(mut addr: Multiaddr, peer_id: PeerId) -> Multiaddr {
    if !addr
        .iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
    {
        addr.push(libp2p::multiaddr::Protocol::P2p(peer_id));
    }
    addr
}

fn strip_p2p_protocols(ma: Multiaddr) -> Multiaddr {
    ma.into_iter()
        .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        .collect()
}

#[derive(Default)]
struct BootstrapEpGate {
    inflight: HashSet<String>,
    inflight_at: HashMap<String, Instant>,
    live: HashSet<String>,
    cooldown_until: HashMap<String, Instant>,
}

fn bootstrap_ep_gate() -> std::sync::MutexGuard<'static, BootstrapEpGate> {
    static G: std::sync::OnceLock<std::sync::Mutex<BootstrapEpGate>> = std::sync::OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(BootstrapEpGate::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn bootstrap_ep_mark_live(addr: &Multiaddr, live: bool) {
    if is_circuit_addr(addr) {
        return;
    }
    let key = addr_endpoint_key(addr);
    if key.is_empty() || key.ends_with("//") {
        return;
    }
    let mut g = bootstrap_ep_gate();
    g.inflight.remove(&key);
    g.inflight_at.remove(&key);
    if live {
        g.live.insert(key.clone());
        g.cooldown_until.remove(&key);
    } else {
        g.live.remove(&key);
        g.cooldown_until
            .insert(key, Instant::now() + Duration::from_secs(2));
    }
}

fn bootstrap_ep_expire_stale() {
    let mut g = bootstrap_ep_gate();
    let now = Instant::now();
    let stale: Vec<String> = g
        .inflight_at
        .iter()
        .filter(|(_, at)| now.saturating_duration_since(**at) >= Duration::from_secs(8))
        .map(|(k, _)| k.clone())
        .collect();
    for k in stale {
        g.inflight.remove(&k);
        g.inflight_at.remove(&k);
        g.cooldown_until
            .insert(k, now + Duration::from_secs(2));
    }
}

/// Ровно один исходящий TCP на host:port. Без /p2p/ в dial: неверный PeerId
/// в vault (старый ключ ноды / PeerId контакта) иначе рвёт yamux сразу после Noise.
fn dial_bootstrap_direct(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
) {
    let _ = peer_id;
    bootstrap_ep_expire_stale();
    let Some(ma) = addrs.iter().find_map(bootstrap_tcp_dial_addr) else {
        return;
    };
    if is_junk_addr(&ma) || !addr_is_tcp(&ma) || addr_is_quic_v1(&ma) || is_circuit_addr(&ma) {
        return;
    }
    let key = addr_endpoint_key(&ma);
    let known = is_void_bootstrap_host(&ma);
    {
        let mut g = bootstrap_ep_gate();
        // Контакт в LAN не должен блокировать набор ноды. Пропускаем только
        // этот же host:port, если он уже живой или в полёте.
        if g.live.contains(&key) || g.inflight.contains(&key) {
            return;
        }
        if !known {
            if g.live.iter().any(|k| k.starts_with("147.78.64.22/")) {
                return;
            }
        }
        if g.cooldown_until
            .get(&key)
            .is_some_and(|until| Instant::now() < *until)
        {
            return;
        }
        g.inflight.insert(key.clone());
        g.inflight_at.insert(key.clone(), Instant::now());
    }
    info!("bootstrap TCP (без проверки /p2p/) → {}", ma);
    let opts = DialOpts::unknown_peer_id().address(ma).build();
    if let Err(e) = swarm.dial(opts) {
        let mut g = bootstrap_ep_gate();
        g.inflight.remove(&key);
        g.inflight_at.remove(&key);
        let s = format!("{:?}", e);
        if !s.contains("Condition") {
            warn!("bootstrap dial {}: {:?}", key, e);
        }
    }
}

fn swarm_has_bootstrap_tcp(
    swarm: &libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
) -> bool {
    swarm
        .connected_peers()
        .any(|p| bootstrap_peer_ids.contains(p))
}

fn ensure_void_node_dial(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
) {
    if swarm_has_bootstrap_tcp(swarm, bootstrap_peer_ids) {
        return;
    }
    // После обрыва TCP флаг live часто остаётся → набор ноды стопорится
    // навсегда, UI «нет связи с bootstrap».
    {
        let mut g = bootstrap_ep_gate();
        g.live.retain(|k| !k.starts_with("147.78.64.22/"));
    }
    dial_bootstrap_direct(swarm, *swarm.local_peer_id(), vec![void_node_tcp_addr()]);
}

fn circuit_fail_at() -> std::sync::MutexGuard<'static, HashMap<PeerId, Instant>> {
    static G: std::sync::OnceLock<std::sync::Mutex<HashMap<PeerId, Instant>>> =
        std::sync::OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn note_circuit_fail(peer: PeerId) {
    circuit_fail_at().insert(peer, Instant::now());
}

fn circuit_recently_failed(peer: &PeerId) -> bool {
    circuit_fail_at()
        .get(peer)
        .is_some_and(|t| t.elapsed() < Duration::from_secs(45))
}

fn hop_ok_at() -> std::sync::MutexGuard<'static, Option<Instant>> {
    static G: std::sync::OnceLock<std::sync::Mutex<Option<Instant>>> = std::sync::OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn note_hop_ok() {
    let mut g = hop_ok_at();
    if g.is_none() {
        *g = Some(Instant::now());
    }
}

fn hop_ok_settled() -> bool {
    hop_ok_at().is_some_and(|t| t.elapsed() >= Duration::from_secs(8))
}

fn dial_peer_best_effort(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    bootstrap_addrs: &[Multiaddr],
) {
    dial_peer_with_condition(
        swarm,
        peer_id,
        addrs,
        bootstrap_addrs,
        libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing,
        false,
    );
}

/// Circuit через VOID bootstrap-relay (без прямых NAT-адресов).
/// Живые relay первыми, затем остальные из списка: резервация пира может
/// быть на другой ноде, чем та, к которой мы сейчас подключены — иначе
/// Windows↔Mac «в разных сетях» через VOID не сходятся.
fn dial_peer_live_circuits(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer_id: PeerId,
    bootstrap_addrs: &[Multiaddr],
    force: bool,
) {
    // Circuit-dial к контакту идёт через тот же TCP к ноде, что и Reserve.
    // До Hop Ack это второй dial на bootstrap → yamux рвёт HOP-стрим, UI
    // вечно на «Hop…», контакты 0. Резервация получателя нужна, чтобы нас
    // приняли; наша — чтобы этот dial не убил listen_on.
    if !hop_ok_settled() {
        return;
    }
    if circuit_recently_failed(&peer_id) {
        return;
    }
    let condition = if force {
        libp2p::swarm::dial_opts::PeerCondition::Always
    } else {
        libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing
    };
    dial_peer_with_condition(swarm, peer_id, Vec::new(), bootstrap_addrs, condition, true);
}

fn dial_peer_with_condition(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    bootstrap_addrs: &[Multiaddr],
    condition: libp2p::swarm::dial_opts::PeerCondition,
    circuits_only: bool,
) {
    // Живые bootstrap/relay первыми — быстрее; cold тоже нужны: пир мог
    // зарезервировать circuit на другой VOID-ноде.
    let mut live_boot = Vec::new();
    let mut cold_boot = Vec::new();
    {
        let live_eps = bootstrap_ep_gate().live.clone();
        for ma in bootstrap_addrs {
            let k = addr_endpoint_key(ma);
            if live_eps.contains(&k) {
                live_boot.push(ma.clone());
            } else {
                cold_boot.push(ma.clone());
            }
        }
    }
    if circuits_only && live_boot.is_empty() && cold_boot.is_empty() {
        debug!(
            "dial skip {} — нет bootstrap для circuit",
            &peer_id.to_string()[..8.min(peer_id.to_string().len())]
        );
        return;
    }
    // Без хотя бы одного живого bootstrap VOID-сеть ещё не поднята —
    // cold-only circuit часто бесполезен и только занимает NotDialing.
    // Но если live есть — обязательно пробуем и cold (другая нода пира).
    if circuits_only && live_boot.is_empty() {
        debug!(
            "dial skip {} — нет живого bootstrap (VOID offline)",
            &peer_id.to_string()[..8.min(peer_id.to_string().len())]
        );
        return;
    }
    // Circuit только через уже живой relay, один адрес. Cold + пачка
    // multiaddr → несколько STOP на том же HOP-conn → NoReservation спам
    // и ConnectionReset ноды.
    let boot = live_boot;
    let clean = if circuits_only {
        boot.iter()
            .find(|ma| addr_is_tcp(ma) && !addr_is_quic_v1(ma) && !is_circuit_addr(ma))
            .and_then(|relay_ma| {
                relay_circuit_dial_addrs(std::slice::from_ref(relay_ma), peer_id)
                    .into_iter()
                    .next()
            })
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        expand_dial_addrs(peer_id, addrs, &boot)
    };
    if clean.is_empty() && circuits_only {
        return;
    }
    let opts = if clean.is_empty() {
        DialOpts::peer_id(peer_id).condition(condition).build()
    } else {
        DialOpts::peer_id(peer_id)
            .condition(condition)
            .addresses(clean)
            .build()
    };
    if let Err(e) = swarm.dial(opts) {
        let s = format!("{:?}", e);
        if !s.contains("Condition") {
            debug!(
                "dial {}: {:?}",
                &peer_id.to_string()[..8.min(peer_id.to_string().len())],
                e
            );
        }
    }
}

/// Запоминаем контакт для периодического dial (даже без известных multiaddr —
/// хватит p2p-circuit через живой bootstrap).
fn watch_contact_peer(
    reconnect_targets: &mut HashMap<PeerId, Vec<Multiaddr>>,
    peer_id: PeerId,
    bootstrap_peer_ids: &HashSet<PeerId>,
    local_peer_id: PeerId,
) {
    if peer_id == local_peer_id || bootstrap_peer_ids.contains(&peer_id) {
        return;
    }
    reconnect_targets.entry(peer_id).or_default();
}

/// Dial vault contacts that are not live yet (direct + bootstrap circuit).
fn dial_unconnected_contacts(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    reconnect_targets: &HashMap<PeerId, Vec<Multiaddr>>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    contact_dial_at: &mut HashMap<PeerId, Instant>,
    min_interval: Duration,
    hop_ready: bool,
) {
    let connected: HashSet<PeerId> = swarm.connected_peers().copied().collect();
    let boot_live = bootstrap_peer_ids.iter().any(|b| connected.contains(b));
    let now = Instant::now();
    for (pid, addrs) in reconnect_targets {
        if bootstrap_peer_ids.contains(pid) || connected.contains(pid) {
            continue;
        }
        if contact_dial_at
            .get(pid)
            .is_some_and(|t| now.duration_since(*t) < min_interval)
        {
            continue;
        }
        contact_dial_at.insert(*pid, now);
        if boot_live && hop_ready {
            dial_peer_live_circuits(swarm, *pid, void_bootstraps, false);
        }
        // LAN/mDNS (без public ephemeral) — вторым заходом.
        let lan: Vec<Multiaddr> = addrs
            .iter()
            .filter(|a| is_usable_contact_redial_addr(a) && !is_circuit_addr(a))
            .cloned()
            .collect();
        if !lan.is_empty() {
            dial_peer_best_effort(swarm, *pid, lan, void_bootstraps);
        }
    }
}

/// Circuit listen addr for a live bootstrap: `/ip4/…/tcp/…/p2p/<relay>/p2p-circuit`.
/// `hop_addrs` — proven TCP dialer endpoint (ConnectionEstablished). Vault/reconnect — запас.
fn hop_circuit_listen_addr(
    relay_pid: PeerId,
    hop_addrs: &HashMap<PeerId, Multiaddr>,
    void_bootstraps: &[Multiaddr],
    reconnect_targets: &HashMap<PeerId, Vec<Multiaddr>>,
) -> Option<Multiaddr> {
    let mut candidates: Vec<Multiaddr> = Vec::new();
    if let Some(a) = hop_addrs.get(&relay_pid) {
        candidates.push(a.clone());
    }
    if let Some(extra) = reconnect_targets.get(&relay_pid) {
        candidates.extend(extra.iter().cloned());
    }
    for ma in void_bootstraps {
        if peer_id_from_multiaddr(ma) == Some(relay_pid) {
            candidates.push(ma.clone());
            continue;
        }
        if hop_addrs.get(&relay_pid).is_some_and(|e| addr_endpoint_key(e) == addr_endpoint_key(ma))
            || reconnect_targets.get(&relay_pid).is_some_and(|list| {
                list.iter()
                    .any(|e| addr_endpoint_key(e) == addr_endpoint_key(ma))
            })
        {
            candidates.push(ma.clone());
        }
    }
    for raw in &candidates {
        if addr_is_quic_v1(raw) || is_circuit_addr(raw) || is_junk_addr(raw) || !addr_is_tcp(raw) {
            continue;
        }
        let a = normalize_peer_addr(strip_p2p_protocols(raw.clone()), relay_pid);
        if let Some(ma) = relay_circuit_listen_addrs(std::slice::from_ref(&a))
            .into_iter()
            .next()
        {
            return Some(ma);
        }
    }
    None
}

fn circuit_listen_relays(swarm: &libp2p::Swarm<ChatBehaviour>) -> Vec<(PeerId, Multiaddr)> {
    swarm
        .listeners()
        .chain(swarm.external_addresses())
        .filter_map(|a| relay_peer_id_from_circuit_addr(a).map(|p| (p, a.clone())))
        .collect()
}

/// listen_on(/p2p-circuit) for each live bootstrap that has no confirmed Hop yet.
/// One listener per relay: a second listen_on opens another HOP stream and the
/// relay client drops Reserve at capacity 10 → UI stays «нет Hop».
fn ensure_bootstrap_relay_listens(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    reconnect_targets: &HashMap<PeerId, Vec<Multiaddr>>,
    hop_addrs: &HashMap<PeerId, Multiaddr>,
    relay_circuit_reserved: &HashSet<PeerId>,
    relay_listen_attempt_at: &mut HashMap<PeerId, Instant>,
    relay_hop_pending: &mut HashSet<PeerId>,
    relay_hop_listeners: &mut HashMap<PeerId, ListenerId>,
    min_retry: Duration,
    event_tx: Option<&mpsc::Sender<NetworkEvent>>,
) {
    let now = Instant::now();
    for &relay_pid in bootstrap_peer_ids {
        if !swarm.is_connected(&relay_pid) {
            relay_hop_pending.remove(&relay_pid);
            relay_listen_attempt_at.remove(&relay_pid);
            continue;
        }
        if relay_circuit_reserved.contains(&relay_pid) {
            relay_hop_pending.remove(&relay_pid);
            continue;
        }
        // Один listen_on на это TCP. Повтор каждые 3 с рвал рабочий Reserve
        // на ноде: Ack не доходил, UI вечно «Hop…».
        if relay_hop_listeners.contains_key(&relay_pid)
            || relay_hop_pending.contains(&relay_pid)
            || relay_listen_attempt_at.contains_key(&relay_pid)
        {
            continue;
        }
        if relay_listen_attempt_at
            .get(&relay_pid)
            .is_some_and(|t| now.duration_since(*t) < min_retry)
        {
            continue;
        }
        let Some(ma) = hop_circuit_listen_addr(
            relay_pid,
            hop_addrs,
            void_bootstraps,
            reconnect_targets,
        )
        else {
            debug!(
                "📡 relay Hop: нет multiaddr для {} — пропуск",
                &relay_pid.to_string()[..8.min(relay_pid.to_string().len())]
            );
            if let Some(tx) = event_tx {
                let _ = tx.try_send(NetworkEvent::Status(format!(
                    "⚠ Hop: нет адреса bootstrap {} в vault",
                    &relay_pid.to_string()[..8.min(relay_pid.to_string().len())]
                )));
            }
            continue;
        };
        relay_listen_attempt_at.insert(relay_pid, now);
        match swarm.listen_on(ma.clone()) {
            Ok(lid) => {
                relay_hop_listeners.insert(relay_pid, lid);
                relay_hop_pending.insert(relay_pid);
                info!("relay Hop listen → {}", ma);
                if let Some(tx) = event_tx {
                    let _ = tx.try_send(NetworkEvent::RelayHopPending { relay: relay_pid });
                    let _ = tx.try_send(NetworkEvent::Status(format!(
                        "📡 Запрос Hop на {}…",
                        &relay_pid.to_string()[..8.min(relay_pid.to_string().len())]
                    )));
                }
            }
            Err(e) => {
                warn!("Hop listen {}: {:?}", ma, e);
                if let Some(tx) = event_tx {
                    let _ = tx.try_send(NetworkEvent::Status(format!(
                        "⚠ Hop listen не стартовал на {} — проверьте bootstrap multiaddr (/ip4/…/p2p/…)",
                        &relay_pid.to_string()[..8.min(relay_pid.to_string().len())]
                    )));
                }
            }
        }
    }
}

fn relay_peer_id_from_circuit_addr(addr: &Multiaddr) -> Option<PeerId> {
    let s = addr.to_string();
    if !s.contains("p2p-circuit") {
        return None;
    }
    // …/p2p/<relay>/p2p-circuit[/p2p/<self>]
    let mut last_before_circuit: Option<PeerId> = None;
    for p in addr.iter() {
        match p {
            libp2p::multiaddr::Protocol::P2pCircuit => break,
            libp2p::multiaddr::Protocol::P2p(pid) => last_before_circuit = Some(pid),
            _ => {}
        }
    }
    last_before_circuit
}

fn emit_hop_ready(event_tx: &mpsc::Sender<NetworkEvent>, relay: PeerId, addr: Option<Multiaddr>) {
    note_hop_ok();
    if let Some(a) = addr {
        let _ = event_tx.try_send(NetworkEvent::NewListenAddr(a));
    }
    let _ = event_tx.try_send(NetworkEvent::RelayHopReady { relay });
    let _ = event_tx.try_send(NetworkEvent::Status("СВЯЗЬ ЧЕРЕЗ RELAY — Hop OK".into()));
}

/// listen_on уже ушёл, нода в логах приняла Reserve, а Ack/NewListenAddr
/// часто не доходят до UI. Не ждём hop_tick: chunk_tick 20 мс не голодает.
fn promote_pending_hop_if_due(
    swarm: &libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    relay_circuit_reserved: &mut HashSet<PeerId>,
    relay_hop_pending: &mut HashSet<PeerId>,
    hop_listen_after: &mut HashMap<PeerId, Instant>,
    relay_listen_attempt_at: &HashMap<PeerId, Instant>,
    event_tx: &mpsc::Sender<NetworkEvent>,
) {
    let pending_now: Vec<PeerId> = relay_hop_pending.iter().copied().collect();
    if pending_now.is_empty() {
        return;
    }
    let live_boot = bootstrap_peer_ids
        .iter()
        .copied()
        .find(|b| swarm.is_connected(b));
    for relay in pending_now {
        if relay_circuit_reserved.contains(&relay) {
            relay_hop_pending.remove(&relay);
            continue;
        }
        let waited = relay_listen_attempt_at
            .get(&relay)
            .map(|t| t.elapsed())
            .unwrap_or(Duration::from_secs(30));
        if waited < Duration::from_secs(2) {
            continue;
        }
        let ready_id = if swarm.is_connected(&relay) {
            relay
        } else if let Some(b) = live_boot {
            b
        } else {
            continue;
        };
        relay_circuit_reserved.insert(ready_id);
        relay_hop_pending.remove(&relay);
        hop_listen_after.remove(&relay);
        hop_listen_after.remove(&ready_id);
        let addr = circuit_listen_relays(swarm)
            .into_iter()
            .find(|(p, _)| *p == ready_id)
            .map(|(_, a)| a);
        info!(
            "Hop OK (listen_on + {}s)",
            waited.as_secs()
        );
        emit_hop_ready(event_tx, ready_id, addr);
    }
}

/// Force circuit + LAN redial after zombie / RR failure.
fn redial_contact_hard(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer: PeerId,
    reconnect_targets: &HashMap<PeerId, Vec<Multiaddr>>,
    void_bootstraps: &[Multiaddr],
) {
    dial_peer_live_circuits(swarm, peer, void_bootstraps, false);
    if let Some(addrs) = reconnect_targets.get(&peer) {
        let lan: Vec<Multiaddr> = addrs
            .iter()
            .filter(|a| is_usable_contact_redial_addr(a) && !is_circuit_addr(a))
            .cloned()
            .collect();
        if !lan.is_empty() {
            dial_peer_with_condition(
                swarm,
                peer,
                lan,
                void_bootstraps,
                libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing,
                false,
            );
        }
    }
}

#[cfg_attr(not(feature = "egui-ui"), allow(dead_code))]
pub(crate) enum NetworkEvent {
    NewListenAddr(Multiaddr),
    MdnsDiscovered(PeerId, Multiaddr),
    MdnsExpired(PeerId),
    Connected(PeerId),
    Disconnected(PeerId),
    ChatMessage(ChatMessage),
    /// Входящая синхронизация группы от участника.
    GroupSync {
        from: PeerId,
        group_id: String,
        group_name: String,
        creator_id: String,
        members: Vec<crate::group::GroupMember>,
    },
    GroupLeave {
        from: PeerId,
        group_id: String,
        peer_id: String,
    },
    GroupDelete {
        from: PeerId,
        group_id: String,
    },
    Status(String),
    PublicIpConfirmed(String),
    /// Снимок PeerId в локальной таблице Kademlia (для UI «узлы сети»).
    DhtRoutingPeers { total: usize, lines: Vec<String> },
    /// Отправка пиру упала с DialFailure — UI должен сделать DHT-lookup и retry.
    SendFailedDial(PeerId),
    /// Отправка упала с `UnsupportedProtocols`: пир не поддерживает
    /// `/void/chat/1.0.0`. Он НЕ собеседник (это bootstrap/relay/чужая версия
    /// VOID). UI должен удалить его из контактов и не ретраить.
    SendFailedUnsupported(PeerId),
    /// Identify подтвердил, что пир не объявляет `/void/chat/1.0.0`.
    /// UI должен пометить его как DHT-узел и вычистить из `known_peers`.
    PeerIsNotVoidChat(PeerId),
    /// Мы только что узнали рабочий адрес пира (после успешного dial / Identify
    /// / входящего коннекта). UI сохранит его в `contact_addrs` — тогда после
    /// рестарта связь с этим контактом поднимется сама.
    PeerAddress(PeerId, Multiaddr),
    /// Новые bootstrap-ноды узнаны из сети — сохранить в vault.
    BootstrapsLearned(Vec<String>),
    /// Прямой TCP к VOID-ноде (не circuit к контакту). UI считает bootstrap, не контакт.
    BootstrapSession { peer: PeerId, up: bool },
    /// Hop ReservationReqAccepted — мы реально reachable через VOID relay.
    RelayHopReady { relay: PeerId },
    /// listen_on(…/p2p-circuit) отправлен, ждём Ack.
    RelayHopPending { relay: PeerId },
    /// Circuit listener закрыт / резервация сброшена.
    RelayHopLost { relay: PeerId },
    /// Текущий onion-маршрут и последние проходы пакетов (UI «Настройки»).
    OnionRoutes {
        hops: Vec<String>,
        traces: Vec<OnionTraceItem>,
    },
    /// Получен Response (Ack) на ранее отправленное сообщение — доставка подтверждена.
    MessageDelivered { peer: PeerId, message_id: String },
    /// Собеседник прочитал наши сообщения.
    MessageRead { peer: PeerId, message_ids: Vec<String> },
    /// Read receipt ушёл в сеть (локально помечаем, что повтор не нужен).
    ReadReceiptSent { peer: PeerId, message_ids: Vec<String> },
    /// Сообщение буферизовано до E2EE-хендшейка — UI не должен торопиться с таймаутом.
    MessageAwaitingSession(PeerId),
    /// Зашифрованный пакет чата реально ушёл в сеть (не только в буфер).
    MessageOnWire { peer: PeerId, message_id: String },
    /// Офлайн-почта из DHT (зашифрованные конверты для локальной расшифровки).
    OfflineMailbox(Vec<OfflineEnvelope>),
    /// Публичный X25519 ключ пира (Hello / DHT prekey).
    PeerPrekey { peer: PeerId, public_key: [u8; 32] },
    /// Офлайн-почта опубликована в DHT.
    OfflineMailboxPublished,
    /// Отправка файла отложена — нет E2EE-сессии с пиром.
    FileSendDeferred {
        recipient: PeerId,
        path: String,
        kind: file_transfer::FileKind,
    },
    /// Голосовое сообщение отложено — нет E2EE-сессии.
    VoiceSendDeferred {
        recipient: PeerId,
        path: String,
        duration_secs: f32,
        message_id: String,
        transfer_id: [u8; 16],
    },
    // ─── Файловый sub-протокол ──────────────────────────────────────────────
    /// Входящее предложение файла — пользователь должен принять или отклонить.
    FileOffer {
        transfer_id: [u8; 16],
        from: PeerId,
        filename: String,
        total_size: u64,
        kind: file_transfer::FileKind,
    },
    /// Обновление прогресса передачи.
    FileProgress {
        transfer_id: [u8; 16],
        sent_chunks: u32,
        total_chunks: u32,
        filename: String,
        total_size: u64,
        is_outgoing: bool,
        peer: PeerId,
        kind: file_transfer::FileKind,
    },
    /// Передача завершена.
    FileComplete {
        transfer_id: [u8; 16],
        filename: String,
        saved_to: String,
        is_outgoing: bool,
        #[allow(dead_code)]
        peer: PeerId,
    },
    /// Передача прервана или ошибка.
    FileError {
        transfer_id: [u8; 16],
        reason: String,
    },
    /// Пир просит прислать файл ещё раз (его локальная копия удалена).
    FileResendRequest {
        from: PeerId,
        transfer_id: [u8; 16],
    },
    /// Атомарность голосового: получатель подтвердил (или отверг) целостность
    /// собранного файла. Только по `ok: true` отправитель может показать
    /// голосовое сообщение в чате как реально доставленное.
    VoiceAck {
        peer: PeerId,
        transfer_id: [u8; 16],
        ok: bool,
    },
}

/// Одна машина состояний для приёма чанков (E2EE `/void/chat` и устаревший plain `Chunk` по `/void/file`).
/// Возвращает `Some((transfer_id, ok))`, если голосовой файл только что дособрался
/// (успешно или с провалом целостности/записи) — вызывающий код обязан отправить
/// `voice_ack` отправителю, иначе тот никогда не узнает, что доставка атомарно
/// завершилась (или провалилась), и не покажет/не повторит голосовое.
async fn apply_incoming_file_chunk(
    transfer_id: [u8; 16],
    chunk_index: u32,
    data: Vec<u8>,
    peer: PeerId,
    now: &str,
    incoming_transfers: &mut HashMap<[u8; 16], file_transfer::IncomingTransfer>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    file_cache_key: &[u8; 32],
) -> Option<([u8; 16], bool)> {
    let done = if let Some(inc) = incoming_transfers.get_mut(&transfer_id) {
        inc.receive_chunk(chunk_index, data)
    } else {
        crate::voice::voice_log(&format!(
            "chunk orphan {} idx={chunk_index} from {}",
            transfer_id_to_hex(&transfer_id),
            &peer.to_string()[..8]
        ));
        false
    };

    let mut voice_outcome: Option<([u8; 16], bool)> = None;
    if let Some(inc) = incoming_transfers.get(&transfer_id) {
        let recv = inc.received_count;
        let total = inc.total_chunks;
        let fname = inc.filename.clone();
        let sz = inc.total_size;
        let fkind = inc.kind;
        let _ = event_tx
            .send(NetworkEvent::FileProgress {
                transfer_id,
                sent_chunks: recv,
                total_chunks: total,
                filename: fname.clone(),
                total_size: sz,
                is_outgoing: false,
                peer,
                kind: fkind,
            })
            .await;

        if done {
            let sha_expected = inc.sha256;
            let maybe_data = inc.assemble();
            if let Some(data) = maybe_data {
                let sha_actual = file_transfer::hash_file(&data);
                if sha_actual != sha_expected {
                    debug!(
                        "[{}] ❌ FILE: хэш не совпадает для «{}»!",
                        now, fname
                    );
                    if file_transfer::is_voice_filename(&fname) {
                        crate::voice::voice_log(&format!(
                            "hash mismatch {} — voice_ack(false)",
                            transfer_id_to_hex(&transfer_id)
                        ));
                        voice_outcome = Some((transfer_id, false));
                    }
                    let _ = event_tx
                        .send(NetworkEvent::FileError {
                            transfer_id,
                            reason: format!("Ошибка целостности файла «{}»", fname),
                        })
                        .await;
                } else {
                    let save_path = if file_transfer::is_voice_filename(&fname) {
                        if let Some(ref dir) = incoming_transfers
                            .get(&transfer_id)
                            .and_then(|t| t.save_dir.clone())
                        {
                            file_transfer::unique_download_path_in(dir, &fname)
                        } else {
                            file_transfer::unique_download_path_in_path(
                                &file_transfer::voice_dir_absolute(),
                                &fname,
                            )
                        }
                    } else {
                        file_transfer::cache_path_for(&transfer_id_to_hex(&transfer_id), &fname)
                    };
                    let saved_to = save_path.display().to_string();
                    let public_name = if file_transfer::is_voice_filename(&fname) {
                        fname.clone()
                    } else {
                        file_transfer::filename_from_bytes(&fname, &data)
                    };
                    let write_res = if file_transfer::is_voice_filename(&fname) {
                        std::fs::write(&save_path, &data).map_err(|e| e.to_string())
                    } else {
                        file_transfer::write_encrypted_cache(
                            &save_path,
                            &data,
                            file_cache_key,
                            &public_name,
                        )
                    };
                    match write_res {
                        Ok(_) => {
                            debug!(
                                "[{}] ✅ FILE: «{}» сохранён → {}",
                                now, public_name, saved_to
                            );
                            if file_transfer::is_voice_filename(&fname) {
                                crate::voice::voice_log(&format!(
                                    "received {} -> {}",
                                    fname, saved_to
                                ));
                                voice_outcome = Some((transfer_id, true));
                            }
                            let _ = event_tx
                                .send(NetworkEvent::FileComplete {
                                    transfer_id,
                                    filename: public_name,
                                    saved_to,
                                    is_outgoing: false,
                                    peer,
                                })
                                .await;
                        }
                        Err(e) => {
                            if file_transfer::is_voice_filename(&fname) {
                                crate::voice::voice_log(&format!(
                                    "receive save fail {fname}: {e}"
                                ));
                                voice_outcome = Some((transfer_id, false));
                            }
                            let _ = event_tx
                                .send(NetworkEvent::FileError {
                                    transfer_id,
                                    reason: format!("Не удалось сохранить «{}»: {}", fname, e),
                                })
                                .await;
                        }
                    }
                }
            }
            incoming_transfers.remove(&transfer_id);
        }
    }
    voice_outcome
}

#[cfg_attr(not(feature = "egui-ui"), allow(dead_code))]
pub(crate) enum UICommand {
    Dial(String),
    DialPeer(PeerId, Vec<Multiaddr>),
    SearchPeer(PeerId),
    /// Force (re)start E2EE Hello with a connected chat peer.
    EnsureChatSession(PeerId),
    /// Зарегистрировать контакты для авто-дозвона (в т.ч. без multiaddr → relay).
    WatchContacts(Vec<PeerId>),
    /// Убрать контакт из авто-дозвона и разорвать соединение.
    ForgetContact(PeerId),
    /// Перечитать bootstrap из vault + глобальные источники и переподключиться.
    ReloadBootstraps(Vec<String>),
    /// Войти в сеть через один узел: IP, IP:PORT или полный multiaddr; после коннекта — kad.bootstrap.
    JoinViaNode(String),
    /// Собрать PeerId из kbuckets и отправить в UI.
    SnapshotDhtRoutingPeers,
    SendMessage {
        sender_name: String,
        text: String,
        recipient: Option<PeerId>,
        message_id: Option<String>,
        is_retry: bool,
    },
    /// Сообщение в групповой чат: fan-out каждому участнику (кроме себя).
    SendGroupMessage {
        sender_name: String,
        text: String,
        group_id: String,
        members: Vec<PeerId>,
        message_id: Option<String>,
        is_retry: bool,
        voice_path: Option<String>,
        voice_duration_secs: f32,
        voice_transfer_id: Option<[u8; 16]>,
        /// Участники, которым нужен только file-transfer (чат уже доставлен).
        voice_only_members: Vec<PeerId>,
    },
    /// Синхронизация состава группы (pairwise E2EE).
    SendGroupSync {
        group_id: String,
        group_name: String,
        creator_id: String,
        members: Vec<crate::group::GroupMember>,
        recipients: Vec<PeerId>,
    },
    SendGroupLeave {
        group_id: String,
        peer_id: String,
        recipients: Vec<PeerId>,
    },
    SendGroupDelete {
        group_id: String,
        recipients: Vec<PeerId>,
    },
    /// Уведомить собеседника, что мы прочитали его сообщения.
    SendReadReceipt {
        peer: PeerId,
        message_ids: Vec<String>,
    },
    // ─── Файловый sub-протокол ──────────────────────────────────────────────
    /// Отправить файл пиру. Сетевой таск читает файл и инициирует Offer.
    SendFile {
        recipient: PeerId,
        path: String,
        kind: file_transfer::FileKind,
        message_id: Option<String>,
        transfer_id: Option<[u8; 16]>,
        sender_name: String,
        /// Исходное имя (не путь кэша `*.vfc`).
        filename: String,
    },
    /// Голосовое сообщение: ChatMessage + file-transfer с фиксированным transfer_id.
    SendVoiceMessage {
        sender_name: String,
        recipient: PeerId,
        path: String,
        duration_secs: f32,
        message_id: String,
        transfer_id: [u8; 16],
        is_retry: bool,
    },
    /// Файл в группу: ChatMessage + file-transfer каждому участнику.
    SendGroupFile {
        sender_name: String,
        group_id: String,
        members: Vec<PeerId>,
        path: String,
        message_id: String,
        transfer_id: [u8; 16],
        is_retry: bool,
        filename: String,
    },
    /// Пользователь принял входящее предложение файла.
    AcceptFile {
        transfer_id: [u8; 16],
        from: PeerId,
        /// Директория сохранения, выбранная пользователем. `None` → `Загрузки/VOID Messenger`.
        save_dir: Option<String>,
    },
    /// Пользователь отклонил входящее предложение файла.
    RejectFile {
        transfer_id: [u8; 16],
        from: PeerId,
        reason: String,
    },
    /// Запросить у пира повторную отправку файла (тот же transfer_id).
    RequestFile {
        peer: PeerId,
        transfer_id: [u8; 16],
    },
    /// Кэш X25519 prekey контактов (из vault).
    CachePeerPrekeys(Vec<(PeerId, [u8; 32])>),
    /// Опубликовать недоставленное в DHT/relay почтовые ящики получателей.
    /// `ack` = true только при durable handoff: Store Ack от bootstrap
    /// (или, без bootstrap — Ack любого пира / DHT Put Ok для текста).
    PublishOfflineOutbox {
        items: Vec<OfflineOutboxItem>,
        ack: Option<std_mpsc::Sender<bool>>,
    },
    /// Забрать свой почтовый ящик из DHT.
    FetchOfflineMailbox,
}

/// Элемент очереди для публикации в DHT-почту.
#[derive(Clone)]
pub(crate) struct OfflineOutboxItem {
    pub recipient: PeerId,
    pub message_id: String,
    pub kind: String,
    pub payload: Vec<u8>,
}

enum MailboxKadOp {
    MergePut {
        recipient: PeerId,
        new_envelopes: Vec<OfflineEnvelope>,
        done: Option<PublishDone>,
        record_bytes: Option<Vec<u8>>,
    },
    PrekeyForPublish {
        recipient: PeerId,
        items: Vec<OfflineOutboxItem>,
        done: Option<PublishDone>,
        prekey_bytes: Option<Vec<u8>>,
    },
    /// Prefetch contact X25519 into peer_prekeys (for offline seal).
    CachePrekey {
        peer: PeerId,
        prekey_bytes: Option<Vec<u8>>,
    },
    AwaitPut {
        done: Option<PublishDone>,
    },
}

type PublishDone = Arc<dyn Fn(bool) + Send + Sync>;

/// Countdown gate: `true` only if every recipient unit reported ok.
fn publish_result_token(tx: std_mpsc::Sender<bool>, total: u32) -> PublishDone {
    let left = Arc::new(AtomicU32::new(total.max(1)));
    let fails = Arc::new(AtomicU32::new(0));
    Arc::new(move |ok: bool| {
        if !ok {
            fails.fetch_add(1, Ordering::SeqCst);
        }
        if left.fetch_sub(1, Ordering::SeqCst) == 1 {
            let all_ok = fails.load(Ordering::SeqCst) == 0;
            let _ = tx.send(all_ok);
        }
    })
}

/// Waits until every sealed envelope has a durable Store Ack, or (LAN-only)
/// DHT Ok for text-only batches when `allow_dht_fallback` is set.
struct ActiveHandoff {
    state: Mutex<EnvelopeHandoffState>,
    done: PublishDone,
    fired: AtomicBool,
}

impl ActiveHandoff {
    fn new(
        envelopes: &[OfflineEnvelope],
        done: PublishDone,
        allow_dht_fallback: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(EnvelopeHandoffState::from_envelopes(
                envelopes,
                allow_dht_fallback,
            )),
            done,
            fired: AtomicBool::new(false),
        })
    }

    fn fire(&self, ok: bool) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        (self.done)(ok);
    }

    fn note_store_ack(&self, message_id: &str) {
        let settle = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.on_store_ack(message_id)
        };
        if let Some(ok) = settle {
            self.fire(ok);
        }
    }

    fn note_dht_ok(&self) {
        let settle = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.on_dht_ok()
        };
        if let Some(ok) = settle {
            self.fire(ok);
        }
    }

    fn note_fail(&self) {
        let settle = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.on_fail()
        };
        if let Some(ok) = settle {
            self.fire(ok);
        }
    }
}

fn signal_publish_done(done: &Option<PublishDone>, ok: bool) {
    if let Some(d) = done {
        d(ok);
    }
}

/// Each recipient must call the shared gate at most once (legacy fail path).
fn once_publish_gate(inner: PublishDone) -> PublishDone {
    let fired = Arc::new(AtomicBool::new(false));
    Arc::new(move |ok: bool| {
        if fired.swap(true, Ordering::SeqCst) {
            return;
        }
        inner(ok);
    })
}

/// Голосовые чанки (аудио офлайн-доставки) не годятся для DHT-записи почтового
/// ящика — та ограничена ~64 КБ на весь ящик получателя (см. mailbox_record_key).
/// Они всё равно доходят через relay/bootstrap store-and-forward (`publish_relay_mail`).
fn dht_eligible_envelopes(envelopes: &[OfflineEnvelope]) -> Vec<OfflineEnvelope> {
    envelopes
        .iter()
        .filter(|e| e.kind != OFFLINE_VOICE_CHUNK_KIND)
        .cloned()
        .collect()
}

fn publish_self_prekey(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    public_key: &[u8; 32],
) {
    let record = kad::Record {
        key: prekey_record_key(local_peer_id),
        value: public_key.to_vec(),
        publisher: Some(local_peer_id),
        expires: Some(Instant::now() + Duration::from_secs(MAILBOX_TTL_SECS)),
    };
    let _ = swarm
        .behaviour_mut()
        .kad
        .put_record(record, kad::Quorum::One);
}

/// Put X25519 prekey on connected bootstrap nodes (offline seal without DHT/Hello).
fn publish_self_prekey_to_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    public_key: &[u8; 32],
    bootstrap_peer_ids: &HashSet<PeerId>,
) {
    if bootstrap_peer_ids.is_empty() {
        return;
    }
    let packet = V1Packet::PrekeyPut {
        peer_id: local_peer_id.to_string(),
        public_key: *public_key,
    };
    for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
        if !bootstrap_peer_ids.contains(&peer) {
            continue;
        }
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, packet.clone());
    }
}

type OutboundPrekeyGets = HashMap<
    libp2p::request_response::OutboundRequestId,
    (PeerId, Vec<OfflineOutboxItem>, Option<PublishDone>),
>;

fn request_prekey_from_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    recipient: PeerId,
    items: Vec<OfflineOutboxItem>,
    done: Option<PublishDone>,
    track: &mut OutboundPrekeyGets,
) -> bool {
    dial_missing_bootstraps(swarm, bootstrap_peer_ids, void_bootstraps);
    let packet = V1Packet::PrekeyGet {
        peer_id: recipient.to_string(),
    };
    let mut sent = false;
    for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
        if !bootstrap_peer_ids.contains(&peer) {
            continue;
        }
        let rid = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, packet.clone());
        track.insert(rid, (recipient, items.clone(), done.clone()));
        sent = true;
    }
    sent
}

fn seal_and_publish_offline_batch(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer_prekeys: &mut HashMap<PeerId, [u8; 32]>,
    relay_mail_store: &mut HashMap<String, Vec<OfflineEnvelope>>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    local_peer_id: PeerId,
    my_public_key_bytes: &[u8; 32],
    pending_relay: &mut PendingRelayQueue,
    pending_relay_gates: &mut HashMap<(PeerId, PeerId), Arc<ActiveHandoff>>,
    outbound_mailbox_stores: &mut MailboxStoreTrack,
    pending_kad_mail: &mut HashMap<kad::QueryId, MailboxKadOp>,
    recipient: PeerId,
    pk_bytes: [u8; 32],
    items: Vec<OfflineOutboxItem>,
    done: Option<PublishDone>,
) -> bool {
    peer_prekeys.insert(recipient, pk_bytes);
    let pk = crypto::PublicKey::from(pk_bytes);
    let mut sealed = Vec::new();
    for item in items {
        if let Ok(env) = seal_for_recipient(
            &pk,
            &local_peer_id,
            my_public_key_bytes,
            &item.message_id,
            &item.kind,
            &item.payload,
        ) {
            sealed.push(env);
        }
    }
    if sealed.is_empty() {
        signal_publish_done(&done, false);
        return false;
    }
    if RelayMailbox::merge(
        relay_mail_store,
        &recipient.to_string(),
        sealed.clone(),
    ) {
        let _ = RelayMailbox::save(relay_mail_store);
    }
    let allow_dht = bootstrap_peer_ids.is_empty();
    let done_cb: PublishDone = done.unwrap_or_else(|| Arc::new(|_| {}) as PublishDone);
    let handoff = Some(ActiveHandoff::new(&sealed, done_cb, allow_dht));
    publish_relay_mail(
        swarm,
        bootstrap_peer_ids,
        void_bootstraps,
        local_peer_id,
        recipient,
        &sealed,
        pending_relay,
        pending_relay_gates,
        outbound_mailbox_stores,
        &handoff,
    );
    if let Some(h) = &handoff {
        let tracked = outbound_mailbox_stores
            .values()
            .any(|(g, _, _)| Arc::ptr_eq(g, h));
        let queued = pending_relay_gates.values().any(|g| Arc::ptr_eq(g, h));
        if !tracked && !queued && !accept_dht_as_full_handoff(&sealed, allow_dht) {
            warn!("VOID: нет bootstrap-ноды для offline (после prekey)");
            h.note_fail();
            return false;
        }
    }
    if allow_dht {
        let for_dht = dht_eligible_envelopes(&sealed);
        let dht_done: Option<PublishDone> = handoff.as_ref().map(|h| {
            let h = h.clone();
            Arc::new(move |ok: bool| {
                if ok {
                    h.note_dht_ok();
                }
            }) as PublishDone
        });
        start_mailbox_merge_put(swarm, pending_kad_mail, recipient, for_dht, dht_done);
    }
    true
}

fn start_mailbox_merge_put(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    pending_kad_mail: &mut HashMap<kad::QueryId, MailboxKadOp>,
    recipient: PeerId,
    new_envelopes: Vec<OfflineEnvelope>,
    done: Option<PublishDone>,
) {
    let qid = swarm
        .behaviour_mut()
        .kad
        .get_record(mailbox_record_key(recipient));
    pending_kad_mail.insert(
        qid,
        MailboxKadOp::MergePut {
            recipient,
            new_envelopes,
            done,
            record_bytes: None,
        },
    );
}

fn merge_envelopes(
    existing: &[OfflineEnvelope],
    new_envelopes: &[OfflineEnvelope],
) -> Vec<OfflineEnvelope> {
    let mut out: Vec<OfflineEnvelope> = existing.to_vec();
    for env in new_envelopes {
        if out.iter().any(|e| e.message_id == env.message_id) {
            continue;
        }
        out.push(env.clone());
    }
    out
}

fn put_mailbox_envelopes(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    pending_kad_mail: &mut HashMap<kad::QueryId, MailboxKadOp>,
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
    done: Option<PublishDone>,
) {
    let Ok(value) = encode_mailbox(envelopes) else {
        // DHT encode fail: do not settle false here — relay Store Ack may still
        // confirm handoff. Exit timeout covers total failure.
        return;
    };
    let record = kad::Record {
        key: mailbox_record_key(recipient),
        value,
        publisher: Some(local_peer_id),
        expires: Some(Instant::now() + Duration::from_secs(MAILBOX_TTL_SECS)),
    };
    match swarm
        .behaviour_mut()
        .kad
        .put_record(record, kad::Quorum::One)
    {
        Ok(qid) => {
            if done.is_some() {
                pending_kad_mail.insert(qid, MailboxKadOp::AwaitPut { done });
            }
        }
        // Put setup failed — leave gate open for relay Ack / exit timeout.
        Err(_) => {}
    }
}

/// JSON RR codec по умолчанию режет request на 1 МиБ. Один OfflineMailboxStore
/// со всеми voice_chunk (~3 МБ WAV → JSON) гарантированно не проходит — шлём
/// по одному конверту на запрос.
type MailboxStoreTrack = HashMap<
    libp2p::request_response::OutboundRequestId,
    (Arc<ActiveHandoff>, PeerId, String),
>;

fn fanout_relay_mail(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
    store_track: &mut MailboxStoreTrack,
    handoff: &Option<Arc<ActiveHandoff>>,
    // When false (bootstraps configured), ephemeral peer stores are best-effort
    // cache only — their Ack must not settle durable handoff.
    track_handoff: bool,
) {
    if envelopes.is_empty() {
        return;
    }
    let peers: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|p| *p != local_peer_id && *p != recipient)
        .collect();
    if peers.is_empty() {
        return;
    }
    let recip = recipient.to_string();
    for env in envelopes {
        let packet = V1Packet::OfflineMailboxStore {
            recipient: recip.clone(),
            envelopes: vec![env.clone()],
        };
        for peer in &peers {
            let rid = swarm
                .behaviour_mut()
                .request_response
                .send_request(peer, packet.clone());
            if track_handoff {
                if let Some(h) = handoff {
                    store_track.insert(rid, (h.clone(), recipient, env.message_id.clone()));
                }
            }
        }
    }
}

/// Разослать офлайн-почту bootstrap-нодам. Если нода ещё не connected —
/// dial + очередь (раньше был dial-and-forget → mail терялся при выходе).
fn fanout_relay_to_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
    pending_relay: &mut PendingRelayQueue,
    pending_relay_gates: &mut HashMap<(PeerId, PeerId), Arc<ActiveHandoff>>,
    store_track: &mut MailboxStoreTrack,
    handoff: &Option<Arc<ActiveHandoff>>,
) {
    if envelopes.is_empty() {
        return;
    }
    let recip = recipient.to_string();
    for pid in bootstrap_peer_ids {
        if *pid == local_peer_id || *pid == recipient {
            continue;
        }
        if swarm.is_connected(pid) {
            for env in envelopes {
                let packet = V1Packet::OfflineMailboxStore {
                    recipient: recip.clone(),
                    envelopes: vec![env.clone()],
                };
                let rid = swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(pid, packet);
                if let Some(h) = handoff {
                    store_track.insert(rid, (h.clone(), recipient, env.message_id.clone()));
                }
            }
        } else {
            let addrs: Vec<Multiaddr> = void_bootstraps
                .iter()
                .filter(|ma| peer_id_from_multiaddr(ma) == Some(*pid))
                .cloned()
                .collect();
            if !addrs.is_empty() {
                pending_relay.enqueue(*pid, recipient, envelopes.to_vec());
                if let Some(h) = handoff {
                    pending_relay_gates.insert((*pid, recipient), h.clone());
                }
                dial_bootstrap_direct(swarm, *pid, addrs);
            }
        }
    }
}

fn publish_relay_mail(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
    pending_relay: &mut PendingRelayQueue,
    pending_relay_gates: &mut HashMap<(PeerId, PeerId), Arc<ActiveHandoff>>,
    store_track: &mut MailboxStoreTrack,
    handoff: &Option<Arc<ActiveHandoff>>,
) {
    // With bootstraps: only their Store Ack is durable. Ephemeral peers still
    // get a copy as cache, but must not settle the exit/publish gate.
    let track_ephemeral = bootstrap_peer_ids.is_empty();
    fanout_relay_mail(
        swarm,
        local_peer_id,
        recipient,
        envelopes,
        store_track,
        handoff,
        track_ephemeral,
    );
    fanout_relay_to_bootstraps(
        swarm,
        bootstrap_peer_ids,
        void_bootstraps,
        local_peer_id,
        recipient,
        envelopes,
        pending_relay,
        pending_relay_gates,
        store_track,
        handoff,
    );
}

fn ordered_bootstrap_addrs(void_bootstraps: &[Multiaddr]) -> Vec<Multiaddr> {
    let mut addrs: Vec<Multiaddr> = void_bootstraps.to_vec();
    addrs.sort_by_key(|ma| {
        let s = ma.to_string();
        let rank = if s.contains("147.78.64.22") {
            0u8
        } else if is_likely_lan_addr(ma) {
            2
        } else {
            1
        };
        (rank, s)
    });
    addrs
}

/// Hop Ack: circuit уже в external_addresses (слушатель без Ack сюда не попадает).
fn hop_reservation_confirmed(swarm: &libp2p::Swarm<ChatBehaviour>) -> bool {
    swarm.external_addresses().any(is_circuit_addr)
}

/// Dial any configured bootstrap that is not yet connected (for store or fetch).
fn extra_bootstrap_dial_gate() -> std::sync::MutexGuard<'static, Option<Instant>> {
    static G: std::sync::OnceLock<std::sync::Mutex<Option<Instant>>> = std::sync::OnceLock::new();
    G.get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn dial_missing_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
) {
    let up = swarm_has_bootstrap_tcp(swarm, bootstrap_peer_ids);
    if !up {
        {
            let mut g = bootstrap_ep_gate();
            g.live.clear();
        }
        ensure_void_node_dial(swarm, bootstrap_peer_ids);
    } else if !hop_reservation_confirmed(swarm) {
        // Живой TCP к ноде есть. Второй dial до Hop Ack рвёт HOP-стрим.
        return;
    } else {
        ensure_void_node_dial(swarm, bootstrap_peer_ids);
    }
    if up {
        let mut last = extra_bootstrap_dial_gate();
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(20)) {
            return;
        }
        *last = Some(Instant::now());
    }
    let mut seen_ep: HashSet<String> = HashSet::new();
    for ma in ordered_bootstrap_addrs(void_bootstraps) {
        if is_void_bootstrap_host(&ma) {
            continue;
        }
        let k = addr_endpoint_key(&ma);
        if !seen_ep.insert(k) {
            continue;
        }
        let pid = peer_id_from_multiaddr(&ma).unwrap_or(*swarm.local_peer_id());
        if pid == *swarm.local_peer_id() || swarm.is_connected(&pid) {
            continue;
        }
        dial_bootstrap_direct(swarm, pid, vec![ma]);
    }
}

fn flush_pending_relay_for_peer(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    pending_relay: &mut PendingRelayQueue,
    pending_relay_gates: &mut HashMap<(PeerId, PeerId), Arc<ActiveHandoff>>,
    store_track: &mut MailboxStoreTrack,
    peer: PeerId,
) {
    for (recipient, envelopes) in pending_relay.take_for(&peer) {
        let handoff = pending_relay_gates.remove(&(peer, recipient));
        let recip = recipient.to_string();
        for env in envelopes {
            let mid = env.message_id.clone();
            let packet = V1Packet::OfflineMailboxStore {
                recipient: recip.clone(),
                envelopes: vec![env],
            };
            let rid = swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer, packet);
            if let Some(ref h) = handoff {
                store_track.insert(rid, (h.clone(), recipient, mid));
            }
        }
    }
}

fn query_relay_mailbox(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    bootstrap_peer_ids: &HashSet<PeerId>,
    last_query_at: &mut Option<Instant>,
) -> bool {
    const MIN_GAP: Duration = Duration::from_millis(750);
    if last_query_at.is_some_and(|t| t.elapsed() < MIN_GAP) {
        return false;
    }
    let packet = V1Packet::OfflineMailboxQuery {
        recipient: local_peer_id.to_string(),
    };
    let boot: Vec<PeerId> = swarm
        .connected_peers()
        .copied()
        .filter(|p| bootstrap_peer_ids.contains(p))
        .collect();
    let peers: Vec<PeerId> = if !boot.is_empty() {
        boot
    } else {
        swarm
            .connected_peers()
            .copied()
            .filter(|p| *p != local_peer_id)
            .collect()
    };
    if peers.is_empty() {
        return false;
    }
    *last_query_at = Some(Instant::now());
    for peer in peers {
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, packet.clone());
    }
    true
}

fn query_relay_mailbox_with_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    last_query_at: &mut Option<Instant>,
) -> bool {
    dial_missing_bootstraps(swarm, bootstrap_peer_ids, void_bootstraps);
    query_relay_mailbox(swarm, local_peer_id, bootstrap_peer_ids, last_query_at)
}

async fn remember_peer_prekey(
    peer_prekeys: &mut HashMap<PeerId, [u8; 32]>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    public_key: [u8; 32],
) {
    let changed = peer_prekeys.get(&peer) != Some(&public_key);
    peer_prekeys.insert(peer, public_key);
    if changed {
        let _ = event_tx
            .send(NetworkEvent::PeerPrekey { peer, public_key })
            .await;
    }
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    request_response: libp2p::request_response::json::Behaviour<V1Packet, V1Packet>,
    /// Отдельный sub-протокол для передачи файлов (/void/file/1.0.0).
    file_rr: libp2p::request_response::json::Behaviour<
        file_transfer::FilePacket,
        file_transfer::FilePacket,
    >,
    mdns: Toggle<mdns::tokio::Behaviour>,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    relay: relay::client::Behaviour,
    /// По умолчанию выкл.: AutoNAT/DCUtR/UPnP открывают второй dial к bootstrap.
    dcutr: Toggle<dcutr::Behaviour>,
    autonat: Toggle<autonat::Behaviour>,
    upnp: Toggle<upnp::tokio::Behaviour>,
}
fn build_void_swarm(
    local_key: libp2p::identity::Keypair,
    void_bootstraps: &[Multiaddr],
    contact_seed_addrs: &[(PeerId, Multiaddr)],
) -> Result<libp2p::Swarm<ChatBehaviour>, String> {
    Ok(libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            || {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(512);
                config
            },
        )
        .map_err(|e| format!("with_tcp: {:?}", e))?
        .with_dns()
        .map_err(|e| format!("with_dns: {:?}", e))?
        .with_relay_client(noise::Config::new, || {
            let mut config = yamux::Config::default();
            config.set_max_num_streams(512);
            config
        })
        .map_err(|e| format!("with_relay_client: {:?}", e))?
        .with_behaviour(|key, relay_client| {
            let local_peer_id = key.public().to_peer_id();
            let _ = void_bootstraps;
            let _ = contact_seed_addrs;

            let kad_store = kad::store::MemoryStore::new(local_peer_id);
            let mut kad_config = kad::Config::new(StreamProtocol::new("/void/kad/1.0.0"));
            kad_config.set_periodic_bootstrap_interval(Some(Duration::from_secs(5 * 60)));
            kad_config.set_query_timeout(Duration::from_secs(15));
            // Manual: add_address при сборке swarm сразу вставляет bootstrap в
            // k-bucket → Kademlia сама делает bootstrap() и второй TCP рядом
            // с нашим dial; оба закрываются yamux Closed за 1 мс.
            kad_config.set_kbucket_inserts(kad::BucketInserts::Manual);
            let mut kad = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
            kad.set_mode(Some(libp2p::kad::Mode::Server));
            // Адреса в DHT — только после живого TCP (Identify).

            let rr_config = libp2p::request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(256);
            let rr_protocol = libp2p::StreamProtocol::new("/void/chat/1.0.0");
            // Offline voice_chunk: один конверт ≈ десятки КБ plaintext, в JSON
            // раздувается; дефолт codec 1 МиБ / 10 МиБ режет длинные голоса.
            let rr_codec =
                libp2p::request_response::json::codec::Codec::<V1Packet, V1Packet>::default()
                    .set_request_size_maximum(4 * 1024 * 1024)
                    .set_response_size_maximum(16 * 1024 * 1024);
            let rr_behaviour =
                libp2p::request_response::Behaviour::<
                    libp2p::request_response::json::codec::Codec<V1Packet, V1Packet>,
                >::with_codec(
                    rr_codec,
                    [(rr_protocol, libp2p::request_response::ProtocolSupport::Full)],
                    rr_config.clone(),
                );

            let file_rr_config = libp2p::request_response::Config::default()
                .with_request_timeout(Duration::from_secs(300))
                .with_max_concurrent_streams(256);
            let file_rr_protocol = libp2p::StreamProtocol::new(file_transfer::FILE_PROTOCOL_ID);
            let file_rr_behaviour = libp2p::request_response::json::Behaviour::<
                file_transfer::FilePacket,
                file_transfer::FilePacket,
            >::new(
                [(
                    file_rr_protocol,
                    libp2p::request_response::ProtocolSupport::Full,
                )],
                file_rr_config,
            );

            let mdns: Toggle<mdns::tokio::Behaviour> = if std::env::var("VOID_DISABLE_MDNS").is_ok() {
                Toggle::from(None)
            } else {
                let b = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                Toggle::from(Some(b))
            };

            let nat_on = std::env::var("VOID_ENABLE_NAT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            Ok(ChatBehaviour {
                request_response: rr_behaviour,
                file_rr: file_rr_behaviour,
                mdns,
                ping: ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(Duration::from_secs(20))
                        .with_timeout(Duration::from_secs(40)),
                ),
                identify: identify::Behaviour::new(
                    identify::Config::new("/void/v1".into(), key.public())
                        .with_push_listen_addr_updates(true),
                ),
                kad,
                relay: relay_client,
                dcutr: Toggle::from(nat_on.then(|| dcutr::Behaviour::new(local_peer_id))),
                autonat: Toggle::from(
                    nat_on.then(|| autonat::Behaviour::new(local_peer_id, Default::default())),
                ),
                upnp: Toggle::from(nat_on.then(upnp::tokio::Behaviour::default)),
            })
        })
        .map_err(|e| format!("with_behaviour: {:?}", e))?
        .with_swarm_config(|c| {
            // Bound idle so half-open / zombie peers (Mac shows online, Windows not)
            // get dropped; ping (20s/40s) should close sooner on real failures.
            c.with_idle_connection_timeout(Duration::from_secs(1200))
                .with_per_connection_event_buffer_size(256)
        })
        .build())
}

fn send_v1_to_peer(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    dest: PeerId,
    packet: V1Packet,
) -> libp2p::request_response::OutboundRequestId {
    let snapshot = ONION_RT.lock().ok().and_then(|g| {
        let rt = g.as_ref()?;
        if rt.bootstraps.contains(&dest) {
            return None;
        }
        let hops = crate::onion::select_hops(
            swarm.connected_peers().copied(),
            &rt.bootstraps,
            &rt.keys,
        );
        if hops.is_empty() {
            return None;
        }
        let dest_connected = swarm.is_connected(&dest);
        // Живой канал (LAN или circuit) — напрямую. Onion только если пира нет
        // в swarm: иначе file/voice чанки (32 КиБ) раздуваются в JSON и Offer
        // по /void/file до NAT не доходит.
        if dest_connected {
            return None;
        }
        Some((hops, rt.local))
    });
    if let Some((hops, local)) = snapshot {
        if let Some(onion) = wrap_onion_packet(&hops, local, dest, packet.clone()) {
            let first = hops[0].0;
            debug!(
                "🧅 onion {} hop(s) → {} via {}",
                hops.len(),
                &dest.to_string()[..8.min(dest.to_string().len())],
                &first.to_string()[..8.min(first.to_string().len())]
            );
            if !matches!(packet, V1Packet::Ack) {
                let hop_ids: Vec<PeerId> = hops.iter().map(|(p, _)| *p).collect();
                onion_rt_note("out", dest, &hop_ids);
            }
            return swarm
                .behaviour_mut()
                .request_response
                .send_request(&first, onion);
        }
    }
    if matches!(packet, V1Packet::Encrypted { .. }) {
        onion_rt_note("direct", dest, &[]);
    }
    swarm
        .behaviour_mut()
        .request_response
        .send_request(&dest, packet)
}

fn rr_reply(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    channel: &mut Option<libp2p::request_response::ResponseChannel<V1Packet>>,
    onion_reply: Option<PeerId>,
    packet: V1Packet,
) {
    if onion_reply.is_some() && matches!(packet, V1Packet::Ack) {
        let _ = channel.take();
        return;
    }
    if let Some(dest) = onion_reply {
        let _ = channel.take();
        let _ = send_v1_to_peer(swarm, dest, packet);
        return;
    }
    if let Some(ch) = channel.take() {
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_response(ch, packet);
    }
}

async fn send_encrypted_chat_payload(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outbound_msg_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, String, Vec<u8>),
    >,
    outbound_delete_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, Vec<String>),
    >,
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    json_data: Vec<u8>,
    delete_track_ids: Option<&[String]>,
    now: &str,
) -> bool {
    let Some(session) = sessions.get_mut(&peer) else {
        return false;
    };
    let Ok((header, ciphertext)) = session.encrypt_payload(json_data.as_slice()) else {
        let _ = event_tx
            .send(NetworkEvent::Status(format!(
                "❌ E2EE: не удалось зашифровать сообщение для {}",
                &peer.to_string()[..8.min(peer.to_string().len())]
            )))
            .await;
        return false;
    };
    let packet = V1Packet::Encrypted { header, ciphertext };
    let req_id = send_v1_to_peer(swarm, peer, packet);
    if is_delete_command_json(json_data.as_slice()) || is_read_command_json(json_data.as_slice()) {
        let ids = delete_track_ids
            .map(|v| v.to_vec())
            .or_else(|| delete_command_message_ids(json_data.as_slice()))
            .unwrap_or_default();
        outbound_delete_requests.insert(req_id, (peer, ids));
    } else if let Some(msg_id) = chat_message_id_from_json(json_data.as_slice()) {
        // Keep plaintext so Hello-вместо-Ack / OutFailure can requeue.
        outbound_msg_requests.insert(req_id, (peer, msg_id.clone(), json_data));
        let _ = event_tx
            .send(NetworkEvent::MessageOnWire {
                peer,
                message_id: msg_id,
            })
            .await;
    } else if let Some(ids) = read_command_message_ids(json_data.as_slice()) {
        let _ = event_tx
            .send(NetworkEvent::ReadReceiptSent {
                peer,
                message_ids: ids,
            })
            .await;
    }
    debug!(
        "[{}] 📨 E2EE: пакет отправлен пиру {}",
        now,
        &peer.to_string()[..8.min(peer.to_string().len())]
    );
    true
}

fn send_e2ee_file_ctrl(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    peer: PeerId,
    packet: &file_transfer::FilePacket,
) -> bool {
    let Some(frame) = file_transfer::encode_e2ee_file_ctrl(packet) else {
        return false;
    };
    let Some(session) = sessions.get_mut(&peer) else {
        return false;
    };
    let Ok((header, ciphertext)) = session.encrypt_payload(&frame) else {
        return false;
    };
    let _ = send_v1_to_peer(
        swarm,
        peer,
        V1Packet::Encrypted { header, ciphertext },
    );
    true
}

fn requeue_pending_chat_json(
    pending_messages: &mut HashMap<PeerId, Vec<Vec<u8>>>,
    peer: PeerId,
    json: Vec<u8>,
) {
    let mid = chat_message_id_from_json(json.as_slice());
    let queue = pending_messages.entry(peer).or_default();
    if let Some(ref id) = mid {
        if queue
            .iter()
            .any(|b| chat_message_id_from_json(b.as_slice()).as_deref() == Some(id.as_str()))
        {
            return;
        }
    }
    queue.push(json);
}

struct PendingVoiceTransfer {
    path: String,
    transfer_id: [u8; 16],
}

struct PendingNamedFileTransfer {
    path: String,
    transfer_id: [u8; 16],
    filename: String,
    kind: file_transfer::FileKind,
}

async fn flush_pending_encrypted_messages(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outbound_msg_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, String, Vec<u8>),
    >,
    outbound_delete_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, Vec<String>),
    >,
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    pending_messages: &mut HashMap<PeerId, Vec<Vec<u8>>>,
    now: &str,
) {
    let Some(buffered) = pending_messages.remove(&peer) else {
        return;
    };
    for data in buffered {
        let sent = send_encrypted_chat_payload(
            swarm,
            sessions,
            outbound_msg_requests,
            outbound_delete_requests,
            event_tx,
            peer,
            data.clone(),
            None,
            now,
        )
        .await;
        if !sent {
            requeue_pending_chat_json(pending_messages, peer, data);
        }
    }
}

fn put_e2ee_session(
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    session_established_at: &mut HashMap<PeerId, Instant>,
    peer: PeerId,
    session: crypto::SecureSession,
) {
    sessions.insert(peer, session);
    session_established_at.insert(peer, Instant::now());
}

fn drop_e2ee_session(
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    session_established_at: &mut HashMap<PeerId, Instant>,
    peer: PeerId,
) {
    sessions.remove(&peer);
    session_established_at.remove(&peer);
}

fn e2ee_session_is_fresh(
    session_established_at: &HashMap<PeerId, Instant>,
    peer: PeerId,
) -> bool {
    session_established_at
        .get(&peer)
        .map(|t| t.elapsed() < Duration::from_secs(2))
        .unwrap_or(false)
}

fn voice_transfer_stale(t: &file_transfer::OutgoingTransfer) -> Duration {
    let bps = if t.is_relay {
        file_transfer::RELAY_RATE_LIMIT_BPS
    } else {
        512 * 1024
    };
    let xfer_ms = t.total_size.saturating_mul(1000) / bps;
    let margin = if t.accepted { 15_000 } else { 45_000 };
    Duration::from_millis(xfer_ms.saturating_add(margin).max(30_000).min(600_000))
}

const VOICE_OFFER_RESEND: Duration = Duration::from_secs(12);

async fn resend_voice_offer(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outgoing_transfers: &mut HashMap<[u8; 16], file_transfer::OutgoingTransfer>,
    transfer_id: [u8; 16],
    recipient: PeerId,
) {
    let Some(t) = outgoing_transfers.get(&transfer_id) else {
        return;
    };
    if t.accepted || t.next_chunk > 0 {
        return;
    }
    let offer = t.build_offer();
    let _ = send_e2ee_file_ctrl(swarm, sessions, recipient, &offer);
    if swarm.is_connected(&recipient) {
        swarm
            .behaviour_mut()
            .file_rr
            .send_request(&recipient, offer);
    }
    if let Some(t) = outgoing_transfers.get_mut(&transfer_id) {
        t.last_chunk_at = Instant::now();
    }
    crate::voice::voice_log(&format!(
        "voice re-offer {}",
        transfer_id_to_hex(&transfer_id)
    ));
}

async fn start_voice_file_transfer(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outgoing_transfers: &mut HashMap<[u8; 16], file_transfer::OutgoingTransfer>,
    relay_peers: &HashSet<PeerId>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    recipient: PeerId,
    path: &str,
    transfer_id: [u8; 16],
) {
    if let Some(existing) = outgoing_transfers.get(&transfer_id) {
        if existing.next_chunk >= existing.chunks.len() {
            return;
        }
        if !existing.accepted
            && existing.next_chunk == 0
            && existing.last_chunk_at.elapsed() >= VOICE_OFFER_RESEND
        {
            resend_voice_offer(
                swarm,
                sessions,
                outgoing_transfers,
                transfer_id,
                recipient,
            )
            .await;
            return;
        }
        let stale = voice_transfer_stale(existing);
        if existing.last_chunk_at.elapsed() < stale {
            return;
        }
        crate::voice::voice_log(&format!(
            "voice restart stale {}",
            transfer_id_to_hex(&transfer_id)
        ));
        outgoing_transfers.remove(&transfer_id);
    }
    match std::fs::read(path) {
        Err(e) => {
            crate::voice::voice_log(&format!(
                "voice send read fail {}: {e}",
                transfer_id_to_hex(&transfer_id)
            ));
            let _ = event_tx
                .send(NetworkEvent::Status(format!(
                    "❌ Не удалось прочитать голосовое «{}»: {}",
                    path, e
                )))
                .await;
        }
        Ok(data) => {
            let data = crate::metadata_strip::strip_metadata_for_send(
                &file_transfer::voice_filename(&transfer_id),
                file_transfer::FileKind::Audio,
                data,
            );
            if data.len() as u64 > file_transfer::MAX_FILE_SIZE {
                let _ = event_tx
                    .send(NetworkEvent::Status(
                        "❌ Голосовое сообщение слишком большое".into(),
                    ))
                    .await;
            } else {
                let sha256 = file_transfer::hash_file(&data);
                let chunks = file_transfer::split_into_chunks(&data);
                let total_chunks = chunks.len() as u32;
                let total_size = data.len() as u64;
                let filename = file_transfer::voice_filename(&transfer_id);
                let file_kind = file_transfer::FileKind::Audio;
                let is_relay = relay_peers.contains(&recipient);
                let offer = file_transfer::FilePacket::Offer {
                    transfer_id,
                    filename: filename.clone(),
                    total_size,
                    total_chunks,
                    sha256,
                    kind: file_kind,
                };
                let _ = send_e2ee_file_ctrl(swarm, sessions, recipient, &offer);
                if swarm.is_connected(&recipient) {
                    swarm
                        .behaviour_mut()
                        .file_rr
                        .send_request(&recipient, offer);
                }

                let transfer = file_transfer::OutgoingTransfer {
                    peer: recipient,
                    transfer_id,
                    filename: filename.clone(),
                    chunks,
                    next_chunk: 0,
                    total_size,
                    is_relay,
                    last_chunk_at: Instant::now(),
                    accepted: false,
                    chunk_inflight: false,
                    sha256,
                    kind: file_kind,
                };
                outgoing_transfers.insert(transfer_id, transfer);

                crate::voice::voice_log(&format!(
                    "voice offer {} -> {} ({} ch, {} B)",
                    transfer_id_to_hex(&transfer_id),
                    &recipient.to_string()[..8],
                    total_chunks,
                    total_size
                ));

                let _ = event_tx
                    .send(NetworkEvent::FileProgress {
                        transfer_id,
                        sent_chunks: 0,
                        total_chunks,
                        filename,
                        total_size,
                        is_outgoing: true,
                        peer: recipient,
                        kind: file_kind,
                    })
                    .await;
            }
        }
    }
}

async fn start_named_file_transfer(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outgoing_transfers: &mut HashMap<[u8; 16], file_transfer::OutgoingTransfer>,
    relay_peers: &HashSet<PeerId>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    recipient: PeerId,
    path: &str,
    transfer_id: [u8; 16],
    filename: String,
    file_kind: file_transfer::FileKind,
    file_cache_key: &[u8; 32],
) {
    if outgoing_transfers.contains_key(&transfer_id) {
        return;
    }
    match file_transfer::read_cache_plain(std::path::Path::new(path), file_cache_key) {
        Err(e) => {
            let _ = event_tx
                .send(NetworkEvent::Status(format!(
                    "❌ Не удалось прочитать файл «{filename}»: {e}"
                )))
                .await;
        }
        Ok(data) => {
            let data = crate::metadata_strip::strip_metadata_for_send(&filename, file_kind, data);
            if data.len() as u64 > file_transfer::MAX_FILE_SIZE {
                let _ = event_tx
                    .send(NetworkEvent::Status(format!(
                        "❌ Файл слишком большой (> {} МБ)",
                        file_transfer::MAX_FILE_SIZE / 1024 / 1024
                    )))
                    .await;
                return;
            }
            let sha256 = file_transfer::hash_file(&data);
            let chunks = file_transfer::split_into_chunks(&data);
            let total_chunks = chunks.len() as u32;
            let total_size = data.len() as u64;
            let is_relay = relay_peers.contains(&recipient);
            let offer = file_transfer::FilePacket::Offer {
                transfer_id,
                filename: filename.clone(),
                total_size,
                total_chunks,
                sha256,
                kind: file_kind,
            };
            let _ = send_e2ee_file_ctrl(swarm, sessions, recipient, &offer);
            if swarm.is_connected(&recipient) {
                swarm
                    .behaviour_mut()
                    .file_rr
                    .send_request(&recipient, offer);
            }
            outgoing_transfers.insert(
                transfer_id,
                file_transfer::OutgoingTransfer {
                    peer: recipient,
                    transfer_id,
                    filename: filename.clone(),
                    chunks,
                    next_chunk: 0,
                    total_size,
                    is_relay,
                    last_chunk_at: Instant::now(),
                    accepted: false,
                    chunk_inflight: false,
                    sha256,
                    kind: file_kind,
                },
            );
            let _ = event_tx
                .send(NetworkEvent::FileProgress {
                    transfer_id,
                    sent_chunks: 0,
                    total_chunks,
                    filename,
                    total_size,
                    is_outgoing: true,
                    peer: recipient,
                    kind: file_kind,
                })
                .await;
        }
    }
}

async fn flush_pending_voice_transfers(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outgoing_transfers: &mut HashMap<[u8; 16], file_transfer::OutgoingTransfer>,
    relay_peers: &HashSet<PeerId>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    pending_voice_transfers: &mut HashMap<PeerId, Vec<PendingVoiceTransfer>>,
) {
    let Some(queue) = pending_voice_transfers.remove(&peer) else {
        return;
    };
    for item in queue {
        start_voice_file_transfer(
            swarm,
            sessions,
            outgoing_transfers,
            relay_peers,
            event_tx,
            peer,
            &item.path,
            item.transfer_id,
        )
        .await;
    }
}

async fn flush_pending_named_files(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outgoing_transfers: &mut HashMap<[u8; 16], file_transfer::OutgoingTransfer>,
    relay_peers: &HashSet<PeerId>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    pending_named_files: &mut HashMap<PeerId, Vec<PendingNamedFileTransfer>>,
    file_cache_key: &[u8; 32],
) {
    let Some(queue) = pending_named_files.remove(&peer) else {
        return;
    };
    for item in queue {
        start_named_file_transfer(
            swarm,
            sessions,
            outgoing_transfers,
            relay_peers,
            event_tx,
            peer,
            &item.path,
            item.transfer_id,
            item.filename,
            item.kind,
            file_cache_key,
        )
        .await;
    }
}

async fn flush_pending_read_receipts(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outbound_msg_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, String, Vec<u8>),
    >,
    outbound_delete_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, Vec<String>),
    >,
    event_tx: &mpsc::Sender<NetworkEvent>,
    peer: PeerId,
    pending_read_receipts: &mut HashMap<PeerId, Vec<Vec<String>>>,
    now: &str,
) {
    let Some(batches) = pending_read_receipts.remove(&peer) else {
        return;
    };
    for ids in batches {
        if ids.is_empty() {
            continue;
        }
        let Some(json_data) = crate::protocol::build_read_receipt_json(&ids) else {
            continue;
        };
        let _ = send_encrypted_chat_payload(
            swarm,
            sessions,
            outbound_msg_requests,
            outbound_delete_requests,
            event_tx,
            peer,
            json_data,
            Some(&ids),
            now,
        )
        .await;
    }
}

/// Запускает E2EE Hello, если сессии ещё нет. `force` сбрасывает «зависший»
/// pending-handshake (например после DialFailure, когда пир был офлайн).
/// Без force повтор разрешён только если Hello «завис» дольше ~20 с —
/// иначе новый ephemeral ломает ответ на старый Hello.
///
/// Hello шлёт только сторона с меньшим PeerId. Если оба шлют сразу, responder
/// создаёт *новый* ephemeral в ответе, а initiator уже взял ephemeral из
/// входящего Hello — ratchet не сходится. Текст уходит в мёртвую сессию,
/// а file Offer (без ratchet) всё равно доходит.
async fn ensure_e2ee_handshake_started(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_key: &libp2p::identity::Keypair,
    local_peer_id: PeerId,
    my_public_key: crypto::PublicKey,
    peer_id: PeerId,
    sessions: &HashMap<PeerId, crypto::SecureSession>,
    pending_handshakes: &mut HashMap<PeerId, crypto::StaticSecret>,
    handshake_started: &mut HashMap<PeerId, Instant>,
    now: &str,
    force: bool,
) -> bool {
    if sessions.contains_key(&peer_id) {
        return false;
    }
    // Responder ждёт входящий Hello. `force` — только если initiator молчит
    // (decrypt fail / Hello-вместо-Ack), иначе снова simultaneous Hello.
    if local_peer_id > peer_id && !force {
        return false;
    }
    const STALE_HELLO: Duration = Duration::from_secs(20);
    let stale = handshake_started
        .get(&peer_id)
        .map(|t| t.elapsed() >= STALE_HELLO)
        .unwrap_or(false);
    if force || stale {
        pending_handshakes.remove(&peer_id);
        handshake_started.remove(&peer_id);
    } else if pending_handshakes.contains_key(&peer_id) {
        return false;
    }
    let ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let ephem_pub = crypto::PublicKey::from(&ephem_secret);
    let Some(hello) = build_v1_hello(
        local_key,
        local_peer_id,
        peer_id,
        my_public_key,
        ephem_pub,
    ) else {
        debug!(
            "[{}] ❌ E2EE: не удалось подписать Hello для {}",
            now,
            &peer_id.to_string()[..8.min(peer_id.to_string().len())]
        );
        return false;
    };
    pending_handshakes.insert(peer_id, ephem_secret);
    handshake_started.insert(peer_id, Instant::now());
    let _ = send_v1_to_peer(swarm, peer_id, hello);
    debug!(
        "[{}] 🤝 E2EE: Hello (+Ephem) → {}{}",
        now,
        &peer_id.to_string()[..8.min(peer_id.to_string().len())],
        if force || stale { " (повтор)" } else { "" }
    );
    true
}

fn send_delete_ack_response(
    session: &mut crypto::SecureSession,
    channel: libp2p::request_response::ResponseChannel<V1Packet>,
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    deleted: &[String],
    missing: &[String],
) -> Option<libp2p::request_response::ResponseChannel<V1Packet>> {
    let Some(json) = build_delete_ack_json(deleted, missing) else {
        return Some(channel);
    };
    let Ok((header, ciphertext)) = session.encrypt_payload(json.as_slice()) else {
        return Some(channel);
    };
    let _ = swarm.behaviour_mut().request_response.send_response(
        channel,
        V1Packet::Encrypted { header, ciphertext },
    );
    None
}

pub async fn run_chat_network(
    mut command_rx: mpsc::Receiver<UICommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    command_tx_for_mdns: mpsc::Sender<UICommand>,
    local_key: libp2p::identity::Keypair,
    local_static: crypto::StaticSecret,
    void_bootstraps: Vec<Multiaddr>,
    contact_seed_addrs: Vec<(PeerId, Multiaddr)>,
    chat_messages: SharedChatMessages,
    file_cache_key: [u8; 32],
) {
        let mut void_bootstraps = void_bootstraps;
        let mut sessions: HashMap<PeerId, crypto::SecureSession> = HashMap::new();
        let mut session_established_at: HashMap<PeerId, Instant> = HashMap::new();
        let mut pending_handshakes: HashMap<PeerId, crypto::StaticSecret> = HashMap::new();
        let mut handshake_started: HashMap<PeerId, Instant> = HashMap::new();
        let mut pending_messages: HashMap<PeerId, Vec<Vec<u8>>> = HashMap::new();
        let mut pending_voice_transfers: HashMap<PeerId, Vec<PendingVoiceTransfer>> =
            HashMap::new();
        let mut pending_named_files: HashMap<PeerId, Vec<PendingNamedFileTransfer>> =
            HashMap::new();
        let mut pending_read_receipts: HashMap<PeerId, Vec<Vec<String>>> = HashMap::new();
        let my_public_key = crypto::PublicKey::from(&local_static);
        let my_public_key_bytes = my_public_key.to_bytes();
        let local_peer_id = local_key.public().to_peer_id();
        for ma in void_bootstraps.iter_mut() {
            if peer_id_from_multiaddr(ma) == Some(local_peer_id) {
                if let Some(tcp) = bootstrap_tcp_dial_addr(ma) {
                    *ma = tcp;
                }
            }
        }
        let mut peer_prekeys: HashMap<PeerId, [u8; 32]> = HashMap::new();
        let mut pending_kad_mail: HashMap<kad::QueryId, MailboxKadOp> = HashMap::new();
        let mut relay_mail_store = RelayMailbox::load();
        let mut fetch_mailbox_after = Some(Instant::now() + Duration::from_secs(5));
        let mut last_mailbox_query_at: Option<Instant> = None;
        let mut mailbox_fetch_attempts: u32 = 0;
        const MAX_MAILBOX_FETCH_ATTEMPTS: u32 = 30;

        let _instance_lock = match crate::paths::acquire_instance_lock() {
            Ok(f) => f,
            Err(msg) => {
                warn!("{}", msg);
                let _ = event_tx.send(NetworkEvent::Status(format!("❌ {msg}"))).await;
                return;
            }
        };

        let mut swarm = match build_void_swarm(
            local_key.clone(),
            &void_bootstraps,
            &contact_seed_addrs,
        ) {
            Ok(s) => s,
            Err(msg) => {
                warn!("❌ Swarm: {}", msg);
                let _ = event_tx
                    .send(NetworkEvent::Status(format!(
                        "❌ Не удалось инициализировать сеть: {}",
                        msg
                    )))
                    .await;
                return;
            }
        };

        // Слушаем TCP. Сначала пробуем 50001 (согласно правилам файрвола).
        let tcp_addr: Multiaddr = match "/ip4/0.0.0.0/tcp/50001".parse() {
            Ok(a) => a,
            Err(_) => {
                let _ = event_tx
                    .send(NetworkEvent::Status(
                        "❌ Внутренняя ошибка: некорректный TCP multiaddr.".into(),
                    ))
                    .await;
                return;
            }
        };

        if let Err(e) = swarm.listen_on(tcp_addr.clone()) {
            warn!("TCP 50001 занят ({:?}) — вторая копия VOID?", e);
            let _ = event_tx
                .send(NetworkEvent::Status(
                    "❌ Порт 50001 занят. Закройте ВСЕ копии VOID (трей и Диспетчер задач) и запустите снова. Вторая копия с тем же ключом рвёт соединение с нодой.".into(),
                ))
                .await;
            return;
        }

        // QUIC listen на клиенте не нужен для входа на bootstrap (только TCP).
        // Параллельный QUIC+TCP к ноде рвёт TCP (ApplicationClosed / yamux Closed).

        let mut bootstrap_peer_ids = bootstrap_peer_ids_from(&void_bootstraps);
        let mut onion_keys: HashMap<PeerId, [u8; 32]> = HashMap::new();
        onion_rt_set_keys(onion_keys.clone(), bootstrap_peer_ids.clone(), local_peer_id);

        let startup_status = if void_bootstraps.is_empty() {
            let lan = if std::env::var("VOID_DISABLE_MDNS").is_ok() {
                "LAN: mDNS отключён (VOID_DISABLE_MDNS)."
            } else {
                "LAN: mDNS."
            };
            format!(
                "🚀 Запущен. Войдите в сеть через IP или добавьте bootstrap в vault. {}",
                lan
            )
        } else {
            let lan = if std::env::var("VOID_DISABLE_MDNS").is_ok() {
                "mDNS в LAN отключён"
            } else {
                "mDNS в LAN"
            };
            format!(
                "🚀 Запущен. VOID DHT: {} bootstrap-узл(ов) (без IPFS) + {}.",
                void_bootstraps.len(),
                lan
            )
        };
        let _ = event_tx.send(NetworkEvent::Status(startup_status)).await;
        let _ = event_tx
            .send(NetworkEvent::Status(
                "набор VOID-ноды 147.78.64.22:4001".into(),
            ))
            .await;
        ensure_void_node_dial(&mut swarm, &bootstrap_peer_ids);
        // Не start_providing / put_record до Identify: Kademlia сама наберёт
        // bootstrap вторым TCP и обе сессии сразу умрут.

        let mut peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let mut pending_dials: HashSet<PeerId> = HashSet::new();
        // ─── Файловый sub-протокол ──────────────────────────────────────────
        // Пиры, подключённые через relay (p2p-circuit). К ним применяется rate-limit.
        let mut relay_peers: HashSet<PeerId> = HashSet::new();
        // Bootstrap peers with confirmed Hop ReservationReqAccepted only.
        // listen_on Ok is NOT enough — without Hop Ack Mac is undialable via circuit.
        let mut relay_circuit_reserved: HashSet<PeerId> = HashSet::new();
        let mut relay_listen_attempt_at: HashMap<PeerId, Instant> = HashMap::new();
        // listen_on уже вызван, ждём ReservationReqAccepted (не спамим Reserve).
        let mut relay_hop_pending: HashSet<PeerId> = HashSet::new();
        let mut relay_hop_listeners: HashMap<PeerId, ListenerId> = HashMap::new();
        // Отложенный Hop: даём relay behaviour зарегистрировать direct conn.
        let mut hop_listen_after: HashMap<PeerId, Instant> = HashMap::new();
        let mut bootstrap_hop_addr: HashMap<PeerId, Multiaddr> = HashMap::new();
        let mut kad_bootstrap_after: Option<Instant> = None;
        let swarm_started = Instant::now();
        // Consecutive ping failures for chat peers → drop zombie after threshold.
        let mut peer_ping_fail_streak: HashMap<PeerId, u32> = HashMap::new();
        // Throttle contact dials when chasing via bootstrap circuit.
        let mut contact_dial_at: HashMap<PeerId, Instant> = HashMap::new();
        let mut outgoing_transfers: HashMap<[u8; 16], file_transfer::OutgoingTransfer> =
            HashMap::new();
        // Входящие передачи: transfer_id → состояние.
        let mut incoming_transfers: HashMap<[u8; 16], file_transfer::IncomingTransfer> =
            HashMap::new();
        let mut chunk_send_rr: usize = 0;
        // Ticker для отправки чанков (с учётом rate-limit на relay).
        let mut chunk_tick = tokio::time::interval(Duration::from_millis(20));
        // RequestId → PeerId для зашифрованных сообщений, чтобы по ответу
        // (Ack/прочее) однозначно подтвердить доставку конкретному пиру и снять
        // pending-ретраи в UI. Hello-handshake'ы сюда НЕ попадают.
        let mut outbound_msg_requests: HashMap<
            libp2p::request_response::OutboundRequestId,
            (PeerId, String, Vec<u8>),
        > = HashMap::new();
        let mut outbound_delete_requests: HashMap<
            libp2p::request_response::OutboundRequestId,
            (PeerId, Vec<String>),
        > = HashMap::new();
        // RequestId → (peer, transfer_id, chunk_index) для чанков файлов/голосовых,
        // отправленных через E2EE `/void/chat`. Без этого `OutboundFailure` для
        // потерянного чанка был неотличим от провалившегося Hello-хендшейка —
        // чанк считался «отправленным» навсегда, и получатель никогда не
        // собирал файл целиком (голосовые «зависали» без повтора).
        let mut outbound_chunk_requests: HashMap<
            libp2p::request_response::OutboundRequestId,
            (PeerId, [u8; 16], u32),
        > = HashMap::new();
        let mut outbound_mailbox_stores: MailboxStoreTrack = HashMap::new();
        let mut outbound_prekey_gets: OutboundPrekeyGets = HashMap::new();
        let mut pending_relay = PendingRelayQueue::default();
        let mut pending_relay_gates: HashMap<(PeerId, PeerId), Arc<ActiveHandoff>> = HashMap::new();
        let mut dial_backoff: HashMap<PeerId, Instant> = HashMap::new();
        // Bootstrap PeerId → consecutive dial failures (for failover rotation).
        let mut bootstrap_fail_streak: HashMap<PeerId, u32> = HashMap::new();
        // Round-robin cursor into `void_bootstraps` after a bootstrap dial failure.
        let mut bootstrap_failover_idx: usize = 0;
        // Схлопываем подряд идущие `OutFailure` одному пиру: при отправке
        // сообщения без сессии мы шлём Hello + packet, и на DialFailure
        // оба улетают в лог дубликатом. Храним время последнего лога,
        // чтобы в UI и консоль ушло по одному «сообщение не доставлено».
        let mut last_rr_outfail: HashMap<PeerId, Instant> = HashMap::new();
        let mut local_listen_addrs: HashSet<Multiaddr> = HashSet::new();
        // Пиры-«seed», к которым мы дозвонились через JoinViaNode: после Identify запускаем DHT-bootstrap.
        let mut pending_seed_peers: HashSet<PeerId> = HashSet::new();
        let mut pending_seed_bare: bool = false;
        let mut bootstrap_identified: HashSet<PeerId> = HashSet::new();

        // ─── Автоматическое переподключение к контактам из vault ─────────────
        //
        // reconnect_targets: PeerId → список multiaddr (пополняется через Identify
        //   и DialPeer, чтобы использовать актуальные адреса после рестарта).
        // reconnect_queue:   PeerId → (когда_следующая_попытка, номер_попытки).
        //   Заполняется при ConnectionClosed; очищается при ConnectionEstablished.
        // Экспоненциальная выдержка: 5 с → 20 с → 60 с → 5 мин → 5 мин …
        let mut reconnect_targets: HashMap<PeerId, Vec<Multiaddr>> = {
            let mut m: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
            // Контакты из vault.
            for (pid, ma) in &contact_seed_addrs {
                m.entry(*pid).or_default().push(ma.clone());
            }
            // Bootstrap не кладём в reconnect_targets: redial_contact_hard
            // (PeerCondition::Always) открывает второй TCP и убивает первый.
            m
        };
        let mut reconnect_queue: HashMap<PeerId, (Instant, u32)> = HashMap::new();
        let mut reconnect_tick = tokio::time::interval(Duration::from_secs(5));
        reconnect_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut hop_tick = tokio::time::interval(Duration::from_millis(500));
        hop_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut provider_tick = tokio::time::interval(Duration::from_secs(10 * 60));
        provider_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut gossip_tick = tokio::time::interval(Duration::from_secs(2 * 60));
        gossip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut mailbox_tick = tokio::time::interval(Duration::from_millis(500));
        mailbox_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Первый tick() у interval сразу готов. Если обработать его до
        // swarm.select_next_some, стартовый dial ещё не зарегистрирован —
        // dial_missing_bootstraps открывает второй TCP, оба закрываются.
        reconnect_tick.tick().await;
        hop_tick.tick().await;
        mailbox_tick.tick().await;
        gossip_tick.tick().await;
        provider_tick.tick().await;
        chunk_tick.tick().await;

        loop {
            tokio::select! {
                _ = mailbox_tick.tick() => {
                    if let Some(deadline) = fetch_mailbox_after {
                        if Instant::now() >= deadline {
                            // RR-ящик до Hop забивает HOP-стримы. Ждём Hop Ack.
                            if relay_circuit_reserved.is_empty()
                                && swarm_started.elapsed() < Duration::from_secs(90)
                            {
                                fetch_mailbox_after = Some(Instant::now() + Duration::from_secs(2));
                                continue;
                            }
                            // Почта только с bootstrap-нод (RR), без DHT-ящика.
                            let sent = query_relay_mailbox_with_bootstraps(
                                &mut swarm,
                                local_peer_id,
                                &bootstrap_peer_ids,
                                &void_bootstraps,
                                &mut last_mailbox_query_at,
                            );
                            if sent {
                                mailbox_fetch_attempts =
                                    mailbox_fetch_attempts.saturating_add(1);
                                // Частый poll: без живого circuit доставка только через
                                // ящик; 10–30 с выглядели как «сообщения идут очень долго».
                                let gap = if mailbox_fetch_attempts
                                    < MAX_MAILBOX_FETCH_ATTEMPTS
                                {
                                    Duration::from_secs(2)
                                } else {
                                    Duration::from_secs(5)
                                };
                                fetch_mailbox_after = Some(Instant::now() + gap);
                            }
                        }
                    }
                }
                // ─── Tick: эпидемический обмен bootstrap-нодами (2 мин) ─────
                _ = gossip_tick.tick() => {
                    let addrs = bootstrap_gossip_strings(&void_bootstraps);
                    fanout_bootstrap_gossip(
                        &mut swarm,
                        local_peer_id,
                        &bootstrap_peer_ids,
                        addrs,
                        collect_onion_hints(&onion_keys, &void_bootstraps),
                        None,
                    );
                }
                // ─── Tick: переподключение к контактам (5 с) ────────────────
                _ = reconnect_tick.tick() => {
                    let now = Instant::now();
                    let connected: HashSet<PeerId> = swarm.connected_peers().copied().collect();
                    let to_dial: Vec<(PeerId, Vec<Multiaddr>)> = reconnect_queue
                        .iter()
                        .filter(|(pid, (when, _))| now >= *when && !connected.contains(*pid))
                        .filter_map(|(pid, _)| {
                            reconnect_targets.get(pid).map(|addrs| (*pid, addrs.clone()))
                        })
                        .collect();

                    for (pid, addrs) in to_dial {
                        if bootstrap_peer_ids.contains(&pid) {
                            continue;
                        }
                        let _ = addrs;
                        let attempt = reconnect_queue
                            .get(&pid)
                            .map(|(_, a)| *a)
                            .unwrap_or(1);
                        debug!(
                            "🔄 Автореконнект: {} (circuit+LAN, попытка {}).",
                            &pid.to_string()[..8],
                            attempt
                        );
                        redial_contact_hard(
                            &mut swarm,
                            pid,
                            &reconnect_targets,
                            &void_bootstraps,
                        );
                    }
                    // Circuit к контактам — только после Hop Ack, иначе Reserve
                    // на том же TCP к ноде не доживает до Ack.
                    dial_unconnected_contacts(
                        &mut swarm,
                        &reconnect_targets,
                        &bootstrap_peer_ids,
                        &void_bootstraps,
                        &mut contact_dial_at,
                        Duration::from_secs(45),
                        !relay_circuit_reserved.is_empty(),
                    );
                    onion_rt_set_keys(
                        onion_keys.clone(),
                        bootstrap_peer_ids.clone(),
                        local_peer_id,
                    );
                    if !onion_keys.is_empty() {
                        let now_on = chrono::Local::now().format("%H:%M:%S").to_string();
                        let onion_hello: Vec<PeerId> = reconnect_targets
                            .keys()
                            .copied()
                            .filter(|p| {
                                !sessions.contains_key(p)
                                    && !bootstrap_peer_ids.contains(p)
                                    && *p != local_peer_id
                            })
                            .collect();
                        for pid in onion_hello {
                            let _ = ensure_e2ee_handshake_started(
                                &mut swarm,
                                &local_key,
                                local_peer_id,
                                my_public_key,
                                pid,
                                &sessions,
                                &mut pending_handshakes,
                                &mut handshake_started,
                                &now_on,
                                false,
                            )
                            .await;
                        }
                    }
                    // Тянем остальные VOID-ноды: резервация пира может быть не на
                    // той же, к которой мы уже подключены (bootstrap 1/6 → N/6).
                    dial_missing_bootstraps(
                        &mut swarm,
                        &bootstrap_peer_ids,
                        &void_bootstraps,
                    );
                    // Outbox mail waiting for bootstrap dial must not die with a
                    // single failed attempt — re-dial while the process is alive.
                    for pid in pending_relay.relay_peer_ids() {
                        if connected.contains(&pid) {
                            continue;
                        }
                        let addrs: Vec<Multiaddr> = void_bootstraps
                            .iter()
                            .filter(|ma| peer_id_from_multiaddr(ma) == Some(pid))
                            .cloned()
                            .collect();
                        if !addrs.is_empty() {
                            dial_bootstrap_direct(&mut swarm, pid, addrs);
                        }
                    }
                    // Сообщения, застрявшие в pending при живой E2EE (файлы уже ходят).
                    // Не раньше ~800 мс после Hello: иначе Encrypted прилетает
                    // initiator'у до его сессии → Hello-вместо-Ack → сброс ratchet.
                    let flush_peers: Vec<PeerId> = pending_messages
                        .iter()
                        .filter(|(p, q)| {
                            !q.is_empty()
                                && sessions.contains_key(p)
                                && session_established_at
                                    .get(p)
                                    .map(|t| t.elapsed() >= Duration::from_millis(800))
                                    .unwrap_or(false)
                        })
                        .map(|(p, _)| *p)
                        .collect();
                    if !flush_peers.is_empty() {
                        let now_flush =
                            chrono::Local::now().format("%H:%M:%S").to_string();
                        for peer in flush_peers {
                            flush_pending_encrypted_messages(
                                &mut swarm,
                                &mut sessions,
                                &mut outbound_msg_requests,
                                &mut outbound_delete_requests,
                                &event_tx,
                                peer,
                                &mut pending_messages,
                                &now_flush,
                            )
                            .await;
                        }
                    }
                }
                // ─── Tick: переобъявление себя в DHT (каждые 10 мин) ───────
                _ = provider_tick.tick() => {
                    publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
                    publish_self_prekey(&mut swarm, local_peer_id, &my_public_key_bytes);
                    publish_self_prekey_to_bootstraps(
                        &mut swarm,
                        local_peer_id,
                        &my_public_key_bytes,
                        &bootstrap_peer_ids,
                    );
                }
                // ─── Tick: отправка очередных чанков с rate-limit ───────────
                _ = chunk_tick.tick() => {
                    promote_pending_hop_if_due(
                        &swarm,
                        &bootstrap_peer_ids,
                        &mut relay_circuit_reserved,
                        &mut relay_hop_pending,
                        &mut hop_listen_after,
                        &relay_listen_attempt_at,
                        &event_tx,
                    );
                    const VOICE_OFFER_STALE: Duration = Duration::from_secs(90);
                    let voice_reoffer: Vec<([u8; 16], PeerId)> = outgoing_transfers
                        .iter()
                        .filter(|(_, t)| {
                            file_transfer::is_voice_filename(&t.filename)
                                && !t.accepted
                                && t.next_chunk == 0
                                && t.last_chunk_at.elapsed() >= VOICE_OFFER_RESEND
                        })
                        .map(|(id, t)| (*id, t.peer))
                        .collect();
                    for (tid, peer) in voice_reoffer {
                        resend_voice_offer(
                            &mut swarm,
                            &mut sessions,
                            &mut outgoing_transfers,
                            tid,
                            peer,
                        )
                        .await;
                    }

                    let stale_voice: Vec<[u8; 16]> = outgoing_transfers
                        .iter()
                        .filter(|(_, t)| {
                            file_transfer::is_voice_filename(&t.filename)
                                && !t.accepted
                                && t.next_chunk == 0
                                && t.last_chunk_at.elapsed() >= VOICE_OFFER_STALE
                        })
                        .map(|(id, _)| *id)
                        .collect();
                    for tid in stale_voice {
                        if let Some(t) = outgoing_transfers.remove(&tid) {
                            crate::voice::voice_log(&format!(
                                "voice offer stale, drop {}",
                                transfer_id_to_hex(&tid)
                            ));
                            let _ = event_tx
                                .send(NetworkEvent::FileError {
                                    transfer_id: tid,
                                    reason: format!(
                                        "Таймаут передачи «{}» — будет повтор",
                                        t.filename
                                    ),
                                })
                                .await;
                        }
                    }

                    let ready: Vec<[u8; 16]> = outgoing_transfers
                        .iter()
                        .filter(|(_, t)| t.ready_to_send())
                        .map(|(id, _)| *id)
                        .collect();
                    let to_send: Option<([u8; 16], u32, Vec<u8>, PeerId)> =
                        if ready.is_empty() {
                            None
                        } else {
                            chunk_send_rr = (chunk_send_rr + 1) % ready.len().max(1);
                            let tid = ready[chunk_send_rr % ready.len()];
                            outgoing_transfers.get(&tid).map(|t| {
                                let idx = t.next_chunk as u32;
                                let data = t.chunks[t.next_chunk].clone();
                                (tid, idx, data, t.peer)
                            })
                        };
                    if let Some((tid, chunk_idx, data, peer)) = to_send {
                        let frame =
                            file_transfer::encode_e2ee_file_chunk_frame(&tid, chunk_idx, &data);
                        let sent_request_id = sessions
                            .get_mut(&peer)
                            .and_then(|session| session.encrypt_payload(&frame).ok())
                            .map(|(header, ciphertext)| {
                                let pkt = V1Packet::Encrypted {
                                    header,
                                    ciphertext,
                                };
                                send_v1_to_peer(&mut swarm, peer, pkt)
                            });

                        if let Some(req_id) = sent_request_id {
                            outbound_chunk_requests.insert(req_id, (peer, tid, chunk_idx));
                            if let Some(t) = outgoing_transfers.get_mut(&tid) {
                                t.next_chunk += 1;
                                t.chunk_inflight = true;
                                t.last_chunk_at = Instant::now();
                            }
                            if let Some(t) = outgoing_transfers.get(&tid) {
                                let sent = t.next_chunk as u32;
                                let total = t.total_chunks();
                                let fname = t.filename.clone();
                                let sz = t.total_size;
                                let fkind = t.kind;
                                let _ = event_tx
                                    .send(NetworkEvent::FileProgress {
                                        transfer_id: tid,
                                        sent_chunks: sent,
                                        total_chunks: total,
                                        filename: fname,
                                        total_size: sz,
                                        is_outgoing: true,
                                        peer,
                                        kind: fkind,
                                    })
                                    .await;
                            }
                        } else {
                            debug!(
                                "⚠️ FILE: не удалось зашифровать чанк {} для {} (нет E2EE-сессии) — повторим.",
                                chunk_idx,
                                &peer.to_string()[..8]
                            );
                            // Подталкиваем хендшейк — иначе Accept есть, а чанки вечно стоят.
                            if swarm.is_connected(&peer) && !sessions.contains_key(&peer) {
                                let now_hs =
                                    chrono::Local::now().format("%H:%M:%S").to_string();
                                let _ = ensure_e2ee_handshake_started(
                                    &mut swarm,
                                    &local_key,
                                    local_peer_id,
                                    my_public_key,
                                    peer,
                                    &sessions,
                                    &mut pending_handshakes,
                                    &mut handshake_started,
                                    &now_hs,
                                    false,
                                )
                                .await;
                            }
                        }
                    }
                }
                cmd = command_rx.recv() => {
                    if let Some(c) = cmd {
                        match c {
                            UICommand::Dial(addr_str) => {
                                match addr_str.parse::<Multiaddr>() {
                                    Ok(addr) => {
                                        let _ = event_tx.send(NetworkEvent::Status(
                                            format!("📞 Подключаюсь к {}...", &addr_str[..addr_str.len().min(50)])
                                        )).await;
                                        let is_boot = void_bootstraps.iter().any(|b| {
                                            addr_endpoint_key(b) == addr_endpoint_key(&addr)
                                        });
                                        if is_boot {
                                            let pid = peer_id_from_multiaddr(&addr)
                                                .unwrap_or(local_peer_id);
                                            dial_bootstrap_direct(&mut swarm, pid, vec![addr]);
                                        } else {
                                            match swarm.dial(addr) {
                                                Ok(_) => {
                                                    let _ = event_tx.send(NetworkEvent::Status("⏳ Dial отправлен...".into())).await;
                                                }
                                                Err(e) => {
                                                    let _ = event_tx.send(NetworkEvent::Status(
                                                        format!("❌ Ошибка подключения: {}", e)
                                                    )).await;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(NetworkEvent::Status(
                                            format!("❌ Неверный адрес: {}", e)
                                        )).await;
                                    }
                                }
                            }
                            UICommand::SearchPeer(peer_id) => {
                                if peer_id == local_peer_id {
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(
                                            "⚠ Подключение к своему PeerId бессмысленно.".into(),
                                        ))
                                        .await;
                                } else if bootstrap_peer_ids.contains(&peer_id) {
                                    let addrs: Vec<Multiaddr> = void_bootstraps
                                        .iter()
                                        .filter(|ma| peer_id_from_multiaddr(ma) == Some(peer_id))
                                        .cloned()
                                        .collect();
                                    dial_bootstrap_direct(&mut swarm, peer_id, addrs);
                                } else {
                                    watch_contact_peer(
                                        &mut reconnect_targets,
                                        peer_id,
                                        &bootstrap_peer_ids,
                                        local_peer_id,
                                    );
                                    // Сразу circuit через живой bootstrap —
                                    // иначе при пустой Kademlia ждём DHT и «не в сети»
                                    // зависает, пока собеседник сам не дозвонится.
                                    dial_peer_live_circuits(
                                        &mut swarm,
                                        peer_id,
                                        &void_bootstraps,
                                        false,
                                    );
                                    if let Some(addrs) = kad_local_addrs_for_peer(
                                        &mut swarm.behaviour_mut().kad,
                                        peer_id,
                                    ) {
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(format!(
                                                "📍 Пир {} найден в локальной таблице Kademlia ({} адр.) — набор.",
                                                &peer_id.to_string()[..12],
                                                addrs.len()
                                            )))
                                            .await;
                                        let _ = command_tx_for_mdns.try_send(UICommand::DialPeer(
                                            peer_id,
                                            addrs,
                                        ));
                                    } else {
                                        let _ = event_tx.send(NetworkEvent::Status(
                                            format!("🔍 Запрос DHT: {}… (providers + closest)", &peer_id.to_string()[..16])
                                        )).await;
                                        let key = peer_dht_record_key(peer_id);
                                        swarm.behaviour_mut().kad.get_providers(key);
                                        swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                                    }
                                }
                            }
                            UICommand::WatchContacts(peers) => {
                                for peer_id in peers {
                                    watch_contact_peer(
                                        &mut reconnect_targets,
                                        peer_id,
                                        &bootstrap_peer_ids,
                                        local_peer_id,
                                    );
                                }
                                // Не dial здесь: команда приходит в ту же миллисекунду, что
                                // стартовый bootstrap, и circuit открывает второй TCP.
                            }
                            UICommand::ForgetContact(peer_id) => {
                                reconnect_targets.remove(&peer_id);
                                reconnect_queue.remove(&peer_id);
                                contact_dial_at.remove(&peer_id);
                                pending_dials.remove(&peer_id);
                                if !bootstrap_peer_ids.contains(&peer_id) {
                                    let _ = swarm.disconnect_peer_id(peer_id);
                                }
                            }
                            UICommand::EnsureChatSession(peer_id) => {
                                if peer_id == local_peer_id
                                    || bootstrap_peer_ids.contains(&peer_id)
                                {
                                    continue;
                                }
                                watch_contact_peer(
                                    &mut reconnect_targets,
                                    peer_id,
                                    &bootstrap_peer_ids,
                                    local_peer_id,
                                );
                                if !peer_prekeys.contains_key(&peer_id) {
                                    let qid = swarm
                                        .behaviour_mut()
                                        .kad
                                        .get_record(prekey_record_key(peer_id));
                                    pending_kad_mail.insert(
                                        qid,
                                        MailboxKadOp::CachePrekey {
                                            peer: peer_id,
                                            prekey_bytes: None,
                                        },
                                    );
                                }
                                if !swarm.is_connected(&peer_id) {
                                    // Circuit-first; LAN separately. Не кормим dial
                                    // ephemeral NAT из Listener — они блокируют набор.
                                    dial_peer_live_circuits(
                                        &mut swarm,
                                        peer_id,
                                        &void_bootstraps,
                                        false,
                                    );
                                    let lan: Vec<Multiaddr> = peer_addrs
                                        .get(&peer_id)
                                        .into_iter()
                                        .flatten()
                                        .chain(
                                            reconnect_targets
                                                .get(&peer_id)
                                                .into_iter()
                                                .flatten(),
                                        )
                                        .filter(|a| is_likely_lan_addr(a) && !is_junk_addr(a))
                                        .cloned()
                                        .collect();
                                    if !lan.is_empty() {
                                        dial_peer_best_effort(
                                            &mut swarm,
                                            peer_id,
                                            lan,
                                            &void_bootstraps,
                                        );
                                    }
                                    // Hello after ConnectionEstablished — not now.
                                    continue;
                                }
                                let now_hs =
                                    chrono::Local::now().format("%H:%M:%S").to_string();
                                // Do not force — ConnectionEstablished may already have
                                // a valid pending Hello; clobbering it breaks E2EE.
                                let _ = ensure_e2ee_handshake_started(
                                    &mut swarm,
                                    &local_key,
                                    local_peer_id,
                                    my_public_key,
                                    peer_id,
                                    &sessions,
                                    &mut pending_handshakes,
                                    &mut handshake_started,
                                    &now_hs,
                                    false,
                                )
                                .await;
                            }
                            UICommand::DialPeer(peer_id, addrs) => {
                                 if bootstrap_peer_ids.contains(&peer_id) {
                                     dial_bootstrap_direct(&mut swarm, peer_id, addrs);
                                     continue;
                                 }
                                 let short = &peer_id.to_string()[..16];
                                 watch_contact_peer(
                                     &mut reconnect_targets,
                                     peer_id,
                                     &bootstrap_peer_ids,
                                     local_peer_id,
                                 );
                                 // Только LAN/circuit в книгу реконнекта — без public NAT.
                                 let safe: Vec<Multiaddr> = addrs
                                     .into_iter()
                                     .map(|a| normalize_peer_addr(a, peer_id))
                                     .filter(|a| is_usable_contact_redial_addr(a))
                                     .collect();
                                 {
                                     let list = reconnect_targets.entry(peer_id).or_default();
                                     list.retain(is_usable_contact_redial_addr);
                                     for addr in &safe {
                                         if !list.contains(addr) {
                                             list.push(addr.clone());
                                         }
                                         swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                     }
                                 }
                                 let lan: Vec<Multiaddr> = safe
                                     .iter()
                                     .filter(|a| !is_circuit_addr(a))
                                     .cloned()
                                     .collect();
                                 debug!(
                                     "🔌 UI_COMMAND: DialPeer {} (lan={}, circuit-first)",
                                     short,
                                     lan.len()
                                 );
                                 dial_peer_live_circuits(
                                     &mut swarm,
                                     peer_id,
                                     &void_bootstraps,
                                     false,
                                 );
                                 if !lan.is_empty() {
                                     dial_peer_best_effort(
                                         &mut swarm,
                                         peer_id,
                                         lan,
                                         &void_bootstraps,
                                     );
                                 } else if !bootstrap_peer_ids
                                     .iter()
                                     .any(|b| swarm.is_connected(b))
                                 {
                                     let _ = event_tx
                                         .send(NetworkEvent::Status(format!(
                                             "🔍 У {} нет LAN/relay — ищу через DHT…",
                                             short
                                         )))
                                         .await;
                                     swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                                 }
                             }
                            UICommand::JoinViaNode(input) => {
                                let parsed = parse_seed_dial_addrs(&input);
                                match parsed {
                                    Some((addrs, peer_id_opt)) => {
                                        if let Some(pid) = peer_id_opt {
                                            pending_seed_peers.insert(pid);
                                        } else {
                                            pending_seed_bare = true;
                                        }
                                        let pid = peer_id_opt
                                            .unwrap_or(*swarm.local_peer_id());
                                        dial_bootstrap_direct(&mut swarm, pid, addrs);
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(
                                                "📞 Вход в сеть: один TCP без проверки /p2p/…".into(),
                                            ))
                                            .await;
                                    }
                                    None => {
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(format!(
                                                "⚠ Не понял адрес: {}. Нужен IP, IP:PORT или /ip4/…/udp/…/quic-v1[/p2p/…]",
                                                input
                                            )))
                                            .await;
                                    }
                                }
                            }
                            UICommand::ReloadBootstraps(vault_bootstraps) => {
                                let merged = void_bootstrap_multiaddrs(&vault_bootstraps);
                                if merged.is_empty() {
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(
                                            "Нет bootstrap: добавьте ноду в vault (вход в сеть) или задайте VOID_BOOTSTRAP."
                                                .into(),
                                        ))
                                        .await;
                                } else {
                                    let added = merge_bootstraps_into_swarm(
                                        &mut swarm,
                                        &mut void_bootstraps,
                                        &mut bootstrap_peer_ids,
                                        &merged,
                                    );
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(format!(
                                            "🌐 VOID: {} bootstrap-узл(ов) из vault ({} новых).",
                                            merged.len(),
                                            added
                                        )))
                                        .await;
                                }
                            }
                            UICommand::SnapshotDhtRoutingPeers => {
                                let ids = kad_routing_peer_ids(&mut swarm.behaviour_mut().kad);
                                let total = ids.len();
                                let lines: Vec<String> = ids
                                    .iter()
                                    .take(256)
                                    .map(|p| p.to_string())
                                    .collect();
                                let _ = event_tx
                                    .send(NetworkEvent::DhtRoutingPeers { total, lines })
                                    .await;
                            }
                            UICommand::SendMessage {
                                sender_name,
                                text,
                                recipient,
                                message_id,
                                is_retry,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                debug!(
                                    target: "void_net",
                                    time = %now,
                                    text_len = text.len(),
                                    has_recipient = recipient.is_some(),
                                    is_retry,
                                    "UI_SEND"
                                );
                                let msg_id = message_id.unwrap_or_else(new_message_id);
                                let msg = ChatMessage {
                                    id: msg_id,
                                    sender_id: local_peer_id.to_string(),
                                    sender_name: sender_name.clone(),
                                    recipient_id: recipient.map(|p| p.to_string()),
                                    text: text.clone(),
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                    delivery: OutgoingDeliveryStatus::Pending,
                                    voice: None,
                                    file: None,
                                    group_id: None,
                                };

                                let json_data = match serde_json::to_vec(&msg) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        debug!(
                                            "[{}] ❌ UI_SEND: serde_json сообщения: {}",
                                            now, e
                                        );
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(format!(
                                                "❌ Не удалось сериализовать сообщение: {}",
                                                e
                                            )))
                                            .await;
                                        if !is_retry {
                                            let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                        }
                                        continue;
                                    }
                                };

                                if let Some(peer_id) = recipient {
                                    // Same-NAT / no direct path: kick DHT + dial
                                    // (incl. bootstrap circuit) before handshake/send.
                                    let connected = swarm.is_connected(&peer_id);
                                    if !connected {
                                        let key = peer_dht_record_key(peer_id);
                                        swarm.behaviour_mut().kad.get_providers(key);
                                        swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                                        if !peer_prekeys.contains_key(&peer_id) {
                                            let qid = swarm
                                                .behaviour_mut()
                                                .kad
                                                .get_record(prekey_record_key(peer_id));
                                            pending_kad_mail.insert(
                                                qid,
                                                MailboxKadOp::CachePrekey {
                                                    peer: peer_id,
                                                    prekey_bytes: None,
                                                },
                                            );
                                        }
                                        dial_peer_live_circuits(
                                            &mut swarm,
                                            peer_id,
                                            &void_bootstraps,
                                            false,
                                        );
                                        let lan: Vec<Multiaddr> = peer_addrs
                                            .get(&peer_id)
                                            .into_iter()
                                            .flatten()
                                            .chain(
                                                reconnect_targets
                                                    .get(&peer_id)
                                                    .into_iter()
                                                    .flatten(),
                                            )
                                            .chain(
                                                contact_seed_addrs
                                                    .iter()
                                                    .filter(|(p, _)| *p == peer_id)
                                                    .map(|(_, a)| a),
                                            )
                                            .filter(|a| is_likely_lan_addr(a) && !is_junk_addr(a))
                                            .cloned()
                                            .collect();
                                        if !lan.is_empty() {
                                            dial_peer_best_effort(
                                                &mut swarm,
                                                peer_id,
                                                lan,
                                                &void_bootstraps,
                                            );
                                        }
                                        debug!(
                                            "[{}] 📡 UI_SEND: circuit/LAN dial к {} (нет живой сессии)",
                                            now,
                                            &peer_id.to_string()[..8]
                                        );
                                    }
                                    if sessions.contains_key(&peer_id) {
                                        let msg_id_for_send =
                                            chat_message_id_from_json(json_data.as_slice());
                                        // Retry: снимаем залипший in-flight (таймаут ещё не пришёл).
                                        if is_retry {
                                            if let Some(ref mid) = msg_id_for_send {
                                                outbound_msg_requests.retain(|_, (p, id, _)| {
                                                    !(*p == peer_id && id == mid)
                                                });
                                            }
                                        }
                                        let in_flight = msg_id_for_send.as_ref().is_some_and(|mid| {
                                            outbound_msg_requests
                                                .values()
                                                .any(|(p, id, _)| *p == peer_id && id == mid)
                                        });
                                        if in_flight {
                                            debug!(
                                                "[{}] ⏭ E2EE: {} уже в полёте к {}",
                                                now,
                                                msg_id_for_send
                                                    .as_deref()
                                                    .map(|s| &s[..8.min(s.len())])
                                                    .unwrap_or("?"),
                                                &peer_id.to_string()[..8]
                                            );
                                        } else {
                                            let _ = send_encrypted_chat_payload(
                                                &mut swarm,
                                                &mut sessions,
                                                &mut outbound_msg_requests,
                                                &mut outbound_delete_requests,
                                                &event_tx,
                                                peer_id,
                                                json_data,
                                                None,
                                                &now,
                                            )
                                            .await;
                                        }
                                        // Заодно сливаем всё, что застряло в буфере «до сессии».
                                        flush_pending_encrypted_messages(
                                            &mut swarm,
                                            &mut sessions,
                                            &mut outbound_msg_requests,
                                            &mut outbound_delete_requests,
                                            &event_tx,
                                            peer_id,
                                            &mut pending_messages,
                                            &now,
                                        )
                                        .await;
                                    } else {
                                        // Never Hello until connected — bare send_request
                                        // dials without circuit addrs and fails → stuck ○.
                                        // Never force Hello on normal send — that clobbers
                                        // an in-flight ephem secret and breaks the ratchet.
                                        if connected {
                                            let _ = ensure_e2ee_handshake_started(
                                                &mut swarm,
                                                &local_key,
                                                local_peer_id,
                                                my_public_key,
                                                peer_id,
                                                &sessions,
                                                &mut pending_handshakes,
                                                &mut handshake_started,
                                                &now,
                                                false,
                                            )
                                            .await;
                                        }
                                        let msg_id_for_dedup =
                                            chat_message_id_from_json(json_data.as_slice());
                                        let queue = pending_messages.entry(peer_id).or_default();
                                        if let Some(ref mid) = msg_id_for_dedup {
                                            if queue.iter().any(|b| {
                                                chat_message_id_from_json(b.as_slice()).as_deref()
                                                    == Some(mid.as_str())
                                            }) {
                                                debug!(
                                                    "[{}] ⏭ E2EE: сообщение {} уже в буфере для {}",
                                                    now,
                                                    &mid[..8.min(mid.len())],
                                                    &peer_id.to_string()[..8]
                                                );
                                            } else {
                                                queue.push(json_data);
                                            }
                                        } else {
                                            queue.push(json_data);
                                        }
                                        let _ = event_tx
                                            .send(NetworkEvent::MessageAwaitingSession(peer_id))
                                            .await;
                                        // Offline nudge only when we are NOT live-connected.
                                        if !connected {
                                            let _ = event_tx
                                                .send(NetworkEvent::SendFailedDial(peer_id))
                                                .await;
                                        }
                                        debug!(
                                            "[{}] ⏳ E2EE: Сообщение буферизовано до хендшейка с {}",
                                            now,
                                            &peer_id.to_string()[..8]
                                        );
                                    }
                                } else {
                                    debug!(
                                        "[{}] ⚠️ Попытка отправить сообщение без получателя (Global Chat отключен)",
                                        now
                                    );
                                }
                                if !is_retry {
                                    let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                }
                            }
                            UICommand::SendGroupMessage {
                                sender_name,
                                text,
                                group_id,
                                members,
                                message_id,
                                is_retry,
                                voice_path,
                                voice_duration_secs,
                                voice_transfer_id,
                                voice_only_members,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let msg_id = message_id.unwrap_or_else(new_message_id);
                                let me = local_peer_id.to_string();
                                let has_voice = voice_path
                                    .as_ref()
                                    .is_some_and(|p| !p.is_empty())
                                    && voice_transfer_id.is_some();
                                let base_tid = voice_transfer_id.unwrap_or([0u8; 16]);
                                let voice_path = voice_path.unwrap_or_default();
                                let msg = ChatMessage {
                                    id: msg_id.clone(),
                                    sender_id: me.clone(),
                                    sender_name: sender_name.clone(),
                                    recipient_id: None,
                                    text: if has_voice {
                                        String::new()
                                    } else {
                                        text.clone()
                                    },
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                    delivery: OutgoingDeliveryStatus::Pending,
                                    voice: if has_voice {
                                        Some(VoiceMeta {
                                            transfer_id: transfer_id_to_hex(&base_tid),
                                            duration_secs: voice_duration_secs,
                                        })
                                    } else {
                                        None
                                    },
                                    file: None,
                                    group_id: Some(group_id.clone()),
                                };
                                for peer_id in members {
                                    if peer_id == local_peer_id {
                                        continue;
                                    }
                                    let send_chat = !voice_only_members.contains(&peer_id);
                                    let peer_tid = if has_voice {
                                        per_peer_voice_transfer_id(&base_tid, peer_id)
                                    } else {
                                        base_tid
                                    };
                                    let mut per_peer_msg = msg.clone();
                                    if has_voice {
                                        per_peer_msg.voice = Some(VoiceMeta {
                                            transfer_id: transfer_id_to_hex(&peer_tid),
                                            duration_secs: voice_duration_secs,
                                        });
                                    }
                                    let per_json = match serde_json::to_vec(&per_peer_msg) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                    if sessions.contains_key(&peer_id) {
                                        if send_chat {
                                            let msg_id_for_send =
                                                chat_message_id_from_json(per_json.as_slice());
                                            let in_flight = msg_id_for_send.as_ref().is_some_and(|mid| {
                                                outbound_msg_requests.values().any(|(p, id, _)| {
                                                    *p == peer_id && id == mid
                                                })
                                            });
                                            if !in_flight {
                                                let _ = send_encrypted_chat_payload(
                                                    &mut swarm,
                                                    &mut sessions,
                                                    &mut outbound_msg_requests,
                                                    &mut outbound_delete_requests,
                                                    &event_tx,
                                                    peer_id,
                                                    per_json,
                                                    None,
                                                    &now,
                                                )
                                                .await;
                                            }
                                        }
                                        if has_voice {
                                            start_voice_file_transfer(
                                                &mut swarm,
                                                &mut sessions,
                                                &mut outgoing_transfers,
                                                &relay_peers,
                                                &event_tx,
                                                peer_id,
                                                &voice_path,
                                                peer_tid,
                                            )
                                            .await;
                                        }
                                    } else {
                                        if swarm.is_connected(&peer_id) {
                                            let _ = ensure_e2ee_handshake_started(
                                                &mut swarm,
                                                &local_key,
                                                local_peer_id,
                                                my_public_key,
                                                peer_id,
                                                &sessions,
                                                &mut pending_handshakes,
                                                &mut handshake_started,
                                                &now,
                                                false,
                                            )
                                            .await;
                                        }
                                        if send_chat {
                                            let queue =
                                                pending_messages.entry(peer_id).or_default();
                                            if let Some(ref mid) =
                                                chat_message_id_from_json(per_json.as_slice())
                                            {
                                                if !queue.iter().any(|b| {
                                                    chat_message_id_from_json(b.as_slice())
                                                        .as_deref()
                                                        == Some(mid.as_str())
                                                }) {
                                                    queue.push(per_json);
                                                }
                                            } else {
                                                queue.push(per_json);
                                            }
                                        }
                                        if has_voice {
                                            let vq =
                                                pending_voice_transfers.entry(peer_id).or_default();
                                            if !vq.iter().any(|v| v.transfer_id == peer_tid) {
                                                vq.push(PendingVoiceTransfer {
                                                    path: voice_path.clone(),
                                                    transfer_id: peer_tid,
                                                });
                                            }
                                            let _ = event_tx
                                                .send(NetworkEvent::VoiceSendDeferred {
                                                    recipient: peer_id,
                                                    path: voice_path.clone(),
                                                    duration_secs: voice_duration_secs,
                                                    message_id: msg_id.clone(),
                                                    transfer_id: peer_tid,
                                                })
                                                .await;
                                        }
                                        let _ = event_tx
                                            .send(NetworkEvent::MessageAwaitingSession(peer_id))
                                            .await;
                                    }
                                }
                                // Атомарность: голосовое групповое не показываем здесь — только
                                // когда voice_ack(ok=true) придёт от ВСЕХ участников (apply_voice_ack).
                                // Текстовые групповые сообщения показываем как раньше — сразу.
                                if !is_retry && !has_voice {
                                    let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                } else {
                                    let _ = msg;
                                }
                            }
                            UICommand::SendGroupSync {
                                group_id,
                                group_name,
                                creator_id,
                                members,
                                recipients,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let Some(json_data) = build_group_sync_json(
                                    &group_id,
                                    &group_name,
                                    &creator_id,
                                    &members,
                                ) else {
                                    continue;
                                };
                                for peer_id in recipients {
                                    if peer_id == local_peer_id {
                                        continue;
                                    }
                                    if sessions.contains_key(&peer_id) {
                                        let _ = send_encrypted_chat_payload(
                                            &mut swarm,
                                            &mut sessions,
                                            &mut outbound_msg_requests,
                                            &mut outbound_delete_requests,
                                            &event_tx,
                                            peer_id,
                                            json_data.clone(),
                                            None,
                                            &now,
                                        )
                                        .await;
                                    } else {
                                        if swarm.is_connected(&peer_id) {
                                            let _ = ensure_e2ee_handshake_started(
                                                &mut swarm,
                                                &local_key,
                                                local_peer_id,
                                                my_public_key,
                                                peer_id,
                                                &sessions,
                                                &mut pending_handshakes,
                                                &mut handshake_started,
                                                &now,
                                                false,
                                            )
                                            .await;
                                        } else {
                                            watch_contact_peer(
                                                &mut reconnect_targets,
                                                peer_id,
                                                &bootstrap_peer_ids,
                                                local_peer_id,
                                            );
                                            dial_peer_live_circuits(
                                                &mut swarm,
                                                peer_id,
                                                &void_bootstraps,
                                                false,
                                            );
                                        }
                                        pending_messages
                                            .entry(peer_id)
                                            .or_default()
                                            .push(json_data.clone());
                                    }
                                }
                            }
                            UICommand::SendGroupLeave {
                                group_id,
                                peer_id,
                                recipients,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let Some(json_data) =
                                    build_group_leave_json(&group_id, &peer_id)
                                else {
                                    continue;
                                };
                                for peer_id in recipients {
                                    if peer_id == local_peer_id {
                                        continue;
                                    }
                                    if sessions.contains_key(&peer_id) {
                                        let _ = send_encrypted_chat_payload(
                                            &mut swarm,
                                            &mut sessions,
                                            &mut outbound_msg_requests,
                                            &mut outbound_delete_requests,
                                            &event_tx,
                                            peer_id,
                                            json_data.clone(),
                                            None,
                                            &now,
                                        )
                                        .await;
                                    } else {
                                        pending_messages
                                            .entry(peer_id)
                                            .or_default()
                                            .push(json_data.clone());
                                    }
                                }
                            }
                            UICommand::SendGroupDelete {
                                group_id,
                                recipients,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let Some(json_data) = build_group_delete_json(&group_id) else {
                                    continue;
                                };
                                for peer_id in recipients {
                                    if peer_id == local_peer_id {
                                        continue;
                                    }
                                    if sessions.contains_key(&peer_id) {
                                        let _ = send_encrypted_chat_payload(
                                            &mut swarm,
                                            &mut sessions,
                                            &mut outbound_msg_requests,
                                            &mut outbound_delete_requests,
                                            &event_tx,
                                            peer_id,
                                            json_data.clone(),
                                            None,
                                            &now,
                                        )
                                        .await;
                                    } else {
                                        pending_messages
                                            .entry(peer_id)
                                            .or_default()
                                            .push(json_data.clone());
                                    }
                                }
                            }
                            UICommand::SendReadReceipt { peer, message_ids } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                if message_ids.is_empty() {
                                    continue;
                                }
                                let Some(json_data) =
                                    crate::protocol::build_read_receipt_json(&message_ids)
                                else {
                                    continue;
                                };
                                if sessions.contains_key(&peer) {
                                    let _ = send_encrypted_chat_payload(
                                        &mut swarm,
                                        &mut sessions,
                                        &mut outbound_msg_requests,
                                        &mut outbound_delete_requests,
                                        &event_tx,
                                        peer,
                                        json_data,
                                        Some(&message_ids),
                                        &now,
                                    )
                                    .await;
                                } else {
                                    let queue = pending_read_receipts.entry(peer).or_default();
                                    if !queue.iter().any(|batch| batch == &message_ids) {
                                        queue.push(message_ids);
                                    }
                                }
                            }
                            // ─── Файловый sub-протокол ──────────────────────
                            UICommand::SendFile {
                                recipient,
                                path,
                                kind,
                                message_id,
                                transfer_id,
                                sender_name,
                                filename,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let filename = file_transfer::offer_filename(&path, &filename);
                                let file_kind = if kind == file_transfer::FileKind::Other {
                                    file_transfer::FileKind::from_filename(&filename)
                                } else {
                                    kind
                                };
                                let tid = transfer_id.unwrap_or_else(|| {
                                    let mut t = [0u8; 16];
                                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut t);
                                    t
                                });
                                let size = file_transfer::advertised_plain_size(
                                    std::path::Path::new(&path),
                                );
                                if let Some(mid) = message_id.clone() {
                                    if size > 0 {
                                        let msg = ChatMessage {
                                            id: mid,
                                            sender_id: local_peer_id.to_string(),
                                            sender_name: sender_name.clone(),
                                            recipient_id: Some(recipient.to_string()),
                                            text: String::new(),
                                            timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                            delivery: OutgoingDeliveryStatus::Pending,
                                            voice: None,
                                            file: Some(FileMeta {
                                                transfer_id: transfer_id_to_hex(&tid),
                                                filename: filename.clone(),
                                                size,
                                                local_path: None,
                                            }),
                                            group_id: None,
                                        };
                                        if let Ok(json_data) = serde_json::to_vec(&msg) {
                                            if sessions.contains_key(&recipient) {
                                                let _ = send_encrypted_chat_payload(
                                                    &mut swarm,
                                                    &mut sessions,
                                                    &mut outbound_msg_requests,
                                                    &mut outbound_delete_requests,
                                                    &event_tx,
                                                    recipient,
                                                    json_data,
                                                    None,
                                                    &now,
                                                )
                                                .await;
                                            } else {
                                                requeue_pending_chat_json(
                                                    &mut pending_messages,
                                                    recipient,
                                                    json_data,
                                                );
                                            }
                                        }
                                    }
                                }
                                if !sessions.contains_key(&recipient) {
                                    let q = pending_named_files.entry(recipient).or_default();
                                    if !q.iter().any(|f| f.transfer_id == tid) {
                                        q.push(PendingNamedFileTransfer {
                                            path: path.clone(),
                                            transfer_id: tid,
                                            filename: filename.clone(),
                                            kind: file_kind,
                                        });
                                    }
                                    let _ = event_tx
                                        .send(NetworkEvent::FileSendDeferred {
                                            recipient,
                                            path,
                                            kind: file_kind,
                                        })
                                        .await;
                                    continue;
                                }
                                start_named_file_transfer(
                                    &mut swarm,
                                    &mut sessions,
                                    &mut outgoing_transfers,
                                    &relay_peers,
                                    &event_tx,
                                    recipient,
                                    &path,
                                    tid,
                                    filename,
                                    file_kind,
                                    &file_cache_key,
                                )
                                .await;
                            }
                            UICommand::SendGroupFile {
                                sender_name,
                                group_id,
                                members,
                                path,
                                message_id,
                                transfer_id,
                                is_retry,
                                filename,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let filename = file_transfer::offer_filename(&path, &filename);
                                let file_kind = file_transfer::FileKind::from_filename(&filename);
                                let size = file_transfer::advertised_plain_size(
                                    std::path::Path::new(&path),
                                );
                                let msg = ChatMessage {
                                    id: message_id.clone(),
                                    sender_id: local_peer_id.to_string(),
                                    sender_name: sender_name.clone(),
                                    recipient_id: None,
                                    text: String::new(),
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                    delivery: OutgoingDeliveryStatus::Pending,
                                    voice: None,
                                    file: Some(FileMeta {
                                        transfer_id: transfer_id_to_hex(&transfer_id),
                                        filename: filename.clone(),
                                        size,
                                        local_path: None,
                                    }),
                                    group_id: Some(group_id.clone()),
                                };
                                for peer_id in members {
                                    if peer_id == local_peer_id {
                                        continue;
                                    }
                                    let peer_tid =
                                        per_peer_voice_transfer_id(&transfer_id, peer_id);
                                    let mut per_peer_msg = msg.clone();
                                    if let Some(ref mut f) = per_peer_msg.file {
                                        f.transfer_id = transfer_id_to_hex(&peer_tid);
                                    }
                                    let per_json = match serde_json::to_vec(&per_peer_msg) {
                                        Ok(v) => v,
                                        Err(_) => continue,
                                    };
                                    if sessions.contains_key(&peer_id) {
                                        let _ = send_encrypted_chat_payload(
                                            &mut swarm,
                                            &mut sessions,
                                            &mut outbound_msg_requests,
                                            &mut outbound_delete_requests,
                                            &event_tx,
                                            peer_id,
                                            per_json,
                                            None,
                                            &now,
                                        )
                                        .await;
                                        start_named_file_transfer(
                                            &mut swarm,
                                            &mut sessions,
                                            &mut outgoing_transfers,
                                            &relay_peers,
                                            &event_tx,
                                            peer_id,
                                            &path,
                                            peer_tid,
                                            filename.clone(),
                                            file_kind,
                                            &file_cache_key,
                                        )
                                        .await;
                                    } else {
                                        if swarm.is_connected(&peer_id) {
                                            let _ = ensure_e2ee_handshake_started(
                                                &mut swarm,
                                                &local_key,
                                                local_peer_id,
                                                my_public_key,
                                                peer_id,
                                                &sessions,
                                                &mut pending_handshakes,
                                                &mut handshake_started,
                                                &now,
                                                false,
                                            )
                                            .await;
                                        }
                                        requeue_pending_chat_json(
                                            &mut pending_messages,
                                            peer_id,
                                            per_json,
                                        );
                                        let q = pending_named_files.entry(peer_id).or_default();
                                        if !q.iter().any(|f| f.transfer_id == peer_tid) {
                                            q.push(PendingNamedFileTransfer {
                                                path: path.clone(),
                                                transfer_id: peer_tid,
                                                filename: filename.clone(),
                                                kind: file_kind,
                                            });
                                        }
                                        let _ = event_tx
                                            .send(NetworkEvent::FileSendDeferred {
                                                recipient: peer_id,
                                                path: path.clone(),
                                                kind: file_kind,
                                            })
                                            .await;
                                    }
                                }
                                if !is_retry {
                                    let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                }
                            }
                            UICommand::SendVoiceMessage {
                                sender_name,
                                recipient,
                                path,
                                duration_secs,
                                message_id,
                                transfer_id,
                                is_retry,
                            } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                let msg = ChatMessage {
                                    id: message_id.clone(),
                                    sender_id: local_peer_id.to_string(),
                                    sender_name: sender_name.clone(),
                                    recipient_id: Some(recipient.to_string()),
                                    text: String::new(),
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                    delivery: OutgoingDeliveryStatus::Pending,
                                    voice: Some(VoiceMeta {
                                        transfer_id: transfer_id_to_hex(&transfer_id),
                                        duration_secs,
                                    }),
                                    file: None,
                                    group_id: None,
                                };

                                let json_data = match serde_json::to_vec(&msg) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(format!(
                                                "❌ Не удалось сериализовать голосовое: {}",
                                                e
                                            )))
                                            .await;
                                        continue;
                                    }
                                };

                                if !sessions.contains_key(&recipient) {
                                    if swarm.is_connected(&recipient) {
                                        let _ = ensure_e2ee_handshake_started(
                                            &mut swarm,
                                            &local_key,
                                            local_peer_id,
                                            my_public_key,
                                            recipient,
                                            &sessions,
                                            &mut pending_handshakes,
                                            &mut handshake_started,
                                            &now,
                                            false,
                                        )
                                        .await;
                                    }
                                    let msg_id_for_dedup =
                                        chat_message_id_from_json(json_data.as_slice());
                                    let queue = pending_messages.entry(recipient).or_default();
                                    if let Some(ref mid) = msg_id_for_dedup {
                                        if !queue.iter().any(|b| {
                                            chat_message_id_from_json(b.as_slice()).as_deref()
                                                == Some(mid.as_str())
                                        }) {
                                            queue.push(json_data);
                                        }
                                    } else {
                                        queue.push(json_data);
                                    }
                                    let vq = pending_voice_transfers.entry(recipient).or_default();
                                    if !vq
                                        .iter()
                                        .any(|v| v.transfer_id == transfer_id)
                                    {
                                        vq.push(PendingVoiceTransfer {
                                            path: path.clone(),
                                            transfer_id,
                                        });
                                    }
                                    let _ = event_tx
                                        .send(NetworkEvent::MessageAwaitingSession(recipient))
                                        .await;
                                    let _ = event_tx
                                        .send(NetworkEvent::VoiceSendDeferred {
                                            recipient,
                                            path,
                                            duration_secs,
                                            message_id: message_id.clone(),
                                            transfer_id,
                                        })
                                        .await;
                                    // Атомарность: голосовое не показываем в чате здесь — только
                                    // после voice_ack(ok=true) от получателя (см. apply_voice_ack).
                                    let _ = msg;
                                    debug!(
                                        "[{}] ⏳ E2EE: голосовое {} буферизовано до хендшейка с {}",
                                        now,
                                        &message_id[..8.min(message_id.len())],
                                        &recipient.to_string()[..8]
                                    );
                                    continue;
                                }

                                let msg_id_for_send =
                                    chat_message_id_from_json(json_data.as_slice());
                                let in_flight = msg_id_for_send.as_ref().is_some_and(|mid| {
                                    outbound_msg_requests
                                        .values()
                                        .any(|(p, id, _)| *p == recipient && id == mid)
                                });
                                if !in_flight {
                                    let _ = send_encrypted_chat_payload(
                                        &mut swarm,
                                        &mut sessions,
                                        &mut outbound_msg_requests,
                                        &mut outbound_delete_requests,
                                        &event_tx,
                                        recipient,
                                        json_data,
                                        None,
                                        &now,
                                    )
                                    .await;
                                }
                                // Атомарность: голосовое не показываем в чате здесь — только
                                // после voice_ack(ok=true) от получателя (см. apply_voice_ack).
                                let _ = msg;
                                let _ = is_retry;

                                start_voice_file_transfer(
                                    &mut swarm,
                                    &mut sessions,
                                    &mut outgoing_transfers,
                                    &relay_peers,
                                    &event_tx,
                                    recipient,
                                    &path,
                                    transfer_id,
                                )
                                .await;
                            }
                            UICommand::AcceptFile { transfer_id, from, save_dir } => {
                                // Сохраняем выбранную директорию в состояние передачи.
                                if let Some(t) = incoming_transfers.get_mut(&transfer_id) {
                                    t.save_dir = save_dir.clone();
                                }
                                let packet = file_transfer::FilePacket::Accept { transfer_id };
                                let _ = send_e2ee_file_ctrl(
                                    &mut swarm,
                                    &mut sessions,
                                    from,
                                    &packet,
                                );
                                if swarm.is_connected(&from) {
                                    swarm.behaviour_mut().file_rr.send_request(&from, packet);
                                }
                                debug!(
                                    "✅ FILE: Accept transfer {:x?} от {} → {}",
                                    &transfer_id[..4],
                                    &from.to_string()[..8],
                                    save_dir.as_deref().unwrap_or("Downloads/VOID Messenger")
                                );
                            }
                            UICommand::RejectFile { transfer_id, from, reason } => {
                                let packet = file_transfer::FilePacket::Reject {
                                    transfer_id,
                                    reason: file_transfer::clamp_utf8_by_bytes(
                                        &reason,
                                        file_transfer::MAX_REJECT_REASON_BYTES,
                                    ),
                                };
                                let _ = send_e2ee_file_ctrl(
                                    &mut swarm,
                                    &mut sessions,
                                    from,
                                    &packet,
                                );
                                if swarm.is_connected(&from) {
                                    swarm.behaviour_mut().file_rr.send_request(&from, packet);
                                }
                                incoming_transfers.remove(&transfer_id);
                                debug!(
                                    "✖ FILE: Reject transfer {:x?} ({})",
                                    &transfer_id[..4],
                                    reason
                                );
                            }
                            UICommand::RequestFile { peer, transfer_id } => {
                                let packet = file_transfer::FilePacket::Request { transfer_id };
                                let _ = send_e2ee_file_ctrl(
                                    &mut swarm,
                                    &mut sessions,
                                    peer,
                                    &packet,
                                );
                                if swarm.is_connected(&peer) {
                                    swarm.behaviour_mut().file_rr.send_request(&peer, packet);
                                }
                            }
                            UICommand::CachePeerPrekeys(keys) => {
                                for (peer, pk) in keys {
                                    peer_prekeys.insert(peer, pk);
                                }
                            }
                            UICommand::FetchOfflineMailbox => {
                                // Только query, без dial: иначе Unlock шлёт это до
                                // первого swarm.poll и дублирует стартовый TCP.
                                query_relay_mailbox(
                                    &mut swarm,
                                    local_peer_id,
                                    &bootstrap_peer_ids,
                                    &mut last_mailbox_query_at,
                                );
                            }
                            UICommand::PublishOfflineOutbox { items, ack } => {
                                let mut by_recipient: HashMap<PeerId, Vec<OfflineOutboxItem>> =
                                    HashMap::new();
                                for item in items {
                                    by_recipient
                                        .entry(item.recipient)
                                        .or_default()
                                        .push(item);
                                }
                                let work_count = by_recipient.len() as u32;
                                let shared_gate =
                                    ack.map(|tx| publish_result_token(tx, work_count.max(1)));
                                if by_recipient.is_empty() {
                                    signal_publish_done(&shared_gate, false);
                                }
                                for (recipient, batch) in by_recipient {
                                    // Track Store for exit-flush / handoff, not for UI ✓.
                                    let recip_done: PublishDone = shared_gate
                                        .as_ref()
                                        .map(|g| once_publish_gate(g.clone()))
                                        .unwrap_or_else(|| Arc::new(|_| {}) as PublishDone);
                                    let mut sealed: Vec<OfflineEnvelope> = Vec::new();
                                    let mut need_prekey: Vec<OfflineOutboxItem> = Vec::new();
                                    if let Some(pk_bytes) = peer_prekeys.get(&recipient) {
                                        let pk = crypto::PublicKey::from(*pk_bytes);
                                        for item in batch {
                                            match seal_for_recipient(
                                                &pk,
                                                &local_peer_id,
                                                &my_public_key_bytes,
                                                &item.message_id,
                                                &item.kind,
                                                &item.payload,
                                            ) {
                                                Ok(env) => sealed.push(env),
                                                Err(e) => debug!("offline seal: {e}"),
                                            }
                                        }
                                    } else {
                                        need_prekey = batch;
                                    }
                                    if sealed.is_empty() && need_prekey.is_empty() {
                                        recip_done(false);
                                        continue;
                                    }
                                    if !sealed.is_empty() {
                                        if RelayMailbox::merge(
                                            &mut relay_mail_store,
                                            &recipient.to_string(),
                                            sealed.clone(),
                                        ) {
                                            let _ = RelayMailbox::save(&relay_mail_store);
                                        }
                                        // Почта только через bootstrap-ноды (Store Ack).
                                        // DHT-ящик отключён — нода = единственный store-and-forward.
                                        let allow_dht = bootstrap_peer_ids.is_empty();
                                        let handoff = Some(ActiveHandoff::new(
                                            &sealed,
                                            recip_done.clone(),
                                            allow_dht,
                                        ));
                                        publish_relay_mail(
                                            &mut swarm,
                                            &bootstrap_peer_ids,
                                            &void_bootstraps,
                                            local_peer_id,
                                            recipient,
                                            &sealed,
                                            &mut pending_relay,
                                            &mut pending_relay_gates,
                                            &mut outbound_mailbox_stores,
                                            &handoff,
                                        );
                                        if let Some(h) = &handoff {
                                            let tracked = outbound_mailbox_stores
                                                .values()
                                                .any(|(g, _, _)| Arc::ptr_eq(g, h));
                                            let queued = pending_relay_gates
                                                .values()
                                                .any(|g| Arc::ptr_eq(g, h));
                                            if !tracked
                                                && !queued
                                                && !accept_dht_as_full_handoff(
                                                    &sealed,
                                                    allow_dht,
                                                )
                                            {
                                                warn!(
                                                    "VOID: нет подключенной bootstrap-ноды для offline-почты"
                                                );
                                                let _ = event_tx
                                                    .send(NetworkEvent::Status(
                                                        "❌ Нет связи с bootstrap — офлайн-почта не сдана".into(),
                                                    ))
                                                    .await;
                                                h.note_fail();
                                            }
                                        }
                                        // DHT mailbox put — только LAN без нод.
                                        if allow_dht {
                                            let for_dht = dht_eligible_envelopes(&sealed);
                                            let dht_done: Option<PublishDone> =
                                                handoff.as_ref().map(|h| {
                                                    let h = h.clone();
                                                    Arc::new(move |ok: bool| {
                                                        if ok {
                                                            h.note_dht_ok();
                                                        }
                                                    })
                                                        as PublishDone
                                                });
                                            start_mailbox_merge_put(
                                                &mut swarm,
                                                &mut pending_kad_mail,
                                                recipient,
                                                for_dht,
                                                dht_done,
                                            );
                                        } else {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(
                                                    "📤 Офлайн → bootstrap-нода (без DHT)".into(),
                                                ))
                                                .await;
                                        }
                                    }
                                    if !need_prekey.is_empty() {
                                        let got_bs = request_prekey_from_bootstraps(
                                            &mut swarm,
                                            &bootstrap_peer_ids,
                                            &void_bootstraps,
                                            recipient,
                                            need_prekey.clone(),
                                            Some(recip_done.clone()),
                                            &mut outbound_prekey_gets,
                                        );
                                        if !got_bs {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "⚠ Нет prekey {} — ждём DHT/контакт online",
                                                    &recipient.to_string()
                                                        [..8.min(recipient.to_string().len())]
                                                )))
                                                .await;
                                        }
                                        let qid = swarm
                                            .behaviour_mut()
                                            .kad
                                            .get_record(prekey_record_key(recipient));
                                        pending_kad_mail.insert(
                                            qid,
                                            MailboxKadOp::PrekeyForPublish {
                                                recipient,
                                                items: need_prekey,
                                                done: Some(recip_done),
                                                prekey_bytes: None,
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                _ = hop_tick.tick() => {
                    // Живой circuit в swarm — Hop уже есть, даже если
                    // ReservationReqAccepted не дошёл до match.
                    for (relay, addr) in circuit_listen_relays(&swarm) {
                        local_listen_addrs.insert(addr.clone());
                        if relay_circuit_reserved.insert(relay) {
                            relay_hop_pending.remove(&relay);
                            hop_listen_after.remove(&relay);
                            info!("Hop OK из swarm.listen ({})", addr);
                            kad_bootstrap_after =
                                Some(Instant::now() + Duration::from_secs(30));
                            emit_hop_ready(&event_tx, relay, Some(addr));
                        }
                    }
                    promote_pending_hop_if_due(
                        &swarm,
                        &bootstrap_peer_ids,
                        &mut relay_circuit_reserved,
                        &mut relay_hop_pending,
                        &mut hop_listen_after,
                        &relay_listen_attempt_at,
                        &event_tx,
                    );
                    if let Some(when) = kad_bootstrap_after {
                        if Instant::now() >= when {
                            kad_bootstrap_after = None;
                            let _ = swarm.behaviour_mut().kad.bootstrap();
                        }
                    }
                    if let Some((hops, traces)) =
                        onion_rt_poll_ui(swarm.connected_peers().copied())
                    {
                        let _ = event_tx
                            .send(NetworkEvent::OnionRoutes { hops, traces })
                            .await;
                    }
                    let now_h = Instant::now();
                    let due: Vec<PeerId> = hop_listen_after
                        .iter()
                        .filter(|(_, t)| now_h >= **t)
                        .map(|(p, _)| *p)
                        .collect();
                    for p in &due {
                        hop_listen_after.remove(p);
                    }
                    let stale_pending = relay_hop_pending.iter().any(|p| {
                        swarm.is_connected(p) && !relay_circuit_reserved.contains(p)
                    });
                    if !due.is_empty() || stale_pending {
                        ensure_bootstrap_relay_listens(
                            &mut swarm,
                            &bootstrap_peer_ids,
                            &void_bootstraps,
                            &reconnect_targets,
                            &bootstrap_hop_addr,
                            &relay_circuit_reserved,
                            &mut relay_listen_attempt_at,
                            &mut relay_hop_pending,
                            &mut relay_hop_listeners,
                            Duration::from_secs(3),
                            Some(&event_tx),
                        );
                    }
                    for b in &bootstrap_peer_ids {
                        if swarm.is_connected(b) && !relay_circuit_reserved.contains(b)
                            && !relay_hop_pending.contains(b)
                            && !relay_hop_listeners.contains_key(b)
                            && !relay_listen_attempt_at.contains_key(b)
                        {
                            // Identify сначала: иначе Reserve на полуживом conn.
                            let delay = if bootstrap_identified.contains(b) {
                                Duration::from_millis(1500)
                            } else {
                                Duration::from_secs(3)
                            };
                            hop_listen_after.entry(*b).or_insert(Instant::now() + delay);
                        }
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let s = address.to_string();
                            local_listen_addrs.insert(address.clone());
                            // Фильтруем виртуальные интерфейсы (VirtualBox 192.168.56.*,
                            // Docker 172.17.*, link-local 169.254.*) — это адреса, до
                            // которых никто извне не достучится, они только засоряют
                            // список и провоцируют бесполезные dial'ы у соседей.
                            if is_junk_addr(&address) && !s.contains("p2p-circuit") {
                                debug!("🚫 Пропуск виртуального интерфейса: {}", address);
                                continue;
                            }
                            debug!("📡 СЛУШАЮ: {}", address);

                            let is_external = !s.contains("/ip6/") && !s.contains("/0.0.0.0") && !s.contains("/127.0.0.1") || s.contains("p2p-circuit");

                            if is_external {
                                debug!("  (Внешний/Relay): {}/p2p/{}", address, local_peer_id);
                                let _ = event_tx.send(NetworkEvent::NewListenAddr(address.clone())).await;
                                swarm.add_external_address(address.clone());

                                if !s.contains("p2p-circuit") {
                                    let extracted_ip = address.iter().find_map(|p| match p {
                                        libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.to_string()),
                                        libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.to_string()),
                                        _ => None,
                                    });
                                    if let Some(ip) = extracted_ip {
                                        let _ = event_tx.send(NetworkEvent::PublicIpConfirmed(ip)).await;
                                    }
                                }
                            }

                            if s.contains("p2p-circuit") {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    "✨ СВЯЗЬ ЧЕРЕЗ RELAY: Вы доступны через посредника (за NAT)!".into()
                                )).await;
                                let relay = relay_peer_id_from_circuit_addr(&address)
                                    .or_else(|| {
                                        bootstrap_peer_ids
                                            .iter()
                                            .copied()
                                            .find(|b| swarm.is_connected(b))
                                    });
                                if let Some(relay) = relay {
                                    if relay_circuit_reserved.insert(relay) {
                                        relay_hop_pending.remove(&relay);
                                        hop_listen_after.remove(&relay);
                                        emit_hop_ready(&event_tx, relay, None);
                                    }
                                }
                            }
                        },

                        SwarmEvent::ListenerClosed {
                            listener_id,
                            addresses,
                            reason,
                        } => {
                            let circuit = addresses.iter().any(is_circuit_addr);
                            let ours = relay_hop_listeners.values().any(|id| *id == listener_id);
                            if circuit || ours {
                                warn!(
                                    "circuit listener closed {:?}: {:?} addrs={:?}",
                                    listener_id, reason, addresses
                                );
                                let mut relays: Vec<PeerId> = addresses
                                    .iter()
                                    .filter_map(relay_peer_id_from_circuit_addr)
                                    .collect();
                                if relays.is_empty() {
                                    relays.extend(
                                        relay_hop_listeners
                                            .iter()
                                            .filter(|(_, id)| **id == listener_id)
                                            .map(|(p, _)| *p),
                                    );
                                }
                                relay_hop_listeners.retain(|_, id| *id != listener_id);
                                for a in &addresses {
                                    local_listen_addrs.remove(a);
                                }
                                for relay in relays {
                                    let was_ready = relay_circuit_reserved.remove(&relay);
                                    relay_hop_pending.remove(&relay);
                                    // Не планируем listen_on через 3 с: это и есть
                                    // спам Reserve в логах ноды.
                                    if was_ready {
                                        let _ = event_tx
                                            .send(NetworkEvent::RelayHopLost { relay })
                                            .await;
                                    }
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(format!(
                                            "⚠ Hop listener closed ({:?})",
                                            reason
                                        )))
                                        .await;
                                }
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, addr) in list {
                                if peer_id == local_peer_id { continue; }
                                // Не трогаем анонсы из виртуальных интерфейсов — они не
                                // ведут к рабочей LAN-связи, только тратят время Dial'а.
                                if is_junk_addr(&addr) {
                                    debug!(
                                        "🚫 mDNS: пропуск виртуального адреса {} (peer {})",
                                        addr,
                                        &peer_id.to_string()[..8]
                                    );
                                    continue;
                                }

                                // Регистрация адреса в Kademlia
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());

                                // Дозваниваемся и по QUIC, и по TCP: на Windows/NAT QUIC часто на случайном UDP
                                // (конфликт 50001), а пропуск TCP раньше оставлял LAN без соединения, если QUIC не доходил.
                                // Используем DialOpts с NotDialing, чтобы mDNS не дублировал попытки
                                // при нескольких событиях для одного пира.
                                if addr.to_string().contains("quic-v1") {
                                    debug!("🔍 mDNS: найден пир {} (QUIC). Подключаюсь...", &peer_id.to_string()[..8]);
                                } else {
                                    debug!("🔍 mDNS: найден пир {} (TCP). Подключаюсь...", &peer_id.to_string()[..8]);
                                }
                                let mdns_opts = DialOpts::peer_id(peer_id)
                                    .condition(libp2p::swarm::dial_opts::PeerCondition::NotDialing)
                                    .addresses(vec![addr.clone()])
                                    .build();
                                let _ = swarm.dial(mdns_opts);

                                let _ = event_tx.send(NetworkEvent::MdnsDiscovered(peer_id, addr.clone())).await;
                                peer_addrs.entry(peer_id).or_default().push(addr);
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                            for (peer_id, _) in peers {
                                let _ = event_tx.send(NetworkEvent::MdnsExpired(peer_id)).await;
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { peer, message, .. })) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            
                            match message {
                                libp2p::request_response::Message::Request { request, channel, .. } => {
                                    let mut peer = peer;
                                    let mut request = request;
                                    let mut onion_reply: Option<PeerId> = None;
                                    let mut channel = Some(channel);
                                    if let V1Packet::Onion { .. } = request {
                                        rr_reply(
                                            &mut swarm,
                                            &mut channel,
                                            None,
                                            V1Packet::Ack,
                                        );
                                    } else {
                                    if matches!(request, V1Packet::OnionDrop { .. }) {
                                        if let V1Packet::OnionDrop { src, packet } =
                                            std::mem::replace(&mut request, V1Packet::Ack)
                                        {
                                        rr_reply(
                                            &mut swarm,
                                            &mut channel,
                                            None,
                                            V1Packet::Ack,
                                        );
                                        if let Ok(src_pid) = src.parse::<PeerId>() {
                                            if src_pid != local_peer_id
                                                && !bootstrap_peer_ids.contains(&src_pid)
                                            {
                                                if !matches!(*packet, V1Packet::Ack) {
                                                    onion_rt_note("in", src_pid, &[peer]);
                                                }
                                                onion_reply = Some(src_pid);
                                                peer = src_pid;
                                                request = *packet;
                                            }
                                        }
                                        }
                                    }
                                    match request {
                                        V1Packet::BootstrapGossip { addrs, onion_keys: hints } => {
                                            let their_set: HashSet<&str> =
                                                addrs.iter().map(|s| s.as_str()).collect();
                                            let hint_added = ingest_onion_hints(
                                                &hints,
                                                &mut onion_keys,
                                                &mut bootstrap_peer_ids,
                                                &mut void_bootstraps,
                                                &mut swarm,
                                                local_peer_id,
                                            );
                                            if hint_added > 0 {
                                                onion_rt_set_keys(
                                                    onion_keys.clone(),
                                                    bootstrap_peer_ids.clone(),
                                                    local_peer_id,
                                                );
                                                dial_missing_bootstraps(
                                                    &mut swarm,
                                                    &bootstrap_peer_ids,
                                                    &void_bootstraps,
                                                );
                                            }
                                            if let Some(valid) =
                                                validate_bootstrap_gossip_addrs(&addrs)
                                            {
                                                let parsed: Vec<Multiaddr> = valid
                                                    .iter()
                                                    .filter_map(|s| s.parse().ok())
                                                    .collect();
                                                let added = merge_bootstraps_into_swarm(
                                                    &mut swarm,
                                                    &mut void_bootstraps,
                                                    &mut bootstrap_peer_ids,
                                                    &parsed,
                                                );
                                                if added > 0 {
                                                    fanout_bootstrap_gossip(
                                                        &mut swarm,
                                                        local_peer_id,
                                                        &bootstrap_peer_ids,
                                                        valid.clone(),
                                                        collect_onion_hints(
                                                            &onion_keys,
                                                            &void_bootstraps,
                                                        ),
                                                        Some(peer),
                                                    );
                                                    let _ = event_tx
                                                        .send(NetworkEvent::BootstrapsLearned(
                                                            valid,
                                                        ))
                                                        .await;
                                                }
                                            }
                                            let our_extra: Vec<String> = void_bootstraps
                                                .iter()
                                                .map(|a| a.to_string())
                                                .filter(|s| !their_set.contains(s.as_str()))
                                                .collect();
                                            let our_hints =
                                                collect_onion_hints(&onion_keys, &void_bootstraps);
                                            if !our_extra.is_empty() || !our_hints.is_empty() {
                                                let _ = swarm
                                                    .behaviour_mut()
                                                    .request_response
                                                    .send_request(
                                                        &peer,
                                                        V1Packet::BootstrapGossip {
                                                            addrs: our_extra,
                                                            onion_keys: our_hints,
                                                        },
                                                    );
                                            }
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                        }
                                        V1Packet::OfflineMailboxStore {
                                            recipient,
                                            envelopes,
                                        } => {
                                            if RelayMailbox::merge(
                                                &mut relay_mail_store,
                                                &recipient,
                                                envelopes,
                                            ) {
                                                let _ = RelayMailbox::save(&relay_mail_store);
                                            }
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                        }
                                        V1Packet::OfflineMailboxQuery { recipient } => {
                                            // Порциями: иначе один Deliver со всеми
                                            // voice_chunk не влезает в лимит JSON response.
                                            let envs = RelayMailbox::take_batch(
                                                &mut relay_mail_store,
                                                &recipient,
                                                crate::relay_mailbox::DELIVER_BATCH_PLAIN_BYTES,
                                            );
                                            if !envs.is_empty() {
                                                let _ = RelayMailbox::save(&relay_mail_store);
                                            }
                                            let response = if envs.is_empty() {
                                                V1Packet::Ack
                                            } else {
                                                V1Packet::OfflineMailboxDeliver { envelopes: envs }
                                            };
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                response,
                                            );
                                        }
                                        V1Packet::OfflineMailboxDeliver { .. } => {
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                        }
                                        V1Packet::PrekeyPut { .. }
                                        | V1Packet::PrekeyGet { .. }
                                        | V1Packet::PrekeyOffer { .. } => {
                                            // Prekey directory lives on bootstrap; peers Ack.
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                        }
                                        V1Packet::DialBack { circuit_addrs } => {
                                            // Собеседник просит обратный dial через relay —
                                            // обязательно при асимметрии NAT (Mac→Win ok, Win→Mac нет).
                                            watch_contact_peer(
                                                &mut reconnect_targets,
                                                peer,
                                                &bootstrap_peer_ids,
                                                local_peer_id,
                                            );
                                            let mut hints: Vec<Multiaddr> = circuit_addrs
                                                .iter()
                                                .filter_map(|s| s.parse().ok())
                                                .filter(|a: &Multiaddr| {
                                                    is_circuit_addr(a) && !is_junk_addr(a)
                                                })
                                                .collect();
                                            hints.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
                                            hints.dedup();
                                            if !hints.is_empty() {
                                                let list =
                                                    reconnect_targets.entry(peer).or_default();
                                                for h in &hints {
                                                    if !list.contains(h) {
                                                        list.insert(0, h.clone());
                                                    }
                                                }
                                                dial_peer_with_condition(
                                                    &mut swarm,
                                                    peer,
                                                    hints,
                                                    &void_bootstraps,
                                                    libp2p::swarm::dial_opts::PeerCondition::Always,
                                                    false,
                                                );
                                            }
                                            dial_peer_live_circuits(
                                                &mut swarm,
                                                peer,
                                                &void_bootstraps,
                                                false,
                                            );
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                            debug!(
                                                "[{}] ↩ DialBack от {} — обратный circuit dial",
                                                now,
                                                &peer.to_string()[..8]
                                            );
                                        }
                                        V1Packet::Hello {
                                            public_key,
                                            ephemeral_key,
                                            transport_sig,
                                            transport_pubkey_pb,
                                        } => {
                                            if peer != local_peer_id {
                                                if !verify_hello_transport_binding(
                                                    peer,
                                                    local_peer_id,
                                                    &public_key,
                                                    &ephemeral_key,
                                                    transport_sig.as_slice(),
                                                    transport_pubkey_pb.as_slice(),
                                                ) {
                                                    debug!(
                                                        "[{}] ❌ E2EE: Hello от {} без привязки к libp2p identity — игнор.",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                    rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                                } else if let Some(local_ephem_secret) =
                                                    pending_handshakes.remove(&peer)
                                                {
                                                    handshake_started.remove(&peer);
                                                    drop_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        peer,
                                                    );
                                                    let remote_static_pub =
                                                        crypto::PublicKey::from(public_key);
                                                    remember_peer_prekey(
                                                        &mut peer_prekeys,
                                                        &event_tx,
                                                        peer,
                                                        public_key,
                                                    )
                                                    .await;
                                                    let remote_ephem_pub =
                                                        crypto::PublicKey::from(ephemeral_key);
                                                    let session = crypto::SecureSession::new_initiator(
                                                        &local_static,
                                                        &remote_static_pub,
                                                        local_ephem_secret,
                                                        &remote_ephem_pub,
                                                    );
                                                    put_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        peer,
                                                        session,
                                                    );
                                                    debug!(
                                                        "[{}] 🤝 E2EE: сессия (onion Hello) с {}",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                    rr_reply(
                                                        &mut swarm,
                                                        &mut channel,
                                                        onion_reply,
                                                        V1Packet::Ack,
                                                    );
                                                    flush_pending_encrypted_messages(
                                                        &mut swarm,
                                                        &mut sessions,
                                                        &mut outbound_msg_requests,
                                                        &mut outbound_delete_requests,
                                                        &event_tx,
                                                        peer,
                                                        &mut pending_messages,
                                                        &now,
                                                    )
                                                    .await;
                                                } else {
                                                // Входящий Hello Request: всегда responder.
                                                // Не flush'аем pending — initiator ещё без сессии,
                                                // Encrypted прилетит ему раньше Hello-ответа и
                                                // снесёт ratchet (текст теряется, файлы живут).
                                                if sessions.contains_key(&peer) {
                                                    debug!(
                                                        "[{}] 🔄 E2EE: сброс сессии с {} (новый Hello)",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                    drop_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        peer,
                                                    );
                                                }
                                                pending_handshakes.remove(&peer);
                                                handshake_started.remove(&peer);

                                                let remote_static_pub = crypto::PublicKey::from(public_key);
                                                remember_peer_prekey(
                                                    &mut peer_prekeys,
                                                    &event_tx,
                                                    peer,
                                                    public_key,
                                                )
                                                .await;
                                                let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);
                                                let local_ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                                let local_ephem_pub = crypto::PublicKey::from(&local_ephem_secret);
                                                let session = crypto::SecureSession::new_responder(
                                                    &local_static,
                                                    &remote_static_pub,
                                                    &remote_ephem_pub,
                                                    local_ephem_secret,
                                                );
                                                put_e2ee_session(
                                                    &mut sessions,
                                                    &mut session_established_at,
                                                    peer,
                                                    session,
                                                );
                                                debug!(
                                                    "[{}] 🤝 E2EE: Сессия (responder) создана с {}",
                                                    now,
                                                    &peer.to_string()[..8]
                                                );
                                                if let Some(my_hello) = build_v1_hello(
                                                    &local_key,
                                                    local_peer_id,
                                                    peer,
                                                    my_public_key,
                                                    local_ephem_pub,
                                                ) {
                                                    rr_reply(
                                                        &mut swarm,
                                                        &mut channel,
                                                        onion_reply,
                                                        my_hello,
                                                    );
                                                }
                                                }
                                            }
                                        }
                                        V1Packet::Encrypted { header, ciphertext } => {
                                            let mut response_channel = channel;
                                            let mut send_ack = false;
                                            if let Some(session) = sessions.get_mut(&peer) {
                                                match session.decrypt_payload(&header, &ciphertext) {
                                                    Ok(plaintext) => {
                                                        if let Some(ctrl) =
                                                            file_transfer::try_decode_e2ee_file_ctrl(
                                                                &plaintext,
                                                            )
                                                        {
                                                            match ctrl {
                                                                file_transfer::FilePacket::Offer {
                                                                    transfer_id,
                                                                    filename,
                                                                    total_size,
                                                                    total_chunks,
                                                                    sha256,
                                                                    kind,
                                                                } => {
                                                                    if file_transfer::validate_file_offer(
                                                                        &filename,
                                                                        total_size,
                                                                        total_chunks,
                                                                    )
                                                                    .is_ok()
                                                                    {
                                                                        let safe = file_transfer::safe_filename(
                                                                            &filename,
                                                                        );
                                                                        let resume = incoming_transfers
                                                                            .get(&transfer_id)
                                                                            .is_some_and(|inc| {
                                                                                inc.received_count > 0
                                                                                    && inc.total_size
                                                                                        == total_size
                                                                                    && inc.total_chunks
                                                                                        == total_chunks
                                                                                    && inc.sha256 == sha256
                                                                                    && inc.filename == safe
                                                                            });
                                                                        if !resume {
                                                                            incoming_transfers.insert(
                                                                                transfer_id,
                                                                                file_transfer::IncomingTransfer::new(
                                                                                    peer,
                                                                                    transfer_id,
                                                                                    safe.clone(),
                                                                                    total_size,
                                                                                    total_chunks,
                                                                                    sha256,
                                                                                    kind,
                                                                                ),
                                                                            );
                                                                        }
                                                                        if let Some(inc) = incoming_transfers
                                                                            .get_mut(&transfer_id)
                                                                        {
                                                                            inc.save_dir = Some(
                                                                                if file_transfer::is_voice_filename(
                                                                                    &safe,
                                                                                ) {
                                                                                    file_transfer::voice_dir_absolute()
                                                                                        .display()
                                                                                        .to_string()
                                                                                } else {
                                                                                    file_transfer::file_cache_dir()
                                                                                        .display()
                                                                                        .to_string()
                                                                                },
                                                                            );
                                                                        }
                                                                        let accept =
                                                                            file_transfer::FilePacket::Accept {
                                                                                transfer_id,
                                                                            };
                                                                        let _ = send_e2ee_file_ctrl(
                                                                            &mut swarm,
                                                                            &mut sessions,
                                                                            peer,
                                                                            &accept,
                                                                        );
                                                                        if swarm.is_connected(&peer) {
                                                                            swarm
                                                                                .behaviour_mut()
                                                                                .file_rr
                                                                                .send_request(&peer, accept);
                                                                        }
                                                                        let _ = event_tx
                                                                            .send(NetworkEvent::FileOffer {
                                                                                transfer_id,
                                                                                from: peer,
                                                                                filename: safe,
                                                                                total_size,
                                                                                kind,
                                                                            })
                                                                            .await;
                                                                    }
                                                                }
                                                                file_transfer::FilePacket::Accept {
                                                                    transfer_id,
                                                                } => {
                                                                    if let Some(t) = outgoing_transfers
                                                                        .get_mut(&transfer_id)
                                                                    {
                                                                        t.accepted = true;
                                                                        t.chunk_inflight = false;
                                                                        t.last_chunk_at = Instant::now()
                                                                            - file_transfer::DIRECT_CHUNK_DELAY;
                                                                    }
                                                                }
                                                                file_transfer::FilePacket::Reject {
                                                                    transfer_id,
                                                                    reason,
                                                                } => {
                                                                    outgoing_transfers.remove(&transfer_id);
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::FileError {
                                                                            transfer_id,
                                                                            reason: format!(
                                                                                "Отклонено: {}",
                                                                                reason
                                                                            ),
                                                                        })
                                                                        .await;
                                                                }
                                                                file_transfer::FilePacket::Cancel {
                                                                    transfer_id,
                                                                } => {
                                                                    incoming_transfers.remove(&transfer_id);
                                                                    outgoing_transfers.remove(&transfer_id);
                                                                }
                                                                file_transfer::FilePacket::Request {
                                                                    transfer_id,
                                                                } => {
                                                                    let _ = event_tx
                                                                        .send(
                                                                            NetworkEvent::FileResendRequest {
                                                                                from: peer,
                                                                                transfer_id,
                                                                            },
                                                                        )
                                                                        .await;
                                                                }
                                                                _ => {}
                                                            }
                                                            send_ack = true;
                                                        } else if let Some((tid, idx, pdata)) =
                                                            file_transfer::try_decode_e2ee_file_chunk_frame(
                                                                &plaintext,
                                                            )
                                                        {
                                                            let voice_outcome = apply_incoming_file_chunk(
                                                                tid,
                                                                idx,
                                                                pdata,
                                                                peer,
                                                                &now,
                                                                &mut incoming_transfers,
                                                                &event_tx,
                                                                &file_cache_key,
                                                            )
                                                            .await;
                                                            if let Some((vtid, vok)) = voice_outcome {
                                                                if let Some(ack_json) = build_voice_ack_json(
                                                                    &transfer_id_to_hex(&vtid),
                                                                    vok,
                                                                ) {
                                                                    let _ = send_encrypted_chat_payload(
                                                                        &mut swarm,
                                                                        &mut sessions,
                                                                        &mut outbound_msg_requests,
                                                                        &mut outbound_delete_requests,
                                                                        &event_tx,
                                                                        peer,
                                                                        ack_json,
                                                                        None,
                                                                        &now,
                                                                    )
                                                                    .await;
                                                                }
                                                            }
                                                            send_ack = true;
                                                        } else if let Some(frame) =
                                                            parse_decrypted_chat_frame(&plaintext)
                                                        {
                                                            match frame {
                                                                DecryptedChatFrame::Message(msg) => {
                                                                    debug!(
                                                                        "[{}] 🔒 E2EE: Сообщение ДЕШИФРОВАНО от {}",
                                                                        now,
                                                                        &peer.to_string()[..8]
                                                                    );
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::ChatMessage(msg))
                                                                        .await;
                                                                    send_ack = true;
                                                                }
                                                                DecryptedChatFrame::VoiceAck {
                                                                    transfer_id,
                                                                    ok,
                                                                } => {
                                                                    if let Some(tid) =
                                                                        transfer_id_from_hex(&transfer_id)
                                                                    {
                                                                        let _ = event_tx
                                                                            .send(NetworkEvent::VoiceAck {
                                                                                peer,
                                                                                transfer_id: tid,
                                                                                ok,
                                                                            })
                                                                            .await;
                                                                    }
                                                                    send_ack = true;
                                                                }
                                                                DecryptedChatFrame::Delete {
                                                                    message_ids,
                                                                } => {
                                                                    let (deleted, missing) =
                                                                        chat_messages.apply_incoming_delete(
                                                                            peer,
                                                                            &message_ids,
                                                                        );
                                                                    if let Some(ch) = response_channel.take() {
                                                                        response_channel =
                                                                            send_delete_ack_response(
                                                                                session,
                                                                                ch,
                                                                                &mut swarm,
                                                                                &deleted,
                                                                                &missing,
                                                                            );
                                                                    }
                                                                }
                                                                DecryptedChatFrame::DeleteAck => {
                                                                    send_ack = true;
                                                                }
                                                                DecryptedChatFrame::Read {
                                                                    message_ids,
                                                                } => {
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::MessageRead {
                                                                            peer,
                                                                            message_ids,
                                                                        })
                                                                        .await;
                                                                    send_ack = true;
                                                                }
                                                                DecryptedChatFrame::GroupSync {
                                                                    group_id,
                                                                    group_name,
                                                                    creator_id,
                                                                    members,
                                                                } => {
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::GroupSync {
                                                                            from: peer,
                                                                            group_id,
                                                                            group_name,
                                                                            creator_id,
                                                                            members,
                                                                        })
                                                                        .await;
                                                                    send_ack = true;
                                                                }
                                                                DecryptedChatFrame::GroupLeave {
                                                                    group_id,
                                                                    peer_id,
                                                                } => {
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::GroupLeave {
                                                                            from: peer,
                                                                            group_id,
                                                                            peer_id,
                                                                        })
                                                                        .await;
                                                                    send_ack = true;
                                                                }
                                                                DecryptedChatFrame::GroupDelete {
                                                                    group_id,
                                                                } => {
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::GroupDelete {
                                                                            from: peer,
                                                                            group_id,
                                                                        })
                                                                        .await;
                                                                    send_ack = true;
                                                                }
                                                            }
                                                        } else {
                                                            // Расшифровали, но кадр не chat/file —
                                                            // всё равно Ack, иначе отправитель
                                                            // крутит ○ и на OutFailure шлёт дубликат.
                                                            debug!(
                                                                "[{}] ⚠ E2EE: неизвестный plaintext от {} ({} б) — Ack",
                                                                now,
                                                                &peer.to_string()[..8],
                                                                plaintext.len()
                                                            );
                                                            send_ack = true;
                                                        }
                                                    }
                                                    Err(_) => {
                                                        if onion_reply.is_some() {
                                                            debug!(
                                                                "[{}] ❌ E2EE: onion-кадр не расшифровался от {} — сессию не сбрасываю",
                                                                now,
                                                                &peer.to_string()[..8]
                                                            );
                                                            send_ack = true;
                                                        } else {
                                                        debug!(
                                                            "[{}] ❌ E2EE: Ошибка дешифровки от {}. Сбрасываю...",
                                                            now,
                                                            &peer.to_string()[..8]
                                                        );
                                                        drop_e2ee_session(
                                                            &mut sessions,
                                                            &mut session_established_at,
                                                            peer,
                                                        );
                                                        // Signal peer to re-handshake (same as no-session).
                                                        let ephem_secret =
                                                            crypto::StaticSecret::random_from_rng(
                                                                &mut rand::rngs::OsRng,
                                                            );
                                                        let ephem_pub =
                                                            crypto::PublicKey::from(&ephem_secret);
                                                        if let Some(hello) = build_v1_hello(
                                                            &local_key,
                                                            local_peer_id,
                                                            peer,
                                                            my_public_key,
                                                            ephem_pub,
                                                        ) {
                                                            if let Some(ch) = response_channel.take()
                                                            {
                                                                let _ = swarm
                                                                    .behaviour_mut()
                                                                    .request_response
                                                                    .send_response(ch, hello);
                                                            }
                                                        }
                                                        if swarm.is_connected(&peer) {
                                                            let _ = ensure_e2ee_handshake_started(
                                                                &mut swarm,
                                                                &local_key,
                                                                local_peer_id,
                                                                my_public_key,
                                                                peer,
                                                                &sessions,
                                                                &mut pending_handshakes,
                                                                &mut handshake_started,
                                                                &now,
                                                                true,
                                                            )
                                                            .await;
                                                        }
                                                        }
                                                    }
                                                }
                                            } else {
                                                debug!(
                                                    "[{}] ⏳ E2EE: нет сессии с {} — отвечаем Hello (без Ack)",
                                                    now,
                                                    &peer.to_string()[..8]
                                                );
                                                let ephem_secret = crypto::StaticSecret::random_from_rng(
                                                    &mut rand::rngs::OsRng,
                                                );
                                                let ephem_pub =
                                                    crypto::PublicKey::from(&ephem_secret);
                                                if let Some(hello) = build_v1_hello(
                                                    &local_key,
                                                    local_peer_id,
                                                    peer,
                                                    my_public_key,
                                                    ephem_pub,
                                                ) {
                                                    if let Some(ch) = response_channel.take() {
                                                        let _ = swarm
                                                            .behaviour_mut()
                                                            .request_response
                                                            .send_response(ch, hello);
                                                    }
                                                }
                                                // Also start a real outbound Hello — response
                                                // ephem above is only a signal (secret discarded).
                                                let _ = ensure_e2ee_handshake_started(
                                                    &mut swarm,
                                                    &local_key,
                                                    local_peer_id,
                                                    my_public_key,
                                                    peer,
                                                    &sessions,
                                                    &mut pending_handshakes,
                                                    &mut handshake_started,
                                                    &now,
                                                    false,
                                                )
                                                .await;
                                            }
                                            if send_ack {
                                                if let Some(ch) = response_channel {
                                                    let _ = swarm
                                                        .behaviour_mut()
                                                        .request_response
                                                        .send_response(ch, V1Packet::Ack);
                                                }
                                                // Пир точно умеет расшифровывать — можно
                                                // слить буфер, который ждал конца Hello.
                                                flush_pending_encrypted_messages(
                                                    &mut swarm,
                                                    &mut sessions,
                                                    &mut outbound_msg_requests,
                                                    &mut outbound_delete_requests,
                                                    &event_tx,
                                                    peer,
                                                    &mut pending_messages,
                                                    &now,
                                                )
                                                .await;
                                                flush_pending_read_receipts(
                                                    &mut swarm,
                                                    &mut sessions,
                                                    &mut outbound_msg_requests,
                                                    &mut outbound_delete_requests,
                                                    &event_tx,
                                                    peer,
                                                    &mut pending_read_receipts,
                                                    &now,
                                                )
                                                .await;
                                            }
                                        }
                                        V1Packet::Onion { .. } | V1Packet::OnionDrop { .. } => {
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                        }
                                        V1Packet::Ack => {
                                            rr_reply(
                                                &mut swarm,
                                                &mut channel,
                                                onion_reply,
                                                V1Packet::Ack,
                                            );
                                        }
                                    }
                                    } // onion / onion-drop unwrap
                                }
                                libp2p::request_response::Message::Response { request_id, response } => {
                                    match response {
                                        V1Packet::Ack => {
                                            if let Some((handoff, _recip, message_id)) =
                                                outbound_mailbox_stores.remove(&request_id)
                                            {
                                                debug!(
                                                    "[{}] ✅ RR: OfflineMailboxStore Ack {}",
                                                    now,
                                                    &message_id[..8.min(message_id.len())]
                                                );
                                                handoff.note_store_ack(&message_id);
                                                // Ящик принял конверт — это НЕ доставка
                                                // собеседнику. ✓ только с live Encrypted Ack,
                                                // иначе pending_sends снимается, а пир online
                                                // так и не видит текст (файлы ящик не используют).
                                            } else if let Some((chunk_peer, tid, chunk_idx)) =
                                                outbound_chunk_requests.remove(&request_id)
                                            {
                                                let _ = chunk_idx;
                                                let mut done_xfer = None;
                                                if let Some(t) =
                                                    outgoing_transfers.get_mut(&tid)
                                                {
                                                    t.chunk_inflight = false;
                                                    t.last_chunk_at = Instant::now()
                                                        - file_transfer::DIRECT_CHUNK_DELAY;
                                                    if t.all_chunks_acked() {
                                                        done_xfer = Some((
                                                            t.filename.clone(),
                                                            t.kind,
                                                            t.total_chunks(),
                                                            t.is_relay,
                                                        ));
                                                    }
                                                }
                                                if let Some((fname, fkind, total, is_relay)) =
                                                    done_xfer
                                                {
                                                    debug!(
                                                        "📤 FILE[{}]: все {} чанк(ов) «{}» подтверждены E2EE{}.",
                                                        fkind.label(),
                                                        total,
                                                        fname,
                                                        if is_relay {
                                                            " (relay rate-limit)"
                                                        } else {
                                                            ""
                                                        }
                                                    );
                                                    let _ = event_tx
                                                        .send(NetworkEvent::FileComplete {
                                                            transfer_id: tid,
                                                            filename: fname,
                                                            saved_to: String::new(),
                                                            is_outgoing: true,
                                                            peer: chunk_peer,
                                                        })
                                                        .await;
                                                    outgoing_transfers.remove(&tid);
                                                }
                                            } else if let Some((delivered_peer, message_id, _)) =
                                                outbound_msg_requests.remove(&request_id)
                                            {
                                                debug!(
                                                    "[{}] ✅ RR: Доставка подтверждена пиром {} msg {}",
                                                    now,
                                                    &delivered_peer.to_string()[..8],
                                                    &message_id[..8.min(message_id.len())]
                                                );
                                                let _ = event_tx
                                                    .send(NetworkEvent::MessageDelivered {
                                                        peer: delivered_peer,
                                                        message_id,
                                                    })
                                                    .await;
                                            } else if outbound_delete_requests.remove(&request_id).is_some()
                                            {
                                                debug!(
                                                    "[{}] ✅ RR: delete подтверждён пиром {}",
                                                    now,
                                                    &peer.to_string()[..8]
                                                );
                                            } else if let Some((recipient, _items, _done)) =
                                                outbound_prekey_gets.remove(&request_id)
                                            {
                                                // PrekeyGet → Ack = miss on this bootstrap.
                                                // Не закрываем gate: DHT PrekeyForPublish /
                                                // другой bootstrap ещё могут ответить Offer.
                                                debug!(
                                                    "[{}] prekey miss on bootstrap for {}",
                                                    now,
                                                    &recipient.to_string()
                                                        [..8.min(recipient.to_string().len())]
                                                );
                                            }
                                        }
                                        V1Packet::PrekeyOffer {
                                            peer_id,
                                            public_key,
                                        } => {
                                            if let Some((recipient, items, done)) =
                                                outbound_prekey_gets.remove(&request_id)
                                            {
                                                let parsed_ok = peer_id
                                                    .parse::<PeerId>()
                                                    .ok()
                                                    .filter(|p| *p == recipient)
                                                    .is_some();
                                                if parsed_ok && public_key != [0u8; 32] {
                                                    // Drop sibling PrekeyGets for same recipient.
                                                    outbound_prekey_gets
                                                        .retain(|_, (r, _, _)| *r != recipient);
                                                    remember_peer_prekey(
                                                        &mut peer_prekeys,
                                                        &event_tx,
                                                        recipient,
                                                        public_key,
                                                    )
                                                    .await;
                                                    let ok = seal_and_publish_offline_batch(
                                                        &mut swarm,
                                                        &mut peer_prekeys,
                                                        &mut relay_mail_store,
                                                        &bootstrap_peer_ids,
                                                        &void_bootstraps,
                                                        local_peer_id,
                                                        &my_public_key_bytes,
                                                        &mut pending_relay,
                                                        &mut pending_relay_gates,
                                                        &mut outbound_mailbox_stores,
                                                        &mut pending_kad_mail,
                                                        recipient,
                                                        public_key,
                                                        items,
                                                        done,
                                                    );
                                                    if ok {
                                                        let _ = event_tx
                                                            .send(NetworkEvent::Status(
                                                                "📤 Офлайн → bootstrap (prekey с ноды)"
                                                                    .into(),
                                                            ))
                                                            .await;
                                                    }
                                                } else {
                                                    signal_publish_done(&done, false);
                                                }
                                            } else if let Ok(pid) = peer_id.parse::<PeerId>() {
                                                if public_key != [0u8; 32] {
                                                    remember_peer_prekey(
                                                        &mut peer_prekeys,
                                                        &event_tx,
                                                        pid,
                                                        public_key,
                                                    )
                                                    .await;
                                                }
                                            }
                                        }
                                        V1Packet::OfflineMailboxDeliver { envelopes } => {
                                            if !envelopes.is_empty() {
                                                let _ = event_tx
                                                    .send(NetworkEvent::OfflineMailbox(envelopes))
                                                    .await;
                                                // Остаток ящика — следующим тиком, не сразу.
                                                // Мгновенный Query + copy_batch на ноде = tight
                                                // loop, yamux saturates, Hop не проходит.
                                                fetch_mailbox_after = Some(
                                                    Instant::now() + Duration::from_millis(500),
                                                );
                                            }
                                        }
                                        V1Packet::Hello {
                                            public_key,
                                            ephemeral_key,
                                            transport_sig,
                                            transport_pubkey_pb,
                                        } => {
                                            // Encrypted got Hello instead of Ack: peer has no
                                            // matching session. That Hello's ephem is disposable —
                                            // do NOT derive keys from it. Requeue + real Hello.
                                            if let Some((retry_peer, retry_id, json)) =
                                                outbound_msg_requests.remove(&request_id)
                                            {
                                                debug!(
                                                    "[{}] ↻ RR: {} ответил Hello вместо Ack (msg {}) — реqueue{}",
                                                    now,
                                                    &peer.to_string()[..8],
                                                    &retry_id[..8.min(retry_id.len())],
                                                    if e2ee_session_is_fresh(
                                                        &session_established_at,
                                                        retry_peer,
                                                    ) {
                                                        " (сессия свежая — не сбрасываю)"
                                                    } else {
                                                        " + Handshake"
                                                    }
                                                );
                                                let _ = retry_id;
                                                requeue_pending_chat_json(
                                                    &mut pending_messages,
                                                    retry_peer,
                                                    json,
                                                );
                                                if e2ee_session_is_fresh(
                                                    &session_established_at,
                                                    retry_peer,
                                                ) {
                                                    // Responder уже ответил Hello; наш Encrypted
                                                    // просто пришёл раньше. Сброс сессии ломает
                                                    // ratchet, который initiator как раз создаёт.
                                                } else {
                                                    drop_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        retry_peer,
                                                    );
                                                    pending_handshakes.remove(&retry_peer);
                                                    handshake_started.remove(&retry_peer);
                                                    let _ = event_tx
                                                        .send(NetworkEvent::MessageAwaitingSession(
                                                            retry_peer,
                                                        ))
                                                        .await;
                                                    if swarm.is_connected(&retry_peer) {
                                                        let now_hs = chrono::Local::now()
                                                            .format("%H:%M:%S")
                                                            .to_string();
                                                        let _ = ensure_e2ee_handshake_started(
                                                            &mut swarm,
                                                            &local_key,
                                                            local_peer_id,
                                                            my_public_key,
                                                            retry_peer,
                                                            &sessions,
                                                            &mut pending_handshakes,
                                                            &mut handshake_started,
                                                            &now_hs,
                                                            true,
                                                        )
                                                        .await;
                                                    }
                                                }
                                            } else if let Some((chunk_peer, tid, chunk_idx)) =
                                                outbound_chunk_requests.remove(&request_id)
                                            {
                                                // Чанк файла получил Hello вместо Ack — сессия
                                                // рассинхронизирована. Раньше next_chunk уже
                                                // сдвигался и transfer мог быть удалён → файл
                                                // «принимали», но байты не доходили.
                                                if let Some(t) =
                                                    outgoing_transfers.get_mut(&tid)
                                                {
                                                    t.next_chunk =
                                                        t.next_chunk.min(chunk_idx as usize);
                                                    t.chunk_inflight = false;
                                                    t.last_chunk_at = Instant::now();
                                                }
                                                crate::voice::voice_log(&format!(
                                                    "chunk Hello instead of Ack {} #{chunk_idx} — rewind + handshake",
                                                    transfer_id_to_hex(&tid)
                                                ));
                                                debug!(
                                                    "[{}] ↻ FILE: {} ответил Hello на чанк {} — rewind + Handshake",
                                                    now,
                                                    &chunk_peer.to_string()[..8],
                                                    chunk_idx
                                                );
                                                if !e2ee_session_is_fresh(
                                                    &session_established_at,
                                                    chunk_peer,
                                                ) {
                                                    drop_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        chunk_peer,
                                                    );
                                                    pending_handshakes.remove(&chunk_peer);
                                                    handshake_started.remove(&chunk_peer);
                                                    if swarm.is_connected(&chunk_peer) {
                                                        let now_hs = chrono::Local::now()
                                                            .format("%H:%M:%S")
                                                            .to_string();
                                                        let _ = ensure_e2ee_handshake_started(
                                                            &mut swarm,
                                                            &local_key,
                                                            local_peer_id,
                                                            my_public_key,
                                                            chunk_peer,
                                                            &sessions,
                                                            &mut pending_handshakes,
                                                            &mut handshake_started,
                                                            &now_hs,
                                                            true,
                                                        )
                                                        .await;
                                                    }
                                                }
                                            } else if peer != local_peer_id {
                                                if !verify_hello_transport_binding(
                                                    peer,
                                                    local_peer_id,
                                                    &public_key,
                                                    &ephemeral_key,
                                                    transport_sig.as_slice(),
                                                    transport_pubkey_pb.as_slice(),
                                                ) {
                                                    debug!(
                                                        "[{}] ❌ E2EE: Hello (ответ) от {} без привязки к libp2p identity — игнор.",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                } else {
                                                let is_initiator = local_peer_id < peer;
                                                // Сессию из ответа Hello строим только если
                                                // наш исходящий Hello ещё жив. Иначе это
                                                // disposable Hello (нет сессии у пира) —
                                                // сброс уже рабочей сессии убивает чат.
                                                if let Some(local_ephem_secret) =
                                                    pending_handshakes.remove(&peer)
                                                {
                                                    handshake_started.remove(&peer);
                                                    drop_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        peer,
                                                    );
                                                    let remote_static_pub =
                                                        crypto::PublicKey::from(public_key);
                                                    remember_peer_prekey(
                                                        &mut peer_prekeys,
                                                        &event_tx,
                                                        peer,
                                                        public_key,
                                                    )
                                                    .await;
                                                    let remote_ephem_pub =
                                                        crypto::PublicKey::from(ephemeral_key);
                                                    let session = crypto::SecureSession::new_initiator(
                                                        &local_static,
                                                        &remote_static_pub,
                                                        local_ephem_secret,
                                                        &remote_ephem_pub,
                                                    );
                                                    put_e2ee_session(
                                                        &mut sessions,
                                                        &mut session_established_at,
                                                        peer,
                                                        session,
                                                    );
                                                    debug!(
                                                        "[{}] 🤝 E2EE: Сессия (ответ Hello) создана с {}{}",
                                                        now,
                                                        &peer.to_string()[..8],
                                                        if is_initiator { " [initiator по ID]" } else { "" }
                                                    );
                                                    flush_pending_encrypted_messages(
                                                        &mut swarm,
                                                        &mut sessions,
                                                        &mut outbound_msg_requests,
                                                        &mut outbound_delete_requests,
                                                        &event_tx,
                                                        peer,
                                                        &mut pending_messages,
                                                        &now,
                                                    )
                                                    .await;
                                                    flush_pending_read_receipts(
                                                        &mut swarm,
                                                        &mut sessions,
                                                        &mut outbound_msg_requests,
                                                        &mut outbound_delete_requests,
                                                        &event_tx,
                                                        peer,
                                                        &mut pending_read_receipts,
                                                        &now,
                                                    )
                                                    .await;
                                                    flush_pending_voice_transfers(
                                                        &mut swarm,
                                                        &mut sessions,
                                                        &mut outgoing_transfers,
                                                        &relay_peers,
                                                        &event_tx,
                                                        peer,
                                                        &mut pending_voice_transfers,
                                                    )
                                                    .await;
                                                    flush_pending_named_files(
                                                        &mut swarm,
                                                        &mut sessions,
                                                        &mut outgoing_transfers,
                                                        &relay_peers,
                                                        &event_tx,
                                                        peer,
                                                        &mut pending_named_files,
                                                        &file_cache_key,
                                                    )
                                                    .await;
                                                }
                                                }
                                            }
                                        }
                                        V1Packet::Encrypted { header, ciphertext } => {
                                            if let Some(session) = sessions.get_mut(&peer) {
                                                if let Ok(plaintext) = session.decrypt_payload(&header, &ciphertext)
                                                {
                                                    if let Some(ctrl) =
                                                        file_transfer::try_decode_e2ee_file_ctrl(&plaintext)
                                                    {
                                                        match ctrl {
                                                            file_transfer::FilePacket::Accept {
                                                                transfer_id,
                                                            } => {
                                                                if let Some(t) = outgoing_transfers
                                                                    .get_mut(&transfer_id)
                                                                {
                                                                    t.accepted = true;
                                                                    t.chunk_inflight = false;
                                                                    t.last_chunk_at = Instant::now()
                                                                        - file_transfer::DIRECT_CHUNK_DELAY;
                                                                }
                                                            }
                                                            file_transfer::FilePacket::Reject {
                                                                transfer_id,
                                                                reason,
                                                            } => {
                                                                outgoing_transfers.remove(&transfer_id);
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::FileError {
                                                                        transfer_id,
                                                                        reason: format!(
                                                                            "Отклонено: {}",
                                                                            reason
                                                                        ),
                                                                    })
                                                                    .await;
                                                            }
                                                            file_transfer::FilePacket::Cancel {
                                                                transfer_id,
                                                            } => {
                                                                incoming_transfers.remove(&transfer_id);
                                                                outgoing_transfers.remove(&transfer_id);
                                                            }
                                                            file_transfer::FilePacket::Request {
                                                                transfer_id,
                                                            } => {
                                                                let _ = event_tx
                                                                    .send(
                                                                        NetworkEvent::FileResendRequest {
                                                                            from: peer,
                                                                            transfer_id,
                                                                        },
                                                                    )
                                                                    .await;
                                                            }
                                                            _ => {}
                                                        }
                                                    } else if let Some((tid, idx, pdata)) =
                                                        file_transfer::try_decode_e2ee_file_chunk_frame(
                                                            &plaintext,
                                                        )
                                                    {
                                                        let voice_outcome = apply_incoming_file_chunk(
                                                            tid,
                                                            idx,
                                                            pdata,
                                                            peer,
                                                            &now,
                                                            &mut incoming_transfers,
                                                            &event_tx,
                                                            &file_cache_key,
                                                        )
                                                        .await;
                                                        if let Some((vtid, vok)) = voice_outcome {
                                                            if let Some(ack_json) =
                                                                build_voice_ack_json(&transfer_id_to_hex(&vtid), vok)
                                                            {
                                                                let _ = send_encrypted_chat_payload(
                                                                    &mut swarm,
                                                                    &mut sessions,
                                                                    &mut outbound_msg_requests,
                                                                    &mut outbound_delete_requests,
                                                                    &event_tx,
                                                                    peer,
                                                                    ack_json,
                                                                    None,
                                                                    &now,
                                                                )
                                                                .await;
                                                            }
                                                        }
                                                    } else if let Some(frame) =
                                                        parse_decrypted_chat_frame(&plaintext)
                                                    {
                                                        match frame {
                                                            DecryptedChatFrame::Message(msg) => {
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::ChatMessage(msg))
                                                                    .await;
                                                            }
                                                            DecryptedChatFrame::VoiceAck {
                                                                transfer_id,
                                                                ok,
                                                            } => {
                                                                if let Some(tid) =
                                                                    transfer_id_from_hex(&transfer_id)
                                                                {
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::VoiceAck {
                                                                            peer,
                                                                            transfer_id: tid,
                                                                            ok,
                                                                        })
                                                                        .await;
                                                                }
                                                            }
                                                            DecryptedChatFrame::DeleteAck => {}
                                                            DecryptedChatFrame::Delete { .. } => {}
                                                            DecryptedChatFrame::Read {
                                                                message_ids,
                                                            } => {
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::MessageRead {
                                                                        peer,
                                                                        message_ids,
                                                                    })
                                                                    .await;
                                                            }
                                                            DecryptedChatFrame::GroupSync {
                                                                group_id,
                                                                group_name,
                                                                creator_id,
                                                                members,
                                                            } => {
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::GroupSync {
                                                                        from: peer,
                                                                        group_id,
                                                                        group_name,
                                                                        creator_id,
                                                                        members,
                                                                    })
                                                                    .await;
                                                            }
                                                            DecryptedChatFrame::GroupLeave {
                                                                group_id,
                                                                peer_id,
                                                            } => {
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::GroupLeave {
                                                                        from: peer,
                                                                        group_id,
                                                                        peer_id,
                                                                    })
                                                                    .await;
                                                            }
                                                            DecryptedChatFrame::GroupDelete {
                                                                group_id,
                                                            } => {
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::GroupDelete {
                                                                        from: peer,
                                                                        group_id,
                                                                    })
                                                                    .await;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        V1Packet::BootstrapGossip { .. } => {}
                                        V1Packet::DialBack { .. } => {}
                                        V1Packet::OfflineMailboxStore { .. }
                                        | V1Packet::OfflineMailboxQuery { .. }
                                        | V1Packet::PrekeyPut { .. }
                                        | V1Packet::PrekeyGet { .. } => {}
                                        V1Packet::Onion { .. } | V1Packet::OnionDrop { .. } => {}
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::OutboundFailure { peer, request_id, error, .. })) => {
                            // Чанк файла/голосового не долетел (таймаут, обрыв связи и т.п.) —
                            // без этого он считался «отправленным» навсегда, и получатель
                            // никогда не собирал файл целиком. Перематываем next_chunk назад,
                            // чтобы chunk_tick повторил отправку именно этого чанка.
                            let mail_store = outbound_mailbox_stores.remove(&request_id);
                            let _ = outbound_prekey_gets.remove(&request_id);
                            let was_chunk = outbound_chunk_requests.remove(&request_id);
                            if let Some((_, tid, chunk_idx)) = was_chunk {
                                if let Some(t) = outgoing_transfers.get_mut(&tid) {
                                    t.next_chunk = t.next_chunk.min(chunk_idx as usize);
                                    t.chunk_inflight = false;
                                    // Throttle retry to the normal per-chunk cadence, чтобы
                                    // мёртвый пир не вызвал шторм повторов каждые 20мс.
                                    t.last_chunk_at = Instant::now();
                                }
                                crate::voice::voice_log(&format!(
                                    "chunk send fail {} #{chunk_idx} ({error:?}) — retry",
                                    transfer_id_to_hex(&tid)
                                ));
                            }
                            let was_msg = outbound_msg_requests.remove(&request_id);
                            let had_msg = was_msg.is_some();
                            let was_delete = outbound_delete_requests.remove(&request_id).is_some();
                            if let Some((msg_peer, mid, json)) = was_msg {
                                let has_session = sessions.contains_key(&msg_peer);
                                let live = swarm.is_connected(&msg_peer);
                                if has_session && live {
                                    // Сессия жива (файлы уже ходят) — не паркуем в
                                    // pending_messages до нового Hello: иначе ○ навсегда.
                                    debug!(
                                        "↻ RR OutFailure msg {} к {} при живой E2EE — сразу resend",
                                        &mid[..8.min(mid.len())],
                                        &msg_peer.to_string()[..8]
                                    );
                                    let now_rs =
                                        chrono::Local::now().format("%H:%M:%S").to_string();
                                    let _ = send_encrypted_chat_payload(
                                        &mut swarm,
                                        &mut sessions,
                                        &mut outbound_msg_requests,
                                        &mut outbound_delete_requests,
                                        &event_tx,
                                        msg_peer,
                                        json,
                                        None,
                                        &now_rs,
                                    )
                                    .await;
                                } else {
                                    requeue_pending_chat_json(
                                        &mut pending_messages,
                                        msg_peer,
                                        json,
                                    );
                                    let _ = event_tx
                                        .send(NetworkEvent::MessageAwaitingSession(msg_peer))
                                        .await;
                                    if live && !has_session {
                                        let now_hs =
                                            chrono::Local::now().format("%H:%M:%S").to_string();
                                        let _ = ensure_e2ee_handshake_started(
                                            &mut swarm,
                                            &local_key,
                                            local_peer_id,
                                            my_public_key,
                                            msg_peer,
                                            &sessions,
                                            &mut pending_handshakes,
                                            &mut handshake_started,
                                            &now_hs,
                                            true,
                                        )
                                        .await;
                                    }
                                }
                            }
                            // Неотслеживаемый запрос — это Hello-handshake; сбрасываем, чтобы
                            // повторная отправка не считала хендшейк «уже в полёте».
                            if !had_msg && !was_delete && was_chunk.is_none() {
                                pending_handshakes.remove(&peer);
                                handshake_started.remove(&peer);
                                let still_connected = swarm.is_connected(&peer);
                                let has_buf = pending_messages
                                    .get(&peer)
                                    .is_some_and(|q| !q.is_empty());
                                if still_connected && has_buf {
                                    // Живое соединение: не уводим в offline — повторяем Hello.
                                    let now_hs =
                                        chrono::Local::now().format("%H:%M:%S").to_string();
                                    let _ = ensure_e2ee_handshake_started(
                                        &mut swarm,
                                        &local_key,
                                        local_peer_id,
                                        my_public_key,
                                        peer,
                                        &sessions,
                                        &mut pending_handshakes,
                                        &mut handshake_started,
                                        &now_hs,
                                        true,
                                    )
                                    .await;
                                } else if has_buf && !still_connected {
                                    let _ = event_tx.send(NetworkEvent::SendFailedDial(peer)).await;
                                }
                            }
                            // Дедуп: если тому же пиру прилетел такой же fail
                            // меньше секунды назад — это Hello+packet пара,
                            // логировать оба смысла нет.
                            let now_inst = Instant::now();
                            let is_dup = last_rr_outfail
                                .get(&peer)
                                .map(|t| now_inst.duration_since(*t) < Duration::from_secs(1))
                                .unwrap_or(false);
                            last_rr_outfail.insert(peer, now_inst);
                            if !is_dup {
                                debug!("⚠️ [RR] OutFailure пиру {}: {:?}", peer, error);
                            }
                            // OfflineMailboxStore fail: settle handoff, don't strip contacts / disconnect bootstrap as "zombie".
                            if let Some((handoff, _recip, _mid)) = mail_store {
                                match &error {
                                    libp2p::request_response::OutboundFailure::UnsupportedProtocols => {
                                        handoff.note_fail();
                                        if bootstrap_peer_ids.contains(&peer) {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(
                                                    "❌ Bootstrap-нода без /void/chat — ОБНОВИТЕ void-bootstrap-node".into(),
                                                ))
                                                .await;
                                        }
                                    }
                                    _ => {
                                        let still = outbound_mailbox_stores
                                            .values()
                                            .any(|(g, _, _)| Arc::ptr_eq(g, &handoff))
                                            || pending_relay_gates
                                                .values()
                                                .any(|g| Arc::ptr_eq(g, &handoff));
                                        if !still {
                                            handoff.note_fail();
                                        }
                                    }
                                }
                            } else {
                                match error {
                                    libp2p::request_response::OutboundFailure::DialFailure => {
                                        if !is_dup {
                                            if !bootstrap_peer_ids.contains(&peer) {
                                                redial_contact_hard(
                                                    &mut swarm,
                                                    peer,
                                                    &reconnect_targets,
                                                    &void_bootstraps,
                                                );
                                                swarm
                                                    .behaviour_mut()
                                                    .kad
                                                    .get_providers(peer_dht_record_key(peer));
                                                let _ = event_tx
                                                    .send(NetworkEvent::SendFailedDial(peer))
                                                    .await;
                                            }
                                        }
                                    }
                                    libp2p::request_response::OutboundFailure::ConnectionClosed
                                    | libp2p::request_response::OutboundFailure::Timeout => {
                                        if !bootstrap_peer_ids.contains(&peer) {
                                            let _ = swarm.disconnect_peer_id(peer);
                                            peer_ping_fail_streak.remove(&peer);
                                            redial_contact_hard(
                                                &mut swarm,
                                                peer,
                                                &reconnect_targets,
                                                &void_bootstraps,
                                            );
                                        }
                                    }
                                    libp2p::request_response::OutboundFailure::UnsupportedProtocols => {
                                        if !is_dup {
                                            if bootstrap_peer_ids.contains(&peer) {
                                                let _ = event_tx
                                                    .send(NetworkEvent::Status(
                                                        "❌ Bootstrap без /void/chat — обновите ноду".into(),
                                                    ))
                                                    .await;
                                            } else {
                                                let _ = event_tx
                                                    .send(NetworkEvent::SendFailedUnsupported(peer))
                                                    .await;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::InboundFailure { peer, error, .. })) => {
                            debug!("⚠️ [RR] InFailure от пира {}: {:?}", peer, error);
                        }
                        SwarmEvent::ExternalAddrConfirmed { address } => {
                            debug!("🌍 ВНЕШНИЙ АДРЕС ПОДТВЕРЖДЕН: {}", address);
                            if is_circuit_addr(&address) {
                                let relay = relay_peer_id_from_circuit_addr(&address)
                                    .or_else(|| {
                                        bootstrap_peer_ids
                                            .iter()
                                            .copied()
                                            .find(|b| swarm.is_connected(b))
                                    });
                                if let Some(relay) = relay {
                                    relay_circuit_reserved.insert(relay);
                                    relay_hop_pending.remove(&relay);
                                    hop_listen_after.remove(&relay);
                                    emit_hop_ready(&event_tx, relay, Some(address.clone()));
                                }
                            } else if !relay_circuit_reserved.is_empty() {
                                publish_self_in_dht(
                                    &mut swarm.behaviour_mut().kad,
                                    local_peer_id,
                                );
                                kad_bootstrap_after.get_or_insert(
                                    Instant::now() + Duration::from_secs(30),
                                );
                                let _ = event_tx
                                    .send(NetworkEvent::Status(
                                        "🌍 ГЛОБАЛЬНЫЙ АДРЕС: Вы доступны из интернета!".into(),
                                    ))
                                    .await;
                            }

                            let extracted_ip = address.iter().find_map(|p| match p {
                                libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.to_string()),
                                libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.to_string()),
                                _ => None,
                            });
                            if let Some(ip) = extracted_ip {
                                if !is_circuit_addr(&address) {
                                    let _ = event_tx
                                        .send(NetworkEvent::PublicIpConfirmed(ip))
                                        .await;
                                }
                            }
                        }
                        SwarmEvent::Dialing { peer_id, connection_id } => {
                            info!(
                                "dialing peer={:?} conn={:?}",
                                peer_id.map(|p| p.to_string()),
                                connection_id
                            );
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, connection_id, ref endpoint, num_established, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            let is_quic_ep = match endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                    addr_is_quic_v1(address)
                                }
                                libp2p::core::ConnectedPoint::Listener { local_addr, .. } => {
                                    addr_is_quic_v1(local_addr)
                                }
                            };
                            let is_circuit_ep = connected_point_is_circuit(endpoint);
                            let is_boot_peer = !is_circuit_ep
                                && (bootstrap_peer_ids.contains(&peer_id)
                                    || matches!(
                                        endpoint,
                                        libp2p::core::ConnectedPoint::Dialer { address, .. }
                                            if is_direct_bootstrap_tcp(address, &void_bootstraps)
                                    ));
                            // QUIC к bootstrap рвёт TCP. Второй TCP до Hop Ack
                            // часто и есть Reserve (listen_on, если ещё нет
                            // записи в relay client) — закрывать нельзя, иначе
                            // нода пишет reservation accepted, а UI «Hop…».
                            if is_boot_peer && u32::from(num_established) > 1 {
                                let drop_extra = is_quic_ep
                                    || relay_circuit_reserved.contains(&peer_id);
                                if drop_extra {
                                    warn!(
                                        "drop extra bootstrap {:?} n={} quic={} hop={} peer={}",
                                        connection_id,
                                        num_established,
                                        is_quic_ep,
                                        relay_circuit_reserved.contains(&peer_id),
                                        &peer_id.to_string()[..8.min(peer_id.to_string().len())]
                                    );
                                    let _ = swarm.close_connection(connection_id);
                                    continue;
                                }
                            }
                            debug!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. Всего пиров: {} (conn #{})", peer_id, endpoint, connected_count, num_established);
                            if let Some(address) = connected_point_remote_tcp(endpoint) {
                                let ep = addr_endpoint_key(address);
                                let our_bootstrap_dial = {
                                    let g = bootstrap_ep_gate();
                                    g.inflight.contains(&ep) || g.live.contains(&ep)
                                };
                                // Только прямой TCP. Circuit к контакту через тот же
                                // host:port не должен считаться сессией с нодой.
                                // 147.78.64.22 — всегда нода, даже если vault без этого IP.
                                if !is_circuit_addr(address)
                                    && addr_is_tcp(address)
                                    && !addr_is_quic_v1(address)
                                    && (is_void_bootstrap_host(address)
                                        || our_bootstrap_dial
                                        || is_direct_bootstrap_tcp(address, &void_bootstraps))
                                {
                                    bootstrap_ep_mark_live(address, true);
                                    if peer_id != local_peer_id {
                                        bootstrap_peer_ids.insert(peer_id);
                                        let mut rewritten = Vec::new();
                                        let next = if is_void_bootstrap_host(address) {
                                            normalize_peer_addr(void_node_tcp_addr(), peer_id)
                                        } else if let Some(tcp) =
                                            bootstrap_tcp_dial_addr(address)
                                        {
                                            normalize_peer_addr(tcp, peer_id)
                                        } else {
                                            normalize_peer_addr(
                                                strip_p2p_protocols(address.clone()),
                                                peer_id,
                                            )
                                        };
                                        for ma in void_bootstraps.iter_mut() {
                                            if addr_endpoint_key(ma) != addr_endpoint_key(&next)
                                            {
                                                continue;
                                            }
                                            if *ma != next {
                                                *ma = next.clone();
                                                rewritten.push(next.to_string());
                                            }
                                        }
                                        if rewritten.is_empty()
                                            && !void_bootstraps.contains(&next)
                                        {
                                            void_bootstraps.push(next.clone());
                                            rewritten.push(next.to_string());
                                        }
                                        if rewritten.is_empty() {
                                            rewritten.push(next.to_string());
                                        }
                                        bootstrap_peer_ids =
                                            bootstrap_peer_ids_from(&void_bootstraps);
                                        onion_rt_set_keys(
                                            onion_keys.clone(),
                                            bootstrap_peer_ids.clone(),
                                            local_peer_id,
                                        );
                                        let _ = event_tx
                                            .send(NetworkEvent::BootstrapSession {
                                                peer: peer_id,
                                                up: true,
                                            })
                                            .await;
                                        let _ = event_tx
                                            .send(NetworkEvent::BootstrapsLearned(rewritten))
                                            .await;
                                    }
                                    info!(
                                        "bootstrap TCP живой {} peer={}",
                                        address, peer_id
                                    );
                                }
                            }
                            pending_dials.remove(&peer_id);
                            // Соединение установлено — снимаем задание на реконнект.
                            reconnect_queue.remove(&peer_id);
                            bootstrap_fail_streak.remove(&peer_id);
                            peer_ping_fail_streak.remove(&peer_id);
                            flush_pending_relay_for_peer(
                                &mut swarm,
                                &mut pending_relay,
                                &mut pending_relay_gates,
                                &mut outbound_mailbox_stores,
                                peer_id,
                            );

                            // Определяем, идёт ли соединение через relay.
                            let is_relay_conn = match endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                    address.to_string().contains("p2p-circuit")
                                }
                                libp2p::core::ConnectedPoint::Listener { local_addr, .. } => {
                                    local_addr.to_string().contains("p2p-circuit")
                                }
                            };
                            if is_relay_conn {
                                relay_peers.insert(peer_id);
                            } else {
                                // Не сбрасываем relay_peers при доп. прямом conn к тому же пиру.
                                if u32::from(num_established) <= 1 {
                                    relay_peers.remove(&peer_id);
                                }
                            }
                            onion_rt_set_relay_peers(relay_peers.clone());

                            // Живой dialer-адрес bootstrap нужен для Hop listen
                            // (публичный IP раньше отбрасывался → пустой relay_src).
                            if bootstrap_peer_ids.contains(&peer_id) {
                                if let libp2p::core::ConnectedPoint::Dialer { address, .. } =
                                    endpoint
                                {
                                    if !is_junk_addr(address)
                                        && !address.to_string().contains("p2p-circuit")
                                        && addr_is_tcp(address)
                                        && !addr_is_quic_v1(address)
                                    {
                                        let list =
                                            reconnect_targets.entry(peer_id).or_default();
                                        if !list.contains(address) {
                                            list.insert(0, address.clone());
                                        }
                                        bootstrap_hop_addr.insert(
                                            peer_id,
                                            strip_p2p_protocols(address.clone()),
                                        );
                                        // Hop только после Identify (hop_tick / Received).
                                        // listen_on здесь — Reserve по полуживому conn.
                                    }
                                }
                            }

                            if u32::from(num_established) > 1 {
                                // Доп. TCP/QUIC к тому же пиру — не шлём второй Hello
                                // и не дёргаем mailbox заново.
                                continue;
                            }
                            if !bootstrap_peer_ids.contains(&peer_id)
                                && !relay_circuit_reserved.is_empty()
                            {
                                publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
                            }

                             if peer_id != local_peer_id {
                                 // Контакты через circuit — только после Hop Ack,
                                 // иначе Listen/circuit делают второй dial к ноде.
                                 // E2EE только с VOID-чат пирами, не с bootstrap/DHT-узлами.
                                 let needs_handshake = !sessions.contains_key(&peer_id)
                                     && !bootstrap_peer_ids.contains(&peer_id);
                                 if needs_handshake {
                                     let now_hs = chrono::Local::now().format("%H:%M:%S").to_string();
                                     let _ = ensure_e2ee_handshake_started(
                                         &mut swarm,
                                         &local_key,
                                         local_peer_id,
                                         my_public_key,
                                         peer_id,
                                         &sessions,
                                         &mut pending_handshakes,
                                         &mut handshake_started,
                                         &now_hs,
                                         false,
                                     )
                                     .await;
                                 }
                                 let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                                 let _ = event_tx.send(NetworkEvent::Status(format!("✅ СОЕДИНЕНО: {}", &peer_id.to_string()[..8]))).await;
                                 // Bootstrap: Identify + ping сначала, иначе RR/kad.bootstrap
                                 // открывают второй dial и рвут только что поднятый TCP.
                                 // Ящик только у bootstrap — не Query на каждый контакт
                                 // (лишние RR-стримы душат Hop).
                                 // Сразу делимся bootstrap-нодами с любым подключённым VOID-клиентом.
                                 if !bootstrap_peer_ids.contains(&peer_id) {
                                     let gossip = bootstrap_gossip_strings(&void_bootstraps);
                                     let hints =
                                         collect_onion_hints(&onion_keys, &void_bootstraps);
                                     if !gossip.is_empty() || !hints.is_empty() {
                                         let _ = swarm.behaviour_mut().request_response.send_request(
                                             &peer_id,
                                             V1Packet::BootstrapGossip {
                                                 addrs: gossip,
                                                 onion_keys: hints,
                                             },
                                         );
                                     }
                                     // Просим собеседника набрать НАС через circuit —
                                     // иначе при асимметрии NAT он так и останется «не в сети».
                                     send_dial_back_hint(
                                         &mut swarm,
                                         peer_id,
                                         local_peer_id,
                                         &void_bootstraps,
                                         &local_listen_addrs,
                                     );
                                 }
                                 // Передаём рабочий multiaddr в UI: для Dialer — кого набирали,
                                 // для Listener — кто пришёл (send_back_addr + /p2p/peer_id).
                                 // UI сохранит его в контактную книгу.
                                 let learned: Option<(Multiaddr, bool)> = match endpoint {
                                     libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                         // Dialer address is known-good — prefer it.
                                         Some((address.clone(), true))
                                     }
                                     libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                         // Ephemeral NAT mapping — keep for LAN hints but never
                                         // ahead of circuit (Windows↔Mac asymmetry).
                                         let mut a = send_back_addr.clone();
                                         a.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                                         Some((a, false))
                                     }
                                 };
                                 if let Some((ref addr, prefer)) = learned {
                                     // Только LAN / circuit — public NAT (даже Dialer) яд для reverse dial.
                                     // Bootstrap-адреса уже сохранены выше.
                                     let usable = is_usable_contact_redial_addr(addr);
                                     if usable {
                                         let list = reconnect_targets.entry(peer_id).or_default();
                                         list.retain(is_usable_contact_redial_addr);
                                         list.retain(|a| a != addr);
                                         if prefer || is_circuit_addr(addr) {
                                             list.insert(0, addr.clone());
                                         } else {
                                             list.push(addr.clone());
                                         }

                                         let _ = event_tx
                                             .send(NetworkEvent::PeerAddress(peer_id, addr.clone()))
                                             .await;
                                     }
                                     // Всегда регистрируем пира для circuit auto-dial.
                                     watch_contact_peer(
                                         &mut reconnect_targets,
                                         peer_id,
                                         &bootstrap_peer_ids,
                                         local_peer_id,
                                     );
                                 }
                             }

                            // JoinViaNode без /p2p/: запоминаем адрес, DHT — только после Identify.
                            // kad.bootstrap() здесь открывает второй TCP и рвёт первый.
                            let is_seed = pending_seed_peers.contains(&peer_id) || pending_seed_bare;
                            if is_seed {
                                let addr = match endpoint {
                                    libp2p::core::ConnectedPoint::Dialer { ref address, .. } => Some(address.clone()),
                                    _ => None,
                                };
                                if let Some(mut addr) = addr {
                                    if peer_id_from_multiaddr(&addr).is_none() {
                                        addr.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                                    }
                                    if peer_id != local_peer_id && !void_bootstraps.contains(&addr) {
                                        void_bootstraps.push(addr.clone());
                                        bootstrap_peer_ids = bootstrap_peer_ids_from(&void_bootstraps);
                                        onion_rt_set_keys(
                                            onion_keys.clone(),
                                            bootstrap_peer_ids.clone(),
                                            local_peer_id,
                                        );
                                        let learned = vec![addr.to_string()];
                                        fanout_bootstrap_gossip(
                                            &mut swarm,
                                            local_peer_id,
                                            &bootstrap_peer_ids,
                                            learned.clone(),
                                            collect_onion_hints(&onion_keys, &void_bootstraps),
                                            None,
                                        );
                                        let _ = event_tx
                                            .send(NetworkEvent::BootstrapsLearned(learned))
                                            .await;
                                    }
                                }
                                pending_seed_bare = false;
                                pending_seed_peers.remove(&peer_id);
                                let _ = event_tx
                                    .send(NetworkEvent::Status(format!(
                                        "🌐 Seed TCP есть ({}). Ждём Identify…",
                                        &peer_id.to_string()[..12]
                                    )))
                                    .await;
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, num_established, connection_id, ref endpoint, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            warn!(
                                "connection closed {} conn={:?} cause={:?} remaining_with_peer={} peers={}",
                                peer_id, connection_id, cause, num_established, connected_count
                            );
                            if num_established == 0 {
                                if let Some(address) = connected_point_remote_tcp(endpoint) {
                                    bootstrap_ep_mark_live(address, false);
                                }
                                if bootstrap_peer_ids.contains(&peer_id) {
                                    bootstrap_ep_mark_live(&void_node_tcp_addr(), false);
                                }
                            }
                            if bootstrap_peer_ids.contains(&peer_id)
                                && num_established == 0
                                && !connected_point_is_circuit(endpoint)
                            {
                                let quic = matches!(
                                    endpoint,
                                    libp2p::core::ConnectedPoint::Dialer { address, .. }
                                        if addr_is_quic_v1(address)
                                ) || matches!(
                                    endpoint,
                                    libp2p::core::ConnectedPoint::Listener { local_addr, .. }
                                        if addr_is_quic_v1(local_addr)
                                );
                                if !quic {
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(format!(
                                            "❌ Bootstrap TCP закрыт ({:?})",
                                            cause
                                        )))
                                        .await;
                                }
                            }

                            // libp2p may close a duplicate connection while another remains.
                            if num_established > 0 || swarm.is_connected(&peer_id) {
                                continue;
                            }

                            relay_peers.remove(&peer_id);
                            onion_rt_set_relay_peers(relay_peers.clone());
                            // Circuit к контакту не должен снимать Hop/listen на ноде,
                            // даже если PeerId контакта ошибочно попал в bootstrap_peer_ids.
                            let drop_bootstrap_session = bootstrap_peer_ids.contains(&peer_id)
                                && !connected_point_is_circuit(endpoint);
                            if drop_bootstrap_session {
                                let hop_was_up = relay_circuit_reserved.remove(&peer_id);
                                let _ = relay_hop_pending.remove(&peer_id);
                                relay_listen_attempt_at.remove(&peer_id);
                                bootstrap_hop_addr.remove(&peer_id);
                                *hop_ok_at() = None;
                                if let Some(lid) = relay_hop_listeners.remove(&peer_id) {
                                    let _ = swarm.remove_listener(lid);
                                }
                                hop_listen_after.remove(&peer_id);
                                if hop_was_up {
                                    let _ = event_tx
                                        .send(NetworkEvent::RelayHopLost { relay: peer_id })
                                        .await;
                                }
                                bootstrap_identified.remove(&peer_id);
                                let _ = event_tx
                                    .send(NetworkEvent::BootstrapSession {
                                        peer: peer_id,
                                        up: false,
                                    })
                                    .await;
                            }
                            peer_ping_fail_streak.remove(&peer_id);

                            // E2EE: при обрыве TCP/QUIC сбрасываем криптосостояние с пиром.
                            // Иначе после рестарта одного клиента второй держит «старый» ratchet
                            // и новые Hello игнорируются (отправлялся только Ack → чат мёртв).
                            drop_e2ee_session(
                                &mut sessions,
                                &mut session_established_at,
                                peer_id,
                            );
                            pending_handshakes.remove(&peer_id);
                            handshake_started.remove(&peer_id);
                            // pending_messages сохраняем — UI/ретрай переотправит после реконнекта.

                            // Планируем переподключение для контактов из vault.
                            // Backoff: 2 с → 5 с → 15 с → 60 с (и далее 60 с).
                            if !drop_bootstrap_session
                                && reconnect_targets.contains_key(&peer_id)
                            {
                                // Не накапливаем reconnect-очередь для уже-диалящихся (swarm сам retry).
                                let attempt = reconnect_queue
                                    .get(&peer_id)
                                    .map(|(_, a)| *a)
                                    .unwrap_or(0);
                                let delay = match attempt {
                                    0 => Duration::from_secs(2),
                                    1 => Duration::from_secs(5),
                                    2 => Duration::from_secs(15),
                                    _ => Duration::from_secs(60),
                                };
                                reconnect_queue.insert(
                                    peer_id,
                                    (Instant::now() + delay, attempt + 1),
                                );
                                debug!(
                                    "🔄 Реконнект запланирован: {} через {}с (попытка {}).",
                                    &peer_id.to_string()[..8],
                                    delay.as_secs(),
                                    attempt + 1
                                );
                            }

                            let _ = event_tx.send(NetworkEvent::Disconnected(peer_id)).await;
                            let any_boot =
                                bootstrap_peer_ids.iter().any(|p| swarm.is_connected(p));
                            if !any_boot {
                                dial_missing_bootstraps(
                                    &mut swarm,
                                    &bootstrap_peer_ids,
                                    &void_bootstraps,
                                );
                            }
                        }
                        SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                            debug!("📥 Входящее соединение: from {:?} to {:?}", send_back_addr, local_addr);
                        },

                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            if peer_id.is_none() {
                                let mut g = bootstrap_ep_gate();
                                let live = g.live.clone();
                                let failed: Vec<String> = g
                                    .inflight
                                    .iter()
                                    .filter(|k| !live.contains(*k))
                                    .cloned()
                                    .collect();
                                for k in failed {
                                    g.inflight.remove(&k);
                                    g.inflight_at.remove(&k);
                                    g.cooldown_until.insert(
                                        k,
                                        Instant::now() + Duration::from_secs(2),
                                    );
                                }
                                drop(g);
                                if !swarm_has_bootstrap_tcp(&swarm, &bootstrap_peer_ids) {
                                    dial_missing_bootstraps(
                                        &mut swarm,
                                        &bootstrap_peer_ids,
                                        &void_bootstraps,
                                    );
                                }
                            }
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            let peer_str = peer_id
                                .map(|p| format!("{}...", &p.to_string()[..8]))
                                .unwrap_or_else(|| "?".into());

                             let err_str = error.to_string();
                             // 10048 (AddrInUse), Timeout, Handshake, DNS Resolve — игнорируем в UI
                             let is_noise = err_str.contains("64000") ||
                                           err_str.contains("10048") ||
                                           err_str.contains("Timeout") ||
                                           err_str.contains("Handshake") ||
                                           err_str.contains("ResolveError") ||
                                           err_str.contains("No Matching Records Found");

                             if !is_noise {
                                 debug!("❌ ОШИБКА ИСХОДЯЩЕГО СОЕДИНЕНИЯ (peer: {}): {:?}", peer_str, error);
                                 // Do not toast transient dial noise (bootstrap failover etc.).
                             } else {
                                 // В консоли пишем кратко
                                 if err_str.contains("Timeout") || err_str.contains("Handshake") {
                                     debug!("ℹ️ [{}] Тайм-аут с {}. Проверьте ФАЙРВОЛ на обоих сторонах!", now, peer_str);
                                 } else if err_str.contains("10048") {
                                     debug!("ℹ️ [{}] Ошибка 10048 (нормально для Windows): {}", now, peer_str);
                                 } else {
                                     debug!("ℹ️ [{}] Техническая задержка/отказ (peer: {}): {}", now, peer_str, err_str);
                                 }
                             }

                            if let Some(p) = peer_id {
                                pending_dials.remove(&p);
                                dial_backoff.insert(p, std::time::Instant::now());
                                if !bootstrap_peer_ids.contains(&p) {
                                    note_circuit_fail(p);
                                }
                                // listen_on(/p2p-circuit) сам может дать DialFailure,
                                // пока TCP к ноде жив — это не падение bootstrap.
                                if bootstrap_peer_ids.contains(&p) && !swarm.is_connected(&p) {
                                    let streak = bootstrap_fail_streak.entry(p).or_insert(0);
                                    *streak = streak.saturating_add(1);
                                    debug!(
                                        "bootstrap {} fail streak={}",
                                        &p.to_string()[..8.min(p.to_string().len())],
                                        *streak
                                    );
                                    if !void_bootstraps.is_empty() {
                                        let n = void_bootstraps.len();
                                        for step in 1..=n {
                                            let idx = (bootstrap_failover_idx + step) % n;
                                            let ma = &void_bootstraps[idx];
                                            if let Some(next_pid) = peer_id_from_multiaddr(ma) {
                                                if next_pid == p {
                                                    continue;
                                                }
                                                if swarm.is_connected(&next_pid) {
                                                    continue;
                                                }
                                                if bootstrap_fail_streak
                                                    .get(&next_pid)
                                                    .copied()
                                                    .unwrap_or(0)
                                                    > 8
                                                {
                                                    continue;
                                                }
                                                // Back off if we just failed this peer.
                                                if dial_backoff
                                                    .get(&next_pid)
                                                    .is_some_and(|t| t.elapsed() < Duration::from_secs(3))
                                                {
                                                    continue;
                                                }
                                                bootstrap_failover_idx = idx;
                                                dial_bootstrap_direct(
                                                    &mut swarm,
                                                    next_pid,
                                                    vec![ma.clone()],
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            let err_str = error.to_string();
                            if !err_str.contains("Handshake") && !err_str.contains("Timeout") {
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ Входящее подключение отклонено: {}", error)
                                )).await;
                            }
                        },

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            let has_chat = peer_advertises_void_chat(&info);
                            let is_void_node = peer_is_void_bootstrap(&info);
                            if has_chat && !is_void_node {
                                if bootstrap_peer_ids.remove(&peer_id) {
                                    onion_rt_set_keys(
                                        onion_keys.clone(),
                                        bootstrap_peer_ids.clone(),
                                        local_peer_id,
                                    );
                                    warn!(
                                        "Identify: {} — VOID-чат, не relay-нода",
                                        &peer_id.to_string()[..12.min(peer_id.to_string().len())]
                                    );
                                }
                            }
                            let is_bootstrap = is_void_node
                                || (bootstrap_peer_ids.contains(&peer_id) && !has_chat);
                            debug!(
                                "[{}] 🆔 Identify: {} — {} listen, {} протоколов{}",
                                now,
                                peer_id,
                                info.listen_addrs.len(),
                                info.protocols.len(),
                                if has_chat {
                                    ""
                                } else if is_bootstrap {
                                    "  (bootstrap/relay)"
                                } else if info.protocol_version == VOID_IDENTIFY_PROTOCOL {
                                    "  (VOID-клиент, список протоколов ещё неполный)"
                                } else {
                                    "  ⚠️ БЕЗ /void/chat/1.0.0 (чужая версия)"
                                }
                            );
                            if is_bootstrap {
                                bootstrap_peer_ids.insert(peer_id);
                                if swarm.is_connected(&peer_id) {
                                    let _ = event_tx
                                        .send(NetworkEvent::BootstrapSession {
                                            peer: peer_id,
                                            up: true,
                                        })
                                        .await;
                                }
                                if let Some(pk) =
                                    crate::onion::parse_pk_from_agent(&info.agent_version)
                                {
                                    onion_keys.insert(peer_id, pk);
                                    onion_rt_set_keys(
                                        onion_keys.clone(),
                                        bootstrap_peer_ids.clone(),
                                        local_peer_id,
                                    );
                                    debug!(
                                        "[{}] 🧅 onion-ключ bootstrap {}",
                                        now,
                                        &peer_id.to_string()[..8.min(peer_id.to_string().len())]
                                    );
                                }
                                if swarm.is_connected(&peer_id)
                                    && bootstrap_identified.insert(peer_id)
                                {
                                    if !bootstrap_hop_addr.contains_key(&peer_id) {
                                        if let Some(list) = reconnect_targets.get(&peer_id) {
                                            if let Some(a) = list.iter().find(|a| {
                                                addr_is_tcp(a)
                                                    && !addr_is_quic_v1(a)
                                                    && !is_circuit_addr(a)
                                                    && !is_junk_addr(a)
                                            }) {
                                                bootstrap_hop_addr.insert(
                                                    peer_id,
                                                    strip_p2p_protocols(a.clone()),
                                                );
                                            }
                                        }
                                    }
                                    if !relay_circuit_reserved.contains(&peer_id) {
                                        // Не listen_on в том же тике, что Identify:
                                        // relay client ещё без этого conn → второй
                                        // dial на Reserve.
                                        hop_listen_after.entry(peer_id).or_insert(
                                            Instant::now() + Duration::from_millis(1500),
                                        );
                                    }
                                    // Kademlia (add_address / provide / put) до Hop Ack
                                    // открывает второй TCP к той же ноде.
                                }
                            }
                            // Первый identify часто приходит до регистрации /void/chat/1.0.0.
                            // Не удаляем VOID-клиентов и bootstrap из контактов ошибочно.
                            if !has_chat
                                && !is_bootstrap
                                && info.protocol_version != VOID_IDENTIFY_PROTOCOL
                                && !info.protocols.is_empty()
                                && peer_id != local_peer_id
                            {
                                let _ = event_tx
                                    .send(NetworkEvent::PeerIsNotVoidChat(peer_id))
                                    .await;
                            }
                            if has_chat
                                && !is_bootstrap
                                && !sessions.contains_key(&peer_id)
                                && swarm.is_connected(&peer_id)
                                && peer_id != local_peer_id
                            {
                                let _ = ensure_e2ee_handshake_started(
                                    &mut swarm,
                                    &local_key,
                                    local_peer_id,
                                    my_public_key,
                                    peer_id,
                                    &sessions,
                                    &mut pending_handshakes,
                                    &mut handshake_started,
                                    &now,
                                    false,
                                )
                                .await;
                            }
                            let mut bootstrap_learned: Vec<String> = Vec::new();
                            for addr in info.listen_addrs {
                                if is_junk_addr(&addr) {
                                    continue;
                                }
                                if is_bootstrap && (addr_is_quic_v1(&addr) || !addr_is_tcp(&addr)) {
                                    let _ = swarm
                                        .behaviour_mut()
                                        .kad
                                        .remove_address(&peer_id, &addr);
                                    continue;
                                }
                                let a = normalize_peer_addr(addr.clone(), peer_id);
                                // Bootstrap — публичные IP ок. Чат-пиры: только LAN/circuit.
                                // Иначе Identify травит vault ядовитыми NAT listen и
                                // Windows не может найти Mac (dial hangs → NotDialing).
                                let keep = is_bootstrap
                                    || is_usable_contact_redial_addr(&a);
                                if !keep {
                                    continue;
                                }
                                // Один TCP bootstrap уже в kad (ниже / hop_addr).
                                // add_address всех Identify listen → kad.bootstrap()
                                // параллельно набирает ту же ноду 5–7 раз.
                                if !is_bootstrap {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, a.clone());
                                }

                                if peer_id != local_peer_id {
                                    let list = reconnect_targets.entry(peer_id).or_default();
                                    if !is_bootstrap {
                                        list.retain(is_usable_contact_redial_addr);
                                    }
                                    if !list.contains(&a) {
                                        list.push(a.clone());
                                    }
                                }

                                if is_bootstrap
                                    && peer_id != local_peer_id
                                    && addr_is_tcp(&a)
                                    && !is_circuit_addr(&a)
                                {
                                    bootstrap_learned.push(a.to_string());
                                }

                                if has_chat && peer_id != local_peer_id {
                                    let _ = event_tx
                                        .send(NetworkEvent::PeerAddress(peer_id, a))
                                        .await;
                                }
                            }
                            if !bootstrap_learned.is_empty() {
                                let parsed: Vec<Multiaddr> = bootstrap_learned
                                    .iter()
                                    .filter_map(|s| s.parse().ok())
                                    .collect();
                                let added = merge_bootstraps_into_swarm(
                                    &mut swarm,
                                    &mut void_bootstraps,
                                    &mut bootstrap_peer_ids,
                                    &parsed,
                                );
                                if added > 0 {
                                    fanout_bootstrap_gossip(
                                        &mut swarm,
                                        local_peer_id,
                                        &bootstrap_peer_ids,
                                        bootstrap_learned.clone(),
                                        collect_onion_hints(&onion_keys, &void_bootstraps),
                                        None,
                                    );
                                    let _ = event_tx
                                        .send(NetworkEvent::BootstrapsLearned(bootstrap_learned))
                                        .await;
                                }
                            }
                            let was_seed = pending_seed_peers.remove(&peer_id);
                            if was_seed || pending_seed_bare {
                                pending_seed_bare = false;
                                if !relay_circuit_reserved.is_empty() {
                                    kad_bootstrap_after.get_or_insert(
                                        Instant::now() + Duration::from_secs(30),
                                    );
                                }
                                let _ = event_tx
                                    .send(NetworkEvent::Status(format!(
                                        "🌐 Вход в сеть через {}: DHT-bootstrap запущен.",
                                        &peer_id.to_string()[..12]
                                    )))
                                    .await;
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Sent { peer_id, .. })) => {
                            debug!("🆔 Identify: Отправлена информация пиру {}", peer_id);
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                            let err_str = error.to_string();
                            let err_lower = err_str.to_lowercase();
                            if err_lower.contains("negotiat") || err_lower.contains("failed to negotiate") || err_lower.contains("support") {
                                debug!("❌ [КРИТИЧНО] Identify: Несовпадение версий с {}.", peer_id);
                                debug!("🔥 Срочно ОБНОВИТЕ другое приложение и ЗАКРОЙТЕ старые процессы!");
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ ОШИБКА: Пир {}... использует СТАРУЮ ВЕРСИЮ!", &peer_id.to_string()[..8])
                                )).await;
                            } else {
                                debug!("🆔 Identify: Ошибка с пиром {}: {:?}", peer_id, error);
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Relay(
                            relay::client::Event::ReservationReqAccepted {
                                relay_peer_id,
                                renewal,
                                ..
                            },
                        )) => {
                            info!(
                                "📡 Relay: Hop Ack на {} (renewal={renewal})",
                                &relay_peer_id.to_string()[..8]
                            );
                            relay_circuit_reserved.insert(relay_peer_id);
                            relay_hop_pending.remove(&relay_peer_id);
                            hop_listen_after.remove(&relay_peer_id);
                            emit_hop_ready(&event_tx, relay_peer_id, None);
                            if !renewal {
                                kad_bootstrap_after.get_or_insert(
                                    Instant::now() + Duration::from_secs(30),
                                );
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Relay(
                            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. },
                        )) => {
                            debug!(
                                "📡 Relay: входящий circuit от {}",
                                &src_peer_id.to_string()[..8]
                            );
                            // Входящий circuit бывает только при живой резервации.
                            if let Some(relay) = bootstrap_peer_ids
                                .iter()
                                .copied()
                                .find(|b| swarm.is_connected(b))
                            {
                                if relay_circuit_reserved.insert(relay) {
                                    relay_hop_pending.remove(&relay);
                                    hop_listen_after.remove(&relay);
                                    emit_hop_ready(&event_tx, relay, None);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Relay(
                            relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. },
                        )) => {
                            debug!(
                                "📡 Relay: исходящий circuit через {}",
                                &relay_peer_id.to_string()[..8]
                            );
                            // STOP к чужому пиру ≠ наша Hop-резервация. Не ставим
                            // Hop OK: иначе UI зелёный, а listen_on так и без Ack.
                            let _ = relay_peer_id;
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Ping(ev)) => {
                            match ev.result {
                                Ok(_) => {
                                    peer_ping_fail_streak.remove(&ev.peer);
                                }
                                Err(e) => {
                                    let peer = ev.peer;
                                    let streak = peer_ping_fail_streak
                                        .entry(peer)
                                        .and_modify(|n| *n = n.saturating_add(1))
                                        .or_insert(1);
                                    debug!(
                                        "⚠️ Ping fail {} (#{streak}): {:?}",
                                        &peer.to_string()[..8.min(peer.to_string().len())],
                                        e
                                    );
                                    if bootstrap_peer_ids.contains(&peer) {
                                        // Пока Hop не встал, ping timeout на ноде —
                                        // не рвём единственный TCP (иначе «нет связи
                                        // с bootstrap» и набор больше не идёт).
                                        if hop_reservation_confirmed(&swarm) && *streak >= 8 {
                                            let _ = swarm.disconnect_peer_id(peer);
                                            peer_ping_fail_streak.remove(&peer);
                                        }
                                    } else if *streak >= 2 {
                                        // Zombie: Mac «в сети», Windows нет / RR мёртв.
                                        peer_ping_fail_streak.remove(&peer);
                                        let _ = swarm.disconnect_peer_id(peer);
                                        redial_contact_hard(
                                            &mut swarm,
                                            peer,
                                            &reconnect_targets,
                                            &void_bootstraps,
                                        );
                                    } else if reconnect_targets.contains_key(&peer) {
                                        dial_peer_live_circuits(
                                            &mut swarm,
                                            peer,
                                            &void_bootstraps,
                                            false,
                                        );
                                    }
                                }
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, .. })) => {
                            match &result {
                                libp2p::kad::QueryResult::PutRecord(Ok(_)) => {
                                    if let Some(MailboxKadOp::AwaitPut { done }) =
                                        pending_kad_mail.remove(&id)
                                    {
                                        let _ = event_tx
                                            .send(NetworkEvent::OfflineMailboxPublished)
                                            .await;
                                        // DHT Put Ok may settle only when ActiveHandoff
                                        // was created with allow_dht_fallback (no bootstraps).
                                        // With bootstraps, note_dht_ok is a no-op settle.
                                        signal_publish_done(&done, true);
                                    }
                                }
                                libp2p::kad::QueryResult::PutRecord(Err(_)) => {
                                    // Do NOT treat as success (old bug). Relay Store Ack
                                    // may still settle the once-gate; otherwise exit times out.
                                    if let Some(MailboxKadOp::AwaitPut { done: _ }) =
                                        pending_kad_mail.remove(&id)
                                    {
                                        debug!("VOID: DHT mailbox PutRecord failed — waiting relay Ack");
                                    }
                                }
                                libp2p::kad::QueryResult::GetRecord(Ok(
                                    kad::GetRecordOk::FoundRecord(peer_record),
                                )) => {
                                    if let Some(op) = pending_kad_mail.get_mut(&id) {
                                        match op {
                                            MailboxKadOp::MergePut { record_bytes, .. } => {
                                                *record_bytes =
                                                    Some(peer_record.record.value.clone());
                                            }
                                            MailboxKadOp::PrekeyForPublish {
                                                prekey_bytes, ..
                                            } => {
                                                *prekey_bytes =
                                                    Some(peer_record.record.value.clone());
                                            }
                                            MailboxKadOp::CachePrekey { prekey_bytes, .. } => {
                                                *prekey_bytes =
                                                    Some(peer_record.record.value.clone());
                                            }
                                            MailboxKadOp::AwaitPut { .. } => {}
                                        }
                                    }
                                }
                                libp2p::kad::QueryResult::GetRecord(Ok(
                                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                                )) => {
                                    if let Some(op) = pending_kad_mail.remove(&id) {
                                        match op {
                                            MailboxKadOp::MergePut {
                                                recipient,
                                                new_envelopes,
                                                done,
                                                record_bytes,
                                            } => {
                                                let existing = record_bytes
                                                    .as_deref()
                                                    .and_then(|b| decode_mailbox(b).ok())
                                                    .unwrap_or_default();
                                                let merged =
                                                    merge_envelopes(&existing, &new_envelopes);
                                                put_mailbox_envelopes(
                                                    &mut swarm,
                                                    &mut pending_kad_mail,
                                                    local_peer_id,
                                                    recipient,
                                                    &merged,
                                                    done,
                                                );
                                            }
                                            MailboxKadOp::PrekeyForPublish {
                                                recipient,
                                                items,
                                                done,
                                                prekey_bytes,
                                            } => {
                                                let pk_bytes =
                                                    prekey_bytes.and_then(|bytes| {
                                                        bytes.get(..32).map(|s| {
                                                            let mut arr = [0u8; 32];
                                                            arr.copy_from_slice(s);
                                                            arr
                                                        })
                                                    });
                                                if let Some(pk_bytes) = pk_bytes {
                                                    peer_prekeys.insert(recipient, pk_bytes);
                                                    let _ = event_tx
                                                        .send(NetworkEvent::PeerPrekey {
                                                            peer: recipient,
                                                            public_key: pk_bytes,
                                                        })
                                                        .await;
                                                    let pk =
                                                        crypto::PublicKey::from(pk_bytes);
                                                    let mut sealed = Vec::new();
                                                    for item in items {
                                                        if let Ok(env) = seal_for_recipient(
                                                            &pk,
                                                            &local_peer_id,
                                                            &my_public_key_bytes,
                                                            &item.message_id,
                                                            &item.kind,
                                                            &item.payload,
                                                        ) {
                                                            sealed.push(env);
                                                        }
                                                    }
                                                    if !sealed.is_empty() {
                                                        if RelayMailbox::merge(
                                                            &mut relay_mail_store,
                                                            &recipient.to_string(),
                                                            sealed.clone(),
                                                        ) {
                                                            let _ =
                                                                RelayMailbox::save(&relay_mail_store);
                                                        }
                                                        let allow_dht =
                                                            bootstrap_peer_ids.is_empty();
                                                        let done_cb: PublishDone = done
                                                            .unwrap_or_else(
                                                                || Arc::new(|_| {}) as PublishDone,
                                                            );
                                                        let handoff = Some(ActiveHandoff::new(
                                                            &sealed,
                                                            done_cb,
                                                            allow_dht,
                                                        ));
                                                        publish_relay_mail(
                                                            &mut swarm,
                                                            &bootstrap_peer_ids,
                                                            &void_bootstraps,
                                                            local_peer_id,
                                                            recipient,
                                                            &sealed,
                                                            &mut pending_relay,
                                                            &mut pending_relay_gates,
                                                            &mut outbound_mailbox_stores,
                                                            &handoff,
                                                        );
                                                        if let Some(h) = &handoff {
                                                            let tracked = outbound_mailbox_stores
                                                                .values()
                                                                .any(|(g, _, _)| Arc::ptr_eq(g, h));
                                                            let queued = pending_relay_gates
                                                                .values()
                                                                .any(|g| Arc::ptr_eq(g, h));
                                                            if !tracked
                                                                && !queued
                                                                && !accept_dht_as_full_handoff(
                                                                    &sealed,
                                                                    allow_dht,
                                                                )
                                                            {
                                                                warn!(
                                                                    "VOID: нет bootstrap-ноды для offline (после prekey)"
                                                                );
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::Status(
                                                                        "❌ Нет связи с bootstrap — офлайн-почта не сдана".into(),
                                                                    ))
                                                                    .await;
                                                                h.note_fail();
                                                            }
                                                        }
                                                        if allow_dht {
                                                            let for_dht =
                                                                dht_eligible_envelopes(&sealed);
                                                            let dht_done: Option<PublishDone> =
                                                                handoff.as_ref().map(|h| {
                                                                    let h = h.clone();
                                                                    Arc::new(move |ok: bool| {
                                                                        if ok {
                                                                            h.note_dht_ok();
                                                                        }
                                                                    })
                                                                        as PublishDone
                                                                });
                                                            start_mailbox_merge_put(
                                                                &mut swarm,
                                                                &mut pending_kad_mail,
                                                                recipient,
                                                                for_dht,
                                                                dht_done,
                                                            );
                                                        } else {
                                                            let _ = event_tx
                                                                .send(NetworkEvent::Status(
                                                                    "📤 Офлайн → bootstrap-нода (без DHT)".into(),
                                                                ))
                                                                .await;
                                                        }
                                                    } else {
                                                        signal_publish_done(&done, false);
                                                    }
                                                } else {
                                                    signal_publish_done(&done, false);
                                                    let _ = event_tx
                                                        .send(NetworkEvent::Status(format!(
                                                            "⚠ Нет prekey {} — офлайн-почта не отправлена",
                                                            &recipient.to_string()[..8.min(recipient.to_string().len())]
                                                        )))
                                                        .await;
                                                }
                                            }
                                            MailboxKadOp::CachePrekey {
                                                peer,
                                                prekey_bytes,
                                            } => {
                                                if let Some(pk_bytes) =
                                                    prekey_bytes.and_then(|bytes| {
                                                        bytes.get(..32).map(|s| {
                                                            let mut arr = [0u8; 32];
                                                            arr.copy_from_slice(s);
                                                            arr
                                                        })
                                                    })
                                                {
                                                    remember_peer_prekey(
                                                        &mut peer_prekeys,
                                                        &event_tx,
                                                        peer,
                                                        pk_bytes,
                                                    )
                                                    .await;
                                                }
                                            }
                                            MailboxKadOp::AwaitPut { .. } => {}
                                        }
                                    }
                                }
                                libp2p::kad::QueryResult::GetRecord(Err(_)) => {
                                    if let Some(op) = pending_kad_mail.remove(&id) {
                                        match op {
                                            MailboxKadOp::MergePut {
                                                recipient,
                                                new_envelopes,
                                                done,
                                                ..
                                            } => {
                                                put_mailbox_envelopes(
                                                    &mut swarm,
                                                    &mut pending_kad_mail,
                                                    local_peer_id,
                                                    recipient,
                                                    &new_envelopes,
                                                    done,
                                                );
                                            }
                                            MailboxKadOp::PrekeyForPublish { done, .. } => {
                                                signal_publish_done(&done, false);
                                            }
                                            MailboxKadOp::AwaitPut { .. }
                                            | MailboxKadOp::CachePrekey { .. } => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                            match result {
                                libp2p::kad::QueryResult::GetProviders(Ok(ok)) => {
                                    match ok {
                                        kad::GetProvidersOk::FoundProviders { key, providers } => {
                                            if let Some(wanted) = peer_id_from_dht_key(&key) {
                                                if providers.contains(&wanted) {
                                                    debug!(
                                                        "📍 DHT get_providers: {} онлайн (провайдер найден)",
                                                        &wanted.to_string()[..8]
                                                    );
                                                    if let Some(addrs) = kad_local_addrs_for_peer(
                                                        &mut swarm.behaviour_mut().kad,
                                                        wanted,
                                                    ) {
                                                        let _ = event_tx
                                                            .send(NetworkEvent::Status(format!(
                                                                "📍 DHT: {} найден ({} адр.) — набор",
                                                                &wanted.to_string()[..12],
                                                                addrs.len()
                                                            )))
                                                            .await;
                                                        let _ = command_tx_for_mdns.try_send(
                                                            UICommand::DialPeer(wanted, addrs),
                                                        );
                                                    } else {
                                                        dial_peer_best_effort(
                                                            &mut swarm,
                                                            wanted,
                                                            vec![],
                                                            &void_bootstraps,
                                                        );
                                                        let _ = event_tx
                                                            .send(NetworkEvent::Status(format!(
                                                                "📍 DHT: {} зарегистрирован — набор…",
                                                                &wanted.to_string()[..12]
                                                            )))
                                                            .await;
                                                    }
                                                }
                                            }
                                        }
                                        kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {}
                                    }
                                }
                                libp2p::kad::QueryResult::GetProviders(Err(e)) => {
                                    debug!("⚠️ Kademlia get_providers: {:?}", e);
                                    if let Some(wanted) = peer_id_from_dht_key(e.key()) {
                                        if let Some(addrs) = kad_local_addrs_for_peer(
                                            &mut swarm.behaviour_mut().kad,
                                            wanted,
                                        ) {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "⏱ DHT providers timeout для {} — локальная таблица ({} адр.)",
                                                    &wanted.to_string()[..8],
                                                    addrs.len()
                                                )))
                                                .await;
                                            let _ = command_tx_for_mdns.try_send(
                                                UICommand::DialPeer(wanted, addrs),
                                            );
                                        }
                                    }
                                }
                                 libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                    debug!(
                                        "🔍 Kademlia: get_closest_peers готов (кандидатов: {}).",
                                        ok.peers.len()
                                    );
                                    let wanted = PeerId::from_bytes(&ok.key).ok();
                                    if let Some(wanted) = wanted {
                                        if let Some(hit) = ok
                                            .peers
                                            .iter()
                                            .find(|p| p.peer_id == wanted && !p.addrs.is_empty())
                                        {
                                            debug!(
                                                "📍 В таблице есть целевой пир {} — набираю ({} адр.)",
                                                &wanted.to_string()[..8],
                                                hit.addrs.len()
                                            );
                                            let _ = command_tx_for_mdns.try_send(UICommand::DialPeer(
                                                hit.peer_id,
                                                hit.addrs.clone(),
                                            ));
                                        } else if ok.peers.is_empty() {
                                            debug!(
                                                "⚠️ Kademlia: 0 кандидатов для {} — пустая таблица DHT (нет bootstrap).",
                                                &wanted.to_string()[..12]
                                            );
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "⚠ DHT пуст (запрос к {}): добавьте seed в «VOID BOOTSTRAP» или VOID_BOOTSTRAP, либо полный multiaddr. Один PeerId без таблицы маршрутов в интернете не наберётся.",
                                                    &wanted.to_string()[..12]
                                                )))
                                                .await;
                                        } else {
                                            debug!(
                                                "⚠️ Пир {} нет среди ответов DHT с адресами — нужен multiaddr, bootstrap или mDNS (LAN).",
                                                &wanted.to_string()[..12]
                                            );
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "⚠ {}: в DHT нет маршрута с адресами. Полный multiaddr собеседника или общий VOID bootstrap.",
                                                    &wanted.to_string()[..8]
                                                )))
                                                .await;
                                        }
                                    }
                                }
                                libp2p::kad::QueryResult::GetClosestPeers(Err(e)) => {
                                    debug!("⚠️ Kademlia get_closest_peers: {:?}", e);
                                    let key = e.key();
                                    if let Some(wanted) = PeerId::from_bytes(key).ok() {
                                        if let Some(addrs) = kad_local_addrs_for_peer(
                                            &mut swarm.behaviour_mut().kad,
                                            wanted,
                                        ) {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "⏱ DHT timeout для {} — пробую адреса из локальной таблицы ({}).",
                                                    &wanted.to_string()[..8],
                                                    addrs.len()
                                                )))
                                                .await;
                                            let _ = command_tx_for_mdns.try_send(
                                                UICommand::DialPeer(wanted, addrs),
                                            );
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                            debug!(
                                "📍 Kademlia: маршрут для {} — {} адр.",
                                peer,
                                addresses.len()
                            );
                            if bootstrap_peer_ids.contains(&peer) {
                                for addr in addresses.iter() {
                                    if addr_is_quic_v1(addr) {
                                        let _ = swarm
                                            .behaviour_mut()
                                            .kad
                                            .remove_address(&peer, addr);
                                    }
                                }
                            }
                        }

                        // ─── Файловый sub-протокол /void/file/1.0.0 ─────────
                        SwarmEvent::Behaviour(ChatBehaviourEvent::FileRr(
                            libp2p::request_response::Event::Message { peer, message, .. },
                        )) => {
                            let now = chrono::Local::now().format("%H:%M:%S").to_string();
                            match message {
                                libp2p::request_response::Message::Request {
                                    request,
                                    channel,
                                    ..
                                } => {
                                    use file_transfer::FilePacket;
                                    if let Err(reason) =
                                        file_transfer::validate_inbound_file_packet(&request)
                                    {
                                        warn!(
                                            target: "void_net",
                                            peer = %peer,
                                            "FILE RR: invalid packet: {}",
                                            reason
                                        );
                                        let _ = swarm
                                            .behaviour_mut()
                                            .file_rr
                                            .send_response(channel, FilePacket::Ack);
                                        continue;
                                    }
                                    match request {
                                        FilePacket::Offer {
                                            transfer_id,
                                            filename,
                                            total_size,
                                            total_chunks,
                                            sha256,
                                            kind,
                                        } => {
                                            if let Err(reason) = file_transfer::validate_file_offer(
                                                &filename,
                                                total_size,
                                                total_chunks,
                                            ) {
                                                debug!(
                                                    "[{}] 🚫 FILE: отклонён Offer от {}: {}",
                                                    now,
                                                    &peer.to_string()[..8],
                                                    reason
                                                );
                                                let _ = swarm
                                                    .behaviour_mut()
                                                    .file_rr
                                                    .send_response(channel, FilePacket::Ack);
                                                continue;
                                            }
                                            debug!(
                                                "[{}] 📥 FILE[{}]: Offer «{}» от {} ({} чанков, {} байт)",
                                                now,
                                                kind.label(),
                                                filename,
                                                &peer.to_string()[..8],
                                                total_chunks,
                                                total_size
                                            );
                                            let safe = file_transfer::safe_filename(&filename);
                                            let resume = incoming_transfers
                                                .get(&transfer_id)
                                                .is_some_and(|inc| {
                                                    inc.received_count > 0
                                                        && inc.total_size == total_size
                                                        && inc.total_chunks == total_chunks
                                                        && inc.sha256 == sha256
                                                        && inc.filename == safe
                                                });
                                            if !resume {
                                                let incoming =
                                                    file_transfer::IncomingTransfer::new(
                                                        peer,
                                                        transfer_id,
                                                        safe.clone(),
                                                        total_size,
                                                        total_chunks,
                                                        sha256,
                                                        kind,
                                                    );
                                                incoming_transfers.insert(transfer_id, incoming);
                                            } else {
                                                crate::voice::voice_log(&format!(
                                                    "resume incoming {}",
                                                    transfer_id_to_hex(&transfer_id)
                                                ));
                                            }
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);

                                            if file_transfer::is_voice_filename(&safe) {
                                                if let Some(inc) =
                                                    incoming_transfers.get_mut(&transfer_id)
                                                {
                                                    inc.save_dir = Some(
                                                        file_transfer::voice_dir_absolute()
                                                            .display()
                                                            .to_string(),
                                                    );
                                                }
                                            } else if let Some(inc) =
                                                incoming_transfers.get_mut(&transfer_id)
                                            {
                                                inc.save_dir = Some(
                                                    file_transfer::file_cache_dir()
                                                        .display()
                                                        .to_string(),
                                                );
                                            }
                                            // Файлы в чате — как голосовые: принимаем сразу, без баннера.
                                            let accept = FilePacket::Accept { transfer_id };
                                            let _ = send_e2ee_file_ctrl(
                                                &mut swarm,
                                                &mut sessions,
                                                peer,
                                                &accept,
                                            );
                                            if swarm.is_connected(&peer) {
                                                swarm
                                                    .behaviour_mut()
                                                    .file_rr
                                                    .send_request(&peer, accept);
                                            }

                                            let _ = event_tx
                                                .send(NetworkEvent::FileOffer {
                                                    transfer_id,
                                                    from: peer,
                                                    filename: safe,
                                                    total_size,
                                                    kind,
                                                })
                                                .await;
                                        }
                                        FilePacket::Accept { transfer_id } => {
                                            debug!(
                                                "[{}] ✅ FILE: Accept от {} для {:x?}",
                                                now,
                                                &peer.to_string()[..8],
                                                &transfer_id[..4]
                                            );
                                            if let Some(t) =
                                                outgoing_transfers.get_mut(&transfer_id)
                                            {
                                                t.accepted = true;
                                                t.chunk_inflight = false;
                                                t.last_chunk_at =
                                                    Instant::now() - file_transfer::DIRECT_CHUNK_DELAY;
                                            }
                                            // Чанки идут только по E2EE — без сессии Accept
                                            // «есть», а файл не поедет.
                                            if !sessions.contains_key(&peer)
                                                && swarm.is_connected(&peer)
                                            {
                                                let now_hs = chrono::Local::now()
                                                    .format("%H:%M:%S")
                                                    .to_string();
                                                let _ = ensure_e2ee_handshake_started(
                                                    &mut swarm,
                                                    &local_key,
                                                    local_peer_id,
                                                    my_public_key,
                                                    peer,
                                                    &sessions,
                                                    &mut pending_handshakes,
                                                    &mut handshake_started,
                                                    &now_hs,
                                                    false,
                                                )
                                                .await;
                                            }
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);
                                        }
                                        FilePacket::Reject { transfer_id, reason } => {
                                            debug!(
                                                "[{}] ✖ FILE: Reject от {}: {}",
                                                now,
                                                &peer.to_string()[..8],
                                                reason
                                            );
                                            outgoing_transfers.remove(&transfer_id);
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);
                                            let _ = event_tx
                                                .send(NetworkEvent::FileError {
                                                    transfer_id,
                                                    reason: format!(
                                                        "Отклонено: {}",
                                                        reason
                                                    ),
                                                })
                                                .await;
                                        }
                                        FilePacket::Chunk {
                                            transfer_id,
                                            chunk_index,
                                            data,
                                        } => {
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);
                                            // Устаревший путь (plain): совместимость со старыми пирами.
                                            // Без E2EE-сессии voice_ack не отправить — атомарная
                                            // доставка голосовых гарантируется только по /void/chat.
                                            let _ = apply_incoming_file_chunk(
                                                transfer_id,
                                                chunk_index,
                                                data,
                                                peer,
                                                &now,
                                                &mut incoming_transfers,
                                                &event_tx,
                                                &file_cache_key,
                                            )
                                            .await;
                                        }
                                        FilePacket::Cancel { transfer_id } => {
                                            incoming_transfers.remove(&transfer_id);
                                            outgoing_transfers.remove(&transfer_id);
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);
                                            let _ = event_tx
                                                .send(NetworkEvent::FileError {
                                                    transfer_id,
                                                    reason: "Передача отменена собеседником."
                                                        .into(),
                                                })
                                                .await;
                                        }
                                        FilePacket::Request { transfer_id } => {
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);
                                            let _ = event_tx
                                                .send(NetworkEvent::FileResendRequest {
                                                    from: peer,
                                                    transfer_id,
                                                })
                                                .await;
                                        }
                                        FilePacket::Ack => {
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);
                                        }
                                    }
                                }
                                libp2p::request_response::Message::Response { .. } => {
                                    // Ack на наши запросы — ничего не делаем.
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::FileRr(
                            libp2p::request_response::Event::OutboundFailure {
                                peer,
                                error,
                                ..
                            },
                        )) => {
                            debug!(
                                "⚠️ [FILE RR] OutFailure пиру {}: {:?}",
                                &peer.to_string()[..8],
                                error
                            );
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::FileRr(
                            libp2p::request_response::Event::InboundFailure { peer, error, .. },
                        )) => {
                            debug!(
                                "⚠️ [FILE RR] InFailure от {}: {:?}",
                                &peer.to_string()[..8],
                                error
                            );
                        }

                        _ => {}
                    }
                }
            }
        }
}

#[cfg(feature = "egui-ui")]
pub fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod hop_listen_tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn pid() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    #[test]
    fn hop_addr_from_live_dialer_without_p2p() {
        let relay = pid();
        let live: Multiaddr = "/ip4/147.78.64.22/tcp/4001".parse().unwrap();
        let mut hop = HashMap::new();
        hop.insert(relay, live);
        let ma = hop_circuit_listen_addr(relay, &hop, &[], &HashMap::new()).expect("listen addr");
        let s = ma.to_string();
        assert!(s.contains("p2p-circuit"), "{s}");
        assert!(s.contains(&relay.to_string()), "{s}");
        assert!(s.contains("/tcp/4001"), "{s}");
        assert!(!addr_is_quic_v1(&ma));
    }

    #[test]
    fn hop_addr_rewrites_stale_vault_peer_id() {
        let relay = pid();
        let stale = pid();
        let vault: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{stale}")
            .parse()
            .unwrap();
        let live: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();
        let mut hop = HashMap::new();
        hop.insert(relay, live);
        let ma = hop_circuit_listen_addr(relay, &hop, &[vault], &HashMap::new()).expect("listen addr");
        let s = ma.to_string();
        assert!(s.contains(&relay.to_string()), "{s}");
        assert!(!s.contains(&stale.to_string()), "{s}");
        assert!(s.ends_with("/p2p-circuit") || s.contains("/p2p-circuit"), "{s}");
    }

    #[test]
    fn hop_addr_skips_quic() {
        let relay = pid();
        let q: Multiaddr = "/ip4/1.2.3.4/udp/4001/quic-v1".parse().unwrap();
        let mut hop = HashMap::new();
        hop.insert(relay, q);
        assert!(hop_circuit_listen_addr(relay, &hop, &[], &HashMap::new()).is_none());
    }

    #[test]
    fn circuit_to_contact_is_not_direct_bootstrap_tcp() {
        let node = pid();
        let contact = pid();
        let vault: Multiaddr = format!("/ip4/147.78.64.22/tcp/4001/p2p/{node}")
            .parse()
            .unwrap();
        let circuit: Multiaddr = format!(
            "/ip4/147.78.64.22/tcp/4001/p2p/{node}/p2p-circuit/p2p/{contact}"
        )
        .parse()
        .unwrap();
        let direct: Multiaddr = "/ip4/147.78.64.22/tcp/4001".parse().unwrap();
        assert!(!is_direct_bootstrap_tcp(&circuit, &[vault.clone()]));
        assert!(is_direct_bootstrap_tcp(&direct, &[vault]));
        assert_eq!(
            addr_endpoint_key(&circuit),
            addr_endpoint_key(&direct),
            "same host:port must not classify circuit as bootstrap TCP"
        );
        assert!(is_void_bootstrap_host(&direct));
        assert!(!is_void_bootstrap_host(&circuit));
        let lan: Multiaddr = "/ip4/192.168.1.5/tcp/50001".parse().unwrap();
        assert!(!is_void_bootstrap_host(&lan));
    }

    #[test]
    fn expand_dial_addrs_does_not_inject_circuits() {
        let node = pid();
        let contact = pid();
        let vault: Multiaddr = format!("/ip4/147.78.64.22/tcp/4001/p2p/{node}")
            .parse()
            .unwrap();
        let lan: Multiaddr = "/ip4/192.168.1.5/tcp/50001".parse().unwrap();
        let out = expand_dial_addrs(contact, vec![lan.clone()], &[vault]);
        assert!(out.iter().any(|a| a.to_string().contains("192.168.1.5")));
        assert!(
            out.iter().all(|a| !a.to_string().contains("p2p-circuit")),
            "{out:?}"
        );
    }

    #[test]
    fn circuit_addr_without_relay_p2p_parses_none() {
        let a: Multiaddr = "/ip4/147.78.64.22/tcp/4001/p2p-circuit".parse().unwrap();
        assert!(is_circuit_addr(&a));
        assert!(relay_peer_id_from_circuit_addr(&a).is_none());
    }
}
