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
    tcp, upnp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::bootstrap::{
    addr_is_quic_v1, expand_transport_variants, parse_seed_dial_addrs, peer_id_from_multiaddr,
    prefer_tcp_if_available, void_bootstrap_multiaddrs,
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
    wrap_onion_packet,
    DecryptedChatFrame, FileMeta, OutgoingDeliveryStatus, VoiceMeta, V1Packet,
};

struct OnionRuntime {
    keys: HashMap<PeerId, [u8; 32]>,
    bootstraps: HashSet<PeerId>,
    local: PeerId,
}

static ONION_RT: Mutex<Option<OnionRuntime>> = Mutex::new(None);

fn onion_rt_store(rt: OnionRuntime) {
    if let Ok(mut g) = ONION_RT.lock() {
        *g = Some(rt);
    }
}

fn onion_rt_set_keys(keys: HashMap<PeerId, [u8; 32]>, bootstraps: HashSet<PeerId>, local: PeerId) {
    onion_rt_store(OnionRuntime {
        keys,
        bootstraps,
        local,
    });
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

/// Адреса для listen через relay v2: `<relay>/p2p/<relay_id>/p2p-circuit`.
fn relay_circuit_listen_addrs(relay_addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    let mut out = Vec::new();
    for addr in relay_addrs {
        if addr.to_string().contains("p2p-circuit") {
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
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    void_bootstraps: &mut Vec<Multiaddr>,
    bootstrap_peer_ids: &mut HashSet<PeerId>,
    new_addrs: &[Multiaddr],
) -> usize {
    let mut added = 0usize;
    for ma in new_addrs {
        if !void_bootstraps.contains(ma) {
            if let Some(pid) = peer_id_from_multiaddr(ma) {
                void_bootstraps.push(ma.clone());
                swarm.behaviour_mut().kad.add_address(&pid, ma.clone());
                added += 1;
            }
        }
    }
    if added > 0 {
        void_bootstraps.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        void_bootstraps.dedup_by(|a, b| a == b);
        *bootstrap_peer_ids = bootstrap_peer_ids_from(void_bootstraps);
        let mut grouped: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        for ma in new_addrs {
            if let Some(pid) = peer_id_from_multiaddr(ma) {
                grouped.entry(pid).or_default().push(ma.clone());
            }
        }
        for (pid, addrs) in grouped {
            dial_peer_best_effort(swarm, pid, addrs, void_bootstraps);
        }
        let _ = swarm.behaviour_mut().kad.bootstrap();
    }
    added
}

fn bootstrap_gossip_strings(void_bootstraps: &[Multiaddr]) -> Vec<String> {
    void_bootstraps.iter().map(|a| a.to_string()).collect()
}

/// Эпидемический обмен bootstrap-нодами: рассылаем список всем подключённым VOID-клиентам.
fn fanout_bootstrap_gossip(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    bootstrap_peer_ids: &HashSet<PeerId>,
    addrs: Vec<String>,
    exclude: Option<PeerId>,
) {
    if addrs.is_empty() {
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
    direct.sort_by_key(|a| if is_likely_lan_addr(a) { 0u8 } else { 1u8 });

    let mut circuits: Vec<Multiaddr> = Vec::new();
    for relay_ma in bootstrap_addrs {
        if peer_id_from_multiaddr(relay_ma) == Some(peer_id) {
            continue;
        }
        for circuit in relay_circuit_dial_addrs(std::slice::from_ref(relay_ma), peer_id) {
            if !circuits.contains(&circuit) {
                circuits.push(circuit);
            }
        }
    }
    // Circuit FIRST — a stuck dial to a dead NAT addr never reaches relay, and
    // PeerCondition::NotDialing then blocks a second dial that would use circuit.
    let mut expanded = circuits;
    for d in direct {
        if !expanded.contains(&d) {
            expanded.push(d);
        }
    }
    expanded
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
    for ma in bootstrap_addrs {
        if peer_id_from_multiaddr(ma).is_some_and(|p| swarm.is_connected(&p)) {
            live_boot.push(ma.clone());
        } else {
            cold_boot.push(ma.clone());
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
    live_boot.extend(cold_boot);
    let boot = live_boot;
    let clean = if circuits_only {
        let mut circuits = Vec::new();
        for relay_ma in &boot {
            for circuit in relay_circuit_dial_addrs(std::slice::from_ref(relay_ma), peer_id) {
                if !circuits.contains(&circuit) {
                    circuits.push(circuit);
                }
            }
        }
        circuits
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
        if boot_live {
            // Не Always: каждый лишний circuit открывает HOP-стрим на
            // bootstrap (лимит 10/соединение) и душит живой чат.
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

/// listen_on(/p2p-circuit) for each live bootstrap that has no confirmed Hop yet.
/// `relay_circuit_reserved` = ReservationReqAccepted only (not listen_on Ok).
fn ensure_bootstrap_relay_listens(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    reconnect_targets: &HashMap<PeerId, Vec<Multiaddr>>,
    relay_circuit_reserved: &HashSet<PeerId>,
    relay_listen_attempt_at: &mut HashMap<PeerId, Instant>,
    relay_hop_pending: &mut HashSet<PeerId>,
    min_retry: Duration,
    event_tx: Option<&mpsc::Sender<NetworkEvent>>,
) {
    let now = Instant::now();
    for &relay_pid in bootstrap_peer_ids {
        if !swarm.is_connected(&relay_pid) || relay_circuit_reserved.contains(&relay_pid) {
            relay_hop_pending.remove(&relay_pid);
            continue;
        }
        // Один pending listen_on на relay: повторные Reserve забивают
        // MAX_CONCURRENT_STREAMS(10) → Dropping inbound stream / нет Hop.
        if relay_hop_pending.contains(&relay_pid) {
            if relay_listen_attempt_at
                .get(&relay_pid)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(45))
            {
                continue;
            }
            relay_hop_pending.remove(&relay_pid);
        }
        if relay_listen_attempt_at
            .get(&relay_pid)
            .is_some_and(|t| now.duration_since(*t) < min_retry)
        {
            continue;
        }
        relay_listen_attempt_at.insert(relay_pid, now);
        // Всегда берём void_bootstraps + живые dialer-адреса.
        let mut relay_src: Vec<Multiaddr> = void_bootstraps
            .iter()
            .filter(|ma| peer_id_from_multiaddr(ma) == Some(relay_pid))
            .cloned()
            .collect();
        if let Some(extra) = reconnect_targets.get(&relay_pid) {
            for a in extra {
                if peer_id_from_multiaddr(a).is_none() {
                    continue;
                }
                if a.to_string().contains("p2p-circuit") || is_junk_addr(a) {
                    continue;
                }
                if !relay_src.contains(a) {
                    relay_src.insert(0, a.clone());
                }
            }
        }
        if relay_src.is_empty() {
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
        }
        let mut any_ok = false;
        for ma in relay_circuit_listen_addrs(&relay_src) {
            match swarm.listen_on(ma.clone()) {
                Ok(_) => {
                    any_ok = true;
                    debug!("📡 relay circuit listen (pending Hop Ack): {}", ma);
                }
                Err(e) => {
                    debug!("relay circuit listen retry {}: {:?}", ma, e);
                }
            }
        }
        if any_ok {
            relay_hop_pending.insert(relay_pid);
            if let Some(tx) = event_tx {
                let _ = tx.try_send(NetworkEvent::Status(format!(
                    "📡 Запрос Hop на {}…",
                    &relay_pid.to_string()[..8.min(relay_pid.to_string().len())]
                )));
            }
        } else if let Some(tx) = event_tx {
            let _ = tx.try_send(NetworkEvent::Status(format!(
                "⚠ Hop listen не стартовал на {} — проверьте bootstrap multiaddr (/ip4/…/p2p/…)",
                &relay_pid.to_string()[..8.min(relay_pid.to_string().len())]
            )));
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
                libp2p::swarm::dial_opts::PeerCondition::Always,
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
    /// Hop ReservationReqAccepted — мы реально reachable через VOID relay.
    RelayHopReady { relay: PeerId },
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
                dial_peer_best_effort(swarm, *pid, addrs, void_bootstraps);
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

/// Dial any configured bootstrap that is not yet connected (for store or fetch).
fn dial_missing_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
) {
    for pid in bootstrap_peer_ids {
        if swarm.is_connected(pid) {
            continue;
        }
        let addrs: Vec<Multiaddr> = void_bootstraps
            .iter()
            .filter(|ma| peer_id_from_multiaddr(ma) == Some(*pid))
            .cloned()
            .collect();
        if !addrs.is_empty() {
            dial_peer_best_effort(swarm, *pid, addrs, void_bootstraps);
        }
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
) {
    let packet = V1Packet::OfflineMailboxQuery {
        recipient: local_peer_id.to_string(),
    };
    let peers: Vec<PeerId> = if !bootstrap_peer_ids.is_empty() {
        swarm
            .connected_peers()
            .copied()
            .filter(|p| bootstrap_peer_ids.contains(p))
            .collect()
    } else {
        swarm
            .connected_peers()
            .copied()
            .filter(|p| *p != local_peer_id)
            .collect()
    };
    for peer in peers {
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, packet.clone());
    }
}

fn query_relay_mailbox_with_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
) {
    dial_missing_bootstraps(swarm, bootstrap_peer_ids, void_bootstraps);
    query_relay_mailbox(swarm, local_peer_id, bootstrap_peer_ids);
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
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    upnp: upnp::tokio::Behaviour,
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
        .with_quic()
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

            let kad_store = kad::store::MemoryStore::new(local_peer_id);
            let mut kad_config = kad::Config::new(StreamProtocol::new("/void/kad/1.0.0"));
            kad_config.set_periodic_bootstrap_interval(Some(Duration::from_secs(2 * 60)));
            kad_config.set_query_timeout(Duration::from_secs(15));
            let mut kad = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
            kad.set_mode(Some(libp2p::kad::Mode::Server));

            let mut kad_by_peer: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
            for ma in void_bootstraps {
                if let Some(pid) = peer_id_from_multiaddr(ma) {
                    kad_by_peer.entry(pid).or_default().push(ma.clone());
                } else {
                    warn!("VOID bootstrap: нет /p2p/ в конце адреса, пропуск: {}", ma);
                }
            }
            for (pid, addrs) in kad_by_peer {
                for ma in prefer_tcp_if_available(addrs) {
                    kad.add_address(&pid, ma);
                }
            }
            for (pid, ma) in contact_seed_addrs {
                kad.add_address(pid, ma.clone());
            }
            // Не вызываем kad.bootstrap() здесь: параллельный dial с
            // dial_missing_bootstraps даёт два QUIC к одной ноде — оба
            // сразу закрываются ApplicationClosed. Периодический bootstrap
            // Kademlia остаётся (интервал ниже).

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
                dcutr: dcutr::Behaviour::new(local_peer_id),
                autonat: autonat::Behaviour::new(local_peer_id, Default::default()),
                upnp: upnp::tokio::Behaviour::default(),
            })
        })
        .map_err(|e| format!("with_behaviour: {:?}", e))?
        .with_swarm_config(|c| {
            // Bound idle so half-open / zombie peers (Mac shows online, Windows not)
            // get dropped; ping (20s/40s) should close sooner on real failures.
            c.with_idle_connection_timeout(Duration::from_secs(120))
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
            return swarm
                .behaviour_mut()
                .request_response
                .send_request(&first, onion);
        }
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
    swarm
        .behaviour_mut()
        .file_rr
        .send_request(&recipient, offer);
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
                swarm
                    .behaviour_mut()
                    .file_rr
                    .send_request(&recipient, offer);

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
            swarm
                .behaviour_mut()
                .file_rr
                .send_request(&recipient, offer);
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
        let mut peer_prekeys: HashMap<PeerId, [u8; 32]> = HashMap::new();
        let mut pending_kad_mail: HashMap<kad::QueryId, MailboxKadOp> = HashMap::new();
        let mut relay_mail_store = RelayMailbox::load();
        let mut fetch_mailbox_after = Some(Instant::now() + Duration::from_secs(5));
        let mut mailbox_fetch_attempts: u32 = 0;
        const MAX_MAILBOX_FETCH_ATTEMPTS: u32 = 30;

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
            debug!("⚠️ TCP порт 50001 занят ({:?}). Срочно ЗАКРОЙТЕ старые процессы или проверьте настройки.", e);
            let _ = event_tx
                .send(NetworkEvent::Status(
                    "⚠️ ПОРТ 50001 ЗАНЯТ! Закройте старые копии программы.".into(),
                ))
                .await;
            match "/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>() {
                Ok(fallback) => {
                    if let Err(e2) = swarm.listen_on(fallback) {
                        warn!("❌ TCP fallback 0: {:?}", e2);
                        let _ = event_tx
                            .send(NetworkEvent::Status(format!(
                                "❌ Не удалось слушать TCP даже на свободном порту: {:?}",
                                e2
                            )))
                            .await;
                        return;
                    }
                }
                Err(_) => {
                    let _ = event_tx
                        .send(NetworkEvent::Status(
                            "❌ Внутренняя ошибка: некорректный fallback TCP multiaddr.".into(),
                        ))
                        .await;
                    return;
                }
            }
        }

        // Слушаем QUIC (50001 часто занят другим процессом на Windows — пробуем 50002, затем ОС).
        let quic_candidates = [
            "/ip4/0.0.0.0/udp/50001/quic-v1",
            "/ip4/0.0.0.0/udp/50002/quic-v1",
            "/ip4/0.0.0.0/udp/0/quic-v1",
        ];
        let mut quic_listening = false;
        for addr in quic_candidates {
            match addr.parse::<Multiaddr>() {
                Ok(ma) => match swarm.listen_on(ma) {
                    Ok(_) => {
                        debug!("🚀 QUIC: {}", addr);
                        quic_listening = true;
                        break;
                    }
                    Err(e) => debug!("⚠️ QUIC {}: {:?} — следующий вариант...", addr, e),
                },
                Err(e) => debug!("⚠️ QUIC parse {}: {:?}", addr, e),
            }
        }
        if !quic_listening {
            debug!("⚠️ QUIC не поднят ни на одном порту");
        }

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

        // Сразу пробуем дозвониться до сохранённых контактов: если они онлайн и
        // их адрес не сменился — связь появится в первые же секунды без
        // ручного «ПОДКЛЮЧИТЬ».
        //
        // ВАЖНО: все адреса одного пира собираем в ОДИН DialOpts, иначе второй
        // и третий вызовы отклоняются условием DisconnectedAndNotDialing (пир уже
        // "Dialing"), и при устаревшем первом адресе подключение молча падает —
        // libp2p не пробует следующий адрес из другого DialOpts.
        {
            let mut grouped: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
            for (pid, ma) in &contact_seed_addrs {
                grouped.entry(*pid).or_default().push(ma.clone());
            }
            for (pid, addrs) in &grouped {
                debug!(
                    "📇 Стартовый dial контакта {} ({} адр.)",
                    &pid.to_string()[..8],
                    addrs.len()
                );
                dial_peer_best_effort(&mut swarm, *pid, addrs.clone(), &void_bootstraps);
            }
        }

        // Bootstrap-узлы: явный dial + регистрация в DHT. Без прямого dial
        // kad.bootstrap() часто не наполняет таблицу достаточно быстро.
        {
            let mut grouped: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
            for ma in &void_bootstraps {
                if let Some(pid) = peer_id_from_multiaddr(ma) {
                    grouped.entry(pid).or_default().push(ma.clone());
                }
            }
            for (pid, addrs) in grouped {
                debug!(
                    "🌐 Стартовый dial bootstrap {} ({} адр.)",
                    &pid.to_string()[..8],
                    addrs.len()
                );
                dial_peer_best_effort(&mut swarm, pid, addrs, &void_bootstraps);
            }
        }

        publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
        publish_self_prekey(&mut swarm, local_peer_id, &my_public_key_bytes);
        // kad.bootstrap() только после ConnectionEstablished: иначе второй
        // параллельный dial (часто QUIC) закрывает только что поднятый TCP.

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
        // Отложенный Hop: даём relay behaviour зарегистрировать direct conn.
        let mut hop_listen_after: HashMap<PeerId, Instant> = HashMap::new();
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
            // Bootstrap-ноды: их адреса известны заранее из конфига/файла,
            // поэтому добавляем сразу — реконнект к ним будет автоматическим
            // при обрыве соединения (NAT-timeout, перезагрузка ноды и т.п.).
            for ma in &void_bootstraps {
                if let Some(pid) = peer_id_from_multiaddr(ma) {
                    m.entry(pid).or_default().push(ma.clone());
                }
            }
            m
        };
        let mut reconnect_queue: HashMap<PeerId, (Instant, u32)> = HashMap::new();
        let mut reconnect_tick = tokio::time::interval(Duration::from_secs(5));
        reconnect_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut provider_tick = tokio::time::interval(Duration::from_secs(10 * 60));
        provider_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut gossip_tick = tokio::time::interval(Duration::from_secs(2 * 60));
        gossip_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut mailbox_tick = tokio::time::interval(Duration::from_secs(2));
        mailbox_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = mailbox_tick.tick() => {
                    if let Some(deadline) = fetch_mailbox_after {
                        if Instant::now() >= deadline {
                            mailbox_fetch_attempts = mailbox_fetch_attempts.saturating_add(1);
                            // Почта только с bootstrap-нод (RR), без DHT-ящика.
                            query_relay_mailbox_with_bootstraps(
                                &mut swarm,
                                local_peer_id,
                                &bootstrap_peer_ids,
                                &void_bootstraps,
                            );
                            // Частый poll: без живого circuit доставка только через
                            // ящик; 10–30 с выглядели как «сообщения идут очень долго».
                            let gap = if mailbox_fetch_attempts < MAX_MAILBOX_FETCH_ATTEMPTS {
                                Duration::from_secs(2)
                            } else {
                                Duration::from_secs(5)
                            };
                            fetch_mailbox_after = Some(Instant::now() + gap);
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
                    // Hop reservation: retry listen until ReservationReqAccepted.
                    // Hop reservation: отложенные + редкий retry (не чаще 30 с).
                    {
                        let now_h = Instant::now();
                        let due: Vec<PeerId> = hop_listen_after
                            .iter()
                            .filter(|(_, t)| now_h >= **t)
                            .map(|(p, _)| *p)
                            .collect();
                        for p in &due {
                            hop_listen_after.remove(p);
                        }
                        let need_hop = bootstrap_peer_ids.iter().any(|b| {
                            swarm.is_connected(b) && !relay_circuit_reserved.contains(b)
                        });
                        if !due.is_empty() || need_hop {
                            ensure_bootstrap_relay_listens(
                                &mut swarm,
                                &bootstrap_peer_ids,
                                &void_bootstraps,
                                &reconnect_targets,
                                &relay_circuit_reserved,
                                &mut relay_listen_attempt_at,
                                &mut relay_hop_pending,
                                Duration::from_secs(30),
                                Some(&event_tx),
                            );
                        }
                    }
                    // Пока хоть один bootstrap жив — набираем контакты через VOID circuit
                    // (LAN не требуется: путь relay/p2p-circuit/p2p/<peer>).
                    dial_unconnected_contacts(
                        &mut swarm,
                        &reconnect_targets,
                        &bootstrap_peer_ids,
                        &void_bootstraps,
                        &mut contact_dial_at,
                        Duration::from_secs(15),
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
                            dial_peer_best_effort(
                                &mut swarm,
                                pid,
                                addrs,
                                &void_bootstraps,
                            );
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
                                dial_unconnected_contacts(
                                    &mut swarm,
                                    &reconnect_targets,
                                    &bootstrap_peer_ids,
                                    &void_bootstraps,
                                    &mut contact_dial_at,
                                    Duration::from_secs(2),
                                );
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
                                            for ma in &addrs {
                                                swarm.behaviour_mut().kad.add_address(&pid, ma.clone());
                                            }
                                            pending_seed_peers.insert(pid);
                                            dial_peer_best_effort(
                                                &mut swarm,
                                                pid,
                                                addrs.clone(),
                                                &void_bootstraps,
                                            );
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "📞 Вход в сеть: дозваниваюсь до {} ({} адр.)…",
                                                    pid,
                                                    addrs.len()
                                                )))
                                                .await;
                                        } else {
                                            pending_seed_bare = true;
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(
                                                    "⚠ Вход без /p2p/<PeerId>: пробуем QUIC+TCP; \
                                                     для bootstrap лучше полный multiaddr."
                                                        .into(),
                                                ))
                                                .await;
                                            let mut any_ok = false;
                                            for ma in addrs {
                                                match swarm.dial(ma.clone()) {
                                                    Ok(_) => {
                                                        any_ok = true;
                                                        let _ = event_tx
                                                            .send(NetworkEvent::Status(format!(
                                                                "📞 Вход в сеть: дозваниваюсь до {}…",
                                                                ma
                                                            )))
                                                            .await;
                                                    }
                                                    Err(e) => {
                                                        debug!("JoinViaNode dial {}: {:?}", ma, e);
                                                    }
                                                }
                                            }
                                            if !any_ok {
                                                let _ = event_tx
                                                    .send(NetworkEvent::Status(format!(
                                                        "❌ Не дозвониться до {}",
                                                        input
                                                    )))
                                                    .await;
                                            }
                                        }
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
                                swarm.behaviour_mut().file_rr.send_request(&from, packet);
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
                                swarm.behaviour_mut().file_rr.send_request(&from, packet);
                                incoming_transfers.remove(&transfer_id);
                                debug!(
                                    "✖ FILE: Reject transfer {:x?} ({})",
                                    &transfer_id[..4],
                                    reason
                                );
                            }
                            UICommand::RequestFile { peer, transfer_id } => {
                                swarm.behaviour_mut().file_rr.send_request(
                                    &peer,
                                    file_transfer::FilePacket::Request { transfer_id },
                                );
                            }
                            UICommand::CachePeerPrekeys(keys) => {
                                for (peer, pk) in keys {
                                    peer_prekeys.insert(peer, pk);
                                }
                            }
                            UICommand::FetchOfflineMailbox => {
                                // Только bootstrap-ноды — без DHT-ящика.
                                query_relay_mailbox_with_bootstraps(
                                    &mut swarm,
                                    local_peer_id,
                                    &bootstrap_peer_ids,
                                    &void_bootstraps,
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
                                publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
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
                                if let Some(relay) = relay_peer_id_from_circuit_addr(&address) {
                                    if relay_circuit_reserved.insert(relay) {
                                        relay_hop_pending.remove(&relay);
                                        hop_listen_after.remove(&relay);
                                        let _ = event_tx
                                            .send(NetworkEvent::RelayHopReady { relay })
                                            .await;
                                    }
                                }
                            }
                        },

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
                                                onion_reply = Some(src_pid);
                                                peer = src_pid;
                                                request = *packet;
                                            }
                                        }
                                        }
                                    }
                                    match request {
                                        V1Packet::BootstrapGossip { addrs } => {
                                            let their_set: HashSet<&str> =
                                                addrs.iter().map(|s| s.as_str()).collect();
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
                                            if !our_extra.is_empty() {
                                                let _ = swarm
                                                    .behaviour_mut()
                                                    .request_response
                                                    .send_request(
                                                        &peer,
                                                        V1Packet::BootstrapGossip {
                                                            addrs: our_extra,
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
                                                        if let Some((tid, idx, pdata)) =
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
                                                // take_batch отдаёт порциями — сразу
                                                // запрашиваем остаток ящика.
                                                query_relay_mailbox(
                                                    &mut swarm,
                                                    local_peer_id,
                                                    &bootstrap_peer_ids,
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
                                                        &mut outgoing_transfers,
                                                        &relay_peers,
                                                        &event_tx,
                                                        peer,
                                                        &mut pending_voice_transfers,
                                                    )
                                                    .await;
                                                    flush_pending_named_files(
                                                        &mut swarm,
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
                                                    if let Some((tid, idx, pdata)) =
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
                            publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
                            let _ = swarm.behaviour_mut().kad.bootstrap();
                            if let Some(relay) = relay_peer_id_from_circuit_addr(&address) {
                                // Дубль сигнала Hop (на случай если Event::ReservationReqAccepted
                                // не дошёл до match из-за версии).
                                if relay_circuit_reserved.insert(relay) {
                                    relay_hop_pending.remove(&relay);
                                    hop_listen_after.remove(&relay);
                                    let _ = event_tx
                                        .send(NetworkEvent::RelayHopReady { relay })
                                        .await;
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(
                                            "СВЯЗЬ ЧЕРЕЗ RELAY — Hop OK".into(),
                                        ))
                                        .await;
                                }
                            } else {
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
                                let _ = event_tx.send(NetworkEvent::PublicIpConfirmed(ip)).await;
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, ref endpoint, num_established, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            debug!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. Всего пиров: {} (conn #{})", peer_id, endpoint, connected_count, num_established);
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

                            // Живой dialer-адрес bootstrap нужен для Hop listen
                            // (публичный IP раньше отбрасывался → пустой relay_src).
                            if bootstrap_peer_ids.contains(&peer_id) {
                                if u32::from(num_established) <= 1 {
                                    let _ = swarm.behaviour_mut().kad.bootstrap();
                                }
                                if let libp2p::core::ConnectedPoint::Dialer { address, .. } =
                                    endpoint
                                {
                                    if !is_junk_addr(address)
                                        && !address.to_string().contains("p2p-circuit")
                                    {
                                        let list =
                                            reconnect_targets.entry(peer_id).or_default();
                                        if !list.contains(address) {
                                            list.insert(0, address.clone());
                                        }
                                    }
                                }
                                // Не сразу: relay behaviour должен успеть
                                // зарегистрировать direct connection, иначе
                                // ListenReq делает лишний Dial → шторм соединений.
                                hop_listen_after
                                    .entry(peer_id)
                                    .or_insert_with(|| Instant::now() + Duration::from_millis(800));
                            }

                            if u32::from(num_established) > 1 {
                                // Доп. TCP/QUIC к тому же пиру — не шлём второй Hello
                                // и не дёргаем mailbox заново.
                                continue;
                            }
                            publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);

                             if peer_id != local_peer_id {
                                 if bootstrap_peer_ids.contains(&peer_id) {
                                     dial_unconnected_contacts(
                                         &mut swarm,
                                         &reconnect_targets,
                                         &bootstrap_peer_ids,
                                         &void_bootstraps,
                                         &mut contact_dial_at,
                                         Duration::from_secs(5),
                                     );
                                 }
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
                                 // Запрашиваем офлайн-почту у всех пиров (включая bootstrap-relay).
                                 query_relay_mailbox(
                                     &mut swarm,
                                     local_peer_id,
                                     &bootstrap_peer_ids,
                                 );
                                 if bootstrap_peer_ids.contains(&peer_id) {
                                     publish_self_prekey_to_bootstraps(
                                         &mut swarm,
                                         local_peer_id,
                                         &my_public_key_bytes,
                                         &bootstrap_peer_ids,
                                     );
                                     let _ = event_tx
                                         .send(NetworkEvent::Status(
                                             "📬 Запрос офлайн-почты у bootstrap-ноды".into(),
                                         ))
                                         .await;
                                 }
                                 // Сразу делимся bootstrap-нодами с любым подключённым VOID-клиентом.
                                 if !bootstrap_peer_ids.contains(&peer_id) {
                                     let gossip = bootstrap_gossip_strings(&void_bootstraps);
                                     if !gossip.is_empty() {
                                         let _ = swarm.behaviour_mut().request_response.send_request(
                                             &peer_id,
                                             V1Packet::BootstrapGossip { addrs: gossip },
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

                            // Если мы звонили этому пиру как seed (вход в сеть через IP) — страховка:
                            // добавляем dialed-адрес в Kademlia и запускаем DHT-bootstrap сразу после коннекта,
                            // не дожидаясь Identify. На bootstrap без Identify Identify::Received никогда не придёт,
                            // а DHT хотя бы попробует найти маршруты через этого пира.
                            let is_seed = pending_seed_peers.contains(&peer_id) || pending_seed_bare;
                            if is_seed {
                                let addr = match endpoint {
                                    libp2p::core::ConnectedPoint::Dialer { ref address, .. } => Some(address.clone()),
                                    _ => None,
                                };
                                if let Some(mut addr) = addr {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                    if peer_id_from_multiaddr(&addr).is_none() {
                                        addr.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                                    }
                                    let added = merge_bootstraps_into_swarm(
                                        &mut swarm,
                                        &mut void_bootstraps,
                                        &mut bootstrap_peer_ids,
                                        &[addr.clone()],
                                    );
                                    if added > 0 {
                                        let learned = vec![addr.to_string()];
                                        fanout_bootstrap_gossip(
                                            &mut swarm,
                                            local_peer_id,
                                            &bootstrap_peer_ids,
                                            learned.clone(),
                                            None,
                                        );
                                        let _ = event_tx
                                            .send(NetworkEvent::BootstrapsLearned(learned))
                                            .await;
                                    }
                                }
                                pending_seed_bare = false;
                                pending_seed_peers.remove(&peer_id);
                                let _ = swarm.behaviour_mut().kad.bootstrap();
                                let _ = event_tx
                                    .send(NetworkEvent::Status(format!(
                                        "🌐 Seed подхвачен ({}): DHT-bootstrap запущен.",
                                        &peer_id.to_string()[..12]
                                    )))
                                    .await;
                            }
                        },
                        SwarmEvent::ConnectionClosed { peer_id, cause, num_established, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            debug!("❌ СОЕДИНЕНИЕ ЗАКРЫТО: {}. Причина: {:?}. Осталось: {} (с пиром ещё {})", peer_id, cause, connected_count, num_established);

                            // libp2p may close a duplicate connection while another remains.
                            if num_established > 0 || swarm.is_connected(&peer_id) {
                                continue;
                            }

                            relay_peers.remove(&peer_id);
                            relay_circuit_reserved.remove(&peer_id);
                            relay_listen_attempt_at.remove(&peer_id);
                            relay_hop_pending.remove(&peer_id);
                            hop_listen_after.remove(&peer_id);
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
                            if reconnect_targets.contains_key(&peer_id) {
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
                        }
                        SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                            debug!("📥 Входящее соединение: from {:?} to {:?}", send_back_addr, local_addr);
                        },

                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
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
                                // Bootstrap failover: dial next vault bootstrap quietly (no UI spam).
                                if bootstrap_peer_ids.contains(&p) {
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
                                                dial_peer_best_effort(
                                                    &mut swarm,
                                                    next_pid,
                                                    vec![ma.clone()],
                                                    &void_bootstraps,
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
                            let is_bootstrap = bootstrap_peer_ids.contains(&peer_id)
                                || peer_is_bootstrap_agent(&info);
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
                            let identify_has_tcp = is_bootstrap
                                && info.listen_addrs.iter().any(|a| {
                                    a.iter().any(|p| {
                                        matches!(p, libp2p::multiaddr::Protocol::Tcp(_))
                                    })
                                });
                            for addr in info.listen_addrs {
                                if is_junk_addr(&addr) {
                                    continue;
                                }
                                if is_bootstrap && identify_has_tcp && addr_is_quic_v1(&addr) {
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
                                swarm.behaviour_mut().kad.add_address(&peer_id, a.clone());

                                if peer_id != local_peer_id {
                                    let list = reconnect_targets.entry(peer_id).or_default();
                                    if !is_bootstrap {
                                        list.retain(is_usable_contact_redial_addr);
                                    }
                                    if !list.contains(&a) {
                                        list.push(a.clone());
                                    }
                                }

                                if is_bootstrap && peer_id != local_peer_id {
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
                                let _ = swarm.behaviour_mut().kad.bootstrap();
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
                            debug!(
                                "📡 Relay: Hop Ack на {} (renewal={renewal})",
                                &relay_peer_id.to_string()[..8]
                            );
                            relay_circuit_reserved.insert(relay_peer_id);
                            relay_hop_pending.remove(&relay_peer_id);
                            hop_listen_after.remove(&relay_peer_id);
                            let _ = event_tx
                                .send(NetworkEvent::RelayHopReady {
                                    relay: relay_peer_id,
                                })
                                .await;
                            publish_self_in_dht(
                                &mut swarm.behaviour_mut().kad,
                                local_peer_id,
                            );
                            // Мы только что стали достижимы через VOID relay —
                            // чужие клиенты (другая сеть/NAT) могут дозвониться к нам;
                            // сами тоже сразу набираем контакты по всем bootstrap.
                            if !renewal {
                                let _ = event_tx
                                    .send(NetworkEvent::Status(
                                        "СВЯЗЬ ЧЕРЕЗ RELAY — можно принимать звонки из VOID".into(),
                                    ))
                                    .await;
                            }
                            dial_unconnected_contacts(
                                &mut swarm,
                                &reconnect_targets,
                                &bootstrap_peer_ids,
                                &void_bootstraps,
                                &mut contact_dial_at,
                                Duration::from_secs(2),
                            );
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Relay(
                            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. },
                        )) => {
                            debug!(
                                "📡 Relay: входящий circuit от {}",
                                &src_peer_id.to_string()[..8]
                            );
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Relay(
                            relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. },
                        )) => {
                            debug!(
                                "📡 Relay: исходящий circuit через {}",
                                &relay_peer_id.to_string()[..8]
                            );
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
                                        if *streak >= 3 {
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
                            // Полный список адресов быстро раздувает лог (IPFS-пиры часто обновляют DHT).
                            debug!(
                                "📍 Kademlia: маршрут для {} — {} адр.",
                                peer,
                                addresses.len()
                            );
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
                                            swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_request(&peer, accept);

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
