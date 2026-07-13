//! libp2p swarm, сетевой цикл и события UI ↔ сеть.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc as std_mpsc, Arc};
use std::sync::atomic::{AtomicU32, Ordering};
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

use crate::bootstrap::{parse_seed_input, peer_id_from_multiaddr, void_bootstrap_multiaddrs};
use crate::app::SharedChatMessages;
use crate::crypto;
use crate::file_transfer;
use crate::offline_mail::{
    decode_mailbox, encode_mailbox, mailbox_record_key, prekey_record_key, seal_for_recipient,
    OfflineEnvelope, MAILBOX_TTL_SECS,
};
use crate::relay_mailbox::RelayMailbox;
use crate::protocol::{
    build_delete_ack_json, build_v1_hello,
    chat_message_id_from_json,     delete_command_message_ids, is_delete_command_json,
    is_read_command_json, new_message_id, parse_decrypted_chat_frame,
    read_command_message_ids, verify_hello_transport_binding, validate_bootstrap_gossip_addrs,
    build_group_sync_json, build_group_leave_json, build_group_delete_json,
    transfer_id_to_hex, per_peer_voice_transfer_id, ChatMessage,
    DecryptedChatFrame, OutgoingDeliveryStatus, VoiceMeta, V1Packet,
};

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
    let mut expanded: Vec<Multiaddr> = addrs
        .into_iter()
        .filter(|a| !is_junk_addr(a))
        .collect();
    for relay_ma in bootstrap_addrs {
        for circuit in relay_circuit_dial_addrs(std::slice::from_ref(relay_ma), peer_id) {
            if !expanded.contains(&circuit) {
                expanded.push(circuit);
            }
        }
    }
    expanded
}

fn dial_peer_best_effort(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    bootstrap_addrs: &[Multiaddr],
) {
    let clean = expand_dial_addrs(peer_id, addrs, bootstrap_addrs);
    let opts = if clean.is_empty() {
        DialOpts::peer_id(peer_id)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .build()
    } else {
        DialOpts::peer_id(peer_id)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .addresses(clean)
            .build()
    };
    if let Err(e) = swarm.dial(opts) {
        let s = format!("{:?}", e);
        if !s.contains("Condition") {
            debug!("dial {}: {:?}", &peer_id.to_string()[..8.min(peer_id.to_string().len())], e);
        }
    }
}
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
}

/// Одна машина состояний для приёма чанков (E2EE `/void/chat` и устаревший plain `Chunk` по `/void/file`).
async fn apply_incoming_file_chunk(
    transfer_id: [u8; 16],
    chunk_index: u32,
    data: Vec<u8>,
    peer: PeerId,
    now: &str,
    incoming_transfers: &mut HashMap<[u8; 16], file_transfer::IncomingTransfer>,
    event_tx: &mpsc::Sender<NetworkEvent>,
) {
    let done = if let Some(inc) = incoming_transfers.get_mut(&transfer_id) {
        inc.receive_chunk(chunk_index, data)
    } else {
        false
    };

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
                    let _ = event_tx
                        .send(NetworkEvent::FileError {
                            transfer_id,
                            reason: format!("Ошибка целостности файла «{}»", fname),
                        })
                        .await;
                } else {
                    let save_path = if let Some(ref dir) = incoming_transfers
                        .get(&transfer_id)
                        .and_then(|t| t.save_dir.clone())
                    {
                        file_transfer::unique_download_path_in(dir, &fname)
                    } else if file_transfer::is_voice_filename(&fname) {
                        file_transfer::unique_download_path_in_path(
                            &file_transfer::voice_dir_absolute(),
                            &fname,
                        )
                    } else {
                        file_transfer::unique_download_path(&fname)
                    };
                    let saved_to = save_path.display().to_string();
                    match std::fs::write(&save_path, &data) {
                        Ok(_) => {
                            debug!(
                                "[{}] ✅ FILE: «{}» сохранён → {}",
                                now, fname, saved_to
                            );
                            if file_transfer::is_voice_filename(&fname) {
                                crate::voice::voice_log(&format!(
                                    "received {} -> {}",
                                    fname, saved_to
                                ));
                            }
                            let _ = event_tx
                                .send(NetworkEvent::FileComplete {
                                    transfer_id,
                                    filename: fname,
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
}

pub(crate) enum UICommand {
    Dial(String),
    DialPeer(PeerId, Vec<Multiaddr>),
    SearchPeer(PeerId),
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
    /// Пользователь принял входящее предложение файла.
    AcceptFile {
        transfer_id: [u8; 16],
        from: PeerId,
        /// Директория сохранения, выбранная пользователем. `None` → `void_downloads/`.
        save_dir: Option<String>,
    },
    /// Пользователь отклонил входящее предложение файла.
    RejectFile {
        transfer_id: [u8; 16],
        from: PeerId,
        reason: String,
    },
    /// Кэш X25519 prekey контактов (из vault).
    CachePeerPrekeys(Vec<(PeerId, [u8; 32])>),
    /// Опубликовать недоставленное в DHT-почтовые ящики получателей.
    PublishOfflineOutbox {
        items: Vec<OfflineOutboxItem>,
        ack: Option<std_mpsc::Sender<()>>,
    },
    /// Забрать свой почтовый ящик из DHT.
    FetchOfflineMailbox,
    /// Очистить свой почтовый ящик в DHT после успешной обработки.
    ClearOfflineMailbox,
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
    FetchInbox {
        record_bytes: Option<Vec<u8>>,
    },
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
    AwaitPut {
        done: Option<PublishDone>,
    },
}

type PublishDone = Arc<dyn Fn() + Send + Sync>;

fn publish_done_token(tx: std_mpsc::Sender<()>, total: u32) -> PublishDone {
    let left = Arc::new(AtomicU32::new(total));
    Arc::new(move || {
        if left.fetch_sub(1, Ordering::SeqCst) == 1 {
            let _ = tx.send(());
        }
    })
}

fn signal_publish_done(done: &Option<PublishDone>) {
    if let Some(d) = done {
        d();
    }
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
        signal_publish_done(&done);
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
        Err(_) => signal_publish_done(&done),
    }
}

fn fanout_relay_mail(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
) {
    if envelopes.is_empty() {
        return;
    }
    let packet = V1Packet::OfflineMailboxStore {
        recipient: recipient.to_string(),
        envelopes: envelopes.to_vec(),
    };
    for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
        if peer == local_peer_id || peer == recipient {
            continue;
        }
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, packet.clone());
    }
}

/// Разослать офлайн-почту всем bootstrap-нодам (даже если ещё не в connected_peers — dial).
fn fanout_relay_to_bootstraps(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
) {
    if envelopes.is_empty() {
        return;
    }
    let packet = V1Packet::OfflineMailboxStore {
        recipient: recipient.to_string(),
        envelopes: envelopes.to_vec(),
    };
    for pid in bootstrap_peer_ids {
        if *pid == local_peer_id || *pid == recipient {
            continue;
        }
        if swarm.is_connected(pid) {
            let _ = swarm
                .behaviour_mut()
                .request_response
                .send_request(pid, packet.clone());
        } else {
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
}

fn publish_relay_mail(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    bootstrap_peer_ids: &HashSet<PeerId>,
    void_bootstraps: &[Multiaddr],
    local_peer_id: PeerId,
    recipient: PeerId,
    envelopes: &[OfflineEnvelope],
) {
    fanout_relay_mail(swarm, local_peer_id, recipient, envelopes);
    fanout_relay_to_bootstraps(
        swarm,
        bootstrap_peer_ids,
        void_bootstraps,
        local_peer_id,
        recipient,
        envelopes,
    );
}

fn query_relay_mailbox(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_peer_id: PeerId,
) {
    let packet = V1Packet::OfflineMailboxQuery {
        recipient: local_peer_id.to_string(),
    };
    for peer in swarm.connected_peers().copied().collect::<Vec<_>>() {
        if peer == local_peer_id {
            continue;
        }
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, packet.clone());
    }
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

            for ma in void_bootstraps {
                if let Some(pid) = peer_id_from_multiaddr(ma) {
                    kad.add_address(&pid, ma.clone());
                } else {
                    warn!("VOID bootstrap: нет /p2p/ в конце адреса, пропуск: {}", ma);
                }
            }
            for (pid, ma) in contact_seed_addrs {
                kad.add_address(pid, ma.clone());
            }
            if !void_bootstraps.is_empty() {
                let _ = kad.bootstrap();
            }

            let rr_config = libp2p::request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(256);
            let rr_protocol = libp2p::StreamProtocol::new("/void/chat/1.0.0");
            let rr_behaviour = libp2p::request_response::json::Behaviour::<V1Packet, V1Packet>::new(
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
            c.with_idle_connection_timeout(Duration::MAX)
                .with_per_connection_event_buffer_size(256)
        })
        .build())
}

async fn send_encrypted_chat_payload(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outbound_msg_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, String),
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
    let req_id = swarm.behaviour_mut().request_response.send_request(&peer, packet);
    if is_delete_command_json(json_data.as_slice()) || is_read_command_json(json_data.as_slice()) {
        let ids = delete_track_ids
            .map(|v| v.to_vec())
            .or_else(|| delete_command_message_ids(json_data.as_slice()))
            .unwrap_or_default();
        outbound_delete_requests.insert(req_id, (peer, ids));
    } else if let Some(msg_id) = chat_message_id_from_json(json_data.as_slice()) {
        outbound_msg_requests.insert(req_id, (peer, msg_id.clone()));
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

struct PendingVoiceTransfer {
    path: String,
    transfer_id: [u8; 16],
}

async fn flush_pending_encrypted_messages(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outbound_msg_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, String),
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
        let _ = send_encrypted_chat_payload(
            swarm,
            sessions,
            outbound_msg_requests,
            outbound_delete_requests,
            event_tx,
            peer,
            data,
            None,
            now,
        )
        .await;
    }
}

async fn start_voice_file_transfer(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    outgoing_transfers: &mut HashMap<[u8; 16], file_transfer::OutgoingTransfer>,
    relay_peers: &HashSet<PeerId>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    recipient: PeerId,
    path: &str,
    transfer_id: [u8; 16],
    allow_restart: bool,
) {
    if let Some(existing) = outgoing_transfers.get(&transfer_id) {
        let done = existing.next_chunk >= existing.chunks.len();
        if done || !allow_restart {
            return;
        }
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
                    kind: file_kind,
                };
                outgoing_transfers.insert(transfer_id, transfer);

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
            true,
        )
        .await;
    }
}

async fn flush_pending_read_receipts(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    sessions: &mut HashMap<PeerId, crypto::SecureSession>,
    outbound_msg_requests: &mut HashMap<
        libp2p::request_response::OutboundRequestId,
        (PeerId, String),
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
async fn ensure_e2ee_handshake_started(
    swarm: &mut libp2p::Swarm<ChatBehaviour>,
    local_key: &libp2p::identity::Keypair,
    local_peer_id: PeerId,
    my_public_key: crypto::PublicKey,
    peer_id: PeerId,
    sessions: &HashMap<PeerId, crypto::SecureSession>,
    pending_handshakes: &mut HashMap<PeerId, crypto::StaticSecret>,
    now: &str,
    force: bool,
) -> bool {
    if sessions.contains_key(&peer_id) {
        return false;
    }
    if force {
        pending_handshakes.remove(&peer_id);
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
    let _ = swarm
        .behaviour_mut()
        .request_response
        .send_request(&peer_id, hello);
    debug!(
        "[{}] 🤝 E2EE: Hello (+Ephem) → {}{}",
        now,
        &peer_id.to_string()[..8.min(peer_id.to_string().len())],
        if force { " (повтор)" } else { "" }
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
) {
        let mut void_bootstraps = void_bootstraps;
        let mut sessions: HashMap<PeerId, crypto::SecureSession> = HashMap::new();
        let mut pending_handshakes: HashMap<PeerId, crypto::StaticSecret> = HashMap::new();
        let mut pending_messages: HashMap<PeerId, Vec<Vec<u8>>> = HashMap::new();
        let mut pending_voice_transfers: HashMap<PeerId, Vec<PendingVoiceTransfer>> =
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
        if !void_bootstraps.is_empty() {
            let _ = swarm.behaviour_mut().kad.bootstrap();
        }

        let mut peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let mut pending_dials: HashSet<PeerId> = HashSet::new();
        // ─── Файловый sub-протокол ──────────────────────────────────────────
        // Пиры, подключённые через relay (p2p-circuit). К ним применяется rate-limit.
        let mut relay_peers: HashSet<PeerId> = HashSet::new();
        // Исходящие передачи: transfer_id → состояние.
        let mut outgoing_transfers: HashMap<[u8; 16], file_transfer::OutgoingTransfer> =
            HashMap::new();
        // Входящие передачи: transfer_id → состояние.
        let mut incoming_transfers: HashMap<[u8; 16], file_transfer::IncomingTransfer> =
            HashMap::new();
        // Ticker для отправки чанков (с учётом rate-limit на relay).
        let mut chunk_tick = tokio::time::interval(Duration::from_millis(20));
        // RequestId → PeerId для зашифрованных сообщений, чтобы по ответу
        // (Ack/прочее) однозначно подтвердить доставку конкретному пиру и снять
        // pending-ретраи в UI. Hello-handshake'ы сюда НЕ попадают.
        let mut outbound_msg_requests: HashMap<
            libp2p::request_response::OutboundRequestId,
            (PeerId, String),
        > = HashMap::new();
        let mut outbound_delete_requests: HashMap<
            libp2p::request_response::OutboundRequestId,
            (PeerId, Vec<String>),
        > = HashMap::new();
        let mut dial_backoff: HashMap<PeerId, Instant> = HashMap::new();
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
                            query_relay_mailbox(&mut swarm, local_peer_id);
                            let qid = swarm
                                .behaviour_mut()
                                .kad
                                .get_record(mailbox_record_key(local_peer_id));
                            pending_kad_mail.insert(qid, MailboxKadOp::FetchInbox { record_bytes: None });
                            if mailbox_fetch_attempts < MAX_MAILBOX_FETCH_ATTEMPTS {
                                fetch_mailbox_after =
                                    Some(Instant::now() + Duration::from_secs(10));
                            } else {
                                fetch_mailbox_after = None;
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
                        let clean: Vec<Multiaddr> = addrs
                            .into_iter()
                            .filter(|a| !is_junk_addr(a))
                            .collect();
                        if clean.is_empty() {
                            continue;
                        }
                        let attempt = reconnect_queue
                            .get(&pid)
                            .map(|(_, a)| *a)
                            .unwrap_or(1);
                        debug!(
                            "🔄 Автореконнект: {} ({} адр., попытка {}).",
                            &pid.to_string()[..8],
                            clean.len(),
                            attempt
                        );
                        dial_peer_best_effort(&mut swarm, pid, clean, &void_bootstraps);
                    }
                }
                // ─── Tick: переобъявление себя в DHT (каждые 10 мин) ───────
                _ = provider_tick.tick() => {
                    publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
                    publish_self_prekey(&mut swarm, local_peer_id, &my_public_key_bytes);
                }
                // ─── Tick: отправка очередных чанков с rate-limit ───────────
                _ = chunk_tick.tick() => {
                    const VOICE_OFFER_STALE: Duration = Duration::from_secs(25);
                    let stale_voice: Vec<[u8; 16]> = outgoing_transfers
                        .iter()
                        .filter(|(_, t)| {
                            file_transfer::is_voice_filename(&t.filename)
                                && !t.accepted
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

                    // Ищем одну исходящую передачу, готовую к отправке чанка.
                    let to_send: Option<([u8; 16], u32, Vec<u8>, PeerId)> = {
                        let mut found = None;
                        for (tid, t) in outgoing_transfers.iter() {
                            if t.ready_to_send() {
                                let idx = t.next_chunk as u32;
                                let data = t.chunks[t.next_chunk].clone();
                                found = Some((*tid, idx, data, t.peer));
                                break;
                            }
                        }
                        found
                    };
                    if let Some((tid, chunk_idx, data, peer)) = to_send {
                        let frame =
                            file_transfer::encode_e2ee_file_chunk_frame(&tid, chunk_idx, &data);
                        let encrypted_ok = sessions
                            .get_mut(&peer)
                            .and_then(|session| session.encrypt_payload(&frame).ok())
                            .map(|(header, ciphertext)| {
                                let pkt = V1Packet::Encrypted {
                                    header,
                                    ciphertext,
                                };
                                swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_request(&peer, pkt);
                            })
                            .is_some();

                        if encrypted_ok {
                            if let Some(t) = outgoing_transfers.get_mut(&tid) {
                                t.next_chunk += 1;
                                t.last_chunk_at = Instant::now();
                            }
                            if let Some(t) = outgoing_transfers.get(&tid) {
                                let sent = t.next_chunk as u32;
                                let total = t.total_chunks();
                                let fname = t.filename.clone();
                                let sz = t.total_size;
                                let is_relay = t.is_relay;
                                let fkind = t.kind;
                                let all_sent = t.next_chunk >= t.chunks.len();
                                let _ = event_tx
                                    .send(NetworkEvent::FileProgress {
                                        transfer_id: tid,
                                        sent_chunks: sent,
                                        total_chunks: total,
                                        filename: fname.clone(),
                                        total_size: sz,
                                        is_outgoing: true,
                                        peer,
                                        kind: fkind,
                                    })
                                    .await;
                                if all_sent {
                                    debug!(
                                        "📤 FILE[{}]: все {} чанк(ов) «{}» отправлены через E2EE{}.",
                                        fkind.label(),
                                        total,
                                        fname,
                                        if is_relay { " (relay rate-limit)" } else { "" }
                                    );
                                    let _ = event_tx
                                        .send(NetworkEvent::FileComplete {
                                            transfer_id: tid,
                                            filename: fname,
                                            saved_to: String::new(),
                                            is_outgoing: true,
                                            peer,
                                        })
                                        .await;
                                    outgoing_transfers.remove(&tid);
                                }
                            }
                        } else {
                            debug!(
                                "⚠️ FILE: не удалось зашифровать чанк {} для {} (нет E2EE-сессии).",
                                chunk_idx,
                                &peer.to_string()[..8]
                            );
                            let _ = event_tx
                                .send(NetworkEvent::FileError {
                                    transfer_id: tid,
                                    reason:
                                        "Передача файла прервана: нет активной E2EE-сессии с пиром."
                                            .into(),
                                })
                                .await;
                            outgoing_transfers.remove(&tid);
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
                                } else if let Some(addrs) = kad_local_addrs_for_peer(
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
                            UICommand::DialPeer(peer_id, addrs) => {
                                 let short = &peer_id.to_string()[..16];
                                 // Выкидываем loopback и виртуальные интерфейсы — чтобы
                                 // не тратить время на заведомо пустой dial.
                                 let addrs: Vec<Multiaddr> = expand_dial_addrs(
                                     peer_id,
                                     addrs,
                                     &void_bootstraps,
                                 );
                                 debug!("🔌 UI_COMMAND: DialPeer {} ({} addresses)", short, addrs.len());

                                 for addr in &addrs {
                                     swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                     // Сохраняем адрес в таблице реконнекта: пир, до которого
                                     // явно дозванивались, — кандидат на автопереподключение.
                                     let list = reconnect_targets.entry(peer_id).or_default();
                                     if !list.contains(addr) {
                                         list.push(addr.clone());
                                     }
                                 }

                                 if addrs.is_empty() {
                                     let _ = event_tx
                                         .send(NetworkEvent::Status(format!(
                                             "🔍 У {} нет годных адресов — ищу через DHT…",
                                             short
                                         )))
                                         .await;
                                     swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                                     continue;
                                 }

                                  let opts = DialOpts::peer_id(peer_id)
                                     .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                                     .addresses(addrs)
                                     .build();

                                 if let Err(e) = swarm.dial(opts) {
                                      let err_str = format!("{:?}", e);
                                      if !err_str.contains("Condition") {
                                          debug!("❌ Dial ERROR для {}: {:?}", short, e);
                                      }
                                      pending_dials.remove(&peer_id);
                                 }
                             }
                            UICommand::JoinViaNode(input) => {
                                let parsed = parse_seed_input(&input);
                                match parsed {
                                    Some((ma, peer_id_opt)) => {
                                        if let Some(pid) = peer_id_opt {
                                            swarm.behaviour_mut().kad.add_address(&pid, ma.clone());
                                            pending_seed_peers.insert(pid);
                                        } else {
                                            pending_seed_bare = true;
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(
                                                    "⚠ Вход без /p2p/<PeerId>: транспортный PeerId \
                                                     будет известен только после соединения; \
                                                     для bootstrap предпочтительно полный multiaddr."
                                                        .into(),
                                                ))
                                                .await;
                                        }
                                        match swarm.dial(ma.clone()) {
                                            Ok(_) => {
                                                let _ = event_tx
                                                    .send(NetworkEvent::Status(format!(
                                                        "📞 Вход в сеть: дозваниваюсь до {}…",
                                                        ma
                                                    )))
                                                    .await;
                                            }
                                            Err(e) => {
                                                let _ = event_tx
                                                    .send(NetworkEvent::Status(format!(
                                                        "❌ Не дозвониться до {}: {}",
                                                        ma, e
                                                    )))
                                                    .await;
                                            }
                                        }
                                    }
                                    None => {
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(format!(
                                                "⚠ Не понял адрес: {}. Нужен IP, IP:PORT или /ip4/…/tcp/…[/p2p/…]",
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
                                    if sessions.contains_key(&peer_id) {
                                        let msg_id_for_send =
                                            chat_message_id_from_json(json_data.as_slice());
                                        let in_flight = msg_id_for_send.as_ref().is_some_and(|mid| {
                                            outbound_msg_requests
                                                .values()
                                                .any(|(p, id)| *p == peer_id && id == mid)
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
                                    } else {
                                        let force_hs = pending_handshakes.contains_key(&peer_id)
                                            && swarm.is_connected(&peer_id);
                                        let _ = ensure_e2ee_handshake_started(
                                            &mut swarm,
                                            &local_key,
                                            local_peer_id,
                                            my_public_key,
                                            peer_id,
                                            &sessions,
                                            &mut pending_handshakes,
                                            &now,
                                            force_hs,
                                        )
                                        .await;
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
                                    group_id: Some(group_id.clone()),
                                };
                                for peer_id in members {
                                    if peer_id == local_peer_id {
                                        continue;
                                    }
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
                                        let msg_id_for_send =
                                            chat_message_id_from_json(per_json.as_slice());
                                        let in_flight = !is_retry
                                            && msg_id_for_send.as_ref().is_some_and(|mid| {
                                                outbound_msg_requests.values().any(|(p, id)| {
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
                                        if has_voice {
                                            start_voice_file_transfer(
                                                &mut swarm,
                                                &mut outgoing_transfers,
                                                &relay_peers,
                                                &event_tx,
                                                peer_id,
                                                &voice_path,
                                                peer_tid,
                                                is_retry,
                                            )
                                            .await;
                                        }
                                    } else {
                                        let force_hs = pending_handshakes.contains_key(&peer_id)
                                            && swarm.is_connected(&peer_id);
                                        let _ = ensure_e2ee_handshake_started(
                                            &mut swarm,
                                            &local_key,
                                            local_peer_id,
                                            my_public_key,
                                            peer_id,
                                            &sessions,
                                            &mut pending_handshakes,
                                            &now,
                                            force_hs,
                                        )
                                        .await;
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
                                if !is_retry {
                                    let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
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
                                        let force_hs = pending_handshakes.contains_key(&peer_id)
                                            && swarm.is_connected(&peer_id);
                                        let _ = ensure_e2ee_handshake_started(
                                            &mut swarm,
                                            &local_key,
                                            local_peer_id,
                                            my_public_key,
                                            peer_id,
                                            &sessions,
                                            &mut pending_handshakes,
                                            &now,
                                            force_hs,
                                        )
                                        .await;
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
                            UICommand::SendFile { recipient, path, kind } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                if !sessions.contains_key(&recipient) {
                                    let _ = event_tx
                                        .send(NetworkEvent::FileSendDeferred {
                                            recipient,
                                            path,
                                            kind,
                                        })
                                        .await;
                                    continue;
                                }
                                match std::fs::read(&path) {
                                    Err(e) => {
                                        let _ = event_tx
                                            .send(NetworkEvent::Status(format!(
                                                "❌ Не удалось прочитать файл «{}»: {}",
                                                path, e
                                            )))
                                            .await;
                                    }
                                    Ok(data) => {
                                        let filename = file_transfer::safe_filename(&path);
                                        // Уточняем тип по реальному расширению файла
                                        let file_kind = if kind == file_transfer::FileKind::Other {
                                            file_transfer::FileKind::from_filename(&filename)
                                        } else {
                                            kind
                                        };
                                        let data = crate::metadata_strip::strip_metadata_for_send(
                                            &filename,
                                            file_kind,
                                            data,
                                        );
                                        if data.len() as u64 > file_transfer::MAX_FILE_SIZE {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "❌ Файл слишком большой (> {} МБ)",
                                                    file_transfer::MAX_FILE_SIZE / 1024 / 1024
                                                )))
                                                .await;
                                        } else if !sessions.contains_key(&recipient) {
                                            let _ = event_tx
                                                .send(NetworkEvent::FileSendDeferred {
                                                    recipient,
                                                    path,
                                                    kind,
                                                })
                                                .await;
                                        } else {
                                            let sha256 = file_transfer::hash_file(&data);
                                            let chunks = file_transfer::split_into_chunks(&data);
                                            let total_chunks = chunks.len() as u32;
                                            let total_size = data.len() as u64;

                                            let mut tid = [0u8; 16];
                                            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut tid);

                                            let is_relay = relay_peers.contains(&recipient);
                                            let offer = file_transfer::FilePacket::Offer {
                                                transfer_id: tid,
                                                filename: filename.clone(),
                                                total_size,
                                                total_chunks,
                                                sha256,
                                                kind: file_kind,
                                            };
                                            swarm.behaviour_mut().file_rr.send_request(&recipient, offer);

                                            let transfer = file_transfer::OutgoingTransfer {
                                                peer: recipient,
                                                transfer_id: tid,
                                                filename: filename.clone(),
                                                chunks,
                                                next_chunk: 0,
                                                total_size,
                                                is_relay,
                                                last_chunk_at: Instant::now(),
                                                accepted: false,
                                                kind: file_kind,
                                            };
                                            outgoing_transfers.insert(tid, transfer);

                                            debug!(
                                                "[{}] 📤 FILE[{}]: Offer «{}» → {} ({} чанков{})",
                                                now,
                                                file_kind.label(),
                                                filename,
                                                &recipient.to_string()[..8],
                                                total_chunks,
                                                if is_relay { ", relay rate-limit" } else { "" }
                                            );
                                            let _ = event_tx
                                                .send(NetworkEvent::FileProgress {
                                                    transfer_id: tid,
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
                                    let force_hs = pending_handshakes.contains_key(&recipient)
                                        && swarm.is_connected(&recipient);
                                    let _ = ensure_e2ee_handshake_started(
                                        &mut swarm,
                                        &local_key,
                                        local_peer_id,
                                        my_public_key,
                                        recipient,
                                        &sessions,
                                        &mut pending_handshakes,
                                        &now,
                                        force_hs,
                                    )
                                    .await;
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
                                    if !is_retry {
                                        let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                    }
                                    debug!(
                                        "[{}] ⏳ E2EE: голосовое {} буферизовано до хендшейка с {}",
                                        now,
                                        &message_id[..8.min(message_id.len())],
                                        &recipient.to_string()[..8]
                                    );
                                    continue;
                                }

                                if !is_retry {
                                    let msg_id_for_send =
                                        chat_message_id_from_json(json_data.as_slice());
                                    let in_flight = msg_id_for_send.as_ref().is_some_and(|mid| {
                                        outbound_msg_requests
                                            .values()
                                            .any(|(p, id)| *p == recipient && id == mid)
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
                                    let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                }

                                start_voice_file_transfer(
                                    &mut swarm,
                                    &mut outgoing_transfers,
                                    &relay_peers,
                                    &event_tx,
                                    recipient,
                                    &path,
                                    transfer_id,
                                    is_retry,
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
                                    save_dir.as_deref().unwrap_or("void_downloads/")
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
                            UICommand::CachePeerPrekeys(keys) => {
                                for (peer, pk) in keys {
                                    peer_prekeys.insert(peer, pk);
                                }
                            }
                            UICommand::FetchOfflineMailbox => {
                                query_relay_mailbox(&mut swarm, local_peer_id);
                                let qid = swarm
                                    .behaviour_mut()
                                    .kad
                                    .get_record(mailbox_record_key(local_peer_id));
                                pending_kad_mail.insert(qid, MailboxKadOp::FetchInbox { record_bytes: None });
                            }
                            UICommand::ClearOfflineMailbox => {
                                put_mailbox_envelopes(
                                    &mut swarm,
                                    &mut pending_kad_mail,
                                    local_peer_id,
                                    local_peer_id,
                                    &[],
                                    None,
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
                                let done_gate = ack.map(|tx| publish_done_token(tx, work_count.max(1)));
                                let mut work_queued = false;
                                for (recipient, batch) in by_recipient {
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
                                    if !sealed.is_empty() {
                                        work_queued = true;
                                        if RelayMailbox::merge(
                                            &mut relay_mail_store,
                                            &recipient.to_string(),
                                            sealed.clone(),
                                        ) {
                                            let _ = RelayMailbox::save(&relay_mail_store);
                                        }
                                        publish_relay_mail(
                                            &mut swarm,
                                            &bootstrap_peer_ids,
                                            &void_bootstraps,
                                            local_peer_id,
                                            recipient,
                                            &sealed,
                                        );
                                        start_mailbox_merge_put(
                                            &mut swarm,
                                            &mut pending_kad_mail,
                                            recipient,
                                            sealed,
                                            done_gate.clone(),
                                        );
                                    }
                                    if !need_prekey.is_empty() {
                                        work_queued = true;
                                        let qid = swarm
                                            .behaviour_mut()
                                            .kad
                                            .get_record(prekey_record_key(recipient));
                                        pending_kad_mail.insert(
                                            qid,
                                            MailboxKadOp::PrekeyForPublish {
                                                recipient,
                                                items: need_prekey,
                                                done: done_gate.clone(),
                                                prekey_bytes: None,
                                            },
                                        );
                                    }
                                }
                                if !work_queued {
                                    signal_publish_done(&done_gate);
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
                                            let _ = swarm
                                                .behaviour_mut()
                                                .request_response
                                                .send_response(channel, V1Packet::Ack);
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
                                            let _ = swarm
                                                .behaviour_mut()
                                                .request_response
                                                .send_response(channel, V1Packet::Ack);
                                        }
                                        V1Packet::OfflineMailboxQuery { recipient } => {
                                            let envs =
                                                RelayMailbox::take_for(&mut relay_mail_store, &recipient);
                                            if !envs.is_empty() {
                                                let _ = RelayMailbox::save(&relay_mail_store);
                                            }
                                            let response = if envs.is_empty() {
                                                V1Packet::Ack
                                            } else {
                                                V1Packet::OfflineMailboxDeliver { envelopes: envs }
                                            };
                                            let _ = swarm
                                                .behaviour_mut()
                                                .request_response
                                                .send_response(channel, response);
                                        }
                                        V1Packet::OfflineMailboxDeliver { .. } => {
                                            let _ = swarm
                                                .behaviour_mut()
                                                .request_response
                                                .send_response(channel, V1Packet::Ack);
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
                                                    let _ = swarm
                                                        .behaviour_mut()
                                                        .request_response
                                                        .send_response(channel, V1Packet::Ack);
                                                } else {
                                                let is_initiator = local_peer_id < peer;
                                                let _role_str = if is_initiator { "Initiator" } else { "Responder" };

                                                // Новый Hello всегда перезапускает согласование: иначе после рестарта
                                                // пира мы бы оставили старый ratchet и только вернули Ack.
                                                if sessions.contains_key(&peer) {
                                                    debug!(
                                                        "[{}] 🔄 E2EE: сброс сессии с {} (новый Hello)",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                    sessions.remove(&peer);
                                                }
                                                // Наш незавершённый Hello (если был) — одно значение; либо дополняем им
                                                // рукопожатие, либо уступаем ответом как responder.
                                                let took_outgoing = pending_handshakes.remove(&peer);

                                                let remote_static_pub = crypto::PublicKey::from(public_key);
                                                remember_peer_prekey(
                                                    &mut peer_prekeys,
                                                    &event_tx,
                                                    peer,
                                                    public_key,
                                                )
                                                .await;
                                                let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);

                                                if is_initiator {
                                                    // По PeerId мы «инициатор»; если уже посылали Hello — закрываем пару.
                                                    if let Some(local_ephem_secret) = took_outgoing {
                                                        let session = crypto::SecureSession::new_initiator(&local_static, &remote_static_pub, local_ephem_secret, &remote_ephem_pub);
                                                        sessions.insert(peer, session);
                                                        debug!("[{}] 🤝 E2EE: Сессия (Alice/Req) создана с {}", now, &peer.to_string()[..8]);
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
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                                    } else {
                                                        // Инициатор по ID, но свой Hello мы ещё не слали — завершаем как responder.
                                                        let local_ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                                        let local_ephem_pub = crypto::PublicKey::from(&local_ephem_secret);

                                                        let session = crypto::SecureSession::new_responder(&local_static, &remote_static_pub, &remote_ephem_pub, local_ephem_secret);
                                                        sessions.insert(peer, session);
                                                        debug!("[{}] 🤝 E2EE: Сессия (fallback Res после Hello пира) с {}", now, &peer.to_string()[..8]);
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

                                                    if let Some(my_hello) = build_v1_hello(
                                                        &local_key,
                                                        local_peer_id,
                                                        peer,
                                                        my_public_key,
                                                        local_ephem_pub,
                                                    ) {
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, my_hello);
                                                    }
                                                    }
                                                } else {
                                                    // Боб получил Hello от Алисы
                                                    let local_ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                                    let local_ephem_pub = crypto::PublicKey::from(&local_ephem_secret);

                                                    let session = crypto::SecureSession::new_responder(&local_static, &remote_static_pub, &remote_ephem_pub, local_ephem_secret);
                                                    sessions.insert(peer, session);
                                                    debug!("[{}] 🤝 E2EE: Сессия (Bob/Res) создана с {}", now, &peer.to_string()[..8]);
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

                                                    if let Some(my_hello) = build_v1_hello(
                                                        &local_key,
                                                        local_peer_id,
                                                        peer,
                                                        my_public_key,
                                                        local_ephem_pub,
                                                    ) {
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, my_hello);
                                                    }
                                                }
                                                }
                                            }
                                        }
                                        V1Packet::Encrypted { header, ciphertext } => {
                                            let mut response_channel = Some(channel);
                                            let mut send_ack = false;
                                            if let Some(session) = sessions.get_mut(&peer) {
                                                match session.decrypt_payload(&header, &ciphertext) {
                                                    Ok(plaintext) => {
                                                        if let Some((tid, idx, pdata)) =
                                                            file_transfer::try_decode_e2ee_file_chunk_frame(
                                                                &plaintext,
                                                            )
                                                        {
                                                            apply_incoming_file_chunk(
                                                                tid,
                                                                idx,
                                                                pdata,
                                                                peer,
                                                                &now,
                                                                &mut incoming_transfers,
                                                                &event_tx,
                                                            )
                                                            .await;
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
                                                        }
                                                    }
                                                    Err(_) => {
                                                        debug!(
                                                            "[{}] ❌ E2EE: Ошибка дешифровки от {}. Сбрасываю...",
                                                            now,
                                                            &peer.to_string()[..8]
                                                        );
                                                        sessions.remove(&peer);
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
                                            }
                                            if send_ack {
                                                if let Some(ch) = response_channel {
                                                    let _ = swarm
                                                        .behaviour_mut()
                                                        .request_response
                                                        .send_response(ch, V1Packet::Ack);
                                                }
                                            }
                                        }
                                        V1Packet::Ack => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                        }
                                    }
                                }
                                libp2p::request_response::Message::Response { request_id, response } => {
                                    match response {
                                        V1Packet::Ack => {
                                            if let Some((delivered_peer, message_id)) =
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
                                            }
                                        }
                                        V1Packet::OfflineMailboxDeliver { envelopes } => {
                                            if !envelopes.is_empty() {
                                                let _ = event_tx
                                                    .send(NetworkEvent::OfflineMailbox(envelopes))
                                                    .await;
                                            }
                                        }
                                        V1Packet::Hello {
                                            public_key,
                                            ephemeral_key,
                                            transport_sig,
                                            transport_pubkey_pb,
                                        } => {
                                            if let Some((retry_peer, retry_id)) =
                                                outbound_msg_requests.remove(&request_id)
                                            {
                                                debug!(
                                                    "[{}] ↻ RR: {} ответил Hello вместо Ack (msg {}), ждём ретрай",
                                                    now,
                                                    &peer.to_string()[..8],
                                                    &retry_id[..8.min(retry_id.len())]
                                                );
                                                let _ = retry_peer;
                                            }
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
                                                        "[{}] ❌ E2EE: Hello (ответ) от {} без привязки к libp2p identity — игнор.",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                } else {
                                                let is_initiator = local_peer_id < peer;
                                                if sessions.contains_key(&peer) {
                                                    debug!(
                                                        "[{}] 🔄 E2EE: сброс сессии с {} (Hello в ответе)",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                    sessions.remove(&peer);
                                                }
                                                let session_exists = sessions.contains_key(&peer);
                                                // Завершение стороны, которая первая послала Hello (есть наш ephem в pending).
                                                // Раньше требовался is_initiator (меньший PeerId) — тогда пир с большим ID,
                                                // написавший первым, никогда не создавал сессию по Hello в ответе.
                                                if !session_exists {
                                                    let remote_static_pub = crypto::PublicKey::from(public_key);
                                                    remember_peer_prekey(
                                                        &mut peer_prekeys,
                                                        &event_tx,
                                                        peer,
                                                        public_key,
                                                    )
                                                    .await;
                                                    let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);
                                                    if let Some(local_ephem_secret) = pending_handshakes.remove(&peer) {
                                                        let session = crypto::SecureSession::new_initiator(&local_static, &remote_static_pub, local_ephem_secret, &remote_ephem_pub);
                                                        sessions.insert(peer, session);
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
                                                    }
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
                                                        apply_incoming_file_chunk(
                                                            tid,
                                                            idx,
                                                            pdata,
                                                            peer,
                                                            &now,
                                                            &mut incoming_transfers,
                                                            &event_tx,
                                                        )
                                                        .await;
                                                    } else if let Some(frame) =
                                                        parse_decrypted_chat_frame(&plaintext)
                                                    {
                                                        match frame {
                                                            DecryptedChatFrame::Message(msg) => {
                                                                let _ = event_tx
                                                                    .send(NetworkEvent::ChatMessage(msg))
                                                                    .await;
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
                                        V1Packet::OfflineMailboxStore { .. }
                                        | V1Packet::OfflineMailboxQuery { .. } => {}
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::OutboundFailure { peer, request_id, error, .. })) => {
                            let was_msg = outbound_msg_requests.remove(&request_id).is_some();
                            let was_delete = outbound_delete_requests.remove(&request_id).is_some();
                            // Неотслеживаемый запрос — это Hello-handshake; сбрасываем, чтобы
                            // повторная отправка не считала хендшейк «уже в полёте».
                            if !was_msg && !was_delete {
                                pending_handshakes.remove(&peer);
                                // Hello упал — UI не должен вечно ждать E2EE-сессию.
                                if pending_messages
                                    .get(&peer)
                                    .is_some_and(|q| !q.is_empty())
                                {
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
                            match error {
                                libp2p::request_response::OutboundFailure::DialFailure => {
                                    if !is_dup {
                                        if let Some(addrs) = reconnect_targets.get(&peer) {
                                            dial_peer_best_effort(
                                                &mut swarm,
                                                peer,
                                                addrs.clone(),
                                                &void_bootstraps,
                                            );
                                        }
                                        swarm
                                            .behaviour_mut()
                                            .kad
                                            .get_providers(peer_dht_record_key(peer));
                                        let _ = event_tx.send(NetworkEvent::SendFailedDial(peer)).await;
                                    }
                                }
                                libp2p::request_response::OutboundFailure::UnsupportedProtocols => {
                                    if !is_dup {
                                        let _ = event_tx
                                            .send(NetworkEvent::SendFailedUnsupported(peer))
                                            .await;
                                    }
                                }
                                _ => {}
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::InboundFailure { peer, error, .. })) => {
                            debug!("⚠️ [RR] InFailure от пира {}: {:?}", peer, error);
                        }
                        SwarmEvent::ExternalAddrConfirmed { address } => {
                            debug!("🌍 ВНЕШНИЙ АДРЕС ПОДТВЕРЖДЕН: {}", address);
                            publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);
                            let _ = swarm.behaviour_mut().kad.bootstrap();
                            let _ = event_tx.send(NetworkEvent::Status(
                                format!("🌍 ГЛОБАЛЬНЫЙ АДРЕС: Вы доступны из интернета!")
                            )).await;

                            let extracted_ip = address.iter().find_map(|p| match p {
                                libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.to_string()),
                                libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.to_string()),
                                _ => None,
                            });
                            if let Some(ip) = extracted_ip {
                                let _ = event_tx.send(NetworkEvent::PublicIpConfirmed(ip)).await;
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, ref endpoint, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            debug!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. Всего пиров: {}", peer_id, endpoint, connected_count);
                            pending_dials.remove(&peer_id);
                            // Соединение установлено — снимаем задание на реконнект.
                            reconnect_queue.remove(&peer_id);
                            publish_self_in_dht(&mut swarm.behaviour_mut().kad, local_peer_id);

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
                                debug!(
                                    "📡 FILE rate-limit: {} подключён через relay.",
                                    &peer_id.to_string()[..8]
                                );
                            } else {
                                relay_peers.remove(&peer_id);
                            }

                             if peer_id != local_peer_id {
                                 // Резервируем слот на bootstrap-relay, чтобы другие пиры
                                 // могли дозвониться через NAT (circuit relay v2).
                                 if bootstrap_peer_ids.contains(&peer_id) {
                                     let relay_src: Vec<Multiaddr> = reconnect_targets
                                         .get(&peer_id)
                                         .cloned()
                                         .unwrap_or_else(|| {
                                             void_bootstraps
                                                 .iter()
                                                 .filter(|ma| {
                                                     peer_id_from_multiaddr(ma) == Some(peer_id)
                                                 })
                                                 .cloned()
                                                 .collect()
                                         });
                                     for ma in relay_circuit_listen_addrs(&relay_src) {
                                         if let Err(e) = swarm.listen_on(ma.clone()) {
                                             debug!(
                                                 "relay circuit listen {}: {:?}",
                                                 ma, e
                                             );
                                         } else {
                                             debug!("📡 relay circuit listen: {}", ma);
                                         }
                                     }
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
                                         &now_hs,
                                         false,
                                     )
                                     .await;
                                 }
                                 let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                                 let _ = event_tx.send(NetworkEvent::Status(format!("✅ СОЕДИНЕНО: {}", &peer_id.to_string()[..8]))).await;
                                 // Запрашиваем офлайн-почту у всех пиров (включая bootstrap-relay).
                                 query_relay_mailbox(&mut swarm, local_peer_id);
                                 if bootstrap_peer_ids.contains(&peer_id) {
                                     let qid = swarm
                                         .behaviour_mut()
                                         .kad
                                         .get_record(mailbox_record_key(local_peer_id));
                                     pending_kad_mail.insert(
                                         qid,
                                         MailboxKadOp::FetchInbox { record_bytes: None },
                                     );
                                     let _ = event_tx
                                         .send(NetworkEvent::Status(
                                             "📬 Запрос офлайн-почты у bootstrap".into(),
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
                                 }
                                 // Передаём рабочий multiaddr в UI: для Dialer — кого набирали,
                                 // для Listener — кто пришёл (send_back_addr + /p2p/peer_id).
                                 // UI сохранит его в контактную книгу.
                                 let learned: Option<Multiaddr> = match endpoint {
                                     libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                         Some(address.clone())
                                     }
                                     libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                         let mut a = send_back_addr.clone();
                                         a.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                                         Some(a)
                                     }
                                 };
                                 if let Some(ref addr) = learned {
                                     if !is_junk_addr(addr) {
                                         // Обновляем таблицу реконнекта: ставим рабочий адрес первым,
                                         // чтобы следующая попытка начиналась с него.
                                         let list = reconnect_targets.entry(peer_id).or_default();
                                         list.retain(|a| a != addr);
                                         list.insert(0, addr.clone());

                                         let _ = event_tx
                                             .send(NetworkEvent::PeerAddress(peer_id, addr.clone()))
                                             .await;
                                     }
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
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            debug!("❌ СОЕДИНЕНИЕ ЗАКРЫТО: {}. Причина: {:?}. Осталось: {}", peer_id, cause, connected_count);
                            relay_peers.remove(&peer_id);

                            // E2EE: при обрыве TCP/QUIC сбрасываем криптосостояние с пиром.
                            // Иначе после рестарта одного клиента второй держит «старый» ratchet
                            // и новые Hello игнорируются (отправлялся только Ack → чат мёртв).
                            sessions.remove(&peer_id);
                            pending_handshakes.remove(&peer_id);
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
                                 let _ = event_tx.send(NetworkEvent::Status(
                                     format!("❌ Ошибка подключения: {}", peer_str)
                                 )).await;
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
                                    &now,
                                    false,
                                )
                                .await;
                            }
                            let mut bootstrap_learned: Vec<String> = Vec::new();
                            for addr in info.listen_addrs {
                                // Не тащим к себе заведомо-невалидные адреса пира
                                // (VirtualBox/Docker/link-local). Они только
                                // провоцируют долгие таймауты в dial.
                                if is_junk_addr(&addr) {
                                    continue;
                                }
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());

                                // Нормализуем адрес: добавляем /p2p/<peer_id> если нет.
                                let mut a = addr.clone();
                                if !a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_))) {
                                    a.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                                }

                                // Обновляем таблицу реконнекта: при следующем disconnet/restart
                                // dial будет по актуальным listen-адресам, а не по устаревшим.
                                if peer_id != local_peer_id {
                                    let list = reconnect_targets.entry(peer_id).or_default();
                                    if !list.contains(&a) {
                                        list.push(a.clone());
                                    }
                                }

                                if is_bootstrap && peer_id != local_peer_id {
                                    bootstrap_learned.push(a.to_string());
                                }

                                // Если это настоящий VOID-клиент — сохраним его
                                // listen-адрес в контактной книге, чтобы связь поднялась
                                // после рестарта без ручного ПОДКЛЮЧИТЬ.
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
                                "📡 Relay: резервация на {} (renewal={renewal})",
                                &relay_peer_id.to_string()[..8]
                            );
                            publish_self_in_dht(
                                &mut swarm.behaviour_mut().kad,
                                local_peer_id,
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

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, .. })) => {
                            match &result {
                                libp2p::kad::QueryResult::PutRecord(Ok(_))
                                | libp2p::kad::QueryResult::PutRecord(Err(_)) => {
                                    if let Some(MailboxKadOp::AwaitPut { done }) =
                                        pending_kad_mail.remove(&id)
                                    {
                                        let _ = event_tx
                                            .send(NetworkEvent::OfflineMailboxPublished)
                                            .await;
                                        signal_publish_done(&done);
                                    }
                                }
                                libp2p::kad::QueryResult::GetRecord(Ok(
                                    kad::GetRecordOk::FoundRecord(peer_record),
                                )) => {
                                    if let Some(op) = pending_kad_mail.get_mut(&id) {
                                        match op {
                                            MailboxKadOp::FetchInbox { record_bytes } => {
                                                *record_bytes =
                                                    Some(peer_record.record.value.clone());
                                            }
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
                                            MailboxKadOp::AwaitPut { .. } => {}
                                        }
                                    }
                                }
                                libp2p::kad::QueryResult::GetRecord(Ok(
                                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                                )) => {
                                    if let Some(op) = pending_kad_mail.remove(&id) {
                                        match op {
                                            MailboxKadOp::FetchInbox { record_bytes } => {
                                                let envelopes = record_bytes
                                                    .as_deref()
                                                    .and_then(|b| decode_mailbox(b).ok())
                                                    .unwrap_or_default();
                                                if !envelopes.is_empty() {
                                                    let _ = event_tx
                                                        .send(NetworkEvent::OfflineMailbox(
                                                            envelopes,
                                                        ))
                                                        .await;
                                                }
                                            }
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
                                                        publish_relay_mail(
                                                            &mut swarm,
                                                            &bootstrap_peer_ids,
                                                            &void_bootstraps,
                                                            local_peer_id,
                                                            recipient,
                                                            &sealed,
                                                        );
                                                        start_mailbox_merge_put(
                                                            &mut swarm,
                                                            &mut pending_kad_mail,
                                                            recipient,
                                                            sealed,
                                                            done,
                                                        );
                                                    } else {
                                                        signal_publish_done(&done);
                                                    }
                                                } else {
                                                    signal_publish_done(&done);
                                                    let _ = event_tx
                                                        .send(NetworkEvent::Status(format!(
                                                            "⚠ Нет prekey {} — офлайн-почта не отправлена",
                                                            &recipient.to_string()[..8.min(recipient.to_string().len())]
                                                        )))
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
                                                signal_publish_done(&done);
                                            }
                                            MailboxKadOp::FetchInbox { .. }
                                            | MailboxKadOp::AwaitPut { .. } => {}
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
                                            let incoming = file_transfer::IncomingTransfer::new(
                                                peer,
                                                transfer_id,
                                                safe.clone(),
                                                total_size,
                                                total_chunks,
                                                sha256,
                                                kind,
                                            );
                                            incoming_transfers.insert(transfer_id, incoming);
                                            let _ = swarm
                                                .behaviour_mut()
                                                .file_rr
                                                .send_response(channel, FilePacket::Ack);

                                            if file_transfer::is_voice_filename(&safe) {
                                                // Голосовые принимаем сразу в сети — без roundtrip через UI.
                                                if let Some(inc) =
                                                    incoming_transfers.get_mut(&transfer_id)
                                                {
                                                    inc.save_dir = Some(
                                                        file_transfer::voice_dir_absolute()
                                                            .display()
                                                            .to_string(),
                                                    );
                                                }
                                                let accept =
                                                    FilePacket::Accept { transfer_id };
                                                swarm
                                                    .behaviour_mut()
                                                    .file_rr
                                                    .send_request(&peer, accept);
                                                debug!(
                                                    "[{}] 🔊 FILE: auto-Accept голосового {:x?} от {}",
                                                    now,
                                                    &transfer_id[..4],
                                                    &peer.to_string()[..8]
                                                );
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
                                                t.last_chunk_at =
                                                    Instant::now() - file_transfer::DIRECT_CHUNK_DELAY;
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
                                            apply_incoming_file_chunk(
                                                transfer_id,
                                                chunk_index,
                                                data,
                                                peer,
                                                &now,
                                                &mut incoming_transfers,
                                                &event_tx,
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

pub fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}
