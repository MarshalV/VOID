mod crypto;
mod file_transfer;
mod ui;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use chrono;
use eframe::egui;
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, kad, mdns, noise, ping, relay,
    swarm::{dial_opts::DialOpts, NetworkBehaviour, SwarmEvent},
    tcp, upnp, yamux, Multiaddr, PeerId, StreamProtocol,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use ui::{setup_custom_style, truncate_text, Toast, ToastKind, TOAST_TTL_LONG, TOAST_TTL_SHORT};

/// `PeerId` с конца multiaddr (`.../p2p/<id>`).
fn peer_id_from_multiaddr(ma: &Multiaddr) -> Option<PeerId> {
    ma.iter().last().and_then(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// Подсети «виртуальных» интерфейсов, которые не должны попадать в список
/// своих listen-адресов / объявляться соседям / подниматься через mDNS.
/// Эти адреса недостижимы для **чужих** хостов и только мешают dial'ам.
///
/// - `192.168.56.0/24` — VirtualBox Host-Only (`vboxnet0`).
/// - `172.17.0.0/16`   — Docker default bridge (часто проваливается в WSL2).
/// - `172.18–25.0/16`  — доп. bridge-сети Docker/Podman.
/// - `169.254.0.0/16`  — APIPA link-local (когда DHCP не выдал IP).
/// - Loopback/unspec оставляем для случаев, когда адрес пришёл без фильтра.
///
/// Расширяется через `VOID_SKIP_SUBNETS` (CIDR через запятую: `10.8.0.0/24,...`).
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

/// Встроенные seed-адреса в бинарнике (пользователи ничего не вводят). Достаточно нескольких — дальше Kademlia сама находит тысячи пиров.
/// Формат: полный multiaddr с `/p2p/<PeerId>` в конце.
const BUILTIN_VOID_BOOTSTRAP: &[&str] = &[];

/// Публичный URL со списком seed (как `void-bootstrap.txt`: одна multiaddr на строку, `#` — комментарий).
/// Замените на свой endpoint один раз на релиз; клиенты подтянут список при старте.
const VOID_BOOTSTRAP_PUBLIC_LIST_URL: &str = "";

/// Узлы для заполнения **отдельного** VOID DHT (не IPFS): сообщения по-прежнему идут напрямую между пирами.
///
/// Источники (все опциональны, объединяются и дедуплицируются):
/// - `BUILTIN_VOID_BOOTSTRAP` и сборка с `VOID_BUILTIN_BOOTSTRAP=/ip4/.../p2p/...,...` (вшито в exe);
/// - HTTP(S): `VOID_BOOTSTRAP_URL` и/или `VOID_BOOTSTRAP_PUBLIC_LIST_URL` (если не пустой и не задан `VOID_SKIP_PUBLIC_BOOTSTRAP_LIST`);
/// - переменная `VOID_BOOTSTRAP`: multiaddr через запятую;
/// - файл `void-bootstrap.txt`: одна multiaddr на строку.
///
/// Любой может поднять публичный узел VOID — это не «центральный сервер чата», а точка входа в DHT (как у torrent).
fn append_bootstraps_from_lines(out: &mut Vec<Multiaddr>, text: &str, source: &str) {
    for line in text.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => out.push(ma),
            Err(_) => eprintln!("{}: пропуск строки: {}", source, t),
        }
    }
}

fn append_bootstraps_from_comma_separated(out: &mut Vec<Multiaddr>, s: &str, source: &str) {
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => out.push(ma),
            Err(_) => eprintln!("{}: пропуск неверной multiaddr: {}", source, t),
        }
    }
}

fn fetch_void_bootstrap_list(url: &str) -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .ok()?;
    match client.get(url).send() {
        Ok(resp) => {
            if !resp.status().is_success() {
                eprintln!(
                    "VOID bootstrap URL {}: HTTP {}",
                    url,
                    resp.status()
                );
                return None;
            }
            resp.text().ok()
        }
        Err(e) => {
            eprintln!("VOID bootstrap URL {}: {}", url, e);
            None
        }
    }
}

/// Разбирает ввод «войти в сеть»: полный multiaddr, `IP`, `IP:PORT`. Возвращает multiaddr и (опц.) PeerId.
fn parse_seed_input(raw: &str) -> Option<(Multiaddr, Option<PeerId>)> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with('/') {
        let ma: Multiaddr = t.parse().ok()?;
        let pid = peer_id_from_multiaddr(&ma);
        return Some((ma, pid));
    }
    let (host, port) = if let Some((h, p)) = t.rsplit_once(':') {
        let port: u16 = p.parse().ok()?;
        (h.to_string(), port)
    } else {
        (t.to_string(), 4001u16)
    };
    let ip: std::net::IpAddr = host.parse().ok()?;
    let base = match ip {
        std::net::IpAddr::V4(v4) => format!("/ip4/{}/tcp/{}", v4, port),
        std::net::IpAddr::V6(v6) => format!("/ip6/{}/tcp/{}", v6, port),
    };
    let ma: Multiaddr = base.parse().ok()?;
    Some((ma, None))
}

fn void_bootstrap_multiaddrs() -> Vec<Multiaddr> {
    let mut out = Vec::new();

    for s in BUILTIN_VOID_BOOTSTRAP {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        match t.parse::<Multiaddr>() {
            Ok(ma) => out.push(ma),
            Err(_) => eprintln!("BUILTIN_VOID_BOOTSTRAP: пропуск: {}", t),
        }
    }

    if let Some(s) = option_env!("VOID_BUILTIN_BOOTSTRAP") {
        append_bootstraps_from_comma_separated(&mut out, s, "VOID_BUILTIN_BOOTSTRAP (сборка)");
    }

    let mut urls: Vec<String> = Vec::new();
    if let Ok(u) = std::env::var("VOID_BOOTSTRAP_URL") {
        let t = u.trim().to_string();
        if !t.is_empty() {
            urls.push(t);
        }
    }
    if std::env::var("VOID_SKIP_PUBLIC_BOOTSTRAP_LIST").is_err() {
        let u = VOID_BOOTSTRAP_PUBLIC_LIST_URL.trim();
        if !u.is_empty() {
            urls.push(u.to_string());
        }
    }
    urls.sort();
    urls.dedup();
    for url in urls {
        if let Some(body) = fetch_void_bootstrap_list(&url) {
            append_bootstraps_from_lines(&mut out, &body, &format!("GET {}", url));
        }
    }

    let path = Path::new("void-bootstrap.txt");
    if path.exists() {
        if let Ok(txt) = std::fs::read_to_string(path) {
            append_bootstraps_from_lines(&mut out, &txt, "void-bootstrap.txt");
        }
    }

    if let Ok(s) = std::env::var("VOID_BOOTSTRAP") {
        append_bootstraps_from_comma_separated(&mut out, &s, "VOID_BOOTSTRAP");
    }

    out.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
    out.dedup_by(|a, b| a == b);
    out
}

/// Адреса пира из **локальной** Kademlia-таблицы (без сетевого запроса).
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

#[derive(Serialize, Deserialize, Clone, Default)]
struct AddressBookEntry {
    peer_id: String,
    display_name: String,
    /// Последние известные multiaddr собеседника — прогреваем kbuckets Kademlia
    /// на старте, чтобы «написать контакту» работало без предварительного
    /// дозвона. Старые vault'ы без этого поля читаются нормально.
    #[serde(default)]
    addrs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct StorageData {
    nickname: String,
    keypair_bytes: Vec<u8>,
    static_secret_bytes: [u8; 32],
    /// Записная книга: PeerId и отображаемое имя (внутри того же зашифрованного vault).
    #[serde(default)]
    address_book: Vec<AddressBookEntry>,
}

struct Storage;
impl Storage {
    const FILE: &'static str = "vault.bin";
    const FILE_TMP: &'static str = "vault.bin.tmp";
    const FILE_BAK: &'static str = "vault.bin.bak";
    const KEY_FILE: &'static str = "void.key";

    fn get_master_key() -> [u8; 32] {
        if let Ok(k) = std::fs::read(Self::KEY_FILE) {
            if k.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&k);
                return key;
            }
        }
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let _ = std::fs::write(Self::KEY_FILE, &key);
        key
    }

    fn save(
        nickname: &str,
        keypair: Option<&libp2p::identity::Keypair>,
        static_secret: Option<&crypto::StaticSecret>,
        address_book: Option<&[AddressBookEntry]>,
    ) -> Result<(), Box<dyn Error>> {
        let current_load = Self::load();

        let keypair_bytes = if let Some(kp) = keypair {
            kp.to_protobuf_encoding()?
        } else if let Ok(ref c) = current_load {
            if c.keypair_bytes.is_empty() {
                return Err("vault: keypair в файле пустой — запись отменена".into());
            }
            c.keypair_bytes.clone()
        } else {
            return Err(format!(
                "vault: не удалось прочитать {} перед сохранением ({}). Запись отменена, чтобы не затереть ключи.",
                Self::FILE,
                current_load.err().map(|e| e.to_string()).unwrap_or_default()
            )
            .into());
        };

        let static_secret_bytes = if let Some(ss) = static_secret {
            ss.to_bytes()
        } else if let Ok(ref c) = current_load {
            c.static_secret_bytes
        } else {
            return Err("vault: нет static_secret для сохранения".into());
        };

        let address_book_vec: Vec<AddressBookEntry> = if let Some(ab) = address_book {
            ab.to_vec()
        } else {
            current_load
                .as_ref()
                .map(|c| c.address_book.clone())
                .unwrap_or_default()
        };

        let data = StorageData {
            nickname: nickname.to_string(),
            keypair_bytes,
            static_secret_bytes,
            address_book: address_book_vec,
        };
        let plaintext = serde_json::to_vec(&data)?;

        let master_key = Self::get_master_key();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        let mut final_data = nonce_bytes.to_vec();
        final_data.extend(ciphertext);

        // Сначала пишем во временный файл, затем подменяем vault — иначе при сбое
        // посередине fs::write остаётся усечённый vault и следующий load() ломается,
        // после чего старый save подставлял пустой keypair и окончательно портил ключи.
        std::fs::write(Self::FILE_TMP, &final_data)?;
        if Path::new(Self::FILE).exists() {
            let _ = std::fs::remove_file(Self::FILE_BAK);
            std::fs::rename(Self::FILE, Self::FILE_BAK)?;
        }
        std::fs::rename(Self::FILE_TMP, Self::FILE)?;
        let _ = std::fs::remove_file(Self::FILE_BAK);
        Ok(())
    }

    fn load() -> Result<StorageData, Box<dyn Error>> {
        if !std::path::Path::new(Self::FILE).exists() {
            return Err("Vault file not found".into());
        }
        let data = std::fs::read(Self::FILE)?;
        if data.len() < 12 {
            return Err("Invalid vault".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let master_key = Self::get_master_key();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&master_key));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {}", e))?;

        let storage: StorageData = serde_json::from_slice(&plaintext)?;
        Ok(storage)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    sender_id: String,
    sender_name: String,
    recipient_id: Option<String>, // Some(peer_id) for private, None for global
    text: String,
    timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum V1Packet {
    Hello {
        public_key: [u8; 32],
        ephemeral_key: [u8; 32],
    },
    Encrypted {
        header: crypto::MessageHeader,
        ciphertext: Vec<u8>,
    },
    Plain(ChatMessage),
    Ack,
}

/// Прогресс активной передачи файла (для UI).
pub(crate) struct FileTransferProgress {
    pub filename: String,
    pub total_size: u64,
    pub sent_chunks: u32,
    pub total_chunks: u32,
    pub is_outgoing: bool,
    pub completed: bool,
    pub saved_to: String,
    pub peer: PeerId,
    pub kind: file_transfer::FileKind,
}

enum NetworkEvent {
    NewListenAddr(Multiaddr),
    MdnsDiscovered(PeerId, Multiaddr),
    MdnsExpired(PeerId),
    Connected(PeerId),
    Disconnected(PeerId),
    ChatMessage(ChatMessage),
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
    /// Получен Response (Ack/прочее) на ранее отправленное сообщение пиру —
    /// сигнал UI снять одно ожидание из `pending_sends` и не показывать ошибку.
    MessageDelivered(PeerId),
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

enum UICommand {
    Dial(String),
    DialPeer(PeerId, Vec<Multiaddr>),
    SearchPeer(PeerId),
    /// Перечитать `VOID_BOOTSTRAP` / файл / встроенные / URL и снова подать в Kad (как при старте).
    ReloadBootstrapFromSources,
    /// Войти в сеть через один узел: IP, IP:PORT или полный multiaddr; после коннекта — kad.bootstrap.
    JoinViaNode(String),
    /// Собрать PeerId из kbuckets и отправить в UI.
    SnapshotDhtRoutingPeers,
    SendMessage {
        sender_name: String,
        text: String,
        recipient: Option<PeerId>,
        is_retry: bool,
    },
    // ─── Файловый sub-протокол ──────────────────────────────────────────────
    /// Отправить файл пиру. Сетевой таск читает файл и инициирует Offer.
    SendFile {
        recipient: PeerId,
        path: String,
        kind: file_transfer::FileKind,
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
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    request_response: libp2p::request_response::json::Behaviour<V1Packet, V1Packet>,
    /// Отдельный sub-протокол для передачи файлов (/void/file/1.0.0).
    file_rr: libp2p::request_response::json::Behaviour<
        file_transfer::FilePacket,
        file_transfer::FilePacket,
    >,
    mdns: mdns::tokio::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    relay: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    upnp: upnp::tokio::Behaviour,
}

/// Сообщение в очереди ожидания доставки. Если в течение `RESEND_GRACE` после
/// последней попытки прилетел `SendFailedDial` (или просто прошло столько же
/// времени без подтверждения), запускаем DHT-lookup и через `RESEND_DELAY`
/// отправляем повторно. После `MAX_ATTEMPTS` попыток сдаёмся с toast'ом.
struct PendingSend {
    peer: PeerId,
    text: String,
    last_send_at: Instant,
    /// Был ли уже запущен DHT-поиск для текущей попытки.
    dht_kicked: bool,
    /// Когда был запущен DHT-поиск (для отсчёта `RESEND_DELAY`).
    dht_kicked_at: Option<Instant>,
    /// Сколько раз отправка уже улетала в сеть (1 = только начальная).
    attempts: u8,
}

const RESEND_GRACE: Duration = Duration::from_secs(3);
const RESEND_DELAY: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: u8 = 2;

struct App {
    local_peer_id: PeerId,
    local_nickname: String,
    listen_addrs: Vec<String>,
    connected_peers: usize,
    dial_address: String,
    chat_input: String,
    // Storage: "GLOBAL" or PeerId string
    messages: HashMap<String, Vec<ChatMessage>>,
    known_peers: HashMap<PeerId, String>,
    /// Известные multiaddr контактов из зашифрованного vault. При старте
    /// подаются в Kademlia; при добавлении контакта — сразу Dial + Kad.
    contact_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    selected_chat: String, // "GLOBAL" or PeerId string
    status_log: Vec<String>,
    show_logs: bool,
    show_sidebar: bool,
    sidebar_width: f32,
    public_ip: Option<String>,
    /// Ручное добавление в зашифрованную записную книгу
    add_contact_peer: String,
    add_contact_name: String,
    /// Черновики имён для полей ввода (иначе egui сбрасывает текст каждый кадр).
    peer_name_edits: HashMap<PeerId, String>,
    /// Редактор `void-bootstrap.txt` (одна multiaddr на строку); «Применить» шлёт в сеть.
    void_bootstrap_draft: String,
    /// Последний снимок таблицы Kademlia (не полный каталог пользователей).
    dht_routing_lines: Vec<String>,
    dht_routing_total: usize,
    command_tx: mpsc::Sender<UICommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    _sessions: HashMap<libp2p::PeerId, crypto::SecureSession>,
    _local_static: crypto::StaticSecret,
    /// Сообщения, доставку которых мы пытаемся повторить при DialFailure.
    pending_sends: Vec<PendingSend>,
    /// Плавающие уведомления (рендерятся в правом верхнем углу).
    toasts: Vec<Toast>,
    /// Лениво загружаемая текстура фона области диалогов (`static/icon.png`,
    /// вшит в бинарь через `include_bytes!`).
    chat_bg_texture: Option<egui::TextureHandle>,
    // ─── Файловый sub-протокол ──────────────────────────────────────────────
    /// Входящие предложения файлов, ожидающие ответа пользователя.
    pub(crate) incoming_file_offers: Vec<file_transfer::PendingFileOffer>,
    /// Активные передачи (исходящие и входящие).
    pub(crate) active_file_transfers: HashMap<[u8; 16], FileTransferProgress>,
    /// Флаг: показывать popup-меню выбора типа вложения.
    pub(crate) show_attach_menu: bool,
    /// Ожидаемый результат выбора папки сохранения: `(rx, transfer_id, from_peer)`.
    /// Поллим `try_recv()` каждый кадр; `None` = выбор не идёт.
    pub(crate) pending_accept: Option<(
        std::sync::mpsc::Receiver<Option<String>>,
        [u8; 16],
        PeerId,
    )>,
}

impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        local_peer_id: PeerId,
        local_nickname: String,
        local_static: crypto::StaticSecret,
        initial_address_book: HashMap<PeerId, String>,
        initial_contact_addrs: HashMap<PeerId, Vec<Multiaddr>>,
        command_tx: mpsc::Sender<UICommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        setup_custom_style(&cc.egui_ctx);
        let messages = HashMap::new();

        Self {
            local_peer_id,
            local_nickname,
            listen_addrs: Vec::new(),
            connected_peers: 0,
            dial_address: String::new(),
            chat_input: String::new(),
            messages,
            known_peers: initial_address_book,
            contact_addrs: initial_contact_addrs,
            selected_chat: String::new(),
            status_log: Vec::new(),
            show_logs: false,
            show_sidebar: true,
            sidebar_width: 300.0,
            public_ip: None,
            add_contact_peer: String::new(),
            add_contact_name: String::new(),
            peer_name_edits: HashMap::new(),
            void_bootstrap_draft: std::fs::read_to_string(Path::new("void-bootstrap.txt"))
                .unwrap_or_default(),
            dht_routing_lines: Vec::new(),
            dht_routing_total: 0,
            command_tx,
            event_rx,
            _sessions: HashMap::new(),
            _local_static: local_static,
            pending_sends: Vec::new(),
            toasts: Vec::new(),
            chat_bg_texture: None,
            incoming_file_offers: Vec::new(),
            active_file_transfers: HashMap::new(),
            show_attach_menu: false,
            pending_accept: None,
        }
    }

    /// Сохраняет ник и записную книгу в `vault.bin` (AES-GCM, ключ в `void.key`).
    fn persist_vault(&self) {
        let mut entries: Vec<AddressBookEntry> = self
            .known_peers
            .iter()
            .map(|(pid, name)| {
                let addrs = self
                    .contact_addrs
                    .get(pid)
                    .map(|v| v.iter().map(|a| a.to_string()).collect::<Vec<_>>())
                    .unwrap_or_default();
                AddressBookEntry {
                    peer_id: pid.to_string(),
                    display_name: name.clone(),
                    addrs,
                }
            })
            .collect();
        entries.sort_by(|a, b| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        });
        if let Err(e) = Storage::save(
            &self.local_nickname,
            None,
            None,
            Some(&entries),
        ) {
            eprintln!("VOID: не удалось сохранить vault (записная книга): {}", e);
        }
    }

    /// Машина состояний для повторных отправок: 3 сек ждём DialFailure / тишину →
    /// дёргаем `SearchPeer` (kad.get_closest_peers), 5 сек ждём → ретраим
    /// `SendMessage`. После `MAX_ATTEMPTS` попыток — toast и снимаем.
    fn tick_pending_sends(&mut self) {
        let now = Instant::now();
        let mut to_drop: Vec<usize> = Vec::new();
        let mut search_cmds: Vec<PeerId> = Vec::new();
        let mut resend_cmds: Vec<(PeerId, String)> = Vec::new();
        let mut toasts: Vec<(String, ToastKind, Duration)> = Vec::new();

        for (idx, p) in self.pending_sends.iter_mut().enumerate() {
            // Финальная сдача — после исчерпания попыток.
            if p.attempts >= MAX_ATTEMPTS {
                if let Some(kicked_at) = p.dht_kicked_at {
                    if now.duration_since(kicked_at) >= RESEND_DELAY {
                        let name_short = format!("{}…", &p.peer.to_string()[..10]);
                        toasts.push((
                            format!(
                                "✖ Не удалось доставить «{}» пиру {}",
                                truncate_text(&p.text, 32),
                                name_short
                            ),
                            ToastKind::Error,
                            TOAST_TTL_LONG,
                        ));
                        to_drop.push(idx);
                    }
                }
                continue;
            }

            // Фаза 1: ждём `RESEND_GRACE` после последней попытки, потом дёргаем DHT.
            if !p.dht_kicked && now.duration_since(p.last_send_at) >= RESEND_GRACE {
                let name_short = format!("{}…", &p.peer.to_string()[..10]);
                toasts.push((
                    format!("⏳ Ищу пира {} через DHT…", name_short),
                    ToastKind::Info,
                    TOAST_TTL_SHORT,
                ));
                search_cmds.push(p.peer);
                p.dht_kicked = true;
                p.dht_kicked_at = Some(now);
            }

            // Фаза 2: после DHT-поиска ждём `RESEND_DELAY` и шлём повторно.
            if let Some(kicked_at) = p.dht_kicked_at {
                if now.duration_since(kicked_at) >= RESEND_DELAY {
                    resend_cmds.push((p.peer, p.text.clone()));
                    p.attempts = p.attempts.saturating_add(1);
                    p.last_send_at = now;
                    p.dht_kicked = false;
                    p.dht_kicked_at = None;

                    if p.attempts >= MAX_ATTEMPTS {
                        // Сразу запустим финальный таймер «сдачи» (см. ветку выше
                        // — сработает, когда снова пройдёт RESEND_DELAY).
                        p.dht_kicked_at = Some(now);
                    } else {
                        let name_short = format!("{}…", &p.peer.to_string()[..10]);
                        toasts.push((
                            format!(
                                "↻ Повтор #{} → {}",
                                p.attempts,
                                name_short
                            ),
                            ToastKind::Warn,
                            TOAST_TTL_SHORT,
                        ));
                    }
                }
            }
        }

        // Удаляем сданные (с конца, чтобы индексы не съехали).
        for idx in to_drop.iter().rev() {
            self.pending_sends.swap_remove(*idx);
        }

        // Применяем накопленные команды и toast'ы (борем borrow checker).
        for (text, kind, ttl) in toasts {
            self.push_toast(text, kind, ttl);
        }
        for peer in search_cmds {
            let _ = self.command_tx.try_send(UICommand::SearchPeer(peer));
        }
        for (peer, text) in resend_cmds {
            let _ = self.command_tx.try_send(UICommand::SendMessage {
                sender_name: self.local_nickname.clone(),
                text,
                recipient: Some(peer),
                is_retry: true,
            });
        }
    }

    fn add_status(&mut self, msg: String) {
        let ts = chrono::Local::now().format("%H:%M").to_string();
        self.status_log.push(format!("[{}] {}", ts, msg));
        if self.status_log.len() > 30 {
            self.status_log.remove(0);
        }
    }

    /// Личный чат не выбран, пока пользователь не нажмёт 💬. Если чат пуст — открываем первого пира (mDNS / входящее).
    fn select_peer_if_no_chat(&mut self, peer_id: PeerId) {
        if !self.selected_chat.is_empty() {
            return;
        }
        let s = peer_id.to_string();
        self.selected_chat = s.clone();
        self.messages.entry(s).or_insert_with(Vec::new);
        self.add_status(format!(
            "Открыт чат с {} — можно отправлять сообщения.",
            &peer_id.to_string()[..8]
        ));
    }

}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Включаем логи для отладки
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    // === Автоматически добавляем правило файрвола ===
    #[allow(unused_variables)]
    let exe_path = std::env::current_exe().unwrap_or_default();
    #[allow(unused_variables)]
    let exe = exe_path.display().to_string();

    #[cfg(target_os = "windows")]
    {
        // Проверяем, запущены ли мы уже от Администратора
        let is_admin = std::process::Command::new("net")
            .args(["session"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if is_admin {
            println!("Настраиваю файрвол Windows (Admin Mode)...");
            let _ = std::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=VOID P2P"])
                .output();
            let tcp_r = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=VOID P2P",
                    "dir=in",
                    "action=allow",
                    "protocol=TCP",
                    "localport=50001",
                    "profile=any",
                    "enable=yes",
                ])
                .output();
            let udp_r = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=VOID P2P",
                    "dir=in",
                    "action=allow",
                    "protocol=UDP",
                    "localport=50001",
                    "profile=any",
                    "edge=yes",
                    "enable=yes",
                ])
                .output();
            match (tcp_r, udp_r) {
                (Ok(t), Ok(u)) if t.status.success() && u.status.success() => {
                    println!("✅ Файрвол настроен (TCP + UDP разрешены)")
                }
                _ => println!("⚠ Не удалось настроить файрвол"),
            }
        } else {
            // Пишем команды в временный .bat файл, запускаем от админа через UAC
            let bat = format!(
                "@echo off\r\n\
                 netsh advfirewall firewall delete rule name=\"VOID P2P\"\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=TCP localport=50001 profile=any enable=yes\r\n\
                 netsh advfirewall firewall add rule name=\"VOID P2P\" dir=in action=allow protocol=UDP localport=50001 profile=any edge=yes enable=yes\r\n"
            );
            let bat_path = std::env::temp_dir().join("void_p2p_firewall.bat");
            if std::fs::write(&bat_path, bat).is_ok() {
                println!("Настраиваю файрвол (запрос UAC)...");
                // ShellExecute runas — самый надёжный способ UAC-элевации
                let result = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-Command",
                        &format!(
                            "Start-Process -FilePath '{}' -Verb RunAs -Wait",
                            bat_path.display()
                        ),
                    ])
                    .status();
                match result {
                    Ok(s) if s.success() => println!("✅ Файрвол настроен"),
                    _ => {
                        println!("⚠ UAC отклонён. Запустите вручную от Админастратора:");
                        println!("  {}", bat_path.display());
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        println!("Настраиваю файрвол macOS...");
        let _ = std::process::Command::new("sudo")
            .args([
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--add",
                &exe,
            ])
            .output();
        let _ = std::process::Command::new("sudo")
            .args([
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                "--unblockapp",
                &exe,
            ])
            .output();
        println!("✅ Файрвол macOS настроен");
    }

    let (local_key, local_nickname, static_secret, initial_address_book, initial_contact_addrs) =
        if let Ok(storage) = Storage::load() {
            let key = libp2p::identity::Keypair::from_protobuf_encoding(&storage.keypair_bytes)
                .expect("Failed to decode saved keypair");
            let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
            let my_id = PeerId::from(key.public());
            let mut book = HashMap::new();
            let mut addrs_map: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
            for entry in storage.address_book {
                if let Ok(pid) = entry.peer_id.parse::<PeerId>() {
                    if pid != my_id {
                        book.insert(pid, entry.display_name);
                        let mut parsed: Vec<Multiaddr> = entry
                            .addrs
                            .iter()
                            .filter_map(|s| s.parse::<Multiaddr>().ok())
                            .collect();
                        if !parsed.is_empty() {
                            addrs_map.entry(pid).or_default().append(&mut parsed);
                        }
                    }
                }
            }
            (key, storage.nickname, static_secret, book, addrs_map)
        } else {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let static_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
            let nickname = format!("User_{}", &PeerId::from(key.public()).to_string()[..4]);
            let _ = Storage::save(&nickname, Some(&key), Some(&static_secret), None);
            (
                key,
                nickname,
                static_secret,
                HashMap::new(),
                HashMap::new(),
            )
        };
    let local_peer_id = PeerId::from(local_key.public());

    println!("=== VOID P2P Chat ===");
    println!("Ваш Peer ID: {}", local_peer_id);
    println!("Ваш никнейм: {}", local_nickname);

    let void_bootstraps = void_bootstrap_multiaddrs();
    if void_bootstraps.is_empty() {
        println!(
            "🌐 Глобально: нет seed для DHT — задайте BUILTIN_VOID_BOOTSTRAP / VOID_BOOTSTRAP_PUBLIC_LIST_URL в коде, VOID_BOOTSTRAP_URL, VOID_BOOTSTRAP, void-bootstrap.txt, либо полный multiaddr собеседника. mDNS — только LAN."
        );
    } else {
        println!(
            "🌐 VOID bootstrap: {} multiaddr → заполнение DHT /void/kad/1.0.0 (без IPFS).",
            void_bootstraps.len()
        );
    }

    let (event_tx, event_rx) = mpsc::channel(256);
    let (command_tx, mut command_rx) = mpsc::channel(256);

    let event_tx_clone = event_tx.clone();
    let command_tx_for_mdns = command_tx.clone(); // для delayed dial из mDNS

    let static_secret_net = static_secret.clone();
    let void_bootstraps_for_net = void_bootstraps.clone();
    let contact_addrs_for_net: Vec<(PeerId, Multiaddr)> = initial_contact_addrs
        .iter()
        .flat_map(|(pid, addrs)| addrs.iter().cloned().map(move |a| (*pid, a)))
        .collect();
    tokio::spawn(async move {
        let event_tx = event_tx_clone;
        let command_tx_for_mdns = command_tx_for_mdns;
        let local_static = static_secret_net;
        let void_bootstraps = void_bootstraps_for_net;
        let contact_seed_addrs = contact_addrs_for_net;
        let mut sessions: HashMap<PeerId, crypto::SecureSession> = HashMap::new();
        let mut pending_handshakes: HashMap<PeerId, crypto::StaticSecret> = HashMap::new();
        let my_public_key = crypto::PublicKey::from(&local_static);

        // Swarm: TCP + noise + yamux + Relay Client
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                || {
                    let mut config = yamux::Config::default();
                    // SYNC CHECK: This should appear in your editor if synced.
                    config.set_max_num_streams(512);
                    config
                },
            )
            .unwrap()
            .with_quic()
            .with_dns()
            .unwrap()
            .with_relay_client(noise::Config::new, || {
                let mut config = yamux::Config::default();
                config.set_max_num_streams(512);
                config
            })
            .unwrap()
            .with_behaviour(|key, relay_client| {
                let local_peer_id = key.public().to_peer_id();

                // Kademlia: отдельный DHT VOID (/void/kad/1.0.0), не общий IPFS (/ipfs/kad/1.0.0).
                // Иначе в таблицу попадают тысячи чужих узлов и «поиск пира» оборачивается звонками на IPFS.
                let kad_store = kad::store::MemoryStore::new(local_peer_id);
                let mut kad_config = kad::Config::new(StreamProtocol::new("/void/kad/1.0.0"));
                // Переосвежаем routing table каждые 5 минут: без этого узел со временем
                // «проваливается» из DHT и новые контакты перестают находиться.
                kad_config.set_periodic_bootstrap_interval(Some(Duration::from_secs(5 * 60)));
                kad_config.set_query_timeout(Duration::from_secs(60));
                let mut kad = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
                kad.set_mode(Some(libp2p::kad::Mode::Server));

                for ma in &void_bootstraps {
                    if let Some(pid) = peer_id_from_multiaddr(ma) {
                        kad.add_address(&pid, ma.clone());
                    } else {
                        eprintln!("VOID bootstrap: нет /p2p/ в конце адреса, пропуск: {}", ma);
                    }
                }
                // Прогреваем kbuckets адресами контактов из vault — тогда
                // `send_request` к ним работает без предварительного ручного dial.
                for (pid, ma) in &contact_seed_addrs {
                    kad.add_address(pid, ma.clone());
                }
                if !void_bootstraps.is_empty() {
                    let _ = kad.bootstrap();
                }

                let rr_config = libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30)); // Увеличиваем тайм-аут до 30с
                let rr_protocol = libp2p::StreamProtocol::new("/void/chat/1.0.0");
                let rr_behaviour = libp2p::request_response::json::Behaviour::<V1Packet, V1Packet>::new(
                    [(rr_protocol, libp2p::request_response::ProtocolSupport::Full)],
                    rr_config.clone(),
                );

                // Отдельный request-response для файлового sub-протокола.
                // Тайм-аут 5 мин: большие файлы через relay могут идти долго.
                let file_rr_config = libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(300));
                let file_rr_protocol =
                    libp2p::StreamProtocol::new(file_transfer::FILE_PROTOCOL_ID);
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

                Ok(ChatBehaviour {
                    request_response: rr_behaviour,
                    file_rr: file_rr_behaviour,
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .unwrap(),
                    ping: ping::Behaviour::new(
                        ping::Config::new()
                            .with_interval(Duration::from_secs(20))
                            .with_timeout(Duration::from_secs(20)),
                    ),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "/void/v1".into(), // Фиксируем версию для всех
                        key.public(),
                    )),
                    kad,
                    relay: relay_client,
                    dcutr: dcutr::Behaviour::new(local_peer_id),
                    autonat: autonat::Behaviour::new(local_peer_id, Default::default()),
                    upnp: upnp::tokio::Behaviour::default(),
                })
            })
            .unwrap()
            .with_swarm_config(|c| {
                // Не закрываем idle-коннекты по таймеру: в мессенджере между
                // сообщениями легко проходят часы, а ping / identify / kad в
                // libp2p 0.56 не считаются «keep-alive» для свома. Старое
                // значение 120s давало каскад KeepAliveTimeout → реконнект →
                // `Os 48 AddrInUse` (TIME_WAIT на macOS). Закрытия мёртвых
                // коннектов мы всё равно получаем через transport-ошибки
                // стримов (ping/request-response) и TCP keepalive ОС.
                c.with_idle_connection_timeout(Duration::MAX)
                    .with_per_connection_event_buffer_size(256)
            })
            .build();

        // Слушаем TCP. Сначала пробуем 50001 (согласно правилам файрвола).
        let tcp_addr: Multiaddr = "/ip4/0.0.0.0/tcp/50001".parse().unwrap();

        if let Err(e) = swarm.listen_on(tcp_addr.clone()) {
            println!("⚠️ TCP порт 50001 занят ({:?}). Срочно ЗАКРОЙТЕ старые процессы или проверьте настройки.", e);
            let _ = event_tx
                .send(NetworkEvent::Status(
                    "⚠️ ПОРТ 50001 ЗАНЯТ! Закройте старые копии программы.".into(),
                ))
                .await;
            swarm
                .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
                .unwrap();
        }

        // Слушаем QUIC (50001 часто занят другим процессом на Windows — пробуем 50002, затем ОС).
        let quic_candidates = [
            "/ip4/0.0.0.0/udp/50001/quic-v1",
            "/ip4/0.0.0.0/udp/50002/quic-v1",
            "/ip4/0.0.0.0/udp/0/quic-v1",
        ];
        let mut quic_listening = false;
        for addr in quic_candidates {
            match swarm.listen_on(addr.parse::<Multiaddr>().unwrap()) {
                Ok(_) => {
                    println!("🚀 QUIC: {}", addr);
                    quic_listening = true;
                    break;
                }
                Err(e) => println!("⚠️ QUIC {}: {:?} — следующий вариант...", addr, e),
            }
        }
        if !quic_listening {
            println!("⚠️ QUIC не поднят ни на одном порту");
        }

        // Слушаем через Relay для работы за NAT
        let _ = swarm.listen_on("/p2p-circuit".parse().unwrap());

        let startup_status = if void_bootstraps.is_empty() {
            "🚀 Запущен. Интернет: полный multiaddr контакта или встроенный/URL seed (см. код), VOID_BOOTSTRAP, void-bootstrap.txt. LAN: mDNS.".to_string()
        } else {
            format!(
                "🚀 Запущен. VOID DHT: {} bootstrap-узл(ов) (без IPFS) + mDNS в LAN.",
                void_bootstraps.len()
            )
        };
        let _ = event_tx.send(NetworkEvent::Status(startup_status)).await;

        // Сразу пробуем дозвониться до сохранённых контактов: если они онлайн и
        // их адрес не сменился — связь появится в первые же секунды без
        // ручного «ПОДКЛЮЧИТЬ».
        for (pid, ma) in &contact_seed_addrs {
            let opts = DialOpts::peer_id(*pid)
                .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                .addresses(vec![ma.clone()])
                .build();
            if let Err(e) = swarm.dial(opts) {
                let s = format!("{:?}", e);
                if !s.contains("Condition") {
                    eprintln!("contact dial {} ({}): {:?}", pid, ma, e);
                }
            }
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
        // RequestId → PeerId для сообщений (Plain/Encrypted), чтобы по ответу
        // (Ack/прочее) однозначно подтвердить доставку конкретному пиру и снять
        // pending-ретраи в UI. Hello-handshake'ы сюда НЕ попадают.
        let mut outbound_msg_requests: HashMap<libp2p::request_response::OutboundRequestId, PeerId> = HashMap::new();
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

        loop {
            tokio::select! {
                // ─── Tick: отправка очередных чанков с rate-limit ───────────
                _ = chunk_tick.tick() => {
                    // Ищем одну исходящую передачу, готовую к отправке чанка.
                    let to_send: Option<([u8; 16], u32, Vec<u8>, PeerId)> = {
                        let mut found = None;
                        for (tid, t) in outgoing_transfers.iter_mut() {
                            if t.ready_to_send() {
                                let idx = t.next_chunk as u32;
                                let data = t.chunks[t.next_chunk].clone();
                                t.next_chunk += 1;
                                t.last_chunk_at = Instant::now();
                                found = Some((*tid, idx, data, t.peer));
                                break;
                            }
                        }
                        found
                    };
                    if let Some((tid, chunk_idx, data, peer)) = to_send {
                        let packet = file_transfer::FilePacket::Chunk {
                            transfer_id: tid,
                            chunk_index: chunk_idx,
                            data,
                        };
                        swarm.behaviour_mut().file_rr.send_request(&peer, packet);

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
                                println!(
                                    "📤 FILE[{}]: все {} чанк(ов) «{}» отправлены{}.",
                                    fkind.label(),
                                    total,
                                    fname,
                                    if is_relay { " (через relay)" } else { "" }
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
                                        format!("🔍 Запрос DHT: {}… (если кандидатов 0 — задайте VOID bootstrap или полный multiaddr)", &peer_id.to_string()[..16])
                                    )).await;
                                    swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                                }
                            }
                            UICommand::DialPeer(peer_id, addrs) => {
                                 let short = &peer_id.to_string()[..16];
                                 // Выкидываем loopback и виртуальные интерфейсы — чтобы
                                 // не тратить время на заведомо пустой dial.
                                 let addrs: Vec<Multiaddr> = addrs
                                     .into_iter()
                                     .filter(|addr| !is_junk_addr(addr))
                                     .collect();
                                 println!("🔌 UI_COMMAND: DialPeer {} ({} addresses)", short, addrs.len());

                                 for addr in &addrs {
                                     swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
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
                                          println!("❌ Dial ERROR для {}: {:?}", short, e);
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
                            UICommand::ReloadBootstrapFromSources => {
                                let addrs = void_bootstrap_multiaddrs();
                                if addrs.is_empty() {
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(
                                            "Нет seed: задайте BUILTIN/URL в коде, VOID_BOOTSTRAP или void-bootstrap.txt."
                                                .into(),
                                        ))
                                        .await;
                                } else {
                                    for ma in &addrs {
                                        if let Some(pid) = peer_id_from_multiaddr(ma) {
                                            swarm.behaviour_mut().kad.add_address(&pid, ma.clone());
                                            let _ = swarm.dial(ma.clone());
                                        }
                                    }
                                    let _ = swarm.behaviour_mut().kad.bootstrap();
                                    let _ = event_tx
                                        .send(NetworkEvent::Status(format!(
                                            "🌐 VOID: переподключение к {} seed (источники как при старте).",
                                            addrs.len()
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
                            UICommand::SendMessage { sender_name, text, recipient, is_retry: _is_retry } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
                                println!("[{}] 📤 UI_SEND: '{}' (To: {:?})", now, text, recipient);
                                let msg = ChatMessage {
                                    sender_id: local_peer_id.to_string(),
                                    sender_name: sender_name.clone(),
                                    recipient_id: recipient.map(|p| p.to_string()),
                                    text: text.clone(),
                                    timestamp: chrono::Local::now().format("%H:%M").to_string(),
                                };

                                let json_data = serde_json::to_vec(&msg).unwrap();
                                let mut packet = V1Packet::Plain(msg.clone());

                                if let Some(peer_id) = recipient {
                                    if let Some(session) = sessions.get_mut(&peer_id) {
                                        if let Ok((header, ciphertext)) = session.encrypt_payload(json_data.as_slice()) {
                                            packet = V1Packet::Encrypted { header, ciphertext };
                                            println!("[{}] 🔒 E2EE: Сообщение зашифровано для {}", now, &peer_id.to_string()[..8]);
                                        }
                                    } else {
                                        let ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                        let ephem_pub = crypto::PublicKey::from(&ephem_secret);
                                        pending_handshakes.insert(peer_id, ephem_secret);

                                        let hello = V1Packet::Hello {
                                            public_key: my_public_key.to_bytes(),
                                            ephemeral_key: ephem_pub.to_bytes(),
                                        };
                                        let _ = swarm.behaviour_mut().request_response.send_request(&peer_id, hello);
                                        println!("[{}] 🤝 E2EE: Сессии нет, направлен Hello (+Ephem) пиру {}", now, &peer_id.to_string()[..8]);
                                    }

                                    // Отправляем конкретному пиру и запоминаем RequestId,
                                    // чтобы по входящему Response отметить доставку и не ретраить.
                                    let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, packet);
                                    outbound_msg_requests.insert(req_id, peer_id);
                                    println!("[{}] 📨 RequestResponse: Отправка пиру {}", now, &peer_id.to_string()[..8]);
                                } else {
                                    println!("[{}] ⚠️ Попытка отправить сообщение без получателя (Global Chat отключен)", now);
                                }
                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                            }
                            // ─── Файловый sub-протокол ──────────────────────
                            UICommand::SendFile { recipient, path, kind } => {
                                let now = chrono::Local::now().format("%H:%M:%S").to_string();
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
                                        if data.len() as u64 > file_transfer::MAX_FILE_SIZE {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(format!(
                                                    "❌ Файл слишком большой (> {} МБ)",
                                                    file_transfer::MAX_FILE_SIZE / 1024 / 1024
                                                )))
                                                .await;
                                        } else {
                                            let sha256 = file_transfer::hash_file(&data);
                                            let chunks = file_transfer::split_into_chunks(&data);
                                            let total_chunks = chunks.len() as u32;
                                            let total_size = data.len() as u64;
                                            let filename = file_transfer::safe_filename(&path);
                                            // Уточняем тип по реальному расширению файла
                                            let file_kind = if kind == file_transfer::FileKind::Other {
                                                file_transfer::FileKind::from_filename(&filename)
                                            } else {
                                                kind
                                            };

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

                                            println!(
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
                            UICommand::AcceptFile { transfer_id, from, save_dir } => {
                                // Сохраняем выбранную директорию в состояние передачи.
                                if let Some(t) = incoming_transfers.get_mut(&transfer_id) {
                                    t.save_dir = save_dir.clone();
                                }
                                let packet = file_transfer::FilePacket::Accept { transfer_id };
                                swarm.behaviour_mut().file_rr.send_request(&from, packet);
                                println!(
                                    "✅ FILE: Accept transfer {:x?} от {} → {}",
                                    &transfer_id[..4],
                                    &from.to_string()[..8],
                                    save_dir.as_deref().unwrap_or("void_downloads/")
                                );
                            }
                            UICommand::RejectFile { transfer_id, from, reason } => {
                                let packet = file_transfer::FilePacket::Reject {
                                    transfer_id,
                                    reason: reason.clone(),
                                };
                                swarm.behaviour_mut().file_rr.send_request(&from, packet);
                                incoming_transfers.remove(&transfer_id);
                                println!(
                                    "✖ FILE: Reject transfer {:x?} ({})",
                                    &transfer_id[..4],
                                    reason
                                );
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
                                println!("🚫 Пропуск виртуального интерфейса: {}", address);
                                continue;
                            }
                            println!("📡 СЛУШАЮ: {}", address);

                            let is_external = !s.contains("/ip6/") && !s.contains("/0.0.0.0") && !s.contains("/127.0.0.1") || s.contains("p2p-circuit");

                            if is_external {
                                println!("  (Внешний/Relay): {}/p2p/{}", address, local_peer_id);
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
                                    println!(
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
                                if addr.to_string().contains("quic-v1") {
                                    println!("🔍 mDNS: найден пир {} (QUIC). Подключаюсь...", &peer_id.to_string()[..8]);
                                } else {
                                    println!("🔍 mDNS: найден пир {} (TCP). Подключаюсь...", &peer_id.to_string()[..8]);
                                }
                                let _ = swarm.dial(addr.clone());

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
                                        V1Packet::Hello { public_key, ephemeral_key } => {
                                            if peer != local_peer_id {
                                                let is_initiator = local_peer_id < peer;
                                                let _role_str = if is_initiator { "Initiator" } else { "Responder" };
                                                let session_exists = sessions.contains_key(&peer);

                                                if !session_exists {
                                                    let remote_static_pub = crypto::PublicKey::from(public_key);
                                                    let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);

                                                    if is_initiator {
                                                        // Alice получила Hello от Боба (как запрос)
                                                        if let Some(local_ephem_secret) = pending_handshakes.remove(&peer) {
                                                            let session = crypto::SecureSession::new_initiator(&local_static, &remote_static_pub, local_ephem_secret, &remote_ephem_pub);
                                                            sessions.insert(peer, session);
                                                            println!("[{}] 🤝 E2EE: Сессия (Alice/Req) создана с {}", now, &peer.to_string()[..8]);
                                                        }
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                                    } else {
                                                        // Боб получил Hello от Алисы
                                                        let local_ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                                        let local_ephem_pub = crypto::PublicKey::from(&local_ephem_secret);

                                                        let session = crypto::SecureSession::new_responder(&local_static, &remote_static_pub, &remote_ephem_pub, local_ephem_secret);
                                                        sessions.insert(peer, session);
                                                        println!("[{}] 🤝 E2EE: Сессия (Bob/Res) создана с {}", now, &peer.to_string()[..8]);

                                                        // Боб отвечает своим Hello
                                                        let my_hello = V1Packet::Hello {
                                                            public_key: my_public_key.to_bytes(),
                                                            ephemeral_key: local_ephem_pub.to_bytes(),
                                                        };
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, my_hello);
                                                    }
                                                } else {
                                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                                }
                                            }
                                        }
                                        V1Packet::Encrypted { header, ciphertext } => {
                                            if let Some(session) = sessions.get_mut(&peer) {
                                                if let Ok(plaintext) = session.decrypt_payload(&header, &ciphertext) {
                                                    if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                                                        println!("[{}] 🔒 E2EE: Сообщение ДЕШИФРОВАНО от {}", now, &peer.to_string()[..8]);
                                                        let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                                    }
                                                } else {
                                                    println!("[{}] ❌ E2EE: Ошибка дешифровки от {}. Сбрасываю...", now, &peer.to_string()[..8]);
                                                    sessions.remove(&peer);
                                                }
                                            }
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                        }
                                        V1Packet::Plain(msg) => {
                                            if peer != local_peer_id {
                                                println!("[{}] 📖 Текст открытый: {}", now, msg.text);
                                                let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                            }
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                        }
                                        V1Packet::Ack => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                        }
                                    }
                                }
                                libp2p::request_response::Message::Response { request_id, response } => {
                                    // Если это ответ на наше отправленное сообщение (Plain/Encrypted),
                                    // считаем доставку подтверждённой и сообщаем UI, чтобы он снял
                                    // соответствующий pending-ретрай и не показывал ошибку.
                                    if let Some(delivered_peer) = outbound_msg_requests.remove(&request_id) {
                                        println!("[{}] ✅ RR: Доставка подтверждена пиром {}", now, &delivered_peer.to_string()[..8]);
                                        let _ = event_tx.send(NetworkEvent::MessageDelivered(delivered_peer)).await;
                                    }
                                    match response {
                                        V1Packet::Hello { public_key, ephemeral_key } => {
                                            if peer != local_peer_id {
                                                let is_initiator = local_peer_id < peer;
                                                let session_exists = sessions.contains_key(&peer);
                                                if is_initiator && !session_exists {
                                                    // Алиса получила Hello от Боба (как ответ)
                                                    let remote_static_pub = crypto::PublicKey::from(public_key);
                                                    let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);
                                                    if let Some(local_ephem_secret) = pending_handshakes.remove(&peer) {
                                                        let session = crypto::SecureSession::new_initiator(&local_static, &remote_static_pub, local_ephem_secret, &remote_ephem_pub);
                                                        sessions.insert(peer, session);
                                                        println!("[{}] 🤝 E2EE: Сессия (Alice/Res) создана с {}", now, &peer.to_string()[..8]);
                                                    }
                                                }
                                            }
                                        }
                                        V1Packet::Encrypted { header, ciphertext } => {
                                            if let Some(session) = sessions.get_mut(&peer) {
                                                if let Ok(plaintext) = session.decrypt_payload(&header, &ciphertext) {
                                                    if let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plaintext) {
                                                        let _ = event_tx.send(NetworkEvent::ChatMessage(msg)).await;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::OutboundFailure { peer, request_id, error, .. })) => {
                            outbound_msg_requests.remove(&request_id);
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
                                println!("⚠️ [RR] OutFailure пиру {}: {:?}", peer, error);
                            }
                            match error {
                                libp2p::request_response::OutboundFailure::DialFailure => {
                                    if !is_dup {
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
                            println!("⚠️ [RR] InFailure от пира {}: {:?}", peer, error);
                        }
                        SwarmEvent::ExternalAddrConfirmed { address } => {
                            println!("🌍 ВНЕШНИЙ АДРЕС ПОДТВЕРЖДЕН: {}", address);
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
                            println!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. Всего пиров: {}", peer_id, endpoint, connected_count);
                            pending_dials.remove(&peer_id);

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
                                println!(
                                    "📡 FILE rate-limit: {} подключён через relay.",
                                    &peer_id.to_string()[..8]
                                );
                            } else {
                                relay_peers.remove(&peer_id);
                            }

                             if peer_id != local_peer_id {
                                 let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                                 let _ = event_tx.send(NetworkEvent::Status(format!("✅ СОЕДИНЕНО: {}", &peer_id.to_string()[..8]))).await;
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
                                 if let Some(addr) = learned {
                                     if !is_junk_addr(&addr) {
                                         let _ = event_tx
                                             .send(NetworkEvent::PeerAddress(peer_id, addr))
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
                                if let Some(addr) = addr {
                                    swarm.behaviour_mut().kad.add_address(&peer_id, addr);
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
                            println!("❌ СОЕДИНЕНИЕ ЗАКРЫТО: {}. Причина: {:?}. Осталось: {}", peer_id, cause, connected_count);
                            relay_peers.remove(&peer_id);
                            let _ = event_tx.send(NetworkEvent::Disconnected(peer_id)).await;
                        }
                        SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                            println!("📥 Входящее соединение: from {:?} to {:?}", send_back_addr, local_addr);
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
                                 println!("❌ ОШИБКА ИСХОДЯЩЕГО СОЕДИНЕНИЯ (peer: {}): {:?}", peer_str, error);
                                 let _ = event_tx.send(NetworkEvent::Status(
                                     format!("❌ Ошибка подключения: {}", peer_str)
                                 )).await;
                             } else {
                                 // В консоли пишем кратко
                                 if err_str.contains("Timeout") || err_str.contains("Handshake") {
                                     println!("ℹ️ [{}] Тайм-аут с {}. Проверьте ФАЙРВОЛ на обоих сторонах!", now, peer_str);
                                 } else if err_str.contains("10048") {
                                     println!("ℹ️ [{}] Ошибка 10048 (нормально для Windows): {}", now, peer_str);
                                 } else {
                                     println!("ℹ️ [{}] Техническая задержка/отказ (peer: {}): {}", now, peer_str, err_str);
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
                            let has_chat = info
                                .protocols
                                .iter()
                                .any(|p| p.as_ref() == "/void/chat/1.0.0");
                            println!(
                                "[{}] 🆔 Identify: {} — {} listen, {} протоколов{}",
                                now,
                                peer_id,
                                info.listen_addrs.len(),
                                info.protocols.len(),
                                if has_chat { "" } else { "  ⚠️ БЕЗ /void/chat/1.0.0 (bootstrap/чужая версия)" }
                            );
                            if !has_chat && peer_id != local_peer_id {
                                let _ = event_tx
                                    .send(NetworkEvent::PeerIsNotVoidChat(peer_id))
                                    .await;
                            }
                            for addr in info.listen_addrs {
                                // Не тащим к себе заведомо-невалидные адреса пира
                                // (VirtualBox/Docker/link-local). Они только
                                // провоцируют долгие таймауты в dial.
                                if is_junk_addr(&addr) {
                                    continue;
                                }
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                // Если это настоящий VOID-клиент — сохраним один его
                                // listen-адрес в контактной книге, чтобы связь поднялась
                                // после рестарта без ручного ПОДКЛЮЧИТЬ.
                                if has_chat && peer_id != local_peer_id {
                                    let mut a = addr.clone();
                                    // Если в addr нет /p2p/<peer_id>, добавим — иначе Dial потом
                                    // не свяжет адрес с PeerId.
                                    if !a.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2p(_))) {
                                        a.push(libp2p::multiaddr::Protocol::P2p(peer_id));
                                    }
                                    let _ = event_tx
                                        .send(NetworkEvent::PeerAddress(peer_id, a))
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
                            println!("🆔 Identify: Отправлена информация пиру {}", peer_id);
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(identify::Event::Error { peer_id, error, .. })) => {
                            let err_str = error.to_string();
                            let err_lower = err_str.to_lowercase();
                            if err_lower.contains("negotiat") || err_lower.contains("failed to negotiate") || err_lower.contains("support") {
                                println!("❌ [КРИТИЧНО] Identify: Несовпадение версий с {}.", peer_id);
                                println!("🔥 Срочно ОБНОВИТЕ другое приложение и ЗАКРОЙТЕ старые процессы!");
                                let _ = event_tx.send(NetworkEvent::Status(
                                    format!("❌ ОШИБКА: Пир {}... использует СТАРУЮ ВЕРСИЮ!", &peer_id.to_string()[..8])
                                )).await;
                            } else {
                                println!("🆔 Identify: Ошибка с пиром {}: {:?}", peer_id, error);
                            }
                        }

                        SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. })) => {
                            match result {
                                 libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                    println!(
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
                                            println!(
                                                "📍 В таблице есть целевой пир {} — набираю ({} адр.)",
                                                &wanted.to_string()[..8],
                                                hit.addrs.len()
                                            );
                                            let _ = command_tx_for_mdns.try_send(UICommand::DialPeer(
                                                hit.peer_id,
                                                hit.addrs.clone(),
                                            ));
                                        } else if ok.peers.is_empty() {
                                            println!(
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
                                            println!(
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
                                    println!("⚠️ Kademlia get_closest_peers: {:?}", e);
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
                            println!(
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
                                    match request {
                                        FilePacket::Offer {
                                            transfer_id,
                                            filename,
                                            total_size,
                                            total_chunks,
                                            sha256,
                                            kind,
                                        } => {
                                            println!(
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
                                            println!(
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
                                            println!(
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
                                            let done = if let Some(inc) =
                                                incoming_transfers.get_mut(&transfer_id)
                                            {
                                                inc.receive_chunk(chunk_index, data)
                                            } else {
                                                false
                                            };

                                            if let Some(inc) =
                                                incoming_transfers.get(&transfer_id)
                                            {
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
                                                    // Проверяем хэш и сохраняем файл.
                                                    let sha_expected = inc.sha256;
                                                    let maybe_data = inc.assemble();
                                                    if let Some(data) = maybe_data {
                                                        let sha_actual =
                                                            file_transfer::hash_file(&data);
                                                        if sha_actual != sha_expected {
                                                            println!(
                                                                "[{}] ❌ FILE: хэш не совпадает для «{}»!",
                                                                now, fname
                                                            );
                                                            let _ = event_tx
                                                                .send(NetworkEvent::FileError {
                                                                    transfer_id,
                                                                    reason: format!(
                                                                        "Ошибка целостности файла «{}»",
                                                                        fname
                                                                    ),
                                                                })
                                                                .await;
                                                        } else {
                                                            let save_path = if let Some(ref dir) =
                                                                incoming_transfers
                                                                    .get(&transfer_id)
                                                                    .and_then(|t| t.save_dir.clone())
                                                            {
                                                                file_transfer::unique_download_path_in(
                                                                    dir, &fname,
                                                                )
                                                            } else {
                                                                file_transfer::unique_download_path(
                                                                    &fname,
                                                                )
                                                            };
                                                            let saved_to =
                                                                save_path.display().to_string();
                                                            match std::fs::write(&save_path, &data) {
                                                                Ok(_) => {
                                                                    println!(
                                                                        "[{}] ✅ FILE: «{}» сохранён → {}",
                                                                        now, fname, saved_to
                                                                    );
                                                                    let _ = event_tx
                                                                        .send(
                                                                            NetworkEvent::FileComplete {
                                                                                transfer_id,
                                                                                filename: fname,
                                                                                saved_to,
                                                                                is_outgoing: false,
                                                                                peer,
                                                                            },
                                                                        )
                                                                        .await;
                                                                }
                                                                Err(e) => {
                                                                    let _ = event_tx
                                                                        .send(NetworkEvent::FileError {
                                                                            transfer_id,
                                                                            reason: format!(
                                                                                "Не удалось сохранить «{}»: {}",
                                                                                fname, e
                                                                            ),
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
                            println!(
                                "⚠️ [FILE RR] OutFailure пиру {}: {:?}",
                                &peer.to_string()[..8],
                                error
                            );
                        }
                        SwarmEvent::Behaviour(ChatBehaviourEvent::FileRr(
                            libp2p::request_response::Event::InboundFailure { peer, error, .. },
                        )) => {
                            println!(
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
    });

    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([820.0, 540.0])
        .with_title(format!("VOID Chat [{}]", &local_peer_id.to_string()[..8]));

    eframe::run_native(
        &format!("VOID Chat [{}]", local_peer_id.to_string()[..8].to_string()),
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(move |cc| {
            Ok(Box::new(App::new(
                cc,
                local_peer_id,
                local_nickname,
                static_secret,
                initial_address_book,
                initial_contact_addrs,
                command_tx,
                event_rx,
            )))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
