mod crypto;
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
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// `PeerId` с конца multiaddr (`.../p2p/<id>`).
fn peer_id_from_multiaddr(ma: &Multiaddr) -> Option<PeerId> {
    ma.iter().last().and_then(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
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

#[derive(Serialize, Deserialize, Clone)]
struct AddressBookEntry {
    peer_id: String,
    display_name: String,
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
    /// Получен Response (Ack/прочее) на ранее отправленное сообщение пиру —
    /// сигнал UI снять одно ожидание из `pending_sends` и не показывать ошибку.
    MessageDelivered(PeerId),
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
}

#[derive(NetworkBehaviour)]
struct ChatBehaviour {
    request_response: libp2p::request_response::json::Behaviour<V1Packet, V1Packet>,
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

/// Плавающее уведомление в правом верхнем углу.
struct Toast {
    text: String,
    expires_at: Instant,
    kind: ToastKind,
}

#[derive(Clone, Copy)]
enum ToastKind {
    Info,
    Warn,
    Error,
}

const RESEND_GRACE: Duration = Duration::from_secs(3);
const RESEND_DELAY: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: u8 = 2;
const TOAST_TTL_SHORT: Duration = Duration::from_secs(4);
const TOAST_TTL_LONG: Duration = Duration::from_secs(7);

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
}

impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        local_peer_id: PeerId,
        local_nickname: String,
        local_static: crypto::StaticSecret,
        initial_address_book: HashMap<PeerId, String>,
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
        }
    }

    /// Лениво грузит `static/icon.png` в GPU-текстуру и возвращает её id.
    /// PNG вшит в бинарь, так что отдельный файл при запуске не нужен.
    fn ensure_chat_bg(&mut self, ctx: &egui::Context) -> Option<egui::TextureId> {
        if self.chat_bg_texture.is_none() {
            const BYTES: &[u8] = include_bytes!("../static/icon.png");
            match image::load_from_memory(BYTES) {
                Ok(img) => {
                    let rgba = img.to_rgba8();
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let pixels = rgba.into_raw();
                    let color_image =
                        egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                    let handle = ctx.load_texture(
                        "chat_bg_icon",
                        color_image,
                        egui::TextureOptions::LINEAR,
                    );
                    self.chat_bg_texture = Some(handle);
                }
                Err(e) => {
                    eprintln!("VOID: не удалось декодировать static/icon.png: {}", e);
                }
            }
        }
        self.chat_bg_texture.as_ref().map(|h| h.id())
    }

    /// Сохраняет ник и записную книгу в `vault.bin` (AES-GCM, ключ в `void.key`).
    fn persist_vault(&self) {
        let mut entries: Vec<AddressBookEntry> = self
            .known_peers
            .iter()
            .map(|(pid, name)| AddressBookEntry {
                peer_id: pid.to_string(),
                display_name: name.clone(),
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

    /// Рендерит активные toast'ы как floating Area в правом верхнем углу,
    /// стопкой сверху вниз. Каждый toast — закруглённая «пилюля» с акцент-цветом
    /// слева и подписью.
    fn draw_toasts(&mut self, ctx: &egui::Context) {
        if self.toasts.is_empty() {
            return;
        }
        let screen = ctx.screen_rect();
        let anchor = egui::pos2(screen.right() - 16.0, screen.top() + 72.0);
        let now = Instant::now();

        for (i, t) in self.toasts.iter().enumerate() {
            // Прозрачность: плавное затухание в последнюю секунду жизни.
            let remaining = t.expires_at.saturating_duration_since(now).as_secs_f32();
            let alpha = (remaining.min(1.0) * 255.0).clamp(40.0, 255.0) as u8;
            let (accent, bg) = match t.kind {
                ToastKind::Info => (palette::ACCENT_2, palette::BG_CARD),
                ToastKind::Warn => (palette::ACCENT, palette::BG_CARD),
                ToastKind::Error => (
                    egui::Color32::from_rgb(0xff, 0x6a, 0x88),
                    palette::BG_CARD,
                ),
            };
            let accent = egui::Color32::from_rgba_unmultiplied(
                accent.r(),
                accent.g(),
                accent.b(),
                alpha,
            );
            let bg = egui::Color32::from_rgba_unmultiplied(bg.r(), bg.g(), bg.b(), alpha);

            egui::Area::new(egui::Id::new(("toast_area", i)))
                .order(egui::Order::Tooltip)
                .anchor(
                    egui::Align2::RIGHT_TOP,
                    egui::vec2(
                        anchor.x - screen.right(),
                        anchor.y - screen.top() + (i as f32) * 56.0,
                    ),
                )
                .interactable(false)
                .show(ctx, |ui| {
                    egui::Frame::none()
                        .fill(bg)
                        .stroke(egui::Stroke::new(1.0, accent))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                        .shadow(egui::epaint::Shadow {
                            offset: egui::vec2(0.0, 4.0),
                            blur: 18.0,
                            spread: 0.0,
                            color: egui::Color32::from_rgba_premultiplied(0, 0, 0, 120),
                        })
                        .show(ui, |ui| {
                            ui.set_max_width(360.0);
                            ui.horizontal(|ui| {
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_size(
                                        ui.cursor().left_top(),
                                        egui::vec2(3.0, 18.0),
                                    ),
                                    1.5,
                                    accent,
                                );
                                ui.add_space(10.0);
                                ui.label(
                                    egui::RichText::new(&t.text)
                                        .size(13.0)
                                        .color(egui::Color32::from_rgba_unmultiplied(
                                            palette::TEXT.r(),
                                            palette::TEXT.g(),
                                            palette::TEXT.b(),
                                            alpha,
                                        )),
                                );
                            });
                        });
                });
        }
    }

    /// Кладёт toast в очередь рендера. Дубликаты с тем же текстом не накапливаем.
    fn push_toast(&mut self, text: String, kind: ToastKind, ttl: Duration) {
        if self.toasts.iter().any(|t| t.text == text) {
            return;
        }
        self.toasts.push(Toast {
            text,
            expires_at: Instant::now() + ttl,
            kind,
        });
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

    // =====================================================================
    //  НОВЫЙ Telegram-подобный sidebar (космическая палитра)
    // =====================================================================
    fn ui_sidebar(&mut self, ui: &mut egui::Ui) {
        let avail = ui.available_width();

        // -------- Шапка профиля --------
        egui::Frame::none()
            .fill(palette::BG_PANEL)
            .inner_margin(egui::Margin {
                left: 16.0,
                right: 16.0,
                top: 16.0,
                bottom: 12.0,
            })
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    draw_avatar(
                        ui,
                        &self.local_peer_id.to_string(),
                        &self.local_nickname,
                        46.0,
                        Some(true),
                    );
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        let inner_w = (avail - 78.0).max(60.0);
                        ui.set_width(inner_w);
                        let nick_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.local_nickname)
                                .desired_width(inner_w)
                                .frame(false)
                                .font(egui::TextStyle::Heading),
                        );
                        if nick_resp.lost_focus() {
                            self.persist_vault();
                        }
                        let pid = self.local_peer_id.to_string();
                        // Полный Peer ID: выделяется мышью (Ctrl+C работает штатно),
                        // переносится по ширине карточки, клик копирует всё целиком.
                        let r = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&pid)
                                    .size(11.5)
                                    .monospace()
                                    .color(palette::TEXT_MUTED),
                            )
                            .wrap()
                            .selectable(true)
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_text("Клик — копировать Peer ID целиком");
                        if r.clicked() {
                            ui.output_mut(|o| o.copied_text = pid.clone());
                            self.add_status("Скопирован Peer ID".into());
                        }
                        if let Some(ip) = &self.public_ip {
                            ui.label(
                                egui::RichText::new(format!("◐ {ip}"))
                                    .size(11.0)
                                    .color(palette::ACCENT_2),
                            );
                        }
                    });
                });
            });

        // -------- Поиск --------
        egui::Frame::none()
            .inner_margin(egui::Margin {
                left: 12.0,
                right: 12.0,
                top: 0.0,
                bottom: 8.0,
            })
            .show(ui, |ui| {
                let id = egui::Id::new("void_search_query");
                let mut buf: String =
                    ui.memory_mut(|m| m.data.get_temp::<String>(id).unwrap_or_default());
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut buf)
                        .hint_text("🔍   Поиск контактов")
                        .desired_width(f32::INFINITY),
                );
                if resp.changed() {
                    ui.memory_mut(|m| m.data.insert_temp(id, buf.clone()));
                }
            });

        // тонкий разделитель
        let sep_rect = ui
            .allocate_space(egui::vec2(ui.available_width(), 1.0))
            .1;
        ui.painter().rect_filled(sep_rect, 0.0, palette::DIVIDER);

        // -------- Список контактов --------
        let search: String = ui
            .memory(|m| m.data.get_temp::<String>(egui::Id::new("void_search_query")))
            .unwrap_or_default()
            .to_lowercase();

        egui::ScrollArea::vertical()
            .id_salt("contacts_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(4.0);

                let mut peers: Vec<(PeerId, String)> = self
                    .known_peers
                    .iter()
                    .map(|(p, n)| (*p, n.clone()))
                    .collect();
                peers.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));

                let mut to_remove: Vec<PeerId> = Vec::new();
                let me_str = self.local_peer_id.to_string();

                if peers.is_empty() {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            egui::RichText::new("✦")
                                .size(40.0)
                                .color(palette::ACCENT_2),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("Контактов пока нет")
                                .color(palette::TEXT)
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new("Войдите в сеть VOID или\nдобавьте Peer ID вручную")
                                .color(palette::TEXT_MUTED)
                                .size(12.0),
                        );
                    });
                    ui.add_space(20.0);
                }

                for (peer_id, name) in &peers {
                    if !search.is_empty()
                        && !name.to_lowercase().contains(&search)
                        && !peer_id.to_string().to_lowercase().contains(&search)
                    {
                        continue;
                    }
                    let peer_str = peer_id.to_string();
                    let is_selected = self.selected_chat == peer_str;

                    let last_msg: Option<&ChatMessage> =
                        self.messages.get(&peer_str).and_then(|v| v.last());
                    let preview = match last_msg {
                        Some(m) if m.sender_id == me_str => format!("Вы: {}", m.text),
                        Some(m) => m.text.clone(),
                        None => "Нажмите, чтобы написать…".to_string(),
                    };
                    let time_str = last_msg
                        .map(|m| short_time(&m.timestamp))
                        .unwrap_or_default();

                    let bg = if is_selected {
                        palette::BG_SELECTED
                    } else {
                        egui::Color32::TRANSPARENT
                    };

                    let inner = egui::Frame::none()
                        .fill(bg)
                        .rounding(10.0)
                        .inner_margin(egui::Margin {
                            left: 10.0,
                            right: 10.0,
                            top: 8.0,
                            bottom: 8.0,
                        })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                draw_avatar(ui, &peer_str, name, 42.0, None);
                                ui.add_space(10.0);
                                ui.vertical(|ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(name)
                                                .strong()
                                                .color(palette::TEXT)
                                                .size(14.5),
                                        );
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    egui::RichText::new(&time_str)
                                                        .size(10.5)
                                                        .color(palette::TEXT_MUTED),
                                                );
                                            },
                                        );
                                    });
                                    ui.label(
                                        egui::RichText::new(truncate_text(&preview, 40))
                                            .color(palette::TEXT_MUTED)
                                            .size(12.5),
                                    );
                                });
                            });
                        })
                        .response;

                    let click = inner.interact(egui::Sense::click());
                    if click.clicked() {
                        self.selected_chat = peer_str.clone();
                        self.messages.entry(peer_str.clone()).or_insert_with(Vec::new);
                    }
                    click.context_menu(|ui| {
                        ui.label(
                            egui::RichText::new("Контакт")
                                .color(palette::TEXT_MUTED)
                                .size(11.0),
                        );
                        ui.separator();
                        let buf = self
                            .peer_name_edits
                            .entry(*peer_id)
                            .or_insert_with(|| name.clone());
                        let r = ui.add(
                            egui::TextEdit::singleline(buf)
                                .desired_width(220.0)
                                .hint_text("Новое имя"),
                        );
                        if r.lost_focus() {
                            let trimmed = buf.trim().to_string();
                            if !trimmed.is_empty() && trimmed != *name {
                                self.known_peers.insert(*peer_id, trimmed.clone());
                                *buf = trimmed;
                                self.persist_vault();
                            }
                            ui.close_menu();
                        }
                        if ui.button("📋 Копировать Peer ID").clicked() {
                            ui.output_mut(|o| o.copied_text = peer_str.clone());
                            ui.close_menu();
                        }
                        if ui.button("🗑 Удалить контакт").clicked() {
                            to_remove.push(*peer_id);
                            ui.close_menu();
                        }
                    });
                }

                if !to_remove.is_empty() {
                    for pid in to_remove {
                        let p = pid.to_string();
                        self.known_peers.remove(&pid);
                        self.peer_name_edits.remove(&pid);
                        self.messages.remove(&p);
                        if self.selected_chat == p {
                            self.selected_chat.clear();
                        }
                    }
                    self.persist_vault();
                }

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(8.0);

                // -------- ➕ Добавить контакт --------
                ui.collapsing(
                    egui::RichText::new("➕  Добавить контакт")
                        .color(palette::ACCENT)
                        .strong(),
                    |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.add_contact_peer)
                                .hint_text("Peer ID")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.add_contact_name)
                                .hint_text("Имя в записной книге")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(8.0);
                        let save = ui.add_sized(
                            [ui.available_width(), 34.0],
                            egui::Button::new(
                                egui::RichText::new("Сохранить (зашифровано)")
                                    .color(palette::TEXT)
                                    .strong(),
                            )
                            .fill(palette::ACCENT),
                        );
                        if save.clicked() {
                            let pid_t = self.add_contact_peer.trim().to_string();
                            let name_t = self.add_contact_name.trim().to_string();
                            if !pid_t.is_empty() && !name_t.is_empty() {
                                if let Ok(pid) = pid_t.parse::<PeerId>() {
                                    if pid != self.local_peer_id {
                                        self.known_peers.insert(pid, name_t);
                                        self.persist_vault();
                                        self.add_contact_peer.clear();
                                        self.add_contact_name.clear();
                                    }
                                } else {
                                    self.add_status("Некорректный Peer ID".into());
                                }
                            }
                        }
                    },
                );

                ui.add_space(6.0);

                // -------- 🛰  Сеть VOID --------
                ui.collapsing(
                    egui::RichText::new("🛰   Сеть VOID")
                        .color(palette::ACCENT_2)
                        .strong(),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("Подключено:")
                                    .color(palette::TEXT_MUTED)
                                    .size(12.0),
                            );
                            ui.label(
                                egui::RichText::new(format!("{}", self.connected_peers))
                                    .color(palette::ONLINE)
                                    .strong(),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("DHT-таблица:")
                                    .color(palette::TEXT_MUTED)
                                    .size(12.0),
                            );
                            ui.label(
                                egui::RichText::new(format!("{} узл.", self.dht_routing_total))
                                    .color(palette::ACCENT_2),
                            );
                        });
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("Войти в сеть через IP")
                                .color(palette::TEXT_MUTED)
                                .size(11.5),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.void_bootstrap_draft)
                                .hint_text("157.22.192.234")
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                        ui.add_space(6.0);
                        let join = ui.add_sized(
                            [ui.available_width(), 32.0],
                            egui::Button::new(
                                egui::RichText::new("🌐 Войти в VOID")
                                    .color(palette::TEXT)
                                    .strong(),
                            )
                            .fill(palette::ACCENT),
                        );
                        if join.clicked() {
                            let input = self.void_bootstrap_draft.trim().to_string();
                            if input.is_empty() {
                                self.add_status("⚠ Введите IP другой ноды".into());
                            } else {
                                let _ = self
                                    .command_tx
                                    .try_send(UICommand::JoinViaNode(input.clone()));
                                self.add_status(format!("Вход в сеть через {input}…"));
                            }
                        }
                        ui.add_space(4.0);
                        if ui
                            .button(
                                egui::RichText::new("Переподключить seed").color(palette::TEXT),
                            )
                            .clicked()
                        {
                            let _ = self
                                .command_tx
                                .try_send(UICommand::ReloadBootstrapFromSources);
                        }
                        if ui
                            .button(egui::RichText::new("Снимок DHT").color(palette::TEXT))
                            .clicked()
                        {
                            let _ = self
                                .command_tx
                                .try_send(UICommand::SnapshotDhtRoutingPeers);
                        }
                    },
                );

                ui.add_space(6.0);

                // -------- 🔌 Прямое подключение --------
                ui.collapsing(
                    egui::RichText::new("🔌  Прямое подключение")
                        .color(palette::ACCENT_2)
                        .strong(),
                    |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.dial_address)
                                .hint_text("Peer ID или Multiaddr")
                                .desired_width(f32::INFINITY),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Подключить")
                                            .color(palette::TEXT),
                                    )
                                    .fill(palette::BG_HOVER),
                                )
                                .clicked()
                                && !self.dial_address.is_empty()
                            {
                                let input = self.dial_address.trim().to_string();
                                if let Ok(pid) = input.parse::<PeerId>() {
                                    if pid == self.local_peer_id {
                                        self.add_status(
                                            "Это ваш собственный PeerId.".into(),
                                        );
                                    } else {
                                        let _ =
                                            self.command_tx.try_send(UICommand::SearchPeer(pid));
                                    }
                                } else {
                                    let _ = self.command_tx.try_send(UICommand::Dial(input));
                                }
                                self.dial_address.clear();
                            }
                            if ui
                                .button(
                                    egui::RichText::new("📋 Свой ID").color(palette::TEXT),
                                )
                                .clicked()
                            {
                                ui.output_mut(|o| {
                                    o.copied_text = self.local_peer_id.to_string()
                                });
                            }
                        });
                    },
                );

                ui.add_space(14.0);
            });
    }
}

// ============================================================
//  ВИЗУАЛ: космическая палитра + helpers (Telegram-like layout)
// ============================================================

mod palette {
    use eframe::egui::Color32;
    // База фона: #16232B — взято с пользовательского эталона. Остальные оттенки
    // выведены из неё, чтобы сохранить «лестницу» глубина→панель→карточка→hover→selected.
    pub const BG_DEEP:       Color32 = Color32::from_rgb(0x0f, 0x1b, 0x22); // глубокий тон под панелями
    pub const BG_PANEL:      Color32 = Color32::from_rgb(0x16, 0x23, 0x2b); // sidebar / главный фон
    pub const BG_CHAT:       Color32 = Color32::from_rgb(0x16, 0x23, 0x2b); // чат — единый тон с sidebar
    pub const BG_CARD:       Color32 = Color32::from_rgb(0x1c, 0x2d, 0x38); // карточки/инпуты
    pub const BG_HOVER:      Color32 = Color32::from_rgb(0x23, 0x36, 0x46);
    pub const BG_SELECTED:   Color32 = Color32::from_rgb(0x2a, 0x40, 0x53);
    pub const DIVIDER:       Color32 = Color32::from_rgb(0x34, 0x4c, 0x61);
    pub const TEXT:          Color32 = Color32::from_rgb(0xe8, 0xec, 0xf8);
    pub const TEXT_MUTED:    Color32 = Color32::from_rgb(0x7d, 0x86, 0xa8);
    pub const ACCENT:        Color32 = Color32::from_rgb(0x7c, 0x5c, 0xff); // cosmic violet
    pub const ACCENT_2:      Color32 = Color32::from_rgb(0x5c, 0xc7, 0xff); // starlight cyan
    pub const BUBBLE_ME:     Color32 = Color32::from_rgb(0x32, 0x3f, 0x88);
    pub const BUBBLE_THEM:   Color32 = Color32::from_rgb(0x14, 0x18, 0x33);
    pub const ONLINE:        Color32 = Color32::from_rgb(0x3a, 0xd6, 0x8b);
    pub const NEBULA_VIOLET: Color32 = Color32::from_rgba_premultiplied(0x55, 0x28, 0x88, 170);
    pub const NEBULA_BLUE:   Color32 = Color32::from_rgba_premultiplied(0x18, 0x40, 0x90, 140);
    pub const STAR:          Color32 = Color32::from_rgb(0xd8, 0xe0, 0xf0);
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> egui::Color32 {
    let c = v * s;
    let hh = (h / 60.0).rem_euclid(6.0);
    let x = c * (1.0 - (hh.rem_euclid(2.0) - 1.0).abs());
    let (r, g, b) = if hh < 1.0 { (c, x, 0.0) }
        else if hh < 2.0 { (x, c, 0.0) }
        else if hh < 3.0 { (0.0, c, x) }
        else if hh < 4.0 { (0.0, x, c) }
        else if hh < 5.0 { (x, 0.0, c) }
        else             { (c, 0.0, x) };
    let m = v - c;
    egui::Color32::from_rgb(
        (((r + m) * 255.0) as u32).min(255) as u8,
        (((g + m) * 255.0) as u32).min(255) as u8,
        (((b + m) * 255.0) as u32).min(255) as u8,
    )
}

/// Цвет, выводимый детерминированно из строки (peer_id) — для аватаров.
fn deterministic_color(seed: &str) -> egui::Color32 {
    let mut h: u64 = 0x9e37_79b9_7f4a_7c15;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    // диапазон оттенков 200..360 + 0..40 = холодный край (синий → фиолетовый → магента)
    let raw = (h % 200) as f32; // 0..200
    let hue = (200.0 + raw) % 360.0;
    hsv_to_rgb(hue, 0.55, 0.78)
}

/// Кружок-аватар с инициалом и (опц.) индикатором онлайна.
fn draw_avatar(
    ui: &mut egui::Ui,
    seed: &str,
    label: &str,
    size: f32,
    online: Option<bool>,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return resp;
    }
    let painter = ui.painter();
    let bg = deterministic_color(seed);
    // мягкое свечение
    painter.circle_filled(
        rect.center(),
        size / 2.0 + 2.5,
        egui::Color32::from_rgba_premultiplied(bg.r(), bg.g(), bg.b(), 50),
    );
    painter.circle_filled(rect.center(), size / 2.0, bg);
    let initial: String = label
        .trim()
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".into());
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initial,
        egui::FontId::new(size * 0.46, egui::FontFamily::Proportional),
        palette::TEXT,
    );
    if let Some(true) = online {
        let dot_r = (size * 0.16).max(4.0);
        let dot_pos = egui::pos2(rect.right() - dot_r, rect.bottom() - dot_r);
        painter.circle_filled(dot_pos, dot_r + 1.6, palette::BG_PANEL);
        painter.circle_filled(dot_pos, dot_r, palette::ONLINE);
    }
    resp
}

/// Один раз генерируемое случайное «звёздное небо» (нормализованные координаты).
fn starfield() -> &'static [(f32, f32, f32, u8)] {
    use std::sync::OnceLock;
    static STARS: OnceLock<Vec<(f32, f32, f32, u8)>> = OnceLock::new();
    STARS.get_or_init(|| {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..240)
            .map(|_| {
                (
                    rng.gen::<f32>(),
                    rng.gen::<f32>(),
                    rng.gen_range(0.6_f32..2.2),
                    rng.gen_range(110_u8..245),
                )
            })
            .collect()
    })
}

/// Рисует `static/icon.png` как фон области диалогов в режиме «cover»:
/// картинка центрируется и масштабируется так, чтобы заполнить всю область
/// без пустых полей; clip самой панели обрежет лишнее. Поверх кладётся
/// лёгкое затемнение для читаемости пузырей сообщений.
fn draw_chat_bg_image(
    painter: &egui::Painter,
    rect: egui::Rect,
    tex_id: egui::TextureId,
    tex_size: egui::Vec2,
) {
    if tex_size.x <= 0.0 || tex_size.y <= 0.0 || rect.width() <= 0.0 || rect.height() <= 0.0 {
        return;
    }
    let scale = (rect.width() / tex_size.x).max(rect.height() / tex_size.y);
    let scaled = egui::vec2(tex_size.x * scale, tex_size.y * scale);
    let img_rect = egui::Rect::from_center_size(rect.center(), scaled);
    let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
    painter.image(tex_id, img_rect, uv, egui::Color32::WHITE);
    // Затемняющая вуаль — без неё bubbles теряются на ярких участках обоев.
    painter.rect_filled(
        rect,
        0.0,
        egui::Color32::from_rgba_unmultiplied(0, 0, 0, 110),
    );
}

/// Звёзды + две туманности, рисуем как фон чата.
fn draw_starfield(painter: &egui::Painter, rect: egui::Rect) {
    // туманности (несколько концентрических кругов с убывающей альфой = soft glow)
    let blob = |c: egui::Pos2, r: f32, color: egui::Color32| {
        for i in 0..9 {
            let alpha = ((color.a() as f32) / (i as f32 + 1.4)) as u8;
            painter.circle_filled(
                c,
                r * (i as f32 / 9.0 + 0.3),
                egui::Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), alpha),
            );
        }
    };
    let nebula1 = egui::pos2(
        rect.left() + rect.width() * 0.22,
        rect.top() + rect.height() * 0.24,
    );
    let nebula2 = egui::pos2(
        rect.left() + rect.width() * 0.78,
        rect.top() + rect.height() * 0.72,
    );
    let scale = rect.width().min(rect.height());
    blob(nebula1, scale * 0.55, palette::NEBULA_VIOLET);
    blob(nebula2, scale * 0.45, palette::NEBULA_BLUE);

    // звёзды
    for (xf, yf, r, a) in starfield() {
        let pos = egui::pos2(rect.left() + xf * rect.width(), rect.top() + yf * rect.height());
        painter.circle_filled(
            pos,
            *r,
            egui::Color32::from_rgba_premultiplied(
                palette::STAR.r(),
                palette::STAR.g(),
                palette::STAR.b(),
                *a,
            ),
        );
    }
}

fn truncate_text(s: &str, max_chars: usize) -> String {
    let mut count = 0usize;
    let mut out = String::new();
    for ch in s.chars() {
        if count >= max_chars {
            out.push('…');
            return out;
        }
        out.push(ch);
        count += 1;
    }
    out
}

/// Из "2026-04-18 14:30:45" берём "14:30".
fn short_time(ts: &str) -> String {
    let last = ts.split_whitespace().last().unwrap_or(ts);
    last.split(':').take(2).collect::<Vec<_>>().join(":")
}

fn setup_custom_style(ctx: &egui::Context) {
    use egui::{FontFamily, FontId, TextStyle};

    // ----- Шрифты: добавляем системный emoji-шрифт как fallback,
    // чтобы такие глифы как ☰, ⋯, 🛰, 🔌, 🔍, ➤ не превращались в □ -----
    let mut fonts = egui::FontDefinitions::default();
    let candidates: &[&str] = &[
        #[cfg(target_os = "windows")]
        "C:/Windows/Fonts/seguiemj.ttf",
        #[cfg(target_os = "windows")]
        "C:/Windows/Fonts/seguisym.ttf",
        #[cfg(target_os = "windows")]
        "C:/Windows/Fonts/segoeui.ttf",
        #[cfg(target_os = "macos")]
        "/System/Library/Fonts/Apple Color Emoji.ttc",
        #[cfg(target_os = "linux")]
        "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let name = format!("sysfont_{}", path);
            fonts
                .font_data
                .insert(name.clone(), egui::FontData::from_owned(bytes));
            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .push(name.clone());
            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push(name);
        }
    }
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::dark();

    visuals.override_text_color = Some(palette::TEXT);
    visuals.panel_fill          = palette::BG_PANEL;
    visuals.window_fill         = palette::BG_PANEL;
    visuals.extreme_bg_color    = palette::BG_DEEP;
    visuals.faint_bg_color      = palette::BG_CARD;

    visuals.widgets.noninteractive.bg_fill      = palette::BG_PANEL;
    visuals.widgets.noninteractive.weak_bg_fill = palette::BG_PANEL;
    visuals.widgets.noninteractive.bg_stroke    = egui::Stroke::new(1.0, palette::DIVIDER);
    visuals.widgets.noninteractive.fg_stroke    = egui::Stroke::new(1.0, palette::TEXT);
    visuals.widgets.noninteractive.rounding     = 12.0.into();

    visuals.widgets.inactive.bg_fill      = palette::BG_CARD;
    visuals.widgets.inactive.weak_bg_fill = palette::BG_CARD;
    visuals.widgets.inactive.bg_stroke    = egui::Stroke::new(1.0, palette::DIVIDER);
    visuals.widgets.inactive.fg_stroke    = egui::Stroke::new(1.0, palette::TEXT);
    visuals.widgets.inactive.rounding     = 12.0.into();

    visuals.widgets.hovered.bg_fill      = palette::BG_HOVER;
    visuals.widgets.hovered.weak_bg_fill = palette::BG_HOVER;
    visuals.widgets.hovered.bg_stroke    = egui::Stroke::new(1.0, palette::ACCENT);
    visuals.widgets.hovered.fg_stroke    = egui::Stroke::new(1.4, palette::ACCENT_2);
    visuals.widgets.hovered.rounding     = 12.0.into();

    visuals.widgets.active.bg_fill      = palette::BG_SELECTED;
    visuals.widgets.active.weak_bg_fill = palette::BG_SELECTED;
    visuals.widgets.active.bg_stroke    = egui::Stroke::new(1.4, palette::ACCENT);
    visuals.widgets.active.fg_stroke    = egui::Stroke::new(1.4, palette::ACCENT);
    visuals.widgets.active.rounding     = 12.0.into();

    visuals.widgets.open.bg_fill      = palette::BG_HOVER;
    visuals.widgets.open.weak_bg_fill = palette::BG_HOVER;
    visuals.widgets.open.rounding     = 12.0.into();

    visuals.selection.bg_fill = palette::ACCENT;
    visuals.selection.stroke  = egui::Stroke::new(1.0, palette::TEXT);
    visuals.hyperlink_color   = palette::ACCENT_2;

    visuals.window_rounding = 14.0.into();
    visuals.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 6.0),
        blur:   28.0,
        spread: 0.0,
        color:  egui::Color32::from_rgba_premultiplied(0, 0, 0, 140),
    };
    visuals.popup_shadow = visuals.window_shadow;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Small,     FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Body,      FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        (TextStyle::Button,    FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Heading,   FontId::new(20.0, FontFamily::Proportional)),
    ]
    .into();
    style.spacing.item_spacing    = egui::vec2(8.0, 6.0);
    style.spacing.window_margin   = egui::Margin::same(0.0);
    style.spacing.button_padding  = egui::vec2(12.0, 8.0);
    style.spacing.menu_margin     = egui::Margin::same(8.0);
    ctx.set_style(style);
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.known_peers.remove(&self.local_peer_id);
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::PublicIpConfirmed(ip) => {
                    self.public_ip = Some(ip);
                }
                NetworkEvent::NewListenAddr(addr) => {
                    let full = format!("{}/p2p/{}", addr, self.local_peer_id);
                    if !self.listen_addrs.contains(&full) {
                        self.add_status(format!("🚀 Listen: {}", addr));
                        self.listen_addrs.push(full);
                    }
                }
                NetworkEvent::MdnsDiscovered(peer, addr) => {
                    self.add_status(format!(
                        "🔍 Найдён пир: {} на {}",
                        &peer.to_string()[..8],
                        addr
                    ));
                    if peer != self.local_peer_id {
                        if let Entry::Vacant(e) = self.known_peers.entry(peer) {
                            e.insert(format!("Peer_{}", &peer.to_string()[..8]));
                            self.persist_vault();
                        }
                        self.select_peer_if_no_chat(peer);
                    }
                }
                NetworkEvent::MdnsExpired(peer) => {
                    self.add_status(format!("⏳ Оффлайн (MDNS): {}", &peer.to_string()[..8]));
                }
                NetworkEvent::Connected(peer) => {
                    self.connected_peers += 1;
                    self.add_status(format!("✅ Подключено: {}...", &peer.to_string()[..8]));
                    if peer != self.local_peer_id {
                        self.select_peer_if_no_chat(peer);
                    }
                }
                NetworkEvent::Disconnected(peer) => {
                    self.connected_peers = self.connected_peers.saturating_sub(1);
                    self.add_status(format!("❌ Отключено: {}...", &peer.to_string()[..8]));
                }
                NetworkEvent::ChatMessage(msg) => {
                    // Update known peers for display names
                    if let Ok(peer_id) = msg.sender_id.parse::<PeerId>() {
                        if peer_id != self.local_peer_id {
                            let prev = self
                                .known_peers
                                .insert(peer_id, msg.sender_name.clone());
                            if prev.as_ref() != Some(&msg.sender_name) {
                                self.persist_vault();
                            }
                        }
                    }

                    // Route message
                    let bucket = if let Some(ref target) = msg.recipient_id {
                        if target == &self.local_peer_id.to_string() {
                            Some(msg.sender_id.clone())
                        } else if msg.sender_id == self.local_peer_id.to_string() {
                            Some(target.clone())
                        } else {
                            None
                        }
                    } else {
                        None // Ignore global messages
                    };

                    if let Some(b) = bucket {
                        self.messages.entry(b).or_default().push(msg);
                    }
                }
                NetworkEvent::Status(msg) => {
                    self.add_status(msg);
                }
                NetworkEvent::DhtRoutingPeers { total, lines } => {
                    self.dht_routing_total = total;
                    self.dht_routing_lines = lines;
                    self.add_status(format!("DHT: в таблице маршрутов {} узл.", total));
                }
                NetworkEvent::MessageDelivered(peer) => {
                    // Снимаем самое раннее ожидание этого пира: ретрая не будет,
                    // ошибочный toast «✖ Не удалось доставить…» тоже не появится.
                    if let Some(idx) = self
                        .pending_sends
                        .iter()
                        .position(|p| p.peer == peer)
                    {
                        self.pending_sends.remove(idx);
                    }
                }
                NetworkEvent::SendFailedDial(peer) => {
                    // Сразу подталкиваем самое раннее ожидающее сообщение
                    // этому пиру к фазе DHT-lookup (сдвигаем `last_send_at`
                    // в прошлое — следующий tick запустит retry-логику).
                    if let Some(p) = self
                        .pending_sends
                        .iter_mut()
                        .find(|p| p.peer == peer && !p.dht_kicked)
                    {
                        p.last_send_at = Instant::now()
                            .checked_sub(RESEND_GRACE + Duration::from_millis(50))
                            .unwrap_or_else(Instant::now);
                    }
                }
            }
        }

        // ===== Tick: повторные отправки + истечение toast'ов =====
        self.tick_pending_sends();
        let now = Instant::now();
        self.toasts.retain(|t| t.expires_at > now);

        // Чтобы фоновые таймеры (retry/toast) тикали без активности пользователя.
        if !self.pending_sends.is_empty() || !self.toasts.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }

        // ===== Системная консоль (overlay-окно) =====
        if self.show_logs {
            egui::Window::new("Системная консоль")
                .open(&mut self.show_logs)
                .resizable(true)
                .default_size([460.0, 360.0])
                .frame(
                    egui::Frame::none()
                        .fill(palette::BG_PANEL)
                        .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                        .rounding(12.0)
                        .inner_margin(16.0)
                        .shadow(egui::epaint::Shadow {
                            offset: egui::vec2(0.0, 6.0),
                            blur: 24.0,
                            spread: 0.0,
                            color: egui::Color32::from_rgba_premultiplied(0, 0, 0, 160),
                        }),
                )
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("ЛОКАЛЬНЫЕ АДРЕСА")
                            .strong()
                            .size(12.0)
                            .color(palette::ACCENT_2),
                    );
                    for addr in &self.listen_addrs {
                        ui.label(
                            egui::RichText::new(addr)
                                .small()
                                .monospace()
                                .color(palette::TEXT_MUTED),
                        );
                    }
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new("ЛОГ СОБЫТИЙ")
                            .strong()
                            .size(12.0)
                            .color(palette::ACCENT),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("log_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for log in &self.status_log {
                                ui.label(
                                    egui::RichText::new(log)
                                        .size(12.5)
                                        .color(palette::TEXT_MUTED),
                                );
                            }
                        });
                });
        }

        // ===== Левая панель: контакты (Telegram-стиль) =====
        if self.show_sidebar {
            let screen_w = ctx.screen_rect().width();
            let min_w = 80.0_f32;
            let max_w = (screen_w - 320.0).max(min_w + 40.0);
            self.sidebar_width = self.sidebar_width.clamp(min_w, max_w);

            egui::SidePanel::left("sb_v6_fixed")
                .frame(egui::Frame::none().fill(palette::BG_PANEL))
                .resizable(false)
                .exact_width(self.sidebar_width)
                .show(ctx, |ui| {
                    let panel_rect = ui.max_rect();

                    // 1) Контент сидебара (с правым отступом под ручку).
                    let content_rect = egui::Rect::from_min_max(
                        panel_rect.min,
                        egui::pos2(panel_rect.right() - 8.0, panel_rect.bottom()),
                    );
                    let mut content_ui = ui.new_child(
                        egui::UiBuilder::new()
                            .max_rect(content_rect)
                            .layout(egui::Layout::top_down(egui::Align::Min)),
                    );
                    self.ui_sidebar(&mut content_ui);

                    // 2) Drag-ручка строго на правом краю панели (внутри её rect).
                    let handle_rect = egui::Rect::from_min_max(
                        egui::pos2(panel_rect.right() - 8.0, panel_rect.top()),
                        egui::pos2(panel_rect.right(), panel_rect.bottom()),
                    );
                    let handle_resp = ui.interact(
                        handle_rect,
                        egui::Id::new("sb_v6_drag"),
                        egui::Sense::click_and_drag(),
                    );

                    if handle_resp.dragged() {
                        self.sidebar_width += handle_resp.drag_delta().x;
                        self.sidebar_width = self.sidebar_width.clamp(min_w, max_w);
                    }
                    if handle_resp.hovered() || handle_resp.dragged() {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
                    }

                    let active = handle_resp.hovered() || handle_resp.dragged();
                    let stroke_color = if handle_resp.dragged() {
                        palette::ACCENT
                    } else if active {
                        palette::ACCENT_2
                    } else {
                        palette::DIVIDER
                    };
                    let stroke_w = if active { 3.0 } else { 2.0 };
                    ui.painter().vline(
                        panel_rect.right() - 1.5,
                        panel_rect.y_range(),
                        egui::Stroke::new(stroke_w, stroke_color),
                    );
                });
        }

        // ===== Шапка активного чата =====
        egui::TopBottomPanel::top("chat_header")
            .frame(
                egui::Frame::none()
                    .fill(palette::BG_CHAT)
                    .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                    .inner_margin(egui::Margin {
                        left: 22.0,
                        right: 18.0,
                        top: 12.0,
                        bottom: 12.0,
                    }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let toggle_label = if self.show_sidebar { "≡" } else { "≡" };
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new(toggle_label)
                                    .size(18.0)
                                    .color(palette::TEXT),
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::NONE),
                        )
                        .on_hover_text(if self.show_sidebar {
                            "Скрыть список контактов"
                        } else {
                            "Показать список контактов"
                        })
                        .clicked()
                    {
                        self.show_sidebar = !self.show_sidebar;
                    }
                    ui.add_space(8.0);

                    if !self.selected_chat.is_empty() {
                        let display_name = self
                            .selected_chat
                            .parse::<PeerId>()
                            .ok()
                            .and_then(|pid| self.known_peers.get(&pid).cloned())
                            .unwrap_or_else(|| {
                                let n = self.selected_chat.len().min(8);
                                format!("Peer {}", &self.selected_chat[..n])
                            });
                        draw_avatar(ui, &self.selected_chat, &display_name, 40.0, None);
                        ui.add_space(12.0);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(&display_name)
                                    .strong()
                                    .size(16.0)
                                    .color(palette::TEXT),
                            );
                            let id_short = {
                                let n = self.selected_chat.len().min(20);
                                format!("{}…", &self.selected_chat[..n])
                            };
                            ui.label(
                                egui::RichText::new(id_short)
                                    .size(11.0)
                                    .monospace()
                                    .color(palette::TEXT_MUTED),
                            );
                        });
                    } else {
                        ui.label(
                            egui::RichText::new("✦ VOID")
                                .size(20.0)
                                .strong()
                                .color(palette::ACCENT),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("выберите контакт слева")
                                .color(palette::TEXT_MUTED),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("⋯")
                                        .size(22.0)
                                        .color(palette::TEXT),
                                )
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE),
                            )
                            .on_hover_text("Системная консоль")
                            .clicked()
                        {
                            self.show_logs = !self.show_logs;
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "● {} в сети",
                                self.connected_peers
                            ))
                            .size(11.5)
                            .color(if self.connected_peers > 0 {
                                palette::ONLINE
                            } else {
                                palette::TEXT_MUTED
                            }),
                        );
                    });
                });
            });

        // ===== Поле ввода (нижняя панель) =====
        egui::TopBottomPanel::bottom("chat_input")
            .frame(
                egui::Frame::none()
                    .fill(palette::BG_CHAT)
                    .inner_margin(egui::Margin {
                        left: 18.0,
                        right: 18.0,
                        top: 10.0,
                        bottom: 14.0,
                    }),
            )
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(palette::BG_CARD)
                    .stroke(egui::Stroke::new(1.0, palette::DIVIDER))
                    .rounding(24.0)
                    .inner_margin(egui::Margin {
                        left: 18.0,
                        right: 6.0,
                        top: 4.0,
                        bottom: 4.0,
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let text_w = (ui.available_width() - 56.0).max(80.0);
                            let edit = ui.add(
                                egui::TextEdit::singleline(&mut self.chat_input)
                                    .hint_text("Сообщение…")
                                    .desired_width(text_w)
                                    .frame(false)
                                    .font(egui::TextStyle::Body),
                            );

                            let send_clicked = ui
                                .add_sized(
                                    egui::vec2(44.0, 44.0),
                                    egui::Button::new(
                                        egui::RichText::new("➤")
                                            .size(18.0)
                                            .color(palette::TEXT),
                                    )
                                    .fill(palette::ACCENT)
                                    .rounding(22.0),
                                )
                                .clicked();

                            let enter_pressed = edit.lost_focus()
                                && ctx.input(|i| i.key_pressed(egui::Key::Enter));

                            if (send_clicked || enter_pressed) && !self.chat_input.is_empty() {
                                let recipient = if self.selected_chat.is_empty() {
                                    None
                                } else {
                                    self.selected_chat.parse::<PeerId>().ok()
                                };
                                if let Some(peer_id) = recipient {
                                    let text_to_send = self.chat_input.clone();
                                    match self.command_tx.try_send(UICommand::SendMessage {
                                        sender_name: self.local_nickname.clone(),
                                        text: text_to_send.clone(),
                                        recipient: Some(peer_id),
                                        is_retry: false,
                                    }) {
                                        Ok(()) => {
                                            self.chat_input.clear();
                                            // Помечаем сообщение как «в полёте» — следим
                                            // за DialFailure и при необходимости
                                            // дёрнем DHT + retry.
                                            self.pending_sends.push(PendingSend {
                                                peer: peer_id,
                                                text: text_to_send,
                                                last_send_at: Instant::now(),
                                                dht_kicked: false,
                                                dht_kicked_at: None,
                                                attempts: 1,
                                            });
                                        }
                                        Err(_) => self.add_status(
                                            "⚠ Очередь к сети переполнена, повторите отправку."
                                                .into(),
                                        ),
                                    }
                                } else if self.selected_chat.is_empty() {
                                    self.add_status(
                                        "⚠ Выберите контакт слева, чтобы отправить сообщение."
                                            .into(),
                                    );
                                } else {
                                    self.add_status(
                                        "⚠ Некорректный Peer ID в выбранном чате.".into(),
                                    );
                                }
                                if enter_pressed {
                                    edit.request_focus();
                                }
                            }
                        });
                    });
            });

        // ===== История чата (фоновое изображение + bubbles) =====
        let bg_tex = self.ensure_chat_bg(ctx);
        let bg_tex_size = self
            .chat_bg_texture
            .as_ref()
            .map(|h| h.size_vec2())
            .unwrap_or(egui::Vec2::ZERO);
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(palette::BG_CHAT))
            .show(ctx, |ui| {
                let bg_rect = ui.max_rect();
                if let Some(tex_id) = bg_tex {
                    draw_chat_bg_image(ui.painter(), bg_rect, tex_id, bg_tex_size);
                } else {
                    draw_starfield(ui.painter(), bg_rect);
                }

                if self.selected_chat.is_empty() {
                    ui.allocate_ui_with_layout(
                        ui.available_size(),
                        egui::Layout::centered_and_justified(egui::Direction::TopDown),
                        |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(80.0);
                                ui.label(
                                    egui::RichText::new("✦")
                                        .size(96.0)
                                        .color(palette::ACCENT_2),
                                );
                                ui.add_space(14.0);
                                ui.label(
                                    egui::RichText::new("Тишина в эфире")
                                        .size(22.0)
                                        .strong()
                                        .color(palette::TEXT),
                                );
                                ui.add_space(6.0);
                                ui.label(
                                    egui::RichText::new(
                                        "Выберите контакт слева — и начнём сеанс связи через VOID.",
                                    )
                                    .color(palette::TEXT_MUTED),
                                );
                            });
                        },
                    );
                    return;
                }

                let messages = self
                    .messages
                    .get(&self.selected_chat)
                    .cloned()
                    .unwrap_or_default();
                let me_str = self.local_peer_id.to_string();

                egui::ScrollArea::vertical()
                    .id_salt("chat_stream")
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(12.0);

                        if messages.is_empty() {
                            ui.add_space(40.0);
                            ui.vertical_centered(|ui| {
                                ui.label(
                                    egui::RichText::new(
                                        "Сообщений пока нет — отправьте первое ↓",
                                    )
                                    .color(palette::TEXT_MUTED),
                                );
                            });
                        }

                        for msg in &messages {
                            let is_me = msg.sender_id == me_str;
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let avail = ui.available_width();
                                let max_w = (avail * 0.66).min(560.0).max(180.0);

                                if is_me {
                                    ui.add_space((avail - max_w - 28.0).max(0.0));
                                } else {
                                    ui.add_space(20.0);
                                    draw_avatar(
                                        ui,
                                        &msg.sender_id,
                                        &msg.sender_name,
                                        30.0,
                                        None,
                                    );
                                    ui.add_space(8.0);
                                }

                                let bubble_bg = if is_me {
                                    palette::BUBBLE_ME
                                } else {
                                    palette::BUBBLE_THEM
                                };

                                egui::Frame::none()
                                    .fill(bubble_bg)
                                    .rounding(egui::Rounding {
                                        nw: 16.0,
                                        ne: 16.0,
                                        sw: if is_me { 16.0 } else { 4.0 },
                                        se: if is_me { 4.0 } else { 16.0 },
                                    })
                                    .inner_margin(egui::Margin {
                                        left: 14.0,
                                        right: 14.0,
                                        top: 8.0,
                                        bottom: 6.0,
                                    })
                                    .show(ui, |ui| {
                                        ui.set_max_width(max_w);
                                        ui.vertical(|ui| {
                                            if !is_me {
                                                ui.label(
                                                    egui::RichText::new(&msg.sender_name)
                                                        .size(12.5)
                                                        .strong()
                                                        .color(palette::ACCENT_2),
                                                );
                                            }
                                            ui.label(
                                                egui::RichText::new(&msg.text)
                                                    .size(14.5)
                                                    .color(palette::TEXT),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(
                                                    egui::Align::Center,
                                                ),
                                                |ui| {
                                                    ui.label(
                                                        egui::RichText::new(short_time(
                                                            &msg.timestamp,
                                                        ))
                                                        .size(10.5)
                                                        .color(palette::TEXT_MUTED),
                                                    );
                                                },
                                            );
                                        });
                                    });
                            });
                        }
                        ui.add_space(12.0);
                    });
            });

        // ===== Toasts (поверх всего, правый верхний угол) =====
        self.draw_toasts(ctx);

        ctx.request_repaint_after(Duration::from_millis(100));
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

    let (local_key, local_nickname, static_secret, initial_address_book) =
        if let Ok(storage) = Storage::load() {
            let key = libp2p::identity::Keypair::from_protobuf_encoding(&storage.keypair_bytes)
                .expect("Failed to decode saved keypair");
            let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
            let my_id = PeerId::from(key.public());
            let mut book = HashMap::new();
            for entry in storage.address_book {
                if let Ok(pid) = entry.peer_id.parse::<PeerId>() {
                    if pid != my_id {
                        book.insert(pid, entry.display_name);
                    }
                }
            }
            (key, storage.nickname, static_secret, book)
        } else {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let static_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
            let nickname = format!("User_{}", &PeerId::from(key.public()).to_string()[..4]);
            let _ = Storage::save(&nickname, Some(&key), Some(&static_secret), None);
            (key, nickname, static_secret, HashMap::new())
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
    tokio::spawn(async move {
        let event_tx = event_tx_clone;
        let command_tx_for_mdns = command_tx_for_mdns;
        let local_static = static_secret_net;
        let void_bootstraps = void_bootstraps_for_net;
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
                kad_config.set_periodic_bootstrap_interval(None);
                let mut kad = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);
                kad.set_mode(Some(libp2p::kad::Mode::Server));

                for ma in &void_bootstraps {
                    if let Some(pid) = peer_id_from_multiaddr(ma) {
                        kad.add_address(&pid, ma.clone());
                    } else {
                        eprintln!("VOID bootstrap: нет /p2p/ в конце адреса, пропуск: {}", ma);
                    }
                }
                if !void_bootstraps.is_empty() {
                    let _ = kad.bootstrap();
                }

                let rr_config = libp2p::request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30)); // Увеличиваем тайм-аут до 30с
                let rr_protocol = libp2p::StreamProtocol::new("/void/chat/1.0.0");
                let rr_behaviour = libp2p::request_response::json::Behaviour::<V1Packet, V1Packet>::new(
                    [(rr_protocol, libp2p::request_response::ProtocolSupport::Full)],
                    rr_config,
                );

                Ok(ChatBehaviour {
                    request_response: rr_behaviour,
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                        .unwrap(),
                    ping: ping::Behaviour::default(),
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
                c.with_idle_connection_timeout(Duration::from_secs(120)) // 2 минуты покоя
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

        let mut peer_addrs: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let mut pending_dials: HashSet<PeerId> = HashSet::new();
        // RequestId → PeerId для сообщений (Plain/Encrypted), чтобы по ответу
        // (Ack/прочее) однозначно подтвердить доставку конкретному пиру и снять
        // pending-ретраи в UI. Hello-handshake'ы сюда НЕ попадают.
        let mut outbound_msg_requests: HashMap<libp2p::request_response::OutboundRequestId, PeerId> = HashMap::new();
        let mut dial_backoff: HashMap<PeerId, Instant> = HashMap::new();
        let mut local_listen_addrs: HashSet<Multiaddr> = HashSet::new();
        // Пиры-«seed», к которым мы дозвонились через JoinViaNode: после Identify запускаем DHT-bootstrap.
        let mut pending_seed_peers: HashSet<PeerId> = HashSet::new();
        let mut pending_seed_bare: bool = false;

        loop {
            tokio::select! {
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
                                 println!("🔌 UI_COMMAND: DialPeer {} ({} addresses)", short, addrs.len());

                                 // Добавляем только не-loopback адреса в Kad
                                 for addr in &addrs {
                                     let s = addr.to_string();
                                     if !s.contains("127.0.0.1") && !s.contains("::1") {
                                         swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                                     }
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
                        }
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            let s = address.to_string();
                            local_listen_addrs.insert(address.clone());
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
                            println!("⚠️ [RR] OutFailure пиру {}: {:?}", peer, error);
                            // Сообщение точно не доставлено — освобождаем запись, чтобы не словить
                            // ложный «доставлено» при последующем reuse RequestId.
                            outbound_msg_requests.remove(&request_id);
                            if matches!(error, libp2p::request_response::OutboundFailure::DialFailure) {
                                let _ = event_tx.send(NetworkEvent::SendFailedDial(peer)).await;
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
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            let connected_count = swarm.connected_peers().count();
                            println!("✅ СОЕДИНЕНО: {}. Endpoint: {:?}. Всего пиров: {}", peer_id, endpoint, connected_count);
                            pending_dials.remove(&peer_id);

                             if peer_id != local_peer_id {
                                 let _ = event_tx.send(NetworkEvent::Connected(peer_id)).await;
                                 let _ = event_tx.send(NetworkEvent::Status(format!("✅ СОЕДИНЕНО: {}", &peer_id.to_string()[..8]))).await;
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
                            // Не фильтруем по `/void/chat/1.0.0`: в rust-libp2p список protocols в Identify
                            // не обязан совпадать с request-response; иначе рвём соединение с нормальным VOID-пиром.
                            println!(
                                "[{}] 🆔 Identify: {} — {} listen, {} протоколов",
                                now,
                                peer_id,
                                info.listen_addrs.len(),
                                info.protocols.len()
                            );
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kad.add_address(&peer_id, addr);
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
                command_tx,
                event_rx,
            )))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
