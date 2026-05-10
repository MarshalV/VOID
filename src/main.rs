mod crypto;
mod file_transfer;
mod ui;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
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
use zeroize::{Zeroize, Zeroizing};
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
    /// Магия и размер обёртки `void.key` v2: Argon2id KDF + AES-256-GCM над сыром мастер-ключом vault.
    const KEY_WRAP_MAGIC: &'static [u8; 8] = b"VOIDKEY2";
    const WRAP_SALT_LEN: usize = 32;
    const WRAP_NONCE_LEN: usize = 12;

    fn derive_wrap_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
        let params = Params::new(32768, 3, 4, Some(32)).map_err(|e| e.to_string())?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| format!("argon2: {}", e))?;
        Ok(key)
    }

    /// Пишет `void.key`: мастер-ключ vault (32 байта) зашифрован паролем (KDF Argon2id + AES-GCM).
    pub(crate) fn write_wrapped_master_key_file(
        master_plain: &[u8; 32],
        password: &str,
    ) -> Result<(), Box<dyn Error>> {
        let mut salt = vec![0u8; Self::WRAP_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let wrap_key = Self::derive_wrap_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
        let mut nonce = [0u8; Self::WRAP_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), master_plain.as_ref())
            .map_err(|e| format!("wrap key encrypt: {}", e))?;
        let mut blob = Vec::with_capacity(8 + salt.len() + nonce.len() + ct.len());
        blob.extend_from_slice(Self::KEY_WRAP_MAGIC);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        std::fs::write(Self::KEY_FILE, &blob)?;
        Ok(())
    }

    /// Считывает мастер-ключ из `void.key` v2 (Argon2id + AES-GCM).
    pub(crate) fn unwrap_master_key_file(password: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let blob = std::fs::read(Self::KEY_FILE)?;
        Self::unwrap_master_key_bytes(&blob, password)
    }

    fn unwrap_master_key_bytes(blob: &[u8], password: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let min =
            Self::KEY_WRAP_MAGIC.len() + Self::WRAP_SALT_LEN + Self::WRAP_NONCE_LEN + 16;
        if blob.len() < min {
            return Err("void.key слишком короткий или повреждён".into());
        }
        let (magic, rest) = blob.split_at(Self::KEY_WRAP_MAGIC.len());
        if magic != Self::KEY_WRAP_MAGIC.as_slice() {
            return Err(
                "void.key без магии VOIDKEY2 (ожидается формат с паролём)".into(),
            );
        }
        let (salt, rest) = rest.split_at(Self::WRAP_SALT_LEN);
        let (nonce, ct) = rest.split_at(Self::WRAP_NONCE_LEN);
        let wrap_key = Self::derive_wrap_key(password.as_bytes(), salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce), ct.as_ref())
            .map_err(|_| "Неверный пароль или повреждённый void.key".to_string())?;
        if plain.len() != 32 {
            return Err("void.key: некорректная длина мастер-ключа".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        Ok(out)
    }

    pub(crate) fn read_key_blob() -> Result<Vec<u8>, std::io::Error> {
        std::fs::read(Self::KEY_FILE)
    }

    pub(crate) fn is_wrapped_keyfile(raw: &[u8]) -> bool {
        raw.len() >= Self::KEY_WRAP_MAGIC.len()
            && &raw[..Self::KEY_WRAP_MAGIC.len()] == Self::KEY_WRAP_MAGIC.as_slice()
    }

    fn save(
        master_key: &[u8; 32],
        nickname: &str,
        keypair: Option<&libp2p::identity::Keypair>,
        static_secret: Option<&crypto::StaticSecret>,
        address_book: Option<&[AddressBookEntry]>,
    ) -> Result<(), Box<dyn Error>> {
        let current_load = Self::load(master_key);

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

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_slice()));

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

    fn load(master_key: &[u8; 32]) -> Result<StorageData, Box<dyn Error>> {
        if !std::path::Path::new(Self::FILE).exists() {
            return Err("Vault file not found".into());
        }
        let data = std::fs::read(Self::FILE)?;
        if data.len() < 12 {
            return Err("Invalid vault".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_slice()));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {}", e))?;

        let storage: StorageData = serde_json::from_slice(&plaintext)?;
        Ok(storage)
    }
}

/// Какой экран разблокировки vault показать при старте.
#[derive(Clone)]
pub(crate) enum VaultUnlockKind {
    /// Нет `vault.bin`: создаём профиль, пароль задаётся дважды.
    CreateProfile,
    /// Обычный вход: `void.key` в формате Argon2id + AES-GCM.
    OpenWrappedKey,
    /// Старый `void.key` ровно 32 байта сырого мастер-ключа — перенос на защищённый формат.
    MigratePlainMaster(Zeroizing<[u8; 32]>),
}

pub(crate) struct VaultUnlockState {
    pub kind: VaultUnlockKind,
    pub password: String,
    pub password_confirm: String,
    pub error: Option<String>,
}

pub(crate) struct DeferredNetworkSpawn {
    pub event_tx: mpsc::Sender<NetworkEvent>,
    pub command_rx: mpsc::Receiver<UICommand>,
    pub command_tx_for_mdns: mpsc::Sender<UICommand>,
    pub void_bootstraps: Vec<Multiaddr>,
}

/// Определяет сценарий разблокировки по наличию `vault.bin` и формату `void.key`.
fn detect_vault_unlock_kind() -> Result<VaultUnlockKind, String> {
    let vault_exists = Path::new(Storage::FILE).exists();
    let raw_key = Storage::read_key_blob().unwrap_or_else(|_| Vec::new());
    let key_empty = raw_key.is_empty();

    match (vault_exists, key_empty, raw_key.len()) {
        (false, true, _) => Ok(VaultUnlockKind::CreateProfile),
        (false, false, _) => Err(
            "Найден void.key без vault.bin — восстановите vault или удалите void.key.".into(),
        ),
        (true, true, _) => Err(format!(
            "Нет {} при существующем vault — добавьте void.key или восстановите файл ключа.",
            Storage::KEY_FILE
        )),
        (true, false, 32) if !Storage::is_wrapped_keyfile(&raw_key) => {
            let mut m = [0u8; 32];
            m.copy_from_slice(&raw_key);
            Ok(VaultUnlockKind::MigratePlainMaster(Zeroizing::new(m)))
        }
        (true, false, _) if Storage::is_wrapped_keyfile(&raw_key) => Ok(VaultUnlockKind::OpenWrappedKey),
        (true, false, _) => Err(
            "void.key неизвестного формата (ни 32 байта, ни VOIDKEY2).".into(),
        ),
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
                    println!(
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
                    } else {
                        file_transfer::unique_download_path(&fname)
                    };
                    let saved_to = save_path.display().to_string();
                    match std::fs::write(&save_path, &data) {
                        Ok(_) => {
                            println!(
                                "[{}] ✅ FILE: «{}» сохранён → {}",
                                now, fname, saved_to
                            );
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
    /// Экран ввода пароля до расшифровки `void.key` / создания профиля.
    pub(crate) pending_unlock: Option<VaultUnlockState>,
    deferred_network_spawn: Option<DeferredNetworkSpawn>,
    /// Мастер-ключ AES vault (после разблокировки). До входа отсутствует.
    vault_master_key: Option<Zeroizing<[u8; 32]>>,
}

impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        pending_unlock: Option<VaultUnlockState>,
        deferred_network_spawn: Option<DeferredNetworkSpawn>,
        vault_master_key: Option<Zeroizing<[u8; 32]>>,
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
            pending_unlock,
            deferred_network_spawn,
            vault_master_key,
        }
    }

    /// Экран разблокировки vault. Возвращает `true`, пока нужно блокировать основной UI.
    pub(crate) fn vault_unlock_gate(&mut self, ctx: &egui::Context) -> bool {
        let Some(_) = self.pending_unlock.as_ref() else {
            return false;
        };

        #[derive(Clone, Copy)]
        enum Act {
            Unlock,
        }
        let mut act = None::<Act>;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(56.0);
                ui.label(egui::RichText::new("VOID").size(36.0).strong());
                ui.add_space(12.0);
                let subtitle = match &self.pending_unlock.as_ref().unwrap().kind {
                    VaultUnlockKind::CreateProfile => "Задайте пароль vault (AES-ключ будет защищён Argon2id).",
                    VaultUnlockKind::OpenWrappedKey => "Введите пароль vault.",
                    VaultUnlockKind::MigratePlainMaster(_) => {
                        "Старый void.key без пароля: задаётесь пароль (Argon2id + AES), vault не меняется."
                    }
                };
                ui.label(egui::RichText::new(subtitle).weak());
                ui.add_space(24.0);
                ui.set_max_width(420.0);
                let need_confirm =
                    matches!(
                        self.pending_unlock.as_ref().unwrap().kind,
                        VaultUnlockKind::CreateProfile | VaultUnlockKind::MigratePlainMaster(_),
                    );

                if let Some(p) = self.pending_unlock.as_mut() {
                    ui.label("Пароль:");
                    ui.add(
                        egui::TextEdit::singleline(&mut p.password)
                            .desired_width(320.0)
                            .password(true)
                            .hint_text("Не короче 8 символов"),
                    );

                    if need_confirm {
                        ui.add_space(8.0);
                        ui.label("Пароль ещё раз:");
                        ui.add(
                            egui::TextEdit::singleline(&mut p.password_confirm)
                                .desired_width(320.0)
                                .password(true),
                        );
                    }

                    if let Some(err) = &p.error {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(220, 100, 100), err);
                    }

                    ui.add_space(24.0);
                    if ui
                        .add_sized([180.0, 36.0], egui::Button::new("Продолжить"))
                        .clicked()
                    {
                        act = Some(Act::Unlock);
                    }
                }
                ui.add_space(12.0);
                ui.small(
                    "Мастер-ключ vault зашифрован в void.key паролем (Argon2id + AES-GCM).",
                );
            });
        });

        if matches!(act, Some(Act::Unlock)) {
            self.submit_vault_unlock(ctx);
        }
        ctx.request_repaint_after(Duration::from_millis(200));
        true
    }

    fn submit_vault_unlock(&mut self, ctx: &egui::Context) {
        let Some(mut pending) = self.pending_unlock.take() else {
            return;
        };
        pending.error = None;
        let pwd = pending.password.trim();
        let pwd2 = pending.password_confirm.trim();
        let require_confirm = matches!(
            pending.kind,
            VaultUnlockKind::CreateProfile | VaultUnlockKind::MigratePlainMaster(_),
        );

        if pwd.len() < 8 {
            pending.error = Some("Укажите пароль не короче 8 символов.".into());
            self.pending_unlock = Some(pending);
            return;
        }
        if require_confirm && pwd != pwd2 {
            pending.error = Some("Пароли не совпадают.".into());
            self.pending_unlock = Some(pending);
            return;
        }

        let kind_followup = match &pending.kind {
            VaultUnlockKind::CreateProfile => VaultUnlockKind::CreateProfile,
            VaultUnlockKind::OpenWrappedKey => VaultUnlockKind::OpenWrappedKey,
            VaultUnlockKind::MigratePlainMaster(z) => {
                VaultUnlockKind::MigratePlainMaster(z.clone())
            }
        };

        let master_arr: Zeroizing<[u8; 32]> = match &pending.kind {
            VaultUnlockKind::OpenWrappedKey => match Storage::unwrap_master_key_file(pwd) {
                Ok(m) => Zeroizing::new(m),
                Err(e) => {
                    pending.password.zeroize();
                    pending.password_confirm.zeroize();
                    pending.error = Some(format!("{}", e));
                    self.pending_unlock = Some(pending);
                    return;
                }
            },
            VaultUnlockKind::MigratePlainMaster(leg) => {
                let plain = **leg;
                if let Err(e) = Storage::write_wrapped_master_key_file(&plain, pwd) {
                    pending.error = Some(format!("{}", e));
                    self.pending_unlock = Some(pending);
                    return;
                }
                Zeroizing::new(plain)
            }
            VaultUnlockKind::CreateProfile => {
                let mut plain = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut plain);
                if let Err(e) = Storage::write_wrapped_master_key_file(&plain, pwd) {
                    pending.error = Some(format!("{}", e));
                    self.pending_unlock = Some(pending);
                    return;
                }
                Zeroizing::new(plain)
            }
        };

        pending.password.zeroize();
        pending.password_confirm.zeroize();
        drop(pending);

        let Some(dn_sp) = self.deferred_network_spawn.take() else {
            self.pending_unlock = Some(VaultUnlockState {
                kind: kind_followup,
                password: String::new(),
                password_confirm: String::new(),
                error: Some("Внутренняя ошибка: параметры сети недоступны.".into()),
            });
            return;
        };

        match kind_followup {
            VaultUnlockKind::OpenWrappedKey | VaultUnlockKind::MigratePlainMaster(_) => {
                let storage = match Storage::load(&master_arr) {
                    Ok(s) => s,
                    Err(e) => {
                        self.pending_unlock = Some(VaultUnlockState {
                            kind: VaultUnlockKind::OpenWrappedKey,
                            password: String::new(),
                            password_confirm: String::new(),
                            error: Some(format!("Не удалось прочитать vault.bin: {}", e)),
                        });
                        self.deferred_network_spawn = Some(dn_sp);
                        return;
                    }
                };
                let local_key = match libp2p::identity::Keypair::from_protobuf_encoding(
                    &storage.keypair_bytes,
                ) {
                    Ok(k) => k,
                    Err(e) => {
                        self.pending_unlock = Some(VaultUnlockState {
                            kind: VaultUnlockKind::OpenWrappedKey,
                            password: String::new(),
                            password_confirm: String::new(),
                            error: Some(format!("Не удалось восстановить ключи: {}", e)),
                        });
                        self.deferred_network_spawn = Some(dn_sp);
                        return;
                    }
                };
                let static_secret = crypto::StaticSecret::from(storage.static_secret_bytes);
                let my_id = PeerId::from(local_key.public());
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
                let contact_addrs_flat: Vec<(PeerId, Multiaddr)> = addrs_map
                    .iter()
                    .flat_map(|(pid, addrs)| addrs.iter().cloned().map(move |a| (*pid, a)))
                    .collect();
                tokio::spawn(run_chat_network(
                    dn_sp.command_rx,
                    dn_sp.event_tx,
                    dn_sp.command_tx_for_mdns,
                    local_key.clone(),
                    static_secret.clone(),
                    dn_sp.void_bootstraps,
                    contact_addrs_flat,
                ));
                self.apply_unlock_success(
                    ctx,
                    local_key,
                    storage.nickname,
                    static_secret,
                    book,
                    addrs_map,
                    master_arr,
                );
            }
            VaultUnlockKind::CreateProfile => {
                let local_key = libp2p::identity::Keypair::generate_ed25519();
                let static_secret =
                    crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                let nickname = format!(
                    "User_{}",
                    &PeerId::from(local_key.public()).to_string()[..4]
                );
                if let Err(e) = Storage::save(
                    &master_arr,
                    &nickname,
                    Some(&local_key),
                    Some(&static_secret),
                    None,
                ) {
                    let _ = std::fs::remove_file(Storage::KEY_FILE);
                    self.pending_unlock = Some(VaultUnlockState {
                        kind: VaultUnlockKind::CreateProfile,
                        password: String::new(),
                        password_confirm: String::new(),
                        error: Some(format!("Не удалось создать vault: {}", e)),
                    });
                    self.deferred_network_spawn = Some(dn_sp);
                    return;
                }

                tokio::spawn(run_chat_network(
                    dn_sp.command_rx,
                    dn_sp.event_tx,
                    dn_sp.command_tx_for_mdns,
                    local_key.clone(),
                    static_secret.clone(),
                    dn_sp.void_bootstraps,
                    Vec::new(),
                ));

                self.apply_unlock_success(
                    ctx,
                    local_key,
                    nickname,
                    static_secret,
                    HashMap::new(),
                    HashMap::new(),
                    master_arr,
                );
            }
        }
    }

    fn apply_unlock_success(
        &mut self,
        ctx: &egui::Context,
        local_key: libp2p::identity::Keypair,
        nickname: String,
        static_secret: crypto::StaticSecret,
        book: HashMap<PeerId, String>,
        addrs_map: HashMap<PeerId, Vec<Multiaddr>>,
        master_arr: Zeroizing<[u8; 32]>,
    ) {
        self.local_peer_id = PeerId::from(local_key.public());
        self.local_nickname = nickname;
        self.known_peers = book;
        self.contact_addrs = addrs_map;
        self._local_static = static_secret;
        self.pending_unlock = None;
        self.vault_master_key = Some(master_arr);

        println!("=== VOID P2P Chat ===");
        println!("Ваш Peer ID: {}", self.local_peer_id);
        println!("Ваш никнейм: {}", self.local_nickname);

        let pid = self.local_peer_id.to_string();
        let tit = pid
            .as_str()
            .get(..8)
            .map(str::to_string)
            .unwrap_or_else(|| pid.clone());
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(format!("VOID Chat [{}]", tit)));

        self.add_status("Vault разблокирован, сеть запущена.".into());
    }

    /// Сохраняет ник и записную книгу в `vault.bin` (AES-GCM под мастер-ключом).
    fn persist_vault(&self) {
        let Some(ref vault_master_key) = self.vault_master_key else {
            return;
        };

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
            vault_master_key,
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

async fn run_chat_network(
    mut command_rx: mpsc::Receiver<UICommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    command_tx_for_mdns: mpsc::Sender<UICommand>,
    local_key: libp2p::identity::Keypair,
    local_static: crypto::StaticSecret,
    void_bootstraps: Vec<Multiaddr>,
    contact_seed_addrs: Vec<(PeerId, Multiaddr)>,
) {
        let mut sessions: HashMap<PeerId, crypto::SecureSession> = HashMap::new();
        let mut pending_handshakes: HashMap<PeerId, crypto::StaticSecret> = HashMap::new();
        let mut pending_messages: HashMap<PeerId, Vec<Vec<u8>>> = HashMap::new();
        let my_public_key = crypto::PublicKey::from(&local_static);
        let local_peer_id = local_key.public().to_peer_id();

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
                    identify: identify::Behaviour::new(
                        identify::Config::new(
                            "/void/v1".into(), // Фиксируем версию для всех
                            key.public(),
                        )
                        // Рассылаем пирам (в т.ч. bootstrap-ноде) обновлённые
                        // listen-адреса при их изменении (UPnP, autonat, relay).
                        // Без этого после смены внешнего IP bootstrap-нода хранит
                        // устаревший адрес и другие пиры не могут нас найти в DHT.
                        .with_push_listen_addr_updates(true),
                    ),
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
                println!(
                    "📇 Стартовый dial контакта {} ({} адр.)",
                    &pid.to_string()[..8],
                    addrs.len()
                );
                let opts = DialOpts::peer_id(*pid)
                    .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                    .addresses(addrs.clone())
                    .build();
                if let Err(e) = swarm.dial(opts) {
                    let s = format!("{:?}", e);
                    if !s.contains("Condition") {
                        eprintln!("contact dial {}: {:?}", pid, e);
                    }
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
        let mut reconnect_tick = tokio::time::interval(Duration::from_secs(15));
        reconnect_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // ─── Tick: переподключение к контактам (15 с) ────────────────
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
                        println!(
                            "🔄 Автореконнект: {} ({} адр., попытка {}).",
                            &pid.to_string()[..8],
                            clean.len(),
                            attempt
                        );
                        let opts = DialOpts::peer_id(pid)
                            .condition(
                                libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing,
                            )
                            .addresses(clean)
                            .build();
                        if let Err(e) = swarm.dial(opts) {
                            let s = format!("{:?}", e);
                            if !s.contains("Condition") {
                                // Обновляем время следующей попытки (следующий backoff-шаг).
                                if let Some(entry) = reconnect_queue.get_mut(&pid) {
                                    let next_delay = match entry.1 {
                                        0..=1 => Duration::from_secs(20),
                                        2 => Duration::from_secs(60),
                                        _ => Duration::from_secs(300),
                                    };
                                    entry.0 = Instant::now() + next_delay;
                                    entry.1 += 1;
                                }
                                eprintln!("reconnect dial {}: {:?}", &pid.to_string()[..8], e);
                            }
                        }
                    }
                }
                // ─── Tick: отправка очередных чанков с rate-limit ───────────
                _ = chunk_tick.tick() => {
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
                                    println!(
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
                            println!(
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

                                if let Some(peer_id) = recipient {
                                    if let Some(session) = sessions.get_mut(&peer_id) {
                                        if let Ok((header, ciphertext)) = session.encrypt_payload(json_data.as_slice()) {
                                            let packet = V1Packet::Encrypted { header, ciphertext };
                                            println!("[{}] 🔒 E2EE: Сообщение зашифровано для {}", now, &peer_id.to_string()[..8]);
                                            let req_id = swarm.behaviour_mut().request_response.send_request(&peer_id, packet);
                                            outbound_msg_requests.insert(req_id, peer_id);
                                            println!("[{}] 📨 RequestResponse: Отправка пиру {}", now, &peer_id.to_string()[..8]);
                                        }
                                    } else {
                                        // Нет сессии — инициируем хендшейк (если ещё не начат)
                                        // и буферизуем сообщение до завершения E2EE.
                                        if !pending_handshakes.contains_key(&peer_id) {
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
                                        pending_messages.entry(peer_id).or_default().push(json_data);
                                        println!("[{}] ⏳ E2EE: Сообщение буферизовано до хендшейка с {}", now, &peer_id.to_string()[..8]);
                                    }
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
                                        } else if !sessions.contains_key(&recipient) {
                                            let _ = event_tx
                                                .send(NetworkEvent::Status(
                                                    "❌ Файл: сначала установите зашифрованный чат с этим контактом (E2EE-сессия)."
                                                        .into(),
                                                ))
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
                                // Используем DialOpts с NotDialing, чтобы mDNS не дублировал попытки
                                // при нескольких событиях для одного пира.
                                if addr.to_string().contains("quic-v1") {
                                    println!("🔍 mDNS: найден пир {} (QUIC). Подключаюсь...", &peer_id.to_string()[..8]);
                                } else {
                                    println!("🔍 mDNS: найден пир {} (TCP). Подключаюсь...", &peer_id.to_string()[..8]);
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
                                        V1Packet::Hello { public_key, ephemeral_key } => {
                                            if peer != local_peer_id {
                                                let is_initiator = local_peer_id < peer;
                                                let _role_str = if is_initiator { "Initiator" } else { "Responder" };

                                                // Новый Hello всегда перезапускает согласование: иначе после рестарта
                                                // пира мы бы оставили старый ratchet и только вернули Ack.
                                                if sessions.contains_key(&peer) {
                                                    println!(
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
                                                let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);

                                                if is_initiator {
                                                    // По PeerId мы «инициатор»; если уже посылали Hello — закрываем пару.
                                                    if let Some(local_ephem_secret) = took_outgoing {
                                                        let session = crypto::SecureSession::new_initiator(&local_static, &remote_static_pub, local_ephem_secret, &remote_ephem_pub);
                                                        sessions.insert(peer, session);
                                                        println!("[{}] 🤝 E2EE: Сессия (Alice/Req) создана с {}", now, &peer.to_string()[..8]);
                                                        if let Some(buffered) = pending_messages.remove(&peer) {
                                                            if let Some(sess) = sessions.get_mut(&peer) {
                                                                for data in buffered {
                                                                    if let Ok((header, ciphertext)) = sess.encrypt_payload(&data) {
                                                                        let pkt = V1Packet::Encrypted { header, ciphertext };
                                                                        let req_id = swarm.behaviour_mut().request_response.send_request(&peer, pkt);
                                                                        outbound_msg_requests.insert(req_id, peer);
                                                                        println!("[{}] 📨 E2EE: Буферизованное сообщение отправлено {}", now, &peer.to_string()[..8]);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, V1Packet::Ack);
                                                    } else {
                                                        // Инициатор по ID, но свой Hello мы ещё не слали — завершаем как responder.
                                                        let local_ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                                        let local_ephem_pub = crypto::PublicKey::from(&local_ephem_secret);

                                                        let session = crypto::SecureSession::new_responder(&local_static, &remote_static_pub, &remote_ephem_pub, local_ephem_secret);
                                                        sessions.insert(peer, session);
                                                        println!("[{}] 🤝 E2EE: Сессия (fallback Res после Hello пира) с {}", now, &peer.to_string()[..8]);
                                                        if let Some(buffered) = pending_messages.remove(&peer) {
                                                            if let Some(sess) = sessions.get_mut(&peer) {
                                                                for data in buffered {
                                                                    if let Ok((header, ciphertext)) = sess.encrypt_payload(&data) {
                                                                        let pkt = V1Packet::Encrypted { header, ciphertext };
                                                                        let req_id = swarm.behaviour_mut().request_response.send_request(&peer, pkt);
                                                                        outbound_msg_requests.insert(req_id, peer);
                                                                        println!("[{}] 📨 E2EE: Буферизованное сообщение отправлено {}", now, &peer.to_string()[..8]);
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        let my_hello = V1Packet::Hello {
                                                            public_key: my_public_key.to_bytes(),
                                                            ephemeral_key: local_ephem_pub.to_bytes(),
                                                        };
                                                        let _ = swarm.behaviour_mut().request_response.send_response(channel, my_hello);
                                                    }
                                                } else {
                                                    // Боб получил Hello от Алисы
                                                    let local_ephem_secret = crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
                                                    let local_ephem_pub = crypto::PublicKey::from(&local_ephem_secret);

                                                    let session = crypto::SecureSession::new_responder(&local_static, &remote_static_pub, &remote_ephem_pub, local_ephem_secret);
                                                    sessions.insert(peer, session);
                                                    println!("[{}] 🤝 E2EE: Сессия (Bob/Res) создана с {}", now, &peer.to_string()[..8]);
                                                    if let Some(buffered) = pending_messages.remove(&peer) {
                                                        if let Some(sess) = sessions.get_mut(&peer) {
                                                            for data in buffered {
                                                                if let Ok((header, ciphertext)) = sess.encrypt_payload(&data) {
                                                                    let pkt = V1Packet::Encrypted { header, ciphertext };
                                                                    let req_id = swarm.behaviour_mut().request_response.send_request(&peer, pkt);
                                                                    outbound_msg_requests.insert(req_id, peer);
                                                                    println!("[{}] 📨 E2EE: Буферизованное сообщение отправлено {}", now, &peer.to_string()[..8]);
                                                                }
                                                            }
                                                        }
                                                    }

                                                    let my_hello = V1Packet::Hello {
                                                        public_key: my_public_key.to_bytes(),
                                                        ephemeral_key: local_ephem_pub.to_bytes(),
                                                    };
                                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, my_hello);
                                                }
                                            }
                                        }
                                        V1Packet::Encrypted { header, ciphertext } => {
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
                                                        } else if let Ok(msg) =
                                                            serde_json::from_slice::<ChatMessage>(
                                                                &plaintext,
                                                            )
                                                        {
                                                            println!(
                                                                "[{}] 🔒 E2EE: Сообщение ДЕШИФРОВАНО от {}",
                                                                now,
                                                                &peer.to_string()[..8]
                                                            );
                                                            let _ = event_tx
                                                                .send(NetworkEvent::ChatMessage(msg))
                                                                .await;
                                                        }
                                                    }
                                                    Err(_) => {
                                                        println!(
                                                            "[{}] ❌ E2EE: Ошибка дешифровки от {}. Сбрасываю...",
                                                            now,
                                                            &peer.to_string()[..8]
                                                        );
                                                        sessions.remove(&peer);
                                                    }
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
                                                if sessions.contains_key(&peer) {
                                                    println!(
                                                        "[{}] 🔄 E2EE: сброс сессии с {} (Hello в ответе)",
                                                        now,
                                                        &peer.to_string()[..8]
                                                    );
                                                    sessions.remove(&peer);
                                                }
                                                let session_exists = sessions.contains_key(&peer);
                                                if is_initiator && !session_exists {
                                                    // Алиса получила Hello от Боба (как ответ)
                                                    let remote_static_pub = crypto::PublicKey::from(public_key);
                                                    let remote_ephem_pub = crypto::PublicKey::from(ephemeral_key);
                                                    if let Some(local_ephem_secret) = pending_handshakes.remove(&peer) {
                                                        let session = crypto::SecureSession::new_initiator(&local_static, &remote_static_pub, local_ephem_secret, &remote_ephem_pub);
                                                        sessions.insert(peer, session);
                                                        println!("[{}] 🤝 E2EE: Сессия (Alice/Res) создана с {}", now, &peer.to_string()[..8]);
                                                        if let Some(buffered) = pending_messages.remove(&peer) {
                                                            if let Some(sess) = sessions.get_mut(&peer) {
                                                                for data in buffered {
                                                                    if let Ok((header, ciphertext)) = sess.encrypt_payload(&data) {
                                                                        let pkt = V1Packet::Encrypted { header, ciphertext };
                                                                        let req_id = swarm.behaviour_mut().request_response.send_request(&peer, pkt);
                                                                        outbound_msg_requests.insert(req_id, peer);
                                                                        println!("[{}] 📨 E2EE: Буферизованное сообщение отправлено {}", now, &peer.to_string()[..8]);
                                                                    }
                                                                }
                                                            }
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
                                                    } else if let Ok(msg) =
                                                        serde_json::from_slice::<ChatMessage>(
                                                            &plaintext,
                                                        )
                                                    {
                                                        let _ = event_tx
                                                            .send(NetworkEvent::ChatMessage(msg))
                                                            .await;
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
                            // Соединение установлено — снимаем задание на реконнект.
                            reconnect_queue.remove(&peer_id);

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

                            // E2EE: при обрыве TCP/QUIC сбрасываем криптосостояние с пиром.
                            // Иначе после рестарта одного клиента второй держит «старый» ratchet
                            // и новые Hello игнорируются (отправлялся только Ack → чат мёртв).
                            sessions.remove(&peer_id);
                            pending_handshakes.remove(&peer_id);
                            pending_messages.remove(&peer_id);

                            // Планируем переподключение для контактов из vault.
                            // Backoff: 5 с → 20 с → 60 с → 5 мин (и далее 5 мин).
                            if reconnect_targets.contains_key(&peer_id) {
                                // Не накапливаем reconnect-очередь для уже-диалящихся (swarm сам retry).
                                let attempt = reconnect_queue
                                    .get(&peer_id)
                                    .map(|(_, a)| *a)
                                    .unwrap_or(0);
                                let delay = match attempt {
                                    0 => Duration::from_secs(5),
                                    1 => Duration::from_secs(20),
                                    2 => Duration::from_secs(60),
                                    _ => Duration::from_secs(300),
                                };
                                reconnect_queue.insert(
                                    peer_id,
                                    (Instant::now() + delay, attempt + 1),
                                );
                                println!(
                                    "🔄 Реконнект запланирован: {} через {}с (попытка {}).",
                                    &peer_id.to_string()[..8],
                                    delay.as_secs(),
                                    attempt + 1
                                );
                            }

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

                                // Если это настоящий VOID-клиент — сохраним его
                                // listen-адрес в контактной книге, чтобы связь поднялась
                                // после рестарта без ручного ПОДКЛЮЧИТЬ.
                                if has_chat && peer_id != local_peer_id {
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

    let vault_unlock_kind =
        detect_vault_unlock_kind().map_err(|m| Box::<dyn Error>::from(m))?;

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
    let (command_tx, command_rx) = mpsc::channel(256);
    let command_tx_for_mdns = command_tx.clone();

    let deferred_network_spawn = DeferredNetworkSpawn {
        event_tx: event_tx.clone(),
        command_rx,
        command_tx_for_mdns,
        void_bootstraps,
    };

    let pending_unlock_state = VaultUnlockState {
        kind: vault_unlock_kind,
        password: String::new(),
        password_confirm: String::new(),
        error: None,
    };

    let placeholder_kp = libp2p::identity::Keypair::generate_ed25519();
    let placeholder_peer_id = PeerId::from(placeholder_kp.public());
    let placeholder_static_secret =
        crypto::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);

    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([820.0, 540.0])
        .with_title("VOID — пароль vault");

    eframe::run_native(
        "VOID P2P",
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(move |cc| {
            Ok(Box::new(App::new(
                cc,
                Some(pending_unlock_state),
                Some(deferred_network_spawn),
                None,
                placeholder_peer_id,
                "Разблокировка…".into(),
                placeholder_static_secret,
                HashMap::new(),
                HashMap::new(),
                command_tx,
                event_rx,
            )))
        }),
    )
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
