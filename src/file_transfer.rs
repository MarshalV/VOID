//! Передача файлов по sub-протоколу `/void/file/1.0.0` (офферы, принятие).
//!
//! Особенности:
//! * **Содержимое чанков** шифруется тем же Double Ratchet (`SecureSession`),
//!   что и чат (`/void/chat/1.0.0`): шум транспортного уровня не раскрывает файлы оператору relay.
//! * Метаданные оффера (имя, размер, хэш для целостности) всё ещё идут по `/void/file/1.0.0`.
//! * Чанковая передача: файл разбивается на куски `FILE_CHUNK_SIZE` байт.
//! * Integrity: BLAKE2b-512 (первые 32 байта) всего файла проверяется на приёмнике.
//! * Rate-limit на relay: если соединение идёт через p2p-circuit relay,
//!   скорость отправки ограничивается `RELAY_RATE_LIMIT_BPS` байт/сек.
//! * Обычные файлы хранятся в локальном кэше (`files/`) как AES-256-GCM (ключ из vault).
//! * «Скачать» расшифровывает копию в `Загрузки/VOID Messenger/`.
//! * Удаление файла из чата стирает кэш; копии в Загрузках не трогаем.
//! * Голосовые — в каталоге данных приложения (`voice/`), не в Загрузках.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{Duration, Instant};

// ─── Тип файла ────────────────────────────────────────────────────────────────

/// Категория файла: влияет на фильтры диалога выбора, иконку и отображение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FileKind {
    Image,
    Audio,
    #[default]
    Other,
}

impl FileKind {
    /// Определяет тип по расширению файла.
    pub fn from_filename(name: &str) -> Self {
        let ext = std::path::Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match ext.as_str() {
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "tiff" | "tif" | "avif"
            | "ico" | "svg" => FileKind::Image,
            "mp3" | "ogg" | "flac" | "wav" | "aac" | "m4a" | "opus" | "wma" | "aiff"
            | "ape" | "mid" | "midi" => FileKind::Audio,
            _ => FileKind::Other,
        }
    }

    /// Эмодзи-иконка для UI.
    #[cfg(feature = "egui-ui")]
    pub fn icon(self) -> &'static str {
        match self {
            FileKind::Image => "🖼",
            FileKind::Audio => "🎵",
            FileKind::Other => "📄",
        }
    }

    /// Читаемое название для hover-текста.
    pub fn label(self) -> &'static str {
        match self {
            FileKind::Image => "Изображение",
            FileKind::Audio => "Аудио",
            FileKind::Other => "Файл",
        }
    }

    /// Расширения для фильтра диалога выбора.
    #[cfg(feature = "egui-ui")]
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            FileKind::Image => &[
                "png", "jpg", "jpeg", "gif", "webp", "bmp", "tiff", "tif", "avif", "ico",
            ],
            FileKind::Audio => &[
                "mp3", "ogg", "flac", "wav", "aac", "m4a", "opus", "wma", "aiff", "ape",
            ],
            FileKind::Other => &[],
        }
    }
}

// ─── Константы ───────────────────────────────────────────────────────────────

/// ID sub-протокола (отдельно от чата `/void/chat/1.0.0`).
pub const FILE_PROTOCOL_ID: &str = "/void/file/1.0.0";

/// Размер одного чанка при передаче: 32 КБ.
pub const FILE_CHUNK_SIZE: usize = 32 * 1024;

/// Максимально допустимый размер файла: 512 МБ.
pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Максимальная длина имени файла в оффере (защита от DoS по памяти в JSON RR).
pub const MAX_OFFER_FILENAME_BYTES: usize = 512;

/// Максимальная длина поля `Reject.reason` (байты UTF-8).
pub const MAX_REJECT_REASON_BYTES: usize = 512;

/// Устаревший plain-чанк по `/void/file`: не больше одного логического чанка файла.
pub const MAX_LEGACY_CHUNK_DATA_BYTES: usize = FILE_CHUNK_SIZE;

/// Скорость отправки через relay: 64 КБ/с.
pub const RELAY_RATE_LIMIT_BPS: u64 = 64 * 1024;

/// Минимальный интервал между чанками при прямом соединении.
pub const DIRECT_CHUNK_DELAY: Duration = Duration::from_millis(5);

/// Имя папки в системных «Загрузках» (как `Telegram Desktop`) — только явный «Скачать».
pub const USER_DOWNLOADS_FOLDER: &str = "VOID Messenger";

/// Устаревшая папка в каталоге данных (до переноса в Загрузки).
pub const DOWNLOADS_DIR: &str = "void_downloads";

/// Локальный кэш вложений чата (не Загрузки).
pub const FILES_CACHE_DIR: &str = "files";

/// Подпапка голосовых в каталоге данных приложения.
pub const VOICE_DIR: &str = "voice";

/// Устаревший путь голосовых (искать при открытии старых сообщений).
const LEGACY_VOICE_DIR: &str = "void_downloads/voice";

/// Префикс имени файла голосового сообщения.
pub const VOICE_FILENAME_PREFIX: &str = "void_voice_";

/// Имя WAV-файла для голосового сообщения по transfer_id.
pub fn voice_filename(transfer_id: &[u8; 16]) -> String {
    format!(
        "{}{}.wav",
        VOICE_FILENAME_PREFIX,
        transfer_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    )
}

/// Голосовое сообщение по имени файла (не обычное аудио-вложение).
pub fn is_voice_filename(name: &str) -> bool {
    name.starts_with(VOICE_FILENAME_PREFIX) && name.ends_with(".wav")
}

/// 32 hex-символа transfer_id из имени `void_voice_<hex>.wav` (в т.ч. `_(1)`).
pub fn voice_transfer_hex_from_filename(name: &str) -> Option<String> {
    let safe = safe_filename(name);
    let rest = safe.strip_prefix(VOICE_FILENAME_PREFIX)?;
    let hex: String = rest
        .chars()
        .take(32)
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() == 32 {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// Абсолютный путь к каталогу голосовых (в каталоге данных VOID).
pub fn voice_dir_absolute() -> std::path::PathBuf {
    let dir = crate::paths::data_dir().join(VOICE_DIR);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Все каталоги, где могут лежать WAV (текущий + устаревший рядом с exe / в data).
pub(crate) fn voice_search_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![voice_dir_absolute()];
    let data = crate::paths::data_dir();
    for extra in [
        data.join(LEGACY_VOICE_DIR),
        data.join(DOWNLOADS_DIR).join("voice"),
    ] {
        if !dirs.iter().any(|d| d == &extra) {
            dirs.push(extra);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            for extra in [parent.join(VOICE_DIR), parent.join(LEGACY_VOICE_DIR)] {
                if !dirs.iter().any(|d| d == &extra) {
                    dirs.push(extra);
                }
            }
        }
    }
    dirs
}

/// Каталог копий по кнопке «Скачать»: `Загрузки/VOID Messenger`.
pub fn user_file_downloads_dir() -> std::path::PathBuf {
    let base = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .unwrap_or_else(crate::paths::data_dir);
    let dir = base.join(USER_DOWNLOADS_FOLDER);
    if std::fs::create_dir_all(&dir).is_err() {
        let fallback = crate::paths::data_dir().join(USER_DOWNLOADS_FOLDER);
        let _ = std::fs::create_dir_all(&fallback);
        return fallback;
    }
    dir
}

/// Локальный кэш вложений (каталог данных VOID / `files`).
/// Файлы на диске — AES-256-GCM; без мастер-ключа vault это непрозрачный шифротекст.
pub fn file_cache_dir() -> std::path::PathBuf {
    let dir = crate::paths::data_dir().join(FILES_CACHE_DIR);
    let _ = std::fs::create_dir_all(&dir);
    harden_file_cache_dir(&dir);
    dir
}

fn harden_file_cache_dir(dir: &std::path::Path) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            let _ = std::process::Command::new("attrib")
                .args(["+H"])
                .arg(dir)
                .creation_flags(CREATE_NO_WINDOW)
                .status();
            if let Ok(user) = std::env::var("USERNAME") {
                let grant = format!("{user}:(OI)(CI)F");
                let _ = std::process::Command::new("icacls")
                    .arg(dir)
                    .args(["/inheritance:r", "/grant:r", &grant])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status();
            }
        }
    });
}

const FILE_CACHE_MAGIC_V1: &[u8; 8] = b"VOIDFC01";
const FILE_CACHE_MAGIC_V2: &[u8; 8] = b"VOIDFC02";
const FILE_CACHE_NONCE_LEN: usize = 12;
const FILE_CACHE_TAG_LEN: usize = 16;
const FILE_CACHE_OVERHEAD: u64 =
    (FILE_CACHE_MAGIC_V2.len() + FILE_CACHE_NONCE_LEN + FILE_CACHE_TAG_LEN) as u64;

/// Отдельный ключ кэша: HKDF-SHA256 от мастер-ключа vault (не сам master).
pub fn derive_file_cache_key(vault_master: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"VOID_FILE_CACHE_SALT_v1"), vault_master);
    let mut okm = [0u8; 32];
    hk.expand(b"VOID_FILE_CACHE_v1", &mut okm)
        .expect("HKDF file cache key");
    okm
}

pub fn is_encrypted_cache_blob(data: &[u8]) -> bool {
    data.len() >= FILE_CACHE_MAGIC_V1.len() + FILE_CACHE_NONCE_LEN + FILE_CACHE_TAG_LEN
        && (data.starts_with(FILE_CACHE_MAGIC_V1) || data.starts_with(FILE_CACHE_MAGIC_V2))
}

/// Внутреннее имя кэша (`*.vfc`) нельзя показывать в чате и класть в Загрузки.
pub fn is_cache_blob_filename(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("vfc"))
        .unwrap_or(false)
}

/// Имя для оффера/UI: явное исходное имя, иначе имя пути, но не `*.vfc`.
pub fn offer_filename(path: &str, explicit: &str) -> String {
    let from_explicit = safe_filename(explicit);
    if from_explicit != "file" && !is_cache_blob_filename(&from_explicit) {
        return from_explicit;
    }
    let from_path = safe_filename(path);
    if !is_cache_blob_filename(&from_path) {
        return from_path;
    }
    "file".into()
}

/// Подпись в чате: не показываем хеш `.vfc`.
pub fn display_filename(name: &str) -> String {
    if name.trim().is_empty() || is_cache_blob_filename(name) {
        "Файл".into()
    } else {
        name.to_string()
    }
}

/// Если в метаданных осталось `.vfc`, угадываем расширение по сигнатуре.
pub fn filename_from_bytes(preferred: &str, data: &[u8]) -> String {
    let preferred = safe_filename(preferred);
    if preferred != "file" && !is_cache_blob_filename(&preferred) {
        return preferred;
    }
    let ext = sniff_extension(data).unwrap_or("bin");
    format!("file.{ext}")
}

fn sniff_extension(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some("mp4");
    }
    if data.len() >= 8 && &data[4..8] == b"moov" {
        return Some("mov");
    }
    if data.starts_with(b"%PDF") {
        return Some("pdf");
    }
    if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some("png");
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpg");
    }
    if data.starts_with(b"GIF8") {
        return Some("gif");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some("webp");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WAVE" {
        return Some("wav");
    }
    if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some("webm");
    }
    if data.starts_with(b"PK\x03\x04") {
        return Some("zip");
    }
    if data.starts_with(b"ID3") {
        return Some("mp3");
    }
    if data.starts_with(b"OggS") {
        return Some("ogg");
    }
    if data.starts_with(b"fLaC") {
        return Some("flac");
    }
    if data.starts_with(&[0x1F, 0x8B]) {
        return Some("gz");
    }
    None
}

/// Размер исходного файла (для UI/оффера). У шифротекста вычитается заголовок GCM.
pub fn advertised_plain_size(path: &std::path::Path) -> u64 {
    let meta = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut hdr = [0u8; 8];
    let encrypted = std::fs::File::open(path)
        .ok()
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut hdr).ok()?;
            Some(hdr == *FILE_CACHE_MAGIC_V1 || hdr == *FILE_CACHE_MAGIC_V2)
        })
        .unwrap_or(false);
    if encrypted {
        meta.saturating_sub(FILE_CACHE_OVERHEAD)
    } else {
        meta
    }
}

fn pack_named_plain(filename: &str, data: &[u8]) -> Vec<u8> {
    let name = safe_filename(filename);
    let name_bytes = name.as_bytes();
    let n = name_bytes.len().min(u16::MAX as usize) as u16;
    let mut v = Vec::with_capacity(2 + n as usize + data.len());
    v.extend_from_slice(&n.to_le_bytes());
    v.extend_from_slice(&name_bytes[..n as usize]);
    v.extend_from_slice(data);
    v
}

fn unpack_named_plain(plain: &[u8]) -> (Option<String>, &[u8]) {
    if plain.len() < 2 {
        return (None, plain);
    }
    let n = u16::from_le_bytes([plain[0], plain[1]]) as usize;
    if 2 + n > plain.len() {
        return (None, plain);
    }
    let name = String::from_utf8(plain[2..2 + n].to_vec()).ok();
    let name = name.filter(|s| !s.is_empty() && !is_cache_blob_filename(s));
    (name, &plain[2 + n..])
}

fn encrypt_cache_blob(key: &[u8; 32], filename: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let packed = pack_named_plain(filename, plaintext);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; FILE_CACHE_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), packed.as_ref())
        .map_err(|e| format!("file cache encrypt: {e}"))?;
    let mut out = Vec::with_capacity(FILE_CACHE_MAGIC_V2.len() + nonce_bytes.len() + ct.len());
    out.extend_from_slice(FILE_CACHE_MAGIC_V2);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

struct CachePlain {
    filename: Option<String>,
    data: Vec<u8>,
}

fn decrypt_cache_blob(key: &[u8; 32], blob: &[u8]) -> Result<CachePlain, String> {
    if !is_encrypted_cache_blob(blob) {
        return Err("файл кэша повреждён или не зашифрован".into());
    }
    let v2 = blob.starts_with(FILE_CACHE_MAGIC_V2);
    let nonce = &blob[8..8 + FILE_CACHE_NONCE_LEN];
    let ct = &blob[8 + FILE_CACHE_NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "не удалось расшифровать кэш (неверный ключ vault?)".to_string())?;
    if v2 {
        let (filename, data) = unpack_named_plain(&plain);
        Ok(CachePlain {
            filename,
            data: data.to_vec(),
        })
    } else {
        Ok(CachePlain {
            filename: None,
            data: plain,
        })
    }
}

/// Пишет вложение в кэш как AES-256-GCM (атомарно: tmp + rename).
/// В шифротекст кладётся исходное имя файла — в Загрузки оно вернётся как есть.
pub fn write_encrypted_cache(
    path: &std::path::Path,
    plaintext: &[u8],
    key: &[u8; 32],
    original_filename: &str,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("не удалось создать {}: {e}", parent.display()))?;
        harden_file_cache_dir(parent);
    }
    let blob = encrypt_cache_blob(key, original_filename, plaintext)?;
    let tmp = path.with_extension("vfc.tmp");
    std::fs::write(&tmp, &blob)
        .map_err(|e| format!("не удалось записать {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).or_else(|_| {
        std::fs::write(path, &blob)
            .map_err(|e| format!("не удалось записать {}: {e}", path.display()))
    })?;
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

/// Читает вложение: расшифровывает VOIDFC01/02, иначе отдаёт plaintext (старый кэш).
pub fn read_cache_plain(path: &std::path::Path, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    Ok(read_cache_entry(path, key)?.data)
}

fn read_cache_entry(path: &std::path::Path, key: &[u8; 32]) -> Result<CachePlain, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))?;
    if is_encrypted_cache_blob(&data) {
        return decrypt_cache_blob(key, &data);
    }
    let guessed = filename_from_bytes(
        &path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        &data,
    );
    if is_under_file_cache(path) {
        let _ = write_encrypted_cache(path, &data, key, &guessed);
    }
    Ok(CachePlain {
        filename: Some(guessed).filter(|s| !is_cache_blob_filename(s)),
        data,
    })
}

/// Путь кэша: только transfer_id, без исходного имени файла.
pub fn cache_path_for(transfer_id_hex: &str, _filename: &str) -> std::path::PathBuf {
    let dir = file_cache_dir();
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{}.vfc", transfer_id_hex.to_ascii_lowercase()))
}

pub fn legacy_cache_path(transfer_id_hex: &str, filename: &str) -> std::path::PathBuf {
    file_cache_dir().join(format!(
        "{}_{}",
        transfer_id_hex.to_ascii_lowercase(),
        safe_filename(filename)
    ))
}

fn path_is_under(path: &std::path::Path, dir: &std::path::Path) -> bool {
    let canon_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let canon_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    #[cfg(windows)]
    {
        let p = canon_path.to_string_lossy().to_ascii_lowercase();
        let d = canon_dir.to_string_lossy().to_ascii_lowercase();
        !d.is_empty() && p.starts_with(&d)
    }
    #[cfg(not(windows))]
    {
        canon_path.starts_with(&canon_dir)
    }
}

/// Файл лежит в локальном кэше чата (его можно удалять вместе с сообщением).
pub fn is_under_file_cache(path: &std::path::Path) -> bool {
    path_is_under(path, &file_cache_dir())
}

/// Кладёт копию в кэш чата (на диске — шифротекст). Исходный файл не трогает.
pub fn copy_into_file_cache(
    src: &std::path::Path,
    transfer_id_hex: &str,
    filename: &str,
    key: &[u8; 32],
) -> Result<std::path::PathBuf, String> {
    if !src.is_file() {
        return Err(format!("исходный файл не найден: {}", src.display()));
    }
    let dest = cache_path_for(transfer_id_hex, filename);
    if dest.is_file() {
        return Ok(dest);
    }
    let plain = if is_under_file_cache(src) {
        read_cache_plain(src, key)?
    } else {
        std::fs::read(src).map_err(|e| format!("не удалось прочитать {}: {e}", src.display()))?
    };
    write_encrypted_cache(&dest, &plain, key, filename)?;
    Ok(dest)
}

/// Расшифровывает кэш в `Загрузки/VOID Messenger` под исходным именем файла.
pub fn export_cached_to_downloads(
    src: &std::path::Path,
    filename: &str,
    key: &[u8; 32],
) -> Result<std::path::PathBuf, String> {
    if !src.is_file() {
        return Err("файла нет в локальном хранилище".into());
    }
    let entry = read_cache_entry(src, key)?;
    let name = filename_from_bytes(
        if !is_cache_blob_filename(filename) {
            filename
        } else {
            entry.filename.as_deref().unwrap_or(filename)
        },
        &entry.data,
    );
    let dest = unique_download_path(&name);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("не удалось создать {}: {e}", parent.display()))?;
    }
    std::fs::write(&dest, &entry.data)
        .map_err(|e| format!("не удалось записать {}: {e}", dest.display()))?;
    Ok(dest)
}

/// Удаляет файл только если он в кэше чата — не Загрузки и не исходник пользователя.
pub fn delete_cached_file(path: &std::path::Path) {
    if path.is_file() && is_under_file_cache(path) {
        let _ = std::fs::remove_file(path);
    }
}

/// Каталоги поиска копии: кэш, затем устаревшие папки (миграция старых чатов).
pub fn file_search_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![file_cache_dir()];
    let data = crate::paths::data_dir();
    for extra in [
        data.join(DOWNLOADS_DIR),
        user_file_downloads_dir(),
    ] {
        if !dirs.iter().any(|d| d == &extra) {
            dirs.push(extra);
        }
    }
    dirs
}

/// Префикс открытого текста перед Double Ratchet: не начинается с `{`, чтобы отличаться от JSON чата.
pub const FILE_CHUNK_E2EE_MAGIC: &[u8; 4] = b"VfC1";

/// Кодирует один чанк для `SecureSession::encrypt_payload` / `decrypt_payload`.
pub fn encode_e2ee_file_chunk_frame(
    transfer_id: &[u8; 16],
    chunk_index: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(FILE_CHUNK_E2EE_MAGIC.len() + 16 + 4 + data.len());
    v.extend_from_slice(FILE_CHUNK_E2EE_MAGIC);
    v.extend_from_slice(transfer_id);
    v.extend_from_slice(&chunk_index.to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// Разбор результата `decrypt_payload`, если это чанк файла.
pub fn try_decode_e2ee_file_chunk_frame(buf: &[u8]) -> Option<([u8; 16], u32, Vec<u8>)> {
    const HEADER: usize = FILE_CHUNK_E2EE_MAGIC.len() + 16 + 4;
    if buf.len() < HEADER || &buf[..4] != FILE_CHUNK_E2EE_MAGIC {
        return None;
    }
    let mut tid = [0u8; 16];
    tid.copy_from_slice(&buf[4..20]);
    let idx = u32::from_le_bytes(buf[20..HEADER].try_into().ok()?);
    Some((tid, idx, buf[HEADER..].to_vec()))
}

/// Вычисляет задержку между чанками для relay-соединения.
pub fn relay_chunk_delay() -> Duration {
    let ms = (FILE_CHUNK_SIZE as u64 * 1000) / RELAY_RATE_LIMIT_BPS;
    Duration::from_millis(ms)
}

/// Проверка входящего `Offer` до выделения буферов чанков.
pub fn validate_file_offer(
    filename: &str,
    total_size: u64,
    total_chunks: u32,
) -> Result<(), &'static str> {
    if filename.len() > MAX_OFFER_FILENAME_BYTES {
        return Err("слишком длинное имя файла в оффере");
    }
    if total_size == 0 || total_size > MAX_FILE_SIZE {
        return Err("некорректный размер файла в оффере");
    }
    let chunk_sz = FILE_CHUNK_SIZE as u64;
    let expected = ((total_size + chunk_sz - 1) / chunk_sz) as u32;
    if total_chunks == 0 || total_chunks != expected {
        return Err("несогласованы размер файла и число чанков");
    }
    Ok(())
}

/// Обрезает строку по границе UTF-8, не превышая `max_bytes` байт.
pub fn clamp_utf8_by_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Проверка входящего `FilePacket` после JSON-десериализации (DoS по полям).
pub fn validate_inbound_file_packet(p: &FilePacket) -> Result<(), &'static str> {
    match p {
        FilePacket::Offer {
            filename,
            total_size,
            total_chunks,
            ..
        } => validate_file_offer(filename, *total_size, *total_chunks),
        FilePacket::Reject { reason, .. } => {
            if reason.len() > MAX_REJECT_REASON_BYTES {
                return Err("слишком длинная причина отклонения файла");
            }
            Ok(())
        }
        FilePacket::Chunk { data, .. } => {
            if data.len() > MAX_LEGACY_CHUNK_DATA_BYTES {
                return Err("слишком большой устаревший чанк файла");
            }
            Ok(())
        }
        FilePacket::Accept { .. } | FilePacket::Cancel { .. } | FilePacket::Ack | FilePacket::Request { .. } => Ok(()),
    }
}

// ─── Пакеты протокола ─────────────────────────────────────────────────────────

/// Все пакеты файлового sub-протокола.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilePacket {
    /// Отправитель → получатель: предложение файла.
    Offer {
        transfer_id: [u8; 16],
        filename: String,
        total_size: u64,
        total_chunks: u32,
        /// BLAKE2b-512 хэш всего файла (первые 32 байта).
        sha256: [u8; 32],
        /// Категория файла (Image / Audio / Other).
        #[serde(default)]
        kind: FileKind,
    },
    /// Получатель → отправитель: принять файл.
    Accept { transfer_id: [u8; 16] },
    /// Получатель → отправитель: отклонить файл.
    Reject {
        transfer_id: [u8; 16],
        reason: String,
    },
    /// Отправитель → получатель: один чанк данных (**устарело**: новые узлы шлют чанки по E2EE чата).
    /// Оставлено для совместимости со старыми пирами.
    Chunk {
        transfer_id: [u8; 16],
        chunk_index: u32,
        data: Vec<u8>,
    },
    /// Либая сторона → другой: прервать передачу.
    Cancel { transfer_id: [u8; 16] },
    /// Получатель → отправитель: пришли файл ещё раз (локальная копия удалена).
    Request { transfer_id: [u8; 16] },
    /// Универсальное подтверждение (ответ на большинство пакетов).
    Ack,
}

// ─── Исходящая передача (мы — отправитель) ──────────────────────────────────

pub struct OutgoingTransfer {
    pub peer: PeerId,
    #[allow(dead_code)]
    pub transfer_id: [u8; 16],
    pub filename: String,
    pub chunks: Vec<Vec<u8>>,
    pub next_chunk: usize,
    pub total_size: u64,
    pub is_relay: bool,
    pub last_chunk_at: Instant,
    /// Флаг: получатель принял оффер и ждёт чанки.
    pub accepted: bool,
    /// Ждём Ack/Failure на последний отправленный чанк (stop-and-wait).
    /// Иначе при Hello вместо Ack чанк теряется, а transfer уже удалён.
    pub chunk_inflight: bool,
    pub sha256: [u8; 32],
    pub kind: FileKind,
}

impl OutgoingTransfer {
    pub fn build_offer(&self) -> FilePacket {
        FilePacket::Offer {
            transfer_id: self.transfer_id,
            filename: self.filename.clone(),
            total_size: self.total_size,
            total_chunks: self.total_chunks(),
            sha256: self.sha256,
            kind: self.kind,
        }
    }

    /// true — пора слать следующий чанк (с учётом rate-limit и stop-and-wait).
    pub fn ready_to_send(&self) -> bool {
        if !self.accepted || self.chunk_inflight || self.next_chunk >= self.chunks.len() {
            return false;
        }
        let delay = if self.is_relay {
            relay_chunk_delay()
        } else {
            DIRECT_CHUNK_DELAY
        };
        self.last_chunk_at.elapsed() >= delay
    }

    /// Все чанки ушли и подтверждены (нет inflight).
    pub fn all_chunks_acked(&self) -> bool {
        self.accepted && !self.chunk_inflight && self.next_chunk >= self.chunks.len()
    }

    pub fn total_chunks(&self) -> u32 {
        self.chunks.len() as u32
    }
}

// ─── Входящая передача (мы — получатель) ─────────────────────────────────────

pub struct IncomingTransfer {
    #[allow(dead_code)]
    pub peer: PeerId,
    #[allow(dead_code)]
    pub transfer_id: [u8; 16],
    pub filename: String,
    pub total_size: u64,
    pub total_chunks: u32,
    pub sha256: [u8; 32],
    /// Принятые чанки. `None` = ещё не получен.
    pub chunks: Vec<Option<Vec<u8>>>,
    pub received_count: u32,
    pub kind: FileKind,
    /// Директория сохранения, выбранная пользователем. `None` → `Загрузки/VOID Messenger`.
    pub save_dir: Option<String>,
}

impl IncomingTransfer {
    pub fn new(
        peer: PeerId,
        transfer_id: [u8; 16],
        filename: String,
        total_size: u64,
        total_chunks: u32,
        sha256: [u8; 32],
        kind: FileKind,
    ) -> Self {
        Self {
            peer,
            transfer_id,
            filename,
            total_size,
            total_chunks,
            sha256,
            chunks: vec![None; total_chunks as usize],
            received_count: 0,
            kind,
            save_dir: None,
        }
    }

    /// Записывает чанк. Возвращает `true`, если все чанки получены.
    pub fn receive_chunk(&mut self, index: u32, data: Vec<u8>) -> bool {
        let i = index as usize;
        if i < self.chunks.len() && self.chunks[i].is_none() {
            self.chunks[i] = Some(data);
            self.received_count += 1;
        }
        self.received_count >= self.total_chunks
    }

    /// Собирает все данные из чанков. `None`, если есть пропуски.
    pub fn assemble(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(self.total_size as usize);
        for chunk in &self.chunks {
            out.extend_from_slice(chunk.as_ref()?);
        }
        Some(out)
    }
}

// ─── Ожидающее предложение файла (UI ещё не ответил) ─────────────────────────

#[cfg(feature = "egui-ui")]
#[derive(Clone)]
pub struct PendingFileOffer {
    pub transfer_id: [u8; 16],
    pub from: PeerId,
    pub filename: String,
    pub total_size: u64,
    pub kind: FileKind,
}

// ─── Хэш файла ───────────────────────────────────────────────────────────────

/// Вычисляет BLAKE2b-512 хэш, возвращает первые 32 байта.
pub fn hash_file(data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b512, Digest};
    let mut h = Blake2b512::new();
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

/// Разбивает данные на чанки `FILE_CHUNK_SIZE`.
pub fn split_into_chunks(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(FILE_CHUNK_SIZE)
        .map(|c| c.to_vec())
        .collect()
}

/// Формирует безопасное имя файла (без пути, без `..`).
pub fn safe_filename(raw: &str) -> String {
    let name = std::path::Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let cleaned: String = name
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\0')
        })
        .collect();
    let cleaned = cleaned
        .trim()
        .trim_start_matches('.')
        .trim()
        .to_string();
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

/// Формирует уникальный путь к файлу в `Загрузки/VOID Messenger`,
/// добавляя суффикс _(1), _(2)… если файл уже существует.
pub fn unique_download_path(filename: &str) -> std::path::PathBuf {
    unique_download_path_in_path(&user_file_downloads_dir(), filename)
}

/// Формирует уникальный путь к файлу в указанной директории.
/// Создаёт директорию при необходимости.
pub fn unique_download_path_in_path(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(filename);
    if !path.exists() {
        return path;
    }
    let stem = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);
    let ext = std::path::Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    for i in 1u32.. {
        let candidate = if ext.is_empty() {
            dir.join(format!("{}_({i})", stem))
        } else {
            dir.join(format!("{}_({i}).{}", stem, ext))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

/// Формирует уникальный путь к файлу в указанной директории (строковый путь).
/// Создаёт директорию при необходимости.
pub fn unique_download_path_in(dir: &str, filename: &str) -> std::path::PathBuf {
    unique_download_path_in_path(std::path::Path::new(dir), filename)
}

/// Копирует записанный WAV в каталог голосовых с именем по transfer_id.
pub fn stage_voice_wav(
    src: &std::path::Path,
    transfer_id: &[u8; 16],
) -> Result<std::path::PathBuf, String> {
    if !src.is_file() {
        return Err(format!("исходный файл не найден: {}", src.display()));
    }
    let voice_name = voice_filename(transfer_id);
    let dir = voice_dir_absolute();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("не удалось создать {}: {e}", dir.display()))?;
    let dest = unique_download_path_in_path(&dir, &voice_name);
    if std::fs::copy(src, &dest).is_err() {
        let data = std::fs::read(src)
            .map_err(|e| format!("не удалось прочитать {}: {e}", src.display()))?;
        std::fs::write(&dest, &data)
            .map_err(|e| format!("не удалось записать {}: {e}", dest.display()))?;
    }
    if !dest.is_file() {
        return Err(format!("файл не создан: {}", dest.display()));
    }
    Ok(dest)
}

/// Форматирует размер в байтах в читаемую строку (КБ/МБ/ГБ).
#[cfg(feature = "egui-ui")]
pub fn fmt_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} ГБ", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} МБ", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} КБ", bytes as f64 / KB as f64)
    } else {
        format!("{} Б", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_offer_ok_one_chunk() {
        assert!(validate_file_offer("a.txt", 100, 1).is_ok());
    }

    #[test]
    fn validate_offer_rejects_chunk_mismatch() {
        assert!(validate_file_offer("a.txt", 100, 2).is_err());
    }

    #[test]
    fn validate_offer_rejects_zero_size() {
        assert!(validate_file_offer("a.txt", 0, 0).is_err());
    }

    #[test]
    fn inbound_reject_reason_too_long() {
        let reason = "x".repeat(MAX_REJECT_REASON_BYTES + 1);
        let p = FilePacket::Reject {
            transfer_id: [0u8; 16],
            reason,
        };
        assert!(validate_inbound_file_packet(&p).is_err());
    }

    #[test]
    fn inbound_chunk_too_large() {
        let p = FilePacket::Chunk {
            transfer_id: [0u8; 16],
            chunk_index: 0,
            data: vec![0u8; MAX_LEGACY_CHUNK_DATA_BYTES + 1],
        };
        assert!(validate_inbound_file_packet(&p).is_err());
    }

    #[test]
    fn clamp_utf8_respects_boundary() {
        let s = "абв"; // 6 bytes in UTF-8
        assert_eq!(clamp_utf8_by_bytes(s, 5).len(), 4);
    }

    #[test]
    fn file_cache_roundtrip_and_wrong_key() {
        let mut master = [0u8; 32];
        master[0] = 7;
        let key = derive_file_cache_key(&master);
        let plain = b"secret-attachment-bytes";
        let blob = encrypt_cache_blob(&key, "video.mp4", plain).unwrap();
        assert!(blob.starts_with(FILE_CACHE_MAGIC_V2));
        assert!(is_encrypted_cache_blob(&blob));
        let got = decrypt_cache_blob(&key, &blob).unwrap();
        assert_eq!(got.filename.as_deref(), Some("video.mp4"));
        assert_eq!(got.data, plain);
        let mut other = master;
        other[0] = 9;
        let bad = derive_file_cache_key(&other);
        assert!(decrypt_cache_blob(&bad, &blob).is_err());
    }

    #[test]
    fn offer_filename_ignores_vfc() {
        assert_eq!(
            offer_filename("C:/cache/abc.vfc", "holiday.mp4"),
            "holiday.mp4"
        );
        assert_eq!(offer_filename("C:/cache/abc.vfc", ""), "file");
        assert_eq!(display_filename("abc.vfc"), "Файл");
        assert_eq!(
            filename_from_bytes("x.vfc", b"%PDF-1.7 leftover"),
            "file.pdf"
        );
    }
}
