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
//! * Файлы сохраняются в папку `void_downloads/` рядом с исполняемым файлом.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
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

/// Папка для сохранения принятых файлов.
pub const DOWNLOADS_DIR: &str = "void_downloads";

/// Подпапка для голосовых сообщений (автоприём без диалога).
pub const VOICE_DIR: &str = "void_downloads/voice";

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

/// Все каталоги, где могут лежать WAV (текущий + устаревший рядом с exe).
pub(crate) fn voice_search_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = vec![voice_dir_absolute()];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let legacy = parent.join(VOICE_DIR);
            if !dirs.iter().any(|d| d == &legacy) {
                dirs.push(legacy);
            }
        }
    }
    let cwd_voice = std::path::PathBuf::from(VOICE_DIR);
    if !dirs.iter().any(|d| d == &cwd_voice) {
        dirs.push(cwd_voice);
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
        FilePacket::Accept { .. } | FilePacket::Cancel { .. } | FilePacket::Ack => Ok(()),
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

    /// true — пора слать следующий чанк (с учётом rate-limit).
    pub fn ready_to_send(&self) -> bool {
        if !self.accepted || self.next_chunk >= self.chunks.len() {
            return false;
        }
        let delay = if self.is_relay {
            relay_chunk_delay()
        } else {
            DIRECT_CHUNK_DELAY
        };
        self.last_chunk_at.elapsed() >= delay
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
    /// Директория сохранения, выбранная пользователем. `None` → `void_downloads/`.
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
    // Убираем управляющие символы и опасные последовательности.
    name.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control() && *c != '/' && *c != '\\')
        .collect::<String>()
        .trim_start_matches('.')
        .to_string()
        .into()
}

/// Формирует уникальный путь к файлу в DOWNLOADS_DIR,
/// добавляя суффикс _(1), _(2)… если файл уже существует.
pub fn unique_download_path(filename: &str) -> std::path::PathBuf {
    unique_download_path_in(DOWNLOADS_DIR, filename)
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
}
