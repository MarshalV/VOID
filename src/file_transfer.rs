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

/// Скорость отправки через relay: 64 КБ/с.
pub const RELAY_RATE_LIMIT_BPS: u64 = 64 * 1024;

/// Минимальный интервал между чанками при прямом соединении.
pub const DIRECT_CHUNK_DELAY: Duration = Duration::from_millis(5);

/// Папка для сохранения принятых файлов.
pub const DOWNLOADS_DIR: &str = "void_downloads";

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
    pub kind: FileKind,
}

impl OutgoingTransfer {
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
pub fn unique_download_path_in(dir: &str, filename: &str) -> std::path::PathBuf {
    let dir_path = std::path::Path::new(dir);
    let _ = std::fs::create_dir_all(dir_path);
    let path = dir_path.join(filename);
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
            dir_path.join(format!("{}_({i})", stem))
        } else {
            dir_path.join(format!("{}_({i}).{}", stem, ext))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
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
