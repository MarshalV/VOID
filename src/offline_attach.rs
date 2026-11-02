//! Куски офлайн-файла: чтение, резка, сборка. Голос использует тот же рез.

use std::collections::HashMap;

use libp2p::PeerId;

use crate::file_transfer;
use crate::network::OfflineOutboxItem;
use crate::offline_mail::{
    assemble_voice_chunks, decode_voice_chunk_payload, split_capped_for_offline,
    OFFLINE_FILE_CHUNK_KIND, OFFLINE_FILE_MAX_BYTES, OFFLINE_VOICE_CHUNK_KIND,
    OFFLINE_VOICE_MAX_BYTES,
};
use crate::protocol::transfer_id_to_hex;

pub(crate) fn blake_hex(data: &[u8]) -> String {
    file_transfer::hash_file(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Байты, которые уйдут в конверт. Кэш `*.vfc` читается только с ключом.
/// `None` — файла нет или он больше офлайн-потолка.
pub(crate) fn load_offline_file(
    path: &str,
    filename: &str,
    cache_key: Option<&[u8; 32]>,
) -> Option<Vec<u8>> {
    let p = std::path::Path::new(path);
    let raw = if file_transfer::is_under_file_cache(p) {
        let key = cache_key?;
        file_transfer::read_cache_plain(p, key).ok()?
    } else {
        std::fs::read(p).ok()?
    };
    let kind = file_transfer::FileKind::from_filename(filename);
    let plain = crate::metadata_strip::strip_metadata_for_send(filename, kind, raw);
    // Исходник до 64 МиБ: после deflate он может уложиться в 8 МиБ очереди.
    if plain.is_empty() || plain.len() as u64 > 64 * 1024 * 1024 {
        return None;
    }
    let wire = crate::wire_compress::pack_file(&plain, filename);
    if wire.len() as u64 > OFFLINE_FILE_MAX_BYTES {
        None
    } else {
        Some(wire)
    }
}

pub(crate) fn push_offline_chunks(
    items: &mut Vec<OfflineOutboxItem>,
    recipient: PeerId,
    transfer_id: &[u8; 16],
    bytes: &[u8],
    voice: bool,
) -> bool {
    let (max, kind, prefix) = if voice {
        (
            OFFLINE_VOICE_MAX_BYTES,
            OFFLINE_VOICE_CHUNK_KIND,
            "vchunk",
        )
    } else {
        (OFFLINE_FILE_MAX_BYTES, OFFLINE_FILE_CHUNK_KIND, "fchunk")
    };
    let Some(chunks) = split_capped_for_offline(transfer_id, bytes, max) else {
        return false;
    };
    let tid_hex = transfer_id_to_hex(transfer_id);
    for (i, payload) in chunks.into_iter().enumerate() {
        items.push(OfflineOutboxItem {
            recipient,
            message_id: format!("{prefix}:{tid_hex}:{i}"),
            kind: kind.to_string(),
            payload,
        });
    }
    true
}

pub(crate) struct ChunkBin {
    pub total: u32,
    pub total_size: u32,
    pub chunks: HashMap<u32, Vec<u8>>,
}

/// `Some(None)` — кусок принят, файл ещё не собран.
/// `Some(Some((transfer_hex, bytes)))` — собран и снят с полки.
/// `None` — битый кусок или конфликт метаданных.
pub(crate) fn absorb_chunk(
    bins: &mut HashMap<String, ChunkBin>,
    plaintext: &[u8],
) -> Option<Option<(String, Vec<u8>)>> {
    let chunk = decode_voice_chunk_payload(plaintext)?;
    let tid = transfer_id_to_hex(&chunk.transfer_id);
    let entry = bins.entry(tid.clone()).or_insert_with(|| ChunkBin {
        total: chunk.total,
        total_size: chunk.total_size,
        chunks: HashMap::new(),
    });
    if entry.total != chunk.total || entry.total_size != chunk.total_size {
        return None;
    }
    entry.chunks.insert(chunk.index, chunk.data);
    if entry.chunks.len() < entry.total as usize {
        return Some(None);
    }
    let done = assemble_voice_chunks(entry.total, entry.total_size, &entry.chunks)?;
    bins.remove(&tid);
    Some(Some((tid, done)))
}
