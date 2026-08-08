//! Store-and-forward relay for offline mail (persisted on disk).

use std::collections::HashMap;
use std::error::Error;

use serde::{Deserialize, Serialize};

use crate::offline_mail::OfflineEnvelope;
use crate::paths;

const FILE: &str = "relay_mailbox.bin";
/// Голосовое ~3 МБ ≈ 128 чанков; несколько pending voice на одного адресата.
const MAX_PER_RECIPIENT: usize = 1024;
/// Голосовые чанки — большие, поэтому помимо счётчика конвертов ограничиваем
/// суммарный объём на одного адресата (иначе один длинный voice завалит диск
/// relay/bootstrap-ноды). Старые конверты вытесняются первыми.
const MAX_BYTES_PER_RECIPIENT: usize = 32 * 1024 * 1024;
/// Сколько байт plaintext-конвертов отдаём за один OfflineMailboxDeliver
/// (JSON раздувает Vec<u8> ~3×; держимся заметно ниже лимита response RR).
pub(crate) const DELIVER_BATCH_PLAIN_BYTES: usize = 512 * 1024;

fn envelope_len(env: &OfflineEnvelope) -> usize {
    env.ct.len() + 96
}

#[derive(Default, Serialize, Deserialize)]
struct RelayData {
    #[serde(default)]
    by_recipient: HashMap<String, Vec<OfflineEnvelope>>,
}

pub(crate) struct RelayMailbox;

impl RelayMailbox {
    pub(crate) fn load() -> HashMap<String, Vec<OfflineEnvelope>> {
        let path = paths::data_file(FILE);
        if !path.exists() {
            return HashMap::new();
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                // bincode — компактнее JSON для бинарных полей (важно для
                // голосовых чанков); при апгрейде со старого файла — fallback на JSON.
                if let Ok(d) = bincode::deserialize::<RelayData>(&bytes) {
                    d.by_recipient
                } else {
                    serde_json::from_slice::<RelayData>(&bytes)
                        .map(|d| d.by_recipient)
                        .unwrap_or_default()
                }
            }
            Err(_) => HashMap::new(),
        }
    }

    pub(crate) fn save(map: &HashMap<String, Vec<OfflineEnvelope>>) -> Result<(), Box<dyn Error>> {
        let data = RelayData {
            by_recipient: map.clone(),
        };
        let bytes = bincode::serialize(&data)?;
        let path = paths::data_file(FILE);
        let path_tmp = paths::data_file(format!("{FILE}.tmp"));
        let path_bak = paths::data_file(format!("{FILE}.bak"));
        std::fs::write(&path_tmp, &bytes)?;
        if path.exists() {
            let _ = std::fs::remove_file(&path_bak);
            let _ = std::fs::rename(&path, &path_bak);
        }
        std::fs::rename(&path_tmp, &path)?;
        Ok(())
    }

    pub(crate) fn merge(
        map: &mut HashMap<String, Vec<OfflineEnvelope>>,
        recipient: &str,
        envelopes: Vec<OfflineEnvelope>,
    ) -> bool {
        let slot = map.entry(recipient.to_string()).or_default();
        let mut changed = false;
        for env in envelopes {
            if slot.iter().any(|e| e.message_id == env.message_id) {
                continue;
            }
            slot.push(env);
            changed = true;
        }
        if slot.len() > MAX_PER_RECIPIENT {
            let drop = slot.len() - MAX_PER_RECIPIENT;
            slot.drain(0..drop);
            changed = true;
        }
        let mut total: usize = slot.iter().map(envelope_len).sum();
        while total > MAX_BYTES_PER_RECIPIENT && !slot.is_empty() {
            total -= envelope_len(&slot.remove(0));
            changed = true;
        }
        changed
    }

    /// Забирает порцию конвертов (не весь ящик), чтобы ответ RR не превысил
    /// лимит codec. Остаток остаётся в store — клиент сделает повторный Query.
    pub(crate) fn take_batch(
        map: &mut HashMap<String, Vec<OfflineEnvelope>>,
        recipient: &str,
        max_plain_bytes: usize,
    ) -> Vec<OfflineEnvelope> {
        let Some(slot) = map.get_mut(recipient) else {
            return Vec::new();
        };
        if slot.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut used = 0usize;
        while let Some(env) = slot.first() {
            let n = envelope_len(env);
            if !out.is_empty() && used.saturating_add(n) > max_plain_bytes {
                break;
            }
            out.push(slot.remove(0));
            used = used.saturating_add(n);
            if used >= max_plain_bytes {
                break;
            }
        }
        if slot.is_empty() {
            map.remove(recipient);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline_mail::OfflineEnvelope;

    fn env(id: &str, ct_len: usize) -> OfflineEnvelope {
        OfflineEnvelope {
            v: 1,
            sender: "s".into(),
            sender_pk: [0u8; 32],
            message_id: id.into(),
            kind: "voice_chunk".into(),
            eph: [0u8; 32],
            nonce: [0u8; 12],
            ct: vec![0u8; ct_len],
        }
    }

    #[test]
    fn take_batch_leaves_remainder_for_next_query() {
        let mut map = HashMap::new();
        let recip = "peer";
        let big = (0..20)
            .map(|i| env(&format!("c{i}"), 40_000))
            .collect::<Vec<_>>();
        assert!(RelayMailbox::merge(&mut map, recip, big));
        let first = RelayMailbox::take_batch(&mut map, recip, 100_000);
        assert!(!first.is_empty());
        assert!(map.get(recip).map(|s| !s.is_empty()).unwrap_or(false));
        let second = RelayMailbox::take_batch(&mut map, recip, 100_000);
        assert!(!second.is_empty());
        assert_ne!(first[0].message_id, second[0].message_id);
    }
}