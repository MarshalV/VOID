//! Зашифрованный журнал переписок (`chat_journal.bin`).

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::protocol::ChatMessage;

#[derive(Serialize, Deserialize, Default)]
struct ChatJournalData {
    #[serde(default = "journal_format_v1")]
    format_version: u32,
    #[serde(default)]
    threads: HashMap<String, Vec<ChatMessage>>,
    /// Надгробия: id локально удалённых сообщений — без них ретраи/offline-мейлбокс
    /// воскрешают уже удалённое после перезапуска.
    #[serde(default)]
    deleted_ids: Vec<String>,
}

fn journal_format_v1() -> u32 {
    1
}

pub(crate) struct ChatJournal;

impl ChatJournal {
    pub(crate) const FILE: &'static str = "chat_journal.bin";
    const FILE_TMP: &'static str = "chat_journal.bin.tmp";
    const FILE_BAK: &'static str = "chat_journal.bin.bak";

    const PLAINTEXT_JSON_MAX: usize = 16 * 1024 * 1024;
    const MAX_THREADS: usize = 4096;
    const MAX_MESSAGES_PER_THREAD: usize = 5000;
    const MAX_TOTAL_MESSAGES: usize = 50_000;
    const MAX_THREAD_KEY_BYTES: usize = 320;
    const MAX_DELETED_IDS: usize = 20_000;

    pub(crate) fn save(
        master_key: &[u8; 32],
        threads: &HashMap<String, Vec<ChatMessage>>,
        deleted_ids: &[String],
    ) -> Result<(), Box<dyn Error>> {
        let trimmed = Self::trim_threads(threads);
        let mut deleted_ids = deleted_ids.to_vec();
        if deleted_ids.len() > Self::MAX_DELETED_IDS {
            let drop_n = deleted_ids.len() - Self::MAX_DELETED_IDS;
            deleted_ids.drain(0..drop_n);
        }
        let data = ChatJournalData {
            format_version: 1,
            threads: trimmed,
            deleted_ids,
        };
        Self::validate_plain(&data)?;

        let plaintext = serde_json::to_vec(&data)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_slice()));

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("chat journal encrypt: {}", e))?;

        let mut final_data = nonce_bytes.to_vec();
        final_data.extend(ciphertext);

        std::fs::write(Self::FILE_TMP, &final_data)?;
        if Path::new(Self::FILE).exists() {
            let _ = std::fs::remove_file(Self::FILE_BAK);
            std::fs::rename(Self::FILE, Self::FILE_BAK)?;
        }
        std::fs::rename(Self::FILE_TMP, Self::FILE)?;
        let _ = std::fs::remove_file(Self::FILE_BAK);
        Ok(())
    }

    pub(crate) fn load(
        master_key: &[u8; 32],
    ) -> Result<(HashMap<String, Vec<ChatMessage>>, Vec<String>), Box<dyn Error>> {
        if !Path::new(Self::FILE).exists() {
            return Ok((HashMap::new(), Vec::new()));
        }
        let data = std::fs::read(Self::FILE)?;
        if data.len() < 12 {
            return Err("Invalid chat journal".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_slice()));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("chat journal decrypt: {}", e))?;

        if plaintext.len() > Self::PLAINTEXT_JSON_MAX {
            return Err(format!(
                "chat journal: plaintext {} превышает лимит {} байт",
                plaintext.len(),
                Self::PLAINTEXT_JSON_MAX
            )
            .into());
        }

        let journal: ChatJournalData = serde_json::from_slice(&plaintext)?;
        Self::validate_plain(&journal)?;
        if journal.format_version != 1 {
            return Err(format!(
                "chat journal: неподдерживаемая format_version {}",
                journal.format_version
            )
            .into());
        }
        Ok((journal.threads, journal.deleted_ids))
    }

    fn trim_threads(
        threads: &HashMap<String, Vec<ChatMessage>>,
    ) -> HashMap<String, Vec<ChatMessage>> {
        let mut out: HashMap<String, Vec<ChatMessage>> = threads
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for msgs in out.values_mut() {
            if msgs.len() > Self::MAX_MESSAGES_PER_THREAD {
                let drop_n = msgs.len() - Self::MAX_MESSAGES_PER_THREAD;
                msgs.drain(0..drop_n);
            }
        }

        while out.values().map(|v| v.len()).sum::<usize>() > Self::MAX_TOTAL_MESSAGES {
            let mut oldest: Option<(String, usize)> = None;
            for (peer, msgs) in &out {
                if msgs.is_empty() {
                    continue;
                }
                let (idx, msg) = msgs
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, m)| m.timestamp.as_str())
                    .map(|(i, m)| (i, m.timestamp.as_str()))
                    .unwrap_or((0, ""));
                let replace = oldest
                    .as_ref()
                    .and_then(|(op, oi)| {
                        out.get(op)
                            .and_then(|v| v.get(*oi))
                            .map(|m| m.timestamp.as_str())
                    })
                    .map(|ots| msg < ots)
                    .unwrap_or(true);
                if replace {
                    oldest = Some((peer.clone(), idx));
                }
            }
            let Some((peer, idx)) = oldest else {
                break;
            };
            if let Some(msgs) = out.get_mut(&peer) {
                if idx < msgs.len() {
                    msgs.remove(idx);
                }
            }
        }
        out
    }

    fn validate_plain(data: &ChatJournalData) -> Result<(), Box<dyn Error>> {
        if data.threads.len() > Self::MAX_THREADS {
            return Err(format!(
                "chat journal: threads больше {} записей",
                Self::MAX_THREADS
            )
            .into());
        }
        let mut total = 0usize;
        for (peer, msgs) in &data.threads {
            if peer.len() > Self::MAX_THREAD_KEY_BYTES {
                return Err("chat journal: ключ потока слишком длинный".into());
            }
            if msgs.len() > Self::MAX_MESSAGES_PER_THREAD {
                return Err(format!(
                    "chat journal: thread {} содержит больше {} сообщений",
                    peer,
                    Self::MAX_MESSAGES_PER_THREAD
                )
                .into());
            }
            total += msgs.len();
        }
        if total > Self::MAX_TOTAL_MESSAGES {
            return Err(format!(
                "chat journal: всего {} сообщений, лимит {}",
                total,
                Self::MAX_TOTAL_MESSAGES
            )
            .into());
        }
        if data.deleted_ids.len() > Self::MAX_DELETED_IDS {
            return Err(format!(
                "chat journal: deleted_ids больше {} записей",
                Self::MAX_DELETED_IDS
            )
            .into());
        }
        Ok(())
    }
}
