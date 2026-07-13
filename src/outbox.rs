//! Быстрая очередь недоставленного (`outbox.bin`) — только pending, без всего журнала.

use std::error::Error;
use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::group::GroupMember;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum OutboxEntry {
    DirectMessage {
        peer: String,
        message_id: String,
        text: String,
    },
    DirectVoice {
        peer: String,
        message_id: String,
        transfer_id: String,
        duration_secs: f32,
        voice_path: String,
    },
    GroupMessage {
        group_id: String,
        message_id: String,
        text: String,
        members: Vec<String>,
    },
    GroupVoice {
        group_id: String,
        message_id: String,
        transfer_id: String,
        duration_secs: f32,
        voice_path: String,
        members: Vec<String>,
    },
    GroupSync {
        group_id: String,
        group_name: String,
        creator_id: String,
        members: Vec<GroupMember>,
        recipient: String,
    },
}

#[derive(Serialize, Deserialize, Default)]
struct OutboxData {
    #[serde(default)]
    entries: Vec<OutboxEntry>,
}

pub(crate) struct Outbox;

impl Outbox {
    pub(crate) const FILE: &'static str = "outbox.bin";
    const FILE_TMP: &'static str = "outbox.bin.tmp";
    const MAX_ENTRIES: usize = 4096;
    const PLAINTEXT_MAX: usize = 512 * 1024;

    pub(crate) fn load(master_key: &[u8; 32]) -> Result<Vec<OutboxEntry>, Box<dyn Error>> {
        if !Path::new(Self::FILE).exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read(Self::FILE)?;
        if data.len() < 12 {
            return Err("Invalid outbox".into());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|e| format!("outbox decrypt: {}", e))?;
        if plaintext.len() > Self::PLAINTEXT_MAX {
            return Err("outbox too large".into());
        }
        let parsed: OutboxData = serde_json::from_slice(&plaintext)?;
        Ok(parsed.entries)
    }

    pub(crate) fn save(master_key: &[u8; 32], entries: &[OutboxEntry]) -> Result<(), Box<dyn Error>> {
        if entries.len() > Self::MAX_ENTRIES {
            return Err(format!("outbox: больше {} записей", Self::MAX_ENTRIES).into());
        }
        let data = OutboxData {
            entries: entries.to_vec(),
        };
        let plaintext = serde_json::to_vec(&data)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|e| format!("outbox encrypt: {}", e))?;
        let mut final_data = nonce_bytes.to_vec();
        final_data.extend(ciphertext);
        std::fs::write(Self::FILE_TMP, &final_data)?;
        if Path::new(Self::FILE).exists() {
            let _ = std::fs::remove_file("outbox.bin.bak");
            let _ = std::fs::rename(Self::FILE, "outbox.bin.bak");
        }
        std::fs::rename(Self::FILE_TMP, Self::FILE)?;
        Ok(())
    }
}
