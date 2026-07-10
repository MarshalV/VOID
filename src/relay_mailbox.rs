//! Store-and-forward relay for offline mail (persisted on disk).

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::offline_mail::OfflineEnvelope;

const FILE: &str = "relay_mailbox.bin";
const MAX_PER_RECIPIENT: usize = 256;

#[derive(Default, Serialize, Deserialize)]
struct RelayData {
    #[serde(default)]
    by_recipient: HashMap<String, Vec<OfflineEnvelope>>,
}

pub(crate) struct RelayMailbox;

impl RelayMailbox {
    pub(crate) fn load() -> HashMap<String, Vec<OfflineEnvelope>> {
        if !Path::new(FILE).exists() {
            return HashMap::new();
        }
        match std::fs::read(FILE) {
            Ok(bytes) => serde_json::from_slice::<RelayData>(&bytes)
                .map(|d| d.by_recipient)
                .unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    pub(crate) fn save(map: &HashMap<String, Vec<OfflineEnvelope>>) -> Result<(), Box<dyn Error>> {
        let data = RelayData {
            by_recipient: map.clone(),
        };
        let bytes = serde_json::to_vec(&data)?;
        std::fs::write(format!("{FILE}.tmp"), &bytes)?;
        if Path::new(FILE).exists() {
            let _ = std::fs::remove_file(format!("{FILE}.bak"));
            let _ = std::fs::rename(FILE, format!("{FILE}.bak"));
        }
        std::fs::rename(format!("{FILE}.tmp"), FILE)?;
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
        changed
    }

    pub(crate) fn take_for(
        map: &mut HashMap<String, Vec<OfflineEnvelope>>,
        recipient: &str,
    ) -> Vec<OfflineEnvelope> {
        map.remove(recipient).unwrap_or_default()
    }
}