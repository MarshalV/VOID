//! Локальное состояние MLS-групп. Снимок уходит в `vault.bin` и шифруется мастер-ключом.

use anyhow::{anyhow, Result};
use void_protocol::mls::{AddOutcome, CommitOutcome, Device, Incoming, Sealed};

pub use void_protocol::mls::MlsSnapshot;

pub struct GroupMls {
    device: Option<Device>,
}

pub enum MlsIn {
    Joined {
        #[allow(dead_code)]
        epoch: u64,
    },
    Commit {
        #[allow(dead_code)]
        epoch: u64,
    },
    Application { plaintext: Vec<u8> },
}

impl GroupMls {
    pub fn empty() -> Self {
        Self { device: None }
    }

    pub fn open(peer_id: &str, snapshot: Option<&MlsSnapshot>) -> Self {
        if let Some(snapshot) = snapshot {
            if snapshot.peer_id == peer_id {
                if let Ok(device) = Device::from_snapshot(snapshot) {
                    return Self {
                        device: Some(device),
                    };
                }
            }
        }
        Self {
            device: Device::create(peer_id).ok(),
        }
    }

    pub fn snapshot(&self) -> Option<MlsSnapshot> {
        self.device.as_ref().and_then(|d| d.snapshot().ok())
    }

    pub fn has(&self, group_id: &str) -> bool {
        self.device.as_ref().is_some_and(|d| d.has_group(group_id))
    }

    pub fn ensure_group(&mut self, group_id: &str) -> Result<()> {
        let device = self.device.as_mut().ok_or_else(|| anyhow!("mls: устройство не открыто"))?;
        device.create_group(group_id)
    }

    pub fn key_package(&mut self) -> Result<Vec<u8>> {
        let device = self.device.as_mut().ok_or_else(|| anyhow!("mls: устройство не открыто"))?;
        device.key_package()
    }

    pub fn admit(&mut self, group_id: &str, key_package: &[u8]) -> Result<AddOutcome> {
        let device = self.device.as_mut().ok_or_else(|| anyhow!("mls: устройство не открыто"))?;
        device.add_member(group_id, key_package)
    }

    pub fn evict(&mut self, group_id: &str, peer_id: &str) -> Result<CommitOutcome> {
        let device = self.device.as_mut().ok_or_else(|| anyhow!("mls: устройство не открыто"))?;
        device.remove_member(group_id, peer_id)
    }

    pub fn seal(&mut self, group_id: &str, plaintext: &[u8]) -> Result<Sealed> {
        let device = self.device.as_mut().ok_or_else(|| anyhow!("mls: устройство не открыто"))?;
        device.seal(group_id, plaintext)
    }

    pub fn take(&mut self, group_id: &str, body: &[u8]) -> Result<MlsIn> {
        let device = self.device.as_mut().ok_or_else(|| anyhow!("mls: устройство не открыто"))?;
        if !device.has_group(group_id) {
            let (id, epoch) = device.join(body)?;
            if id != group_id {
                return Err(anyhow!("mls: welcome от другой группы"));
            }
            return Ok(MlsIn::Joined { epoch });
        }
        match device.process(group_id, body)? {
            Incoming::Commit { epoch } => Ok(MlsIn::Commit { epoch }),
            Incoming::Application { plaintext, .. } => Ok(MlsIn::Application { plaintext }),
        }
    }

    pub fn forget(&mut self, group_id: &str) {
        if let Some(device) = self.device.as_mut() {
            device.forget(group_id);
        }
    }
}
