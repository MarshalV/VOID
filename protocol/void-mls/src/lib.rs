//! Групповой MLS (RFC 9420) на OpenMLS и RustCrypto.
//!
//! Один шифротекст на эпоху, а не отдельный Double Ratchet каждому участнику.
//! Состояние группы лежит в storage провайдера. Снимок этого storage кладётся
//! в vault и шифруется тем же мастер-ключом, что и остальной vault.
//!
//! Состав по-прежнему решает подписанный roster. Здесь только ключи эпохи:
//! добавить, убрать, запечатать, открыть. Повтор старого Commit не применяется.
//! После удаления участника его прежнее состояние группы новое письмо не открывает.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Снимок устройства: ключ подписи и storage всех групп. Это и есть состояние в vault.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlsSnapshot {
    pub peer_id: String,
    pub signer_public: Vec<u8>,
    pub group_ids: Vec<String>,
    pub storage: Vec<StoredKv>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredKv {
    pub k: String,
    pub v: String,
}

#[derive(Clone, Debug)]
pub struct AddOutcome {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
    pub epoch: u64,
}

#[derive(Clone, Debug)]
pub struct CommitOutcome {
    pub commit: Vec<u8>,
    pub epoch: u64,
}

#[derive(Clone, Debug)]
pub struct Sealed {
    pub body: Vec<u8>,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
    Commit { epoch: u64 },
    Application { epoch: u64, plaintext: Vec<u8> },
}

pub struct Device {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    peer_id: String,
    groups: HashMap<String, MlsGroup>,
    group_ids: Vec<String>,
}

impl Device {
    pub fn create(peer_id: &str) -> Result<Self> {
        if peer_id.is_empty() || peer_id.len() > 256 {
            return Err(anyhow!("mls: пустой peer id"));
        }
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CS.signature_algorithm())
            .map_err(|e| anyhow!("mls signer: {e:?}"))?;
        signer
            .store(provider.storage())
            .map_err(|e| anyhow!("mls store signer: {e:?}"))?;
        Ok(Self {
            provider,
            signer,
            peer_id: peer_id.to_string(),
            groups: HashMap::new(),
            group_ids: Vec::new(),
        })
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.peer_id.as_bytes().to_vec()).into(),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    /// Свежий key package. Один пакет — одно вступление.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .build(CS, &self.provider, &self.signer, self.credential())
            .map_err(|e| anyhow!("mls key package: {e:?}"))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| anyhow!("mls key package bytes: {e}"))
    }

    pub fn create_group(&mut self, group_id_hex: &str) -> Result<()> {
        let gid = group_id_bytes(group_id_hex)?;
        if self.groups.contains_key(group_id_hex) {
            return Ok(());
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CS)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(&gid),
            self.credential(),
        )
        .map_err(|e| anyhow!("mls create: {e:?}"))?;
        self.remember(group_id_hex, group);
        Ok(())
    }

    pub fn add_member(&mut self, group_id_hex: &str, key_package: &[u8]) -> Result<AddOutcome> {
        let kp = decode_key_package(&self.provider, key_package)?;
        let mut group = self.take_group(group_id_hex)?;
        let (commit, welcome, _info) = group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|e| anyhow!("mls add: {e:?}"))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| anyhow!("mls merge add: {e:?}"))?;
        let epoch = epoch_of(&group);
        let commit = tls_bytes(&commit)?;
        let welcome = tls_bytes(&welcome)?;
        self.remember(group_id_hex, group);
        Ok(AddOutcome {
            commit,
            welcome,
            epoch,
        })
    }

    pub fn remove_member(&mut self, group_id_hex: &str, peer_id: &str) -> Result<CommitOutcome> {
        let mut group = self.take_group(group_id_hex)?;
        let leaf = leaf_of(&group, peer_id).ok_or_else(|| anyhow!("mls: нет такого участника"))?;
        let (commit, _welcome, _info) = group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|e| anyhow!("mls remove: {e:?}"))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| anyhow!("mls merge remove: {e:?}"))?;
        let epoch = epoch_of(&group);
        let commit = tls_bytes(&commit)?;
        self.remember(group_id_hex, group);
        Ok(CommitOutcome { commit, epoch })
    }

    pub fn join(&mut self, welcome_bytes: &[u8]) -> Result<(String, u64)> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| anyhow!("mls welcome frame: {e}"))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(anyhow!("mls: это не Welcome")),
        };
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|e| anyhow!("mls staged welcome: {e:?}"))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| anyhow!("mls join: {e:?}"))?;
        let hex_id = hex::encode(group.group_id().as_slice());
        let epoch = epoch_of(&group);
        self.remember(&hex_id, group);
        Ok((hex_id, epoch))
    }

    pub fn seal(&mut self, group_id_hex: &str, plaintext: &[u8]) -> Result<Sealed> {
        if plaintext.is_empty() || plaintext.len() > 64 * 1024 {
            return Err(anyhow!("mls: пустой или слишком большой plaintext"));
        }
        let mut group = self.take_group(group_id_hex)?;
        let msg = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| anyhow!("mls seal: {e:?}"))?;
        let epoch = epoch_of(&group);
        let body = tls_bytes(&msg)?;
        self.remember(group_id_hex, group);
        Ok(Sealed { body, epoch })
    }

    /// Commit или письмо приложения. Повтор уже принятого Commit — ошибка.
    pub fn process(&mut self, group_id_hex: &str, body: &[u8]) -> Result<Incoming> {
        let msg = MlsMessageIn::tls_deserialize_exact(body)
            .map_err(|e| anyhow!("mls frame: {e}"))?;
        let protocol = msg
            .try_into_protocol_message()
            .map_err(|e| anyhow!("mls protocol message: {e:?}"))?;
        let mut group = self.take_group(group_id_hex)?;
        let processed = match group.process_message(&self.provider, protocol) {
            Ok(p) => p,
            Err(e) => {
                self.remember(group_id_hex, group);
                return Err(anyhow!("mls process: {e:?}"));
            }
        };
        let incoming = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Incoming::Application {
                epoch: epoch_of(&group),
                plaintext: app.into_bytes(),
            },
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                if let Err(e) = group.merge_staged_commit(&self.provider, *staged) {
                    self.remember(group_id_hex, group);
                    return Err(anyhow!("mls merge commit: {e:?}"));
                }
                Incoming::Commit {
                    epoch: epoch_of(&group),
                }
            }
            _ => {
                self.remember(group_id_hex, group);
                return Err(anyhow!("mls: кадр не commit и не письмо"));
            }
        };
        self.remember(group_id_hex, group);
        Ok(incoming)
    }

    pub fn epoch(&self, group_id_hex: &str) -> Option<u64> {
        self.groups.get(group_id_hex).map(epoch_of)
    }

    pub fn has_group(&self, group_id_hex: &str) -> bool {
        self.groups.contains_key(group_id_hex)
    }

    /// Забывает группу в памяти. Следующий снимок её уже не загружает.
    pub fn forget(&mut self, group_id_hex: &str) {
        self.groups.remove(group_id_hex);
        self.group_ids.retain(|id| id != group_id_hex);
    }

    pub fn snapshot(&self) -> Result<MlsSnapshot> {
        let guard = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| anyhow!("mls storage lock"))?;
        let mut storage = Vec::with_capacity(guard.len());
        for (k, v) in guard.iter() {
            storage.push(StoredKv {
                k: B64.encode(k),
                v: B64.encode(v),
            });
        }
        drop(guard);
        Ok(MlsSnapshot {
            peer_id: self.peer_id.clone(),
            signer_public: self.signer.to_public_vec(),
            group_ids: self.group_ids.clone(),
            storage,
        })
    }

    pub fn from_snapshot(snapshot: &MlsSnapshot) -> Result<Self> {
        if snapshot.peer_id.is_empty() || snapshot.signer_public.is_empty() {
            return Err(anyhow!("mls: пустой снимок"));
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let mut map = provider
                .storage()
                .values
                .write()
                .map_err(|_| anyhow!("mls storage lock"))?;
            map.clear();
            for row in &snapshot.storage {
                let k = B64
                    .decode(row.k.as_bytes())
                    .map_err(|e| anyhow!("mls snapshot key: {e}"))?;
                let v = B64
                    .decode(row.v.as_bytes())
                    .map_err(|e| anyhow!("mls snapshot value: {e}"))?;
                map.insert(k, v);
            }
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &snapshot.signer_public,
            SignatureScheme::ED25519,
        )
        .ok_or_else(|| anyhow!("mls: ключ подписи не читается из снимка"))?;
        let mut device = Self {
            provider,
            signer,
            peer_id: snapshot.peer_id.clone(),
            groups: HashMap::new(),
            group_ids: Vec::new(),
        };
        for id in &snapshot.group_ids {
            let gid = GroupId::from_slice(&group_id_bytes(id)?);
            let Some(group) = MlsGroup::load(device.provider.storage(), &gid)
                .map_err(|e| anyhow!("mls load: {e:?}"))?
            else {
                continue;
            };
            device.remember(id, group);
        }
        Ok(device)
    }

    fn remember(&mut self, group_id_hex: &str, group: MlsGroup) {
        if !self.group_ids.iter().any(|id| id == group_id_hex) {
            self.group_ids.push(group_id_hex.to_string());
        }
        self.groups.insert(group_id_hex.to_string(), group);
    }

    fn take_group(&mut self, group_id_hex: &str) -> Result<MlsGroup> {
        self.groups
            .remove(group_id_hex)
            .ok_or_else(|| anyhow!("mls: нет локальной группы"))
    }
}

fn group_id_bytes(hex_id: &str) -> Result<[u8; 16]> {
    if hex_id.len() != 32 || !hex_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("mls: group id не 16 байт hex"));
    }
    let raw = hex::decode(hex_id).map_err(|e| anyhow!("mls group id: {e}"))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn tls_bytes(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    msg.tls_serialize_detached()
        .map_err(|e| anyhow!("mls tls: {e}"))
}

fn epoch_of(group: &MlsGroup) -> u64 {
    group.epoch().as_u64()
}

fn decode_key_package(provider: &OpenMlsRustCrypto, bytes: &[u8]) -> Result<KeyPackage> {
    let incoming = KeyPackageIn::tls_deserialize_exact(bytes)
        .map_err(|e| anyhow!("mls key package frame: {e}"))?;
    incoming
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow!("mls key package validate: {e:?}"))
}

fn leaf_of(group: &MlsGroup, peer_id: &str) -> Option<LeafNodeIndex> {
    group.members().find_map(|member| {
        let cred = member.credential.serialized_content();
        if cred == peer_id.as_bytes() {
            Some(member.index)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid() -> String {
        "0123456789abcdef0123456789abcdef".into()
    }

    fn plain(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn add_remove_forward_secrecy_and_commit_replay() {
        let mut alice = Device::create("alice").unwrap();
        let mut bob = Device::create("bob").unwrap();
        let mut carol = Device::create("carol").unwrap();
        alice.create_group(&gid()).unwrap();

        let bob_kp = bob.key_package().unwrap();
        let added = alice.add_member(&gid(), &bob_kp).unwrap();
        let (joined, epoch) = bob.join(&added.welcome).unwrap();
        assert_eq!(joined, gid());
        assert_eq!(epoch, added.epoch);
        assert!(matches!(
            bob.process(&gid(), &added.commit).unwrap_err().to_string(),
            _
        ));

        let sealed = alice.seal(&gid(), &plain("hello bob")).unwrap();
        match bob.process(&gid(), &sealed.body).unwrap() {
            Incoming::Application { plaintext, .. } => assert_eq!(plaintext, plain("hello bob")),
            other => panic!("expected application, {other:?}"),
        }

        let carol_kp = carol.key_package().unwrap();
        let added_c = alice.add_member(&gid(), &carol_kp).unwrap();
        let commit = bob.process(&gid(), &added_c.commit).unwrap();
        assert!(matches!(commit, Incoming::Commit { .. }));
        assert!(bob.process(&gid(), &added_c.commit).is_err());
        let (carol_id, carol_epoch) = carol.join(&added_c.welcome).unwrap();
        assert_eq!(carol_id, gid());
        assert_eq!(carol_epoch, added_c.epoch);

        let sealed = alice.seal(&gid(), &plain("all three")).unwrap();
        match bob.process(&gid(), &sealed.body).unwrap() {
            Incoming::Application { plaintext, .. } => assert_eq!(plaintext, plain("all three")),
            other => panic!("bob {other:?}"),
        }
        match carol.process(&gid(), &sealed.body).unwrap() {
            Incoming::Application { plaintext, .. } => assert_eq!(plaintext, plain("all three")),
            other => panic!("carol {other:?}"),
        }

        let removed = alice.remove_member(&gid(), "carol").unwrap();
        assert!(matches!(
            bob.process(&gid(), &removed.commit).unwrap(),
            Incoming::Commit { .. }
        ));
        assert!(bob.process(&gid(), &removed.commit).is_err());

        let sealed = alice.seal(&gid(), &plain("after leave")).unwrap();
        match bob.process(&gid(), &sealed.body).unwrap() {
            Incoming::Application { plaintext, .. } => assert_eq!(plaintext, plain("after leave")),
            other => panic!("bob after {other:?}"),
        }
        assert!(carol.process(&gid(), &sealed.body).is_err());
    }

    #[test]
    fn snapshot_roundtrip_still_opens() {
        let mut alice = Device::create("alice").unwrap();
        let mut bob = Device::create("bob").unwrap();
        alice.create_group(&gid()).unwrap();
        let added = alice.add_member(&gid(), &bob.key_package().unwrap()).unwrap();
        bob.join(&added.welcome).unwrap();
        let snap = alice.snapshot().unwrap();
        let mut alice = Device::from_snapshot(&snap).unwrap();
        let sealed = alice.seal(&gid(), &plain("from disk")).unwrap();
        match bob.process(&gid(), &sealed.body).unwrap() {
            Incoming::Application { plaintext, .. } => assert_eq!(plaintext, plain("from disk")),
            other => panic!("{other:?}"),
        }
    }
}
