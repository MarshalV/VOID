//! Зашифрованный vault (`vault.bin`) и обёртка мастер-ключа (`void.key`).

use std::error::Error;
use std::path::Path;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto;

#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct AddressBookEntry {
    pub(crate) peer_id: String,
    pub(crate) display_name: String,
    /// Последние известные multiaddr собеседника — прогреваем kbuckets Kademlia
    /// на старте, чтобы «написать контакту» работало без предварительного
    /// дозвона. Старые vault'ы без этого поля читаются нормально.
    #[serde(default)]
    pub(crate) addrs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct StorageData {
    #[serde(default = "storage_format_v1")]
    format_version: u32,
    pub(crate) nickname: String,
    pub(crate) keypair_bytes: Vec<u8>,
    pub(crate) static_secret_bytes: [u8; 32],
    #[serde(default)]
    pub(crate) address_book: Vec<AddressBookEntry>,
    /// Известные VOID bootstrap-ноды (полные multiaddr с `/p2p/`). Обмениваются с участниками сети.
    #[serde(default)]
    pub(crate) void_bootstraps: Vec<String>,
}

fn storage_format_v1() -> u32 {
    1
}

pub(crate) struct Storage;
impl Storage {
    /// Максимум байт JSON после расшифровки `vault.bin` (защита от чрезмерного `serde_json`).
    const VAULT_PLAINTEXT_JSON_MAX: usize = 512 * 1024;
    const VAULT_NICKNAME_MAX: usize = 256;
    const VAULT_KEYPAIR_BYTES_MAX: usize = 16384;
    const VAULT_ADDRESS_BOOK_MAX_ENTRIES: usize = 4096;
    const VAULT_ENTRY_PEER_ID_MAX: usize = 256;
    const VAULT_ENTRY_NAME_MAX: usize = 256;
    const VAULT_ENTRY_ADDRS_MAX: usize = 128;
    const VAULT_ENTRY_ONE_ADDR_MAX: usize = 1024;
    const VAULT_BOOTSTRAPS_MAX: usize = 64;
    const VAULT_BOOTSTRAP_ONE_ADDR_MAX: usize = 1024;

    pub(crate) const FILE: &'static str = "vault.bin";
    const FILE_TMP: &'static str = "vault.bin.tmp";
    const FILE_BAK: &'static str = "vault.bin.bak";
    pub(crate) const KEY_FILE: &'static str = "void.key";
    /// Магия и размер обёртки `void.key` v2: Argon2id KDF + AES-256-GCM над сыром мастер-ключом vault.
    const KEY_WRAP_MAGIC: &'static [u8; 8] = b"VOIDKEY2";
    const WRAP_SALT_LEN: usize = 32;
    const WRAP_NONCE_LEN: usize = 12;

    fn derive_wrap_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
        let params = Params::new(32768, 3, 4, Some(32)).map_err(|e| e.to_string())?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(password, salt, &mut key)
            .map_err(|e| format!("argon2: {}", e))?;
        Ok(key)
    }

    /// Пишет `void.key`: мастер-ключ vault (32 байта) зашифрован паролем (KDF Argon2id + AES-GCM).
    pub(crate) fn write_wrapped_master_key_file(
        master_plain: &[u8; 32],
        password: &str,
    ) -> Result<(), Box<dyn Error>> {
        let mut salt = vec![0u8; Self::WRAP_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let wrap_key = Self::derive_wrap_key(password.as_bytes(), &salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
        let mut nonce = [0u8; Self::WRAP_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), master_plain.as_ref())
            .map_err(|e| format!("wrap key encrypt: {}", e))?;
        let mut blob = Vec::with_capacity(8 + salt.len() + nonce.len() + ct.len());
        blob.extend_from_slice(Self::KEY_WRAP_MAGIC);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        std::fs::write(Self::KEY_FILE, &blob)?;
        Ok(())
    }

    /// Считывает мастер-ключ из `void.key` v2 (Argon2id + AES-GCM).
    pub(crate) fn unwrap_master_key_file(password: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let blob = std::fs::read(Self::KEY_FILE)?;
        Self::unwrap_master_key_bytes(&blob, password)
    }

    fn unwrap_master_key_bytes(blob: &[u8], password: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let min =
            Self::KEY_WRAP_MAGIC.len() + Self::WRAP_SALT_LEN + Self::WRAP_NONCE_LEN + 16;
        if blob.len() < min {
            return Err("void.key слишком короткий или повреждён".into());
        }
        let (magic, rest) = blob.split_at(Self::KEY_WRAP_MAGIC.len());
        if magic != Self::KEY_WRAP_MAGIC.as_slice() {
            return Err(
                "void.key без магии VOIDKEY2 (ожидается формат с паролём)".into(),
            );
        }
        let (salt, rest) = rest.split_at(Self::WRAP_SALT_LEN);
        let (nonce, ct) = rest.split_at(Self::WRAP_NONCE_LEN);
        let wrap_key = Self::derive_wrap_key(password.as_bytes(), salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap_key));
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce), ct.as_ref())
            .map_err(|_| "Неверный пароль или повреждённый void.key".to_string())?;
        if plain.len() != 32 {
            return Err("void.key: некорректная длина мастер-ключа".into());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        Ok(out)
    }

    pub(crate) fn read_key_blob() -> Result<Vec<u8>, std::io::Error> {
        std::fs::read(Self::KEY_FILE)
    }

    pub(crate) fn is_wrapped_keyfile(raw: &[u8]) -> bool {
        raw.len() >= Self::KEY_WRAP_MAGIC.len()
            && &raw[..Self::KEY_WRAP_MAGIC.len()] == Self::KEY_WRAP_MAGIC.as_slice()
    }

    pub(crate) fn save(
        master_key: &[u8; 32],
        nickname: &str,
        keypair: Option<&libp2p::identity::Keypair>,
        static_secret: Option<&crypto::StaticSecret>,
        address_book: Option<&[AddressBookEntry]>,
        void_bootstraps: Option<&[String]>,
    ) -> Result<(), Box<dyn Error>> {
        let current_load = Self::load(master_key);

        let keypair_bytes = if let Some(kp) = keypair {
            kp.to_protobuf_encoding()?
        } else if let Ok(ref c) = current_load {
            if c.keypair_bytes.is_empty() {
                return Err("vault: keypair в файле пустой — запись отменена".into());
            }
            c.keypair_bytes.clone()
        } else {
            return Err(format!(
                "vault: не удалось прочитать {} перед сохранением ({}). Запись отменена, чтобы не затереть ключи.",
                Self::FILE,
                current_load.err().map(|e| e.to_string()).unwrap_or_default()
            )
            .into());
        };

        let static_secret_bytes = if let Some(ss) = static_secret {
            ss.to_bytes()
        } else if let Ok(ref c) = current_load {
            c.static_secret_bytes
        } else {
            return Err("vault: нет static_secret для сохранения".into());
        };

        let address_book_vec: Vec<AddressBookEntry> = if let Some(ab) = address_book {
            ab.to_vec()
        } else {
            current_load
                .as_ref()
                .map(|c| c.address_book.clone())
                .unwrap_or_default()
        };

        let void_bootstraps_vec: Vec<String> = if let Some(bs) = void_bootstraps {
            bs.to_vec()
        } else {
            current_load
                .as_ref()
                .map(|c| c.void_bootstraps.clone())
                .unwrap_or_default()
        };

        let data = StorageData {
            format_version: 1,
            nickname: nickname.to_string(),
            keypair_bytes,
            static_secret_bytes,
            address_book: address_book_vec,
            void_bootstraps: void_bootstraps_vec,
        };
        let plaintext = serde_json::to_vec(&data)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_slice()));

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        let mut final_data = nonce_bytes.to_vec();
        final_data.extend(ciphertext);

        // Сначала пишем во временный файл, затем подменяем vault — иначе при сбое
        // посередине fs::write остаётся усечённый vault и следующий load() ломается,
        // после чего старый save подставлял пустой keypair и окончательно портил ключи.
        std::fs::write(Self::FILE_TMP, &final_data)?;
        if Path::new(Self::FILE).exists() {
            let _ = std::fs::remove_file(Self::FILE_BAK);
            std::fs::rename(Self::FILE, Self::FILE_BAK)?;
        }
        std::fs::rename(Self::FILE_TMP, Self::FILE)?;
        let _ = std::fs::remove_file(Self::FILE_BAK);
        Ok(())
    }

    fn validate_plain_storage(s: &StorageData) -> Result<(), Box<dyn Error>> {
        if s.nickname.len() > Self::VAULT_NICKNAME_MAX {
            return Err(format!(
                "vault: nickname длиннее {} байт",
                Self::VAULT_NICKNAME_MAX
            )
            .into());
        }
        if s.keypair_bytes.len() > Self::VAULT_KEYPAIR_BYTES_MAX {
            return Err(format!(
                "vault: keypair_bytes больше {} байт",
                Self::VAULT_KEYPAIR_BYTES_MAX
            )
            .into());
        }
        if s.address_book.len() > Self::VAULT_ADDRESS_BOOK_MAX_ENTRIES {
            return Err(format!(
                "vault: address_book больше {} записей",
                Self::VAULT_ADDRESS_BOOK_MAX_ENTRIES
            )
            .into());
        }
        for (i, e) in s.address_book.iter().enumerate() {
            if e.peer_id.len() > Self::VAULT_ENTRY_PEER_ID_MAX {
                return Err(format!(
                    "vault: address_book[{}].peer_id слишком длинный",
                    i
                )
                .into());
            }
            if e.display_name.len() > Self::VAULT_ENTRY_NAME_MAX {
                return Err(format!(
                    "vault: address_book[{}].display_name слишком длинный",
                    i
                )
                .into());
            }
            if e.addrs.len() > Self::VAULT_ENTRY_ADDRS_MAX {
                return Err(format!(
                    "vault: address_book[{}].addrs — слишком много адресов",
                    i
                )
                .into());
            }
            for (j, a) in e.addrs.iter().enumerate() {
                if a.len() > Self::VAULT_ENTRY_ONE_ADDR_MAX {
                    return Err(format!(
                        "vault: address_book[{}].addrs[{}] — строка multiaddr слишком длинная",
                        i, j
                    )
                    .into());
                }
            }
        }
        if s.void_bootstraps.len() > Self::VAULT_BOOTSTRAPS_MAX {
            return Err(format!(
                "vault: void_bootstraps больше {} записей",
                Self::VAULT_BOOTSTRAPS_MAX
            )
            .into());
        }
        for (i, a) in s.void_bootstraps.iter().enumerate() {
            if a.len() > Self::VAULT_BOOTSTRAP_ONE_ADDR_MAX {
                return Err(format!(
                    "vault: void_bootstraps[{}] — строка multiaddr слишком длинная",
                    i
                )
                .into());
            }
        }
        Ok(())
    }

    pub(crate) fn load(master_key: &[u8; 32]) -> Result<StorageData, Box<dyn Error>> {
        if !std::path::Path::new(Self::FILE).exists() {
            return Err("Vault file not found".into());
        }
        let data = std::fs::read(Self::FILE)?;
        if data.len() < 12 {
            return Err("Invalid vault".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key.as_slice()));
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption error: {}", e))?;

        if plaintext.len() > Self::VAULT_PLAINTEXT_JSON_MAX {
            return Err(format!(
                "vault: размер plaintext {} превышает лимит {} байт",
                plaintext.len(),
                Self::VAULT_PLAINTEXT_JSON_MAX
            )
            .into());
        }

        let storage: StorageData = serde_json::from_slice(&plaintext)?;
        Self::validate_plain_storage(&storage)?;
        if storage.format_version != 1 {
            return Err(format!(
                "vault: неподдерживаемая format_version {}",
                storage.format_version
            )
            .into());
        }
        Ok(storage)
    }
}

/// Какой экран разблокировки vault показать при старте.
#[derive(Clone)]
pub(crate) enum VaultUnlockKind {
    /// Нет `vault.bin`: создаём профиль, пароль задаётся дважды.
    CreateProfile,
    /// Обычный вход: `void.key` в формате Argon2id + AES-GCM.
    OpenWrappedKey,
    /// Старый `void.key` ровно 32 байта сырого мастер-ключа — перенос на защищённый формат.
    MigratePlainMaster(Zeroizing<[u8; 32]>),
}

pub(crate) struct VaultUnlockState {
    pub kind: VaultUnlockKind,
    pub password: String,
    pub password_confirm: String,
    pub error: Option<String>,
}

/// Определяет сценарий разблокировки по наличию `vault.bin` и формату `void.key`.
pub(crate) fn detect_vault_unlock_kind() -> Result<VaultUnlockKind, String> {
    let vault_exists = Path::new(Storage::FILE).exists();
    let raw_key = Storage::read_key_blob().unwrap_or_else(|_| Vec::new());
    let key_empty = raw_key.is_empty();

    match (vault_exists, key_empty, raw_key.len()) {
        (false, true, _) => Ok(VaultUnlockKind::CreateProfile),
        (false, false, _) => Err(
            "Найден void.key без vault.bin — восстановите vault или удалите void.key.".into(),
        ),
        (true, true, _) => Err(format!(
            "Нет {} при существующем vault — добавьте void.key или восстановите файл ключа.",
            Storage::KEY_FILE
        )),
        (true, false, 32) if !Storage::is_wrapped_keyfile(&raw_key) => {
            let mut m = [0u8; 32];
            m.copy_from_slice(&raw_key);
            Ok(VaultUnlockKind::MigratePlainMaster(Zeroizing::new(m)))
        }
        (true, false, _) if Storage::is_wrapped_keyfile(&raw_key) => Ok(VaultUnlockKind::OpenWrappedKey),
        (true, false, _) => Err(
            "void.key неизвестного формата (ни 32 байта, ни VOIDKEY2).".into(),
        ),
    }
}
