use anyhow::{anyhow, Result};
use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[allow(dead_code)]
pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// KDF (Key Derivation Function) на базе BLAKE2b
fn kdf(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(salt);
    hasher.update(ikm);
    hasher.update(info);
    let result = hasher.finalize();
    result[..output_len].to_vec()
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    fn step(&mut self) -> [u8; 32] {
        let message_key = kdf(
            self.key.as_slice(),
            b"message_key",
            &self.index.to_be_bytes(),
            32,
        );
        self.key = kdf(
            self.key.as_slice(),
            b"chain_key",
            &self.index.to_be_bytes(),
            32,
        )
        .try_into()
        .unwrap_or([0; 32]);
        self.index += 1;
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&message_key);
        mk
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub dh_pub: [u8; 32],
    pub pn: u32, // Previous number of messages in sending chain
    pub n: u32,  // Message index in current chain
}

#[allow(dead_code)]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureSession {
    dhs: StaticSecret, // Our DH ratchet key (private)
    dhr: PublicKey,    // Their DH ratchet key (public)
    rk: [u8; 32],      // Root Key
    ck_send: Option<ChainKey>,
    ck_recv: Option<ChainKey>,
    ns: u32, // Number of messages sent in current chain
    nr: u32, // Number of messages received in current chain
    pn: u32, // Number of messages in previous sending chain
    #[zeroize(skip)]
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>, // (DH_pub, index) -> MessageKey
}

#[allow(dead_code)]
impl SecureSession {
    pub fn new_initiator(local_static: &StaticSecret, remote_static: &PublicKey) -> Self {
        let mut rng = OsRng;
        let dhs = StaticSecret::random_from_rng(&mut rng);
        let dhr = *remote_static;

        let shared = local_static.diffie_hellman(remote_static);
        let rk: [u8; 32] = kdf(
            b"VOID_SALT".as_slice(),
            shared.as_bytes(),
            b"VOID_INIT_IK".as_slice(),
            32,
        )
        .try_into()
        .unwrap();

        Self {
            dhs,
            dhr,
            rk,
            ck_send: Some(ChainKey { key: rk, index: 0 }),
            ck_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_keys: HashMap::new(),
        }
    }

    pub fn new_responder(local_static: &StaticSecret, remote_static: &PublicKey) -> Self {
        let dhr = *remote_static;
        let shared = local_static.diffie_hellman(&dhr);
        let rk: [u8; 32] = kdf(
            b"VOID_SALT".as_slice(),
            shared.as_bytes(),
            b"VOID_INIT_IK".as_slice(),
            32,
        )
        .try_into()
        .unwrap();

        Self {
            dhs: StaticSecret::random_from_rng(&mut OsRng),
            dhr,
            rk,
            ck_send: None,
            ck_recv: Some(ChainKey { key: rk, index: 0 }),
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_keys: HashMap::new(),
        }
    }

    pub fn encrypt_payload(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>)> {
        let ck = self
            .ck_send
            .as_mut()
            .ok_or_else(|| anyhow!("No sending chain"))?;
        let mk = ck.step();
        let header = MessageHeader {
            dh_pub: PublicKey::from(&self.dhs).to_bytes(),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let cipher = ChaCha20Poly1305::new(mk.as_slice().into());
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("Encryption failed"))?;

        Ok((header, ciphertext))
    }

    pub fn decrypt_payload(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(mk) = self.skipped_keys.remove(&(header.dh_pub, header.n)) {
            return self.decrypt_with_key(&mk, ciphertext);
        }

        if header.dh_pub != self.dhr.to_bytes() {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }

        self.skip_message_keys(header.n)?;

        let ck = self
            .ck_recv
            .as_mut()
            .ok_or_else(|| anyhow!("No receiving chain"))?;
        let mk = ck.step();
        self.nr += 1;

        self.decrypt_with_key(&mk, ciphertext)
    }

    fn decrypt_with_key(&self, mk: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(mk.as_slice().into());
        let nonce = Nonce::from_slice(&[0u8; 12]);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))
    }

    fn dh_ratchet(&mut self, header: &MessageHeader) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = PublicKey::from(header.dh_pub);

        let shared_recv = self.dhs.diffie_hellman(&self.dhr);
        let (rk, ck_recv_key) = self.kdf_rk(&shared_recv);
        self.rk = rk;
        self.ck_recv = Some(ChainKey {
            key: ck_recv_key,
            index: 0,
        });

        let mut rng = OsRng;
        self.dhs = StaticSecret::random_from_rng(&mut rng);
        let shared_send = self.dhs.diffie_hellman(&self.dhr);
        let (rk, ck_send_key) = self.kdf_rk(&shared_send);
        self.rk = rk;
        self.ck_send = Some(ChainKey {
            key: ck_send_key,
            index: 0,
        });

        Ok(())
    }

    fn kdf_rk(&self, shared: &SharedSecret) -> ([u8; 32], [u8; 32]) {
        let out = kdf(self.rk.as_slice(), shared.as_bytes(), b"dr_ratchet", 64);
        (
            out[0..32].try_into().unwrap(),
            out[32..64].try_into().unwrap(),
        )
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if let Some(ck) = self.ck_recv.as_mut() {
            while ck.index < until {
                if self.skipped_keys.len() >= 100 {
                    return Err(anyhow!("Too many skipped keys"));
                }
                let mk = ck.step();
                self.skipped_keys
                    .insert((self.dhr.to_bytes(), ck.index - 1), mk);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::StaticSecret;

    #[test]
    fn test_secure_session_initialization() {
        let mut rng = OsRng;
        let alice_static = StaticSecret::random_from_rng(&mut rng);
        let bob_static = StaticSecret::random_from_rng(&mut rng);
        let bob_pub = PublicKey::from(&bob_static);

        let mut alice_session = SecureSession::new_initiator(&alice_static, &bob_pub);
        let msg = "Привет, Боб!".as_bytes();
        let (header, ciphertext) = alice_session
            .encrypt_payload(msg)
            .expect("Шифрование должно работать");

        assert_eq!(header.n, 0);
        assert!(!ciphertext.is_empty());
    }
}
