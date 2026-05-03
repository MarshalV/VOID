use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[allow(dead_code)]
pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF-SHA256 по RFC 5869: positional args совпадают с прежним API —
/// `salt` → HKDF-Extract salt, `ikm` → input keying material, `info` → HKDF-Expand info.
fn hkdf_sha256_derive(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm).expect("HKDF output_len within SHA256 limit");
    okm
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    fn step(&mut self) -> [u8; 32] {
        let message_key = hkdf_sha256_derive(
            self.key.as_slice(),
            b"message_key",
            &self.index.to_be_bytes(),
            32,
        );
        self.key = hkdf_sha256_derive(
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
pub struct SecureSession {
    dhs: StaticSecret, // Our DH ratchet key (private)
    dhr: PublicKey,    // Their DH ratchet key (public)
    rk: [u8; 32],      // Root Key
    ck_send: Option<ChainKey>,
    ck_recv: Option<ChainKey>,
    ns: u32, // Number of messages sent in current chain
    nr: u32, // Number of messages received in current chain
    pn: u32, // Number of messages in previous sending chain
    skipped_keys: HashMap<([u8; 32], u32), [u8; 32]>, // (DH_pub, index) -> MessageKey
}

impl Zeroize for SecureSession {
    fn zeroize(&mut self) {
        self.rk.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
        self.ns.zeroize();
        self.nr.zeroize();
        self.pn.zeroize();
        // Manually zeroize every message key stored for out-of-order delivery,
        // then clear the map so the (DH_pub, index) slots are also released.
        for mk in self.skipped_keys.values_mut() {
            mk.zeroize();
        }
        self.skipped_keys.clear();
        // dhs (StaticSecret) is ZeroizeOnDrop — zeroed when it is dropped.
        // dhr (PublicKey) is non-secret public material.
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[allow(dead_code)]
impl SecureSession {
    pub fn new_initiator(
        local_static: &StaticSecret,
        remote_static: &PublicKey,
        local_ephemeral: StaticSecret,
        remote_ephemeral: &PublicKey,
    ) -> Self {
        let shared_static = local_static.diffie_hellman(remote_static);
        let rk: [u8; 32] = hkdf_sha256_derive(
            b"VOID_SALT".as_slice(),
            shared_static.as_bytes(),
            b"VOID_INIT_RK".as_slice(),
            32,
        )
        .try_into()
        .unwrap();

        let mut sess = Self {
            dhs: local_ephemeral,
            dhr: *remote_static,
            rk,
            ck_send: None,
            ck_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_keys: HashMap::new(),
        };

        // 1. Ratchet send: DH(e_alice, s_bob)
        let shared_send_static = sess.dhs.diffie_hellman(remote_static);
        let (rk1, ck_send_key) = sess.kdf_rk(&shared_send_static);
        sess.rk = rk1;
        sess.ck_send = Some(ChainKey {
            key: ck_send_key,
            index: 0,
        });

        // 2. Ratchet recv: DH(e_alice, e_bob)
        sess.dhr = *remote_ephemeral;
        let shared_recv_ephem = sess.dhs.diffie_hellman(&sess.dhr);
        let (rk2, ck_recv_key) = sess.kdf_rk(&shared_recv_ephem);
        sess.rk = rk2;
        sess.ck_recv = Some(ChainKey {
            key: ck_recv_key,
            index: 0,
        });

        sess
    }

    pub fn new_responder(
        local_static: &StaticSecret,
        remote_static: &PublicKey,
        remote_ephemeral: &PublicKey,
        local_ephemeral: StaticSecret,
    ) -> Self {
        let shared_static = local_static.diffie_hellman(remote_static);
        let rk: [u8; 32] = hkdf_sha256_derive(
            b"VOID_SALT".as_slice(),
            shared_static.as_bytes(),
            b"VOID_INIT_RK".as_slice(),
            32,
        )
        .try_into()
        .unwrap();

        let mut sess = Self {
            dhs: local_ephemeral,
            dhr: *remote_ephemeral,
            rk,
            ck_send: None,
            ck_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_keys: HashMap::new(),
        };

        // 1. Ratchet recv: DH(s_bob, e_alice)
        let shared_recv_static = local_static.diffie_hellman(remote_ephemeral);
        let (rk1, ck_recv_key) = sess.kdf_rk(&shared_recv_static);
        sess.rk = rk1;
        sess.ck_recv = Some(ChainKey {
            key: ck_recv_key,
            index: 0,
        });

        // 2. Ratchet send: DH(e_bob, e_alice)
        let shared_send_ephem = sess.dhs.diffie_hellman(remote_ephemeral);
        let (rk2, ck_send_key) = sess.kdf_rk(&shared_send_ephem);
        sess.rk = rk2;
        sess.ck_send = Some(ChainKey {
            key: ck_send_key,
            index: 0,
        });

        sess
    }

    pub fn encrypt_payload(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>)> {
        let ck = self
            .ck_send
            .as_mut()
            .ok_or_else(|| anyhow!("No sending chain"))?;
        let mk = ck.step();
        let ns = self.ns;
        let header = MessageHeader {
            dh_pub: PublicKey::from(&self.dhs).to_bytes(),
            pn: self.pn,
            n: ns,
        };
        self.ns += 1;

        let cipher = ChaCha20Poly1305::new(mk.as_slice().into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&ns.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
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
            return self.decrypt_with_key(&mk, header.n, ciphertext);
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

        self.decrypt_with_key(&mk, header.n, ciphertext)
    }

    fn decrypt_with_key(&self, mk: &[u8; 32], n: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(mk.as_slice().into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&n.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
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
        let out = hkdf_sha256_derive(self.rk.as_slice(), shared.as_bytes(), b"dr_ratchet", 64);
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

    #[test]
    fn test_secure_session_initialization() {
        let mut rng = OsRng;
        let alice_static = StaticSecret::random_from_rng(&mut rng);
        let bob_static = StaticSecret::random_from_rng(&mut rng);
        let alice_pub = PublicKey::from(&alice_static);
        let bob_pub = PublicKey::from(&bob_static);

        let alice_ephem = StaticSecret::random_from_rng(&mut rng);
        let bob_ephem = StaticSecret::random_from_rng(&mut rng);
        let alice_ephem_pub = PublicKey::from(&alice_ephem);
        let bob_ephem_pub = PublicKey::from(&bob_ephem);

        let mut alice_session =
            SecureSession::new_initiator(&alice_static, &bob_pub, alice_ephem, &bob_ephem_pub);
        let mut bob_session =
            SecureSession::new_responder(&bob_static, &alice_pub, &alice_ephem_pub, bob_ephem);

        let msg = b"Hello Bob!";
        let (header, ciphertext) = alice_session.encrypt_payload(msg).unwrap();
        let decrypted = bob_session.decrypt_payload(&header, &ciphertext).unwrap();
        assert_eq!(msg, decrypted.as_slice());
    }
}
