use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
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

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    fn step(&mut self) -> Result<[u8; 32]> {
        let message_key = hkdf_sha256_derive(
            self.key.as_slice(),
            b"message_key",
            &self.index.to_be_bytes(),
            32,
        );
        let next: [u8; 32] = hkdf_sha256_derive(
            self.key.as_slice(),
            b"chain_key",
            &self.index.to_be_bytes(),
            32,
        )
        .try_into()
        .map_err(|_| anyhow!("chain key KDF length"))?;
        self.key = next;
        self.index += 1;
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&message_key);
        Ok(mk)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub dh_pub: [u8; 32],
    pub pn: u32, // Previous number of messages in sending chain
    pub n: u32,  // Message index in current chain
}

impl MessageHeader {
    fn aad(&self, peers: &[u8]) -> Vec<u8> {
        const DOMAIN: &[u8; 19] = b"VOID_RATCHET_HDR_V1";
        let mut v = Vec::with_capacity(DOMAIN.len() + 32 + 8 + peers.len());
        v.extend_from_slice(DOMAIN);
        v.extend_from_slice(&self.dh_pub);
        v.extend_from_slice(&self.pn.to_le_bytes());
        v.extend_from_slice(&self.n.to_le_bytes());
        v.extend_from_slice(peers);
        v
    }
}

fn canonical_peer_aad(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len());
    if a <= b {
        v.extend_from_slice(a);
        v.extend_from_slice(b);
    } else {
        v.extend_from_slice(b);
        v.extend_from_slice(a);
    }
    v
}

fn header_nonce(n: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&n.to_le_bytes());
    nonce
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct SecureSession {
    dhs: StaticSecret, // Our DH ratchet key (private)
    dhr: PublicKey,    // Their DH ratchet key (public)
    rk: [u8; 32],      // Root Key
    ck_send: Option<ChainKey>,
    ck_recv: Option<ChainKey>,
    ns: u32, // Number of messages sent in current chain
    nr: u32, // Number of messages received in current chain
    pn: u32, // Number of messages in previous sending chain
    skipped_keys: HashMap<([u8; 32], u32), ([u8; 32], Instant)>, // (DH_pub, n) -> (mk, when)
    // Заголовок + PeerId обеих сторон в AAD: шлём, когда пир объявил поддержку
    // (Hello caps) или сам прислал такой кадр. Без AAD — пока не пришёл первый кадр с AAD.
    send_header_aad: bool,
    require_header_aad: bool,
    peer_aad: Vec<u8>,
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
        for (mk, _) in self.skipped_keys.values_mut() {
            mk.zeroize();
        }
        self.skipped_keys.clear();
        self.peer_aad.zeroize();
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
            send_header_aad: false,
            require_header_aad: false,
            peer_aad: Vec::new(),
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

        // 3. Первый шаг DH ratchet. Без него обе стороны так и шлют с e_alice / e_bob:
        // ключ меняется только при приёме чужого нового dh_pub, а его никто не создаёт.
        // Ответчик (в том числе старый клиент) проходит шаг штатным dh_ratchet.
        sess.dhs = StaticSecret::random_from_rng(OsRng);
        let shared_kickoff = sess.dhs.diffie_hellman(&sess.dhr);
        let (rk3, ck_send_key) = sess.kdf_rk(&shared_kickoff);
        sess.rk = rk3;
        sess.ck_send = Some(ChainKey {
            key: ck_send_key,
            index: 0,
        });

        sess
    }

    /// Пир поддерживает заголовок в AAD (`HELLO_CAP_HEADER_AAD`).
    pub fn enable_header_aad(&mut self) {
        self.send_header_aad = true;
    }

    /// Привязать кадры к PeerId обеих сторон (канонический порядок, одинаковый у обоих).
    pub fn bind_peers(&mut self, local: &[u8], remote: &[u8]) {
        self.peer_aad = canonical_peer_aad(local, remote);
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
            send_header_aad: false,
            require_header_aad: false,
            peer_aad: Vec::new(),
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
        let mk = ck.step()?;
        let ns = self.ns;
        let header = MessageHeader {
            dh_pub: PublicKey::from(&self.dhs).to_bytes(),
            pn: self.pn,
            n: ns,
        };
        self.ns += 1;

        let cipher = ChaCha20Poly1305::new(mk.as_slice().into());
        let nonce_bytes = header_nonce(ns);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = header.aad(&self.peer_aad);
        let ciphertext = if self.send_header_aad {
            cipher.encrypt(nonce, Payload { msg: plaintext, aad: &aad })
        } else {
            cipher.encrypt(nonce, plaintext)
        }
        .map_err(|_| anyhow!("Encryption failed"))?;

        Ok((header, ciphertext))
    }

    /// Состояние меняется только при успешной проверке AEAD: поддельный или
    /// повторённый кадр не сдвигает ratchet и не забивает skipped keys.
    pub fn decrypt_payload(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        self.purge_stale_skipped();
        if let Some(&(mk, _)) = self.skipped_keys.get(&(header.dh_pub, header.n)) {
            let (plaintext, with_aad) = self.decrypt_with_key(&mk, header, ciphertext)?;
            if let Some((mut used, _)) = self.skipped_keys.remove(&(header.dh_pub, header.n)) {
                used.zeroize();
            }
            self.note_header_aad(with_aad);
            return Ok(plaintext);
        }

        let mut trial = self.clone();
        let (plaintext, with_aad) = trial.decrypt_advancing(header, ciphertext)?;
        *self = trial;
        self.note_header_aad(with_aad);
        Ok(plaintext)
    }

    fn note_header_aad(&mut self, with_aad: bool) {
        if with_aad {
            self.require_header_aad = true;
            self.send_header_aad = true;
        }
    }

    fn decrypt_advancing(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        if header.dh_pub != self.dhr.to_bytes() {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }

        self.skip_message_keys(header.n)?;

        let ck = self
            .ck_recv
            .as_mut()
            .ok_or_else(|| anyhow!("No receiving chain"))?;
        let mk = ck.step()?;
        self.nr += 1;

        self.decrypt_with_key(&mk, header, ciphertext)
    }

    /// `(plaintext, был ли заголовок в AAD)`.
    fn decrypt_with_key(
        &self,
        mk: &[u8; 32],
        header: &MessageHeader,
        ciphertext: &[u8],
    ) -> Result<(Vec<u8>, bool)> {
        let cipher = ChaCha20Poly1305::new(mk.as_slice().into());
        let nonce_bytes = header_nonce(header.n);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = header.aad(&self.peer_aad);
        if let Ok(pt) = cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &aad }) {
            return Ok((pt, true));
        }
        if self.require_header_aad {
            return Err(anyhow!("Decryption failed"));
        }
        cipher
            .decrypt(nonce, ciphertext)
            .map(|pt| (pt, false))
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
        const MAX_SKIPPED_MESSAGE_KEYS: usize = 4096;
        const MAX_SKIP_PER_HEADER: u32 = 1000;
        if let Some(ck) = self.ck_recv.as_mut() {
            if until > ck.index && until - ck.index > MAX_SKIP_PER_HEADER {
                return Err(anyhow!("Skip jump too large"));
            }
            while ck.index < until {
                if self.skipped_keys.len() >= MAX_SKIPPED_MESSAGE_KEYS {
                    return Err(anyhow!("Too many skipped keys"));
                }
                let mk = ck.step()?;
                self.skipped_keys
                    .insert((self.dhr.to_bytes(), ck.index - 1), (mk, Instant::now()));
            }
        }
        Ok(())
    }

    fn purge_stale_skipped(&mut self) {
        const TTL: Duration = Duration::from_secs(3600);
        let now = Instant::now();
        self.skipped_keys.retain(|_, (mk, at)| {
            if now.saturating_duration_since(*at) <= TTL {
                true
            } else {
                mk.zeroize();
                false
            }
        });
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

    fn pair() -> (SecureSession, SecureSession) {
        let mut rng = OsRng;
        let alice_static = StaticSecret::random_from_rng(&mut rng);
        let bob_static = StaticSecret::random_from_rng(&mut rng);
        let alice_ephem = StaticSecret::random_from_rng(&mut rng);
        let bob_ephem = StaticSecret::random_from_rng(&mut rng);
        let alice_ephem_pub = PublicKey::from(&alice_ephem);
        let bob_ephem_pub = PublicKey::from(&bob_ephem);
        let alice = SecureSession::new_initiator(
            &alice_static,
            &PublicKey::from(&bob_static),
            alice_ephem,
            &bob_ephem_pub,
        );
        let bob = SecureSession::new_responder(
            &bob_static,
            &PublicKey::from(&alice_static),
            &alice_ephem_pub,
            bob_ephem,
        );
        (alice, bob)
    }

    #[test]
    fn forged_frames_do_not_break_session() {
        let (mut alice, mut bob) = pair();
        let forged = [
            MessageHeader {
                dh_pub: PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes(),
                pn: 10,
                n: 0,
            },
            MessageHeader {
                dh_pub: PublicKey::from(&alice.dhs).to_bytes(),
                pn: 0,
                n: 4095,
            },
        ];
        for h in &forged {
            assert!(bob.decrypt_payload(h, b"garbage-garbage-garbage").is_err());
        }
        assert!(bob.skipped_keys.is_empty());
        let (h, ct) = alice.encrypt_payload(b"still works").unwrap();
        assert_eq!(bob.decrypt_payload(&h, &ct).unwrap(), b"still works");
    }

    #[test]
    fn replayed_frame_is_rejected_and_harmless() {
        let (mut alice, mut bob) = pair();
        let (h1, ct1) = alice.encrypt_payload(b"one").unwrap();
        assert_eq!(bob.decrypt_payload(&h1, &ct1).unwrap(), b"one");
        assert!(bob.decrypt_payload(&h1, &ct1).is_err());
        let (h2, ct2) = alice.encrypt_payload(b"two").unwrap();
        assert_eq!(bob.decrypt_payload(&h2, &ct2).unwrap(), b"two");
    }

    #[test]
    fn skipped_key_survives_forged_attempt() {
        let (mut alice, mut bob) = pair();
        let (h1, ct1) = alice.encrypt_payload(b"late").unwrap();
        let (h2, ct2) = alice.encrypt_payload(b"first").unwrap();
        assert_eq!(bob.decrypt_payload(&h2, &ct2).unwrap(), b"first");
        assert!(bob.decrypt_payload(&h1, b"forged-forged-forged").is_err());
        assert_eq!(bob.decrypt_payload(&h1, &ct1).unwrap(), b"late");
    }

    #[test]
    fn dh_ratchet_turns_every_round_trip() {
        let (mut alice, mut bob) = pair();
        let initial_alice = PublicKey::from(&alice.dhs).to_bytes();
        let mut seen = std::collections::HashSet::new();
        for round in 0..4u8 {
            let (ha, ca) = alice.encrypt_payload(&[round]).unwrap();
            assert_eq!(bob.decrypt_payload(&ha, &ca).unwrap(), [round]);
            let (hb, cb) = bob.encrypt_payload(&[round, 1]).unwrap();
            assert_eq!(alice.decrypt_payload(&hb, &cb).unwrap(), [round, 1]);
            assert!(seen.insert(ha.dh_pub), "Alice reused a ratchet key");
            assert!(seen.insert(hb.dh_pub), "Bob reused a ratchet key");
        }
        assert_ne!(PublicKey::from(&alice.dhs).to_bytes(), initial_alice);
    }

    #[test]
    fn responder_may_speak_first() {
        let (mut alice, mut bob) = pair();
        let (hb, cb) = bob.encrypt_payload(b"bob first").unwrap();
        let (ha, ca) = alice.encrypt_payload(b"alice crossing").unwrap();
        assert_eq!(alice.decrypt_payload(&hb, &cb).unwrap(), b"bob first");
        assert_eq!(bob.decrypt_payload(&ha, &ca).unwrap(), b"alice crossing");
        let (hb2, cb2) = bob.encrypt_payload(b"after ratchet").unwrap();
        assert_ne!(hb2.dh_pub, hb.dh_pub);
        assert_eq!(alice.decrypt_payload(&hb2, &cb2).unwrap(), b"after ratchet");
    }

    #[test]
    fn out_of_order_across_ratchet_steps() {
        let (mut alice, mut bob) = pair();
        let (h1, c1) = alice.encrypt_payload(b"a1").unwrap();
        let (h2, c2) = alice.encrypt_payload(b"a2").unwrap();
        assert_eq!(bob.decrypt_payload(&h2, &c2).unwrap(), b"a2");
        let (hb, cb) = bob.encrypt_payload(b"b1").unwrap();
        assert_eq!(alice.decrypt_payload(&hb, &cb).unwrap(), b"b1");
        let (h3, c3) = alice.encrypt_payload(b"a3").unwrap();
        assert_ne!(h3.dh_pub, h1.dh_pub);
        assert_eq!(bob.decrypt_payload(&h3, &c3).unwrap(), b"a3");
        assert_eq!(bob.decrypt_payload(&h1, &c1).unwrap(), b"a1");
    }

    #[test]
    fn header_aad_rejects_tampered_header() {
        let (mut alice, mut bob) = pair();
        alice.enable_header_aad();
        let (h1, c1) = alice.encrypt_payload(b"one").unwrap();
        assert_eq!(bob.decrypt_payload(&h1, &c1).unwrap(), b"one");
        assert!(bob.require_header_aad && bob.send_header_aad);

        let (h2, c2) = alice.encrypt_payload(b"two").unwrap();
        let mut tampered = h2.clone();
        tampered.pn ^= 7;
        assert!(bob.decrypt_payload(&tampered, &c2).is_err());
        assert_eq!(bob.decrypt_payload(&h2, &c2).unwrap(), b"two");

        let (hb, cb) = bob.encrypt_payload(b"reply").unwrap();
        assert_eq!(alice.decrypt_payload(&hb, &cb).unwrap(), b"reply");
        assert!(alice.require_header_aad);
    }

    #[test]
    fn plain_frames_rejected_after_aad_seen() {
        let (mut alice, mut bob) = pair();
        let (h_plain, c_plain) = alice.encrypt_payload(b"plain").unwrap();
        alice.enable_header_aad();
        let (h_aad, c_aad) = alice.encrypt_payload(b"aad").unwrap();
        assert_eq!(bob.decrypt_payload(&h_aad, &c_aad).unwrap(), b"aad");
        assert!(bob.decrypt_payload(&h_plain, &c_plain).is_err());
    }

    #[test]
    fn legacy_peer_without_aad_still_works() {
        let (mut alice, mut bob) = pair();
        for i in 0..3u8 {
            let (h, c) = alice.encrypt_payload(&[i]).unwrap();
            assert_eq!(bob.decrypt_payload(&h, &c).unwrap(), [i]);
            let (h, c) = bob.encrypt_payload(&[i, i]).unwrap();
            assert_eq!(alice.decrypt_payload(&h, &c).unwrap(), [i, i]);
        }
        assert!(!alice.send_header_aad && !bob.send_header_aad);
    }

    #[test]
    fn skip_jump_over_one_header_limit_is_rejected() {
        let (mut alice, mut bob) = pair();
        let (h, c) = alice.encrypt_payload(b"ok").unwrap();
        let mut huge = h.clone();
        huge.n = 1001;
        assert!(bob.decrypt_payload(&huge, b"garbage-garbage-garbage").is_err());
        assert!(bob.skipped_keys.is_empty());
        assert_eq!(bob.decrypt_payload(&h, &c).unwrap(), b"ok");
    }

    #[test]
    fn peer_aad_must_match_on_both_sides() {
        let (mut alice, mut bob) = pair();
        alice.bind_peers(b"alice", b"bob");
        bob.bind_peers(b"bob", b"alice");
        alice.enable_header_aad();
        let (h, c) = alice.encrypt_payload(b"bound").unwrap();
        assert_eq!(bob.decrypt_payload(&h, &c).unwrap(), b"bound");

        let (mut alice2, mut bob2) = pair();
        alice2.bind_peers(b"alice", b"bob");
        bob2.bind_peers(b"alice", b"eve");
        alice2.enable_header_aad();
        let (h, c) = alice2.encrypt_payload(b"nope").unwrap();
        assert!(bob2.decrypt_payload(&h, &c).is_err());
    }
}
