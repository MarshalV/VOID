//! ML-KEM-768 рядом с X25519. Секрет — 64-байтный seed FIPS 203.

use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, Kem as _, Key, KeyExport, MlKem768};
use zeroize::Zeroize;

pub const EK_LEN: usize = 1184;
pub const CT_LEN: usize = 1088;
pub const DK_LEN: usize = 64;

#[derive(Clone)]
pub struct KemDk {
    bytes: Vec<u8>,
}

impl Drop for KemDk {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl KemDk {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DK_LEN {
            return None;
        }
        Some(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn encapsulation_key(&self) -> Option<Vec<u8>> {
        let dk = load_dk(&self.bytes)?;
        Some(dk.encapsulation_key().to_bytes().as_slice().to_vec())
    }
}

fn load_dk(bytes: &[u8]) -> Option<DecapsulationKey> {
    let seed = ml_kem::Seed::try_from(bytes).ok()?;
    Some(DecapsulationKey::from_seed(seed))
}

fn load_ek(bytes: &[u8]) -> Option<EncapsulationKey> {
    let key = Key::<EncapsulationKey>::try_from(bytes).ok()?;
    EncapsulationKey::new(&key).ok()
}

/// Свежая пара. Второе значение — encapsulation key для Hello и prekey.
pub fn generate() -> (KemDk, Vec<u8>) {
    let (dk, _ek) = MlKem768::generate_keypair();
    let seed = dk.to_seed().expect("ML-KEM key was generated from a seed");
    let ek = dk.encapsulation_key().to_bytes();
    (
        KemDk {
            bytes: seed.as_slice().to_vec(),
        },
        ek.as_slice().to_vec(),
    )
}

/// `(ciphertext, shared secret)`.
pub fn encapsulate(ek: &[u8]) -> Option<(Vec<u8>, [u8; 32])> {
    let ek = load_ek(ek)?;
    let (ct, ss) = ek.encapsulate();
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Some((ct.as_slice().to_vec(), shared))
}

pub fn decapsulate(dk: &KemDk, ct: &[u8]) -> Option<[u8; 32]> {
    let dk = load_dk(dk.as_bytes())?;
    let ct = Ciphertext::try_from(ct).ok()?;
    let ss = dk.decapsulate(&ct);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(ss.as_slice());
    Some(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encaps_matches_decaps() {
        let (dk, ek) = generate();
        assert_eq!(ek.len(), EK_LEN);
        assert_eq!(dk.as_bytes().len(), DK_LEN);
        let (ct, ss) = encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), CT_LEN);
        assert_eq!(decapsulate(&dk, &ct).unwrap(), ss);
    }
}
