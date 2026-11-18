//! PeerId as the multihash bytes, same rules as `void-onion`.
//!
//! The swarm still speaks `libp2p_identity::PeerId`. This newtype is the one
//! session and envelope store. `AsPeerId` lets a caller pass either type;
//! the bytes are the same.

use multihash::Multihash;

const PEER_CODE_IDENTITY: u64 = 0;
const PEER_CODE_SHA256: u64 = 0x12;
const PEER_MAX_INLINE: usize = 42;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId {
    hash: Multihash<64>,
}

#[derive(Debug)]
pub struct PeerIdError;

impl std::fmt::Display for PeerIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bad peer id")
    }
}

impl std::error::Error for PeerIdError {}

impl PeerId {
    pub fn from_bytes(data: &[u8]) -> Result<Self, PeerIdError> {
        let hash = Multihash::<64>::from_bytes(data).map_err(|_| PeerIdError)?;
        match hash.code() {
            PEER_CODE_SHA256 => Ok(Self { hash }),
            PEER_CODE_IDENTITY if hash.digest().len() <= PEER_MAX_INLINE => Ok(Self { hash }),
            _ => Err(PeerIdError),
        }
    }

    pub fn from_public_key(key: &libp2p_identity::PublicKey) -> Self {
        let id = libp2p_identity::PeerId::from_public_key(key);
        Self::from_bytes(&id.to_bytes()).expect("libp2p peer id")
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.hash.to_bytes()
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn multihash(&self) -> &Multihash<64> {
        &self.hash
    }

    /// Swarm id with the same bytes. Dial and Kademlia stay on this type.
    pub fn to_identity(self) -> libp2p_identity::PeerId {
        libp2p_identity::PeerId::from_bytes(&self.to_bytes()).expect("peer id")
    }
}

/// Anything whose bytes are a PeerId. Session and envelope accept both the
/// newtype and `libp2p_identity::PeerId` so the node and the client keep
/// compiling on the current paths.
pub trait AsPeerId {
    fn to_peer_id(&self) -> PeerId;
}

impl AsPeerId for PeerId {
    fn to_peer_id(&self) -> PeerId {
        *self
    }
}

impl AsPeerId for libp2p_identity::PeerId {
    fn to_peer_id(&self) -> PeerId {
        PeerId::from_bytes(&self.to_bytes()).expect("libp2p peer id")
    }
}

impl From<&libp2p_identity::PublicKey> for PeerId {
    fn from(key: &libp2p_identity::PublicKey) -> Self {
        Self::from_public_key(key)
    }
}

impl From<libp2p_identity::PublicKey> for PeerId {
    fn from(key: libp2p_identity::PublicKey) -> Self {
        Self::from_public_key(&key)
    }
}

impl PartialEq<libp2p_identity::PeerId> for PeerId {
    fn eq(&self, other: &libp2p_identity::PeerId) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

impl std::fmt::Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PeerId").field(&self.to_base58()).finish()
    }
}

impl std::str::FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(|_| PeerIdError)?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_base58_match_libp2p() {
        let kp = libp2p_identity::Keypair::generate_ed25519();
        let theirs = kp.public().to_peer_id();
        let ours = PeerId::from_public_key(&kp.public());
        assert_eq!(ours.to_bytes(), theirs.to_bytes());
        assert_eq!(ours.to_string(), theirs.to_string());
        assert_eq!(ours, theirs);
        let parsed: PeerId = theirs.to_string().parse().unwrap();
        assert_eq!(parsed, ours);
    }
}
