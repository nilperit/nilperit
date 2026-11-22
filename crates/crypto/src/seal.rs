//! The read key and the seal of a pack key (format.md 3.2.9.1 and 3.3.2).
//!
//! The KEM is X-Wing, draft 06. A seal is a simple KEM-DEM: encapsulate to the
//! public part of the read key, derive a seal key from the shared secret, and
//! encrypt the pack key with XChaCha20-Poly1305. The associated data is the
//! hash of the header of the pack, so a seal belongs to one pack.

use alloc::vec::Vec;
use core::fmt;

use x_wing::{Ciphertext, CryptoRng, Decapsulate, Decapsulator, Encapsulate, KeyExport};
use zeroize::Zeroize;

use crate::aead::{self, OVERHEAD};
use crate::keys::{AeadKey, KEY_LEN};

/// The name of the key encapsulation algorithm in a pack header and in the vault
/// config (format.md 3.3.2.1).
pub const KEM_NAME: &str = "x-wing-draft-06";
/// The size of the public part of the read key.
pub const READ_PUBLIC_KEY_SIZE: usize = 1216;
/// The size of the X-Wing ciphertext in a seal.
pub const KEM_CIPHERTEXT_SIZE: usize = 1120;
/// The size of a seal: the ciphertext, the nonce, the encrypted pack key, the tag.
pub const SEAL_SIZE: usize = KEM_CIPHERTEXT_SIZE + OVERHEAD + KEY_LEN;

const CTX_PACK_SEAL: &str = "nilperit 2026-11-22 pack-seal";

/// Why a seal or a key could not be made or opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The bytes are not a read public key.
    BadKey,
    /// The seal does not have the size of format.md 3.3.2.2.
    BadSize,
    /// The seal could not be opened: a wrong read key, a wrong header, or damage.
    /// The error does not say which, on purpose.
    Invalid,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadKey => "bytes are not a read public key",
            Self::BadSize => "seal has the wrong size",
            Self::Invalid => "seal could not be opened",
        })
    }
}

impl core::error::Error for SealError {}

/// The read key: the private part of the key pair that opens R objects.
pub struct ReadKey(x_wing::DecapsulationKey);

impl ReadKey {
    /// Makes the read key from its 32 bytes (format.md 3.2.9.1).
    pub fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        Self(x_wing::DecapsulationKey::from(seed))
    }

    /// The secret bytes. Handle them with care and never log them.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_bytes()
    }

    /// The public part of the read key.
    pub fn public_key(&self) -> ReadPublicKey {
        ReadPublicKey(self.0.encapsulation_key().clone())
    }
}

// Never print key bytes (AGENTS.md).
impl fmt::Debug for ReadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadKey(..)")
    }
}

/// The public part of the read key. It is in the vault config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadPublicKey(x_wing::EncapsulationKey);

impl ReadPublicKey {
    /// The 1216 bytes of the public key.
    pub fn to_bytes(&self) -> [u8; READ_PUBLIC_KEY_SIZE] {
        let key = self.0.to_bytes();
        let mut out = [0u8; READ_PUBLIC_KEY_SIZE];
        out.copy_from_slice(key.as_slice());
        out
    }

    /// Reads a public key. The bytes must be exactly 1216 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        x_wing::EncapsulationKey::try_from(bytes)
            .map(Self)
            .map_err(|_| SealError::BadKey)
    }
}

fn seal_key(shared_secret: &mut [u8]) -> AeadKey {
    let key = AeadKey::from_bytes(blake3::derive_key(CTX_PACK_SEAL, shared_secret));
    shared_secret.zeroize();
    key
}

/// Seals a pack key to the public part of the read key (format.md 3.3.2.2).
///
/// `header_hash` is the BLAKE3 hash of the header of the pack. The result is
/// [`SEAL_SIZE`] bytes.
pub fn seal_pack_key<R: CryptoRng>(
    public_key: &ReadPublicKey,
    pack_key: &AeadKey,
    header_hash: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>, SealError> {
    let (ciphertext, mut shared_secret) = public_key.0.encapsulate_with_rng(rng);
    let key = seal_key(shared_secret.as_mut_slice());
    let encrypted = aead::encrypt(&key, header_hash, pack_key.as_bytes(), rng)
        .map_err(|_| SealError::Invalid)?;
    let mut seal = Vec::with_capacity(SEAL_SIZE);
    seal.extend_from_slice(ciphertext.as_slice());
    seal.extend_from_slice(&encrypted);
    Ok(seal)
}

/// Opens a seal and returns the pack key (format.md 3.3.2.3).
pub fn open_seal(
    read_key: &ReadKey,
    seal: &[u8],
    header_hash: &[u8; 32],
) -> Result<AeadKey, SealError> {
    if seal.len() != SEAL_SIZE {
        return Err(SealError::BadSize);
    }
    let (ciphertext, encrypted) = seal.split_at(KEM_CIPHERTEXT_SIZE);
    let ciphertext = Ciphertext::try_from(ciphertext).map_err(|_| SealError::BadSize)?;
    let mut shared_secret = read_key.0.decapsulate(&ciphertext);
    let key = seal_key(shared_secret.as_mut_slice());
    let mut plain = aead::decrypt(&key, header_hash, encrypted).map_err(|_| SealError::Invalid)?;
    let mut bytes = [0u8; KEY_LEN];
    let result = if plain.len() == KEY_LEN {
        bytes.copy_from_slice(&plain);
        Ok(AeadKey::from_bytes(bytes))
    } else {
        Err(SealError::Invalid)
    };
    plain.zeroize();
    bytes.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;

    fn read_key() -> ReadKey {
        ReadKey::from_seed([0x42; 32])
    }

    #[test]
    fn sizes_match_the_kem_and_the_spec() {
        assert_eq!(READ_PUBLIC_KEY_SIZE, x_wing::ENCAPSULATION_KEY_SIZE);
        assert_eq!(KEM_CIPHERTEXT_SIZE, x_wing::CIPHERTEXT_SIZE);
        assert_eq!(SEAL_SIZE, 1192);
    }

    #[test]
    fn seal_round_trip() {
        let mut rng = TestRng::new(7);
        let pack_key = AeadKey::generate(&mut rng);
        let header_hash = [9u8; 32];
        let seal =
            seal_pack_key(&read_key().public_key(), &pack_key, &header_hash, &mut rng).unwrap();
        assert_eq!(seal.len(), SEAL_SIZE);
        let opened = open_seal(&read_key(), &seal, &header_hash).unwrap();
        assert_eq!(opened.as_bytes(), pack_key.as_bytes());

        // A new seal of the same key is different (new encapsulation, new nonce).
        let other =
            seal_pack_key(&read_key().public_key(), &pack_key, &header_hash, &mut rng).unwrap();
        assert_ne!(seal, other);
    }

    #[test]
    fn seal_is_bound_to_the_header_and_the_read_key() {
        let mut rng = TestRng::new(8);
        let pack_key = AeadKey::generate(&mut rng);
        let seal =
            seal_pack_key(&read_key().public_key(), &pack_key, &[1u8; 32], &mut rng).unwrap();
        assert_eq!(
            open_seal(&read_key(), &seal, &[2u8; 32]).unwrap_err(),
            SealError::Invalid
        );
        let other_key = ReadKey::from_seed([0x43; 32]);
        assert_eq!(
            open_seal(&other_key, &seal, &[1u8; 32]).unwrap_err(),
            SealError::Invalid
        );
    }

    #[test]
    fn damaged_and_wrongly_sized_seals_are_rejected() {
        let mut rng = TestRng::new(10);
        let pack_key = AeadKey::generate(&mut rng);
        let seal =
            seal_pack_key(&read_key().public_key(), &pack_key, &[1u8; 32], &mut rng).unwrap();
        // One byte in each part: the X-Wing ciphertext, the nonce, the encrypted key, the tag.
        for i in [
            0,
            600,
            KEM_CIPHERTEXT_SIZE - 1,
            KEM_CIPHERTEXT_SIZE,
            KEM_CIPHERTEXT_SIZE + 30,
            SEAL_SIZE - 1,
        ] {
            let mut bad = seal.clone();
            bad[i] ^= 1;
            assert_eq!(
                open_seal(&read_key(), &bad, &[1u8; 32]).unwrap_err(),
                SealError::Invalid,
                "byte {i}"
            );
        }
        for size in [0, 1, SEAL_SIZE - 1, SEAL_SIZE + 1] {
            let bad = alloc::vec![0u8; size];
            assert_eq!(
                open_seal(&read_key(), &bad, &[1u8; 32]).unwrap_err(),
                SealError::BadSize
            );
        }
    }

    #[test]
    fn public_key_bytes_round_trip() {
        let public = read_key().public_key();
        let bytes = public.to_bytes();
        assert_eq!(bytes.len(), 1216);
        assert_eq!(ReadPublicKey::from_bytes(&bytes).unwrap(), public);
        assert_eq!(
            ReadPublicKey::from_bytes(&bytes[..1215]).unwrap_err(),
            SealError::BadKey
        );
        assert_eq!(
            ReadPublicKey::from_bytes(&[]).unwrap_err(),
            SealError::BadKey
        );
    }

    #[test]
    fn the_read_key_is_the_same_for_the_same_seed() {
        assert_eq!(
            read_key().public_key(),
            ReadKey::from_seed([0x42; 32]).public_key()
        );
        assert_ne!(
            read_key().public_key(),
            ReadKey::from_seed([0x43; 32]).public_key()
        );
        assert_eq!(read_key().as_bytes(), &[0x42; 32]);
    }
}
