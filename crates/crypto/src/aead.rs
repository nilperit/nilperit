//! XChaCha20-Poly1305 for packed objects (format.md 3.3.5 and 6.7.2).
//!
//! A packed object is a random 24-byte nonce, the ciphertext, and a 16-byte
//! tag. The functions here make and open exactly that layout. The caller gives
//! the associated data (format.md 6.7.2.3 for objects in packs).

use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use x_wing::CryptoRng;

pub use crate::keys::AeadKey;

/// The size of the nonce in a packed object.
pub const NONCE_SIZE: usize = 24;
/// The size of the AEAD tag.
pub const TAG_SIZE: usize = 16;
/// The bytes that a packed object adds to its plaintext: nonce and tag.
pub const OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;

/// The data could not be encrypted, or it could not be opened. This covers a
/// wrong key, wrong associated data, damaged data, and data that is too short.
/// The error does not say which, on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authenticated encryption failed")
    }
}

impl core::error::Error for AeadError {}

fn cipher(key: &AeadKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key.as_bytes()).into())
}

/// Encrypts `plaintext` and returns a packed object: nonce, ciphertext, tag.
///
/// The nonce is new and random for each call (format.md 6.7.2.4).
pub fn encrypt<R: CryptoRng>(
    key: &AeadKey,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, AeadError> {
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    encrypt_with_nonce(key, &nonce, aad, plaintext)
}

/// Encrypts with a nonce that the caller chose. Only for tests with fixed nonces.
pub(crate) fn encrypt_with_nonce(
    key: &AeadKey,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let sealed = cipher(key)
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AeadError)?;
    let mut out = Vec::with_capacity(NONCE_SIZE + sealed.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Opens a packed object and returns the plaintext.
///
/// It checks the tag before it returns any data (format.md 6.6.4).
pub fn decrypt(key: &AeadKey, aad: &[u8], packed: &[u8]) -> Result<Vec<u8>, AeadError> {
    if packed.len() < OVERHEAD {
        return Err(AeadError);
    }
    let (nonce, ciphertext) = packed.split_at(NONCE_SIZE);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    nonce_bytes.copy_from_slice(nonce);
    cipher(key)
        .decrypt(
            &nonce_bytes.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng::TestRng;

    fn key(byte: u8) -> AeadKey {
        AeadKey::from_bytes([byte; 32])
    }

    #[test]
    fn round_trip_and_layout() {
        let mut rng = TestRng::new(5);
        for len in [0usize, 1, 5, 64, 1000] {
            let plain = alloc::vec![0xabu8; len];
            let packed = encrypt(&key(1), b"aad", &plain, &mut rng).unwrap();
            assert_eq!(packed.len(), len + OVERHEAD);
            assert_eq!(decrypt(&key(1), b"aad", &packed).unwrap(), plain);
        }
    }

    #[test]
    fn nonces_are_new_for_each_call() {
        let mut rng = TestRng::new(5);
        let a = encrypt(&key(1), b"", b"x", &mut rng).unwrap();
        let b = encrypt(&key(1), b"", b"x", &mut rng).unwrap();
        assert_ne!(a[..NONCE_SIZE], b[..NONCE_SIZE]);
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_wrong_key_aad_and_damage() {
        let mut rng = TestRng::new(9);
        let packed = encrypt(&key(1), b"aad", b"secret", &mut rng).unwrap();
        assert_eq!(decrypt(&key(2), b"aad", &packed), Err(AeadError));
        assert_eq!(decrypt(&key(1), b"other", &packed), Err(AeadError));
        assert_eq!(decrypt(&key(1), b"", &packed), Err(AeadError));
        // Every single-bit flip is detected: nonce, ciphertext and tag.
        for i in 0..packed.len() {
            let mut bad = packed.clone();
            bad[i] ^= 1;
            assert_eq!(decrypt(&key(1), b"aad", &bad), Err(AeadError), "byte {i}");
        }
    }

    #[test]
    fn rejects_short_input() {
        assert_eq!(decrypt(&key(1), b"", &[]), Err(AeadError));
        assert_eq!(decrypt(&key(1), b"", &[0u8; OVERHEAD - 1]), Err(AeadError));
        // An empty plaintext needs exactly nonce and tag.
        let mut rng = TestRng::new(1);
        let packed = encrypt(&key(1), b"", b"", &mut rng).unwrap();
        assert_eq!(packed.len(), OVERHEAD);
        assert_eq!(decrypt(&key(1), b"", &packed).unwrap(), b"");
    }
}
