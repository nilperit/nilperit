//! The root seed, the recovery phrase and the keys that derive from them
//! (format.md 3.1, 3.2.9, 3.3.3, 3.3.7 and 3.3.8).
//!
//! Every secret type here wipes its bytes when it is dropped and prints no
//! bytes in `Debug`.

use alloc::string::String;
use core::fmt;

use bip39::{Language, Mnemonic};
use x_wing::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::hash::DedupKey;
use crate::seal::ReadKey;

/// The size of every key in this module, in bytes.
pub const KEY_LEN: usize = 32;
/// The number of words in a recovery phrase (format.md 3.1.2).
pub const PHRASE_WORDS: usize = 24;

// The context strings of format.md 3.2.9, 3.3.3, 3.3.7 and 3.3.8. They are part
// of the format: changing one changes every key that derives with it.
const CTX_DEDUP_KEY: &str = "nilperit 2026-11-22 dedup-key";
const CTX_WRITER_KEY: &str = "nilperit 2026-11-22 writer-key";
const CTX_CHUNKER_SEED: &str = "nilperit 2026-11-22 chunker-seed";
const CTX_READ_KEY: &str = "nilperit 2026-11-22 read-key";
const CTX_PACK_OBJECT: &str = "nilperit 2026-11-22 pack-object";
const CTX_PACK_TABLE: &str = "nilperit 2026-11-22 pack-table";
const CTX_SNAPSHOT_HEADER: &str = "nilperit 2026-11-22 snapshot-header";
const CTX_CONDEMNATION_RECORD: &str = "nilperit 2026-11-22 condemnation-record";
const CTX_INDEX_SEGMENT: &str = "nilperit 2026-11-22 index-segment";
const CTX_CONFIG_MAC: &str = "nilperit 2026-11-22 config-mac";

macro_rules! secret_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name([u8; KEY_LEN]);

        impl $name {
            /// Wraps the 32 bytes of the key.
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// The secret bytes. Handle them with care and never log them.
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        // Never print key bytes (AGENTS.md).
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

secret_key!(
    /// A symmetric key for XChaCha20-Poly1305. A pack key and every key that
    /// derives from the writer key is one.
    AeadKey
);

secret_key!(
    /// A key for the BLAKE3 MAC of the vault config.
    MacKey
);

secret_key!(
    /// The writer key (format.md 3.2.3). The node has it.
    WriterKey
);

secret_key!(
    /// The chunker seed (format.md 3.2.3). The node has it.
    ChunkerSeed
);

secret_key!(
    /// The root seed (format.md 3.1). Everything derives from it.
    RootSeed
);

impl AeadKey {
    /// A random key, for example a pack key.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// The recovery phrase is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhraseError {
    /// The phrase does not have 24 words.
    WordCount,
    /// A word is not in the English word list, or the checksum is not correct.
    Invalid,
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No part of the phrase goes into a message.
        f.write_str(match self {
            Self::WordCount => "recovery phrase must have 24 words",
            Self::Invalid => "recovery phrase is not valid",
        })
    }
}

impl core::error::Error for PhraseError {}

impl RootSeed {
    /// A new random root seed.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The recovery phrase: 24 BIP39 words, English word list (format.md 3.1.2).
    ///
    /// Only the mapping from the 32 bytes to the words is BIP39. There is no
    /// passphrase and no BIP39 seed (format.md 3.1.2.1).
    pub fn to_phrase(&self) -> Zeroizing<String> {
        // 32 bytes is a valid entropy size, so this cannot fail.
        let phrase = Mnemonic::from_entropy_in(Language::English, &self.0)
            .map(|m| m.words().collect::<alloc::vec::Vec<_>>().join(" "))
            .unwrap_or_default();
        Zeroizing::new(phrase)
    }

    /// Reads a recovery phrase. It checks the word list and the checksum.
    pub fn from_phrase(phrase: &str) -> Result<Self, PhraseError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase).map_err(|e| match e {
            bip39::Error::BadWordCount(_) => PhraseError::WordCount,
            _ => PhraseError::Invalid,
        })?;
        if mnemonic.word_count() != PHRASE_WORDS {
            return Err(PhraseError::WordCount);
        }
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let result = if len == KEY_LEN {
            let mut bytes = [0u8; KEY_LEN];
            bytes.copy_from_slice(&entropy[..KEY_LEN]);
            Ok(Self(bytes))
        } else {
            Err(PhraseError::Invalid)
        };
        entropy.zeroize();
        result
    }

    /// The dedup key (format.md 3.2.9).
    pub fn dedup_key(&self) -> DedupKey {
        DedupKey::from_bytes(blake3::derive_key(CTX_DEDUP_KEY, &self.0))
    }

    /// The writer key (format.md 3.2.9).
    pub fn writer_key(&self) -> WriterKey {
        WriterKey(blake3::derive_key(CTX_WRITER_KEY, &self.0))
    }

    /// The chunker seed (format.md 3.2.9).
    pub fn chunker_seed(&self) -> ChunkerSeed {
        ChunkerSeed(blake3::derive_key(CTX_CHUNKER_SEED, &self.0))
    }

    /// The read key (format.md 3.2.9).
    pub fn read_key(&self) -> ReadKey {
        let mut seed = blake3::derive_key(CTX_READ_KEY, &self.0);
        let key = ReadKey::from_seed(seed);
        seed.zeroize();
        key
    }
}

impl WriterKey {
    fn derive(&self, context: &str) -> [u8; KEY_LEN] {
        blake3::derive_key(context, &self.0)
    }

    /// The key for W objects in the body of a pack (format.md 3.3.3).
    pub fn pack_object_key(&self) -> AeadKey {
        AeadKey(self.derive(CTX_PACK_OBJECT))
    }

    /// The key for the object table of a pack (format.md 3.3.3).
    pub fn pack_table_key(&self) -> AeadKey {
        AeadKey(self.derive(CTX_PACK_TABLE))
    }

    /// The key for snapshot header files (format.md 3.3.7.1).
    pub fn snapshot_header_key(&self) -> AeadKey {
        AeadKey(self.derive(CTX_SNAPSHOT_HEADER))
    }

    /// The key for condemnation record files (format.md 3.3.7.1).
    pub fn condemnation_record_key(&self) -> AeadKey {
        AeadKey(self.derive(CTX_CONDEMNATION_RECORD))
    }

    /// The key for index segment files (format.md 3.3.7.1).
    pub fn index_segment_key(&self) -> AeadKey {
        AeadKey(self.derive(CTX_INDEX_SEGMENT))
    }

    /// The MAC key of the vault config (format.md 3.3.8).
    pub fn config_mac_key(&self) -> MacKey {
        MacKey(self.derive(CTX_CONFIG_MAC))
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;
    use crate::test_rng::TestRng;

    #[test]
    fn phrase_round_trip() {
        let seed = RootSeed::generate(&mut TestRng::new(1));
        let phrase = seed.to_phrase();
        assert_eq!(phrase.split(' ').count(), PHRASE_WORDS);
        let back = RootSeed::from_phrase(&phrase).unwrap();
        assert_eq!(back.as_bytes(), seed.as_bytes());
    }

    #[test]
    fn phrase_accepts_extra_whitespace_and_rejects_bad_input() {
        let seed = RootSeed::from_bytes([7; 32]);
        let phrase = seed.to_phrase();
        let spaced = phrase.replace(' ', "  ");
        assert_eq!(
            RootSeed::from_phrase(&spaced).unwrap().as_bytes(),
            seed.as_bytes()
        );

        // Fewer than 24 words, even with a valid checksum (a 12-word phrase).
        let twelve = Mnemonic::from_entropy_in(Language::English, &[7u8; 16]).unwrap();
        let twelve = twelve.words().collect::<alloc::vec::Vec<_>>().join(" ");
        assert_eq!(
            RootSeed::from_phrase(&twelve).unwrap_err(),
            PhraseError::WordCount
        );
        assert_eq!(
            RootSeed::from_phrase("").unwrap_err(),
            PhraseError::WordCount
        );

        // A wrong checksum: change the last word to another word.
        let mut words: alloc::vec::Vec<&str> = phrase.split(' ').collect();
        let last = words.pop().unwrap();
        let other = if last == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        words.push(other);
        assert_eq!(
            RootSeed::from_phrase(&words.join(" ")).unwrap_err(),
            PhraseError::Invalid
        );

        // A word that is not in the list.
        let mut words: alloc::vec::Vec<&str> = phrase.split(' ').collect();
        words[3] = "nilperit";
        assert_eq!(
            RootSeed::from_phrase(&words.join(" ")).unwrap_err(),
            PhraseError::Invalid
        );
    }

    #[test]
    fn different_purposes_give_different_keys() {
        let root = RootSeed::from_bytes([1; 32]);
        let writer = root.writer_key();
        let keys = [
            root.dedup_key().as_bytes().to_vec(),
            writer.as_bytes().to_vec(),
            root.chunker_seed().as_bytes().to_vec(),
            root.read_key().as_bytes().to_vec(),
            writer.pack_object_key().as_bytes().to_vec(),
            writer.pack_table_key().as_bytes().to_vec(),
            writer.snapshot_header_key().as_bytes().to_vec(),
            writer.condemnation_record_key().as_bytes().to_vec(),
            writer.index_segment_key().as_bytes().to_vec(),
            writer.config_mac_key().as_bytes().to_vec(),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn debug_output_hides_secrets() {
        let root = RootSeed::from_bytes([9; 32]);
        for shown in [
            format!("{root:?}"),
            format!("{:?}", root.writer_key()),
            format!("{:?}", root.chunker_seed()),
            format!("{:?}", root.writer_key().pack_object_key()),
            format!("{:?}", root.writer_key().config_mac_key()),
            format!("{:?}", root.read_key()),
        ] {
            assert!(shown.ends_with("(..)"), "{shown}");
        }
    }
}
