//! Opening a vault: choosing the vault config (format.md 7.2.6).

use crate::keys::Keys;
use crate::layout::{CONFIG_A, CONFIG_B};
use crate::pack::{ObjectReadError, Pack, PackOpenError};
use crate::target::{Target, TargetError};
use alloc::vec::Vec;
use core::fmt;
use nilperit_crypto::seal::KEM_NAME;
use nilperit_crypto::{RootSeed, WriterKey, verify_config_mac};
use nilperit_format::{ObjectError, ObjectId, PackName, VaultConfig, split_config_file};

/// A vault could not be opened.
#[derive(Debug)]
pub enum VaultError {
    /// The target failed.
    Target(TargetError),
    /// No config file is valid: both are missing, damaged, or not authentic.
    /// Salvage (format.md 10.7) can rebuild the essential fields.
    NoValidConfig,
    /// The config is not the config of this vault: two valid files with the same
    /// sequence differ, or the read public key is not the one that the recovery
    /// phrase gives (format.md 3.3.9.1, 7.2.6).
    ChangedConfig,
    /// The format version of the vault is higher than this code knows. The person
    /// must use a newer version or the reader in the vault (format.md 9.5).
    NewerFormat(u32),
    /// The vault uses an algorithm that this code does not know.
    UnknownAlgorithm,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(e) => e.fmt(f),
            Self::NoValidConfig => f.write_str("no valid vault config"),
            Self::ChangedConfig => f.write_str("the vault config was changed"),
            Self::NewerFormat(v) => write!(f, "the vault uses format version {v}, which is newer"),
            Self::UnknownAlgorithm => f.write_str("the vault uses an unknown algorithm"),
        }
    }
}

impl core::error::Error for VaultError {}

impl From<TargetError> for VaultError {
    fn from(e: TargetError) -> Self {
        Self::Target(e)
    }
}

/// An open vault: a target, its vault config, and the keys to read it.
pub struct Vault<T> {
    target: T,
    config: VaultConfig,
    keys: Keys,
}

impl<T: Target> Vault<T> {
    /// Opens a vault with the root seed (the recovery phrase).
    ///
    /// It chooses the vault config as format.md 7.2.6 says and checks that the
    /// config belongs to the root seed.
    pub async fn open(target: T, seed: &RootSeed) -> Result<Self, VaultError> {
        let keys = Keys::from_seed(seed);
        let config = choose_config(&target, keys.writer()).await?;
        if config.essentials.key_encapsulation != KEM_NAME {
            return Err(VaultError::UnknownAlgorithm);
        }
        if config.essentials.read_public_key[..] != keys.read().public_key().to_bytes()[..] {
            return Err(VaultError::ChangedConfig);
        }
        Ok(Self {
            target,
            config,
            keys,
        })
    }

    /// Opens a pack of the vault (format.md 6.7.5, steps 1 to 4).
    pub async fn open_pack(&self, name: PackName) -> Result<Pack, PackOpenError> {
        Pack::open(&self.target, name, self.keys.writer()).await
    }

    /// Reads an object of a pack and returns its stored bytes (format.md 6.7.5,
    /// step 5).
    pub async fn read_object(
        &self,
        pack: &Pack,
        id: &ObjectId,
    ) -> Result<Vec<u8>, ObjectReadError> {
        pack.read_object(&self.target, id, &self.keys).await
    }

    /// The vault config that the reader uses.
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }
}

/// Reads both config files and returns the valid one with the highest sequence.
async fn choose_config<T: Target>(
    target: &T,
    writer: &WriterKey,
) -> Result<VaultConfig, VaultError> {
    let mut valid: Vec<(VaultConfig, Vec<u8>)> = Vec::new();
    for path in [CONFIG_A, CONFIG_B] {
        let file = match target.read(path).await {
            Ok(file) => file,
            Err(TargetError::NotFound) => continue,
            Err(e) => return Err(e.into()),
        };
        if let Some(entry) = check_config_file(&file, writer)? {
            valid.push(entry);
        }
    }
    let mut best: Option<(VaultConfig, Vec<u8>)> = None;
    for (config, bytes) in valid {
        best = match best {
            None => Some((config, bytes)),
            Some((best_config, best_bytes)) => {
                if config.sequence > best_config.sequence {
                    Some((config, bytes))
                } else if config.sequence == best_config.sequence && bytes != best_bytes {
                    return Err(VaultError::ChangedConfig);
                } else {
                    Some((best_config, best_bytes))
                }
            }
        };
    }
    best.map(|(config, _)| config)
        .ok_or(VaultError::NoValidConfig)
}

/// Checks one config file. A file that is too large, whose MAC is not correct,
/// or that does not decode is ignored (`None`). A file that is authentic but
/// newer or uses an unknown algorithm stops the reader (format.md 7.2.4).
fn check_config_file(
    file: &[u8],
    writer: &WriterKey,
) -> Result<Option<(VaultConfig, Vec<u8>)>, VaultError> {
    let Ok((map, mac)) = split_config_file(file) else {
        return Ok(None);
    };
    if !verify_config_mac(&writer.config_mac_key(), map, &mac) {
        return Ok(None);
    }
    match VaultConfig::decode(map) {
        Ok(config) => Ok(Some((config, file.to_vec()))),
        Err(ObjectError::NewerFormat(v)) => Err(VaultError::NewerFormat(v)),
        Err(ObjectError::UnknownAlgorithm) => Err(VaultError::UnknownAlgorithm),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_target::MemoryTarget;
    use crate::test_util::block_on;
    use alloc::string::ToString;
    use alloc::vec;
    use nilperit_crypto::config_mac;
    use nilperit_format::pack::{ENCRYPTION_XCHACHA20_POLY1305, HASH_BLAKE3};
    use nilperit_format::{ChunkingProfile, VaultEssentials, VaultId, join_config_file};

    const SEED: [u8; 32] = [7; 32];

    fn seed() -> RootSeed {
        RootSeed::from_bytes(SEED)
    }

    fn config(seed: &RootSeed, sequence: u64, vault_id: u8) -> VaultConfig {
        VaultConfig {
            essentials: VaultEssentials {
                format_version: 0,
                vault_id: VaultId::from_bytes([vault_id; 16]),
                encryption: ENCRYPTION_XCHACHA20_POLY1305.to_string(),
                hash: HASH_BLAKE3.to_string(),
                key_encapsulation: KEM_NAME.to_string(),
                read_public_key: seed.read_key().public_key().to_bytes().to_vec(),
            },
            sequence,
            chunking_profiles: vec![ChunkingProfile {
                id: 1,
                algorithm: "fastcdc-2020".to_string(),
                min_size: 65536,
                avg_size: 262_144,
                max_size: 1_048_576,
            }],
        }
    }

    fn file(config: &VaultConfig) -> Vec<u8> {
        file_with_key(config, &seed())
    }

    fn file_with_key(config: &VaultConfig, seed: &RootSeed) -> Vec<u8> {
        let map = config.encode().unwrap();
        let mac = config_mac(&seed.writer_key().config_mac_key(), &map);
        join_config_file(&map, &mac).unwrap()
    }

    fn target(a: Option<Vec<u8>>, b: Option<Vec<u8>>) -> MemoryTarget {
        let mut target = MemoryTarget::new();
        if let Some(a) = a {
            target.insert(CONFIG_A, a);
        }
        if let Some(b) = b {
            target.insert(CONFIG_B, b);
        }
        target
    }

    fn open(target: MemoryTarget) -> Result<Vault<MemoryTarget>, VaultError> {
        block_on(Vault::open(target, &seed()))
    }

    #[test]
    fn opens_a_vault_with_two_equal_copies() {
        let file = file(&config(&seed(), 1, 1));
        let vault = open(target(Some(file.clone()), Some(file))).unwrap();
        assert_eq!(vault.config().sequence, 1);
        assert_eq!(vault.config().chunking_profiles.len(), 1);
    }

    #[test]
    fn uses_the_copy_with_the_highest_sequence() {
        let old = file(&config(&seed(), 1, 1));
        let new = file(&config(&seed(), 2, 1));
        // After a crash, either copy can be the newer one.
        assert_eq!(
            open(target(Some(old.clone()), Some(new.clone())))
                .unwrap()
                .config()
                .sequence,
            2
        );
        assert_eq!(
            open(target(Some(new), Some(old)))
                .unwrap()
                .config()
                .sequence,
            2
        );
    }

    #[test]
    fn ignores_a_copy_that_is_missing() {
        let file = file(&config(&seed(), 1, 1));
        assert!(open(target(None, Some(file.clone()))).is_ok());
        assert!(open(target(Some(file), None)).is_ok());
    }

    #[test]
    fn ignores_a_copy_whose_mac_is_not_correct() {
        let good = file(&config(&seed(), 1, 1));
        let mut bad = file(&config(&seed(), 9, 1));
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let vault = open(target(Some(bad), Some(good))).unwrap();
        assert_eq!(vault.config().sequence, 1);
    }

    #[test]
    fn ignores_a_copy_that_another_key_authenticated() {
        let other = RootSeed::from_bytes([8; 32]);
        let foreign = file_with_key(&config(&other, 9, 1), &other);
        let good = file(&config(&seed(), 1, 1));
        let vault = open(target(Some(foreign), Some(good))).unwrap();
        assert_eq!(vault.config().sequence, 1);
    }

    #[test]
    fn ignores_a_copy_that_is_damaged_or_too_short() {
        let good = file(&config(&seed(), 1, 1));
        let vault = open(target(Some(vec![1, 2, 3]), Some(good.clone()))).unwrap();
        assert_eq!(vault.config().sequence, 1);
        let huge = vec![0; 2 * 1024 * 1024];
        assert!(open(target(Some(huge), Some(good))).is_ok());
    }

    #[test]
    fn stops_when_no_copy_is_valid() {
        assert!(matches!(
            open(target(None, None)),
            Err(VaultError::NoValidConfig)
        ));
        let mut bad = file(&config(&seed(), 1, 1));
        bad[0] ^= 0xff;
        assert!(matches!(
            open(target(Some(bad), None)),
            Err(VaultError::NoValidConfig)
        ));
    }

    #[test]
    fn stops_when_two_valid_copies_with_the_same_sequence_differ() {
        let a = file(&config(&seed(), 3, 1));
        let b = file(&config(&seed(), 3, 2));
        assert!(matches!(
            open(target(Some(a), Some(b))),
            Err(VaultError::ChangedConfig)
        ));
    }

    #[test]
    fn stops_when_the_read_public_key_is_not_the_one_of_the_phrase() {
        let other = RootSeed::from_bytes([8; 32]);
        // The MAC is right, but the config names the read key of another seed.
        let changed = file(&config(&other, 1, 1));
        assert!(matches!(
            open(target(Some(changed.clone()), Some(changed))),
            Err(VaultError::ChangedConfig)
        ));
    }

    #[test]
    fn stops_on_a_newer_format_version() {
        let mut newer = config(&seed(), 1, 1);
        newer.essentials.format_version = 1;
        let file = file(&newer);
        // The newer copy is authentic, so the reader stops, even though the other
        // copy is valid.
        let old = self::file(&config(&seed(), 1, 1));
        assert!(matches!(
            open(target(Some(old), Some(file))),
            Err(VaultError::NewerFormat(1))
        ));
    }

    #[test]
    fn stops_on_an_unknown_algorithm() {
        let mut unknown = config(&seed(), 1, 1);
        unknown.essentials.hash = "sha-256".to_string();
        assert!(matches!(
            open(target(Some(file(&unknown)), None)),
            Err(VaultError::UnknownAlgorithm)
        ));
        let mut kem = config(&seed(), 1, 1);
        kem.essentials.key_encapsulation = "other-kem".to_string();
        assert!(matches!(
            open(target(Some(file(&kem)), None)),
            Err(VaultError::UnknownAlgorithm)
        ));
    }

    #[test]
    fn a_failing_target_is_an_error_not_a_missing_file() {
        struct Failing;
        impl Target for Failing {
            async fn len(&self, _: &str) -> Result<u64, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
            async fn read_range(
                &self,
                _: &str,
                _: core::ops::Range<u64>,
            ) -> Result<Vec<u8>, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
            async fn read(&self, _: &str) -> Result<Vec<u8>, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
            async fn list(&self, _: &str) -> Result<Vec<alloc::string::String>, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
        }
        assert!(matches!(
            block_on(Vault::open(Failing, &seed())),
            Err(VaultError::Target(TargetError::Other(_)))
        ));
    }
}
