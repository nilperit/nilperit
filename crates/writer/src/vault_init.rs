//! Making a new vault (format.md 7.2).

use crate::chunking::default_profiles;
use crate::target::WriteTarget;
use nilperit_crypto::seal::KEM_NAME;
use nilperit_crypto::{CryptoRng, RootSeed, config_mac};
use nilperit_format::pack::{ENCRYPTION_XCHACHA20_POLY1305, FORMAT_VERSION, HASH_BLAKE3};
use nilperit_format::{ObjectError, VaultConfig, VaultEssentials, VaultId, join_config_file};
use nilperit_reader::TargetError;
use nilperit_reader::layout::{CONFIG_A, CONFIG_B, PACKS_DIR, SNAPSHOTS_DIR};
use std::fmt;

/// A vault could not be made.
#[derive(Debug)]
pub enum InitError {
    /// The target already has a vault config, packs or snapshot headers. NilPerit
    /// never writes a new vault over data (ADR 0010).
    NotEmpty,
    /// The target failed.
    Target(TargetError),
    /// The vault config is not valid.
    Config(ObjectError),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEmpty => f.write_str("the target already holds a vault or its data"),
            Self::Target(e) => e.fmt(f),
            Self::Config(e) => write!(f, "the vault config is not valid: {e}"),
        }
    }
}

impl std::error::Error for InitError {}

impl From<TargetError> for InitError {
    fn from(e: TargetError) -> Self {
        Self::Target(e)
    }
}

/// Makes a new vault on a target and returns its vault ID.
///
/// It refuses a target that has a config file, a pack or a snapshot header. It
/// writes `config-a` and then `config-b` (format.md 7.2.5). The vault config has
/// sequence 1, the public part of the read key of `seed`, and the default chunking
/// profiles.
pub async fn create_vault<T: WriteTarget, R: CryptoRng>(
    target: &T,
    seed: &RootSeed,
    rng: &mut R,
) -> Result<VaultId, InitError> {
    for path in [CONFIG_A, CONFIG_B] {
        match target.len(path).await {
            Ok(_) => return Err(InitError::NotEmpty),
            Err(TargetError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
    }
    for dir in [PACKS_DIR, SNAPSHOTS_DIR] {
        if !target.list(dir).await?.is_empty() {
            return Err(InitError::NotEmpty);
        }
    }

    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    let vault_id = VaultId::from_bytes(id);
    let config = VaultConfig {
        essentials: VaultEssentials {
            format_version: FORMAT_VERSION,
            vault_id,
            encryption: ENCRYPTION_XCHACHA20_POLY1305.into(),
            hash: HASH_BLAKE3.into(),
            key_encapsulation: KEM_NAME.into(),
            read_public_key: seed.read_key().public_key().to_bytes().to_vec(),
        },
        sequence: 1,
        chunking_profiles: default_profiles(),
    };
    let map = config.encode().map_err(InitError::Config)?;
    let mac = config_mac(&seed.writer_key().config_mac_key(), &map);
    let file = join_config_file(&map, &mac).map_err(InitError::Config)?;
    target.put(CONFIG_A, &file).await?;
    target.put(CONFIG_B, &file).await?;
    Ok(vault_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{Flaky, TestRng, block_on};
    use nilperit_format::PackName;
    use nilperit_reader::layout::pack_path;
    use nilperit_reader::{MemoryTarget, Target, Vault, VaultError};

    fn seed() -> RootSeed {
        RootSeed::from_bytes([7; 32])
    }

    #[test]
    fn makes_a_vault_that_the_reader_opens() {
        let target = MemoryTarget::new();
        let id = block_on(create_vault(&target, &seed(), &mut TestRng::new(1))).unwrap();
        let vault = block_on(Vault::open(&target, &seed())).unwrap();
        let config = vault.config();
        assert_eq!(config.essentials.vault_id, id);
        assert_eq!(config.sequence, 1);
        assert_eq!(config.essentials.format_version, FORMAT_VERSION);
        assert_eq!(config.chunking_profiles, default_profiles());
        // Both copies are the same file.
        assert_eq!(
            block_on(target.read(CONFIG_A)).unwrap(),
            block_on(target.read(CONFIG_B)).unwrap()
        );
    }

    #[test]
    fn another_recovery_phrase_does_not_open_the_vault() {
        let target = MemoryTarget::new();
        block_on(create_vault(&target, &seed(), &mut TestRng::new(1))).unwrap();
        let other = RootSeed::from_bytes([8; 32]);
        assert!(matches!(
            block_on(Vault::open(&target, &other)),
            Err(VaultError::NoValidConfig)
        ));
    }

    #[test]
    fn each_vault_has_its_own_id() {
        let a = block_on(create_vault(
            &MemoryTarget::new(),
            &seed(),
            &mut TestRng::new(1),
        ))
        .unwrap();
        let b = block_on(create_vault(
            &MemoryTarget::new(),
            &seed(),
            &mut TestRng::new(2),
        ))
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn never_writes_over_a_vault_or_its_data() {
        // A config file, or only the second copy.
        for path in [CONFIG_A, CONFIG_B] {
            let target = MemoryTarget::new();
            target.insert(path, vec![1, 2, 3]);
            let result = block_on(create_vault(&target, &seed(), &mut TestRng::new(1)));
            assert!(matches!(result, Err(InitError::NotEmpty)), "{path}");
            assert_eq!(block_on(target.read(path)).unwrap(), [1, 2, 3]);
        }
        // A pack, or a snapshot header.
        let pack = pack_path(&PackName::from_bytes([0xab; 32]));
        for path in [pack.as_str(), "snapshots/00112233445566778899aabbccddeeff"] {
            let target = MemoryTarget::new();
            target.insert(path, vec![1]);
            let result = block_on(create_vault(&target, &seed(), &mut TestRng::new(1)));
            assert!(matches!(result, Err(InitError::NotEmpty)), "{path}");
            assert!(block_on(target.len(CONFIG_A)).is_err());
        }
    }

    #[test]
    fn writes_config_a_before_config_b() {
        let target = MemoryTarget::new();
        let flaky = Flaky::new(&target, 2);
        block_on(create_vault(&flaky, &seed(), &mut TestRng::new(1))).unwrap();
        assert_eq!(*flaky.log.borrow(), [CONFIG_A, CONFIG_B]);
    }

    #[test]
    fn a_crash_between_the_copies_leaves_a_vault_that_opens() {
        // Format.md 7.2.5: after a crash, one copy can be missing.
        let target = MemoryTarget::new();
        let flaky = Flaky::new(&target, 1);
        let result = block_on(create_vault(&flaky, &seed(), &mut TestRng::new(1)));
        assert!(matches!(result, Err(InitError::Target(_))));
        assert!(block_on(target.len(CONFIG_B)).is_err());
        assert!(block_on(Vault::open(&target, &seed())).is_ok());
    }

    #[test]
    fn a_failure_at_the_first_write_leaves_nothing() {
        let target = MemoryTarget::new();
        let flaky = Flaky::new(&target, 0);
        assert!(block_on(create_vault(&flaky, &seed(), &mut TestRng::new(1))).is_err());
        assert!(block_on(target.len(CONFIG_A)).is_err());
    }
}
