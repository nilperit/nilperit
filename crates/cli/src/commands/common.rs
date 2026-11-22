//! What more than one command needs.

use crate::credential::load_credential;
use crate::environment::Environment;
use crate::error::CliError;
use crate::exec::block_on;
use crate::progress::{Reporter, Status};
use nilperit_crypto::RootSeed;
use nilperit_format::{SourceId, VaultConfig, VaultId, split_config_file};
use nilperit_reader::layout::{CONFIG_A, CONFIG_B};
use nilperit_reader::{PackIndex, Snapshots, Target, Vault, VaultError};
use nilperit_target_fs::FsTarget;
use nilperit_writer::Credential;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The time of this machine in milliseconds since 1970.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// The ID of the vault in a folder, from its vault config.
///
/// The config is not authenticated here: this needs no key. The ID only chooses which
/// credential file to read. Opening the vault checks the config with the keys in the
/// credential, so a changed config does no harm.
pub fn read_vault_id(target: &FsTarget) -> Result<VaultId, CliError> {
    for path in [CONFIG_A, CONFIG_B] {
        let Ok(file) = block_on(target.read(path)) else {
            continue;
        };
        let Ok((map, _)) = split_config_file(&file) else {
            continue;
        };
        if let Ok(config) = VaultConfig::decode(map) {
            return Ok(config.essentials.vault_id);
        }
    }
    Err(CliError::NoVault)
}

/// Loads the node credential of a vault: the file that the person named, or the file
/// that `init` made for this vault. It checks that the credential is for this vault.
pub fn load_node_credential(
    named: Option<PathBuf>,
    env: &Environment,
    vault_id: &VaultId,
) -> Result<Credential, CliError> {
    let (path, was_named) = match named.or_else(|| env.credential.clone()) {
        Some(path) => (path, true),
        None => (env.default_credential_path(vault_id)?, false),
    };
    let shown = path.display().to_string();
    let (credential_vault, credential) = match load_credential(&path) {
        Ok(loaded) => loaded,
        Err(crate::credential::CredentialError::Io(std::io::ErrorKind::NotFound)) if !was_named => {
            return Err(CliError::NoCredential(shown));
        }
        Err(e) => return Err(CliError::CredentialFile(shown, e)),
    };
    if credential_vault != *vault_id {
        return Err(CliError::WrongCredential);
    }
    Ok(credential)
}

/// A vault that is open for reading: with the keys of the recovery phrase, the index of
/// its packs and its snapshot headers.
pub struct OpenVault {
    pub seed: RootSeed,
    pub vault: Vault<FsTarget>,
    pub index: PackIndex,
    pub snapshots: Snapshots,
}

/// Opens the vault with the keys of the recovery phrase, and reads the index of the packs and
/// the snapshot headers. A pack or a header that cannot be used does not stop this: the
/// caller finds them in `index.skipped()` and `snapshots.skipped()` (damage stays local).
///
/// The caller gets the phrase first, and then starts the reporter: the person must not be
/// asked for a phrase while a line of progress is on the screen. A large vault takes time
/// here, so the reporter tells the steps.
pub fn open_vault(
    folder: &Path,
    seed: RootSeed,
    reporter: &Reporter<'_, '_>,
) -> Result<OpenVault, CliError> {
    reporter.report(Status::step("Opening the vault"));
    let vault = block_on(Vault::open(FsTarget::new(folder), &seed)).map_err(CliError::Vault)?;
    reporter.report(Status::step("Reading the packs"));
    let index = block_on(vault.scan_packs()).map_err(|e| CliError::Vault(VaultError::Target(e)))?;
    reporter.report(Status::step("Reading the snapshots"));
    let snapshots =
        block_on(vault.read_snapshots()).map_err(|e| CliError::Vault(VaultError::Target(e)))?;
    Ok(OpenVault {
        seed,
        vault,
        index,
        snapshots,
    })
}

/// A source ID as the list of sources shows it: 32 hexadecimal characters.
pub fn parse_source_id(text: &str) -> Result<SourceId, CliError> {
    if text.len() != 32 || !text.is_ascii() {
        return Err(CliError::BadSourceId);
    }
    let mut bytes = [0u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| CliError::BadSourceId)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| CliError::BadSourceId)?;
    }
    Ok(SourceId::from_bytes(bytes))
}
