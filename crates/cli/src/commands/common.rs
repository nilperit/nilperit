//! What more than one command needs.

use crate::credential::load_credential;
use crate::environment::Environment;
use crate::error::CliError;
use crate::exec::block_on;
use nilperit_format::{VaultConfig, VaultId, split_config_file};
use nilperit_reader::Target;
use nilperit_reader::layout::{CONFIG_A, CONFIG_B};
use nilperit_target_fs::FsTarget;
use nilperit_writer::Credential;
use std::path::PathBuf;
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
