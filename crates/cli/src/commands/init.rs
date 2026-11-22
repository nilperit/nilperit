//! `nilperit init`: make a new vault.

use crate::cli::InitArgs;
use crate::credential::{CredentialError, write_credential};
use crate::environment::Environment;
use crate::error::CliError;
use crate::exec::block_on;
use nilperit_crypto::{CryptoRng, RootSeed};
use nilperit_target_fs::FsTarget;
use nilperit_writer::{check_empty, create_vault};
use std::io::Write;
use std::path::PathBuf;

/// Makes a vault in the folder, shows the recovery phrase once, and saves the node
/// credential of this machine.
///
/// The order protects the person. Everything that can be checked is checked first, so
/// that the phrase is never shown for a vault that is not made. The phrase is shown before
/// the vault is made, so that a vault never exists without the phrase having been shown.
/// The root seed and the phrase are never written to disk.
pub fn run<R: CryptoRng>(
    args: &InitArgs,
    env: &Environment,
    out: &mut dyn Write,
    rng: &mut R,
) -> Result<(), CliError> {
    // The credential file: the person named it, or it is in the configuration folder and
    // its name depends on the vault, which is not made yet.
    let named = args.credential.clone().or_else(|| env.credential.clone());
    if let Some(path) = &named {
        if path.symlink_metadata().is_ok() {
            return Err(CliError::CredentialExists);
        }
    } else if env.config_dir.is_none() {
        return Err(CliError::NoConfigFolder);
    }

    let target = FsTarget::new(&args.vault);
    block_on(check_empty(&target))?;

    let seed = RootSeed::generate(rng);
    show_phrase(out, &seed)?;
    let vault_id = block_on(create_vault(&target, &seed, rng))?;

    // The vault exists. A failure from here on does not lose the vault, and the phrase
    // makes the credential again.
    let credential_path: PathBuf = match named {
        Some(path) => path,
        None => env
            .default_credential_path(&vault_id)
            .map_err(|e| CliError::VaultMadeWithoutCredential(Box::new(e)))?,
    };
    write_credential(&credential_path, &vault_id, &seed).map_err(|e| {
        let e = match e {
            CredentialError::Exists => CliError::CredentialExists,
            other => CliError::Credential(other),
        };
        CliError::VaultMadeWithoutCredential(Box::new(e))
    })?;

    writeln!(out)?;
    writeln!(out, "Vault ID: {vault_id}")?;
    writeln!(
        out,
        "Credential of this machine: {} (only you can read it)",
        credential_path.display()
    )?;
    writeln!(
        out,
        "The credential lets this machine add data to the vault. It cannot read the vault."
    )?;
    out.flush()?;
    Ok(())
}

/// Shows the 24 words of the recovery phrase, numbered, with what the person must know.
fn show_phrase(out: &mut dyn Write, seed: &RootSeed) -> Result<(), CliError> {
    let phrase = seed.to_phrase();
    writeln!(out, "Recovery phrase of the new vault:")?;
    writeln!(out)?;
    let words: Vec<&str> = phrase.split(' ').collect();
    for row in words.chunks(4).enumerate() {
        let (index, row) = row;
        for (column, word) in row.iter().enumerate() {
            write!(out, "  {:>2} {:<10}", index * 4 + column + 1, word)?;
        }
        writeln!(out)?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Write these 24 words down and keep them safe. They are the only way to read the \
         vault if you lose this machine. They are shown once and saved nowhere."
    )?;
    out.flush()?;
    Ok(())
}
