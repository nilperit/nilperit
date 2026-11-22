//! What the program takes from its surroundings.
//!
//! The values are read once in `main` and passed in, so that the tests can give their own
//! and never touch the environment of the process.

use crate::error::CliError;
use nilperit_format::VaultId;
use std::ffi::OsString;
use std::path::PathBuf;

/// The surroundings of a run.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    /// The folder for the configuration of the user. The program makes a folder
    /// `nilperit` in it.
    pub config_dir: Option<PathBuf>,
    /// The credential file that the person named in `NILPERIT_CREDENTIAL`.
    pub credential: Option<PathBuf>,
}

impl Environment {
    /// Reads the surroundings of the process: `XDG_CONFIG_HOME`, or `.config` in `HOME`,
    /// or `APPDATA` (Windows), and `NILPERIT_CREDENTIAL`.
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
        let absolute = |value: OsString| Some(PathBuf::from(value)).filter(|p| p.is_absolute());
        let config_dir = var("XDG_CONFIG_HOME")
            .and_then(absolute)
            .or_else(|| {
                var("HOME")
                    .and_then(absolute)
                    .map(|home| home.join(".config"))
            })
            .or_else(|| var("APPDATA").and_then(absolute));
        Self {
            config_dir,
            credential: var("NILPERIT_CREDENTIAL").map(PathBuf::from),
        }
    }

    /// The credential file for a vault, when the person named none: a file in the
    /// configuration folder, named after the vault.
    pub fn default_credential_path(&self, vault_id: &VaultId) -> Result<PathBuf, CliError> {
        let folder = self.config_dir.as_ref().ok_or(CliError::NoConfigFolder)?;
        Ok(folder
            .join("nilperit")
            .join(format!("{vault_id}.credential")))
    }
}
