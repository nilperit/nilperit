//! What the program takes from its surroundings.
//!
//! The values are read once in `main` and passed in, so that the tests can give their own
//! and never touch the environment of the process.

use crate::error::CliError;
use crate::progress::ProgressMode;
use nilperit_format::VaultId;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

/// The surroundings of a run.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    /// The folder for the configuration of the user. The program makes a folder
    /// `nilperit` in it.
    pub config_dir: Option<PathBuf>,
    /// The credential file that the person named in `NILPERIT_CREDENTIAL`.
    pub credential: Option<PathBuf>,
    /// Whether the input is a terminal. A command that needs the recovery phrase then
    /// asks for it, without showing what is typed. Otherwise it reads it from the input.
    pub interactive: bool,
    /// How a command that takes time shows its progress, on the error output.
    pub progress: ProgressMode,
}

/// The time between two lines of progress when the error output is not a terminal.
const HEARTBEAT: Duration = Duration::from_secs(30);

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
            interactive: std::io::stdin().is_terminal(),
            progress: progress_mode(
                std::io::stderr().is_terminal(),
                var("TERM").is_some_and(|term| term == "dumb"),
            ),
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

/// A line that is redrawn needs a terminal that does it. Otherwise a line now and then
/// shows that the run is alive.
fn progress_mode(stderr_is_terminal: bool, dumb_terminal: bool) -> ProgressMode {
    if stderr_is_terminal && !dumb_terminal {
        ProgressMode::Live
    } else {
        ProgressMode::Heartbeat(HEARTBEAT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_gets_a_live_line_and_everything_else_gets_a_heartbeat() {
        assert_eq!(progress_mode(true, false), ProgressMode::Live);
        assert_eq!(
            progress_mode(true, true),
            ProgressMode::Heartbeat(HEARTBEAT)
        );
        assert_eq!(
            progress_mode(false, false),
            ProgressMode::Heartbeat(HEARTBEAT)
        );
    }
}
