//! The errors of the program. A message tells what went wrong. It never has keys, the
//! recovery phrase or content.

use crate::credential::CredentialError;
use nilperit_writer::{InitError, LockError, SyncError};
use std::fmt;
use std::io;

/// Something that stops a command.
#[derive(Debug)]
pub enum CliError {
    /// A vault cannot be made.
    Init(InitError),
    /// The credential file cannot be written or read.
    Credential(CredentialError),
    /// There is no configuration folder, and no file was named.
    NoConfigFolder,
    /// The file for the credential exists. The program never writes over it.
    CredentialExists,
    /// The program cannot write its output.
    Output(io::ErrorKind),
    /// There is no vault config in the folder, or it cannot be read.
    NoVault,
    /// No credential file for the vault. The text says where the program looked.
    NoCredential(String),
    /// The credential file cannot be used.
    CredentialFile(String, CredentialError),
    /// The credential is the credential of another vault.
    WrongCredential,
    /// The name of the source is empty.
    EmptyName,
    /// The folder to back up cannot be used. Only the kind of the error is shown.
    Folder(io::ErrorKind),
    /// Another run has the writer lock. The value is the age of its last heartbeat, in
    /// seconds, and the number of seconds after which the lock is stale.
    LockHeld(u64, u64),
    /// The writer lock cannot be taken.
    Lock(LockError),
    /// The run failed.
    Sync(SyncError),
    /// The vault was made, and the credential could not be saved. The text says what
    /// the person can do.
    VaultMadeWithoutCredential(Box<CliError>),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(e) => e.fmt(f),
            Self::Credential(e) => e.fmt(f),
            Self::NoVault => f.write_str("there is no vault in that folder"),
            Self::NoCredential(looked) => write!(
                f,
                "no credential for this vault ({looked}): run `nilperit init` on this machine or name a file with --credential"
            ),
            Self::CredentialFile(path, why) => write!(f, "{why} ({path})"),
            Self::WrongCredential => f.write_str("the credential is the credential of another vault"),
            Self::EmptyName => f.write_str("the name of the source is empty"),
            Self::Folder(kind) => write!(f, "the folder to back up cannot be used ({kind:?})"),
            Self::LockHeld(age, stale) => write!(
                f,
                "another run has the writer lock of this vault (its last sign of life was {age} s ago). \
                 If no run is active, the lock can be taken over after {stale} s of silence"
            ),
            Self::Lock(e) => e.fmt(f),
            Self::Sync(e) => e.fmt(f),
            Self::NoConfigFolder => f.write_str(
                "there is no configuration folder for the credential: name a file with --credential",
            ),
            Self::CredentialExists => {
                f.write_str("the credential file exists already: it is never written over")
            }
            Self::Output(kind) => write!(f, "cannot write the output ({kind:?})"),
            Self::VaultMadeWithoutCredential(why) => write!(
                f,
                "the vault was made and the recovery phrase was shown, but the credential was not saved: {why}"
            ),
        }
    }
}

impl std::error::Error for CliError {}

impl From<InitError> for CliError {
    fn from(e: InitError) -> Self {
        Self::Init(e)
    }
}

impl From<CredentialError> for CliError {
    fn from(e: CredentialError) -> Self {
        Self::Credential(e)
    }
}

impl From<SyncError> for CliError {
    fn from(e: SyncError) -> Self {
        Self::Sync(e)
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        Self::Output(e.kind())
    }
}
