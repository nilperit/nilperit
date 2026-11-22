//! The errors of the program. A message tells what went wrong. It never has keys, the
//! recovery phrase or content.

use crate::credential::CredentialError;
use nilperit_writer::InitError;
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
    /// The vault was made, and the credential could not be saved. The text says what
    /// the person can do.
    VaultMadeWithoutCredential(Box<CliError>),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init(e) => e.fmt(f),
            Self::Credential(e) => e.fmt(f),
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

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        Self::Output(e.kind())
    }
}
