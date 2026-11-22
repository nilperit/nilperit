//! Reading a file with a secret in it.
//!
//! A secret that other users can read is refused, as `ssh` refuses a private key: the
//! person is told to make the file private, and the program does not read it before.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;

/// A file with a secret cannot be read.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretFileError {
    /// It is not a file.
    NotAFile,
    /// Other users can read it (on Unix).
    Permissions,
    /// It is larger than the limit.
    TooLarge,
    /// It is not text.
    NotText,
    /// The file system failed.
    Io(io::ErrorKind),
}

impl From<io::Error> for SecretFileError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Reads a text file of fewer than `max` bytes. The permissions are checked on the open
/// file, so the file cannot change between the check and the read. The text is wiped
/// when it is dropped.
pub fn read_private_text(path: &Path, max: u64) -> Result<Zeroizing<String>, SecretFileError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(SecretFileError::NotAFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(SecretFileError::Permissions);
        }
    }
    let mut text = Zeroizing::new(String::new());
    match file.take(max).read_to_string(&mut text) {
        Ok(size) if (size as u64) < max => Ok(text),
        Ok(_) => Err(SecretFileError::TooLarge),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => Err(SecretFileError::NotText),
        Err(e) => Err(e.into()),
    }
}
