//! The target trait: the only way the reader touches a vault.
//!
//! The trait is async and needs no runtime, so that native code can use the file
//! system and the browser can use `fetch`. It only reads. The trait that writes
//! lives in the writer crate, so a reader cannot change a vault (ADR 0014).
//!
//! The reader builds every path with the functions in [`crate::layout`]. A path
//! is relative to the root of the vault, uses `/` as separator, and has no `.` or
//! `..` parts. An implementation MUST still reject a path that does not follow
//! this rule.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

/// An error from a target implementation.
#[derive(Debug)]
pub enum TargetError {
    /// The file does not exist.
    NotFound,
    /// The range is not inside the file.
    OutOfRange,
    /// Any other failure. The text MUST NOT contain keys or data of the owner.
    Other(String),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("file not found"),
            Self::OutOfRange => f.write_str("range outside the file"),
            Self::Other(text) => write!(f, "target error: {text}"),
        }
    }
}

impl core::error::Error for TargetError {}

/// Read access to the files of one vault.
///
/// The futures are not required to be `Send`: the browser cannot give that
/// guarantee. A native caller that needs `Send` futures runs the reader on a
/// single thread.
#[allow(async_fn_in_trait)]
pub trait Target {
    /// Returns the size of a file in bytes.
    async fn len(&self, path: &str) -> Result<u64, TargetError>;

    /// Reads the bytes in `range` of a file. It fails with
    /// [`TargetError::OutOfRange`] when the range is not inside the file.
    async fn read_range(&self, path: &str, range: Range<u64>) -> Result<Vec<u8>, TargetError>;

    /// Reads a whole file.
    async fn read(&self, path: &str) -> Result<Vec<u8>, TargetError>;

    /// Lists the paths of all files below a directory, at any depth, in any order.
    /// A directory that does not exist has no files.
    async fn list(&self, dir: &str) -> Result<Vec<String>, TargetError>;
}

/// A shared reference to a target is a target. A reader and a writer can then use
/// the same target.
impl<T: Target + ?Sized> Target for &T {
    async fn len(&self, path: &str) -> Result<u64, TargetError> {
        (**self).len(path).await
    }

    async fn read_range(&self, path: &str, range: Range<u64>) -> Result<Vec<u8>, TargetError> {
        (**self).read_range(path, range).await
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>, TargetError> {
        (**self).read(path).await
    }

    async fn list(&self, dir: &str) -> Result<Vec<String>, TargetError> {
        (**self).list(dir).await
    }
}
