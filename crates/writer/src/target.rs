//! The part of a target that only a writer needs.
//!
//! The reader's [`Target`] only reads, so that a reader cannot change a vault
//! (ADR 0014). A writer needs one more operation.

use nilperit_reader::{MemoryTarget, Target, TargetError};

/// A target that a writer can write to.
#[allow(async_fn_in_trait)]
pub trait WriteTarget: Target {
    /// Writes a whole file.
    ///
    /// When it returns `Ok`, the file is complete under `path` and has reached
    /// durable storage. A crash while it runs leaves no file under `path`, or the
    /// whole file. It can leave a temporary file under another name, which is an
    /// orphan (format.md 8.5). That name MUST NOT be a name that a reader
    /// accepts as a pack or as a snapshot header.
    ///
    /// A local file system does this as format.md 8.1 says: write a file with a
    /// temporary name, sync it, and rename it. A target whose upload is atomic
    /// (for example object storage) can do it in one step. When a file exists
    /// under `path`, it is replaced.
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError>;
}

impl<T: WriteTarget + ?Sized> WriteTarget for &T {
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
        (**self).put(path, bytes).await
    }
}

impl WriteTarget for MemoryTarget {
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
        self.insert(path, bytes.to_vec());
        Ok(())
    }
}
