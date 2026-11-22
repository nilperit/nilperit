//! The part of a target that only a writer needs.
//!
//! The reader's [`Target`] only reads, so that a reader cannot change a vault
//! (ADR 0014). A writer needs one more operation.

use nilperit_reader::layout::LOCK_PATH;
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

    /// Writes a whole file only when no file exists under `path`, in one atomic
    /// step. It returns `true` when it wrote the file and `false` when a file
    /// existed. The writer lock needs this (format.md 8.6.2).
    async fn put_new(&self, path: &str, bytes: &[u8]) -> Result<bool, TargetError>;

    /// Deletes the writer lock file (format.md 8.6.4). It is not an error when the
    /// file does not exist.
    ///
    /// This is the only delete in the trait, and it can name only the lock file. A
    /// writer cannot delete a pack or a snapshot header through the trait by
    /// mistake. Removing stored data is retention (ADR 0010) and will need its own
    /// operation. This method does not check whose lock it deletes:
    /// `WriterLock::release` checks, and the takeover of a stale lock (format.md
    /// 8.6.2) deletes the lock of another holder on purpose.
    async fn remove_lock(&self) -> Result<(), TargetError>;
}

impl<T: WriteTarget + ?Sized> WriteTarget for &T {
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
        (**self).put(path, bytes).await
    }

    async fn put_new(&self, path: &str, bytes: &[u8]) -> Result<bool, TargetError> {
        (**self).put_new(path, bytes).await
    }

    async fn remove_lock(&self) -> Result<(), TargetError> {
        (**self).remove_lock().await
    }
}

impl WriteTarget for MemoryTarget {
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
        self.insert(path, bytes.to_vec());
        Ok(())
    }

    async fn put_new(&self, path: &str, bytes: &[u8]) -> Result<bool, TargetError> {
        if self.contains(path) {
            return Ok(false);
        }
        self.insert(path, bytes.to_vec());
        Ok(true)
    }

    async fn remove_lock(&self) -> Result<(), TargetError> {
        self.remove(LOCK_PATH);
        Ok(())
    }
}
