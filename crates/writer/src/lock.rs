//! The writer lock (format.md 8.6).
//!
//! The lock protects against two runs by mistake. It is not a strong lock
//! (format.md 8.6.5). The caller gives the time, so that the code needs no clock
//! and tests control it.

use crate::target::WriteTarget;
use nilperit_format::{LockFile, NodeId, ObjectError};
use nilperit_reader::TargetError;
use nilperit_reader::layout::LOCK_PATH;
use std::fmt;

/// The lock could not be taken, or it was lost.
#[derive(Debug)]
pub enum LockError {
    /// Another node holds the lock, and its heartbeat is not older than the
    /// staleness limit.
    Held {
        /// The node that holds the lock.
        node_id: NodeId,
        /// Its last heartbeat, by its own clock.
        heartbeat: i64,
    },
    /// The lock file is not a valid lock file. The node does not take the lock:
    /// the owner decides (format.md 8.6.2).
    Invalid(ObjectError),
    /// The lock is missing or names another node.
    Lost,
    /// The lock changed again and again while the node tried to take it.
    Contended,
    /// The target failed.
    Target(TargetError),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held { node_id, heartbeat } => {
                write!(
                    f,
                    "node {node_id} holds the writer lock (heartbeat {heartbeat})"
                )
            }
            Self::Invalid(e) => write!(f, "the writer lock file is not valid: {e}"),
            Self::Lost => f.write_str("the writer lock is lost"),
            Self::Contended => f.write_str("the writer lock keeps changing"),
            Self::Target(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LockError {}

impl From<TargetError> for LockError {
    fn from(e: TargetError) -> Self {
        Self::Target(e)
    }
}

/// The writer lock of a vault, held by one node.
///
/// Dropping it does not release the lock, because releasing needs the target.
/// Call [`WriterLock::release`]. A lock that is not released goes stale.
#[derive(Debug)]
pub struct WriterLock<'a, T> {
    target: &'a T,
    node_id: NodeId,
}

impl<'a, T: WriteTarget> WriterLock<'a, T> {
    /// Takes the lock (format.md 8.6.2).
    ///
    /// `now` is the time of the clock of this node, in milliseconds. A lock whose
    /// heartbeat is more than `stale_after` milliseconds older than `now` can be
    /// taken over. A heartbeat in the future is not stale.
    pub async fn acquire(
        target: &'a T,
        node_id: NodeId,
        now: i64,
        stale_after: i64,
    ) -> Result<WriterLock<'a, T>, LockError> {
        let mine = LockFile {
            node_id,
            heartbeat: now,
        }
        .encode();
        // A second try after a takeover, and a third for a lock that vanished.
        for _ in 0..3 {
            if target.put_new(LOCK_PATH, &mine).await? {
                return Ok(Self { target, node_id });
            }
            let Some(lock) = read_lock(target).await? else {
                // It was removed after our attempt. Try again.
                continue;
            };
            if now.saturating_sub(lock.heartbeat) <= stale_after {
                return Err(LockError::Held {
                    node_id: lock.node_id,
                    heartbeat: lock.heartbeat,
                });
            }
            // Stale. Delete it and create it again. When another node creates it
            // first, the next try finds a fresh lock.
            target.remove_lock().await?;
        }
        Err(LockError::Contended)
    }

    /// The target of the lock.
    pub fn target(&self) -> &'a T {
        self.target
    }

    /// The node that holds the lock.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Writes a new heartbeat (format.md 8.6.3). It reads the file first. When the
    /// file is missing or names another node, the lock is lost and nothing is
    /// written. The caller MUST stop writing to the vault.
    pub async fn refresh(&self, now: i64) -> Result<(), LockError> {
        self.check().await?;
        let lock = LockFile {
            node_id: self.node_id,
            heartbeat: now,
        };
        self.target.put(LOCK_PATH, &lock.encode()).await?;
        Ok(())
    }

    /// Releases the lock (format.md 8.6.4). It deletes the file only when the file
    /// names this node. Otherwise it leaves the file and returns `Lost`.
    pub async fn release(self) -> Result<(), LockError> {
        self.check().await?;
        self.target.remove_lock().await?;
        Ok(())
    }

    async fn check(&self) -> Result<(), LockError> {
        match read_lock(self.target).await {
            Ok(Some(lock)) if lock.node_id == self.node_id => Ok(()),
            // Missing, another node, or a file that is not valid: not ours.
            Ok(_) | Err(LockError::Invalid(_)) => Err(LockError::Lost),
            Err(e) => Err(e),
        }
    }
}

/// Reads the lock file. `None` means that there is no file.
async fn read_lock<T: WriteTarget>(target: &T) -> Result<Option<LockFile>, LockError> {
    match target.read(LOCK_PATH).await {
        Ok(bytes) => LockFile::decode(&bytes)
            .map(Some)
            .map_err(LockError::Invalid),
        Err(TargetError::NotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use nilperit_reader::{MemoryTarget, Target};
    use std::cell::Cell;
    use std::ops::Range;

    const A: NodeId = NodeId::from_bytes([0xaa; 16]);
    const B: NodeId = NodeId::from_bytes([0xbb; 16]);
    const NOW: i64 = 1_700_000_000_000;
    const STALE: i64 = 60_000;

    fn file(target: &MemoryTarget) -> LockFile {
        LockFile::decode(&block_on(target.read(LOCK_PATH)).unwrap()).unwrap()
    }

    fn take(
        target: &MemoryTarget,
        node: NodeId,
        now: i64,
    ) -> Result<WriterLock<'_, MemoryTarget>, LockError> {
        block_on(WriterLock::acquire(target, node, now, STALE))
    }

    #[test]
    fn takes_a_free_lock() {
        let target = MemoryTarget::new();
        let lock = take(&target, A, NOW).unwrap();
        assert_eq!(lock.node_id(), A);
        assert_eq!(
            file(&target),
            LockFile {
                node_id: A,
                heartbeat: NOW
            }
        );
    }

    #[test]
    fn does_not_take_a_lock_that_another_node_holds() {
        let target = MemoryTarget::new();
        let _a = take(&target, A, NOW).unwrap();
        let result = take(&target, B, NOW + 1_000);
        assert!(matches!(
            result,
            Err(LockError::Held { node_id, heartbeat }) if node_id == A && heartbeat == NOW
        ));
        // The lock is unchanged.
        assert_eq!(file(&target).node_id, A);
    }

    #[test]
    fn the_node_that_holds_the_lock_is_not_special() {
        // A second run of the same node must wait too: it can be a second process.
        let target = MemoryTarget::new();
        let _first = take(&target, A, NOW).unwrap();
        assert!(matches!(
            take(&target, A, NOW + 1),
            Err(LockError::Held { .. })
        ));
    }

    #[test]
    fn takes_over_a_stale_lock_but_not_one_at_the_limit() {
        let target = MemoryTarget::new();
        let _a = take(&target, A, NOW).unwrap();
        // At the limit, the lock is not stale yet.
        assert!(matches!(
            take(&target, B, NOW + STALE),
            Err(LockError::Held { .. })
        ));
        // One millisecond later it is.
        let b = take(&target, B, NOW + STALE + 1).unwrap();
        assert_eq!(
            file(&target),
            LockFile {
                node_id: B,
                heartbeat: NOW + STALE + 1
            }
        );
        assert_eq!(b.node_id(), B);
    }

    #[test]
    fn a_heartbeat_in_the_future_is_not_stale() {
        // The clock of the holder is ahead. The node must not take the lock.
        let target = MemoryTarget::new();
        let _a = take(&target, A, NOW + 10 * STALE).unwrap();
        assert!(matches!(take(&target, B, NOW), Err(LockError::Held { .. })));
    }

    #[test]
    fn the_old_holder_has_lost_the_lock_after_a_takeover() {
        let target = MemoryTarget::new();
        let a = take(&target, A, NOW).unwrap();
        let _b = take(&target, B, NOW + STALE + 1).unwrap();
        assert!(matches!(
            block_on(a.refresh(NOW + STALE + 2)),
            Err(LockError::Lost)
        ));
        // The refresh wrote nothing: the lock is still the lock of B.
        assert_eq!(file(&target).node_id, B);
        // Releasing does not delete the lock of another node either.
        assert!(matches!(block_on(a.release()), Err(LockError::Lost)));
        assert_eq!(file(&target).node_id, B);
    }

    #[test]
    fn refresh_writes_a_new_heartbeat() {
        let target = MemoryTarget::new();
        let a = take(&target, A, NOW).unwrap();
        block_on(a.refresh(NOW + 30_000)).unwrap();
        assert_eq!(
            file(&target),
            LockFile {
                node_id: A,
                heartbeat: NOW + 30_000
            }
        );
        // With the new heartbeat the lock is not stale at the old limit.
        assert!(matches!(
            take(&target, B, NOW + STALE + 1),
            Err(LockError::Held { .. })
        ));
    }

    #[test]
    fn refresh_fails_when_the_file_is_gone_or_not_valid() {
        let target = MemoryTarget::new();
        let a = take(&target, A, NOW).unwrap();
        target.insert(LOCK_PATH, vec![1, 2, 3]);
        assert!(matches!(block_on(a.refresh(NOW + 1)), Err(LockError::Lost)));
        target.remove(LOCK_PATH);
        assert!(matches!(block_on(a.refresh(NOW + 1)), Err(LockError::Lost)));
        assert!(!target.contains(LOCK_PATH));
    }

    #[test]
    fn release_frees_the_lock() {
        let target = MemoryTarget::new();
        let a = take(&target, A, NOW).unwrap();
        block_on(a.release()).unwrap();
        assert!(!target.contains(LOCK_PATH));
        assert!(take(&target, B, NOW + 1).is_ok());
    }

    #[test]
    fn does_not_take_a_lock_file_that_is_not_valid() {
        let target = MemoryTarget::new();
        target.insert(LOCK_PATH, b"garbage".to_vec());
        // Even when it is old: the owner decides (format.md 8.6.2).
        assert!(matches!(
            take(&target, A, NOW + 100 * STALE),
            Err(LockError::Invalid(_))
        ));
        assert_eq!(block_on(target.read(LOCK_PATH)).unwrap(), b"garbage");
    }

    /// A target where another node wins the race for the lock after a takeover.
    struct Racing<'a> {
        inner: &'a MemoryTarget,
        removals: Cell<u32>,
    }

    impl Target for Racing<'_> {
        async fn len(&self, path: &str) -> Result<u64, TargetError> {
            self.inner.len(path).await
        }
        async fn read_range(&self, path: &str, range: Range<u64>) -> Result<Vec<u8>, TargetError> {
            self.inner.read_range(path, range).await
        }
        async fn read(&self, path: &str) -> Result<Vec<u8>, TargetError> {
            self.inner.read(path).await
        }
        async fn list(&self, dir: &str) -> Result<Vec<String>, TargetError> {
            self.inner.list(dir).await
        }
    }

    impl WriteTarget for Racing<'_> {
        async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
            self.inner.put(path, bytes).await
        }
        async fn put_new(&self, path: &str, bytes: &[u8]) -> Result<bool, TargetError> {
            self.inner.put_new(path, bytes).await
        }
        async fn remove_lock(&self) -> Result<(), TargetError> {
            self.inner.remove_lock().await?;
            // Another node creates the lock at once, before this node can.
            self.removals.set(self.removals.get() + 1);
            let other = LockFile {
                node_id: B,
                heartbeat: NOW + STALE + 1,
            };
            self.inner.put_new(LOCK_PATH, &other.encode()).await?;
            Ok(())
        }
    }

    #[test]
    fn when_two_nodes_take_over_the_same_stale_lock_only_one_wins() {
        let target = MemoryTarget::new();
        let _old = take(&target, A, NOW).unwrap();
        let racing = Racing {
            inner: &target,
            removals: Cell::new(0),
        };
        let result = block_on(WriterLock::acquire(
            &racing,
            NodeId::from_bytes([0xcc; 16]),
            NOW + STALE + 1,
            STALE,
        ));
        assert!(matches!(
            result,
            Err(LockError::Held { node_id, .. }) if node_id == B
        ));
        assert_eq!(racing.removals.get(), 1);
        assert_eq!(file(&target).node_id, B);
    }
}
