//! The writer lock (format.md 8.6).
//!
//! The lock protects against two runs by mistake. It is not a strong lock
//! (format.md 8.6.5). The caller gives the time, so that the code needs no clock
//! and tests control it.

use crate::target::WriteTarget;
use nilperit_crypto::CryptoRng;
use nilperit_format::{HolderId, LockFile, ObjectError};
use nilperit_reader::TargetError;
use nilperit_reader::layout::LOCK_PATH;
use std::fmt;

/// The lock could not be taken, or it was lost.
#[derive(Debug)]
pub enum LockError {
    /// Another holder has the lock, and its heartbeat is not older than the
    /// staleness limit.
    Held {
        /// The holder of the lock.
        holder_id: HolderId,
        /// Its last heartbeat, by its own clock.
        heartbeat: i64,
    },
    /// The lock file is not a valid lock file. The node does not take the lock:
    /// the owner decides (format.md 8.6.2).
    Invalid(ObjectError),
    /// The lock is missing or names another holder.
    Lost,
    /// The lock changed again and again while the node tried to take it.
    Contended,
    /// The target failed.
    Target(TargetError),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held {
                holder_id,
                heartbeat,
            } => {
                write!(
                    f,
                    "holder {holder_id} has the writer lock (heartbeat {heartbeat})"
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
    holder_id: HolderId,
}

impl<'a, T: WriteTarget> WriterLock<'a, T> {
    /// Takes the lock (format.md 8.6.2).
    ///
    /// It makes a new holder ID from `rng` (format.md 8.6.1), so that it can tell
    /// itself from every other holder, also from another run of the same node.
    ///
    /// `now` is the time of the clock of this node, in milliseconds. A lock whose
    /// heartbeat is more than `stale_after` milliseconds older than `now` can be
    /// taken over. A heartbeat in the future is not stale.
    pub async fn acquire<R: CryptoRng>(
        target: &'a T,
        now: i64,
        stale_after: i64,
        rng: &mut R,
    ) -> Result<WriterLock<'a, T>, LockError> {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let holder_id = HolderId::from_bytes(id);
        let mine = LockFile {
            holder_id,
            heartbeat: now,
        }
        .encode();
        // A second try after a takeover, and a third for a lock that vanished.
        for _ in 0..3 {
            if target.put_new(LOCK_PATH, &mine).await? {
                return Ok(Self { target, holder_id });
            }
            let Some(lock) = read_lock(target).await? else {
                // It was removed after our attempt. Try again.
                continue;
            };
            if now.saturating_sub(lock.heartbeat) <= stale_after {
                return Err(LockError::Held {
                    holder_id: lock.holder_id,
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

    /// The holder ID of this lock.
    pub fn holder_id(&self) -> HolderId {
        self.holder_id
    }

    /// Writes a new heartbeat (format.md 8.6.3). It reads the file first. When the
    /// file is missing or names another holder, the lock is lost and nothing is
    /// written. The caller MUST stop writing to the vault.
    pub async fn refresh(&self, now: i64) -> Result<(), LockError> {
        self.check().await?;
        let lock = LockFile {
            holder_id: self.holder_id,
            heartbeat: now,
        };
        self.target.put(LOCK_PATH, &lock.encode()).await?;
        Ok(())
    }

    /// Releases the lock (format.md 8.6.4). It deletes the file only when the file
    /// names this holder. Otherwise it leaves the file and returns `Lost`.
    pub async fn release(self) -> Result<(), LockError> {
        self.check().await?;
        self.target.remove_lock().await?;
        Ok(())
    }

    async fn check(&self) -> Result<(), LockError> {
        match read_lock(self.target).await {
            Ok(Some(lock)) if lock.holder_id == self.holder_id => Ok(()),
            // Missing, another holder, or a file that is not valid: not ours.
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
    use crate::test_util::{TestRng, block_on};
    use nilperit_reader::{MemoryTarget, Target};
    use std::cell::Cell;
    use std::ops::Range;
    use x_wing::kem::common::rand_core::TryRng;

    const NOW: i64 = 1_700_000_000_000;
    const STALE: i64 = 60_000;

    fn file(target: &MemoryTarget) -> LockFile {
        LockFile::decode(&block_on(target.read(LOCK_PATH)).unwrap()).unwrap()
    }

    /// Takes the lock. `who` selects the random bytes: a different `who` gives a
    /// different holder ID.
    fn take(
        target: &MemoryTarget,
        who: u64,
        now: i64,
    ) -> Result<WriterLock<'_, MemoryTarget>, LockError> {
        block_on(WriterLock::acquire(
            target,
            now,
            STALE,
            &mut TestRng::new(who),
        ))
    }

    #[test]
    fn takes_a_free_lock() {
        let target = MemoryTarget::new();
        let lock = take(&target, 1, NOW).unwrap();
        assert_eq!(
            file(&target),
            LockFile {
                holder_id: lock.holder_id(),
                heartbeat: NOW
            }
        );
    }

    #[test]
    fn the_holder_id_is_made_from_the_random_bytes_of_the_caller() {
        let target = MemoryTarget::new();
        let lock = take(&target, 1, NOW).unwrap();
        let mut expected = [0u8; 16];
        TestRng::new(1).try_fill_bytes(&mut expected).unwrap();
        assert_eq!(lock.holder_id().as_bytes(), &expected);
        // Other random bytes give another holder ID.
        let other = MemoryTarget::new();
        assert_ne!(take(&other, 2, NOW).unwrap().holder_id(), lock.holder_id());
    }

    #[test]
    fn does_not_take_a_lock_that_another_holder_has() {
        let target = MemoryTarget::new();
        let a = take(&target, 1, NOW).unwrap();
        let result = take(&target, 2, NOW + 1_000);
        assert!(matches!(
            result,
            Err(LockError::Held { holder_id, heartbeat })
                if holder_id == a.holder_id() && heartbeat == NOW
        ));
        // The lock is unchanged.
        assert_eq!(file(&target).holder_id, a.holder_id());
    }

    #[test]
    fn a_second_run_of_the_same_node_waits_like_any_other() {
        // Another process of the same node is another holder. Its ID is its own,
        // so it cannot mistake the lock of the first process for its own.
        let target = MemoryTarget::new();
        let first = take(&target, 1, NOW).unwrap();
        assert!(matches!(
            take(&target, 2, NOW + 1),
            Err(LockError::Held { .. })
        ));
        assert_eq!(file(&target).holder_id, first.holder_id());
    }

    #[test]
    fn takes_over_a_stale_lock_but_not_one_at_the_limit() {
        let target = MemoryTarget::new();
        let _a = take(&target, 1, NOW).unwrap();
        // At the limit, the lock is not stale yet.
        assert!(matches!(
            take(&target, 2, NOW + STALE),
            Err(LockError::Held { .. })
        ));
        // One millisecond later it is.
        let b = take(&target, 2, NOW + STALE + 1).unwrap();
        assert_eq!(
            file(&target),
            LockFile {
                holder_id: b.holder_id(),
                heartbeat: NOW + STALE + 1
            }
        );
    }

    #[test]
    fn a_heartbeat_in_the_future_is_not_stale() {
        // The clock of the holder is ahead. The node must not take the lock.
        let target = MemoryTarget::new();
        let _a = take(&target, 1, NOW + 10 * STALE).unwrap();
        assert!(matches!(take(&target, 2, NOW), Err(LockError::Held { .. })));
    }

    #[test]
    fn the_old_holder_has_lost_the_lock_after_a_takeover() {
        let target = MemoryTarget::new();
        let a = take(&target, 1, NOW).unwrap();
        let b = take(&target, 2, NOW + STALE + 1).unwrap();
        assert!(matches!(
            block_on(a.refresh(NOW + STALE + 2)),
            Err(LockError::Lost)
        ));
        // The refresh wrote nothing: the lock is still the lock of b.
        assert_eq!(file(&target).holder_id, b.holder_id());
        // Releasing does not delete the lock of another holder either.
        assert!(matches!(block_on(a.release()), Err(LockError::Lost)));
        assert_eq!(file(&target).holder_id, b.holder_id());
    }

    #[test]
    fn refresh_writes_a_new_heartbeat() {
        let target = MemoryTarget::new();
        let a = take(&target, 1, NOW).unwrap();
        block_on(a.refresh(NOW + 30_000)).unwrap();
        assert_eq!(
            file(&target),
            LockFile {
                holder_id: a.holder_id(),
                heartbeat: NOW + 30_000
            }
        );
        // With the new heartbeat the lock is not stale at the old limit.
        assert!(matches!(
            take(&target, 2, NOW + STALE + 1),
            Err(LockError::Held { .. })
        ));
    }

    #[test]
    fn refresh_fails_when_the_file_is_gone_or_not_valid() {
        let target = MemoryTarget::new();
        let a = take(&target, 1, NOW).unwrap();
        target.insert(LOCK_PATH, vec![1, 2, 3]);
        assert!(matches!(block_on(a.refresh(NOW + 1)), Err(LockError::Lost)));
        target.remove(LOCK_PATH);
        assert!(matches!(block_on(a.refresh(NOW + 1)), Err(LockError::Lost)));
        assert!(!target.contains(LOCK_PATH));
    }

    #[test]
    fn release_frees_the_lock() {
        let target = MemoryTarget::new();
        let a = take(&target, 1, NOW).unwrap();
        block_on(a.release()).unwrap();
        assert!(!target.contains(LOCK_PATH));
        assert!(take(&target, 2, NOW + 1).is_ok());
    }

    #[test]
    fn does_not_take_a_lock_file_that_is_not_valid() {
        let target = MemoryTarget::new();
        target.insert(LOCK_PATH, b"garbage".to_vec());
        // Even when it is old: the owner decides (format.md 8.6.2).
        assert!(matches!(
            take(&target, 1, NOW + 100 * STALE),
            Err(LockError::Invalid(_))
        ));
        assert_eq!(block_on(target.read(LOCK_PATH)).unwrap(), b"garbage");
    }

    /// A target where another holder wins the race for the lock after a takeover.
    struct Racing<'a> {
        inner: &'a MemoryTarget,
        winner: HolderId,
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
            // Another holder creates the lock at once, before this node can.
            self.removals.set(self.removals.get() + 1);
            let other = LockFile {
                holder_id: self.winner,
                heartbeat: NOW + STALE + 1,
            };
            self.inner.put_new(LOCK_PATH, &other.encode()).await?;
            Ok(())
        }
    }

    #[test]
    fn when_two_nodes_take_over_the_same_stale_lock_only_one_wins() {
        let target = MemoryTarget::new();
        let _old = take(&target, 1, NOW).unwrap();
        let winner = HolderId::from_bytes([0xbb; 16]);
        let racing = Racing {
            inner: &target,
            winner,
            removals: Cell::new(0),
        };
        let result = block_on(WriterLock::acquire(
            &racing,
            NOW + STALE + 1,
            STALE,
            &mut TestRng::new(3),
        ));
        assert!(matches!(
            result,
            Err(LockError::Held { holder_id, .. }) if holder_id == winner
        ));
        assert_eq!(racing.removals.get(), 1);
        assert_eq!(file(&target).holder_id, winner);
    }
}
