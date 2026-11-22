//! A target in memory, for tests and for tools that hold a vault in memory.

use crate::target::{Target, TargetError};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ops::Range;

/// A vault that lives in memory. It is a map from path to file bytes.
///
/// Files can change through a shared reference, like the files of a real target,
/// so that a reader and a writer can use the same target at the same time. It is
/// not `Sync`.
#[derive(Debug, Default, Clone)]
pub struct MemoryTarget {
    files: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl MemoryTarget {
    /// Makes an empty target.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the bytes of a file. It replaces a file with the same path.
    pub fn insert(&self, path: &str, bytes: Vec<u8>) {
        self.files.borrow_mut().insert(path.to_string(), bytes);
    }

    /// Whether a file exists under the path.
    pub fn contains(&self, path: &str) -> bool {
        self.files.borrow().contains_key(path)
    }

    /// Removes a file. It returns whether the file existed.
    pub fn remove(&self, path: &str) -> bool {
        self.files.borrow_mut().remove(path).is_some()
    }
}

impl Target for MemoryTarget {
    async fn len(&self, path: &str) -> Result<u64, TargetError> {
        let files = self.files.borrow();
        let file = files.get(path).ok_or(TargetError::NotFound)?;
        Ok(file.len() as u64)
    }

    async fn read_range(&self, path: &str, range: Range<u64>) -> Result<Vec<u8>, TargetError> {
        let files = self.files.borrow();
        let file = files.get(path).ok_or(TargetError::NotFound)?;
        let start = usize::try_from(range.start).map_err(|_| TargetError::OutOfRange)?;
        let end = usize::try_from(range.end).map_err(|_| TargetError::OutOfRange)?;
        file.get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or(TargetError::OutOfRange)
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>, TargetError> {
        let files = self.files.borrow();
        files.get(path).cloned().ok_or(TargetError::NotFound)
    }

    async fn list(&self, dir: &str) -> Result<Vec<String>, TargetError> {
        let prefix = alloc::format!("{dir}/");
        Ok(self
            .files
            .borrow()
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::block_on;
    use alloc::vec;

    fn sample() -> MemoryTarget {
        let target = MemoryTarget::new();
        target.insert("config-a", vec![1, 2, 3, 4]);
        target.insert("packs/ab/abcd", vec![9; 10]);
        target.insert("packs/cd/cdef", vec![8; 5]);
        target.insert("snapshots/00", vec![7]);
        target
    }

    #[test]
    fn reads_a_whole_file_and_its_length() {
        let target = sample();
        assert_eq!(block_on(target.read("config-a")).unwrap(), [1, 2, 3, 4]);
        assert_eq!(block_on(target.len("config-a")).unwrap(), 4);
    }

    #[test]
    fn reads_a_range() {
        let target = sample();
        assert_eq!(
            block_on(target.read_range("config-a", 1..3)).unwrap(),
            [2, 3]
        );
        assert!(
            block_on(target.read_range("config-a", 2..2))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_a_range_outside_the_file() {
        let target = sample();
        assert!(matches!(
            block_on(target.read_range("config-a", 2..5)),
            Err(TargetError::OutOfRange)
        ));
        let reversed = Range { start: 3, end: 2 };
        assert!(matches!(
            block_on(target.read_range("config-a", reversed)),
            Err(TargetError::OutOfRange)
        ));
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let target = sample();
        assert!(matches!(
            block_on(target.read("config-b")),
            Err(TargetError::NotFound)
        ));
        assert!(matches!(
            block_on(target.len("config-b")),
            Err(TargetError::NotFound)
        ));
    }

    #[test]
    fn lists_files_below_a_directory_at_any_depth() {
        let target = sample();
        let mut packs = block_on(target.list("packs")).unwrap();
        packs.sort();
        assert_eq!(packs, ["packs/ab/abcd", "packs/cd/cdef"]);
        assert!(block_on(target.list("missing")).unwrap().is_empty());
        // A directory name is not a prefix match: "pack" is not "packs".
        assert!(block_on(target.list("pack")).unwrap().is_empty());
    }
}
