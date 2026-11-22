//! Reading the snapshot headers and choosing the head of each journal
//! (format.md 5.9 and 5.5.8).

use crate::layout::{SNAPSHOTS_DIR, parse_snapshot_path, snapshot_path};
use crate::target::{Target, TargetError};
use crate::vault::Vault;
use alloc::vec::Vec;
use core::fmt;
use nilperit_crypto::decrypt;
use nilperit_format::{ObjectError, SnapshotHeader, SnapshotId, SourceId};

/// The largest snapshot header file that a reader accepts (format.md 3.3.7.2).
const MAX_FILE_SIZE: u64 = 1 << 32;

/// Why a snapshot header file is not used.
#[derive(Debug)]
pub enum SnapshotRejected {
    /// The target failed to read the file.
    Target(TargetError),
    /// The file is 2^32 bytes or more (format.md 3.3.7.2).
    TooLarge,
    /// The tag is not correct (format.md 9.4).
    NotAuthentic,
    /// The decrypted bytes are not a valid snapshot header.
    Format(ObjectError),
    /// The name of the file is not the snapshot ID in the header (format.md 5.9.5).
    WrongName,
    /// The header belongs to another vault (format.md 5.9.5).
    WrongVault,
}

impl fmt::Display for SnapshotRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(e) => e.fmt(f),
            Self::TooLarge => f.write_str("the file is too large"),
            Self::NotAuthentic => f.write_str("the snapshot header is not authentic"),
            Self::Format(e) => write!(f, "the snapshot header is not valid: {e}"),
            Self::WrongName => f.write_str("the file name is not the snapshot ID"),
            Self::WrongVault => f.write_str("the snapshot header belongs to another vault"),
        }
    }
}

impl core::error::Error for SnapshotRejected {}

/// The snapshot headers of a vault that the reader accepts.
#[derive(Debug, Default)]
pub struct Snapshots {
    headers: Vec<SnapshotHeader>,
    skipped: Vec<(SnapshotId, SnapshotRejected)>,
}

impl Snapshots {
    /// All accepted headers, in the order of their file names.
    pub fn headers(&self) -> &[SnapshotHeader] {
        &self.headers
    }

    /// The files that the reader did not use, and why. A damaged header does not
    /// stop the reader: a header is a cache (format.md 5.9.3).
    pub fn skipped(&self) -> &[(SnapshotId, SnapshotRejected)] {
        &self.skipped
    }

    /// The sources that have a snapshot header, in ascending order.
    pub fn sources(&self) -> Vec<SourceId> {
        let mut sources: Vec<SourceId> = self.headers.iter().map(|h| h.source_id).collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    /// The newest header of a source: the one with the highest journal sequence
    /// number. A tie goes to the later time (format.md 5.5.8.1). Time is no
    /// criterion before the sequence, because clocks can be wrong. When both are
    /// equal, the higher snapshot ID wins, so the choice is always the same.
    pub fn head(&self, source: &SourceId) -> Option<&SnapshotHeader> {
        self.headers
            .iter()
            .filter(|h| h.source_id == *source)
            .max_by_key(|h| (h.journal_sequence, h.time, h.snapshot_id))
    }
}

impl<T: Target> Vault<T> {
    /// Reads every file in `snapshots/` and keeps the valid snapshot headers.
    ///
    /// Only a failure to list the directory is an error. A file that the reader
    /// does not accept is listed in [`Snapshots::skipped`]. A file whose name is
    /// not a snapshot ID is ignored.
    pub async fn read_snapshots(&self) -> Result<Snapshots, TargetError> {
        let mut ids: Vec<SnapshotId> = self
            .target()
            .list(SNAPSHOTS_DIR)
            .await?
            .iter()
            .filter_map(|path| parse_snapshot_path(path))
            .collect();
        ids.sort_unstable();
        ids.dedup();

        let mut snapshots = Snapshots::default();
        for id in ids {
            match self.read_snapshot(&id).await {
                Ok(header) => snapshots.headers.push(header),
                Err(e) => snapshots.skipped.push((id, e)),
            }
        }
        Ok(snapshots)
    }

    async fn read_snapshot(&self, id: &SnapshotId) -> Result<SnapshotHeader, SnapshotRejected> {
        let path = snapshot_path(id);
        let target = self.target();
        if target.len(&path).await.map_err(SnapshotRejected::Target)? >= MAX_FILE_SIZE {
            return Err(SnapshotRejected::TooLarge);
        }
        let file = target.read(&path).await.map_err(SnapshotRejected::Target)?;
        let stored = decrypt(&self.keys().writer().snapshot_header_key(), &[], &file)
            .map_err(|_| SnapshotRejected::NotAuthentic)?;
        let header = SnapshotHeader::decode(&stored).map_err(SnapshotRejected::Format)?;
        if header.snapshot_id != *id {
            return Err(SnapshotRejected::WrongName);
        }
        if header.vault.vault_id != self.config().essentials.vault_id {
            return Err(SnapshotRejected::WrongVault);
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::snapshot_path;
    use crate::test_util::{
        block_on, header, snapshot_entry, snapshot_file, test_seed, vault_with,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use nilperit_crypto::encrypt;
    use nilperit_format::ObjectId;

    fn id(byte: u8) -> ObjectId {
        ObjectId::from_bytes([byte; 32])
    }

    fn source(byte: u8) -> SourceId {
        SourceId::from_bytes([byte; 16])
    }

    #[test]
    fn a_vault_without_snapshots_has_no_sources() {
        let snapshots = block_on(vault_with(&[], &[]).read_snapshots()).unwrap();
        assert!(snapshots.headers().is_empty());
        assert!(snapshots.sources().is_empty());
        assert!(snapshots.head(&source(1)).is_none());
    }

    #[test]
    fn the_head_is_the_header_with_the_highest_sequence_not_the_latest_time() {
        // The clock of the node went backwards for the newest snapshot.
        let headers = [
            header(1, 0x11, 5_000, id(1), 1),
            header(1, 0x12, 9_000, id(2), 2),
            header(1, 0x13, 1_000, id(3), 3),
        ];
        let files: Vec<_> = headers.iter().map(snapshot_entry).collect();
        let snapshots = block_on(vault_with(&[], &files).read_snapshots()).unwrap();
        assert_eq!(snapshots.headers().len(), 3);
        assert_eq!(snapshots.head(&source(1)).unwrap().journal_sequence, 3);
    }

    #[test]
    fn a_tie_in_sequence_goes_to_the_later_time() {
        let headers = [
            header(1, 0x21, 1_000, id(1), 4),
            header(1, 0x22, 2_000, id(2), 4),
            header(1, 0x23, 1_500, id(3), 4),
        ];
        let files: Vec<_> = headers.iter().map(snapshot_entry).collect();
        let snapshots = block_on(vault_with(&[], &files).read_snapshots()).unwrap();
        assert_eq!(snapshots.head(&source(1)).unwrap().journal_entry, id(2));
    }

    #[test]
    fn a_tie_in_sequence_and_time_is_decided_the_same_way_every_time() {
        let headers = [
            header(1, 0x31, 1_000, id(1), 4),
            header(1, 0x32, 1_000, id(2), 4),
        ];
        let files: Vec<_> = headers.iter().map(snapshot_entry).collect();
        let reversed: Vec<_> = files.iter().rev().cloned().collect();
        let a = block_on(vault_with(&[], &files).read_snapshots()).unwrap();
        let b = block_on(vault_with(&[], &reversed).read_snapshots()).unwrap();
        assert_eq!(a.head(&source(1)), b.head(&source(1)));
    }

    #[test]
    fn each_source_has_its_own_head() {
        let headers = [
            header(2, 0x41, 1_000, id(1), 7),
            header(1, 0x42, 1_000, id(2), 3),
            header(2, 0x43, 1_000, id(3), 8),
        ];
        let files: Vec<_> = headers.iter().map(snapshot_entry).collect();
        let snapshots = block_on(vault_with(&[], &files).read_snapshots()).unwrap();
        assert_eq!(snapshots.sources(), [source(1), source(2)]);
        assert_eq!(snapshots.head(&source(1)).unwrap().journal_sequence, 3);
        assert_eq!(snapshots.head(&source(2)).unwrap().journal_sequence, 8);
    }

    #[test]
    fn skips_headers_that_must_not_be_used() {
        let good = header(1, 0x51, 1_000, id(1), 1);

        // The name is not the snapshot ID in the header (5.9.5).
        let renamed = header(1, 0x52, 1_000, id(2), 2);
        let wrong_name = (
            snapshot_path(&header(1, 0x53, 0, id(0), 0).snapshot_id),
            snapshot_file(&renamed),
        );

        // Another vault (5.9.5).
        let mut foreign = header(1, 0x54, 1_000, id(3), 3);
        foreign.vault.vault_id = nilperit_format::VaultId::from_bytes([9; 16]);

        // A damaged tag, and bytes that are no snapshot header.
        let mut damaged = snapshot_entry(&header(1, 0x55, 1_000, id(4), 4));
        let last = damaged.1.len() - 1;
        damaged.1[last] ^= 1;
        let key = test_seed().writer_key().snapshot_header_key();
        let garbage = (
            snapshot_path(&header(1, 0x56, 0, id(0), 0).snapshot_id),
            encrypt(&key, &[], b"not cbor", &mut crate::test_util::TestRng(1)).unwrap(),
        );
        let short = (
            snapshot_path(&header(1, 0x57, 0, id(0), 0).snapshot_id),
            vec![1, 2, 3],
        );

        let files = vec![
            snapshot_entry(&good),
            wrong_name,
            snapshot_entry(&foreign),
            damaged,
            garbage,
            short,
            // Not a snapshot ID: ignored, not skipped.
            ("snapshots/notes.txt".to_string(), vec![1]),
        ];
        let snapshots = block_on(vault_with(&[], &files).read_snapshots()).unwrap();
        assert_eq!(snapshots.headers(), [good]);
        assert_eq!(snapshots.skipped().len(), 5);
        let reasons: Vec<_> = snapshots.skipped().iter().map(|(_, r)| r).collect();
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, SnapshotRejected::WrongName))
        );
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, SnapshotRejected::WrongVault))
        );
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, SnapshotRejected::Format(_)))
        );
        assert_eq!(
            reasons
                .iter()
                .filter(|r| matches!(r, SnapshotRejected::NotAuthentic))
                .count(),
            2
        );
    }
}
