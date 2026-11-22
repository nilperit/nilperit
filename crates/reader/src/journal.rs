//! Replaying the journal of a source (format.md 5.5).
//!
//! The first system has only delta entries. The state of a source is the result
//! of all delta entries from sequence 1 up to the head.

use crate::index::PackIndex;
use crate::pack::ObjectReadError;
use crate::target::Target;
use crate::vault::Vault;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use nilperit_format::{DeltaEntry, ItemKey, ObjectError, ObjectId, SnapshotHeader, SourceId};

/// The journal of a source cannot be replayed.
#[derive(Debug)]
pub enum JournalError {
    /// A journal entry is not in any pack that opened. The value is its object ID.
    MissingEntry(ObjectId),
    /// A journal entry is in a pack, but it cannot be read.
    Unreadable(ObjectId, ObjectReadError),
    /// The bytes of a journal entry are not a valid delta entry.
    BadEntry(ObjectId, ObjectError),
    /// Two entries or an entry and its snapshot header disagree. The text says how.
    Inconsistent(ObjectId, &'static str),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEntry(id) => write!(f, "journal entry {id} is missing"),
            Self::Unreadable(id, e) => write!(f, "journal entry {id} cannot be read: {e}"),
            Self::BadEntry(id, e) => write!(f, "journal entry {id} is not valid: {e}"),
            Self::Inconsistent(id, what) => write!(f, "journal entry {id}: {what}"),
        }
    }
}

impl core::error::Error for JournalError {}

/// What the state of a source holds for one item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemState {
    /// The object ID of the item record.
    pub item_record: ObjectId,
    /// The object IDs of the content objects, in the order of the item record.
    pub content: Vec<ObjectId>,
}

/// The state of a source at the head of its journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceState {
    /// The source.
    pub source_id: SourceId,
    /// The sequence number of the head entry.
    pub sequence: u64,
    /// The connector cursor of the head entry (format.md 5.5.5.1).
    pub connector_cursor: Option<Vec<u8>>,
    /// The items that exist, by item key.
    pub items: BTreeMap<ItemKey, ItemState>,
}

impl<T: Target> Vault<T> {
    /// Replays the journal that a snapshot header names, and returns the state of
    /// the source.
    ///
    /// It reads the chain of entries from the head back to sequence 1, and
    /// checks that each entry is the child of the next one (format.md 5.5.2.4).
    /// It uses no checkpoint, because the first system writes none.
    pub async fn replay_journal(
        &self,
        index: &PackIndex,
        head: &SnapshotHeader,
    ) -> Result<SourceState, JournalError> {
        // From the head back to the first entry.
        let mut chain: Vec<DeltaEntry> = Vec::new();
        let mut id = head.journal_entry;
        let mut expected_sequence = head.journal_sequence;
        loop {
            let entry = self.read_entry(index, &id).await?;
            if entry.source_id != head.source_id {
                return Err(JournalError::Inconsistent(id, "entry of another source"));
            }
            if entry.sequence != expected_sequence {
                return Err(JournalError::Inconsistent(id, "unexpected sequence number"));
            }
            let parent = entry.parent;
            chain.push(entry);
            match parent {
                Some(parent) => {
                    id = parent;
                    // A valid entry has a parent only when its sequence is above 1
                    // (format.md 5.5.2.4), so this cannot underflow. An entry with
                    // sequence 1 has no parent, which ends the loop.
                    expected_sequence -= 1;
                }
                None => break,
            }
        }
        // From the first entry forward.
        let mut items = BTreeMap::new();
        for entry in chain.iter().rev() {
            for change in &entry.changed {
                items.insert(
                    change.item_key,
                    ItemState {
                        item_record: change.item_record,
                        content: change.content.clone(),
                    },
                );
            }
            for key in &entry.deleted {
                items.remove(key);
            }
        }
        let head_entry = &chain[0];
        Ok(SourceState {
            source_id: head.source_id,
            sequence: head_entry.sequence,
            connector_cursor: head_entry.connector_cursor.clone(),
            items,
        })
    }

    async fn read_entry(
        &self,
        index: &PackIndex,
        id: &ObjectId,
    ) -> Result<DeltaEntry, JournalError> {
        let stored = self.read_indexed(index, id).await.map_err(|e| match e {
            ObjectReadError::NotInPack => JournalError::MissingEntry(*id),
            e => JournalError::Unreadable(*id, e),
        })?;
        DeltaEntry::decode(&stored).map_err(|e| JournalError::BadEntry(*id, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        TestKeys, TestObject, block_on, build_pack, entry_object, header, test_seed, vault_with,
    };
    use nilperit_format::{Change, SnapshotId};

    fn key(byte: u8) -> ItemKey {
        ItemKey::from_bytes([byte; 32])
    }

    fn oid(byte: u8) -> ObjectId {
        ObjectId::from_bytes([byte; 32])
    }

    fn change(item: u8, record: u8, content: &[u8]) -> Change {
        Change {
            item_key: key(item),
            item_record: oid(record),
            content: content.iter().map(|b| oid(*b)).collect(),
        }
    }

    fn entry(
        sequence: u64,
        parent: Option<ObjectId>,
        changed: Vec<Change>,
        deleted: &[u8],
    ) -> DeltaEntry {
        DeltaEntry {
            source_id: SourceId::from_bytes([1; 16]),
            sequence,
            parent,
            snapshot_id: SnapshotId::from_bytes([sequence as u8; 16]),
            time: 1_000 * sequence as i64,
            connector_cursor: Some(alloc::vec![sequence as u8]),
            changed,
            deleted: deleted.iter().map(|b| key(*b)).collect(),
        }
    }

    /// Makes a pack with the entries and returns it with the object IDs.
    fn pack_of(entries: &[&DeltaEntry]) -> (Vec<u8>, Vec<ObjectId>) {
        let (objects, ids): (Vec<TestObject>, Vec<ObjectId>) =
            entries.iter().map(|e| entry_object(e)).unzip();
        let (bytes, _) = build_pack(&TestKeys::from_seed(&test_seed()), &objects);
        (bytes, ids)
    }

    /// Three entries: 1 adds items 1 and 2; 2 changes item 1 and adds 3; 3 deletes 2.
    fn three() -> (DeltaEntry, DeltaEntry, DeltaEntry, [ObjectId; 3]) {
        let e1 = entry(
            1,
            None,
            alloc::vec![change(1, 10, &[20]), change(2, 11, &[21])],
            &[],
        );
        let id1 = entry_object(&e1).1;
        let e2 = entry(
            2,
            Some(id1),
            alloc::vec![change(1, 12, &[22]), change(3, 13, &[])],
            &[],
        );
        let id2 = entry_object(&e2).1;
        let e3 = entry(3, Some(id2), alloc::vec![], &[2]);
        let id3 = entry_object(&e3).1;
        (e1, e2, e3, [id1, id2, id3])
    }

    fn replay(packs: &[&[u8]], head: &SnapshotHeader) -> Result<SourceState, JournalError> {
        let vault = vault_with(packs, &[]);
        let index = block_on(vault.scan_packs()).unwrap();
        block_on(vault.replay_journal(&index, head))
    }

    #[test]
    fn replays_a_chain_across_packs() {
        let (e1, e2, e3, ids) = three();
        let (a, _) = pack_of(&[&e1]);
        let (b, _) = pack_of(&[&e2, &e3]);
        let state = replay(&[&a, &b], &header(1, 0x33, 3_000, ids[2], 3)).unwrap();
        assert_eq!(state.sequence, 3);
        assert_eq!(state.connector_cursor, Some(alloc::vec![3]));
        let expected: BTreeMap<_, _> = [
            (
                key(1),
                ItemState {
                    item_record: oid(12),
                    content: alloc::vec![oid(22)],
                },
            ),
            (
                key(3),
                ItemState {
                    item_record: oid(13),
                    content: alloc::vec![],
                },
            ),
        ]
        .into();
        assert_eq!(state.items, expected);
    }

    #[test]
    fn an_older_head_gives_the_older_state() {
        let (e1, e2, e3, ids) = three();
        let (a, _) = pack_of(&[&e1, &e2, &e3]);
        let state = replay(&[&a], &header(1, 0x32, 2_000, ids[1], 2)).unwrap();
        assert_eq!(state.sequence, 2);
        assert_eq!(state.items.len(), 3);
        assert_eq!(state.items[&key(1)].item_record, oid(12));
        let state = replay(&[&a], &header(1, 0x31, 1_000, ids[0], 1)).unwrap();
        assert_eq!(state.items.len(), 2);
        assert_eq!(state.items[&key(1)].item_record, oid(10));
    }

    #[test]
    fn a_missing_entry_is_reported_with_its_id() {
        let (e1, e2, e3, ids) = three();
        // The first entry is not in any pack.
        let (a, _) = pack_of(&[&e2, &e3]);
        let result = replay(&[&a], &header(1, 0x33, 3_000, ids[2], 3));
        assert!(matches!(result, Err(JournalError::MissingEntry(id)) if id == ids[0]));
        // The head entry is missing.
        let (b, _) = pack_of(&[&e1, &e2]);
        let result = replay(&[&b], &header(1, 0x33, 3_000, ids[2], 3));
        assert!(matches!(result, Err(JournalError::MissingEntry(id)) if id == ids[2]));
    }

    #[test]
    fn a_journal_entry_that_is_not_a_delta_entry_is_rejected() {
        let objects = [TestObject::new(
            5,
            nilperit_format::KeyClass::W,
            nilperit_format::Compression::None,
            b"not an envelope",
        )];
        let keys = TestKeys::from_seed(&test_seed());
        let (bytes, ids) = build_pack(&keys, &objects);
        let result = replay(&[&bytes], &header(1, 0x31, 1_000, ids[0], 1));
        assert!(matches!(result, Err(JournalError::BadEntry(id, _)) if id == ids[0]));
    }

    #[test]
    fn rejects_entries_that_do_not_fit_together() {
        let (e1, e2, _, ids) = three();

        // The header says sequence 3, the entry has sequence 2.
        let (a, _) = pack_of(&[&e1, &e2]);
        let result = replay(&[&a], &header(1, 0x33, 3_000, ids[1], 3));
        assert!(matches!(result, Err(JournalError::Inconsistent(_, _))));

        // A parent whose sequence is not the child's minus 1.
        let skip = entry(3, Some(ids[0]), alloc::vec![], &[]);
        let skip_id = entry_object(&skip).1;
        let (b, _) = pack_of(&[&e1, &skip]);
        let result = replay(&[&b], &header(1, 0x33, 3_000, skip_id, 3));
        assert!(matches!(result, Err(JournalError::Inconsistent(id, _)) if id == ids[0]));

        // An entry of another source in the chain.
        let mut foreign = entry(1, None, alloc::vec![], &[]);
        foreign.source_id = SourceId::from_bytes([2; 16]);
        let foreign_id = entry_object(&foreign).1;
        let child = entry(2, Some(foreign_id), alloc::vec![], &[]);
        let child_id = entry_object(&child).1;
        let (c, _) = pack_of(&[&foreign, &child]);
        let result = replay(&[&c], &header(1, 0x32, 2_000, child_id, 2));
        assert!(matches!(result, Err(JournalError::Inconsistent(id, _)) if id == foreign_id));
    }
}
