//! Delta entry (format.md 5.5.2).
//!
//! A delta entry is a journal entry with the changes of one commit. It is an
//! enveloped object with key class W.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::content_object::ObjectError;
use crate::envelope::Envelope;
use crate::fields::{
    Fields, read_array, read_bytes, read_hashes, read_i64, read_u64, write_array, write_bytes,
    write_hashes, write_i64, write_map, write_u64,
};
use crate::ids::{HASH_LEN, ItemKey, ObjectId, SnapshotId, SourceId};
use crate::object_type;

const KEY_SOURCE_ID: u64 = 1;
const KEY_SEQUENCE: u64 = 2;
const KEY_PARENT: u64 = 3;
const KEY_SNAPSHOT_ID: u64 = 4;
const KEY_TIME: u64 = 5;
const KEY_CURSOR: u64 = 6;
const KEY_CHANGED: u64 = 7;
const KEY_DELETED: u64 = 8;

/// A change of one item: its new item record and content objects (format.md 5.5.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The key of the item.
    pub item_key: ItemKey,
    /// The new item record.
    pub item_record: ObjectId,
    /// The content objects of the item.
    pub content: Vec<ObjectId>,
}

/// A delta entry (format.md 5.5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaEntry {
    /// The source of the journal.
    pub source_id: SourceId,
    /// The sequence number. The first entry of a journal has sequence number 1.
    pub sequence: u64,
    /// The object ID of the parent entry. Not present in the first entry.
    pub parent: Option<ObjectId>,
    /// The snapshot that this entry belongs to.
    pub snapshot_id: SnapshotId,
    /// The time of the snapshot, in milliseconds since 1970.
    pub time: i64,
    /// The connector cursor after this entry. Not present when the connector has none.
    pub connector_cursor: Option<Vec<u8>>,
    /// The items that are new or have a new version, in ascending order of the item key.
    pub changed: Vec<Change>,
    /// The keys of the items that the source no longer has, in ascending order.
    pub deleted: Vec<ItemKey>,
}

impl DeltaEntry {
    /// The object type ID.
    pub const TYPE_ID: u32 = object_type::DELTA_ENTRY;
    /// The schema version that this code writes.
    pub const SCHEMA: u32 = 1;

    /// Checks the rules of format.md 5.5.2.2 and 5.5.2.4.
    fn check(&self) -> Result<(), ObjectError> {
        if self.sequence == 0 {
            return Err(ObjectError::Rule("sequence number is 0"));
        }
        if self.parent.is_some() != (self.sequence > 1) {
            return Err(ObjectError::Rule(
                "parent is present if and only if the sequence number is above 1",
            ));
        }
        let changed = self.changed.iter().map(|c| c.item_key);
        if !is_ascending(changed.clone()) || !is_ascending(self.deleted.iter().copied()) {
            return Err(ObjectError::Rule("item keys are not in ascending order"));
        }
        let mut seen = BTreeSet::new();
        if !changed
            .chain(self.deleted.iter().copied())
            .all(|k| seen.insert(k))
        {
            return Err(ObjectError::Rule("item key occurs more than once"));
        }
        Ok(())
    }

    /// Encodes the delta entry. The result is the stored bytes. The entries MUST be
    /// in ascending order of the item key: the writer sorts them.
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        self.check()?;
        let mut fields = alloc::vec![
            (KEY_SOURCE_ID, write_bytes(self.source_id.as_bytes())),
            (KEY_SEQUENCE, write_u64(self.sequence)),
        ];
        if let Some(parent) = &self.parent {
            fields.push((KEY_PARENT, write_bytes(parent.as_bytes())));
        }
        fields.push((KEY_SNAPSHOT_ID, write_bytes(self.snapshot_id.as_bytes())));
        fields.push((KEY_TIME, write_i64(self.time)));
        if let Some(cursor) = &self.connector_cursor {
            fields.push((KEY_CURSOR, write_bytes(cursor)));
        }
        let changes: Vec<Vec<u8>> = self
            .changed
            .iter()
            .map(|c| {
                write_array(&[
                    write_bytes(c.item_key.as_bytes()),
                    write_bytes(c.item_record.as_bytes()),
                    write_hashes(c.content.iter().map(|id| id.as_bytes().as_slice())),
                ])
            })
            .collect();
        fields.push((KEY_CHANGED, write_array(&changes)));
        fields.push((
            KEY_DELETED,
            write_hashes(self.deleted.iter().map(|k| k.as_bytes().as_slice())),
        ));
        Ok(Envelope::encode(
            Self::TYPE_ID,
            Self::SCHEMA,
            &write_map(&fields),
        )?)
    }

    /// Decodes stored bytes. Ignores unknown fields (format.md 4.5). Rejects entries
    /// that are not in ascending order, an item key that occurs twice, and a parent
    /// that does not fit the sequence number.
    pub fn decode(stored: &[u8]) -> Result<Self, ObjectError> {
        let (_, fields) = Fields::open(stored, Self::TYPE_ID, Self::SCHEMA)?;
        let entry = Self {
            source_id: SourceId::from_bytes(read_array(
                fields.require(KEY_SOURCE_ID)?,
                KEY_SOURCE_ID,
            )?),
            sequence: read_u64(fields.require(KEY_SEQUENCE)?, KEY_SEQUENCE)?,
            parent: fields
                .get(KEY_PARENT)
                .map(|r| read_array(r, KEY_PARENT).map(ObjectId::from_bytes))
                .transpose()?,
            snapshot_id: SnapshotId::from_bytes(read_array(
                fields.require(KEY_SNAPSHOT_ID)?,
                KEY_SNAPSHOT_ID,
            )?),
            time: read_i64(fields.require(KEY_TIME)?, KEY_TIME)?,
            connector_cursor: fields
                .get(KEY_CURSOR)
                .map(|r| read_bytes(r, KEY_CURSOR))
                .transpose()?,
            changed: read_changes(fields.require(KEY_CHANGED)?)?,
            deleted: read_hashes(fields.require(KEY_DELETED)?, KEY_DELETED)?
                .into_iter()
                .map(ItemKey::from_bytes)
                .collect(),
        };
        entry.check()?;
        Ok(entry)
    }
}

fn is_ascending(keys: impl Iterator<Item = ItemKey>) -> bool {
    let mut previous: Option<ItemKey> = None;
    for key in keys {
        if previous.is_some_and(|p| p >= key) {
            return false;
        }
        previous = Some(key);
    }
    true
}

fn read_changes(raw: &[u8]) -> Result<Vec<Change>, ObjectError> {
    let bad = |_| ObjectError::BadField(KEY_CHANGED);
    let mut d = minicbor::Decoder::new(raw);
    let count = d
        .array()
        .map_err(bad)?
        .ok_or(ObjectError::BadField(KEY_CHANGED))?;
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(raw.len()));
    for _ in 0..count {
        if d.array().map_err(bad)? != Some(3) {
            return Err(ObjectError::BadField(KEY_CHANGED));
        }
        let item_key = hash_item(&mut d)?;
        let item_record = hash_item(&mut d)?;
        let ids = d
            .array()
            .map_err(bad)?
            .ok_or(ObjectError::BadField(KEY_CHANGED))?;
        let mut content = Vec::with_capacity(usize::try_from(ids).unwrap_or(0).min(raw.len()));
        for _ in 0..ids {
            content.push(ObjectId::from_bytes(hash_item(&mut d)?));
        }
        out.push(Change {
            item_key: ItemKey::from_bytes(item_key),
            item_record: ObjectId::from_bytes(item_record),
            content,
        });
    }
    Ok(out)
}

fn hash_item(d: &mut minicbor::Decoder<'_>) -> Result<[u8; HASH_LEN], ObjectError> {
    d.bytes()
        .ok()
        .and_then(|b| <[u8; HASH_LEN]>::try_from(b).ok())
        .ok_or(ObjectError::BadField(KEY_CHANGED))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::fields::{raw_object, with_field, write_array, write_text};

    fn key(n: u8) -> ItemKey {
        ItemKey::from_bytes([n; 32])
    }

    fn change(n: u8) -> Change {
        Change {
            item_key: key(n),
            item_record: ObjectId::from_bytes([n + 100; 32]),
            content: vec![ObjectId::from_bytes([n + 50; 32])],
        }
    }

    fn first() -> DeltaEntry {
        DeltaEntry {
            source_id: SourceId::from_bytes([2; 16]),
            sequence: 1,
            parent: None,
            snapshot_id: SnapshotId::from_bytes([3; 16]),
            time: -1,
            connector_cursor: None,
            changed: Vec::new(),
            deleted: Vec::new(),
        }
    }

    fn later() -> DeltaEntry {
        DeltaEntry {
            sequence: 5,
            parent: Some(ObjectId::from_bytes([9; 32])),
            connector_cursor: Some(b"history-123".to_vec()),
            changed: vec![change(1), change(3)],
            deleted: vec![key(2), key(4)],
            ..first()
        }
    }

    // The required fields of a first entry, valid, as raw fields.
    fn base() -> Vec<(u64, Vec<u8>)> {
        vec![
            (KEY_SOURCE_ID, write_bytes(&[2; 16])),
            (KEY_SEQUENCE, write_u64(1)),
            (KEY_SNAPSHOT_ID, write_bytes(&[3; 16])),
            (KEY_TIME, write_u64(0)),
            (KEY_CHANGED, write_array(&[])),
            (KEY_DELETED, write_array(&[])),
        ]
    }

    fn raw_change(key: u8) -> Vec<u8> {
        write_array(&[
            write_bytes(&[key; 32]),
            write_bytes(&[key; 32]),
            write_array(&[write_bytes(&[key; 32])]),
        ])
    }

    #[test]
    fn round_trip() {
        for entry in [first(), later()] {
            assert_eq!(DeltaEntry::decode(&entry.encode().unwrap()).unwrap(), entry);
        }
        assert_eq!(later().encode().unwrap(), later().encode().unwrap());
    }

    #[test]
    fn encode_rejects_entries_that_break_the_rules() {
        let rule = |entry: DeltaEntry| matches!(entry.encode(), Err(ObjectError::Rule(_)));
        assert!(rule(DeltaEntry {
            sequence: 0,
            ..first()
        }));
        // A parent only from sequence number 2.
        assert!(rule(DeltaEntry {
            parent: Some(ObjectId::from_bytes([1; 32])),
            ..first()
        }));
        assert!(rule(DeltaEntry {
            sequence: 2,
            ..first()
        }));
        // Not in ascending order, and the same key twice.
        assert!(rule(DeltaEntry {
            changed: vec![change(3), change(1)],
            ..first()
        }));
        assert!(rule(DeltaEntry {
            changed: vec![change(1), change(1)],
            ..first()
        }));
        assert!(rule(DeltaEntry {
            deleted: vec![key(4), key(2)],
            ..first()
        }));
        assert!(rule(DeltaEntry {
            deleted: vec![key(2), key(2)],
            ..first()
        }));
        // A key that is both changed and deleted.
        assert!(rule(DeltaEntry {
            changed: vec![change(1)],
            deleted: vec![key(1)],
            ..first()
        }));
    }

    #[test]
    fn decode_rejects_entries_that_break_the_rules() {
        let decode = |fields: Vec<(u64, Vec<u8>)>| {
            DeltaEntry::decode(&raw_object(DeltaEntry::TYPE_ID, &fields))
        };
        let rule = |r: Result<DeltaEntry, ObjectError>| matches!(r, Err(ObjectError::Rule(_)));
        // The valid base decodes.
        assert!(decode(base()).is_ok());
        assert!(rule(decode(with_field(
            &base(),
            KEY_SEQUENCE,
            Some(write_u64(0))
        ))));
        // Sequence 2 without a parent, and sequence 1 with one.
        assert!(rule(decode(with_field(
            &base(),
            KEY_SEQUENCE,
            Some(write_u64(2))
        ))));
        assert!(rule(decode(with_field(
            &base(),
            KEY_PARENT,
            Some(write_bytes(&[1; 32]))
        ))));
        // Not in order, a duplicate, and an overlap of the two arrays.
        let unsorted = write_array(&[raw_change(3), raw_change(1)]);
        assert!(rule(decode(with_field(
            &base(),
            KEY_CHANGED,
            Some(unsorted)
        ))));
        let twice = write_array(&[raw_change(1), raw_change(1)]);
        assert!(rule(decode(with_field(&base(), KEY_CHANGED, Some(twice)))));
        let fields = with_field(&base(), KEY_CHANGED, Some(write_array(&[raw_change(1)])));
        let both = with_field(
            &fields,
            KEY_DELETED,
            Some(write_array(&[write_bytes(&[1; 32])])),
        );
        assert!(rule(decode(both)));
    }

    #[test]
    fn decode_rejects_missing_fields_and_wrong_shapes() {
        let decode = |fields: Vec<(u64, Vec<u8>)>| {
            DeltaEntry::decode(&raw_object(DeltaEntry::TYPE_ID, &fields))
        };
        for key in [
            KEY_SOURCE_ID,
            KEY_SEQUENCE,
            KEY_SNAPSHOT_ID,
            KEY_TIME,
            KEY_CHANGED,
            KEY_DELETED,
        ] {
            assert_eq!(
                decode(with_field(&base(), key, None)),
                Err(ObjectError::MissingField(key))
            );
        }
        let bad = |key, value| decode(with_field(&base(), key, Some(value)));
        assert_eq!(
            bad(KEY_SOURCE_ID, write_bytes(&[2; 17])),
            Err(ObjectError::BadField(KEY_SOURCE_ID))
        );
        assert_eq!(
            bad(KEY_SNAPSHOT_ID, write_bytes(&[3; 15])),
            Err(ObjectError::BadField(KEY_SNAPSHOT_ID))
        );
        assert_eq!(
            bad(KEY_CURSOR, write_text("x")),
            Err(ObjectError::BadField(KEY_CURSOR))
        );
        assert_eq!(
            bad(KEY_SEQUENCE, write_i64(-1)),
            Err(ObjectError::BadField(KEY_SEQUENCE))
        );
        assert_eq!(
            bad(KEY_DELETED, write_array(&[write_bytes(&[1; 31])])),
            Err(ObjectError::BadField(KEY_DELETED))
        );
        // A change with 2 items, with a short key, and with a short content ID.
        let two = write_array(&[write_array(&[write_bytes(&[1; 32]), write_bytes(&[1; 32])])]);
        assert_eq!(
            bad(KEY_CHANGED, two),
            Err(ObjectError::BadField(KEY_CHANGED))
        );
        let short_key = write_array(&[write_array(&[
            write_bytes(&[1; 31]),
            write_bytes(&[1; 32]),
            write_array(&[]),
        ])]);
        assert_eq!(
            bad(KEY_CHANGED, short_key),
            Err(ObjectError::BadField(KEY_CHANGED))
        );
        let short_content = write_array(&[write_array(&[
            write_bytes(&[1; 32]),
            write_bytes(&[1; 32]),
            write_array(&[write_bytes(&[1; 5])]),
        ])]);
        assert_eq!(
            bad(KEY_CHANGED, short_content),
            Err(ObjectError::BadField(KEY_CHANGED))
        );
        assert_eq!(
            bad(KEY_CHANGED, write_bytes(&[])),
            Err(ObjectError::BadField(KEY_CHANGED))
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let fields = with_field(&base(), 99, Some(write_text("future")));
        assert!(DeltaEntry::decode(&raw_object(DeltaEntry::TYPE_ID, &fields)).is_ok());
    }
}
