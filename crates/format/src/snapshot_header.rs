//! Snapshot header (format.md 5.9).
//!
//! A snapshot header commits a snapshot of a source. It is an enveloped object
//! with key class W. It is stored in a file outside the packs (format.md 5.9.4).

use alloc::vec::Vec;

use crate::content_object::ObjectError;
use crate::envelope::Envelope;
use crate::fields::{
    Fields, read_array, read_i64, read_u64, write_bytes, write_i64, write_map, write_u64,
};
use crate::ids::{ObjectId, SnapshotId, SourceId};
use crate::object_type;
use crate::vault_config::VaultEssentials;

const KEY_SOURCE_ID: u64 = 1;
const KEY_SNAPSHOT_ID: u64 = 2;
const KEY_TIME: u64 = 3;
const KEY_ITEM_MAP_ROOT: u64 = 4;
const KEY_PARENT_SNAPSHOT: u64 = 5;
const KEY_JOURNAL_ENTRY: u64 = 6;
const KEY_JOURNAL_SEQUENCE: u64 = 7;
const KEY_STATISTICS: u64 = 8;
const KEY_VAULT: u64 = 9;

const STAT_ITEMS: u64 = 1;
const STAT_SIZE: u64 = 2;

/// The numbers about a snapshot (format.md 5.9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statistics {
    /// The number of items that exist after the snapshot.
    pub items: u64,
    /// The sum of their sizes, in bytes.
    pub size: u64,
}

/// A snapshot header (format.md 5.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotHeader {
    /// The source of the snapshot.
    pub source_id: SourceId,
    /// The ID of the snapshot.
    pub snapshot_id: SnapshotId,
    /// The time of the snapshot, in milliseconds since 1970.
    pub time: i64,
    /// The root of the item map. Not present while the writer makes no item maps.
    pub item_map_root: Option<ObjectId>,
    /// The previous snapshot of the source. Not present in the first snapshot.
    pub parent_snapshot: Option<SnapshotId>,
    /// The journal entry that is the head after this snapshot.
    pub journal_entry: ObjectId,
    /// The sequence number of that journal entry.
    pub journal_sequence: u64,
    /// The statistics. Not present when the writer has none.
    pub statistics: Option<Statistics>,
    /// A copy of the essential fields of the vault config.
    pub vault: VaultEssentials,
}

impl SnapshotHeader {
    /// The object type ID.
    pub const TYPE_ID: u32 = object_type::SNAPSHOT_HEADER;
    /// The schema version that this code writes.
    pub const SCHEMA: u32 = 1;

    /// Encodes the snapshot header. The result is the stored bytes, which a
    /// writer then encrypts into the file (format.md 3.3.7.1).
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        let mut fields = alloc::vec![
            (KEY_SOURCE_ID, write_bytes(self.source_id.as_bytes())),
            (KEY_SNAPSHOT_ID, write_bytes(self.snapshot_id.as_bytes())),
            (KEY_TIME, write_i64(self.time)),
        ];
        if let Some(root) = &self.item_map_root {
            fields.push((KEY_ITEM_MAP_ROOT, write_bytes(root.as_bytes())));
        }
        if let Some(parent) = &self.parent_snapshot {
            fields.push((KEY_PARENT_SNAPSHOT, write_bytes(parent.as_bytes())));
        }
        fields.push((
            KEY_JOURNAL_ENTRY,
            write_bytes(self.journal_entry.as_bytes()),
        ));
        fields.push((KEY_JOURNAL_SEQUENCE, write_u64(self.journal_sequence)));
        if let Some(stats) = &self.statistics {
            fields.push((
                KEY_STATISTICS,
                write_map(&[
                    (STAT_ITEMS, write_u64(stats.items)),
                    (STAT_SIZE, write_u64(stats.size)),
                ]),
            ));
        }
        fields.push((KEY_VAULT, self.vault.encode_map()));
        Ok(Envelope::encode(
            Self::TYPE_ID,
            Self::SCHEMA,
            &write_map(&fields),
        )?)
    }

    /// Decodes stored bytes. Ignores unknown fields (format.md 4.5). Rejects a
    /// format version that is newer than this code and an unknown algorithm name.
    pub fn decode(stored: &[u8]) -> Result<Self, ObjectError> {
        let (_, fields) = Fields::open(stored, Self::TYPE_ID, Self::SCHEMA)?;
        let statistics = fields
            .get(KEY_STATISTICS)
            .map(|raw| {
                let stats = Fields::of_map(raw, KEY_STATISTICS)?;
                Ok::<_, ObjectError>(Statistics {
                    items: read_u64(stats.require(STAT_ITEMS)?, KEY_STATISTICS)?,
                    size: read_u64(stats.require(STAT_SIZE)?, KEY_STATISTICS)?,
                })
            })
            .transpose()?;
        Ok(Self {
            source_id: SourceId::from_bytes(read_array(
                fields.require(KEY_SOURCE_ID)?,
                KEY_SOURCE_ID,
            )?),
            snapshot_id: SnapshotId::from_bytes(read_array(
                fields.require(KEY_SNAPSHOT_ID)?,
                KEY_SNAPSHOT_ID,
            )?),
            time: read_i64(fields.require(KEY_TIME)?, KEY_TIME)?,
            item_map_root: fields
                .get(KEY_ITEM_MAP_ROOT)
                .map(|r| read_array(r, KEY_ITEM_MAP_ROOT).map(ObjectId::from_bytes))
                .transpose()?,
            parent_snapshot: fields
                .get(KEY_PARENT_SNAPSHOT)
                .map(|r| read_array(r, KEY_PARENT_SNAPSHOT).map(SnapshotId::from_bytes))
                .transpose()?,
            journal_entry: ObjectId::from_bytes(read_array(
                fields.require(KEY_JOURNAL_ENTRY)?,
                KEY_JOURNAL_ENTRY,
            )?),
            journal_sequence: read_u64(
                fields.require(KEY_JOURNAL_SEQUENCE)?,
                KEY_JOURNAL_SEQUENCE,
            )?,
            statistics,
            vault: VaultEssentials::decode_map(fields.require(KEY_VAULT)?, KEY_VAULT)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use super::*;
    use crate::fields::{raw_object, with_field, write_text};
    use crate::ids::VaultId;

    fn vault() -> VaultEssentials {
        VaultEssentials {
            format_version: 0,
            vault_id: VaultId::from_bytes([0x11; 16]),
            encryption: String::from("xchacha20-poly1305"),
            hash: String::from("blake3"),
            key_encapsulation: String::from("x-wing-draft-06"),
            read_public_key: vec![1, 2, 3],
        }
    }

    fn minimal() -> SnapshotHeader {
        SnapshotHeader {
            source_id: SourceId::from_bytes([2; 16]),
            snapshot_id: SnapshotId::from_bytes([3; 16]),
            time: 1_700_000_001_000,
            item_map_root: None,
            parent_snapshot: None,
            journal_entry: ObjectId::from_bytes([4; 32]),
            journal_sequence: 1,
            statistics: None,
            vault: vault(),
        }
    }

    fn full() -> SnapshotHeader {
        SnapshotHeader {
            item_map_root: Some(ObjectId::from_bytes([5; 32])),
            parent_snapshot: Some(SnapshotId::from_bytes([6; 16])),
            statistics: Some(Statistics {
                items: u64::MAX,
                size: 0,
            }),
            journal_sequence: 77,
            ..minimal()
        }
    }

    // The required fields, valid, as raw fields.
    fn base() -> Vec<(u64, Vec<u8>)> {
        vec![
            (KEY_SOURCE_ID, write_bytes(&[2; 16])),
            (KEY_SNAPSHOT_ID, write_bytes(&[3; 16])),
            (KEY_TIME, write_i64(0)),
            (KEY_JOURNAL_ENTRY, write_bytes(&[4; 32])),
            (KEY_JOURNAL_SEQUENCE, write_u64(1)),
            (KEY_VAULT, vault().encode_map()),
        ]
    }

    #[test]
    fn round_trip() {
        for header in [minimal(), full()] {
            assert_eq!(
                SnapshotHeader::decode(&header.encode().unwrap()).unwrap(),
                header
            );
        }
        assert_eq!(full().encode().unwrap(), full().encode().unwrap());
    }

    #[test]
    fn rejects_a_missing_required_field() {
        for key in [
            KEY_SOURCE_ID,
            KEY_SNAPSHOT_ID,
            KEY_TIME,
            KEY_JOURNAL_ENTRY,
            KEY_JOURNAL_SEQUENCE,
            KEY_VAULT,
        ] {
            let stored = raw_object(SnapshotHeader::TYPE_ID, &with_field(&base(), key, None));
            assert_eq!(
                SnapshotHeader::decode(&stored),
                Err(ObjectError::MissingField(key)),
                "{key}"
            );
        }
    }

    #[test]
    fn rejects_fields_of_the_wrong_type_or_size() {
        let decode = |key, value| {
            SnapshotHeader::decode(&raw_object(
                SnapshotHeader::TYPE_ID,
                &with_field(&base(), key, Some(value)),
            ))
        };
        assert_eq!(
            decode(KEY_SOURCE_ID, write_bytes(&[2; 8])),
            Err(ObjectError::BadField(KEY_SOURCE_ID))
        );
        assert_eq!(
            decode(KEY_SNAPSHOT_ID, write_bytes(&[3; 32])),
            Err(ObjectError::BadField(KEY_SNAPSHOT_ID))
        );
        assert_eq!(
            decode(KEY_ITEM_MAP_ROOT, write_bytes(&[5; 16])),
            Err(ObjectError::BadField(KEY_ITEM_MAP_ROOT))
        );
        assert_eq!(
            decode(KEY_PARENT_SNAPSHOT, write_bytes(&[6; 32])),
            Err(ObjectError::BadField(KEY_PARENT_SNAPSHOT))
        );
        assert_eq!(
            decode(KEY_JOURNAL_ENTRY, write_text("x")),
            Err(ObjectError::BadField(KEY_JOURNAL_ENTRY))
        );
        assert_eq!(
            decode(KEY_VAULT, write_bytes(&[1])),
            Err(ObjectError::BadField(KEY_VAULT))
        );
        // Statistics must have both numbers.
        let only_items = write_map(&[(STAT_ITEMS, write_u64(1))]);
        assert_eq!(
            decode(KEY_STATISTICS, only_items),
            Err(ObjectError::MissingField(STAT_SIZE))
        );
        assert_eq!(
            decode(KEY_STATISTICS, write_u64(1)),
            Err(ObjectError::BadField(KEY_STATISTICS))
        );
    }

    #[test]
    fn rejects_a_newer_format_version_and_unknown_algorithms() {
        let mut newer = vault();
        newer.format_version = 1;
        let fields = with_field(&base(), KEY_VAULT, Some(newer.encode_map()));
        assert_eq!(
            SnapshotHeader::decode(&raw_object(SnapshotHeader::TYPE_ID, &fields)),
            Err(ObjectError::NewerFormat(1))
        );
        for (encryption, hash) in [("aes-gcm", "blake3"), ("xchacha20-poly1305", "sha256")] {
            let mut other = vault();
            other.encryption = String::from(encryption);
            other.hash = String::from(hash);
            let fields = with_field(&base(), KEY_VAULT, Some(other.encode_map()));
            assert_eq!(
                SnapshotHeader::decode(&raw_object(SnapshotHeader::TYPE_ID, &fields)),
                Err(ObjectError::UnknownAlgorithm)
            );
        }
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let fields = with_field(&base(), 99, Some(write_text("future")));
        assert!(SnapshotHeader::decode(&raw_object(SnapshotHeader::TYPE_ID, &fields)).is_ok());
    }

    #[test]
    fn rejects_another_type() {
        let other = Envelope::encode(5, 1, &write_map(&base())).unwrap();
        assert_eq!(
            SnapshotHeader::decode(&other),
            Err(ObjectError::WrongType(5))
        );
    }
}
