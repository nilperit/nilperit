//! Item record (format.md 5.4).
//!
//! An item record describes one item of a source. It is an enveloped object
//! with key class R.

use alloc::string::String;
use alloc::vec::Vec;

use crate::canonical;
use crate::content_object::ObjectError;
use crate::envelope::Envelope;
use crate::fields::{
    Fields, read_array, read_bytes, read_hashes, read_i64, read_text, read_u64, write_bytes,
    write_hashes, write_i64, write_map, write_text, write_u64,
};
use crate::ids::{ObjectId, SourceId};
use crate::object_type;

const KEY_SOURCE_ID: u64 = 1;
const KEY_NATIVE_ID: u64 = 2;
const KEY_TITLE: u64 = 3;
const KEY_MODIFIED: u64 = 4;
const KEY_CREATED: u64 = 5;
const KEY_SIZE: u64 = 6;
const KEY_MEDIA_TYPE: u64 = 7;
const KEY_METADATA: u64 = 8;
const KEY_CONTENT: u64 = 9;

/// One item of a source (format.md 5.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemRecord {
    /// The source of the item.
    pub source_id: SourceId,
    /// The ID that the source gives to the item. At least 1 byte (format.md 5.4.5.2).
    pub native_id: Vec<u8>,
    /// A name to show.
    pub title: String,
    /// The time of the last change at the source, in milliseconds since 1970.
    pub modified: Option<i64>,
    /// The time of creation at the source, in milliseconds since 1970.
    pub created: Option<i64>,
    /// The sum of the sizes of the content objects, in bytes.
    pub size: u64,
    /// The media type.
    pub media_type: Option<String>,
    /// Metadata that only the connector understands: the bytes of one
    /// deterministic CBOR item. The vault does not interpret it.
    pub metadata: Option<Vec<u8>>,
    /// The content objects of the item, in the order that the connector defines.
    pub content: Vec<ObjectId>,
}

impl ItemRecord {
    /// The object type ID.
    pub const TYPE_ID: u32 = object_type::ITEM_RECORD;
    /// The schema version that this code writes.
    pub const SCHEMA: u32 = 1;

    /// Encodes the item record. The result is the stored bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        if self.native_id.is_empty() {
            return Err(ObjectError::BadField(KEY_NATIVE_ID));
        }
        let mut fields = alloc::vec![
            (KEY_SOURCE_ID, write_bytes(self.source_id.as_bytes())),
            (KEY_NATIVE_ID, write_bytes(&self.native_id)),
            (KEY_TITLE, write_text(&self.title)),
        ];
        if let Some(t) = self.modified {
            fields.push((KEY_MODIFIED, write_i64(t)));
        }
        if let Some(t) = self.created {
            fields.push((KEY_CREATED, write_i64(t)));
        }
        fields.push((KEY_SIZE, write_u64(self.size)));
        if let Some(media_type) = &self.media_type {
            fields.push((KEY_MEDIA_TYPE, write_text(media_type)));
        }
        if let Some(metadata) = &self.metadata {
            canonical::check(metadata).map_err(|_| ObjectError::BadField(KEY_METADATA))?;
            fields.push((KEY_METADATA, metadata.clone()));
        }
        fields.push((
            KEY_CONTENT,
            write_hashes(self.content.iter().map(|id| id.as_bytes().as_slice())),
        ));
        Ok(Envelope::encode(
            Self::TYPE_ID,
            Self::SCHEMA,
            &write_map(&fields),
        )?)
    }

    /// Decodes stored bytes. Ignores unknown fields (format.md 4.5) and rejects a
    /// missing required field or a field of another type or size.
    pub fn decode(stored: &[u8]) -> Result<Self, ObjectError> {
        let (_, fields) = Fields::open(stored, Self::TYPE_ID, Self::SCHEMA)?;
        let native_id = read_bytes(fields.require(KEY_NATIVE_ID)?, KEY_NATIVE_ID)?;
        if native_id.is_empty() {
            return Err(ObjectError::BadField(KEY_NATIVE_ID));
        }
        Ok(Self {
            source_id: SourceId::from_bytes(read_array(
                fields.require(KEY_SOURCE_ID)?,
                KEY_SOURCE_ID,
            )?),
            native_id,
            title: read_text(fields.require(KEY_TITLE)?, KEY_TITLE)?,
            modified: fields
                .get(KEY_MODIFIED)
                .map(|r| read_i64(r, KEY_MODIFIED))
                .transpose()?,
            created: fields
                .get(KEY_CREATED)
                .map(|r| read_i64(r, KEY_CREATED))
                .transpose()?,
            size: read_u64(fields.require(KEY_SIZE)?, KEY_SIZE)?,
            media_type: fields
                .get(KEY_MEDIA_TYPE)
                .map(|r| read_text(r, KEY_MEDIA_TYPE))
                .transpose()?,
            // The whole object is deterministic CBOR (checked by the envelope),
            // so this slice is one deterministic item.
            metadata: fields.get(KEY_METADATA).map(<[u8]>::to_vec),
            content: read_hashes(fields.require(KEY_CONTENT)?, KEY_CONTENT)?
                .into_iter()
                .map(ObjectId::from_bytes)
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::fields::{raw_object, with_field, write_array};

    fn full() -> ItemRecord {
        ItemRecord {
            source_id: SourceId::from_bytes([2; 16]),
            native_id: b"a/b.txt".to_vec(),
            title: String::from("b.txt"),
            modified: Some(1_700_000_000_000),
            created: Some(-5),
            size: 12,
            media_type: Some(String::from("text/plain")),
            metadata: Some(vec![0xa1, 0x61, b'k', 0x01]), // {"k": 1}
            content: vec![ObjectId::from_bytes([7; 32]), ObjectId::from_bytes([8; 32])],
        }
    }

    fn minimal() -> ItemRecord {
        ItemRecord {
            source_id: SourceId::from_bytes([2; 16]),
            native_id: vec![0],
            title: String::new(),
            modified: None,
            created: None,
            size: 0,
            media_type: None,
            metadata: None,
            content: Vec::new(),
        }
    }

    // The required fields, valid, as raw fields.
    fn base() -> Vec<(u64, Vec<u8>)> {
        vec![
            (KEY_SOURCE_ID, write_bytes(&[2; 16])),
            (KEY_NATIVE_ID, write_bytes(b"a")),
            (KEY_TITLE, write_text("t")),
            (KEY_SIZE, write_u64(0)),
            (KEY_CONTENT, write_array(&[])),
        ]
    }

    #[test]
    fn round_trip() {
        for record in [full(), minimal()] {
            assert_eq!(
                ItemRecord::decode(&record.encode().unwrap()).unwrap(),
                record
            );
        }
        // The same record always gives the same bytes.
        assert_eq!(full().encode().unwrap(), full().encode().unwrap());
    }

    #[test]
    fn times_can_be_negative_and_extreme() {
        for t in [i64::MIN, -1, 0, i64::MAX] {
            let mut record = minimal();
            record.modified = Some(t);
            record.created = Some(t);
            assert_eq!(
                ItemRecord::decode(&record.encode().unwrap()).unwrap(),
                record
            );
        }
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let fields = with_field(&base(), 99, Some(write_text("future")));
        let record = ItemRecord::decode(&raw_object(ItemRecord::TYPE_ID, &fields)).unwrap();
        assert_eq!(record.title, "t");
    }

    #[test]
    fn rejects_a_missing_required_field() {
        for key in [
            KEY_SOURCE_ID,
            KEY_NATIVE_ID,
            KEY_TITLE,
            KEY_SIZE,
            KEY_CONTENT,
        ] {
            let stored = raw_object(ItemRecord::TYPE_ID, &with_field(&base(), key, None));
            assert_eq!(
                ItemRecord::decode(&stored),
                Err(ObjectError::MissingField(key)),
                "{key}"
            );
        }
    }

    #[test]
    fn rejects_fields_of_the_wrong_type_or_size() {
        let cases: [(u64, Vec<u8>); 12] = [
            (KEY_SOURCE_ID, write_bytes(&[2; 15])),
            (KEY_SOURCE_ID, write_text("x")),
            (KEY_NATIVE_ID, write_bytes(&[])),
            (KEY_NATIVE_ID, write_text("a")),
            (KEY_TITLE, write_bytes(b"t")),
            (KEY_MODIFIED, write_text("now")),
            (KEY_CREATED, write_bytes(&[1])),
            (KEY_SIZE, write_i64(-1)),
            (KEY_MEDIA_TYPE, write_bytes(b"text/plain")),
            (KEY_CONTENT, write_bytes(&[7; 32])),
            (KEY_CONTENT, write_array(&[write_bytes(&[7; 31])])),
            (KEY_CONTENT, write_array(&[write_text("id")])),
        ];
        for (key, value) in cases {
            let stored = raw_object(ItemRecord::TYPE_ID, &with_field(&base(), key, Some(value)));
            assert_eq!(
                ItemRecord::decode(&stored),
                Err(ObjectError::BadField(key)),
                "{key}"
            );
        }
    }

    #[test]
    fn rejects_another_type_and_another_schema() {
        let other = Envelope::encode(5, 1, &write_map(&base())).unwrap();
        assert_eq!(ItemRecord::decode(&other), Err(ObjectError::WrongType(5)));
        let schema2 = Envelope::encode(ItemRecord::TYPE_ID, 2, &write_map(&base())).unwrap();
        assert_eq!(
            ItemRecord::decode(&schema2),
            Err(ObjectError::UnsupportedSchema(2))
        );
    }

    #[test]
    fn encode_rejects_an_empty_native_id_and_bad_metadata() {
        let mut record = full();
        record.native_id.clear();
        assert_eq!(record.encode(), Err(ObjectError::BadField(KEY_NATIVE_ID)));

        for bad in [
            vec![],
            vec![0x18, 0x00],
            vec![0xf9, 0x3c, 0x00],
            vec![0x00, 0x00],
        ] {
            let mut record = full();
            record.metadata = Some(bad);
            assert_eq!(record.encode(), Err(ObjectError::BadField(KEY_METADATA)));
        }
    }
}
