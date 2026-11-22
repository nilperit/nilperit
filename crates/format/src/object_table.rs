//! The object table of a pack (format.md 6.3.1 and 6.7.3).
//!
//! The object table is an enveloped object with type ID 3 and schema version 1.
//! Its body has one field: key 1, an array of entries. Each entry is an array of
//! 7 items. This module reads and writes the plaintext of the object table and
//! checks the rules of format.md 6.7.3.5. The encryption is not here.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::envelope::Envelope;
use crate::ids::{HASH_LEN, ObjectId};
use crate::object_type;
use crate::pack::{PACKED_OBJECT_OVERHEAD, PackError};

const KEY_ENTRIES: u64 = 1;
const ENTRY_ITEMS: u64 = 7;

/// The key class of an object (format.md 3.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// Only the holder of the read key can open the object.
    R,
    /// The node and the owner can open the object.
    W,
}

impl KeyClass {
    /// The text in the object table.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R => "R",
            Self::W => "W",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "R" => Some(Self::R),
            "W" => Some(Self::W),
            _ => None,
        }
    }
}

/// The compression algorithm of an object (format.md 6.6.2).
///
/// A name that this code does not know is an error of the whole pack
/// (format.md 6.6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// The bytes are not changed.
    None,
    /// One DEFLATE stream (RFC 1951).
    Deflate,
}

impl Compression {
    /// The name in the object table.
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Deflate => "deflate",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "deflate" => Some(Self::Deflate),
            _ => None,
        }
    }
}

/// One entry of the object table (format.md 6.3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectTableEntry {
    /// The object ID.
    pub object_id: ObjectId,
    /// The type ID.
    pub object_type: u32,
    /// The key class.
    pub key_class: KeyClass,
    /// The position of the packed object, counted from the start of the pack file.
    pub offset: u64,
    /// The size of the packed object: nonce, ciphertext and tag.
    pub packed_size: u32,
    /// The compression algorithm.
    pub compression: Compression,
    /// The size of the stored bytes: the size before compression.
    pub unpacked_size: u32,
}

/// The object table of a pack.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ObjectTable {
    /// The entries, in the order of the body.
    pub entries: Vec<ObjectTableEntry>,
}

impl ObjectTable {
    /// The type ID of the object table.
    pub const TYPE_ID: u32 = object_type::OBJECT_TABLE;
    /// The schema version that this code writes.
    pub const SCHEMA: u32 = 1;

    /// Encodes the plaintext of the object table: the encoded envelope.
    pub fn encode(&self) -> Result<Vec<u8>, PackError> {
        let bad = |_| PackError::Malformed("object table");
        let mut body = Vec::with_capacity(self.entries.len() * 64 + 8);
        let mut e = minicbor::Encoder::new(&mut body);
        // Writing to a `Vec` cannot fail.
        e.map(1)
            .and_then(|e| e.u64(KEY_ENTRIES))
            .and_then(|e| e.array(self.entries.len() as u64))
            .map_err(bad)?;
        for entry in &self.entries {
            e.array(ENTRY_ITEMS)
                .and_then(|e| e.bytes(entry.object_id.as_bytes()))
                .and_then(|e| e.u32(entry.object_type))
                .and_then(|e| e.str(entry.key_class.as_str()))
                .and_then(|e| e.u64(entry.offset))
                .and_then(|e| e.u32(entry.packed_size))
                .and_then(|e| e.str(entry.compression.name()))
                .and_then(|e| e.u32(entry.unpacked_size))
                .map_err(bad)?;
        }
        Ok(Envelope::encode(Self::TYPE_ID, Self::SCHEMA, &body)?)
    }

    /// Decodes the plaintext of an object table.
    ///
    /// This checks the shape of each entry. It does not check how the entries
    /// fit into a pack: use [`ObjectTable::validate`] for that.
    pub fn decode(stored: &[u8]) -> Result<Self, PackError> {
        let envelope = Envelope::decode(stored)?;
        if envelope.object_type != Self::TYPE_ID {
            return Err(PackError::Malformed("object table type"));
        }
        if envelope.schema != Self::SCHEMA {
            return Err(PackError::UnsupportedSchema(envelope.schema));
        }
        let raw = envelope
            .fields()?
            .into_iter()
            .find_map(|(key, raw)| (key == KEY_ENTRIES).then_some(raw))
            .ok_or(PackError::Malformed("object table entries"))?;

        let bad = |_| PackError::Malformed("object table entry");
        let mut d = minicbor::Decoder::new(raw);
        let count = d
            .array()
            .map_err(bad)?
            .ok_or(PackError::Malformed("object table entries"))?;
        // The input is deterministic CBOR, so every entry uses at least one byte.
        let mut entries = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(raw.len()));
        for _ in 0..count {
            if d.array().map_err(bad)? != Some(ENTRY_ITEMS) {
                return Err(PackError::Malformed("object table entry"));
            }
            let id: [u8; HASH_LEN] = d
                .bytes()
                .map_err(bad)?
                .try_into()
                .map_err(|_| PackError::Malformed("object table entry"))?;
            let object_type = d.u32().map_err(bad)?;
            let key_class = KeyClass::from_str(d.str().map_err(bad)?)
                .ok_or(PackError::Malformed("key class"))?;
            let offset = d.u64().map_err(bad)?;
            let packed_size = d.u32().map_err(bad)?;
            let compression =
                Compression::from_name(d.str().map_err(bad)?).ok_or(PackError::UnknownAlgorithm)?;
            let unpacked_size = d.u32().map_err(bad)?;
            entries.push(ObjectTableEntry {
                object_id: ObjectId::from_bytes(id),
                object_type,
                key_class,
                offset,
                packed_size,
                compression,
                unpacked_size,
            });
        }
        Ok(Self { entries })
    }

    /// Checks how the entries fit into a pack (format.md 6.7.3.1 and 6.7.3.5).
    ///
    /// `header_len` is the length of the header, `trailer_offset` the position of
    /// the trailer, and `seal_size` the size of the sealed pack key.
    pub fn validate(
        &self,
        header_len: usize,
        trailer_offset: u64,
        seal_size: usize,
    ) -> Result<(), PackError> {
        let mut position = header_len as u64;
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if entry.offset != position {
                return Err(PackError::Layout(
                    "packed objects are not in order without gaps",
                ));
            }
            if entry.packed_size < PACKED_OBJECT_OVERHEAD {
                return Err(PackError::Layout(
                    "packed object is smaller than nonce and tag",
                ));
            }
            if !seen.insert(entry.object_id) {
                return Err(PackError::Layout("object ID occurs more than once"));
            }
            if entry.key_class == KeyClass::R && seal_size == 0 {
                return Err(PackError::Layout(
                    "R object in a pack without a sealed pack key",
                ));
            }
            position = position
                .checked_add(u64::from(entry.packed_size))
                .ok_or(PackError::Layout("packed objects are too large"))?;
        }
        if position != trailer_offset {
            return Err(PackError::Layout(
                "last packed object does not end at the trailer",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::pack::tests::{PACK_HEX, unhex};

    // The plaintext of the object table of format.md A.8.3 (109 bytes).
    const TABLE_HEX: &str = "a30003010102a1018287582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e016152183a182f676465666c61746505875820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e0261571869187a646e6f6e651852";

    fn id(byte: u8) -> ObjectId {
        ObjectId::from_bytes([byte; 32])
    }

    fn entry(byte: u8, offset: u64, packed: u32) -> ObjectTableEntry {
        ObjectTableEntry {
            object_id: id(byte),
            object_type: 1,
            key_class: KeyClass::W,
            offset,
            packed_size: packed,
            compression: Compression::None,
            unpacked_size: packed.saturating_sub(40),
        }
    }

    #[test]
    fn reads_and_writes_the_appendix_vector() {
        let plain = unhex(TABLE_HEX);
        assert_eq!(plain.len(), 109);
        let table = ObjectTable::decode(&plain).unwrap();
        assert_eq!(table.entries.len(), 2);

        let chunk = &table.entries[0];
        assert_eq!(chunk.object_type, 1);
        assert_eq!(chunk.key_class, KeyClass::R);
        assert_eq!(
            (chunk.offset, chunk.packed_size, chunk.unpacked_size),
            (58, 47, 5)
        );
        assert_eq!(chunk.compression, Compression::Deflate);
        assert_eq!(
            chunk.object_id.to_string(),
            "09c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e"
        );

        let content = &table.entries[1];
        assert_eq!(content.object_type, 2);
        assert_eq!(content.key_class, KeyClass::W);
        assert_eq!(
            (content.offset, content.packed_size, content.unpacked_size),
            (105, 122, 82)
        );
        assert_eq!(content.compression, Compression::None);

        // Deterministic: the same table gives the same bytes.
        assert_eq!(table.encode().unwrap(), plain);

        // The table fits into the pack of the vector: header 58, trailer at 227, seal of 4 bytes.
        table.validate(58, 227, 4).unwrap();
        assert_eq!(unhex(PACK_HEX).len(), 408);
    }

    #[test]
    fn round_trip_with_large_values() {
        let table = ObjectTable {
            entries: vec![ObjectTableEntry {
                object_id: id(9),
                object_type: u32::MAX,
                key_class: KeyClass::R,
                offset: u64::MAX,
                packed_size: u32::MAX,
                compression: Compression::Deflate,
                unpacked_size: u32::MAX,
            }],
        };
        assert_eq!(
            ObjectTable::decode(&table.encode().unwrap()).unwrap(),
            table
        );
        let empty = ObjectTable::default();
        assert_eq!(
            ObjectTable::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn decode_rejects_an_unknown_compression_name() {
        // One valid entry, but with the compression name "zstd".
        let mut body = vec![0xa1, 0x01, 0x81, 0x87, 0x58, 0x20];
        body.extend([7u8; 32]);
        body.extend([
            0x01, 0x61, b'R', 0x00, 0x18, 0x28, 0x64, b'z', b's', b't', b'd', 0x00,
        ]);
        let stored = Envelope::encode(3, 1, &body).unwrap();
        assert_eq!(
            ObjectTable::decode(&stored),
            Err(PackError::UnknownAlgorithm)
        );
    }

    #[test]
    fn decode_rejects_wrong_shapes() {
        // Another object type.
        let other = Envelope::encode(2, 1, &[0xa0]).unwrap();
        assert_eq!(
            ObjectTable::decode(&other),
            Err(PackError::Malformed("object table type"))
        );
        // Unknown schema version.
        let schema2 = Envelope::encode(3, 2, &[0xa1, 0x01, 0x80]).unwrap();
        assert_eq!(
            ObjectTable::decode(&schema2),
            Err(PackError::UnsupportedSchema(2))
        );
        // No entries field.
        let none = Envelope::encode(3, 1, &[0xa0]).unwrap();
        assert_eq!(
            ObjectTable::decode(&none),
            Err(PackError::Malformed("object table entries"))
        );
        // An entry with 6 items.
        let six = Envelope::encode(
            3,
            1,
            &[0xa1, 0x01, 0x81, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        )
        .unwrap();
        assert_eq!(
            ObjectTable::decode(&six),
            Err(PackError::Malformed("object table entry"))
        );

        // Entries that are wrong in one place each.
        let mut good = vec![0xa1, 0x01, 0x81, 0x87, 0x58, 0x20];
        good.extend([7u8; 32]);
        let tail = |key_class: &[u8], rest: &[u8]| {
            let mut v = good.clone();
            v.extend([0x01]); // type
            v.extend(key_class);
            v.extend(rest);
            Envelope::encode(3, 1, &v).unwrap()
        };
        // Valid reference entry: R, offset 0, packed 40, "none", unpacked 0.
        let valid = tail(
            &[0x61, b'R'],
            &[0x00, 0x18, 0x28, 0x64, b'n', b'o', b'n', b'e', 0x00],
        );
        assert!(ObjectTable::decode(&valid).is_ok());
        // Key class "X".
        let bad_class = tail(
            &[0x61, b'X'],
            &[0x00, 0x18, 0x28, 0x64, b'n', b'o', b'n', b'e', 0x00],
        );
        assert_eq!(
            ObjectTable::decode(&bad_class),
            Err(PackError::Malformed("key class"))
        );
        // Packed size that does not fit in 32 bits.
        let big = tail(
            &[0x61, b'R'],
            &[
                0x00, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x64, b'n', b'o', b'n',
                b'e', 0x00,
            ],
        );
        assert_eq!(
            ObjectTable::decode(&big),
            Err(PackError::Malformed("object table entry"))
        );
        // Object ID with 31 bytes.
        let mut short = vec![0xa1, 0x01, 0x81, 0x87, 0x58, 0x1f];
        short.extend([7u8; 31]);
        short.extend([
            0x01, 0x61, b'R', 0x00, 0x18, 0x28, 0x64, b'n', b'o', b'n', b'e', 0x00,
        ]);
        assert_eq!(
            ObjectTable::decode(&Envelope::encode(3, 1, &short).unwrap()),
            Err(PackError::Malformed("object table entry"))
        );
    }

    #[test]
    fn validate_accepts_a_good_layout_and_rejects_bad_ones() {
        let good = ObjectTable {
            entries: vec![entry(1, 100, 50), entry(2, 150, 60)],
        };
        assert!(good.validate(100, 210, 0).is_ok());
        // The body of an empty pack is empty.
        assert!(ObjectTable::default().validate(100, 100, 0).is_ok());
        assert!(ObjectTable::default().validate(100, 101, 0).is_err());

        // A gap, an overlap and a wrong start.
        let gap = ObjectTable {
            entries: vec![entry(1, 100, 50), entry(2, 151, 60)],
        };
        assert!(gap.validate(100, 211, 0).is_err());
        let overlap = ObjectTable {
            entries: vec![entry(1, 100, 50), entry(2, 149, 60)],
        };
        assert!(overlap.validate(100, 209, 0).is_err());
        let late = ObjectTable {
            entries: vec![entry(1, 101, 50)],
        };
        assert!(late.validate(100, 151, 0).is_err());
        // The last object must end at the trailer.
        assert!(good.validate(100, 209, 0).is_err());
        assert!(good.validate(100, 211, 0).is_err());
        // Too small for nonce and tag.
        let tiny = ObjectTable {
            entries: vec![entry(1, 100, 39)],
        };
        assert!(tiny.validate(100, 139, 0).is_err());
        // The same object ID twice.
        let dup = ObjectTable {
            entries: vec![entry(1, 100, 50), entry(1, 150, 60)],
        };
        assert!(dup.validate(100, 210, 0).is_err());
        // An R object needs a sealed pack key.
        let mut r = entry(1, 100, 50);
        r.key_class = KeyClass::R;
        let table = ObjectTable { entries: vec![r] };
        assert!(table.validate(100, 150, 0).is_err());
        assert!(table.validate(100, 150, 4).is_ok());
        // Offsets cannot overflow.
        let mut huge = entry(1, u64::MAX - 10, 50);
        huge.offset = u64::MAX - 10;
        let overflow = ObjectTable {
            entries: vec![huge],
        };
        assert!(overflow.validate(usize::MAX, u64::MAX, 0).is_err());
    }
}
