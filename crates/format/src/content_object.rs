//! Content object (format.md 5.3).
//!
//! A content object lists the chunks of one content, in order. It is an
//! enveloped object with key class W.
//!
//! Body fields (schema 1):
//!
//! | Key | Field | CBOR type |
//! |---|---|---|
//! | 1 | chunks | array of byte strings of 32 bytes |
//! | 2 | size | unsigned integer |
//! | 3 | content hash | byte string of 32 bytes |
//! | 4 | chunking profile | unsigned integer |

use alloc::vec::Vec;
use core::fmt;

use crate::envelope::{Envelope, EnvelopeError};
use crate::ids::{ContentHash, HASH_LEN, ObjectId};
use crate::object_type;

const KEY_CHUNKS: u64 = 1;
const KEY_SIZE: u64 = 2;
const KEY_CONTENT_HASH: u64 = 3;
const KEY_CHUNKING_PROFILE: u64 = 4;

/// Why an object could not be encoded or decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectError {
    /// The envelope is not valid.
    Envelope(EnvelopeError),
    /// The envelope has the type of another object.
    WrongType(u32),
    /// The schema version is not known to this code.
    UnsupportedSchema(u32),
    /// A required body field is missing. The value is its key.
    MissingField(u64),
    /// A body field has the wrong CBOR type or the wrong size. The value is its key.
    BadField(u64),
}

impl From<EnvelopeError> for ObjectError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "{e}"),
            Self::WrongType(t) => write!(f, "object has type {t}, not the expected type"),
            Self::UnsupportedSchema(s) => write!(f, "schema version {s} is not supported"),
            Self::MissingField(k) => write!(f, "field {k} is missing"),
            Self::BadField(k) => write!(f, "field {k} is not valid"),
        }
    }
}

impl core::error::Error for ObjectError {}

/// The chunks of one content (format.md 5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentObject {
    /// The IDs of the chunks, in order. A chunk ID can appear more than once.
    pub chunks: Vec<ObjectId>,
    /// The total size of the plaintext content, in bytes.
    pub size: u64,
    /// The keyed hash of the full plaintext.
    pub content_hash: ContentHash,
    /// The ID of the chunking profile in the vault config.
    pub chunking_profile: u32,
}

impl ContentObject {
    /// The object type ID.
    pub const TYPE_ID: u32 = object_type::CONTENT_OBJECT;
    /// The schema version that this code writes.
    pub const SCHEMA: u32 = 1;

    /// Encodes the object. The result is the stored bytes: use them for the
    /// object ID and for storage, and never encode a decoded object again.
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        let mut body = Vec::with_capacity(self.chunks.len() * (HASH_LEN + 2) + 64);
        let mut e = minicbor::Encoder::new(&mut body);
        // Keys are in ascending order, which is the deterministic order.
        // Writing to a `Vec` cannot fail.
        e.map(4)
            .and_then(|e| e.u64(KEY_CHUNKS))
            .and_then(|e| e.array(self.chunks.len() as u64))
            .map_err(|_| ObjectError::BadField(KEY_CHUNKS))?;
        for chunk in &self.chunks {
            e.bytes(chunk.as_bytes())
                .map_err(|_| ObjectError::BadField(KEY_CHUNKS))?;
        }
        e.u64(KEY_SIZE)
            .and_then(|e| e.u64(self.size))
            .and_then(|e| e.u64(KEY_CONTENT_HASH))
            .and_then(|e| e.bytes(self.content_hash.as_bytes()))
            .and_then(|e| e.u64(KEY_CHUNKING_PROFILE))
            .and_then(|e| e.u32(self.chunking_profile))
            .map_err(|_| ObjectError::BadField(KEY_SIZE))?;
        Ok(Envelope::encode(Self::TYPE_ID, Self::SCHEMA, &body)?)
    }

    /// Decodes stored bytes.
    ///
    /// A decoder ignores body fields that it does not know (format.md 4.5). It
    /// rejects a schema version that it does not know (format.md 4.5.1).
    pub fn decode(stored: &[u8]) -> Result<Self, ObjectError> {
        let envelope = Envelope::decode(stored)?;
        if envelope.object_type != Self::TYPE_ID {
            return Err(ObjectError::WrongType(envelope.object_type));
        }
        if envelope.schema != Self::SCHEMA {
            return Err(ObjectError::UnsupportedSchema(envelope.schema));
        }

        let (mut chunks, mut size, mut content_hash, mut profile) = (None, None, None, None);
        for (key, raw) in envelope.fields()? {
            match key {
                KEY_CHUNKS => chunks = Some(decode_chunks(raw)?),
                KEY_SIZE => size = Some(decode_u64(raw, KEY_SIZE)?),
                KEY_CONTENT_HASH => content_hash = Some(decode_hash(raw, KEY_CONTENT_HASH)?),
                KEY_CHUNKING_PROFILE => {
                    let value = decode_u64(raw, KEY_CHUNKING_PROFILE)?;
                    profile = Some(
                        u32::try_from(value)
                            .map_err(|_| ObjectError::BadField(KEY_CHUNKING_PROFILE))?,
                    );
                }
                _ => {}
            }
        }

        Ok(Self {
            chunks: chunks.ok_or(ObjectError::MissingField(KEY_CHUNKS))?,
            size: size.ok_or(ObjectError::MissingField(KEY_SIZE))?,
            content_hash: ContentHash::from_bytes(
                content_hash.ok_or(ObjectError::MissingField(KEY_CONTENT_HASH))?,
            ),
            chunking_profile: profile.ok_or(ObjectError::MissingField(KEY_CHUNKING_PROFILE))?,
        })
    }
}

fn decode_u64(raw: &[u8], key: u64) -> Result<u64, ObjectError> {
    minicbor::Decoder::new(raw)
        .u64()
        .map_err(|_| ObjectError::BadField(key))
}

fn decode_hash(raw: &[u8], key: u64) -> Result<[u8; HASH_LEN], ObjectError> {
    let bytes = minicbor::Decoder::new(raw)
        .bytes()
        .map_err(|_| ObjectError::BadField(key))?;
    bytes.try_into().map_err(|_| ObjectError::BadField(key))
}

fn decode_chunks(raw: &[u8]) -> Result<Vec<ObjectId>, ObjectError> {
    let bad = |_| ObjectError::BadField(KEY_CHUNKS);
    let mut d = minicbor::Decoder::new(raw);
    let count = d
        .array()
        .map_err(bad)?
        .ok_or(ObjectError::BadField(KEY_CHUNKS))?;
    // The input was checked as deterministic CBOR, so every item uses at least
    // one byte. The count cannot be larger than the input.
    let mut chunks = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(raw.len()));
    for _ in 0..count {
        let bytes = d.bytes().map_err(bad)?;
        let id: [u8; HASH_LEN] = bytes
            .try_into()
            .map_err(|_| ObjectError::BadField(KEY_CHUNKS))?;
        chunks.push(ObjectId::from_bytes(id));
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn sample() -> ContentObject {
        ContentObject {
            chunks: vec![
                ObjectId::from_bytes([0x11; 32]),
                ObjectId::from_bytes([0x22; 32]),
            ],
            size: 300_000,
            content_hash: ContentHash::from_bytes([0x33; 32]),
            chunking_profile: 1,
        }
    }

    // The vector of format.md A.6.
    fn sample_bytes() -> Vec<u8> {
        let mut v = vec![0xa3, 0x00, 0x02, 0x01, 0x01, 0x02];
        v.extend([0xa4, 0x01, 0x82]);
        for byte in [0x11, 0x22] {
            v.extend([0x58, 0x20]);
            v.extend([byte; 32]);
        }
        v.extend([0x02, 0x1a, 0x00, 0x04, 0x93, 0xe0]);
        v.extend([0x03, 0x58, 0x20]);
        v.extend([0x33; 32]);
        v.extend([0x04, 0x01]);
        v
    }

    // The hexadecimal string of format.md A.6.2.
    const APPENDIX_HEX: &str = "a30002010102a401825820111111111111111111111111111111111111111111111111111111111111111158202222222222222222222222222222222222222222222222222222222222222222021a000493e003582033333333333333333333333333333333333333333333333333333333333333330401";

    #[test]
    fn test_vector() {
        assert_eq!(sample().encode().unwrap(), sample_bytes());
        assert_eq!(ContentObject::decode(&sample_bytes()).unwrap(), sample());

        let hex: alloc::string::String = sample_bytes()
            .iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect();
        assert_eq!(hex, APPENDIX_HEX);
    }

    #[test]
    fn round_trip_edge_cases() {
        // No chunks (empty content).
        let empty = ContentObject {
            chunks: Vec::new(),
            size: 0,
            content_hash: ContentHash::from_bytes([0; 32]),
            chunking_profile: 0,
        };
        assert_eq!(
            ContentObject::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );

        // Repeated chunk IDs, and values that need long CBOR heads.
        let repeated = ContentObject {
            chunks: vec![ObjectId::from_bytes([7; 32]); 300],
            size: u64::MAX,
            content_hash: ContentHash::from_bytes([9; 32]),
            chunking_profile: u32::MAX,
        };
        assert_eq!(
            ContentObject::decode(&repeated.encode().unwrap()).unwrap(),
            repeated
        );
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(sample().encode().unwrap(), sample().encode().unwrap());
    }

    #[test]
    fn unknown_fields_are_ignored() {
        // Same object with an unknown body field 9 and an unknown envelope key 3.
        let mut body = vec![0xa5, 0x01, 0x82];
        for byte in [0x11, 0x22] {
            body.extend([0x58, 0x20]);
            body.extend([byte; 32]);
        }
        body.extend([0x02, 0x1a, 0x00, 0x04, 0x93, 0xe0]);
        body.extend([0x03, 0x58, 0x20]);
        body.extend([0x33; 32]);
        body.extend([0x04, 0x01]);
        body.extend([0x09, 0x61, b'x']);
        let mut stored = vec![0xa4, 0x00, 0x02, 0x01, 0x01, 0x02];
        stored.extend(&body);
        stored.extend([0x03, 0x00]);
        assert_eq!(ContentObject::decode(&stored).unwrap(), sample());
    }

    #[test]
    fn rejects_wrong_type_and_unknown_schema() {
        let other_type = Envelope::encode(3, 1, &[0xa0]).unwrap();
        assert_eq!(
            ContentObject::decode(&other_type),
            Err(ObjectError::WrongType(3))
        );
        for schema in [0u8, 2] {
            let mut bytes = sample_bytes();
            bytes[4] = schema;
            assert_eq!(
                ContentObject::decode(&bytes),
                Err(ObjectError::UnsupportedSchema(u32::from(schema)))
            );
        }
    }

    #[test]
    fn rejects_missing_fields() {
        for (drop_key, expected) in [
            (1, KEY_CHUNKS),
            (2, KEY_SIZE),
            (3, KEY_CONTENT_HASH),
            (4, KEY_CHUNKING_PROFILE),
        ] {
            // Body without one field.
            let mut body = vec![0xa3];
            if drop_key != 1 {
                body.extend([0x01, 0x80]);
            }
            if drop_key != 2 {
                body.extend([0x02, 0x00]);
            }
            if drop_key != 3 {
                body.extend([0x03, 0x58, 0x20]);
                body.extend([0u8; 32]);
            }
            if drop_key != 4 {
                body.extend([0x04, 0x00]);
            }
            let stored = Envelope::encode(2, 1, &body).unwrap();
            assert_eq!(
                ContentObject::decode(&stored),
                Err(ObjectError::MissingField(expected)),
                "drop {drop_key}"
            );
        }
    }

    #[test]
    fn rejects_bad_field_types_and_sizes() {
        let hash = |len: usize| {
            let mut v = vec![0x58, len as u8];
            v.extend(vec![0u8; len]);
            v
        };
        let body = |chunks: Vec<u8>, size: Vec<u8>, hash: Vec<u8>, profile: Vec<u8>| {
            let mut b = vec![0xa4, 0x01];
            b.extend(chunks);
            b.push(0x02);
            b.extend(size);
            b.push(0x03);
            b.extend(hash);
            b.push(0x04);
            b.extend(profile);
            Envelope::encode(2, 1, &b).unwrap()
        };
        let good_chunks = vec![0x80];
        let good_length = vec![0x00];
        let good_profile = vec![0x00];

        // Chunk ID with 31 bytes.
        let mut short_chunk = vec![0x81];
        short_chunk.extend(hash(31));
        assert_eq!(
            ContentObject::decode(&body(
                short_chunk,
                good_length.clone(),
                hash(32),
                good_profile.clone()
            )),
            Err(ObjectError::BadField(KEY_CHUNKS))
        );
        // Chunks is a byte string, not an array.
        assert_eq!(
            ContentObject::decode(&body(
                vec![0x40],
                good_length.clone(),
                hash(32),
                good_profile.clone()
            )),
            Err(ObjectError::BadField(KEY_CHUNKS))
        );
        // Size is a text string.
        assert_eq!(
            ContentObject::decode(&body(
                good_chunks.clone(),
                vec![0x60],
                hash(32),
                good_profile.clone()
            )),
            Err(ObjectError::BadField(KEY_SIZE))
        );
        // Content hash with 33 bytes.
        assert_eq!(
            ContentObject::decode(&body(
                good_chunks.clone(),
                good_length.clone(),
                hash(33),
                good_profile.clone()
            )),
            Err(ObjectError::BadField(KEY_CONTENT_HASH))
        );
        // Profile that does not fit in 32 bits.
        assert_eq!(
            ContentObject::decode(&body(
                good_chunks,
                good_length,
                hash(32),
                vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
            )),
            Err(ObjectError::BadField(KEY_CHUNKING_PROFILE))
        );
    }

    #[test]
    fn decode_rejects_non_canonical_bytes() {
        let mut bytes = sample_bytes();
        bytes.push(0x00); // trailing byte
        assert!(matches!(
            ContentObject::decode(&bytes),
            Err(ObjectError::Envelope(EnvelopeError::NotCanonical(_)))
        ));
    }
}
