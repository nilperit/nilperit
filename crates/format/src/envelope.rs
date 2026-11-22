//! Object envelope (format.md §4.4).
//!
//! An encoded envelope is one CBOR map:
//!
//! ```text
//! { 0: type, 1: schema, 2: body }
//! ```
//!
//! The body is a CBOR map with unsigned integer keys. It is embedded as a CBOR
//! item, not wrapped in a byte string. The stored bytes of an object are the
//! encoded envelope. Object IDs use these bytes and never a re-encoding
//! (format.md §4.9). For this reason [`Envelope`] borrows the stored bytes and
//! gives the body as a slice of them.

use alloc::vec::Vec;
use core::fmt;

use crate::canonical::{self, CanonicalError};

const KEY_TYPE: u64 = 0;
const KEY_SCHEMA: u64 = 1;
const KEY_BODY: u64 = 2;

/// Why an envelope could not be encoded or decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The bytes are not deterministic CBOR.
    NotCanonical(CanonicalError),
    /// The top-level item is not a map, or a known field has the wrong type.
    Malformed,
    /// A required envelope field is missing.
    MissingField,
    /// The body is not a map with unsigned integer keys.
    BadBody,
}

impl From<CanonicalError> for EnvelopeError {
    fn from(e: CanonicalError) -> Self {
        Self::NotCanonical(e)
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonical(e) => write!(f, "envelope is not deterministic CBOR: {e}"),
            Self::Malformed => f.write_str("envelope is malformed"),
            Self::MissingField => f.write_str("envelope field is missing"),
            Self::BadBody => f.write_str("envelope body is not a map with integer keys"),
        }
    }
}

impl core::error::Error for EnvelopeError {}

/// A decoded envelope. It borrows the stored bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope<'a> {
    /// Object type ID.
    pub object_type: u32,
    /// Schema version of the object type.
    pub schema: u32,
    /// The body: one deterministic CBOR map, exactly as stored.
    pub body: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Decodes stored bytes. Rejects input that is not deterministic CBOR.
    ///
    /// Unknown envelope keys are ignored (format.md §4.5). Their bytes stay in the
    /// stored data, so the caller MUST use `stored` (not a new encoding) for the
    /// object ID.
    pub fn decode(stored: &'a [u8]) -> Result<Self, EnvelopeError> {
        canonical::check(stored)?;

        let mut d = minicbor::Decoder::new(stored);
        let entries = d
            .map()
            .map_err(|_| EnvelopeError::Malformed)?
            .ok_or(EnvelopeError::Malformed)?;

        let (mut object_type, mut schema, mut body) = (None, None, None);
        for _ in 0..entries {
            let key = d.u64().map_err(|_| EnvelopeError::Malformed)?;
            match key {
                KEY_TYPE => object_type = Some(d.u32().map_err(|_| EnvelopeError::Malformed)?),
                KEY_SCHEMA => schema = Some(d.u32().map_err(|_| EnvelopeError::Malformed)?),
                KEY_BODY => {
                    let start = d.position();
                    d.skip().map_err(|_| EnvelopeError::Malformed)?;
                    body = Some(&stored[start..d.position()]);
                }
                _ => d.skip().map_err(|_| EnvelopeError::Malformed)?,
            }
        }

        let envelope = Self {
            object_type: object_type.ok_or(EnvelopeError::MissingField)?,
            schema: schema.ok_or(EnvelopeError::MissingField)?,
            body: body.ok_or(EnvelopeError::MissingField)?,
        };
        // Check the body shape now, so `fields` cannot fail later.
        envelope.fields()?;
        Ok(envelope)
    }

    /// Encodes an envelope around an already encoded body.
    ///
    /// `body` MUST be one deterministic CBOR map with unsigned integer keys.
    pub fn encode(object_type: u32, schema: u32, body: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        canonical::check(body)?;
        fields_of(body)?;

        let mut out = Vec::with_capacity(body.len() + 16);
        let mut e = minicbor::Encoder::new(&mut out);
        // Writing to a `Vec` cannot fail.
        e.map(3)
            .and_then(|e| e.u64(KEY_TYPE))
            .and_then(|e| e.u32(object_type))
            .and_then(|e| e.u64(KEY_SCHEMA))
            .and_then(|e| e.u32(schema))
            .and_then(|e| e.u64(KEY_BODY))
            .map_err(|_| EnvelopeError::Malformed)?;
        out.extend_from_slice(body);
        Ok(out)
    }

    /// Lists the body fields as `(key, raw value)` in stored order.
    ///
    /// The caller picks the keys it knows and ignores the others (format.md §4.5).
    pub fn fields(&self) -> Result<Vec<(u64, &'a [u8])>, EnvelopeError> {
        fields_of(self.body)
    }
}

fn fields_of(body: &[u8]) -> Result<Vec<(u64, &[u8])>, EnvelopeError> {
    let mut d = minicbor::Decoder::new(body);
    let entries = d
        .map()
        .map_err(|_| EnvelopeError::BadBody)?
        .ok_or(EnvelopeError::BadBody)?;
    let mut out = Vec::new();
    for _ in 0..entries {
        let key = d.u64().map_err(|_| EnvelopeError::BadBody)?;
        let start = d.position();
        d.skip().map_err(|_| EnvelopeError::BadBody)?;
        out.push((key, &body[start..d.position()]));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Body { 1: 7, 2: "ab" }.
    const BODY: &[u8] = &[0xa2, 0x01, 0x07, 0x02, 0x62, b'a', b'b'];

    #[test]
    fn round_trip() {
        let stored = Envelope::encode(5, 1, BODY).unwrap();
        let env = Envelope::decode(&stored).unwrap();
        assert_eq!((env.object_type, env.schema, env.body), (5, 1, BODY));
        let fields = env.fields().unwrap();
        assert_eq!(fields, [(1, &[0x07][..]), (2, &[0x62, b'a', b'b'][..])]);
    }

    #[test]
    fn test_vector() {
        // { 0: 5, 1: 1, 2: { 1: 7, 2: "ab" } }
        let expected = [
            0xa3, 0x00, 0x05, 0x01, 0x01, 0x02, 0xa2, 0x01, 0x07, 0x02, 0x62, b'a', b'b',
        ];
        assert_eq!(Envelope::encode(5, 1, BODY).unwrap(), expected);
    }

    #[test]
    fn large_ids_use_shortest_form() {
        let stored = Envelope::encode(300, 70_000, BODY).unwrap();
        assert_eq!(
            &stored[..10],
            [0xa3, 0x00, 0x19, 0x01, 0x2c, 0x01, 0x1a, 0x00, 0x01, 0x11]
        );
        let env = Envelope::decode(&stored).unwrap();
        assert_eq!((env.object_type, env.schema), (300, 70_000));
    }

    #[test]
    fn unknown_keys_are_ignored_and_bytes_are_kept() {
        // { 0: 5, 1: 1, 2: { 1: 7, 9: [1] }, 3: "future" }
        let stored = [
            0xa4, 0x00, 0x05, 0x01, 0x01, 0x02, 0xa2, 0x01, 0x07, 0x09, 0x81, 0x01, 0x03, 0x66,
            b'f', b'u', b't', b'u', b'r', b'e',
        ];
        let env = Envelope::decode(&stored).unwrap();
        assert_eq!((env.object_type, env.schema), (5, 1));
        // The unknown body key is visible to the caller, who skips it.
        assert_eq!(env.fields().unwrap().len(), 2);
        // The body is a slice of the stored bytes: nothing is re-encoded.
        assert!(core::ptr::eq(env.body.as_ptr(), stored[6..].as_ptr()));
        assert_eq!(env.body, &stored[6..12]);
    }

    #[test]
    fn rejects_non_canonical_input() {
        // Same envelope with the key 0 written as 0x18 0x00 (non-minimal).
        let stored = [0xa3, 0x18, 0x00, 0x05, 0x01, 0x01, 0x02, 0xa0];
        assert_eq!(
            Envelope::decode(&stored),
            Err(EnvelopeError::NotCanonical(CanonicalError::NonMinimal))
        );
        // Keys out of order.
        let stored = [0xa3, 0x01, 0x01, 0x00, 0x05, 0x02, 0xa0];
        assert_eq!(
            Envelope::decode(&stored),
            Err(EnvelopeError::NotCanonical(CanonicalError::MapKeyOrder))
        );
    }

    #[test]
    fn rejects_missing_fields_and_bad_shapes() {
        // No schema.
        assert_eq!(
            Envelope::decode(&[0xa2, 0x00, 0x05, 0x02, 0xa0]),
            Err(EnvelopeError::MissingField)
        );
        // Not a map.
        assert_eq!(Envelope::decode(&[0x80]), Err(EnvelopeError::Malformed));
        // Type is a text string.
        assert_eq!(
            Envelope::decode(&[0xa3, 0x00, 0x61, b'x', 0x01, 0x01, 0x02, 0xa0]),
            Err(EnvelopeError::Malformed)
        );
        // Body is an array.
        assert_eq!(
            Envelope::decode(&[0xa3, 0x00, 0x05, 0x01, 0x01, 0x02, 0x80]),
            Err(EnvelopeError::BadBody)
        );
        // Body map with a text key.
        assert_eq!(
            Envelope::decode(&[0xa3, 0x00, 0x05, 0x01, 0x01, 0x02, 0xa1, 0x61, b'k', 0x00]),
            Err(EnvelopeError::BadBody)
        );
    }

    #[test]
    fn encode_rejects_bad_body() {
        // Unsorted body keys.
        assert!(Envelope::encode(1, 1, &[0xa2, 0x02, 0x00, 0x01, 0x00]).is_err());
        // Body is not a map.
        assert_eq!(Envelope::encode(1, 1, &[0x00]), Err(EnvelopeError::BadBody));
    }
}
