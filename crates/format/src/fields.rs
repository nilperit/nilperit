//! Helpers to read and write the fields of an object body (format.md 4.4).
//!
//! An object body is a CBOR map with unsigned integer keys. These helpers turn
//! the raw value of a field into a Rust value, and the other way round. They
//! only give errors of the kind [`ObjectError`]: they never put data in a message.

use alloc::string::String;
use alloc::vec::Vec;

use crate::content_object::ObjectError;
use crate::envelope::Envelope;
use crate::ids::HASH_LEN;

/// The raw values of the fields of a body, found by key.
pub(crate) struct Fields<'a>(Vec<(u64, &'a [u8])>);

impl<'a> Fields<'a> {
    /// Opens an envelope of the expected type and schema version, and lists the
    /// fields of its body.
    pub(crate) fn open(
        stored: &'a [u8],
        type_id: u32,
        schema: u32,
    ) -> Result<(Envelope<'a>, Self), ObjectError> {
        let envelope = Envelope::decode(stored)?;
        if envelope.object_type != type_id {
            return Err(ObjectError::WrongType(envelope.object_type));
        }
        if envelope.schema != schema {
            return Err(ObjectError::UnsupportedSchema(envelope.schema));
        }
        let fields = Self(envelope.fields()?);
        Ok((envelope, fields))
    }

    /// Lists the entries of a map value with unsigned integer keys.
    pub(crate) fn of_map(raw: &'a [u8], key: u64) -> Result<Self, ObjectError> {
        let bad = |_| ObjectError::BadField(key);
        let mut d = minicbor::Decoder::new(raw);
        let entries = d.map().map_err(bad)?.ok_or(ObjectError::BadField(key))?;
        let mut out = Vec::new();
        for _ in 0..entries {
            let k = d.u64().map_err(bad)?;
            let start = d.position();
            d.skip().map_err(bad)?;
            out.push((k, &raw[start..d.position()]));
        }
        Ok(Self(out))
    }

    /// The raw value of a field, if it is there.
    pub(crate) fn get(&self, key: u64) -> Option<&'a [u8]> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }

    /// The raw value of a field that must be there.
    pub(crate) fn require(&self, key: u64) -> Result<&'a [u8], ObjectError> {
        self.get(key).ok_or(ObjectError::MissingField(key))
    }
}

pub(crate) fn read_u64(raw: &[u8], key: u64) -> Result<u64, ObjectError> {
    minicbor::Decoder::new(raw)
        .u64()
        .map_err(|_| ObjectError::BadField(key))
}

pub(crate) fn read_u32(raw: &[u8], key: u64) -> Result<u32, ObjectError> {
    minicbor::Decoder::new(raw)
        .u32()
        .map_err(|_| ObjectError::BadField(key))
}

pub(crate) fn read_i64(raw: &[u8], key: u64) -> Result<i64, ObjectError> {
    minicbor::Decoder::new(raw)
        .i64()
        .map_err(|_| ObjectError::BadField(key))
}

pub(crate) fn read_text(raw: &[u8], key: u64) -> Result<String, ObjectError> {
    minicbor::Decoder::new(raw)
        .str()
        .map(String::from)
        .map_err(|_| ObjectError::BadField(key))
}

pub(crate) fn read_bytes(raw: &[u8], key: u64) -> Result<Vec<u8>, ObjectError> {
    minicbor::Decoder::new(raw)
        .bytes()
        .map(<[u8]>::to_vec)
        .map_err(|_| ObjectError::BadField(key))
}

/// A byte string of exactly `N` bytes.
pub(crate) fn read_array<const N: usize>(raw: &[u8], key: u64) -> Result<[u8; N], ObjectError> {
    let bytes = minicbor::Decoder::new(raw)
        .bytes()
        .map_err(|_| ObjectError::BadField(key))?;
    bytes.try_into().map_err(|_| ObjectError::BadField(key))
}

/// An array of byte strings of exactly 32 bytes each.
pub(crate) fn read_hashes(raw: &[u8], key: u64) -> Result<Vec<[u8; HASH_LEN]>, ObjectError> {
    let bad = |_| ObjectError::BadField(key);
    let mut d = minicbor::Decoder::new(raw);
    let count = d.array().map_err(bad)?.ok_or(ObjectError::BadField(key))?;
    // The input is deterministic CBOR, so every item uses at least one byte.
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(raw.len()));
    for _ in 0..count {
        let bytes = d.bytes().map_err(bad)?;
        out.push(bytes.try_into().map_err(|_| ObjectError::BadField(key))?);
    }
    Ok(out)
}

// ---- writing. Writing to a `Vec` cannot fail, so the results are ignored.

fn encode_with(f: impl FnOnce(&mut minicbor::Encoder<&mut Vec<u8>>)) -> Vec<u8> {
    let mut out = Vec::new();
    f(&mut minicbor::Encoder::new(&mut out));
    out
}

pub(crate) fn write_u64(n: u64) -> Vec<u8> {
    encode_with(|e| {
        let _ = e.u64(n);
    })
}

pub(crate) fn write_i64(n: i64) -> Vec<u8> {
    encode_with(|e| {
        let _ = e.i64(n);
    })
}

pub(crate) fn write_text(s: &str) -> Vec<u8> {
    encode_with(|e| {
        let _ = e.str(s);
    })
}

pub(crate) fn write_bytes(b: &[u8]) -> Vec<u8> {
    encode_with(|e| {
        let _ = e.bytes(b);
    })
}

/// An array whose items are already encoded.
pub(crate) fn write_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = encode_with(|e| {
        let _ = e.array(items.len() as u64);
    });
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// An array of byte strings.
pub(crate) fn write_hashes<'a>(items: impl ExactSizeIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = encode_with(|e| {
        let _ = e.array(items.len() as u64);
    });
    for item in items {
        out.extend_from_slice(&write_bytes(item));
    }
    out
}

/// A map with unsigned integer keys. The keys MUST be in ascending order, which
/// is the deterministic order.
pub(crate) fn write_map(fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
    debug_assert!(fields.windows(2).all(|w| w[0].0 < w[1].0));
    let mut out = encode_with(|e| {
        let _ = e.map(fields.len() as u64);
    });
    for (key, value) in fields {
        out.extend_from_slice(&write_u64(*key));
        out.extend_from_slice(value);
    }
    out
}

/// Builds the stored bytes of an object from raw fields, so tests can make
/// objects that the encoders refuse to make. The keys MUST be in ascending order.
#[cfg(test)]
pub(crate) fn raw_object(type_id: u32, fields: &[(u64, Vec<u8>)]) -> Vec<u8> {
    Envelope::encode(type_id, 1, &write_map(fields)).unwrap()
}

/// Returns `fields` with the value of `key` replaced, or the field removed when
/// `value` is `None`.
#[cfg(test)]
pub(crate) fn with_field(
    fields: &[(u64, Vec<u8>)],
    key: u64,
    value: Option<Vec<u8>>,
) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = fields.iter().filter(|(k, _)| *k != key).cloned().collect();
    if let Some(value) = value {
        out.push((key, value));
    }
    out.sort_by_key(|(k, _)| *k);
    out
}
