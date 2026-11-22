//! Strict check for deterministic CBOR (format.md §4.2, §4.6.1, §4.6.2).
//!
//! The check works on the raw bytes. It does not decode and encode again, so it
//! cannot hide a difference between two encodings of the same value.

use core::fmt;

/// Maximum nesting depth of arrays and maps. Protects against stack overflow.
pub const MAX_DEPTH: usize = 32;

/// Why a byte string is not accepted as deterministic CBOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    /// The input ends inside a data item.
    Truncated,
    /// Bytes remain after the data item.
    TrailingBytes,
    /// An integer or length does not use the shortest form.
    NonMinimal,
    /// An indefinite-length item or a break code.
    Indefinite,
    /// A reserved additional-information value.
    Malformed,
    /// A text string is not valid UTF-8.
    InvalidUtf8,
    /// Map keys are not in strictly increasing bytewise order (or repeat).
    MapKeyOrder,
    /// A data item type that the format does not use (tag, float, other simple value).
    Unsupported,
    /// Arrays and maps are nested deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "CBOR input is truncated",
            Self::TrailingBytes => "bytes remain after the CBOR item",
            Self::NonMinimal => "CBOR integer or length is not in shortest form",
            Self::Indefinite => "indefinite-length CBOR is not allowed",
            Self::Malformed => "malformed CBOR",
            Self::InvalidUtf8 => "CBOR text string is not valid UTF-8",
            Self::MapKeyOrder => "CBOR map keys are not sorted or are duplicated",
            Self::Unsupported => "CBOR data item type is not used by the format",
            Self::TooDeep => "CBOR nesting is too deep",
        })
    }
}

impl core::error::Error for CanonicalError {}

/// Checks that `buf` is exactly one deterministic CBOR data item.
pub fn check(buf: &[u8]) -> Result<(), CanonicalError> {
    let end = check_item(buf, 0, 0)?;
    if end == buf.len() {
        Ok(())
    } else {
        Err(CanonicalError::TrailingBytes)
    }
}

/// Checks the data item that starts at `pos`. Returns the position after it.
pub(crate) fn check_item(buf: &[u8], pos: usize, depth: usize) -> Result<usize, CanonicalError> {
    let first = *buf.get(pos).ok_or(CanonicalError::Truncated)?;
    let major = first >> 5;
    let info = first & 0x1f;

    if major == 7 {
        // Only false, true and null.
        return match info {
            20..=22 => Ok(pos + 1),
            31 => Err(CanonicalError::Indefinite),
            28..=30 => Err(CanonicalError::Malformed),
            _ => Err(CanonicalError::Unsupported),
        };
    }
    if major == 6 {
        return Err(CanonicalError::Unsupported);
    }

    let (value, mut next) = read_head(buf, pos, info)?;
    match major {
        // Unsigned and negative integers.
        0 | 1 => Ok(next),
        // Byte string and text string.
        2 | 3 => {
            let len = usize::try_from(value).map_err(|_| CanonicalError::Truncated)?;
            let end = next.checked_add(len).ok_or(CanonicalError::Truncated)?;
            let data = buf.get(next..end).ok_or(CanonicalError::Truncated)?;
            if major == 3 && core::str::from_utf8(data).is_err() {
                return Err(CanonicalError::InvalidUtf8);
            }
            Ok(end)
        }
        // Array and map.
        _ => {
            if depth >= MAX_DEPTH {
                return Err(CanonicalError::TooDeep);
            }
            // Every item needs at least one byte, so a count above the remaining
            // bytes is truncated. This also stops huge counts early.
            let count = usize::try_from(value).map_err(|_| CanonicalError::Truncated)?;
            let items = if major == 5 {
                count.checked_mul(2).ok_or(CanonicalError::Truncated)?
            } else {
                count
            };
            if items > buf.len() - next {
                return Err(CanonicalError::Truncated);
            }
            let mut prev_key: Option<&[u8]> = None;
            for i in 0..items {
                let start = next;
                next = check_item(buf, next, depth + 1)?;
                if major == 5 && i % 2 == 0 {
                    let key = buf.get(start..next).ok_or(CanonicalError::Truncated)?;
                    if prev_key.is_some_and(|prev| prev >= key) {
                        return Err(CanonicalError::MapKeyOrder);
                    }
                    prev_key = Some(key);
                }
            }
            Ok(next)
        }
    }
}

/// Reads the argument of a data item head. Returns it and the position after the head.
fn read_head(buf: &[u8], pos: usize, info: u8) -> Result<(u64, usize), CanonicalError> {
    let (size, min): (usize, u64) = match info {
        0..=23 => return Ok((u64::from(info), pos + 1)),
        24 => (1, 24),
        25 => (2, 1 << 8),
        26 => (4, 1 << 16),
        27 => (8, 1 << 32),
        28..=30 => return Err(CanonicalError::Malformed),
        _ => return Err(CanonicalError::Indefinite),
    };
    let bytes = buf
        .get(pos + 1..pos + 1 + size)
        .ok_or(CanonicalError::Truncated)?;
    let value = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    if value < min {
        return Err(CanonicalError::NonMinimal);
    }
    Ok((value, pos + 1 + size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(bytes: &[u8]) -> CanonicalError {
        check(bytes).unwrap_err()
    }

    #[test]
    fn accepts_rfc8949_appendix_a_examples() {
        let ok: &[&[u8]] = &[
            &[0x00],
            &[0x17],
            &[0x18, 0x18],
            &[0x19, 0x01, 0x00],
            &[0x1a, 0x00, 0x01, 0x00, 0x00],
            &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[0x20],
            &[0x40],
            &[0x44, 1, 2, 3, 4],
            &[0x60],
            &[0x64, b'I', b'E', b'T', b'F'],
            &[0x80],
            &[0x83, 0x01, 0x02, 0x03],
            &[0xa0],
            &[0xa2, 0x01, 0x02, 0x03, 0x04],
            &[0xf4],
            &[0xf5],
            &[0xf6],
        ];
        for bytes in ok {
            assert_eq!(check(bytes), Ok(()), "{bytes:02x?}");
        }
    }

    #[test]
    fn rejects_non_minimal_integers_and_lengths() {
        assert_eq!(err(&[0x18, 0x17]), CanonicalError::NonMinimal);
        assert_eq!(err(&[0x19, 0x00, 0xff]), CanonicalError::NonMinimal);
        assert_eq!(
            err(&[0x1a, 0x00, 0x00, 0xff, 0xff]),
            CanonicalError::NonMinimal
        );
        assert_eq!(
            err(&[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]),
            CanonicalError::NonMinimal
        );
        // Byte string of length 1 with a one-byte length argument.
        assert_eq!(err(&[0x58, 0x01, 0x00]), CanonicalError::NonMinimal);
    }

    #[test]
    fn rejects_indefinite_length_and_break() {
        assert_eq!(err(&[0x5f, 0x41, 0x00, 0xff]), CanonicalError::Indefinite);
        assert_eq!(err(&[0x9f, 0xff]), CanonicalError::Indefinite);
        assert_eq!(err(&[0xbf, 0xff]), CanonicalError::Indefinite);
        assert_eq!(err(&[0xff]), CanonicalError::Indefinite);
    }

    #[test]
    fn rejects_unsorted_and_duplicate_map_keys() {
        assert_eq!(
            err(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
            CanonicalError::MapKeyOrder
        );
        assert_eq!(
            err(&[0xa2, 0x01, 0x00, 0x01, 0x01]),
            CanonicalError::MapKeyOrder
        );
        // Bytewise order of the encoded keys: 0x0a (10) < 0x18 0x18 (24).
        assert_eq!(check(&[0xa2, 0x0a, 0x00, 0x18, 0x18, 0x00]), Ok(()));
        assert_eq!(
            err(&[0xa2, 0x18, 0x18, 0x00, 0x0a, 0x00]),
            CanonicalError::MapKeyOrder
        );
    }

    #[test]
    fn rejects_unsupported_items() {
        assert_eq!(err(&[0xc1, 0x00]), CanonicalError::Unsupported); // tag
        assert_eq!(err(&[0xf9, 0x3c, 0x00]), CanonicalError::Unsupported); // float
        assert_eq!(err(&[0xf7]), CanonicalError::Unsupported); // undefined
        assert_eq!(err(&[0xf0]), CanonicalError::Unsupported); // simple value
        assert_eq!(err(&[0x1c]), CanonicalError::Malformed);
    }

    #[test]
    fn rejects_truncated_trailing_and_bad_text() {
        assert_eq!(err(&[]), CanonicalError::Truncated);
        assert_eq!(err(&[0x44, 1, 2]), CanonicalError::Truncated);
        assert_eq!(err(&[0x19, 0x01]), CanonicalError::Truncated);
        assert_eq!(err(&[0x82, 0x01]), CanonicalError::Truncated);
        assert_eq!(err(&[0x00, 0x00]), CanonicalError::TrailingBytes);
        assert_eq!(err(&[0x62, 0xc3, 0x28]), CanonicalError::InvalidUtf8);
        // Huge declared length must not allocate or loop.
        assert_eq!(
            err(&[0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            CanonicalError::Truncated
        );
    }

    #[test]
    fn limits_nesting_depth() {
        let mut deep = [0x81u8; MAX_DEPTH + 2];
        deep[MAX_DEPTH + 1] = 0x00;
        assert_eq!(err(&deep), CanonicalError::TooDeep);
        let mut ok = [0x81u8; MAX_DEPTH];
        ok[MAX_DEPTH - 1] = 0x00;
        assert_eq!(check(&ok), Ok(()));
    }
}
