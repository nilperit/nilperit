//! The structure of a pack (format.md 6.7): header, trailer and footer.
//!
//! This module has no cryptography. It reads and writes the plaintext parts of
//! a pack and checks them against the rules and limits of format.md. The
//! object table is in [`crate::object_table`].

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::canonical::{self, CanonicalError};
use crate::envelope::EnvelopeError;

/// The magic bytes at the start of a pack (format.md 6.7.1).
pub const MAGIC: [u8; 8] = [0x89, 0x4e, 0x50, 0x4b, 0x0d, 0x0a, 0x1a, 0x0a];
/// The end magic: the last 8 bytes of a pack (format.md 6.7.4).
pub const END_MAGIC: [u8; 8] = *b"NPK-END\n";
/// The magic bytes and the header size: enough to learn the length of the header.
pub const HEADER_PREFIX_SIZE: usize = 12;
/// The size of the footer.
pub const FOOTER_SIZE: usize = 24;
/// The largest allowed header map, in bytes (format.md 6.7.6).
pub const MAX_HEADER_SIZE: u32 = 1 << 16;
/// The largest allowed sealed pack key, in bytes (format.md 6.7.6).
pub const MAX_SEAL_SIZE: u32 = 1 << 16;
/// The largest allowed trailer, in bytes (format.md 6.7.6).
pub const MAX_TRAILER_SIZE: u32 = 1 << 28;
/// The largest allowed packed size and the largest allowed unpacked size of one object, in
/// bytes (format.md 6.7.6). A reader needs memory for about twice this size to read one object.
pub const MAX_OBJECT_SIZE: u32 = 1 << 30;
/// The bytes that a packed object adds to its compressed bytes: nonce and tag.
pub const PACKED_OBJECT_OVERHEAD: u32 = 40;
/// The format version that this code reads and writes (format.md 12.5).
pub const FORMAT_VERSION: u32 = 0;
/// The name of the AEAD algorithm (format.md 6.7.1.2).
pub const ENCRYPTION_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";
/// The name of the hash algorithm (format.md 6.7.1.2).
pub const HASH_BLAKE3: &str = "blake3";

const KEY_FORMAT_VERSION: u64 = 1;
const KEY_PACK_CLASS: u64 = 2;
const KEY_ENCRYPTION: u64 = 3;
const KEY_KEY_ENCAPSULATION: u64 = 4;
const KEY_HASH: u64 = 5;

/// Why a pack, or a part of it, is not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackError {
    /// The input is shorter than the structure needs.
    Truncated,
    /// The magic bytes at the start are not correct.
    BadMagic,
    /// The end magic is not correct.
    BadEndMagic,
    /// A size is above a limit of format.md 6.7.6. The text names the limit.
    TooLarge(&'static str),
    /// A part that must be deterministic CBOR is not.
    NotCanonical(CanonicalError),
    /// The envelope of the object table is not valid.
    Envelope(EnvelopeError),
    /// The format version is higher than this code knows.
    NewerFormat(u32),
    /// The encryption or hash name is not known.
    UnknownAlgorithm,
    /// The schema version of the object table is not known.
    UnsupportedSchema(u32),
    /// A part has the wrong shape. The text says which part.
    Malformed(&'static str),
    /// The parts of the pack do not fit together. The text says how.
    Layout(&'static str),
}

impl From<CanonicalError> for PackError {
    fn from(e: CanonicalError) -> Self {
        Self::NotCanonical(e)
    }
}

impl From<EnvelopeError> for PackError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("pack is truncated"),
            Self::BadMagic => f.write_str("pack does not start with the magic bytes"),
            Self::BadEndMagic => f.write_str("pack does not end with the end magic"),
            Self::TooLarge(what) => write!(f, "{what} is above its limit"),
            Self::NotCanonical(e) => write!(f, "not deterministic CBOR: {e}"),
            Self::Envelope(e) => write!(f, "{e}"),
            Self::NewerFormat(v) => write!(f, "format version {v} is newer than this reader"),
            Self::UnknownAlgorithm => f.write_str("pack uses an algorithm that is not known"),
            Self::UnsupportedSchema(s) => write!(f, "schema version {s} is not supported"),
            Self::Malformed(what) => write!(f, "{what} is malformed"),
            Self::Layout(what) => write!(f, "pack layout is not valid: {what}"),
        }
    }
}

impl core::error::Error for PackError {}

/// The class of a pack (format.md 6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackClass {
    /// A data pack: truth.
    Data,
    /// A metadata pack: caches.
    Metadata,
}

impl PackClass {
    const fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Metadata => 1,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Data),
            1 => Some(Self::Metadata),
            _ => None,
        }
    }
}

/// The header of a pack (format.md 6.7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The format version of the vault.
    pub format_version: u32,
    /// Data pack or metadata pack.
    pub class: PackClass,
    /// The name of the AEAD algorithm.
    pub encryption: String,
    /// The name of the key encapsulation algorithm. Only a pack with a sealed
    /// pack key has it.
    pub key_encapsulation: Option<String>,
    /// The name of the hash algorithm.
    pub hash: String,
}

impl Header {
    /// A header for a pack that this code writes.
    pub fn new(class: PackClass, key_encapsulation: Option<String>) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            class,
            encryption: String::from(ENCRYPTION_XCHACHA20_POLY1305),
            key_encapsulation,
            hash: String::from(HASH_BLAKE3),
        }
    }

    /// The length of the whole header, from the first 12 bytes of a pack.
    ///
    /// A reader that fetches ranges reads 12 bytes first, then the rest of the
    /// header.
    pub fn len_from_prefix(prefix: &[u8]) -> Result<usize, PackError> {
        let prefix = prefix
            .get(..HEADER_PREFIX_SIZE)
            .ok_or(PackError::Truncated)?;
        if prefix[..8] != MAGIC {
            return Err(PackError::BadMagic);
        }
        let size = u32::from_le_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
        if size > MAX_HEADER_SIZE {
            return Err(PackError::TooLarge("header"));
        }
        // The size is at most 65536, so this cannot overflow.
        Ok(HEADER_PREFIX_SIZE + size as usize)
    }

    /// Encodes the whole header: the magic bytes, the size, and the map.
    pub fn encode(&self) -> Result<Vec<u8>, PackError> {
        let mut map = Vec::new();
        let mut e = minicbor::Encoder::new(&mut map);
        let fields = if self.key_encapsulation.is_some() {
            5
        } else {
            4
        };
        // Keys are in ascending order, which is the deterministic order.
        // Writing to a `Vec` cannot fail.
        e.map(fields)
            .and_then(|e| e.u64(KEY_FORMAT_VERSION))
            .and_then(|e| e.u32(self.format_version))
            .and_then(|e| e.u64(KEY_PACK_CLASS))
            .and_then(|e| e.u8(self.class.code()))
            .and_then(|e| e.u64(KEY_ENCRYPTION))
            .and_then(|e| e.str(&self.encryption))
            .map_err(|_| PackError::Malformed("header"))?;
        if let Some(name) = &self.key_encapsulation {
            e.u64(KEY_KEY_ENCAPSULATION)
                .and_then(|e| e.str(name))
                .map_err(|_| PackError::Malformed("header"))?;
        }
        e.u64(KEY_HASH)
            .and_then(|e| e.str(&self.hash))
            .map_err(|_| PackError::Malformed("header"))?;

        let size = u32::try_from(map.len())
            .ok()
            .filter(|s| *s <= MAX_HEADER_SIZE)
            .ok_or(PackError::TooLarge("header"))?;
        let mut out = Vec::with_capacity(HEADER_PREFIX_SIZE + map.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&map);
        Ok(out)
    }

    /// Decodes a header. `bytes` starts at the start of the pack. Bytes after
    /// the header are ignored.
    ///
    /// Rejects a format version that is newer than this code (format.md 6.7.1.3)
    /// and an encryption or hash name that it does not know. Ignores unknown
    /// keys (format.md 4.5).
    pub fn decode(bytes: &[u8]) -> Result<Self, PackError> {
        let len = Self::len_from_prefix(bytes)?;
        let map = bytes
            .get(HEADER_PREFIX_SIZE..len)
            .ok_or(PackError::Truncated)?;
        canonical::check(map)?;

        let bad = |_| PackError::Malformed("header");
        let mut d = minicbor::Decoder::new(map);
        let entries = d
            .map()
            .map_err(bad)?
            .ok_or(PackError::Malformed("header"))?;
        let (mut version, mut class, mut encryption, mut kem, mut hash) =
            (None, None, None, None, None);
        for _ in 0..entries {
            match d.u64().map_err(bad)? {
                KEY_FORMAT_VERSION => version = Some(d.u32().map_err(bad)?),
                KEY_PACK_CLASS => {
                    let code = d.u8().map_err(bad)?;
                    class =
                        Some(PackClass::from_code(code).ok_or(PackError::Malformed("pack class"))?);
                }
                KEY_ENCRYPTION => encryption = Some(String::from(d.str().map_err(bad)?)),
                KEY_KEY_ENCAPSULATION => kem = Some(String::from(d.str().map_err(bad)?)),
                KEY_HASH => hash = Some(String::from(d.str().map_err(bad)?)),
                _ => d.skip().map_err(bad)?,
            }
        }

        let format_version = version.ok_or(PackError::Malformed("header"))?;
        if format_version > FORMAT_VERSION {
            return Err(PackError::NewerFormat(format_version));
        }
        let encryption = encryption.ok_or(PackError::Malformed("header"))?;
        let hash = hash.ok_or(PackError::Malformed("header"))?;
        if encryption != ENCRYPTION_XCHACHA20_POLY1305 || hash != HASH_BLAKE3 {
            return Err(PackError::UnknownAlgorithm);
        }
        Ok(Self {
            format_version,
            class: class.ok_or(PackError::Malformed("header"))?,
            encryption,
            key_encapsulation: kem,
            hash,
        })
    }
}

/// The footer of a pack: the last 24 bytes (format.md 6.7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Footer {
    /// The position of the first byte of the trailer, from the start of the file.
    pub trailer_offset: u64,
    /// The size of the trailer in bytes.
    pub trailer_size: u32,
    /// The format version of the vault.
    pub format_version: u32,
}

impl Footer {
    /// Encodes the footer.
    pub fn encode(&self) -> [u8; FOOTER_SIZE] {
        let mut out = [0u8; FOOTER_SIZE];
        out[0..8].copy_from_slice(&self.trailer_offset.to_le_bytes());
        out[8..12].copy_from_slice(&self.trailer_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.format_version.to_le_bytes());
        out[16..24].copy_from_slice(&END_MAGIC);
        out
    }

    /// Decodes the footer from the last 24 bytes of a pack.
    ///
    /// Rejects a wrong end magic, a trailer size above the limit, and a format
    /// version that is newer than this code.
    pub fn decode(bytes: &[u8; FOOTER_SIZE]) -> Result<Self, PackError> {
        if bytes[16..24] != END_MAGIC {
            return Err(PackError::BadEndMagic);
        }
        let footer = Self {
            trailer_offset: u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            trailer_size: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            format_version: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        };
        if footer.trailer_size > MAX_TRAILER_SIZE {
            return Err(PackError::TooLarge("trailer"));
        }
        if footer.format_version > FORMAT_VERSION {
            return Err(PackError::NewerFormat(footer.format_version));
        }
        Ok(footer)
    }

    /// Checks the footer against the rest of the pack (format.md 6.7.4.1).
    ///
    /// `file_size` is the size of the whole pack file. `header` is the decoded
    /// header and `header_len` its length in bytes.
    pub fn check(
        &self,
        file_size: u64,
        header: &Header,
        header_len: usize,
    ) -> Result<(), PackError> {
        if self.format_version != header.format_version {
            return Err(PackError::Layout(
                "footer and header have different format versions",
            ));
        }
        let end = self
            .trailer_offset
            .checked_add(u64::from(self.trailer_size))
            .and_then(|n| n.checked_add(FOOTER_SIZE as u64));
        if end != Some(file_size) {
            return Err(PackError::Layout(
                "trailer does not end where the footer starts",
            ));
        }
        if self.trailer_offset < header_len as u64 {
            return Err(PackError::Layout("trailer starts inside the header"));
        }
        Ok(())
    }
}

/// The trailer of a pack, split into its parts (format.md 6.7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trailer<'a> {
    /// The sealed pack key. The format treats it as opaque bytes. It is empty
    /// when the pack has no R objects.
    pub seal: &'a [u8],
    /// The object table as a packed object: nonce, ciphertext, tag.
    pub table: &'a [u8],
}

impl<'a> Trailer<'a> {
    /// Splits the bytes of a trailer.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, PackError> {
        let size = bytes.get(..4).ok_or(PackError::Truncated)?;
        let seal_size = u32::from_le_bytes([size[0], size[1], size[2], size[3]]);
        if seal_size > MAX_SEAL_SIZE {
            return Err(PackError::TooLarge("seal"));
        }
        let rest = &bytes[4..];
        let seal_size = seal_size as usize;
        if rest.len() < seal_size {
            return Err(PackError::Truncated);
        }
        let (seal, table) = rest.split_at(seal_size);
        if table.len() < PACKED_OBJECT_OVERHEAD as usize {
            return Err(PackError::Malformed("object table"));
        }
        Ok(Self { seal, table })
    }

    /// Joins a seal and a packed object table into the bytes of a trailer.
    pub fn encode(seal: &[u8], table: &[u8]) -> Result<Vec<u8>, PackError> {
        let seal_size = u32::try_from(seal.len())
            .ok()
            .filter(|s| *s <= MAX_SEAL_SIZE)
            .ok_or(PackError::TooLarge("seal"))?;
        let total = 4 + seal.len() + table.len();
        if u32::try_from(total).map_or(true, |t| t > MAX_TRAILER_SIZE) {
            return Err(PackError::TooLarge("trailer"));
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&seal_size.to_le_bytes());
        out.extend_from_slice(seal);
        out.extend_from_slice(table);
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use alloc::vec;

    use super::*;

    // The pack of format.md A.8 (408 bytes).
    pub(crate) const PACK_HEX: &str = "894e504b0d0a1a0a2e000000a50100020003727863686163686132302d706f6c7931333035046b706c616365686f6c6465720566626c616b65330101010101010101010101010101010101010101010101014683820b6bdd17744f45bb9c2275d3d73057e39b980765020202020202020202020202020202020202020202020202c5e12b97bd9e2e7d093d49a7a9c7db234d82f2da194b7b55517ebcb80e3a652036e81578286e7506f30dcfb8a8ea38f7111dd372053a9b7c65a12982437fe67c87390691e4e97a85f48e30a866aa17f9bebfe753881f5c03d706534a1efb54a9fd9a04000000deadbeef030303030303030303030303030303030303030303030303641136128a959b741d53c008bbdf760f87c8ed6499d7ad62b8c483c0e134ba3c269eff66bb08c01ee9baf1a4a9608275c2a7e0e252b52c3bcdb28471056b637fca99bb999c6ff11fdd451bbaba53b9db719e0eb1f81e91603528d27060f14b5036b5818c1144c0fd989adddcc5353d7ab9ab11c81e9e47dc98fba75147e3000000000000009d000000000000004e504b2d454e440a";

    pub(crate) fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub(crate) fn pack() -> Vec<u8> {
        unhex(PACK_HEX)
    }

    #[test]
    fn reads_the_appendix_vector() {
        let pack = pack();
        assert_eq!(pack.len(), 408);

        let header = Header::decode(&pack).unwrap();
        let header_len = Header::len_from_prefix(&pack).unwrap();
        assert_eq!(header_len, 58);
        assert_eq!(header.format_version, 0);
        assert_eq!(header.class, PackClass::Data);
        assert_eq!(header.encryption, "xchacha20-poly1305");
        assert_eq!(header.key_encapsulation.as_deref(), Some("placeholder"));
        assert_eq!(header.hash, "blake3");

        let footer = Footer::decode(pack[pack.len() - FOOTER_SIZE..].try_into().unwrap()).unwrap();
        assert_eq!(footer.trailer_offset, 227);
        assert_eq!(footer.trailer_size, 157);
        footer
            .check(pack.len() as u64, &header, header_len)
            .unwrap();

        let trailer = Trailer::decode(&pack[227..227 + 157]).unwrap();
        assert_eq!(trailer.seal, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(trailer.table.len(), 149);
    }

    #[test]
    fn writes_the_appendix_vector_parts() {
        let pack = pack();
        let header = Header::new(PackClass::Data, Some(String::from("placeholder")));
        assert_eq!(header.encode().unwrap(), pack[..58]);

        let footer = Footer {
            trailer_offset: 227,
            trailer_size: 157,
            format_version: 0,
        };
        assert_eq!(footer.encode(), pack[pack.len() - FOOTER_SIZE..]);

        let trailer = Trailer::decode(&pack[227..384]).unwrap();
        assert_eq!(
            Trailer::encode(trailer.seal, trailer.table).unwrap(),
            pack[227..384]
        );
    }

    #[test]
    fn header_round_trip_without_a_seal() {
        let header = Header::new(PackClass::Metadata, None);
        let bytes = header.encode().unwrap();
        assert_eq!(Header::decode(&bytes).unwrap(), header);
    }

    #[test]
    fn header_ignores_unknown_keys_and_trailing_bytes() {
        // { 1: 0, 2: 0, 3: "xchacha20-poly1305", 5: "blake3", 9: [1] }
        let mut map = vec![0xa5, 0x01, 0x00, 0x02, 0x00, 0x03, 0x72];
        map.extend(b"xchacha20-poly1305");
        map.extend([0x05, 0x66]);
        map.extend(b"blake3");
        map.extend([0x09, 0x81, 0x01]);
        let mut bytes = MAGIC.to_vec();
        bytes.extend((map.len() as u32).to_le_bytes());
        bytes.extend(&map);
        bytes.extend([0xff; 10]); // the body follows
        let header = Header::decode(&bytes).unwrap();
        assert_eq!(header.key_encapsulation, None);
    }

    #[test]
    fn header_rejections() {
        let good = Header::new(PackClass::Data, None).encode().unwrap();

        let mut bad_magic = good.clone();
        bad_magic[0] = 0;
        assert_eq!(Header::decode(&bad_magic), Err(PackError::BadMagic));

        assert_eq!(Header::decode(&good[..11]), Err(PackError::Truncated));
        assert_eq!(
            Header::decode(&good[..good.len() - 1]),
            Err(PackError::Truncated)
        );

        let mut huge = good.clone();
        huge[8..12].copy_from_slice(&(MAX_HEADER_SIZE + 1).to_le_bytes());
        assert_eq!(Header::decode(&huge), Err(PackError::TooLarge("header")));

        let mut newer = Header::new(PackClass::Data, None);
        newer.format_version = 1;
        assert_eq!(
            Header::decode(&newer.encode().unwrap()),
            Err(PackError::NewerFormat(1))
        );

        let mut other_aead = Header::new(PackClass::Data, None);
        other_aead.encryption = String::from("aes-gcm");
        assert_eq!(
            Header::decode(&other_aead.encode().unwrap()),
            Err(PackError::UnknownAlgorithm)
        );

        let mut other_hash = Header::new(PackClass::Data, None);
        other_hash.hash = String::from("sha256");
        assert_eq!(
            Header::decode(&other_hash.encode().unwrap()),
            Err(PackError::UnknownAlgorithm)
        );

        // Pack class 2 does not exist: { 1: 0, 2: 2, 3: "..", 5: ".." } with valid names.
        let mut map = vec![0xa4, 0x01, 0x00, 0x02, 0x02, 0x03, 0x72];
        map.extend(b"xchacha20-poly1305");
        map.extend([0x05, 0x66]);
        map.extend(b"blake3");
        let mut bytes = MAGIC.to_vec();
        bytes.extend((map.len() as u32).to_le_bytes());
        bytes.extend(&map);
        assert_eq!(
            Header::decode(&bytes),
            Err(PackError::Malformed("pack class"))
        );

        // A missing hash field.
        let mut map = vec![0xa3, 0x01, 0x00, 0x02, 0x00, 0x03, 0x72];
        map.extend(b"xchacha20-poly1305");
        let mut bytes = MAGIC.to_vec();
        bytes.extend((map.len() as u32).to_le_bytes());
        bytes.extend(&map);
        assert_eq!(Header::decode(&bytes), Err(PackError::Malformed("header")));

        // Keys out of order are not deterministic CBOR.
        let map = vec![0xa2, 0x02, 0x00, 0x01, 0x00];
        let mut bytes = MAGIC.to_vec();
        bytes.extend((map.len() as u32).to_le_bytes());
        bytes.extend(&map);
        assert!(matches!(
            Header::decode(&bytes),
            Err(PackError::NotCanonical(_))
        ));
    }

    #[test]
    fn footer_rejections() {
        let pack = pack();
        let header = Header::decode(&pack).unwrap();
        let good = Footer {
            trailer_offset: 227,
            trailer_size: 157,
            format_version: 0,
        };

        let mut bytes = good.encode();
        bytes[23] = 0;
        assert_eq!(Footer::decode(&bytes), Err(PackError::BadEndMagic));

        let big = Footer {
            trailer_size: MAX_TRAILER_SIZE + 1,
            ..good
        }
        .encode();
        assert_eq!(Footer::decode(&big), Err(PackError::TooLarge("trailer")));

        let newer = Footer {
            format_version: 1,
            ..good
        }
        .encode();
        assert_eq!(Footer::decode(&newer), Err(PackError::NewerFormat(1)));

        // Checks against the rest of the pack.
        assert!(good.check(408, &header, 58).is_ok());
        assert!(good.check(409, &header, 58).is_err());
        assert!(
            Footer {
                trailer_offset: 57,
                ..good
            }
            .check(57 + 157 + 24, &header, 58)
            .is_err()
        );
        let mut other_version = header.clone();
        other_version.format_version = 1;
        assert!(
            good.check(408, &other_version, 58).is_err(),
            "the format versions of header and footer must agree"
        );
        assert!(
            Footer {
                trailer_offset: u64::MAX,
                ..good
            }
            .check(408, &header, 58)
            .is_err(),
            "offset arithmetic must not overflow"
        );
    }

    #[test]
    fn trailer_rejections() {
        let table = vec![0u8; 40];
        assert!(Trailer::decode(&[]).is_err());
        assert_eq!(Trailer::decode(&[1, 0, 0]), Err(PackError::Truncated));

        // Seal size above the limit.
        let mut big = (MAX_SEAL_SIZE + 1).to_le_bytes().to_vec();
        big.extend(&table);
        assert_eq!(Trailer::decode(&big), Err(PackError::TooLarge("seal")));

        // Seal size larger than the trailer.
        let mut short = 100u32.to_le_bytes().to_vec();
        short.extend(&table);
        assert_eq!(Trailer::decode(&short), Err(PackError::Truncated));

        // No room for a packed object table.
        let mut small = 0u32.to_le_bytes().to_vec();
        small.extend([0u8; 39]);
        assert_eq!(
            Trailer::decode(&small),
            Err(PackError::Malformed("object table"))
        );

        // An empty seal is valid.
        let ok = Trailer::encode(&[], &table).unwrap();
        assert_eq!(Trailer::decode(&ok).unwrap().seal, &[] as &[u8]);
        assert!(Trailer::encode(&vec![0u8; MAX_SEAL_SIZE as usize + 1], &table).is_err());
    }
}
