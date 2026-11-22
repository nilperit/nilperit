//! One check for each place where bytes that are not trusted come in.
//!
//! Each function takes the bytes and panics when a rule is broken (`assert!`). A function that
//! returns is a pass. The rules, for every input:
//!
//! 1. **No panic**, and no allocation or loop without a limit.
//! 2. **Strict input.** A decoder that accepts bytes accepts only deterministic CBOR
//!    (format.md 4.2).
//! 3. **No change by a round trip.** The value that a decoder gives encodes again, and the
//!    encoding decodes to the same value. The encoding is not longer than the input: a
//!    decoder ignores unknown fields (format.md 4.5), and so only the known fields stay.
//! 4. **The rules of a pack hold** for every pack that is accepted (format.md 6.7).
//!
//! The functions that go through the encryption (`pack_with_table`, `pack_with_object`)
//! encrypt the bytes of the fuzzer with the keys of the test vector A.8, and put them in a
//! pack that is valid in every other way. A random input never has a correct tag, so
//! without this the fuzzer would never get past the tag to the code behind it. The code of
//! the program is not changed for this: the checks call the same functions as the program.

use crate::fixtures::{FixedRng, block_on, dedup_key, keys, writer_key};
use nilperit_crypto::{ReadKey, ReadPublicKey, decrypt, encrypt, open_seal};
use nilperit_format::pack::{FOOTER_SIZE, MAX_HEADER_SIZE};
use nilperit_format::{
    Compression, ContentObject, DeltaEntry, Envelope, Footer, Header, ItemRecord, KeyClass,
    LockFile, ObjectId, ObjectTable, ObjectTableEntry, PackClass, PackName, SnapshotHeader,
    Trailer, VaultConfig, canonical, join_config_file, split_config_file,
};
use nilperit_reader::layout::pack_path;
use nilperit_reader::{MemoryTarget, Pack};
use nilperit_writer::chunking::{ChunkReader, Fixed};
use std::fmt::Debug;
use std::io::{self, Read};

/// The largest size of a body, a seal, or an object that the checks make. A check must not
/// need much memory, whatever the input says.
const MAX_BYTES: usize = 1 << 20;

// ---- The strict check of CBOR, and the decoders ----

/// The check for deterministic CBOR. When it accepts bytes, another decoder (`minicbor`)
/// must read exactly one item, and all of the bytes.
pub fn canonical(data: &[u8]) {
    if canonical::check(data).is_ok() {
        let mut other = minicbor::Decoder::new(data);
        other
            .skip()
            .expect("the strict check accepted CBOR that another decoder cannot read");
        assert_eq!(
            other.position(),
            data.len(),
            "the strict check accepted bytes after the item"
        );
    }
}

/// Rules 2 and 3 for a decoder and its encoder.
fn decoder<T: PartialEq + Debug, E1: Debug, E2: Debug>(
    data: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, E1>,
    encode: impl Fn(&T) -> Result<Vec<u8>, E2>,
) {
    let Ok(value) = decode(data) else {
        return;
    };
    assert!(
        canonical::check(data).is_ok(),
        "a decoder accepted bytes that are not deterministic CBOR"
    );
    let encoded = encode(&value).expect("a value that was decoded can be encoded");
    assert!(
        encoded.len() <= data.len(),
        "the encoding of a decoded value is longer than its input"
    );
    assert!(
        canonical::check(&encoded).is_ok(),
        "an encoding is not deterministic CBOR"
    );
    assert_eq!(
        decode(&encoded).expect("an encoding does not decode"),
        value,
        "a round trip changed the value"
    );
}

/// The envelope (format.md 4.4).
pub fn envelope(data: &[u8]) {
    let Ok(decoded) = Envelope::decode(data) else {
        return;
    };
    assert!(canonical::check(data).is_ok());
    let encoded = Envelope::encode(decoded.object_type, decoded.schema, decoded.body)
        .expect("an envelope that was decoded can be encoded");
    assert!(encoded.len() <= data.len());
    assert_eq!(
        Envelope::decode(&encoded).expect("an encoding decodes"),
        decoded
    );
}

pub fn content_object(data: &[u8]) {
    decoder(data, ContentObject::decode, |v| v.encode());
}

pub fn item_record(data: &[u8]) {
    decoder(data, ItemRecord::decode, |v| v.encode());
}

pub fn delta_entry(data: &[u8]) {
    decoder(data, DeltaEntry::decode, |v| v.encode());
}

pub fn snapshot_header(data: &[u8]) {
    decoder(data, SnapshotHeader::decode, |v| v.encode());
}

pub fn vault_config(data: &[u8]) {
    decoder(data, VaultConfig::decode, |v| v.encode());
    // A config file is the map and a MAC (format.md 7.2.1).
    if let Ok((map, mac)) = split_config_file(data) {
        let joined = join_config_file(map, &mac).expect("a file that was split can be joined");
        assert_eq!(
            joined, data,
            "splitting and joining a config file changed it"
        );
    }
}

pub fn lock_file(data: &[u8]) {
    decoder(data, LockFile::decode, |v| Ok::<_, ()>(v.encode()));
}

pub fn object_table(data: &[u8]) {
    decoder(data, ObjectTable::decode, |v| v.encode());
}

// ---- The parts of a pack ----

/// The header, the footer and the trailer of a pack (format.md 6.7.1, 6.7.3 and 6.7.4).
pub fn pack_parts(data: &[u8]) {
    if let Ok(header) = Header::decode(data) {
        let encoded = header
            .encode()
            .expect("a header that was decoded can be encoded");
        assert_eq!(
            Header::decode(&encoded).expect("an encoding decodes"),
            header
        );
    }
    if let Ok(length) = Header::len_from_prefix(data) {
        assert!(
            (12..=12 + MAX_HEADER_SIZE as usize).contains(&length),
            "{length}"
        );
    }
    if let Some(last) = data.len().checked_sub(FOOTER_SIZE) {
        let bytes: &[u8; FOOTER_SIZE] = data[last..].try_into().expect("24 bytes");
        if let Ok(footer) = Footer::decode(bytes) {
            // All 24 bytes are fields or the end magic: the encoding is the input.
            assert_eq!(&footer.encode(), bytes, "a footer changed in a round trip");
        }
    }
    if let Ok(trailer) = Trailer::decode(data) {
        let encoded = Trailer::encode(trailer.seal, trailer.table)
            .expect("a trailer that was decoded can be encoded");
        assert_eq!(encoded, data, "a trailer changed in a round trip");
    }
}

/// Splits `data` into a part of at most `limit` bytes that its first byte (or two) sizes,
/// and the rest. The fuzzer chooses the sizes.
fn take<'a>(data: &mut &'a [u8], limit: usize, wide: bool) -> &'a [u8] {
    let (size, skip) = match (wide, &**data) {
        (true, [a, b, ..]) => (usize::from(u16::from_le_bytes([*a, *b])), 2),
        (false, [a, ..]) => (usize::from(*a), 1),
        _ => return &[],
    };
    *data = &data[skip..];
    let size = size.min(limit).min(data.len());
    let (part, rest) = data.split_at(size);
    *data = rest;
    part
}

/// A pack with a body, a seal and an object table that the fuzzer makes, and that is valid
/// in every other way (the tag of the table is right, and so are the header and the footer).
///
/// The input is: the size of the body (2 bytes), the body, the size of the seal (1 byte),
/// the seal, and the plaintext of the object table. The header is the header of A.8. So the
/// parts of A.8 are a valid input, and with the nonce `03` the pack of A.8 is made exactly.
///
/// The pack must open or be refused. When it opens, the rules of a pack hold, and every
/// object can be read or refused: no panic.
pub fn pack_with_table(data: &[u8]) {
    let mut rest = data;
    let body = take(&mut rest, MAX_BYTES, true);
    let seal = take(&mut rest, 4096, false);
    let table = rest;

    let file = pack_file(body, seal, table);
    let name = PackName::from_bytes(*blake3::hash(&file).as_bytes());
    let target = MemoryTarget::new();
    target.insert(&pack_path(&name), file);

    let Ok(pack) = block_on(Pack::open(&target, name, &writer_key())) else {
        return;
    };
    // The rules that `open` checks, checked again from the outside (format.md 6.7.3.5).
    let mut position = pack.header_len() as u64;
    for entry in &pack.table().entries {
        assert_eq!(
            entry.offset, position,
            "objects are not in order without gaps"
        );
        assert!(
            entry.packed_size >= 40,
            "a packed object is smaller than nonce and tag"
        );
        position += u64::from(entry.packed_size);
        if entry.key_class == KeyClass::R {
            assert!(
                !pack.seal().is_empty(),
                "an R object in a pack without a seal"
            );
        }
    }
    assert_eq!(
        position,
        (pack.header_len() + body.len()) as u64,
        "the objects do not end at the trailer"
    );
    // Every object: read, or refused. A table that opens can claim sizes that are not true.
    let keys = keys();
    for entry in &pack.table().entries {
        let _ = block_on(pack.read_object(&target, &entry.object_id, entry.object_type, &keys));
    }
}

/// The bytes of a pack with this body, seal and plaintext of the object table. The header is
/// the one of A.8: a data pack with the key encapsulation name `placeholder`.
pub fn pack_file(body: &[u8], seal: &[u8], table: &[u8]) -> Vec<u8> {
    let header = Header::new(PackClass::Data, Some("placeholder".into()))
        .encode()
        .expect("a header");
    let header_hash = *blake3::hash(&header).as_bytes();
    let packed_table = encrypt(
        &writer_key().pack_table_key(),
        &header_hash,
        table,
        &mut FixedRng(0x03),
    )
    .expect("the table encrypts");
    let trailer = Trailer::encode(seal, &packed_table).expect("a trailer");
    let footer = Footer {
        trailer_offset: (header.len() + body.len()) as u64,
        trailer_size: u32::try_from(trailer.len()).expect("a trailer is small"),
        format_version: 0,
    };
    let mut file = header;
    file.extend_from_slice(body);
    file.extend_from_slice(&trailer);
    file.extend_from_slice(&footer.encode());
    file
}

/// One packed object of a pack, with bytes that the fuzzer makes. Reading it checks the tag,
/// decompresses, and checks the size and the object ID (format.md 6.6.4 and 6.7.5). This is
/// the path that ADR 0016 promises to fuzz: a node with the writer key can write a stream
/// that a person who restores will read.
///
/// The input is: the compression (one byte: 0 is none, other values are DEFLATE), the
/// unpacked size (2 bytes), and the bytes that are encrypted as the packed object.
///
/// The result must be exactly what an independent decompression says: the stored bytes with
/// the size of the table, or an error. The object ID is made from the result of that
/// decompression, so that the good path is reached. The size is at most 1 MiB, so the check
/// itself needs little memory.
pub fn pack_with_object(data: &[u8]) {
    let [mode, a, b, packed @ ..] = data else {
        return;
    };
    let unpacked_size = usize::from(u16::from_le_bytes([*a, *b]));
    let deflate = *mode != 0;
    let object_type = 2;

    let expected: Option<Vec<u8>> = if deflate {
        miniz_oxide::inflate::decompress_to_vec_with_limit(packed, unpacked_size)
            .ok()
            .filter(|stored| stored.len() == unpacked_size)
    } else {
        (packed.len() == unpacked_size).then(|| packed.to_vec())
    };
    // The ID of the good bytes, or an ID that nothing has.
    let id = ObjectId::from_bytes(
        dedup_key()
            .domain_keys()
            .object_id(object_type, expected.as_deref().unwrap_or(b"no such bytes")),
    );

    // The packed object: the bytes of the fuzzer, encrypted with the key of a W object.
    let mut aad = [0u8; 36];
    aad[..32].copy_from_slice(id.as_bytes());
    aad[32..].copy_from_slice(&object_type.to_le_bytes());
    let packed_object = encrypt(
        &writer_key().pack_object_key(),
        &aad,
        packed,
        &mut FixedRng(0x02),
    )
    .expect("the object encrypts");

    let header = Header::new(PackClass::Data, None)
        .encode()
        .expect("a header");
    let table = ObjectTable {
        entries: vec![ObjectTableEntry {
            object_id: id,
            object_type,
            key_class: KeyClass::W,
            offset: header.len() as u64,
            packed_size: u32::try_from(packed_object.len()).expect("small"),
            compression: if deflate {
                Compression::Deflate
            } else {
                Compression::None
            },
            unpacked_size: u32::try_from(unpacked_size).expect("a u16"),
        }],
    };
    let header_hash = *blake3::hash(&header).as_bytes();
    let packed_table = encrypt(
        &writer_key().pack_table_key(),
        &header_hash,
        &table.encode().expect("a table"),
        &mut FixedRng(0x03),
    )
    .expect("the table encrypts");
    let trailer = Trailer::encode(&[], &packed_table).expect("a trailer");
    let mut file = header.clone();
    file.extend_from_slice(&packed_object);
    let footer = Footer {
        trailer_offset: file.len() as u64,
        trailer_size: u32::try_from(trailer.len()).expect("small"),
        format_version: 0,
    };
    file.extend_from_slice(&trailer);
    file.extend_from_slice(&footer.encode());

    let name = PackName::from_bytes(*blake3::hash(&file).as_bytes());
    let target = MemoryTarget::new();
    target.insert(&pack_path(&name), file);
    let pack = block_on(Pack::open(&target, name, &writer_key())).expect("the pack opens");
    let read = block_on(pack.read_object(&target, &id, object_type, &keys()));
    match (read, expected) {
        (Ok(stored), Some(expected)) => assert_eq!(
            stored, expected,
            "the stored bytes are not the bytes of the stream"
        ),
        (Err(_), None) => {}
        (Ok(_), None) => {
            panic!("the reader accepted an object that an independent decompression refuses")
        }
        (Err(e), Some(_)) => panic!("the reader refused an object that is valid: {e}"),
    }
}

// ---- The encryption ----

/// A packed object that is not an encryption of anything, and a key that is not a key: the
/// functions refuse, and do not panic (format.md 3.3.5).
pub fn encryption(data: &[u8]) {
    let key = nilperit_crypto::AeadKey::from_bytes([7; 32]);
    let _ = decrypt(&key, b"associated data", data);
    // A seal has a size that the format fixes (format.md 3.3.2). Any other is refused.
    let read_key = ReadKey::from_seed([9; 32]);
    let _ = open_seal(&read_key, data, &[0; 32]);
    let _ = ReadPublicKey::from_bytes(data);
}

// ---- The chunker ----

/// A source that gives its bytes in pieces of a size that the fuzzer chooses.
struct Pieces<'a> {
    data: &'a [u8],
    sizes: &'a [u8],
    next: usize,
}

impl Read for Pieces<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let size = self
            .sizes
            .get(self.next % self.sizes.len().max(1))
            .copied()
            .unwrap_or(1);
        self.next += 1;
        let count = usize::from(size).max(1).min(self.data.len()).min(out.len());
        out[..count].copy_from_slice(&self.data[..count]);
        self.data = &self.data[count..];
        Ok(count)
    }
}

/// The fixed-size chunker (format.md 5.2.4.1), whatever the sizes of the pieces that the
/// source gives: the chunks, put together, are the input, and every chunk has the size of the
/// chunker, except the last one, which is not empty and not larger.
///
/// The input is: the size of a chunk (1 byte, from 1 to 64), the sizes of the pieces (one
/// byte for each of the next 8 bytes), and the bytes to cut.
pub fn chunker(data: &[u8]) {
    let [size, rest @ ..] = data else {
        return;
    };
    let size = usize::from(*size % 64) + 1;
    let (pieces, input) = rest.split_at(rest.len().min(8));
    let source = Pieces {
        data: input,
        sizes: pieces,
        next: 0,
    };
    let chunks: Vec<Vec<u8>> = ChunkReader::new(source, Fixed::new(size).expect("a size above 0"))
        .map(|chunk| chunk.expect("an in-memory source does not fail"))
        .collect();
    assert_eq!(chunks.concat(), input, "the chunks are not the input");
    assert_eq!(
        chunks.len(),
        input.len().div_ceil(size),
        "the number of chunks"
    );
    for (index, chunk) in chunks.iter().enumerate() {
        assert!(!chunk.is_empty(), "an empty chunk");
        if index + 1 < chunks.len() {
            assert_eq!(
                chunk.len(),
                size,
                "a chunk that is not the last has another size"
            );
        } else {
            assert!(chunk.len() <= size, "the last chunk is too large");
        }
    }
}

/// Every check, by name. The mutation tests and the fuzzers use the names.
/// A check: it takes bytes and panics when a rule is broken.
pub type Check = fn(&[u8]);

pub const TARGETS: &[(&str, Check)] = &[
    ("canonical", canonical),
    ("envelope", envelope),
    ("content_object", content_object),
    ("item_record", item_record),
    ("delta_entry", delta_entry),
    ("snapshot_header", snapshot_header),
    ("vault_config", vault_config),
    ("lock_file", lock_file),
    ("object_table", object_table),
    ("pack_parts", pack_parts),
    ("pack_with_table", pack_with_table),
    ("pack_with_object", pack_with_object),
    ("encryption", encryption),
    ("chunker", chunker),
];

#[cfg(test)]
mod tests {
    //! A check that cannot fail is worth nothing. These tests give the checks a decoder that
    //! breaks a rule, and see that the check stops it.

    use super::*;

    #[test]
    #[should_panic(expected = "not deterministic CBOR")]
    fn a_decoder_that_accepts_input_that_is_not_deterministic_cbor_is_caught() {
        // `18 01` is the number 1 in a form that is not the shortest.
        decoder(
            &[0x18, 0x01],
            |d| Ok::<_, ()>(d[0]),
            |v| Ok::<_, ()>(vec![*v]),
        );
    }

    #[test]
    #[should_panic(expected = "longer than its input")]
    fn an_encoder_that_makes_more_than_it_was_given_is_caught() {
        decoder(
            &[0x01],
            |d| Ok::<_, ()>(d[0]),
            |v| Ok::<_, ()>(vec![*v, *v]),
        );
    }

    #[test]
    #[should_panic(expected = "round trip changed the value")]
    fn a_round_trip_that_changes_the_value_is_caught() {
        decoder(&[0x01], |d| Ok::<_, ()>(d[0]), |_| Ok::<_, ()>(vec![0x02]));
    }

    #[test]
    #[should_panic(expected = "can be encoded")]
    fn a_value_that_cannot_be_encoded_is_caught() {
        decoder(&[0x01], |d| Ok::<_, ()>(d[0]), |_| Err::<Vec<u8>, _>(()));
    }

    #[test]
    fn a_decoder_that_refuses_is_a_pass() {
        decoder(&[0xff], |_| Err::<u8, _>(()), |v| Ok::<_, ()>(vec![*v]));
    }

    #[test]
    fn the_checks_pass_on_ordinary_input() {
        // A few inputs by hand: empty, a number, and the pack of A.8.
        for (_, check) in TARGETS {
            check(&[]);
            check(&[0x00]);
            check(&[0xff; 64]);
        }
    }
}
