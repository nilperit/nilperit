//! Opening a pack (format.md 6.7.5, steps 1 to 4).
//!
//! `Pack::open` reads the parts of a pack that tell what is in it: the footer,
//! the header, and the trailer. It needs only the writer key, so a node can use
//! it too. It does not read the objects, and it does not open the seal. A pack
//! with a damaged seal still gives its W objects.
//!
//! It does not check the name of the pack against the hash of the file, because
//! that needs a read of the whole file. The tags check every part that a reader
//! uses. A scrub checks the names (format.md 9.2, 10.1).

use crate::keys::Keys;
use crate::layout::pack_path;
use crate::target::{Target, TargetError};
use alloc::vec::Vec;
use core::fmt;
use nilperit_crypto::seal::KEM_NAME;
use nilperit_crypto::{AeadKey, SealError, WriterKey, decrypt, open_seal};
use nilperit_format::pack::FOOTER_SIZE;
use nilperit_format::{
    Compression, Footer, Header, KeyClass, ObjectId, ObjectTable, ObjectTableEntry, PackError,
    PackName, Trailer,
};

/// A pack could not be opened.
#[derive(Debug)]
pub enum PackOpenError {
    /// The target failed. A pack that is not there is `Target(NotFound)`.
    Target(TargetError),
    /// The pack breaks a rule of the format.
    Format(PackError),
    /// The tag of the object table is not correct: the pack is damaged, or it
    /// belongs to another vault.
    NotAuthentic,
}

impl fmt::Display for PackOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(e) => e.fmt(f),
            Self::Format(e) => e.fmt(f),
            Self::NotAuthentic => f.write_str("the object table of the pack is not authentic"),
        }
    }
}

impl core::error::Error for PackOpenError {}

impl From<TargetError> for PackOpenError {
    fn from(e: TargetError) -> Self {
        Self::Target(e)
    }
}

impl From<PackError> for PackOpenError {
    fn from(e: PackError) -> Self {
        Self::Format(e)
    }
}

/// The associated data of a packed object: the object ID and the type ID as 4
/// bytes, little-endian (format.md 6.7.2.3).
fn associated_data(entry: &ObjectTableEntry) -> [u8; 36] {
    let mut aad = [0u8; 36];
    aad[..32].copy_from_slice(entry.object_id.as_bytes());
    aad[32..].copy_from_slice(&entry.object_type.to_le_bytes());
    aad
}

/// An object could not be read from a pack.
#[derive(Debug)]
pub enum ObjectReadError {
    /// The target failed.
    Target(TargetError),
    /// The object table of the pack has no entry with this object ID.
    NotInPack,
    /// The entry has another type than the caller expects.
    WrongType,
    /// The pack key of an R object cannot be opened because the pack uses an
    /// algorithm that this code does not know.
    UnknownAlgorithm,
    /// The seal does not open with the read key.
    Seal(SealError),
    /// The object is an R object, and the reader has no read key. A node never
    /// has it (ADR 0004).
    NoReadKey,
    /// The tag of the object is not correct: the object is damaged, or it does
    /// not belong to its entry (format.md 6.7.2.3).
    NotAuthentic,
    /// The DEFLATE stream is not valid, or it is longer than the unpacked size.
    BadCompression,
    /// The unpacked bytes do not have the unpacked size of the table.
    SizeMismatch,
    /// The unpacked bytes do not have the object ID of their entry.
    IdMismatch,
    /// The object does not fit in the memory of this reader (format.md 6.7.6.3).
    TooLarge,
}

impl fmt::Display for ObjectReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target(e) => e.fmt(f),
            Self::NotInPack => f.write_str("the object is not in the pack"),
            Self::WrongType => f.write_str("the object has another type than expected"),
            Self::UnknownAlgorithm => f.write_str("the pack uses an unknown algorithm"),
            Self::Seal(e) => write!(f, "the seal does not open: {e}"),
            Self::NoReadKey => f.write_str("the object needs the read key, which is not here"),
            Self::NotAuthentic => f.write_str("the object is not authentic"),
            Self::BadCompression => f.write_str("the compressed bytes are not valid"),
            Self::SizeMismatch => f.write_str("the object does not have its unpacked size"),
            Self::IdMismatch => f.write_str("the object does not have its object ID"),
            Self::TooLarge => f.write_str("the object is too large for this reader"),
        }
    }
}

impl core::error::Error for ObjectReadError {}

impl From<TargetError> for ObjectReadError {
    fn from(e: TargetError) -> Self {
        Self::Target(e)
    }
}

/// A pack that has been opened: its header, its sealed pack key, and its object
/// table. The objects are not read yet.
#[derive(Debug)]
pub struct Pack {
    name: PackName,
    header: Header,
    header_len: usize,
    header_hash: [u8; 32],
    seal: Vec<u8>,
    table: ObjectTable,
}

impl Pack {
    /// Opens the pack with this name.
    pub async fn open<T: Target>(
        target: &T,
        name: PackName,
        writer: &WriterKey,
    ) -> Result<Self, PackOpenError> {
        let path = pack_path(&name);
        let file_size = target.len(&path).await?;

        // 1. The footer. A pack that is shorter than a footer has none.
        let footer_start = file_size
            .checked_sub(FOOTER_SIZE as u64)
            .ok_or(PackError::Truncated)?;
        let footer_bytes: [u8; FOOTER_SIZE] = target
            .read_range(&path, footer_start..file_size)
            .await?
            .try_into()
            .map_err(|_| PackError::Truncated)?;
        let footer = Footer::decode(&footer_bytes)?;

        // 3. The header: first its length, then the whole header. This comes
        // before the trailer, so a footer that lies cannot make us read far.
        let prefix = target.read_range(&path, 0..12.min(file_size)).await?;
        let header_len = Header::len_from_prefix(&prefix)?;
        let header_bytes = target.read_range(&path, 0..header_len as u64).await?;
        let header = Header::decode(&header_bytes)?;
        footer.check(file_size, &header, header_len)?;

        // 2. The trailer. The checks above make the range lie inside the file.
        let trailer_end = footer.trailer_offset + u64::from(footer.trailer_size);
        let trailer_bytes = target
            .read_range(&path, footer.trailer_offset..trailer_end)
            .await?;
        let trailer = Trailer::decode(&trailer_bytes)?;

        // 4. The object table. Its tag authenticates the header as well.
        let header_hash = *blake3::hash(&header_bytes).as_bytes();
        let plain = decrypt(&writer.pack_table_key(), &header_hash, trailer.table)
            .map_err(|_| PackOpenError::NotAuthentic)?;
        let table = ObjectTable::decode(&plain)?;
        table.validate(header_len, footer.trailer_offset, trailer.seal.len())?;

        Ok(Self {
            name,
            header,
            header_len,
            header_hash,
            seal: trailer.seal.to_vec(),
            table,
        })
    }

    /// Reads one object and returns its stored bytes (format.md 6.7.5, step 5).
    ///
    /// The caller says the type that it expects. An entry with another type gives
    /// `WrongType` before any byte is read: a chunk ID must not give the bytes of
    /// another kind of object.
    ///
    /// It checks the tag, decompresses to exactly the unpacked size, and checks the
    /// object ID. It returns no byte before all of these checks pass.
    pub async fn read_object<T: Target>(
        &self,
        target: &T,
        id: &ObjectId,
        object_type: u32,
        keys: &Keys,
    ) -> Result<Vec<u8>, ObjectReadError> {
        let entry = self
            .table
            .entries
            .iter()
            .find(|entry| entry.object_id == *id)
            .ok_or(ObjectReadError::NotInPack)?;
        if entry.object_type != object_type {
            return Err(ObjectReadError::WrongType);
        }
        // Check the size first, so that a reader with little memory stops early.
        let unpacked_size =
            usize::try_from(entry.unpacked_size).map_err(|_| ObjectReadError::TooLarge)?;

        // The table was checked in `open`, so the range lies inside the body.
        let end = entry.offset + u64::from(entry.packed_size);
        let packed = target
            .read_range(&pack_path(&self.name), entry.offset..end)
            .await?;

        let key = match entry.key_class {
            KeyClass::W => keys.writer().pack_object_key(),
            KeyClass::R => self.open_pack_key(keys)?,
        };
        let compressed = decrypt(&key, &associated_data(entry), &packed)
            .map_err(|_| ObjectReadError::NotAuthentic)?;

        let stored = match entry.compression {
            Compression::None => compressed,
            Compression::Deflate => {
                miniz_oxide::inflate::decompress_to_vec_with_limit(&compressed, unpacked_size)
                    .map_err(|_| ObjectReadError::BadCompression)?
            }
        };
        if stored.len() != unpacked_size {
            return Err(ObjectReadError::SizeMismatch);
        }
        let expected = keys.domains().object_id(entry.object_type, &stored);
        if expected != *entry.object_id.as_bytes() {
            return Err(ObjectReadError::IdMismatch);
        }
        Ok(stored)
    }

    /// Opens the sealed pack key (format.md 3.3.2.3).
    fn open_pack_key(&self, keys: &Keys) -> Result<AeadKey, ObjectReadError> {
        let read = keys.read().ok_or(ObjectReadError::NoReadKey)?;
        if self.header.key_encapsulation.as_deref() != Some(KEM_NAME) {
            return Err(ObjectReadError::UnknownAlgorithm);
        }
        open_seal(read, &self.seal, &self.header_hash).map_err(ObjectReadError::Seal)
    }

    /// The name of the pack.
    pub fn name(&self) -> &PackName {
        &self.name
    }

    /// The header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The length of the header in bytes. The first packed object starts here.
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// The BLAKE3 hash of the header. It is the associated data of the seal.
    pub fn header_hash(&self) -> &[u8; 32] {
        &self.header_hash
    }

    /// The sealed pack key. It is empty when the pack has no R objects.
    pub fn seal(&self) -> &[u8] {
        &self.seal
    }

    /// The object table.
    pub fn table(&self) -> &ObjectTable {
        &self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::pack_path;
    use crate::memory_target::MemoryTarget;
    use crate::test_util::block_on;
    use alloc::string::ToString;
    use alloc::vec;
    use nilperit_format::{Compression, KeyClass, PackClass};

    // The pack of format.md A.8.5 (408 bytes), made with other software. Its
    // writer key is the 32 bytes `20 21 ... 3f` (A.8.2).
    const PACK_HEX: &str = "894e504b0d0a1a0a2e000000a50100020003727863686163686132302d706f6c7931333035046b706c616365686f6c6465720566626c616b65330101010101010101010101010101010101010101010101014683820b6bdd17744f45bb9c2275d3d73057e39b980765020202020202020202020202020202020202020202020202c5e12b97bd9e2e7d093d49a7a9c7db234d82f2da194b7b55517ebcb80e3a652036e81578286e7506f30dcfb8a8ea38f7111dd372053a9b7c65a12982437fe67c87390691e4e97a85f48e30a866aa17f9bebfe753881f5c03d706534a1efb54a9fd9a04000000deadbeef030303030303030303030303030303030303030303030303641136128a959b741d53c008bbdf760f87c8ed6499d7ad62b8c483c0e134ba3c269eff66bb08c01ee9baf1a4a9608275c2a7e0e252b52c3bcdb28471056b637fca99bb999c6ff11fdd451bbaba53b9db719e0eb1f81e91603528d27060f14b5036b5818c1144c0fd989adddcc5353d7ab9ab11c81e9e47dc98fba75147e3000000000000009d000000000000004e504b2d454e440a";
    // The name of the pack (A.8.6).
    const PACK_NAME: &str = "815dfe4dc31fbd77d535dbb466deb78b72b45ff294e6c32af5d43fdf7ad2288d";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn writer() -> WriterKey {
        WriterKey::from_bytes(core::array::from_fn(|i| 0x20 + i as u8))
    }

    fn name() -> PackName {
        PackName::from_bytes(unhex(PACK_NAME).try_into().unwrap())
    }

    fn target_with(bytes: Vec<u8>) -> MemoryTarget {
        let target = MemoryTarget::new();
        target.insert(&pack_path(&name()), bytes);
        target
    }

    fn open(bytes: Vec<u8>) -> Result<Pack, PackOpenError> {
        block_on(Pack::open(&target_with(bytes), name(), &writer()))
    }

    #[test]
    fn opens_the_appendix_vector() {
        let pack = open(unhex(PACK_HEX)).unwrap();
        assert_eq!(pack.name(), &name());
        assert_eq!(pack.header().class, PackClass::Data);
        assert_eq!(pack.header_len(), 58);
        assert_eq!(pack.seal(), [0xde, 0xad, 0xbe, 0xef]);
        let entries = &pack.table().entries;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].object_type, 1);
        assert_eq!(entries[0].key_class, KeyClass::R);
        assert_eq!(entries[0].compression, Compression::Deflate);
        assert_eq!((entries[0].offset, entries[0].packed_size), (58, 47));
        assert_eq!(entries[1].object_type, 2);
        assert_eq!(entries[1].key_class, KeyClass::W);
        assert_eq!(entries[1].compression, Compression::None);
        assert_eq!((entries[1].offset, entries[1].packed_size), (105, 122));
        let expected = "d71209092db378d52cf1f9427be77e17f9d6b91cc3fa98068912de99feb819ba";
        assert_eq!(pack.header_hash()[..], unhex(expected)[..]);
    }

    #[test]
    fn a_missing_pack_is_not_found() {
        let result = block_on(Pack::open(&MemoryTarget::new(), name(), &writer()));
        assert!(matches!(
            result,
            Err(PackOpenError::Target(TargetError::NotFound))
        ));
    }

    #[test]
    fn rejects_a_pack_that_another_writer_key_opens() {
        let other = WriterKey::from_bytes([1; 32]);
        let result = block_on(Pack::open(&target_with(unhex(PACK_HEX)), name(), &other));
        assert!(matches!(result, Err(PackOpenError::NotAuthentic)));
    }

    #[test]
    fn rejects_a_pack_that_is_too_short() {
        for len in [0, 11, 23, 24, 58, 100, 383, 407] {
            let mut bytes = unhex(PACK_HEX);
            bytes.truncate(len);
            assert!(open(bytes).is_err(), "length {len}");
        }
    }

    #[test]
    fn rejects_a_changed_byte_in_every_part_that_open_reads() {
        // The header (0..58), the trailer (227..384) and the footer (384..408).
        // The body (58..227) is not read here: the tags of the objects check it.
        // The seal (231..235) is not opened here either (see the next test).
        let good = unhex(PACK_HEX);
        for position in (0..58).chain(227..231).chain(235..408) {
            let mut bytes = good.clone();
            bytes[position] ^= 1;
            assert!(open(bytes).is_err(), "byte {position}");
        }
    }

    #[test]
    fn does_not_open_the_seal() {
        // A damaged seal must not stop a reader from reading the W objects.
        let mut bytes = unhex(PACK_HEX);
        bytes[231] ^= 1;
        let pack = open(bytes).unwrap();
        assert_eq!(pack.seal(), [0xdf, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn does_not_read_the_body() {
        let good = unhex(PACK_HEX);
        let mut bytes = good.clone();
        bytes[100] ^= 1;
        assert!(open(bytes).is_ok());
    }

    #[test]
    fn rejects_a_footer_that_points_outside_the_file() {
        let mut bytes = unhex(PACK_HEX);
        // The trailer offset (the first 8 bytes of the footer) goes beyond the file.
        bytes[384..392].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(open(bytes), Err(PackOpenError::Format(_))));
    }

    #[test]
    fn a_failing_target_is_an_error() {
        struct Failing;
        impl Target for Failing {
            async fn len(&self, _: &str) -> Result<u64, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
            async fn read_range(
                &self,
                _: &str,
                _: core::ops::Range<u64>,
            ) -> Result<Vec<u8>, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
            async fn read(&self, _: &str) -> Result<Vec<u8>, TargetError> {
                Err(TargetError::Other("disk".to_string()))
            }
            async fn list(&self, _: &str) -> Result<Vec<alloc::string::String>, TargetError> {
                Ok(vec![])
            }
        }
        let result = block_on(Pack::open(&Failing, name(), &writer()));
        assert!(matches!(
            result,
            Err(PackOpenError::Target(TargetError::Other(_)))
        ));
    }

    // ---- Reading objects

    use crate::Keys;
    use crate::test_util::{TestKeys, TestObject, build_pack};
    use nilperit_crypto::{DedupKey, ReadKey};
    use nilperit_format::ObjectId;

    // The object ID of the content object in A.8.3, and its 82 stored bytes.
    const A8_CONTENT_ID: &str = "286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e";
    const A8_CONTENT: &str = "a30002010102a40181582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e0205035820ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e0401";
    const A8_CHUNK_ID: &str = "09c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e";

    // The keys of A.8: dedup key `00 .. 1f`, writer key `20 .. 3f`. The read key
    // is not part of the vector: its seal is a placeholder.
    fn a8_keys() -> Keys {
        let dedup = DedupKey::from_bytes(core::array::from_fn(|i| i as u8));
        Keys::new(writer(), ReadKey::from_seed([9; 32]), &dedup)
    }

    fn oid(hex: &str) -> ObjectId {
        ObjectId::from_bytes(unhex(hex).try_into().unwrap())
    }

    fn read(
        pack: &Pack,
        target: &MemoryTarget,
        id: &ObjectId,
        keys: &Keys,
    ) -> Result<Vec<u8>, ObjectReadError> {
        // The tests ask for the type that the table gives, except for an object
        // that is not in the table.
        let object_type = pack
            .table()
            .entries
            .iter()
            .find(|entry| entry.object_id == *id)
            .map_or(0, |entry| entry.object_type);
        block_on(pack.read_object(target, id, object_type, keys))
    }

    #[test]
    fn reads_the_w_object_of_the_appendix_vector() {
        let target = target_with(unhex(PACK_HEX));
        let pack = block_on(Pack::open(&target, name(), &writer())).unwrap();
        let stored = read(&pack, &target, &oid(A8_CONTENT_ID), &a8_keys()).unwrap();
        assert_eq!(stored, unhex(A8_CONTENT));
    }

    #[test]
    fn the_appendix_vector_has_no_seal_that_opens() {
        // The chunk is an R object, and the seal of A.8 is a placeholder.
        let target = target_with(unhex(PACK_HEX));
        let pack = block_on(Pack::open(&target, name(), &writer())).unwrap();
        let result = read(&pack, &target, &oid(A8_CHUNK_ID), &a8_keys());
        assert!(matches!(result, Err(ObjectReadError::UnknownAlgorithm)));
    }

    #[test]
    fn rejects_an_object_of_another_type_than_expected() {
        let target = target_with(unhex(PACK_HEX));
        let pack = block_on(Pack::open(&target, name(), &writer())).unwrap();
        // The content object has type 2.
        let result = block_on(pack.read_object(&target, &oid(A8_CONTENT_ID), 1, &a8_keys()));
        assert!(matches!(result, Err(ObjectReadError::WrongType)));
    }

    #[test]
    fn a_missing_object_is_not_in_the_pack() {
        let target = target_with(unhex(PACK_HEX));
        let pack = block_on(Pack::open(&target, name(), &writer())).unwrap();
        let result = read(&pack, &target, &ObjectId::from_bytes([0; 32]), &a8_keys());
        assert!(matches!(result, Err(ObjectReadError::NotInPack)));
    }

    #[test]
    fn rejects_a_damaged_object_of_the_appendix_vector() {
        let mut bytes = unhex(PACK_HEX);
        // The content object is at 105..227. Change one byte of its ciphertext.
        bytes[150] ^= 1;
        let target = target_with(bytes);
        let pack = block_on(Pack::open(&target, name(), &writer())).unwrap();
        let result = read(&pack, &target, &oid(A8_CONTENT_ID), &a8_keys());
        assert!(matches!(result, Err(ObjectReadError::NotAuthentic)));
    }

    /// Opens a pack that the test builder made.
    fn built(objects: &[TestObject]) -> (Pack, MemoryTarget, TestKeys, Vec<ObjectId>) {
        let keys = TestKeys::new(0x50);
        let (bytes, ids) = build_pack(&keys, objects);
        let name = PackName::from_bytes(*blake3::hash(&bytes).as_bytes());
        let target = MemoryTarget::new();
        target.insert(&pack_path(&name), bytes);
        let pack = block_on(Pack::open(&target, name, &keys.writer)).unwrap();
        (pack, target, keys, ids)
    }

    fn repetitive() -> Vec<u8> {
        b"nilperit ".repeat(2000)
    }

    #[test]
    fn reads_every_combination_of_key_class_and_compression() {
        let objects = [
            TestObject::new(1, KeyClass::R, Compression::None, b"hello"),
            TestObject::new(1, KeyClass::R, Compression::Deflate, &repetitive()),
            TestObject::new(2, KeyClass::W, Compression::None, b"content object"),
            TestObject::new(2, KeyClass::W, Compression::Deflate, &repetitive()),
            TestObject::new(1, KeyClass::R, Compression::None, b""),
            TestObject::new(3, KeyClass::W, Compression::Deflate, b""),
        ];
        let (pack, target, keys, ids) = built(&objects);
        let reader_keys = keys.keys();
        for (object, id) in objects.iter().zip(&ids) {
            let stored = read(&pack, &target, id, &reader_keys).unwrap();
            assert_eq!(stored, object.stored);
        }
    }

    #[test]
    fn a_reader_with_the_wrong_read_key_cannot_open_an_r_object() {
        let objects = [TestObject::new(
            1,
            KeyClass::R,
            Compression::None,
            b"secret",
        )];
        let (pack, target, keys, ids) = built(&objects);
        let wrong = Keys::new(
            WriterKey::from_bytes(*keys.writer.as_bytes()),
            ReadKey::from_seed([0xee; 32]),
            &keys.dedup,
        );
        let result = read(&pack, &target, &ids[0], &wrong);
        assert!(matches!(result, Err(ObjectReadError::Seal(_))));
    }

    #[test]
    fn rejects_an_object_that_does_not_have_its_object_id() {
        let mut object = TestObject::new(1, KeyClass::W, Compression::None, b"data");
        // The tag is right for the claimed ID, but the bytes do not hash to it.
        let claimed = ObjectId::from_bytes([0x77; 32]);
        object.claim_id = Some(claimed);
        let (pack, target, keys, _) = built(&[object]);
        let result = read(&pack, &target, &claimed, &keys.keys());
        assert!(matches!(result, Err(ObjectReadError::IdMismatch)));
    }

    #[test]
    fn rejects_the_wrong_unpacked_size() {
        for (compression, size) in [
            (Compression::None, 3),
            (Compression::None, 12),
            (Compression::Deflate, 3),
            (Compression::Deflate, 12),
        ] {
            let mut object = TestObject::new(1, KeyClass::W, Compression::None, b"data data");
            object.compression = compression;
            object.claim_unpacked_size = Some(size);
            let (pack, target, keys, ids) = built(&[object]);
            let result = read(&pack, &target, &ids[0], &keys.keys());
            assert!(
                matches!(
                    result,
                    Err(ObjectReadError::SizeMismatch | ObjectReadError::BadCompression)
                ),
                "{compression:?} {size}"
            );
        }
    }

    #[test]
    fn rejects_a_compression_name_that_does_not_match_the_bytes() {
        let mut object = TestObject::new(1, KeyClass::W, Compression::None, b"not deflate");
        object.claim_compression = Some(Compression::Deflate);
        let (pack, target, keys, ids) = built(&[object]);
        let result = read(&pack, &target, &ids[0], &keys.keys());
        assert!(matches!(result, Err(ObjectReadError::BadCompression)));
    }

    #[test]
    fn rejects_a_deflate_bomb_without_allocating_its_output() {
        // 1 MiB of zeros compresses to about 1 KiB. The table says 10 bytes.
        let zeros = vec![0u8; 1 << 20];
        let mut object = TestObject::new(1, KeyClass::W, Compression::Deflate, &zeros);
        object.claim_unpacked_size = Some(10);
        let (pack, target, keys, ids) = built(&[object]);
        let result = read(&pack, &target, &ids[0], &keys.keys());
        assert!(matches!(result, Err(ObjectReadError::BadCompression)));
    }

    #[test]
    fn rejects_a_damaged_object_in_a_built_pack() {
        let keys = TestKeys::new(0x50);
        let objects = [TestObject::new(
            1,
            KeyClass::R,
            Compression::Deflate,
            &repetitive(),
        )];
        let (mut bytes, ids) = build_pack(&keys, &objects);
        let name = PackName::from_bytes(*blake3::hash(&bytes).as_bytes());
        let target = MemoryTarget::new();
        target.insert(&pack_path(&name), bytes.clone());
        let offset = block_on(Pack::open(&target, name, &keys.writer))
            .unwrap()
            .table()
            .entries[0]
            .offset as usize;
        // Change one byte of the ciphertext. The table is not changed.
        bytes[offset + 30] ^= 1;
        target.insert(&pack_path(&name), bytes);
        let pack = block_on(Pack::open(&target, name, &keys.writer)).unwrap();
        let result = read(&pack, &target, &ids[0], &keys.keys());
        assert!(matches!(result, Err(ObjectReadError::NotAuthentic)));
    }

    #[test]
    fn a_node_reads_w_objects_and_not_r_objects() {
        let objects = [
            TestObject::new(1, KeyClass::R, Compression::None, b"secret"),
            TestObject::new(2, KeyClass::W, Compression::None, b"structure"),
        ];
        let (pack, target, keys, ids) = built(&objects);
        let node = Keys::for_node(
            WriterKey::from_bytes(*keys.writer.as_bytes()),
            keys.read.public_key(),
            &keys.dedup,
        );
        assert_eq!(read(&pack, &target, &ids[1], &node).unwrap(), b"structure");
        assert!(matches!(
            read(&pack, &target, &ids[0], &node),
            Err(ObjectReadError::NoReadKey)
        ));
        // The owner reads both.
        assert_eq!(
            read(&pack, &target, &ids[0], &keys.keys()).unwrap(),
            b"secret"
        );
    }
}
