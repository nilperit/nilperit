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

use crate::layout::pack_path;
use crate::target::{Target, TargetError};
use alloc::vec::Vec;
use core::fmt;
use nilperit_crypto::{WriterKey, decrypt};
use nilperit_format::pack::FOOTER_SIZE;
use nilperit_format::{Footer, Header, ObjectTable, PackError, PackName, Trailer};

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
        let mut target = MemoryTarget::new();
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
}
