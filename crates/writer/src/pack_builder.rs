//! Building a pack (format.md 6.7).
//!
//! A [`PackBuilder`] takes stored objects, one by one, and encrypts them into the
//! body of a pack. [`PackBuilder::finish`] writes the header, the object table, the
//! seal and the footer, and gives the bytes of the whole pack and its name.
//!
//! The builder does not decide how big a pack is, or which objects go together
//! (format.md 6.1, 6.2). The caller reads [`PackBuilder::len`] and finishes the
//! pack when it is big enough.

use crate::credential::Credential;
use nilperit_crypto::seal::KEM_NAME;
use nilperit_crypto::{AeadKey, CryptoRng, SealError, encrypt, seal_pack_key};
use nilperit_format::pack::PACKED_OBJECT_OVERHEAD;
use nilperit_format::{
    Compression, Footer, Header, KeyClass, ObjectId, ObjectTable, ObjectTableEntry, PackClass,
    PackError, PackName, Trailer,
};
use std::collections::BTreeSet;
use std::fmt;

/// Why a pack could not be built.
#[derive(Debug)]
pub enum BuildError {
    /// The object type is not an object in a pack, so it has no key class.
    UnknownType(u32),
    /// An object is 4 GiB or larger (format.md 6.7.6).
    TooLarge,
    /// The encryption failed.
    Encryption,
    /// The seal failed.
    Seal(SealError),
    /// A part of the pack breaks a rule of the format.
    Format(PackError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(t) => write!(f, "object type {t} is not an object in a pack"),
            Self::TooLarge => f.write_str("the object is too large for a pack"),
            Self::Encryption => f.write_str("the encryption failed"),
            Self::Seal(e) => write!(f, "the seal failed: {e}"),
            Self::Format(e) => write!(f, "the pack is not valid: {e}"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<PackError> for BuildError {
    fn from(e: PackError) -> Self {
        Self::Format(e)
    }
}

/// A finished pack.
#[derive(Debug)]
pub struct BuiltPack {
    /// The name of the pack: the BLAKE3 hash of `bytes` (format.md 6.4).
    pub name: PackName,
    /// The bytes of the whole pack file.
    pub bytes: Vec<u8>,
    /// The objects in the pack, in the order of the body, with their types.
    pub objects: Vec<(ObjectId, u32)>,
}

/// Collects objects for one pack.
pub struct PackBuilder<'a> {
    credential: &'a Credential,
    class: PackClass,
    // The key of R objects. It exists after the first R object.
    pack_key: Option<AeadKey>,
    body: Vec<u8>,
    // The offsets count from the start of the body: the length of the header is
    // not known before `finish`.
    entries: Vec<ObjectTableEntry>,
    seen: BTreeSet<ObjectId>,
}

impl<'a> PackBuilder<'a> {
    /// Starts an empty pack of a class.
    pub fn new(credential: &'a Credential, class: PackClass) -> Self {
        Self {
            credential,
            class,
            pack_key: None,
            body: Vec::new(),
            entries: Vec::new(),
            seen: BTreeSet::new(),
        }
    }

    /// The size of the body so far, in bytes.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Whether the pack has no object yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the pack has this object.
    pub fn contains(&self, id: &ObjectId) -> bool {
        self.seen.contains(id)
    }

    /// Adds an object and returns its object ID.
    ///
    /// `stored` is the stored bytes (format.md 4.7.2): the encoded envelope, or the
    /// plaintext of a chunk. The key class comes from the type (format.md 5.1.4
    /// and others). When `compress` is true, the builder tries DEFLATE and keeps
    /// the result only when it is smaller (format.md 6.6.5).
    ///
    /// An object that the pack already has is not added again, because an object
    /// ID occurs once in a pack (format.md 6.7.3.5).
    pub fn add<R: CryptoRng>(
        &mut self,
        object_type: u32,
        stored: &[u8],
        compress: bool,
        rng: &mut R,
    ) -> Result<ObjectId, BuildError> {
        let key_class =
            KeyClass::of_type(object_type).ok_or(BuildError::UnknownType(object_type))?;
        let id = ObjectId::from_bytes(self.credential.domains().object_id(object_type, stored));
        if self.seen.contains(&id) {
            return Ok(id);
        }
        let unpacked_size = u32::try_from(stored.len()).map_err(|_| BuildError::TooLarge)?;

        let (compression, compressed) = if compress {
            let deflated = miniz_oxide::deflate::compress_to_vec(stored, 6);
            if deflated.len() < stored.len() {
                (Compression::Deflate, Some(deflated))
            } else {
                (Compression::None, None)
            }
        } else {
            (Compression::None, None)
        };
        let to_encrypt = compressed.as_deref().unwrap_or(stored);

        let key = match key_class {
            KeyClass::W => self.credential.writer().pack_object_key(),
            KeyClass::R => {
                let pack_key = self.pack_key.get_or_insert_with(|| AeadKey::generate(rng));
                AeadKey::from_bytes(*pack_key.as_bytes())
            }
        };
        let mut aad = [0u8; 36];
        aad[..32].copy_from_slice(id.as_bytes());
        aad[32..].copy_from_slice(&object_type.to_le_bytes());
        let packed = encrypt(&key, &aad, to_encrypt, rng).map_err(|_| BuildError::Encryption)?;
        let packed_size = u32::try_from(packed.len()).map_err(|_| BuildError::TooLarge)?;
        debug_assert_eq!(
            packed_size,
            to_encrypt.len() as u32 + PACKED_OBJECT_OVERHEAD
        );

        self.entries.push(ObjectTableEntry {
            object_id: id,
            object_type,
            key_class,
            offset: self.body.len() as u64,
            packed_size,
            compression,
            unpacked_size,
        });
        self.body.extend_from_slice(&packed);
        self.seen.insert(id);
        Ok(id)
    }

    /// Writes the header, the object table, the seal and the footer.
    ///
    /// A pack without objects is valid (format.md 6.7.3.6).
    pub fn finish<R: CryptoRng>(self, rng: &mut R) -> Result<BuiltPack, BuildError> {
        let has_r = self.pack_key.is_some();
        // The header has the name of the seal algorithm only when the pack has a seal.
        let kem = has_r.then(|| KEM_NAME.into());
        let header = Header::new(self.class, kem).encode()?;
        let header_hash = *blake3::hash(&header).as_bytes();

        let seal = match &self.pack_key {
            Some(pack_key) => seal_pack_key(
                self.credential.read_public_key(),
                pack_key,
                &header_hash,
                rng,
            )
            .map_err(BuildError::Seal)?,
            None => Vec::new(),
        };

        // The offsets of the table count from the start of the file.
        let header_len = header.len() as u64;
        let entries: Vec<ObjectTableEntry> = self
            .entries
            .iter()
            .map(|entry| ObjectTableEntry {
                offset: entry.offset + header_len,
                ..entry.clone()
            })
            .collect();
        let objects: Vec<(ObjectId, u32)> = entries
            .iter()
            .map(|entry| (entry.object_id, entry.object_type))
            .collect();
        let trailer_offset = header_len + self.body.len() as u64;

        let table = ObjectTable { entries };
        // The checks that a reader makes (format.md 6.7.3.5), before anything is written.
        table.validate(header.len(), trailer_offset, seal.len())?;
        let packed_table = encrypt(
            &self.credential.writer().pack_table_key(),
            &header_hash,
            &table.encode()?,
            rng,
        )
        .map_err(|_| BuildError::Encryption)?;
        let trailer = Trailer::encode(&seal, &packed_table)?;
        let footer = Footer {
            trailer_offset,
            trailer_size: u32::try_from(trailer.len()).map_err(|_| BuildError::TooLarge)?,
            format_version: nilperit_format::pack::FORMAT_VERSION,
        };

        let mut bytes = header;
        bytes.extend_from_slice(&self.body);
        bytes.extend_from_slice(&trailer);
        bytes.extend_from_slice(&footer.encode());
        let name = PackName::from_bytes(*blake3::hash(&bytes).as_bytes());
        Ok(BuiltPack {
            name,
            bytes,
            objects,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nilperit_crypto::{DedupKey, RootSeed, WriterKey};
    use nilperit_format::object_type::{CHUNK, CONTENT_OBJECT, DELTA_ENTRY, ITEM_RECORD};
    use nilperit_reader::layout::pack_path;
    use nilperit_reader::{Keys, MemoryTarget, ObjectReadError, Pack};
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};
    use x_wing::kem::common::rand_core::{TryCryptoRng, TryRng};

    /// Runs a future that never waits for anything (the in-memory target).
    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the future waits"),
        }
    }

    /// A "random" number generator: first the bytes of a script, then SplitMix64.
    /// NOT secure: only for tests.
    struct TestRng {
        script: Vec<u8>,
        state: u64,
    }

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self {
                script: Vec::new(),
                state: seed,
            }
        }

        fn scripted(script: Vec<u8>) -> Self {
            Self { script, state: 1 }
        }

        fn step(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok((self.step() >> 32) as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(self.step())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for byte in dst {
                *byte = if self.script.is_empty() {
                    self.step() as u8
                } else {
                    self.script.remove(0)
                };
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn seed() -> RootSeed {
        RootSeed::from_bytes([7; 32])
    }

    /// Opens a built pack with the reader and returns what the reader needs.
    fn open(pack: &BuiltPack) -> (MemoryTarget, Pack, Keys) {
        let seed = seed();
        let mut target = MemoryTarget::new();
        target.insert(&pack_path(&pack.name), pack.bytes.clone());
        let opened =
            block_on(Pack::open(&target, pack.name, &seed.writer_key())).expect("the pack opens");
        (target, opened, Keys::from_seed(&seed))
    }

    fn read(
        target: &MemoryTarget,
        pack: &Pack,
        keys: &Keys,
        id: &ObjectId,
        object_type: u32,
    ) -> Result<Vec<u8>, ObjectReadError> {
        block_on(pack.read_object(target, id, object_type, keys))
    }

    fn repetitive() -> Vec<u8> {
        b"nilperit ".repeat(1000)
    }

    #[test]
    fn the_reader_reads_every_object_back() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(1);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        let objects: Vec<(u32, Vec<u8>, bool)> = vec![
            (CHUNK, b"hello".to_vec(), false),
            (CHUNK, repetitive(), true),
            (CONTENT_OBJECT, b"content object".to_vec(), false),
            (DELTA_ENTRY, repetitive(), true),
            (ITEM_RECORD, b"item record".to_vec(), true),
            (CHUNK, Vec::new(), true),
        ];
        let ids: Vec<ObjectId> = objects
            .iter()
            .map(|(t, bytes, compress)| builder.add(*t, bytes, *compress, &mut rng).unwrap())
            .collect();
        let pack = builder.finish(&mut rng).unwrap();
        assert_eq!(pack.objects.len(), objects.len());
        assert_eq!(pack.name.as_bytes(), blake3::hash(&pack.bytes).as_bytes());

        let (target, opened, keys) = open(&pack);
        for ((object_type, bytes, _), id) in objects.iter().zip(&ids) {
            assert_eq!(
                &read(&target, &opened, &keys, id, *object_type).unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn the_key_class_follows_the_type() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(2);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        for object_type in [CHUNK, CONTENT_OBJECT, ITEM_RECORD, DELTA_ENTRY] {
            builder.add(object_type, b"x", false, &mut rng).unwrap();
        }
        let (_, opened, _) = open(&builder.finish(&mut rng).unwrap());
        let classes: Vec<_> = opened
            .table()
            .entries
            .iter()
            .map(|e| (e.object_type, e.key_class))
            .collect();
        assert_eq!(
            classes,
            [
                (CHUNK, KeyClass::R),
                (CONTENT_OBJECT, KeyClass::W),
                (ITEM_RECORD, KeyClass::R),
                (DELTA_ENTRY, KeyClass::W),
            ]
        );
    }

    #[test]
    fn rejects_a_type_that_is_not_an_object_in_a_pack() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(3);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        // The object table (3), the snapshot header (6), and an unknown type.
        for object_type in [3, 6, 0, 99] {
            let result = builder.add(object_type, b"x", false, &mut rng);
            assert!(matches!(result, Err(BuildError::UnknownType(t)) if t == object_type));
        }
        assert!(builder.is_empty());
    }

    #[test]
    fn an_object_that_the_pack_has_is_not_added_again() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(4);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        let first = builder.add(CHUNK, b"same", false, &mut rng).unwrap();
        let size = builder.len();
        let second = builder.add(CHUNK, b"same", true, &mut rng).unwrap();
        assert_eq!(first, second);
        assert_eq!(builder.len(), size);
        assert!(builder.contains(&first));
        // The same bytes with another type are another object.
        let other = builder.add(ITEM_RECORD, b"same", false, &mut rng).unwrap();
        assert_ne!(first, other);
        let pack = builder.finish(&mut rng).unwrap();
        assert_eq!(pack.objects.len(), 2);
        open(&pack);
    }

    #[test]
    fn compression_is_kept_only_when_it_is_smaller() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(5);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        let small = builder.add(CHUNK, &repetitive(), true, &mut rng).unwrap();
        // Bytes that DEFLATE cannot make smaller.
        let noise: Vec<u8> = (0..500).map(|_| rng.step() as u8).collect();
        let big = builder.add(CHUNK, &noise, true, &mut rng).unwrap();
        let plain = builder
            .add(CHUNK, &b"abcabcabcabcabc".repeat(50), false, &mut rng)
            .unwrap();
        let (_, opened, _) = open(&builder.finish(&mut rng).unwrap());
        let compression = |id: &ObjectId| {
            opened
                .table()
                .entries
                .iter()
                .find(|e| e.object_id == *id)
                .map(|e| (e.compression, e.packed_size, e.unpacked_size))
                .unwrap()
        };
        let (c, packed, unpacked) = compression(&small);
        assert_eq!(c, Compression::Deflate);
        assert!(packed < unpacked);
        assert_eq!(compression(&big), (Compression::None, 540, 500));
        // Without the request the object stays as it is.
        assert_eq!(compression(&plain).0, Compression::None);
    }

    #[test]
    fn a_pack_with_only_w_objects_has_no_seal() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(6);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        let id = builder
            .add(CONTENT_OBJECT, b"only W", false, &mut rng)
            .unwrap();
        let (target, opened, keys) = open(&builder.finish(&mut rng).unwrap());
        assert!(opened.seal().is_empty());
        assert_eq!(opened.header().key_encapsulation, None);
        assert_eq!(
            read(&target, &opened, &keys, &id, CONTENT_OBJECT).unwrap(),
            b"only W"
        );
    }

    #[test]
    fn a_pack_with_an_r_object_has_a_seal_that_only_the_read_key_opens() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(7);
        let mut builder = PackBuilder::new(&credential, PackClass::Metadata);
        let id = builder.add(CHUNK, b"secret", false, &mut rng).unwrap();
        let pack = builder.finish(&mut rng).unwrap();
        let (target, opened, keys) = open(&pack);
        assert_eq!(opened.seal().len(), nilperit_crypto::seal::SEAL_SIZE);
        assert_eq!(opened.header().key_encapsulation.as_deref(), Some(KEM_NAME));
        assert_eq!(opened.header().class, PackClass::Metadata);
        // A reader with another read key cannot open the R object.
        let other = RootSeed::from_bytes([8; 32]);
        let wrong = Keys::new(
            WriterKey::from_bytes(*seed().writer_key().as_bytes()),
            other.read_key(),
            &seed().dedup_key(),
        );
        assert!(matches!(
            read(&target, &opened, &wrong, &id, CHUNK),
            Err(ObjectReadError::Seal(_))
        ));
        assert_eq!(
            read(&target, &opened, &keys, &id, CHUNK).unwrap(),
            b"secret"
        );
    }

    #[test]
    fn a_pack_without_objects_is_valid() {
        let credential = Credential::from_seed(&seed());
        let mut rng = TestRng::new(8);
        let builder = PackBuilder::new(&credential, PackClass::Data);
        assert!(builder.is_empty());
        let (_, opened, _) = open(&builder.finish(&mut rng).unwrap());
        assert!(opened.table().entries.is_empty());
    }

    #[test]
    fn the_same_objects_and_randomness_make_the_same_pack() {
        let credential = Credential::from_seed(&seed());
        let build = || {
            let mut rng = TestRng::new(9);
            let mut builder = PackBuilder::new(&credential, PackClass::Data);
            builder.add(CHUNK, b"a", true, &mut rng).unwrap();
            builder.add(CONTENT_OBJECT, b"b", false, &mut rng).unwrap();
            builder.finish(&mut rng).unwrap()
        };
        let (a, b) = (build(), build());
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.name, b.name);
        // Other randomness gives other nonces, so other bytes and another name.
        let mut rng = TestRng::new(10);
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        builder.add(CHUNK, b"a", true, &mut rng).unwrap();
        builder.add(CONTENT_OBJECT, b"b", false, &mut rng).unwrap();
        assert_ne!(builder.finish(&mut rng).unwrap().bytes, a.bytes);
    }

    #[test]
    fn makes_the_body_of_the_appendix_pack() {
        // Format.md A.8, made with other software. The keys and the nonces are
        // those of A.8.2. The header, the seal and the table differ, because A.8
        // has a placeholder seal. The objects must be the same.
        let dedup = DedupKey::from_bytes(std::array::from_fn(|i| i as u8));
        let writer = WriterKey::from_bytes(std::array::from_fn(|i| 0x20 + i as u8));
        let credential = Credential::new(&dedup, writer, seed().read_key().public_key());

        // The random bytes that the builder asks for, in order: the pack key
        // `40 .. 5f`, the nonce of the chunk, the nonce of the content object.
        let mut script: Vec<u8> = (0x40..0x60).collect();
        script.extend([0x01; 24]);
        script.extend([0x02; 24]);
        let mut rng = TestRng::scripted(script);

        let content = unhex(
            "a30002010102a40181582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e0205035820ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e0401",
        );
        let mut builder = PackBuilder::new(&credential, PackClass::Data);
        // A.8 compresses the chunk, although the stream (7 bytes) is longer than
        // `hello` (5 bytes). The builder keeps a chunk uncompressed when DEFLATE
        // does not make it smaller (format.md 6.6.5), so here it stores 5 bytes.
        let chunk_id = builder.add(CHUNK, b"hello", true, &mut rng).unwrap();
        let content_id = builder
            .add(CONTENT_OBJECT, &content, false, &mut rng)
            .unwrap();
        assert_eq!(
            chunk_id.as_bytes()[..],
            unhex("09c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e")[..]
        );
        assert_eq!(
            content_id.as_bytes()[..],
            unhex("286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e")[..]
        );
        let pack = builder.finish(&mut rng).unwrap();

        let header_len = Header::len_from_prefix(&pack.bytes).unwrap();
        let trailer_offset = u64::from_le_bytes(
            pack.bytes[pack.bytes.len() - 24..pack.bytes.len() - 16]
                .try_into()
                .unwrap(),
        ) as usize;
        let body = &pack.bytes[header_len..trailer_offset];
        assert_eq!(body.len(), 45 + 122);

        // The content object (W, not compressed) is the packed object of A.8: the
        // last 122 bytes of its body.
        let a8_body = unhex(include_str!("../tests/a8_body.hex").trim());
        assert_eq!(a8_body.len(), 47 + 122);
        assert_eq!(body[45..], a8_body[47..]);

        // The chunk (R, not compressed): the nonce `01` x 24, then the ciphertext and
        // the tag of `hello` with the pack key `40 .. 5f` and the associated data
        // (chunk ID, type ID 1). Made with PyNaCl, not with this code.
        let chunk = unhex(
            "010101010101010101010101010101010101010101010101e5ae23aecd7158df2ccbf6acf810b335cb8fd45261",
        );
        assert_eq!(body[..45], chunk[..]);
    }
}
