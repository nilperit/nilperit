//! Test helpers. The library has no async runtime and no writer, so tests drive
//! futures by hand and build packs with a small builder.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use nilperit_crypto::seal::KEM_NAME;
use nilperit_crypto::{
    AeadKey, DedupKey, ReadKey, RootSeed, WriterKey, config_mac, encrypt, seal_pack_key,
};
use nilperit_format::pack::{ENCRYPTION_XCHACHA20_POLY1305, FOOTER_SIZE, HASH_BLAKE3};
use nilperit_format::{
    ChunkingProfile, Compression, DeltaEntry, Footer, Header, KeyClass, ObjectId, ObjectTable,
    ObjectTableEntry, PackClass, PackName, SnapshotHeader, SnapshotId, SourceId, Trailer,
    VaultConfig, VaultEssentials, VaultId, join_config_file,
};
use x_wing::kem::common::rand_core::{TryCryptoRng, TryRng};

/// Runs a future to completion. It only works for futures that never wait for
/// something outside the future, which is true for the in-memory target.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the future waits for something that never happens"),
    }
}

/// A deterministic random number generator. NOT secure: only for tests.
pub struct TestRng(pub u64);

impl TestRng {
    // SplitMix64.
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
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
        for chunk in dst.chunks_mut(8) {
            let bytes = self.step().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

/// An object to put in a test pack. The `claim_*` fields let a test write an
/// object table that is wrong on purpose.
pub struct TestObject {
    pub object_type: u32,
    pub key_class: KeyClass,
    /// How the builder stores the bytes.
    pub compression: Compression,
    pub stored: Vec<u8>,
    /// The object ID in the table, when it is not the real one.
    pub claim_id: Option<ObjectId>,
    /// The compression name in the table, when it is not the real one.
    pub claim_compression: Option<Compression>,
    /// The unpacked size in the table, when it is not the real one.
    pub claim_unpacked_size: Option<u32>,
}

impl TestObject {
    pub fn new(
        object_type: u32,
        key_class: KeyClass,
        compression: Compression,
        stored: &[u8],
    ) -> Self {
        Self {
            object_type,
            key_class,
            compression,
            stored: stored.to_vec(),
            claim_id: None,
            claim_compression: None,
            claim_unpacked_size: None,
        }
    }
}

/// The keys that a test pack uses.
pub struct TestKeys {
    pub writer: WriterKey,
    pub read: ReadKey,
    pub dedup: DedupKey,
}

impl TestKeys {
    pub fn new(seed: u8) -> Self {
        Self {
            writer: WriterKey::from_bytes([seed; 32]),
            read: ReadKey::from_seed([seed.wrapping_add(1); 32]),
            dedup: DedupKey::from_bytes([seed.wrapping_add(2); 32]),
        }
    }

    /// The keys that a vault with this root seed has.
    pub fn from_seed(seed: &RootSeed) -> Self {
        Self {
            writer: seed.writer_key(),
            read: seed.read_key(),
            dedup: seed.dedup_key(),
        }
    }

    pub fn keys(&self) -> crate::Keys {
        crate::Keys::new(
            WriterKey::from_bytes(*self.writer.as_bytes()),
            ReadKey::from_seed(*self.read.as_bytes()),
            &self.dedup,
        )
    }
}

/// Builds a pack as format.md 6.7 describes. Returns the bytes and the object ID
/// of each object, in order.
pub fn build_pack(keys: &TestKeys, objects: &[TestObject]) -> (Vec<u8>, Vec<ObjectId>) {
    let mut rng = TestRng(1);
    let domains = keys.dedup.domain_keys();
    let any_r = objects.iter().any(|o| o.key_class == KeyClass::R);

    let kem = any_r.then(|| KEM_NAME.to_string());
    let header = Header::new(PackClass::Data, kem).encode().unwrap();
    let header_hash = *blake3::hash(&header).as_bytes();
    let pack_key = AeadKey::generate(&mut rng);
    let seal = if any_r {
        seal_pack_key(&keys.read.public_key(), &pack_key, &header_hash, &mut rng).unwrap()
    } else {
        Vec::new()
    };

    let mut body = Vec::new();
    let mut entries = Vec::new();
    let mut ids = Vec::new();
    for object in objects {
        let real_id = ObjectId::from_bytes(domains.object_id(object.object_type, &object.stored));
        ids.push(real_id);
        let id = object.claim_id.unwrap_or(real_id);
        let compressed = match object.compression {
            Compression::None => object.stored.clone(),
            Compression::Deflate => miniz_oxide::deflate::compress_to_vec(&object.stored, 6),
        };
        let key = match object.key_class {
            KeyClass::R => AeadKey::from_bytes(*pack_key.as_bytes()),
            KeyClass::W => keys.writer.pack_object_key(),
        };
        let mut aad = id.as_bytes().to_vec();
        aad.extend_from_slice(&object.object_type.to_le_bytes());
        let packed = encrypt(&key, &aad, &compressed, &mut rng).unwrap();
        entries.push(ObjectTableEntry {
            object_id: id,
            object_type: object.object_type,
            key_class: object.key_class,
            offset: (header.len() + body.len()) as u64,
            packed_size: packed.len() as u32,
            compression: object.claim_compression.unwrap_or(object.compression),
            unpacked_size: object
                .claim_unpacked_size
                .unwrap_or(object.stored.len() as u32),
        });
        body.extend_from_slice(&packed);
    }

    let table = ObjectTable { entries }.encode().unwrap();
    let packed_table = encrypt(
        &keys.writer.pack_table_key(),
        &header_hash,
        &table,
        &mut rng,
    )
    .unwrap();
    let trailer = Trailer::encode(&seal, &packed_table).unwrap();
    let trailer_offset = (header.len() + body.len()) as u64;
    let footer = Footer {
        trailer_offset,
        trailer_size: trailer.len() as u32,
        format_version: 0,
    };

    let mut pack = header;
    pack.extend_from_slice(&body);
    pack.extend_from_slice(&trailer);
    pack.extend_from_slice(&footer.encode());
    debug_assert_eq!(
        pack.len() as u64,
        trailer_offset + trailer.len() as u64 + FOOTER_SIZE as u64
    );
    (pack, ids)
}

/// A vault config for the root seed.
pub fn config(seed: &RootSeed, sequence: u64, vault_id: u8) -> VaultConfig {
    VaultConfig {
        essentials: VaultEssentials {
            format_version: 0,
            vault_id: VaultId::from_bytes([vault_id; 16]),
            encryption: ENCRYPTION_XCHACHA20_POLY1305.to_string(),
            hash: HASH_BLAKE3.to_string(),
            key_encapsulation: KEM_NAME.to_string(),
            read_public_key: seed.read_key().public_key().to_bytes().to_vec(),
        },
        sequence,
        chunking_profiles: alloc::vec![ChunkingProfile {
            id: 1,
            algorithm: "fastcdc-2020".to_string(),
            min_size: 65536,
            avg_size: 262_144,
            max_size: 1_048_576,
        }],
    }
}

/// The bytes of a config file that `seed` authenticates.
pub fn file_with_key(config: &VaultConfig, seed: &RootSeed) -> Vec<u8> {
    let map = config.encode().unwrap();
    let mac = config_mac(&seed.writer_key().config_mac_key(), &map);
    join_config_file(&map, &mac).unwrap()
}

/// The root seed of the test vaults.
pub fn test_seed() -> RootSeed {
    RootSeed::from_bytes([7; 32])
}

/// The name of a pack: the hash of its bytes.
pub fn pack_name(bytes: &[u8]) -> PackName {
    PackName::from_bytes(*blake3::hash(bytes).as_bytes())
}

/// Opens a vault in memory, with the given packs and extra files. The vault
/// config is valid for `test_seed()` and its vault ID is 1.
pub fn vault_with(
    packs: &[&[u8]],
    files: &[(alloc::string::String, Vec<u8>)],
) -> crate::Vault<crate::MemoryTarget> {
    let seed = test_seed();
    let mut target = crate::MemoryTarget::new();
    target.insert(
        crate::layout::CONFIG_A,
        file_with_key(&config(&seed, 1, 1), &seed),
    );
    for bytes in packs {
        target.insert(&crate::layout::pack_path(&pack_name(bytes)), bytes.to_vec());
    }
    for (path, bytes) in files {
        target.insert(path, bytes.clone());
    }
    block_on(crate::Vault::open(target, &seed)).unwrap()
}

/// A snapshot header of vault 1.
pub fn header(
    source: u8,
    snapshot: u8,
    time: i64,
    entry: ObjectId,
    sequence: u64,
) -> SnapshotHeader {
    SnapshotHeader {
        source_id: SourceId::from_bytes([source; 16]),
        snapshot_id: SnapshotId::from_bytes([snapshot; 16]),
        time,
        item_map_root: None,
        parent_snapshot: None,
        journal_entry: entry,
        journal_sequence: sequence,
        statistics: None,
        vault: config(&test_seed(), 1, 1).essentials,
    }
}

/// The file of a snapshot header: nonce, ciphertext, tag (format.md 3.3.7.1).
pub fn snapshot_file(header: &SnapshotHeader) -> Vec<u8> {
    let key = test_seed().writer_key().snapshot_header_key();
    encrypt(&key, &[], &header.encode().unwrap(), &mut TestRng(5)).unwrap()
}

/// The path and the bytes of a snapshot header file, ready for `vault_with`.
pub fn snapshot_entry(header: &SnapshotHeader) -> (alloc::string::String, Vec<u8>) {
    (
        crate::layout::snapshot_path(&header.snapshot_id),
        snapshot_file(header),
    )
}

/// A delta entry as a pack object (type 5, W, not compressed), and its object ID.
pub fn entry_object(entry: &DeltaEntry) -> (TestObject, ObjectId) {
    let stored = entry.encode().unwrap();
    let id = ObjectId::from_bytes(
        TestKeys::from_seed(&test_seed())
            .dedup
            .domain_keys()
            .object_id(5, &stored),
    );
    (
        TestObject::new(5, KeyClass::W, Compression::None, &stored),
        id,
    )
}
