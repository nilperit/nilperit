//! The inputs that the mutations start from: valid input of every kind.
//!
//! Most of them are made by the encoders of the format crate. The pack comes from the test
//! vector A.8 of format.md, whose hexadecimal text is below. A test checks that the text
//! is in format.md.

use crate::checks::pack_file;
use crate::fixtures::unhex;
use nilperit_format::{
    Change, ChunkingProfile, ContentHash, ContentObject, DeltaEntry, Envelope, HolderId, ItemKey,
    ItemRecord, LockFile, ObjectId, ObjectTable, SnapshotHeader, SnapshotId, SourceId, Statistics,
    VaultConfig, VaultEssentials, VaultId, join_config_file,
};

/// The pack of A.8.5 (408 bytes).
pub const A8_PACK: &str = "894e504b0d0a1a0a2e000000a50100020003727863686163686132302d706f6c7931333035046b706c616365686f6c6465720566626c616b65330101010101010101010101010101010101010101010101014683820b6bdd17744f45bb9c2275d3d73057e39b980765020202020202020202020202020202020202020202020202c5e12b97bd9e2e7d093d49a7a9c7db234d82f2da194b7b55517ebcb80e3a652036e81578286e7506f30dcfb8a8ea38f7111dd372053a9b7c65a12982437fe67c87390691e4e97a85f48e30a866aa17f9bebfe753881f5c03d706534a1efb54a9fd9a04000000deadbeef030303030303030303030303030303030303030303030303641136128a959b741d53c008bbdf760f87c8ed6499d7ad62b8c483c0e134ba3c269eff66bb08c01ee9baf1a4a9608275c2a7e0e252b52c3bcdb28471056b637fca99bb999c6ff11fdd451bbaba53b9db719e0eb1f81e91603528d27060f14b5036b5818c1144c0fd989adddcc5353d7ab9ab11c81e9e47dc98fba75147e3000000000000009d000000000000004e504b2d454e440a";

/// The plaintext of the object table of A.8.3 (109 bytes).
pub const A8_TABLE: &str = "a30003010102a1018287582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e016152183a182f676465666c61746505875820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e0261571869187a646e6f6e651852";

// The positions in the pack of A.8 (A.8.4).
const HEADER: (usize, usize) = (0, 58);
const BODY: (usize, usize) = (58, 227);
const TRAILER: (usize, usize) = (227, 384);
const FOOTER: (usize, usize) = (384, 408);
/// The seal of A.8 is a placeholder of 4 bytes.
const SEAL: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn id(byte: u8) -> ObjectId {
    ObjectId::from_bytes([byte; 32])
}

/// The metadata of an item: `{"mode": 420}` (format.md A.10.2).
fn metadata() -> Vec<u8> {
    vec![0xa1, 0x64, b'm', b'o', b'd', b'e', 0x19, 0x01, 0xa4]
}

fn essentials() -> VaultEssentials {
    VaultEssentials {
        format_version: 0,
        vault_id: VaultId::from_bytes([0x11; 16]),
        encryption: "xchacha20-poly1305".into(),
        hash: "blake3".into(),
        key_encapsulation: "x-wing-draft-06".into(),
        read_public_key: (0..32).collect(),
    }
}

fn content_objects() -> Vec<Vec<u8>> {
    let one = ContentObject {
        chunks: vec![id(1), id(2), id(1)],
        size: 11,
        content_hash: ContentHash::from_bytes([3; 32]),
        chunking_profile: 1,
    };
    let empty = ContentObject {
        chunks: Vec::new(),
        size: 0,
        content_hash: ContentHash::from_bytes([4; 32]),
        chunking_profile: 2,
    };
    vec![one.encode().unwrap(), empty.encode().unwrap()]
}

fn item_records() -> Vec<Vec<u8>> {
    let full = ItemRecord {
        source_id: SourceId::from_bytes([0x22; 16]),
        native_id: b"docs/hello.txt".to_vec(),
        title: "hello.txt".into(),
        modified: Some(1_700_000_000_000),
        created: Some(-5),
        size: 5,
        media_type: Some("text/plain".into()),
        metadata: Some(metadata()),
        content: vec![id(5)],
    };
    let minimal = ItemRecord {
        source_id: SourceId::from_bytes([0x22; 16]),
        native_id: vec![0],
        title: String::new(),
        modified: None,
        created: None,
        size: 0,
        media_type: None,
        metadata: None,
        content: Vec::new(),
    };
    vec![full.encode().unwrap(), minimal.encode().unwrap()]
}

fn delta_entries() -> Vec<Vec<u8>> {
    let change = |byte: u8| Change {
        item_key: ItemKey::from_bytes([byte; 32]),
        item_record: id(byte),
        content: vec![id(byte + 100)],
    };
    let first = DeltaEntry {
        source_id: SourceId::from_bytes([0x22; 16]),
        sequence: 1,
        parent: None,
        snapshot_id: SnapshotId::from_bytes([0x33; 16]),
        time: 1_700_000_001_000,
        connector_cursor: None,
        changed: vec![change(1), change(2)],
        deleted: Vec::new(),
    };
    let second = DeltaEntry {
        sequence: 2,
        parent: Some(id(9)),
        connector_cursor: Some(vec![1, 2, 3]),
        changed: vec![change(3)],
        deleted: vec![ItemKey::from_bytes([1; 32]), ItemKey::from_bytes([5; 32])],
        ..first.clone()
    };
    vec![first.encode().unwrap(), second.encode().unwrap()]
}

fn snapshot_headers() -> Vec<Vec<u8>> {
    let first = SnapshotHeader {
        source_id: SourceId::from_bytes([0x22; 16]),
        snapshot_id: SnapshotId::from_bytes([0x33; 16]),
        time: 1_700_000_001_000,
        item_map_root: None,
        parent_snapshot: None,
        journal_entry: id(7),
        journal_sequence: 1,
        statistics: None,
        vault: essentials(),
    };
    let second = SnapshotHeader {
        item_map_root: Some(id(8)),
        parent_snapshot: Some(SnapshotId::from_bytes([0x44; 16])),
        journal_sequence: 2,
        statistics: Some(Statistics {
            items: 3,
            size: 4096,
        }),
        ..first.clone()
    };
    vec![first.encode().unwrap(), second.encode().unwrap()]
}

fn vault_configs() -> Vec<Vec<u8>> {
    let config = VaultConfig {
        essentials: essentials(),
        sequence: 1,
        chunking_profiles: vec![
            ChunkingProfile {
                id: 1,
                algorithm: "fixed".into(),
                min_size: 0,
                avg_size: 0,
                max_size: 262_144,
            },
            ChunkingProfile {
                id: 2,
                algorithm: "fixed".into(),
                min_size: 0,
                avg_size: 0,
                max_size: 2_097_152,
            },
        ],
    };
    let map = config.encode().unwrap();
    let file = join_config_file(&map, &[0x5a; 32]).unwrap();
    vec![map, file]
}

fn lock_files() -> Vec<Vec<u8>> {
    let lock = LockFile {
        holder_id: HolderId::from_bytes([0x55; 16]),
        heartbeat: 1_700_000_002_000,
    };
    vec![lock.encode()]
}

fn object_tables() -> Vec<Vec<u8>> {
    let table = ObjectTable::decode(&unhex(A8_TABLE)).expect("the table of A.8");
    vec![
        unhex(A8_TABLE),
        table.encode().unwrap(),
        ObjectTable::default().encode().unwrap(),
    ]
}

fn envelopes() -> Vec<Vec<u8>> {
    vec![
        Envelope::encode(5, 1, &[0xa0]).unwrap(),
        // The body of A.1: `{1: 7, 2: "ab"}`.
        Envelope::encode(5, 1, &[0xa2, 0x01, 0x07, 0x02, 0x62, 0x61, 0x62]).unwrap(),
    ]
}

/// Small CBOR items of every kind, and some that the strict check refuses.
fn cbor() -> Vec<Vec<u8>> {
    vec![
        vec![0x00],
        vec![0x17],
        vec![0x18, 0x18],
        vec![0x19, 0x01, 0x00],
        vec![0x1b, 0, 0, 0, 1, 0, 0, 0, 0],
        vec![0x20],
        vec![0x40],
        vec![0x43, 1, 2, 3],
        vec![0x60],
        vec![0x62, b'a', b'b'],
        vec![0x80],
        vec![0x82, 0x01, 0x02],
        vec![0xa0],
        vec![0xa2, 0x01, 0x02, 0x03, 0x04],
        vec![0xa1, 0x61, b'a', 0x81, 0xa0],
        // Not accepted: not the shortest form, not sorted, indefinite, a tag, a float.
        vec![0x18, 0x01],
        vec![0xa2, 0x03, 0x00, 0x01, 0x00],
        vec![0x9f, 0x01, 0xff],
        vec![0xc0, 0x00],
        vec![0xf9, 0x3c, 0x00],
    ]
}

fn a8(range: (usize, usize)) -> Vec<u8> {
    unhex(A8_PACK)[range.0..range.1].to_vec()
}

fn pack_parts() -> Vec<Vec<u8>> {
    vec![
        a8(HEADER),
        a8(TRAILER),
        a8(FOOTER),
        unhex(A8_PACK),
        vec![0; 24],
        vec![0; 12],
    ]
}

/// The input of `pack_with_table`: the size of the body (2 bytes), the body, the size of the
/// seal (1 byte), the seal, and the plaintext of the object table.
fn table_input(body: &[u8], seal: &[u8], table: &[u8]) -> Vec<u8> {
    let mut input = (body.len() as u16).to_le_bytes().to_vec();
    input.extend_from_slice(body);
    input.push(seal.len() as u8);
    input.extend_from_slice(seal);
    input.extend_from_slice(table);
    input
}

fn packs_with_table() -> Vec<Vec<u8>> {
    let table = unhex(A8_TABLE);
    vec![
        table_input(&a8(BODY), &SEAL, &table),
        table_input(&[], &[], &ObjectTable::default().encode().unwrap()),
        table_input(&a8(BODY), &[], &table),
    ]
}

/// The input of `pack_with_object`: the compression, the unpacked size (2 bytes), and the
/// bytes of the packed object.
fn object_input(deflate: bool, unpacked: u16, packed: &[u8]) -> Vec<u8> {
    let mut input = vec![u8::from(deflate)];
    input.extend_from_slice(&unpacked.to_le_bytes());
    input.extend_from_slice(packed);
    input
}

fn packs_with_object() -> Vec<Vec<u8>> {
    // `hello` as one DEFLATE stream (format.md A.7.1), the same bytes not compressed, and a
    // stream that makes 1000 bytes from a few.
    let repeated = b"nilperit ".repeat(111);
    let stream = miniz_oxide::deflate::compress_to_vec(&repeated, 6);
    vec![
        object_input(true, 5, &unhex("cb48cdc9c90700")),
        object_input(false, 5, b"hello"),
        object_input(true, repeated.len() as u16, &stream),
        object_input(true, 0, &[0x03, 0x00]),
    ]
}

fn encryptions() -> Vec<Vec<u8>> {
    vec![
        vec![0; 1192],
        vec![0; 40],
        vec![0; 1216],
        a8((58, 105)),
        Vec::new(),
    ]
}

/// The input of `chunker`: the size of a chunk, the sizes of eight pieces, and the bytes.
fn chunkers() -> Vec<Vec<u8>> {
    let mut one = vec![2, 1, 2, 3, 4, 5, 6, 7, 8];
    one.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    let mut two = vec![63, 255, 255, 255, 255, 255, 255, 255, 255];
    two.extend((0..200u8).collect::<Vec<_>>());
    vec![one, two, vec![0], vec![5, 1, 1, 1, 1, 1, 1, 1, 1]]
}

/// The seeds of a check, by its name (see `checks::TARGETS`). Every seed is valid input, or
/// input that the check refuses in a way that the mutations can turn into valid input.
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    match target {
        "canonical" => {
            let mut all = cbor();
            all.extend(content_objects());
            all.extend(item_records());
            all.extend(delta_entries());
            all.extend(snapshot_headers());
            all.extend(vault_configs().into_iter().take(1));
            all.extend(lock_files());
            all.extend(envelopes());
            all
        }
        "envelope" => {
            let mut all = envelopes();
            all.extend(content_objects());
            all.extend(item_records());
            all
        }
        "content_object" => content_objects(),
        "item_record" => item_records(),
        "delta_entry" => delta_entries(),
        "snapshot_header" => snapshot_headers(),
        "vault_config" => vault_configs(),
        "lock_file" => lock_files(),
        "object_table" => object_tables(),
        "pack_parts" => pack_parts(),
        "pack_with_table" => packs_with_table(),
        "pack_with_object" => packs_with_object(),
        "encryption" => encryptions(),
        "chunker" => chunkers(),
        other => panic!("no check with the name {other}"),
    }
}

/// The pack that `pack_with_table` makes from the seed of A.8. It is the pack of A.8.
pub fn a8_pack_from_seed() -> Vec<u8> {
    pack_file(&a8(BODY), &SEAL, &unhex(A8_TABLE))
}
