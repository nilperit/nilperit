//! Tests against the test vectors of format.md A.9 (the vault config), A.10
//! (item record, delta entry and snapshot header) and A.11 (the writer lock). The vectors were made with
//! other implementations, not with this crate: each type reads its vector and
//! writes it back to exactly the same bytes.

use nilperit_format::{
    ChunkingProfile, DeltaEntry, HolderId, ItemKey, ItemRecord, LockFile, ObjectId, SnapshotHeader,
    SnapshotId, SourceId, Statistics, VaultConfig, VaultId, join_config_file, split_config_file,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn id(s: &str) -> ObjectId {
    ObjectId::from_bytes(hex(s).try_into().unwrap())
}

// ---- A.9: the vault config
const A9_MAP: &str = "a80100020103501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0882850165666978656400001a00040000850265666978656400001a00200000";
const A9_MAC: &str = "30c8938f3fdf3772fc4c9cd43ab4e1369ba11213952739ad63557d7b79b9fc25";
const A9_FILE: &str = "a80100020103501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0882850165666978656400001a00040000850265666978656400001a0020000030c8938f3fdf3772fc4c9cd43ab4e1369ba11213952739ad63557d7b79b9fc25";

#[test]
fn a9_vault_config() {
    let map = hex(A9_MAP);
    let config = VaultConfig::decode(&map).unwrap();
    assert_eq!(config.sequence, 1);
    assert_eq!(config.essentials.format_version, 0);
    assert_eq!(config.essentials.vault_id, VaultId::from_bytes([0x11; 16]));
    assert_eq!(config.essentials.encryption, "xchacha20-poly1305");
    assert_eq!(config.essentials.hash, "blake3");
    assert_eq!(config.essentials.key_encapsulation, "x-wing-draft-06");
    assert_eq!(
        config.essentials.read_public_key,
        (0..32).collect::<Vec<u8>>()
    );
    let profile = |id, algorithm: &str, min_size, avg_size, max_size| ChunkingProfile {
        id,
        algorithm: algorithm.into(),
        min_size,
        avg_size,
        max_size,
    };
    assert_eq!(
        config.chunking_profiles,
        [
            profile(1, "fixed", 0, 0, 262144),
            profile(2, "fixed", 0, 0, 2097152),
        ]
    );
    assert_eq!(config.encode().unwrap(), map);
}

#[test]
fn a9_config_file_is_the_map_and_the_mac() {
    let file = hex(A9_FILE);
    let (map, mac) = split_config_file(&file).unwrap();
    assert_eq!(map, hex(A9_MAP));
    assert_eq!(mac.to_vec(), hex(A9_MAC));
    assert_eq!(join_config_file(map, &mac).unwrap(), file);
}

// ---- A.10: item record, delta entry, snapshot header
const A10_ITEM: &str = "a30004010102a8015022222222222222222222222222222222024e646f63732f68656c6c6f2e747874036968656c6c6f2e747874041b0000018bcfe568000605076a746578742f706c61696e08a1646d6f64651901a409815820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e";
const A10_DELTA: &str = "a30005010102a60150222222222222222222222222222222220201045033333333333333333333333333333333051b0000018bcfe56be80781835820b19168afa67b7e95eb7000c5f93f73444e09b92245b5232d0d287187e6a867f6582025306b653396b5fc2c2fe63cadd537d25a4380bbd717db64771b54303248dd8d815820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e0880";
const A10_SNAPSHOT: &str = "a30006010102a7015022222222222222222222222222222222025033333333333333333333333333333333031b0000018bcfe56be80658207e1d2bde0b19face9b813766be8fde43a9bbccfd97d1144a941f289b5ac7b071070108a20101020509a6010003501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const A10_ITEM_KEY: &str = "b19168afa67b7e95eb7000c5f93f73444e09b92245b5232d0d287187e6a867f6";
const A10_CONTENT_ID: &str = "286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e";
const A10_ITEM_ID: &str = "25306b653396b5fc2c2fe63cadd537d25a4380bbd717db64771b54303248dd8d";
const A10_DELTA_ID: &str = "7e1d2bde0b19face9b813766be8fde43a9bbccfd97d1144a941f289b5ac7b071";

#[test]
fn a10_item_record() {
    let stored = hex(A10_ITEM);
    let item = ItemRecord::decode(&stored).unwrap();
    assert_eq!(item.source_id, SourceId::from_bytes([0x22; 16]));
    assert_eq!(item.native_id, b"docs/hello.txt");
    assert_eq!(item.title, "hello.txt");
    assert_eq!(item.modified, Some(1_700_000_000_000));
    assert_eq!(item.created, None);
    assert_eq!(item.size, 5);
    assert_eq!(item.media_type.as_deref(), Some("text/plain"));
    // The metadata is the CBOR map {"mode": 420}.
    assert_eq!(item.metadata, Some(hex("a1646d6f64651901a4")));
    assert_eq!(item.content, [id(A10_CONTENT_ID)]);
    assert_eq!(item.encode().unwrap(), stored);
}

#[test]
fn a10_delta_entry() {
    let stored = hex(A10_DELTA);
    let delta = DeltaEntry::decode(&stored).unwrap();
    assert_eq!(delta.source_id, SourceId::from_bytes([0x22; 16]));
    assert_eq!(delta.sequence, 1);
    assert_eq!(delta.parent, None);
    assert_eq!(delta.snapshot_id, SnapshotId::from_bytes([0x33; 16]));
    assert_eq!(delta.time, 1_700_000_001_000);
    assert_eq!(delta.connector_cursor, None);
    assert_eq!(delta.changed.len(), 1);
    let change = &delta.changed[0];
    assert_eq!(
        change.item_key,
        ItemKey::from_bytes(hex(A10_ITEM_KEY).try_into().unwrap())
    );
    assert_eq!(change.item_record, id(A10_ITEM_ID));
    assert_eq!(change.content, [id(A10_CONTENT_ID)]);
    assert!(delta.deleted.is_empty());
    assert_eq!(delta.encode().unwrap(), stored);
}

#[test]
fn a10_snapshot_header() {
    let stored = hex(A10_SNAPSHOT);
    let header = SnapshotHeader::decode(&stored).unwrap();
    assert_eq!(header.source_id, SourceId::from_bytes([0x22; 16]));
    assert_eq!(header.snapshot_id, SnapshotId::from_bytes([0x33; 16]));
    assert_eq!(header.time, 1_700_000_001_000);
    assert_eq!(header.item_map_root, None);
    assert_eq!(header.parent_snapshot, None);
    assert_eq!(header.journal_entry, id(A10_DELTA_ID));
    assert_eq!(header.journal_sequence, 1);
    assert_eq!(header.statistics, Some(Statistics { items: 1, size: 5 }));
    // The copy of the essential fields is the one of the config of A.9.
    let config = VaultConfig::decode(&hex(A9_MAP)).unwrap();
    assert_eq!(header.vault, config.essentials);
    assert_eq!(header.encode().unwrap(), stored);
}

#[test]
fn a11_writer_lock() {
    let bytes = hex("a2015055555555555555555555555555555555021b0000018bcfe56fd0");
    let lock = LockFile::decode(&bytes).unwrap();
    assert_eq!(lock.holder_id, HolderId::from_bytes([0x55; 16]));
    assert_eq!(lock.heartbeat, 1_700_000_002_000);
    assert_eq!(lock.encode(), bytes);
}
