//! Tests against the test vectors of format.md A.8 (a pack) and A.9 (keys and the
//! vault config). The vectors were made with other implementations (the Python
//! `blake3`, `mnemonic` and PyNaCl packages), not with this crate.

use std::convert::Infallible;

use nilperit_crypto::{
    AeadKey, CryptoRng, DedupKey, RootSeed, WriterKey, config_mac, decrypt, encrypt,
    verify_config_mac,
};
use x_wing::kem::common::rand_core::{TryCryptoRng, TryRng};

/// A "random" number generator that always gives the same byte. It lets a test
/// make the nonces of the vector. NOT secure: only for tests.
struct FixedRng(u8);

impl TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_ne_bytes([self.0; 4]))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_ne_bytes([self.0; 8]))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(self.0);
        Ok(())
    }
}
impl TryCryptoRng for FixedRng {}

fn _assert_crypto_rng<R: CryptoRng>(_: &R) {}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn range32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start + i as u8)
}

// ---- A.9: keys and the vault config
const A9_WORDS: &str = "pass artist pottery enable foil fatigue pencil crystal produce grace hill garage arch sun solution note repeat saddle common install rookie gain wife theme";
const A9_DEDUP: &str = "817539ea4e9be3fb2c37fc4e8772d525e485efa986ddef131fa2791e397c81fb";
const A9_WRITER: &str = "602b54db5ed2a3c74b36a568b852de6a126d2dec9b1971ea7c1f3ec4cf422c6c";
const A9_CHUNKER: &str = "ae43d7f36553f9e55159aaad739ea9f2070af24ad467a781039ad161107290d5";
const A9_READ: &str = "e943a3cea78674c96b2354ec08caf3064ed001589a3919e75e59a4af2a333b77";
const A9_CONFIG_MAC_KEY: &str = "b6de912a5d95d54c54ac2487914b5ab0a3976e70ea126ac390eb1e5569ee953f";
const A9_SNAPSHOT_HEADER_KEY: &str =
    "6f5e6da437a1f6651279a3b50bddffada3bcfde1573ba1285b41cba6fd460f61";
const A9_CONDEMNATION_KEY: &str =
    "0a96deb444a02736cfd2c4a70e0586f1e8c11abad91b0b6ef5a193d1f3bb8777";
const A9_INDEX_SEGMENT_KEY: &str =
    "0e2db11232654989fd38827244a634d1ea545f11500c7453c63419997ae7b75f";
const A9_PACK_OBJECT_KEY: &str = "b51b12b1ff96580e7e9faf30f1eacfa111927612515cee94780e4d4fa8a81508";
const A9_PACK_TABLE_KEY: &str = "ddc557fb4f9ce07ae8c74f25b59982ccad494a32786ac3eb27b83fbfa59834c0";
const A9_CONFIG_MAP: &str = "a80100020103501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f08838501646e6f6e6500001a0001000085026c666173746364632d323032301a000100001a000400001a0010000085036c666173746364632d323032301a000800001a002000001a00800000";
const A9_CONFIG_MAC: &str = "372fab368795b471732a8a118492fbc5f48c34ac333cf0d1548b47e19ae9c828";

fn a9_root() -> RootSeed {
    RootSeed::from_bytes(range32(0xa0))
}

#[test]
fn a9_recovery_phrase() {
    assert_eq!(&*a9_root().to_phrase(), A9_WORDS);
    let back = RootSeed::from_phrase(A9_WORDS).unwrap();
    assert_eq!(back.as_bytes(), &range32(0xa0));
}

#[test]
fn a9_keys_from_the_root_seed() {
    let root = a9_root();
    assert_eq!(root.dedup_key().as_bytes(), &bytes32(A9_DEDUP));
    assert_eq!(root.writer_key().as_bytes(), &bytes32(A9_WRITER));
    assert_eq!(root.chunker_seed().as_bytes(), &bytes32(A9_CHUNKER));
    assert_eq!(root.read_key().as_bytes(), &bytes32(A9_READ));
}

#[test]
fn a9_keys_from_the_writer_key() {
    let writer = a9_root().writer_key();
    assert_eq!(
        writer.config_mac_key().as_bytes(),
        &bytes32(A9_CONFIG_MAC_KEY)
    );
    assert_eq!(
        writer.snapshot_header_key().as_bytes(),
        &bytes32(A9_SNAPSHOT_HEADER_KEY)
    );
    assert_eq!(
        writer.condemnation_record_key().as_bytes(),
        &bytes32(A9_CONDEMNATION_KEY)
    );
    assert_eq!(
        writer.index_segment_key().as_bytes(),
        &bytes32(A9_INDEX_SEGMENT_KEY)
    );
    assert_eq!(
        writer.pack_object_key().as_bytes(),
        &bytes32(A9_PACK_OBJECT_KEY)
    );
    assert_eq!(
        writer.pack_table_key().as_bytes(),
        &bytes32(A9_PACK_TABLE_KEY)
    );
}

#[test]
fn a9_config_mac() {
    let key = a9_root().writer_key().config_mac_key();
    let map = hex(A9_CONFIG_MAP);
    let mac = bytes32(A9_CONFIG_MAC);
    assert_eq!(config_mac(&key, &map), mac);
    assert!(verify_config_mac(&key, &map, &mac));
    let mut bad = map.clone();
    bad[0] ^= 1;
    assert!(!verify_config_mac(&key, &bad, &mac));
}

// ---- A.8: a pack (408 bytes)
const A8_PACK: &str = "894e504b0d0a1a0a2e000000a50100020003727863686163686132302d706f6c7931333035046b706c616365686f6c6465720566626c616b65330101010101010101010101010101010101010101010101014683820b6bdd17744f45bb9c2275d3d73057e39b980765020202020202020202020202020202020202020202020202c5e12b97bd9e2e7d093d49a7a9c7db234d82f2da194b7b55517ebcb80e3a652036e81578286e7506f30dcfb8a8ea38f7111dd372053a9b7c65a12982437fe67c87390691e4e97a85f48e30a866aa17f9bebfe753881f5c03d706534a1efb54a9fd9a04000000deadbeef030303030303030303030303030303030303030303030303641136128a959b741d53c008bbdf760f87c8ed6499d7ad62b8c483c0e134ba3c269eff66bb08c01ee9baf1a4a9608275c2a7e0e252b52c3bcdb28471056b637fca99bb999c6ff11fdd451bbaba53b9db719e0eb1f81e91603528d27060f14b5036b5818c1144c0fd989adddcc5353d7ab9ab11c81e9e47dc98fba75147e3000000000000009d000000000000004e504b2d454e440a";
const A8_CHUNK_ID: &str = "09c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e";
const A8_CONTENT_ID: &str = "286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e";
const A8_CHUNK_COMPRESSED: &str = "cb48cdc9c90700";
const A8_CONTENT_STORED: &str = "a30002010102a40181582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e0205035820ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e0401";
const A8_TABLE_PLAIN: &str = "a30003010102a1018287582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e016152183a182f676465666c61746505875820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e0261571869187a646e6f6e651852";
const A8_PACK_OBJECT_KEY: &str = "80f42359c8d9d1116b328bc1ff160b156b538c8a70d97e7a172ff6e85acab695";
const A8_PACK_TABLE_KEY: &str = "3e270c1ce6008461ef7d7d2e9e6227e2a957be88a725a489b01c102567eab5a2";

struct A8 {
    pack: Vec<u8>,
    pack_key: AeadKey,
    object_key: AeadKey,
    table_key: AeadKey,
}

fn a8() -> A8 {
    let writer = WriterKey::from_bytes(range32(0x20));
    // The keys of A.8.3 come from the writer key `20 21 ... 3f`.
    assert_eq!(
        writer.pack_object_key().as_bytes(),
        &bytes32(A8_PACK_OBJECT_KEY)
    );
    assert_eq!(
        writer.pack_table_key().as_bytes(),
        &bytes32(A8_PACK_TABLE_KEY)
    );
    A8 {
        pack: hex(A8_PACK),
        pack_key: AeadKey::from_bytes(range32(0x40)),
        object_key: writer.pack_object_key(),
        table_key: writer.pack_table_key(),
    }
}

fn object_aad(id: &str, type_id: u32) -> Vec<u8> {
    let mut aad = hex(id);
    aad.extend(type_id.to_le_bytes());
    aad
}

// Positions in the pack (format.md A.8.4).
const HEADER_END: usize = 58;
const CHUNK: (usize, usize) = (58, 105);
const CONTENT: (usize, usize) = (105, 227);
// The trailer is: seal size (4 bytes), the seal (4 bytes), the packed object table.
const TABLE: (usize, usize) = (227 + 8, 384);

#[test]
fn a8_object_ids_use_the_dedup_key() {
    let keys = DedupKey::from_bytes(range32(0x00)).domain_keys();
    let chunk_id = keys.object_id(1, b"hello");
    assert_eq!(chunk_id.to_vec(), hex(A8_CHUNK_ID));
    let content_id = keys.object_id(2, &hex(A8_CONTENT_STORED));
    assert_eq!(content_id.to_vec(), hex(A8_CONTENT_ID));
}

#[test]
fn a8_decrypts_every_packed_object_of_the_vector() {
    let v = a8();
    // The R chunk: pack key, associated data is the object ID and the type ID 1.
    let chunk = decrypt(
        &v.pack_key,
        &object_aad(A8_CHUNK_ID, 1),
        &v.pack[CHUNK.0..CHUNK.1],
    )
    .unwrap();
    assert_eq!(chunk, hex(A8_CHUNK_COMPRESSED));
    // The W content object: pack object key, type ID 2.
    let content = decrypt(
        &v.object_key,
        &object_aad(A8_CONTENT_ID, 2),
        &v.pack[CONTENT.0..CONTENT.1],
    )
    .unwrap();
    assert_eq!(content, hex(A8_CONTENT_STORED));
    // The object table: pack table key, associated data is the hash of the header.
    let header_hash = blake3::hash(&v.pack[..HEADER_END]);
    let table = decrypt(
        &v.table_key,
        header_hash.as_bytes(),
        &v.pack[TABLE.0..TABLE.1],
    )
    .unwrap();
    assert_eq!(table, hex(A8_TABLE_PLAIN));
}

#[test]
fn a8_encrypts_to_exactly_the_bytes_of_the_vector() {
    let v = a8();
    // The vector uses the nonces `01..`, `02..` and `03..` (24 bytes each).
    let chunk = encrypt(
        &v.pack_key,
        &object_aad(A8_CHUNK_ID, 1),
        &hex(A8_CHUNK_COMPRESSED),
        &mut FixedRng(1),
    )
    .unwrap();
    assert_eq!(chunk, v.pack[CHUNK.0..CHUNK.1]);
    let content = encrypt(
        &v.object_key,
        &object_aad(A8_CONTENT_ID, 2),
        &hex(A8_CONTENT_STORED),
        &mut FixedRng(2),
    )
    .unwrap();
    assert_eq!(content, v.pack[CONTENT.0..CONTENT.1]);
    let header_hash = blake3::hash(&v.pack[..HEADER_END]);
    let table = encrypt(
        &v.table_key,
        header_hash.as_bytes(),
        &hex(A8_TABLE_PLAIN),
        &mut FixedRng(3),
    )
    .unwrap();
    assert_eq!(table, v.pack[TABLE.0..TABLE.1]);
}

#[test]
fn a8_a_packed_object_moved_to_another_entry_is_rejected() {
    let v = a8();
    // The associated data binds a packed object to its object ID and type ID.
    let moved = decrypt(
        &v.object_key,
        &object_aad(A8_CHUNK_ID, 2),
        &v.pack[CONTENT.0..CONTENT.1],
    );
    assert!(moved.is_err());
    let wrong_type = decrypt(
        &v.object_key,
        &object_aad(A8_CONTENT_ID, 1),
        &v.pack[CONTENT.0..CONTENT.1],
    );
    assert!(wrong_type.is_err());
    // A damaged header makes the object table fail.
    let mut header = v.pack[..HEADER_END].to_vec();
    header[20] ^= 1;
    let bad = decrypt(
        &v.table_key,
        blake3::hash(&header).as_bytes(),
        &v.pack[TABLE.0..TABLE.1],
    );
    assert!(bad.is_err());
}
