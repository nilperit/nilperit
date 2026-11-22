//! Hash domains and the keyed hashes of the vault (format.md 3.2.5, 3.2.6, 4.7, 5.6.5).
//!
//! The dedup key is the root of three domain keys. Each kind of hash uses its
//! own domain key, so a hash of one kind never equals a hash of another kind
//! (ADR 0015). The hash function is BLAKE3. Nothing in this module implements a
//! primitive: it only composes `blake3` calls.

use core::fmt;

use zeroize::Zeroize;

/// Size of every hash and every key in this module, in bytes.
pub const HASH_LEN: usize = 32;

/// One kind of keyed hash (format.md 3.2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashDomain {
    /// Object IDs.
    ObjectId,
    /// Item keys.
    ItemKey,
    /// Content hashes.
    ContentHash,
}

impl HashDomain {
    /// The BLAKE3 `derive_key` context string of the domain.
    ///
    /// These strings are part of the format. Changing one changes every hash of
    /// the domain.
    ///
    /// The form `application date purpose` follows the BLAKE3 convention for
    /// `derive_key` context strings. The date has no meaning of its own: it is
    /// not a version and not a build date. Uniqueness is the only requirement.
    pub const fn context(self) -> &'static str {
        match self {
            Self::ObjectId => "nilperit 2026-11-22 object-id",
            Self::ItemKey => "nilperit 2026-11-22 item-key",
            Self::ContentHash => "nilperit 2026-11-22 content-hash",
        }
    }
}

/// An input is larger than a size field of the format can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeError;

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("input is larger than 4 GiB minus 1 byte")
    }
}

impl core::error::Error for SizeError {}

/// The dedup key. The node has it (format.md 3.2.3).
pub struct DedupKey([u8; HASH_LEN]);

impl DedupKey {
    /// Wraps the 32 bytes of the key. The caller derives them from the root seed.
    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// The secret bytes, for the node credential. Handle them with care and
    /// never log them.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Derives the key of one hash domain.
    pub fn domain_key(&self, domain: HashDomain) -> DomainKey {
        DomainKey(blake3::derive_key(domain.context(), &self.0))
    }

    /// Derives the keys of all hash domains.
    pub fn domain_keys(&self) -> DomainKeys {
        DomainKeys {
            object_id: self.domain_key(HashDomain::ObjectId),
            item_key: self.domain_key(HashDomain::ItemKey),
            content_hash: self.domain_key(HashDomain::ContentHash),
        }
    }
}

impl Drop for DedupKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Never print key bytes (AGENTS.md).
impl fmt::Debug for DedupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DedupKey(..)")
    }
}

/// The key of one hash domain.
pub struct DomainKey([u8; HASH_LEN]);

impl DomainKey {
    /// Exposes the key bytes, for test vectors and for deriving further data.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    fn hasher(&self) -> blake3::Hasher {
        blake3::Hasher::new_keyed(&self.0)
    }
}

impl Drop for DomainKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DomainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DomainKey(..)")
    }
}

/// The keys of all hash domains, and the hashes that use them.
pub struct DomainKeys {
    object_id: DomainKey,
    item_key: DomainKey,
    content_hash: DomainKey,
}

impl DomainKeys {
    /// The object ID (format.md 4.7).
    ///
    /// The hash input is `type_id` as 4 bytes (little-endian), then `stored`.
    /// `stored` is the encoded envelope, or for a chunk the plaintext before
    /// compression. Never pass a re-encoding of a decoded object.
    pub fn object_id(&self, type_id: u32, stored: &[u8]) -> [u8; HASH_LEN] {
        let mut h = self.object_id.hasher();
        h.update(&type_id.to_le_bytes());
        h.update(stored);
        h.finalize().into()
    }

    /// The item key (format.md 5.6.5).
    ///
    /// The hash input is the 4-byte little-endian size of `source_id`,
    /// `source_id`, the 4-byte little-endian size of `native_id`, `native_id`.
    pub fn item_key(
        &self,
        source_id: &[u8],
        native_id: &[u8],
    ) -> Result<[u8; HASH_LEN], SizeError> {
        let source_size = u32::try_from(source_id.len()).map_err(|_| SizeError)?;
        let native_size = u32::try_from(native_id.len()).map_err(|_| SizeError)?;
        let mut h = self.item_key.hasher();
        h.update(&source_size.to_le_bytes());
        h.update(source_id);
        h.update(&native_size.to_le_bytes());
        h.update(native_id);
        Ok(h.finalize().into())
    }

    /// Starts a content hash (format.md 5.3.1). Feed it the full plaintext.
    pub fn content_hasher(&self) -> ContentHasher {
        ContentHasher(self.content_hash.hasher())
    }
}

impl fmt::Debug for DomainKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DomainKeys(..)")
    }
}

/// Streaming content hash.
pub struct ContentHasher(blake3::Hasher);

impl ContentHasher {
    /// Adds plaintext.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the hash of all plaintext so far.
    pub fn finalize(&self) -> [u8; HASH_LEN] {
        self.0.finalize().into()
    }
}

impl fmt::Debug for ContentHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentHasher(..)")
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;

    // Vectors made with the Python `blake3` package, not with this crate.
    // Dedup key: bytes 0x00..=0x1f.
    fn dedup() -> DedupKey {
        DedupKey::from_bytes(core::array::from_fn(|i| i as u8))
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        bytes.iter().fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        })
    }

    // { 0: 5, 1: 1, 2: {} }
    const ENVELOPE: &[u8] = &[0xa3, 0x00, 0x05, 0x01, 0x01, 0x02, 0xa0];

    #[test]
    fn domain_key_vectors() {
        let k = dedup();
        assert_eq!(
            hex(k.domain_key(HashDomain::ObjectId).as_bytes()),
            "7a5a3c46561ae064a4d4b3451e3da054f24dec4aabca9289bbd86ac9d2272202"
        );
        assert_eq!(
            hex(k.domain_key(HashDomain::ItemKey).as_bytes()),
            "0c715b92de06677df044d97ee6d42629fbb18f268799e59f5b444da951e07dc1"
        );
        assert_eq!(
            hex(k.domain_key(HashDomain::ContentHash).as_bytes()),
            "a4190220377899bde0d628774ca52f067303395c2c18784c9bb99cbd9a964cb8"
        );
    }

    #[test]
    fn object_id_vectors() {
        let keys = dedup().domain_keys();
        assert_eq!(
            hex(&keys.object_id(5, ENVELOPE)),
            "d7692ea1f63147927d8aaa890330123e9c2991cb6b84b5c86379614092707744"
        );
        assert_eq!(
            hex(&keys.object_id(1, ENVELOPE)),
            "c71aea3d61bec2b68e7f2de593e86ab129268d43f78314b5c21c9830993070aa"
        );
        assert_eq!(
            hex(&keys.object_id(1, &[])),
            "6578b1b6af05c75c4b025a910b22e152925a12f526fe40dea8ca134dbb64cddf"
        );
    }

    #[test]
    fn content_object_id_vector() {
        // The stored bytes of format.md A.6.2, as bytes. Type ID 2.
        let mut stored = Vec::from([0xa3, 0x00, 0x02, 0x01, 0x01, 0x02, 0xa4, 0x01, 0x82]);
        for byte in [0x11u8, 0x22] {
            stored.extend([0x58, 0x20]);
            stored.extend([byte; 32]);
        }
        stored.extend([0x02, 0x1a, 0x00, 0x04, 0x93, 0xe0, 0x03, 0x58, 0x20]);
        stored.extend([0x33; 32]);
        stored.extend([0x04, 0x01]);
        assert_eq!(stored.len(), 120);
        assert_eq!(
            hex(&dedup().domain_keys().object_id(2, &stored)),
            "449fc1f8fb06c9aefa7fe47861cdf2f20b5af3fa1d316427cf2ddd2b504cf5e3"
        );
    }

    #[test]
    fn item_key_vectors() {
        let keys = dedup().domain_keys();
        assert_eq!(
            hex(&keys.item_key(b"ab", b"c").unwrap()),
            "1dc64f7e4a20b22b43463d82b7a5e732ed4b375aa5c3f339705f06792910548d"
        );
        assert_eq!(
            hex(&keys.item_key(b"a", b"bc").unwrap()),
            "a7e0457e53fc93fdd9d3a73b29ddfbbe09bdad9f5b2ae18d3876ec296a7f60d2"
        );
        assert_eq!(
            hex(&keys.item_key(b"gmail", b"msg-1").unwrap()),
            "5bedc3e15a00253238b061e48e4f2323246e8941c2d9fec30c59fd706353814d"
        );
    }

    #[test]
    fn content_hash_vector_and_streaming() {
        let keys = dedup().domain_keys();
        let mut h = keys.content_hasher();
        h.update(b"he");
        h.update(b"llo");
        assert_eq!(
            hex(&h.finalize()),
            "ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e"
        );
    }

    #[test]
    fn type_id_separates_equal_bytes() {
        let keys = dedup().domain_keys();
        assert_ne!(keys.object_id(1, ENVELOPE), keys.object_id(2, ENVELOPE));
    }

    #[test]
    fn domains_never_give_equal_hashes() {
        // The same bytes in all three domains. Item key input is framed, so
        // compare an object ID and a content hash of identical input.
        let keys = dedup().domain_keys();
        let mut content = keys.content_hasher();
        content.update(&1u32.to_le_bytes());
        content.update(ENVELOPE);
        assert_ne!(keys.object_id(1, ENVELOPE), content.finalize());
    }

    #[test]
    fn item_key_framing_is_unambiguous() {
        let keys = dedup().domain_keys();
        assert_ne!(
            keys.item_key(b"ab", b"c").unwrap(),
            keys.item_key(b"a", b"bc").unwrap()
        );
        assert_ne!(
            keys.item_key(b"", b"x").unwrap(),
            keys.item_key(b"x", b"").unwrap()
        );
    }

    #[test]
    fn different_dedup_keys_give_different_hashes() {
        let other = DedupKey::from_bytes([7; HASH_LEN]).domain_keys();
        assert_ne!(
            other.object_id(5, ENVELOPE),
            dedup().domain_keys().object_id(5, ENVELOPE)
        );
    }

    #[test]
    fn debug_output_hides_key_bytes() {
        let k = dedup();
        let keys = k.domain_keys();
        let shown: Vec<String> = alloc::vec![
            alloc::format!("{k:?}"),
            alloc::format!("{keys:?}"),
            alloc::format!("{:?}", k.domain_key(HashDomain::ItemKey)),
        ];
        for s in shown {
            assert!(s.ends_with("(..)"), "{s}");
        }
    }
}
