//! The keys that a reader uses.

use nilperit_crypto::{DedupKey, DomainKeys, ReadKey, ReadPublicKey, RootSeed, WriterKey};

/// The keys that a reader uses.
///
/// A reader needs the writer key for the W objects, the read key for the R
/// objects, and the dedup key to check object IDs. A node does not have the read
/// key (ADR 0004): it can read the W objects and nothing else.
pub struct Keys {
    writer: WriterKey,
    read: Option<ReadKey>,
    read_public_key: ReadPublicKey,
    domains: DomainKeys,
}

impl Keys {
    /// Collects the keys of an owner: all keys.
    pub fn new(writer: WriterKey, read: ReadKey, dedup: &DedupKey) -> Self {
        Self {
            writer,
            read_public_key: read.public_key(),
            read: Some(read),
            domains: dedup.domain_keys(),
        }
    }

    /// Collects the keys of a node (format.md 3.2.4): without the read key. The
    /// public part of the read key is for the check of the vault config.
    pub fn for_node(writer: WriterKey, read_public_key: ReadPublicKey, dedup: &DedupKey) -> Self {
        Self {
            writer,
            read: None,
            read_public_key,
            domains: dedup.domain_keys(),
        }
    }

    /// Derives all keys from the root seed (format.md 3.2.9).
    pub fn from_seed(seed: &RootSeed) -> Self {
        Self::new(seed.writer_key(), seed.read_key(), &seed.dedup_key())
    }

    /// The writer key.
    pub fn writer(&self) -> &WriterKey {
        &self.writer
    }

    /// The read key. A node does not have it.
    pub fn read(&self) -> Option<&ReadKey> {
        self.read.as_ref()
    }

    /// The public part of the read key.
    pub fn read_public_key(&self) -> &ReadPublicKey {
        &self.read_public_key
    }

    /// The keys of the hash domains.
    pub fn domains(&self) -> &DomainKeys {
        &self.domains
    }
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys(..)")
    }
}
