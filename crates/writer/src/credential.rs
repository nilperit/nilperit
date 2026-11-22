//! The keys that a writer has: the node credential (format.md 3.2.4).

use nilperit_crypto::{DedupKey, DomainKeys, ReadPublicKey, RootSeed, WriterKey};

/// The node credential: the public part of the read key, the dedup key and the
/// writer key.
///
/// It lets a writer add data. It cannot open an R object, because it has no
/// private part of the read key (ADR 0004).
pub struct Credential {
    domains: DomainKeys,
    writer: WriterKey,
    read_public_key: ReadPublicKey,
}

impl Credential {
    /// Collects the keys of a node.
    pub fn new(dedup: &DedupKey, writer: WriterKey, read_public_key: ReadPublicKey) -> Self {
        Self {
            domains: dedup.domain_keys(),
            writer,
            read_public_key,
        }
    }

    /// Derives the credential from the root seed (format.md 3.2.9). The root seed
    /// is not kept, and neither is the private part of the read key.
    pub fn from_seed(seed: &RootSeed) -> Self {
        Self::new(
            &seed.dedup_key(),
            seed.writer_key(),
            seed.read_key().public_key(),
        )
    }

    /// The keys of the hash domains: object IDs, item keys and content hashes.
    pub fn domains(&self) -> &DomainKeys {
        &self.domains
    }

    /// The writer key.
    pub fn writer(&self) -> &WriterKey {
        &self.writer
    }

    /// The public part of the read key. It is what a writer seals pack keys to.
    pub fn read_public_key(&self) -> &ReadPublicKey {
        &self.read_public_key
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(..)")
    }
}
