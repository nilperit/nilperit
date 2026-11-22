//! The keys that a writer has: the node credential (format.md 3.2.4).

use nilperit_crypto::{DedupKey, DomainKeys, ReadPublicKey, RootSeed, WriterKey};
use nilperit_reader::Keys;

/// The node credential: the public part of the read key, the dedup key and the
/// writer key.
///
/// It lets a writer add data. It cannot open an R object, because it has no
/// private part of the read key (ADR 0004).
pub struct Credential {
    dedup: DedupKey,
    domains: DomainKeys,
    writer: WriterKey,
    read_public_key: ReadPublicKey,
}

impl Credential {
    /// Collects the keys of a node.
    pub fn new(dedup: &DedupKey, writer: WriterKey, read_public_key: ReadPublicKey) -> Self {
        Self {
            dedup: DedupKey::from_bytes(*dedup.as_bytes()),
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

    /// The keys that a reader needs to open the vault as a node does: without the
    /// read key. The sync engine reads the journal with them (format.md 3.2.4).
    pub fn reader_keys(&self) -> Keys {
        Keys::for_node(
            WriterKey::from_bytes(*self.writer.as_bytes()),
            self.read_public_key.clone(),
            &self.dedup,
        )
    }

    /// The keys of the hash domains: object IDs, item keys, content hashes and
    /// source IDs.
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
