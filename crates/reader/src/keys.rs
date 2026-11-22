//! The keys that a reader uses.

use nilperit_crypto::{DedupKey, DomainKeys, ReadKey, RootSeed, WriterKey};

/// The keys of a reader that has the recovery phrase.
///
/// A reader needs the writer key for the W objects, the read key for the R
/// objects, and the dedup key to check object IDs.
pub struct Keys {
    writer: WriterKey,
    read: ReadKey,
    domains: DomainKeys,
}

impl Keys {
    /// Collects the keys.
    pub fn new(writer: WriterKey, read: ReadKey, dedup: &DedupKey) -> Self {
        Self {
            writer,
            read,
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

    /// The read key.
    pub fn read(&self) -> &ReadKey {
        &self.read
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
