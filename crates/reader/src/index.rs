//! The pack index: which pack holds which object.
//!
//! The index is a cache. A reader builds it by opening every pack and reading its
//! object table (format.md 5.5.10, 10.7). The first system builds it for every
//! run. Index segments in the vault can replace the scan later.

use crate::layout::{PACKS_DIR, parse_pack_path};
use crate::pack::{ObjectReadError, Pack, PackOpenError};
use crate::target::{Target, TargetError};
use crate::vault::Vault;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use nilperit_format::{ObjectId, PackName};

/// The packs of a vault and the objects in them.
#[derive(Debug, Default)]
pub struct PackIndex {
    packs: BTreeMap<PackName, Pack>,
    objects: BTreeMap<ObjectId, Vec<PackName>>,
    skipped: Vec<(PackName, PackOpenError)>,
}

impl PackIndex {
    /// The packs that opened.
    pub fn packs(&self) -> impl Iterator<Item = &Pack> {
        self.packs.values()
    }

    /// The packs that did not open, and why. A damaged pack does not stop the
    /// scan: damage stays local (ADR 0013).
    pub fn skipped(&self) -> &[(PackName, PackOpenError)] {
        &self.skipped
    }

    /// The number of different objects.
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Whether some pack holds the object.
    pub fn contains(&self, id: &ObjectId) -> bool {
        self.objects.contains_key(id)
    }

    /// The names of the packs that hold the object. A crash or a repair can put
    /// the same object in more than one pack.
    pub fn packs_of(&self, id: &ObjectId) -> &[PackName] {
        self.objects.get(id).map_or(&[], Vec::as_slice)
    }
}

impl<T: Target> Vault<T> {
    /// Opens every pack of the vault and indexes its objects.
    ///
    /// A file in `packs/` whose name is not a pack name is ignored. A pack that
    /// does not open is listed in [`PackIndex::skipped`]. Only a failure to list
    /// the packs is an error.
    pub async fn scan_packs(&self) -> Result<PackIndex, TargetError> {
        let mut names: Vec<PackName> = self
            .target()
            .list(PACKS_DIR)
            .await?
            .iter()
            .filter_map(|path| parse_pack_path(path))
            .collect();
        names.sort_unstable();
        names.dedup();

        let mut index = PackIndex::default();
        for name in names {
            match self.open_pack(name).await {
                Ok(pack) => {
                    for entry in &pack.table().entries {
                        index.objects.entry(entry.object_id).or_default().push(name);
                    }
                    index.packs.insert(name, pack);
                }
                Err(e) => index.skipped.push((name, e)),
            }
        }
        Ok(index)
    }

    /// Reads an object from the first pack that gives it. When no pack gives it,
    /// the error is the one of the first pack.
    pub async fn read_indexed(
        &self,
        index: &PackIndex,
        id: &ObjectId,
    ) -> Result<Vec<u8>, ObjectReadError> {
        let mut first_error = None;
        for name in index.packs_of(id) {
            let Some(pack) = index.packs.get(name) else {
                continue;
            };
            match self.read_object(pack, id).await {
                Ok(stored) => return Ok(stored),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        Err(first_error.unwrap_or(ObjectReadError::NotInPack))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{CONFIG_A, pack_path};
    use crate::memory_target::MemoryTarget;
    use crate::test_util::{
        TestKeys, TestObject, block_on, build_pack, config, file_with_key, pack_name, test_seed,
        vault_with,
    };
    use alloc::vec;
    use nilperit_format::{Compression, KeyClass};

    fn vault(packs: &[&[u8]]) -> Vault<MemoryTarget> {
        vault_with(packs, &[])
    }

    fn pack(objects: &[TestObject]) -> (Vec<u8>, Vec<ObjectId>) {
        build_pack(&TestKeys::from_seed(&test_seed()), objects)
    }

    fn chunk(text: &[u8]) -> TestObject {
        TestObject::new(1, KeyClass::R, Compression::Deflate, text)
    }

    fn content(text: &[u8]) -> TestObject {
        TestObject::new(2, KeyClass::W, Compression::None, text)
    }

    #[test]
    fn an_empty_vault_has_an_empty_index() {
        let index = block_on(vault(&[]).scan_packs()).unwrap();
        assert_eq!(index.object_count(), 0);
        assert!(index.skipped().is_empty());
        assert_eq!(index.packs().count(), 0);
    }

    #[test]
    fn indexes_and_reads_objects_of_several_packs() {
        let (a, ids_a) = pack(&[chunk(b"one"), content(b"two")]);
        let (b, ids_b) = pack(&[chunk(b"three")]);
        let vault = vault(&[&a, &b]);
        let index = block_on(vault.scan_packs()).unwrap();
        assert_eq!(index.object_count(), 3);
        assert_eq!(index.packs().count(), 2);
        assert_eq!(index.packs_of(&ids_a[0]), [pack_name(&a)]);
        assert_eq!(index.packs_of(&ids_b[0]), [pack_name(&b)]);
        assert!(index.contains(&ids_a[1]));
        for (id, text) in [
            (&ids_a[0], &b"one"[..]),
            (&ids_a[1], b"two"),
            (&ids_b[0], b"three"),
        ] {
            assert_eq!(block_on(vault.read_indexed(&index, id)).unwrap(), text);
        }
    }

    #[test]
    fn an_unknown_object_is_not_in_the_pack() {
        let (a, _) = pack(&[chunk(b"one")]);
        let vault = vault(&[&a]);
        let index = block_on(vault.scan_packs()).unwrap();
        let unknown = ObjectId::from_bytes([0; 32]);
        assert!(!index.contains(&unknown));
        assert!(matches!(
            block_on(vault.read_indexed(&index, &unknown)),
            Err(ObjectReadError::NotInPack)
        ));
    }

    #[test]
    fn ignores_files_that_are_not_packs() {
        let (a, _) = pack(&[chunk(b"one")]);
        let mut target = MemoryTarget::new();
        target.insert(
            CONFIG_A,
            file_with_key(&config(&test_seed(), 1, 1), &test_seed()),
        );
        target.insert(&pack_path(&pack_name(&a)), a.clone());
        target.insert("packs/ab/temporary", vec![1, 2, 3]);
        target.insert("packs/notes.txt", vec![1, 2, 3]);
        let vault = block_on(Vault::open(target, &test_seed())).unwrap();
        let index = block_on(vault.scan_packs()).unwrap();
        assert_eq!(index.packs().count(), 1);
        assert!(index.skipped().is_empty());
    }

    #[test]
    fn a_damaged_pack_is_skipped_and_the_others_stay_readable() {
        let (good, ids) = pack(&[chunk(b"good")]);
        let (mut bad, _) = pack(&[chunk(b"bad")]);
        let last = bad.len() - 1;
        bad[last] ^= 1; // the end magic of the footer
        let bad_name = pack_name(&bad);
        let vault = vault(&[&good, &bad]);
        let index = block_on(vault.scan_packs()).unwrap();
        assert_eq!(index.packs().count(), 1);
        assert_eq!(index.skipped().len(), 1);
        assert_eq!(index.skipped()[0].0, bad_name);
        assert_eq!(
            block_on(vault.read_indexed(&index, &ids[0])).unwrap(),
            b"good"
        );
    }

    #[test]
    fn the_same_object_in_two_packs_can_be_read_from_the_good_one() {
        let (one, ids) = pack(&[chunk(b"shared"), content(b"only in one")]);
        let (two, _) = pack(&[chunk(b"shared"), content(b"only in two")]);
        // Damage the body of the pack whose name sorts first. The footer, the
        // header and the table stay intact, so both packs open.
        let (first, second) = if pack_name(&one) < pack_name(&two) {
            (one, two)
        } else {
            (two, one)
        };
        let mut damaged = first.clone();
        let probe = vault(&[&first]);
        let probe_index = block_on(probe.scan_packs()).unwrap();
        let offset = probe_index.packs().next().unwrap().table().entries[0].offset as usize;
        damaged[offset + 30] ^= 1;
        let vault = vault(&[&damaged, &second]);
        let index = block_on(vault.scan_packs()).unwrap();
        assert_eq!(index.packs_of(&ids[0]).len(), 2);
        assert_eq!(
            block_on(vault.read_indexed(&index, &ids[0])).unwrap(),
            b"shared"
        );
    }

    #[test]
    fn reports_the_error_of_the_first_pack_when_no_pack_gives_the_object() {
        let (one, ids) = pack(&[chunk(b"shared")]);
        let (two, _) = pack(&[chunk(b"shared"), content(b"x")]);
        let mut damaged = Vec::new();
        for original in [&one, &two] {
            let probe = vault(&[original]);
            let index = block_on(probe.scan_packs()).unwrap();
            let offset = index.packs().next().unwrap().table().entries[0].offset as usize;
            let mut bytes = original.clone();
            bytes[offset + 30] ^= 1;
            damaged.push(bytes);
        }
        let vault = vault(&[&damaged[0], &damaged[1]]);
        let index = block_on(vault.scan_packs()).unwrap();
        assert!(matches!(
            block_on(vault.read_indexed(&index, &ids[0])),
            Err(ObjectReadError::NotAuthentic)
        ));
    }
}
