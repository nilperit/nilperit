//! The commit (format.md section 8).
//!
//! A commit makes new data part of the vault. The snapshot header completes it:
//! before that file exists, a reader does not see the new data (format.md 8.3).

use crate::credential::Credential;
use crate::lock::{LockError, WriterLock};
use crate::pack_builder::BuiltPack;
use crate::target::WriteTarget;
use nilperit_crypto::{CryptoRng, encrypt};
use nilperit_format::{ObjectError, PackClass, SnapshotHeader};
use nilperit_reader::TargetError;
use nilperit_reader::layout::{pack_path, snapshot_path};
use std::fmt;

/// A commit failed. Files that were written before the failure stay in the
/// vault as orphans (format.md 8.5). The snapshot header is not written, so a
/// reader does not see the new data.
#[derive(Debug)]
pub enum CommitError {
    /// The writer lock is lost: a commit needs it (format.md 8.6.3).
    Lock(LockError),
    /// The target failed.
    Target(TargetError),
    /// The snapshot header is not valid.
    Header(ObjectError),
    /// The encryption of the snapshot header failed.
    Encryption,
}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lock(e) => e.fmt(f),
            Self::Target(e) => e.fmt(f),
            Self::Header(e) => write!(f, "the snapshot header is not valid: {e}"),
            Self::Encryption => f.write_str("the encryption failed"),
        }
    }
}

impl std::error::Error for CommitError {}

impl From<LockError> for CommitError {
    fn from(e: LockError) -> Self {
        Self::Lock(e)
    }
}

impl From<TargetError> for CommitError {
    fn from(e: TargetError) -> Self {
        Self::Target(e)
    }
}

/// Writes the packs and then the snapshot header, in the order of format.md 8.2:
/// data packs, metadata packs, snapshot header.
///
/// Each file is written with [`WriteTarget::put`], so a file is either complete or
/// not there. The first failure stops the commit. The snapshot header is the last
/// file, so a commit that stops earlier changes nothing that a reader can see.
///
/// The commit needs the writer lock. It writes a new heartbeat first, and again
/// just before the snapshot header, because writing packs can take a long time
/// (format.md 8.6.3). When the lock is lost, it stops and writes no header.
/// `clock` gives the time of this node in milliseconds.
pub async fn commit<T: WriteTarget, R: CryptoRng>(
    lock: &WriterLock<'_, T>,
    credential: &Credential,
    packs: &[BuiltPack],
    header: &SnapshotHeader,
    clock: impl Fn() -> i64,
    rng: &mut R,
) -> Result<(), CommitError> {
    let target = lock.target();
    lock.refresh(clock()).await?;
    // Encode and encrypt the header first: a header that is not valid must not
    // leave packs behind.
    let stored = header.encode().map_err(CommitError::Header)?;
    let file = encrypt(
        &credential.writer().snapshot_header_key(),
        &[],
        &stored,
        rng,
    )
    .map_err(|_| CommitError::Encryption)?;

    for class in [PackClass::Data, PackClass::Metadata] {
        for pack in packs.iter().filter(|pack| pack.class == class) {
            target.put(&pack_path(&pack.name), &pack.bytes).await?;
        }
    }
    lock.refresh(clock()).await?;
    target
        .put(&snapshot_path(&header.snapshot_id), &file)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunking::{ChunkReader, Fixed};
    use crate::lock::WriterLock;
    use crate::pack_builder::PackBuilder;
    use crate::test_util::{Flaky, TestRng, block_on};
    use crate::vault_init::create_vault;
    use nilperit_crypto::RootSeed;
    use nilperit_format::object_type::{CHUNK, CONTENT_OBJECT, DELTA_ENTRY, ITEM_RECORD};
    use nilperit_format::{
        Change, ContentHash, ContentObject, DeltaEntry, ItemKey, ItemRecord, ObjectId, SnapshotId,
        SourceId, VaultEssentials,
    };
    use nilperit_reader::{MemoryTarget, Target, Vault};

    fn seed() -> RootSeed {
        RootSeed::from_bytes([7; 32])
    }

    const SOURCE: SourceId = SourceId::from_bytes([1; 16]);
    const NOW: i64 = 1_700_000_000_000;
    const STALE: i64 = 600_000;

    fn lock<T: WriteTarget>(target: &T) -> WriterLock<'_, T> {
        block_on(WriterLock::acquire(
            target,
            NOW,
            STALE,
            &mut TestRng::new(77),
        ))
        .unwrap()
    }

    /// One commit of a tiny sync: writes the files as items and commits.
    ///
    /// `parent` is the object ID and the sequence number of the previous entry.
    /// Returns the object ID of the new entry.
    fn sync(
        target: &MemoryTarget,
        essentials: &VaultEssentials,
        parent: Option<(ObjectId, u64)>,
        files: &[(&str, &[u8])],
        deleted: &[&str],
        rng: &mut TestRng,
    ) -> ObjectId {
        let credential = Credential::from_seed(&seed());
        let domains = credential.domains();
        let key_of = |native: &str| {
            ItemKey::from_bytes(
                domains
                    .item_key(SOURCE.as_bytes(), native.as_bytes())
                    .unwrap(),
            )
        };
        let mut builder = PackBuilder::new(&credential, PackClass::Data);

        let mut changed = Vec::new();
        for (native, data) in files {
            // Chunks, in order, then the content object that lists them.
            let mut chunk_ids = Vec::new();
            let mut hasher = domains.content_hasher();
            for chunk in ChunkReader::new(*data, Fixed::new(5).unwrap()) {
                let chunk = chunk.unwrap();
                hasher.update(&chunk);
                chunk_ids.push(builder.add(CHUNK, &chunk, true, rng).unwrap());
            }
            let content = ContentObject {
                chunks: chunk_ids,
                size: data.len() as u64,
                content_hash: ContentHash::from_bytes(hasher.finalize()),
                chunking_profile: 1,
            };
            let content_id = builder
                .add(CONTENT_OBJECT, &content.encode().unwrap(), false, rng)
                .unwrap();
            let record = ItemRecord {
                source_id: SOURCE,
                native_id: native.as_bytes().to_vec(),
                title: (*native).into(),
                modified: Some(1_700_000_000_000),
                created: None,
                size: data.len() as u64,
                media_type: Some("text/plain".into()),
                metadata: None,
                content: vec![content_id],
            };
            let record_id = builder
                .add(ITEM_RECORD, &record.encode().unwrap(), true, rng)
                .unwrap();
            changed.push(Change {
                item_key: key_of(native),
                item_record: record_id,
                content: vec![content_id],
            });
        }
        changed.sort_by_key(|change| change.item_key);
        let mut deleted: Vec<ItemKey> = deleted.iter().map(|n| key_of(n)).collect();
        deleted.sort();

        let sequence = parent.map_or(1, |(_, s)| s + 1);
        let snapshot_id = SnapshotId::from_bytes([sequence as u8; 16]);
        let entry = DeltaEntry {
            source_id: SOURCE,
            sequence,
            parent: parent.map(|(id, _)| id),
            snapshot_id,
            time: 1_700_000_000_000 + sequence as i64,
            connector_cursor: Some(vec![sequence as u8]),
            changed,
            deleted,
        };
        let entry_id = builder
            .add(DELTA_ENTRY, &entry.encode().unwrap(), false, rng)
            .unwrap();
        let pack = builder.finish(rng).unwrap();
        let header = SnapshotHeader {
            source_id: SOURCE,
            snapshot_id,
            time: entry.time,
            item_map_root: None,
            parent_snapshot: None,
            journal_entry: entry_id,
            journal_sequence: sequence,
            statistics: None,
            vault: essentials.clone(),
        };
        let lock = lock(target);
        block_on(commit(&lock, &credential, &[pack], &header, || NOW, rng)).unwrap();
        block_on(lock.release()).unwrap();
        entry_id
    }

    /// Reads the vault as a restore would: the state at the head, and the bytes of
    /// each item, by native ID.
    fn read_all(target: &MemoryTarget) -> (u64, Vec<(String, Vec<u8>)>) {
        let vault = block_on(Vault::open(target, &seed())).unwrap();
        let index = block_on(vault.scan_packs()).unwrap();
        assert!(index.skipped().is_empty());
        let snapshots = block_on(vault.read_snapshots()).unwrap();
        assert!(snapshots.skipped().is_empty());
        let head = snapshots.head(&SOURCE).unwrap();
        let state = block_on(vault.replay_journal(&index, head)).unwrap();
        let mut files = Vec::new();
        for (key, item) in &state.items {
            let record = block_on(vault.read_item(&index, key, item)).unwrap();
            let mut data = Vec::new();
            for content in &record.content {
                data.extend(block_on(vault.read_content_to_vec(&index, content)).unwrap());
            }
            assert_eq!(data.len() as u64, record.size);
            files.push((record.title, data));
        }
        files.sort();
        (state.sequence, files)
    }

    fn new_vault(target: &MemoryTarget, rng: &mut TestRng) -> VaultEssentials {
        block_on(create_vault(target, &seed(), rng)).unwrap();
        block_on(Vault::open(target, &seed()))
            .unwrap()
            .config()
            .essentials
            .clone()
    }

    #[test]
    fn writes_files_that_the_reader_reads_back() {
        let target = MemoryTarget::new();
        let mut rng = TestRng::new(1);
        let essentials = new_vault(&target, &mut rng);
        let first = sync(
            &target,
            &essentials,
            None,
            &[
                ("a.txt", b"hello world, hello world"),
                ("b.txt", b"short"),
                ("empty", b""),
            ],
            &[],
            &mut rng,
        );
        let (sequence, files) = read_all(&target);
        assert_eq!(sequence, 1);
        assert_eq!(
            files,
            [
                ("a.txt".to_string(), b"hello world, hello world".to_vec()),
                ("b.txt".to_string(), b"short".to_vec()),
                ("empty".to_string(), Vec::new()),
            ]
        );

        // A second commit changes a file, deletes one, and adds one. The first
        // commit stays in the vault.
        sync(
            &target,
            &essentials,
            Some((first, 1)),
            &[("a.txt", b"hello world, changed"), ("c.txt", b"new file")],
            &["b.txt"],
            &mut rng,
        );
        let (sequence, files) = read_all(&target);
        assert_eq!(sequence, 2);
        assert_eq!(
            files,
            [
                ("a.txt".to_string(), b"hello world, changed".to_vec()),
                ("c.txt".to_string(), b"new file".to_vec()),
                ("empty".to_string(), Vec::new()),
            ]
        );
    }

    /// Packs and a snapshot header for the order tests: two data packs, one metadata
    /// pack, in the order metadata, data, data.
    fn some_packs(
        credential: &Credential,
        essentials: &VaultEssentials,
        rng: &mut TestRng,
    ) -> (Vec<BuiltPack>, SnapshotHeader) {
        let build = |class: PackClass, text: &[u8], rng: &mut TestRng| {
            let mut builder = PackBuilder::new(credential, class);
            builder.add(CHUNK, text, false, rng).unwrap();
            builder.finish(rng).unwrap()
        };
        let packs = vec![
            build(PackClass::Metadata, b"metadata", rng),
            build(PackClass::Data, b"data one", rng),
            build(PackClass::Data, b"data two", rng),
        ];
        let header = SnapshotHeader {
            source_id: SOURCE,
            snapshot_id: SnapshotId::from_bytes([9; 16]),
            time: 1,
            item_map_root: None,
            parent_snapshot: None,
            journal_entry: ObjectId::from_bytes([5; 32]),
            journal_sequence: 1,
            statistics: None,
            vault: essentials.clone(),
        };
        (packs, header)
    }

    #[test]
    fn writes_data_packs_then_metadata_packs_then_the_snapshot_header() {
        let target = MemoryTarget::new();
        let mut rng = TestRng::new(2);
        let essentials = new_vault(&target, &mut rng);
        let credential = Credential::from_seed(&seed());
        let (packs, header) = some_packs(&credential, &essentials, &mut rng);

        let flaky = Flaky::new(&target, 100);
        let held = lock(&flaky);
        block_on(commit(
            &held,
            &credential,
            &packs,
            &header,
            || NOW,
            &mut rng,
        ))
        .unwrap();
        let log = flaky.log.borrow();
        assert_eq!(log.len(), 4);
        assert_eq!(log[0], pack_path(&packs[1].name));
        assert_eq!(log[1], pack_path(&packs[2].name));
        assert_eq!(log[2], pack_path(&packs[0].name));
        assert_eq!(log[3], snapshot_path(&header.snapshot_id));
    }

    #[test]
    fn a_commit_that_stops_changes_nothing_that_a_reader_sees() {
        let credential = Credential::from_seed(&seed());
        // The write that fails can be the first, the second, the third or the
        // snapshot header itself.
        for working_writes in 0..4 {
            let target = MemoryTarget::new();
            let mut rng = TestRng::new(3);
            let essentials = new_vault(&target, &mut rng);
            let (packs, header) = some_packs(&credential, &essentials, &mut rng);

            let flaky = Flaky::new(&target, working_writes);
            let held = lock(&flaky);
            let result = block_on(commit(
                &held,
                &credential,
                &packs,
                &header,
                || NOW,
                &mut rng,
            ));
            assert!(
                matches!(result, Err(CommitError::Target(_))),
                "{working_writes}"
            );

            // No snapshot header: a reader sees no new data.
            let vault = block_on(Vault::open(&target, &seed())).unwrap();
            let snapshots = block_on(vault.read_snapshots()).unwrap();
            assert!(snapshots.headers().is_empty(), "{working_writes}");
            // The packs that were written are orphans: valid, and not an error.
            let index = block_on(vault.scan_packs()).unwrap();
            assert_eq!(index.packs().count(), working_writes, "{working_writes}");
            assert!(index.skipped().is_empty());
        }
    }

    #[test]
    fn a_failed_commit_can_be_repeated() {
        // The next run writes the same packs again and the header. Files that
        // exist are replaced by the same bytes.
        let credential = Credential::from_seed(&seed());
        let target = MemoryTarget::new();
        let mut rng = TestRng::new(4);
        let essentials = new_vault(&target, &mut rng);
        let (packs, header) = some_packs(&credential, &essentials, &mut rng);
        let flaky = Flaky::new(&target, 2);
        let held = lock(&flaky);
        assert!(
            block_on(commit(
                &held,
                &credential,
                &packs,
                &header,
                || NOW,
                &mut rng
            ))
            .is_err()
        );
        // The failed run did not release the lock. The next run starts after the
        // staleness limit and takes it over.
        let later = NOW + STALE + 1;
        let held = block_on(WriterLock::acquire(
            &target,
            later,
            STALE,
            &mut TestRng::new(78),
        ))
        .unwrap();
        block_on(commit(
            &held,
            &credential,
            &packs,
            &header,
            || later,
            &mut rng,
        ))
        .unwrap();
        let vault = block_on(Vault::open(&target, &seed())).unwrap();
        assert_eq!(
            block_on(vault.read_snapshots()).unwrap().headers(),
            [header]
        );
        assert_eq!(block_on(vault.scan_packs()).unwrap().packs().count(), 3);
    }

    #[test]
    fn a_commit_without_the_lock_writes_nothing() {
        let credential = Credential::from_seed(&seed());
        let target = MemoryTarget::new();
        let mut rng = TestRng::new(5);
        let essentials = new_vault(&target, &mut rng);
        let (packs, header) = some_packs(&credential, &essentials, &mut rng);

        // This node pauses. Another node takes over the stale lock.
        let held = lock(&target);
        let later = NOW + STALE + 1;
        let _taken = block_on(WriterLock::acquire(
            &target,
            later,
            STALE,
            &mut TestRng::new(79),
        ))
        .unwrap();

        let result = block_on(commit(
            &held,
            &credential,
            &packs,
            &header,
            || later,
            &mut rng,
        ));
        assert!(matches!(result, Err(CommitError::Lock(LockError::Lost))));
        let vault = block_on(Vault::open(&target, &seed())).unwrap();
        assert_eq!(block_on(vault.scan_packs()).unwrap().packs().count(), 0);
        assert!(
            block_on(vault.read_snapshots())
                .unwrap()
                .headers()
                .is_empty()
        );
    }

    #[test]
    fn a_commit_writes_new_heartbeats() {
        use nilperit_format::LockFile;
        use nilperit_reader::layout::LOCK_PATH;
        let credential = Credential::from_seed(&seed());
        let target = MemoryTarget::new();
        let mut rng = TestRng::new(6);
        let essentials = new_vault(&target, &mut rng);
        let (packs, header) = some_packs(&credential, &essentials, &mut rng);
        let held = lock(&target);
        block_on(commit(
            &held,
            &credential,
            &packs,
            &header,
            || NOW + 5_000,
            &mut rng,
        ))
        .unwrap();
        let file = LockFile::decode(&block_on(target.read(LOCK_PATH)).unwrap()).unwrap();
        assert_eq!(file.holder_id, held.holder_id());
        assert_eq!(file.heartbeat, NOW + 5_000);
    }
}
