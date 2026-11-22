//! The sync engine: one run of a source into a vault.
//!
//! A run reads the state of the source from the journal, asks the connector what
//! the source has, writes what the vault does not have yet, and commits. It works
//! with the node credential only, so it never reads an item record or a chunk
//! (ADR 0004). It finds out what the vault already holds from the journal and from
//! the object tables of the packs, which are W objects.
//!
//! A run is safe to repeat. It compares with the state that the journal gives, so
//! a run that stopped can be started again, and it continues with what is missing.

use crate::chunking::{CHUNKING_PROFILE_DEFAULT, ChunkReader, ChunkerError, Fixed};
use crate::commit::{CommitError, commit};
use crate::connector::{Changes, Connector, ConnectorError, SourceItem};
use crate::credential::Credential;
use crate::lock::{LockError, WriterLock};
use crate::pack_builder::{BuildError, BuiltPack, PackBuilder};
use crate::target::WriteTarget;
use nilperit_crypto::{CryptoRng, SizeError};
use nilperit_format::object_type::{CHUNK, CONTENT_OBJECT, DELTA_ENTRY, ITEM_RECORD};
use nilperit_format::{
    Change, ContentHash, ContentObject, DeltaEntry, ItemKey, ItemRecord, ObjectError, ObjectId,
    PackClass, SnapshotHeader, SnapshotId, SourceId,
};
use nilperit_reader::TargetError;
use nilperit_reader::{JournalError, PackIndex, Vault, VaultError};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;

/// The settings of a run.
#[derive(Clone, Debug)]
pub struct SyncOptions {
    /// The ID of the chunking profile that the run uses (format.md 5.2). It must be in
    /// the vault config.
    pub chunking_profile: u32,
    /// The size at which a pack is closed, in bytes (format.md 6.1).
    pub pack_size: usize,
    /// The size of new data after which the run commits, in bytes (format.md 8.4).
    /// A run that stops loses at most this much work. The data waits in memory.
    pub commit_size: u64,
    /// Whether to try to compress objects (format.md 6.6.5). The result is kept
    /// only when it is smaller.
    pub compress: bool,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            chunking_profile: CHUNKING_PROFILE_DEFAULT,
            pack_size: 16 * 1024 * 1024,
            commit_size: 256 * 1024 * 1024,
            compress: true,
        }
    }
}

/// An item that the engine could not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailedItem {
    /// The native ID of the item. It is the connector's name for the item, so
    /// a caller must show it only as direct output to the person (AGENTS.md).
    pub native_id: Vec<u8>,
    /// What kind of failure it was. The engine keeps no more than that: the text
    /// of an I/O error can contain a file name.
    pub kind: io::ErrorKind,
}

/// What a run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// How many commits the run made. It is 0 when there was nothing to write.
    pub commits: u32,
    /// Items that the vault did not have.
    pub items_new: u64,
    /// Items that the vault had in another version.
    pub items_changed: u64,
    /// Items that the vault had in the same version.
    pub items_unchanged: u64,
    /// Items that the source no longer has.
    pub items_deleted: u64,
    /// Items that could not be read. They stay as they are in the vault.
    pub failed: Vec<FailedItem>,
    /// Chunks that the run wrote.
    pub chunks_written: u64,
    /// Chunks that the vault had already.
    pub chunks_existing: u64,
    /// The number of bytes that the run read from the source.
    pub bytes_read: u64,
    /// The number of bytes of packs that the run wrote.
    pub bytes_written: u64,
}

/// A run failed. A run that fails after a commit keeps that commit: the vault is
/// in the state of the last commit and a new run continues from there.
#[derive(Debug)]
pub enum SyncError {
    /// The vault cannot be opened.
    Vault(VaultError),
    /// The target failed.
    Target(TargetError),
    /// The journal cannot be replayed.
    Journal(JournalError),
    /// The connector failed.
    Connector(ConnectorError),
    /// The chunking profile is not in the vault config, or this writer cannot use it.
    ChunkingProfile(u32, Option<ChunkerError>),
    /// A pack cannot be built.
    Build(BuildError),
    /// A commit failed.
    Commit(CommitError),
    /// The writer lock is lost.
    Lock(LockError),
    /// An object cannot be encoded.
    Encode(ObjectError),
    /// A native ID is too large for an item key.
    Size(SizeError),
    /// An item has a native ID of no bytes.
    EmptyNativeId,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(e) => write!(f, "the vault cannot be opened: {e}"),
            Self::Target(e) => e.fmt(f),
            Self::Journal(e) => write!(f, "the journal cannot be read: {e}"),
            Self::Connector(e) => e.fmt(f),
            Self::ChunkingProfile(id, None) => {
                write!(f, "chunking profile {id} is not in the vault config")
            }
            Self::ChunkingProfile(id, Some(e)) => {
                write!(f, "chunking profile {id} cannot be used: {e}")
            }
            Self::Build(e) => e.fmt(f),
            Self::Commit(e) => e.fmt(f),
            Self::Lock(e) => e.fmt(f),
            Self::Encode(e) => write!(f, "an object cannot be encoded: {e}"),
            Self::Size(e) => e.fmt(f),
            Self::EmptyNativeId => f.write_str("an item has an empty native ID"),
        }
    }
}

impl std::error::Error for SyncError {}

macro_rules! from {
    ($($from:ty => $variant:ident),* $(,)?) => {$(
        impl From<$from> for SyncError {
            fn from(e: $from) -> Self {
                Self::$variant(e)
            }
        }
    )*};
}

from! {
    VaultError => Vault,
    TargetError => Target,
    JournalError => Journal,
    ConnectorError => Connector,
    BuildError => Build,
    CommitError => Commit,
    LockError => Lock,
    ObjectError => Encode,
    SizeError => Size,
}

/// The source ID of a source with this name (format.md 5.4.5.1). The name has at
/// least 1 byte.
pub fn source_id(credential: &Credential, name: &str) -> Option<SourceId> {
    (!name.is_empty())
        .then(|| SourceId::from_bytes(credential.domains().source_id(name.as_bytes())))
}

/// The newest committed entry of the journal of the source.
#[derive(Clone, Copy)]
struct Head {
    entry: ObjectId,
    sequence: u64,
    snapshot: SnapshotId,
}

/// What the engine made of one item.
struct Prepared {
    change: Change,
    content: Vec<ObjectId>,
}

/// Runs a source into the vault.
///
/// `lock` is the writer lock that the caller holds. `clock` gives the time of this
/// node in milliseconds. The run commits at intervals and at the end.
///
/// The run does not delete anything, and it does not change a stored file: it only
/// adds packs, snapshot headers and the heartbeat of the lock.
pub async fn sync<T: WriteTarget, C: Connector, R: CryptoRng>(
    lock: &WriterLock<'_, T>,
    credential: &Credential,
    source: SourceId,
    connector: &mut C,
    options: &SyncOptions,
    clock: impl Fn() -> i64,
    rng: &mut R,
) -> Result<SyncReport, SyncError> {
    // What the vault holds now.
    let vault = Vault::open_with(lock.target(), credential.reader_keys()).await?;
    let index = vault.scan_packs().await?;
    let snapshots = vault.read_snapshots().await?;
    let chunking_profile = vault
        .config()
        .chunking_profiles
        .iter()
        .find(|p| p.id == options.chunking_profile)
        .ok_or(SyncError::ChunkingProfile(options.chunking_profile, None))?;
    let chunker = Fixed::from_profile(chunking_profile)
        .map_err(|e| SyncError::ChunkingProfile(options.chunking_profile, Some(e)))?;

    let (state, head) = match snapshots.head(&source) {
        Some(header) => {
            let state = vault.replay_journal(&index, header).await?;
            let head = Head {
                entry: header.journal_entry,
                sequence: header.journal_sequence,
                snapshot: header.snapshot_id,
            };
            (Some(state), Some(head))
        }
        None => (None, None),
    };
    let known_items: BTreeMap<ItemKey, (ObjectId, Vec<ObjectId>)> = state
        .as_ref()
        .map(|s| {
            s.items
                .iter()
                .map(|(key, item)| (*key, (item.item_record, item.content.clone())))
                .collect()
        })
        .unwrap_or_default();
    let start_cursor = state.as_ref().and_then(|s| s.connector_cursor.clone());

    // What the source has.
    let Changes {
        complete,
        items,
        deleted,
        cursor,
    } = connector.changes(start_cursor.as_deref()).await?;

    let mut session = Session {
        lock,
        credential,
        vault: &vault,
        index: &index,
        source,
        options,
        clock: &clock,
        rng,
        chunker,
        builder: PackBuilder::new(credential, PackClass::Data),
        packs: Vec::new(),
        new_ids: BTreeSet::new(),
        pending: Vec::new(),
        head,
        stored_cursor: start_cursor.clone(),
        report: SyncReport::default(),
    };

    let mut seen: BTreeSet<ItemKey> = BTreeSet::new();
    for item in items {
        if item.native_id.is_empty() {
            return Err(SyncError::EmptyNativeId);
        }
        let key = ItemKey::from_bytes(
            credential
                .domains()
                .item_key(source.as_bytes(), &item.native_id)?,
        );
        // An item that occurs twice is read once. The second one is reported.
        if !seen.insert(key) {
            session.report.failed.push(FailedItem {
                native_id: item.native_id,
                kind: io::ErrorKind::InvalidInput,
            });
            continue;
        }
        let native_id = item.native_id.clone();
        match session.prepare(key, item).await? {
            Ok(prepared) => match known_items.get(&key) {
                Some((record, content))
                    if *record == prepared.change.item_record && *content == prepared.content =>
                {
                    session.report.items_unchanged += 1;
                }
                Some(_) => {
                    session.report.items_changed += 1;
                    session.pending.push(prepared.change);
                }
                None => {
                    session.report.items_new += 1;
                    session.pending.push(prepared.change);
                }
            },
            // An item that cannot be read stays as it is in the vault: it is not
            // deleted.
            Err(kind) => session.report.failed.push(FailedItem { native_id, kind }),
        }
        if session.pending_bytes() >= options.commit_size && !session.pending.is_empty() {
            session
                .commit(Vec::new(), session.stored_cursor.clone())
                .await?;
        }
    }

    // The items that the source no longer has.
    let mut gone: BTreeSet<ItemKey> = BTreeSet::new();
    if complete {
        gone.extend(known_items.keys().filter(|key| !seen.contains(key)));
    } else {
        for native_id in &deleted {
            let key = ItemKey::from_bytes(
                credential
                    .domains()
                    .item_key(source.as_bytes(), native_id)?,
            );
            if known_items.contains_key(&key) {
                gone.insert(key);
            }
        }
    }
    session.report.items_deleted = gone.len() as u64;

    // The last commit. The first run always commits, so that the source exists in
    // the vault, also when it is empty.
    let cursor_changed = cursor != session.stored_cursor;
    if session.head.is_none() || !session.pending.is_empty() || !gone.is_empty() || cursor_changed {
        session.commit(gone.into_iter().collect(), cursor).await?;
    }
    Ok(session.report)
}

/// The state of one run.
struct Session<'a, T: WriteTarget, R> {
    lock: &'a WriterLock<'a, T>,
    credential: &'a Credential,
    vault: &'a Vault<&'a T>,
    index: &'a PackIndex,
    source: SourceId,
    options: &'a SyncOptions,
    clock: &'a dyn Fn() -> i64,
    rng: &'a mut R,
    chunker: Fixed,
    builder: PackBuilder<'a>,
    /// Packs that are closed and not committed yet.
    packs: Vec<BuiltPack>,
    /// The objects that this run added. The index shows only what the vault had
    /// when the run began.
    new_ids: BTreeSet<ObjectId>,
    /// The changes since the last commit.
    pending: Vec<Change>,
    head: Option<Head>,
    /// The cursor that the last commit stored.
    stored_cursor: Option<Vec<u8>>,
    report: SyncReport,
}

impl<'a, T: WriteTarget, R: CryptoRng> Session<'a, T, R> {
    /// The size of the data that waits for a commit.
    fn pending_bytes(&self) -> u64 {
        let closed: usize = self.packs.iter().map(|pack| pack.bytes.len()).sum();
        (closed + self.builder.len()) as u64
    }

    /// Adds an object that the vault does not have yet, and returns its ID. The
    /// object ID needs the dedup key, which the node has.
    async fn add(&mut self, object_type: u32, stored: &[u8]) -> Result<ObjectId, SyncError> {
        let id = ObjectId::from_bytes(self.credential.domains().object_id(object_type, stored));
        if self.index.contains(&id) || self.new_ids.contains(&id) {
            if object_type == CHUNK {
                self.report.chunks_existing += 1;
            }
            return Ok(id);
        }
        self.builder
            .add(object_type, stored, self.options.compress, self.rng)?;
        self.new_ids.insert(id);
        if object_type == CHUNK {
            self.report.chunks_written += 1;
        }
        if self.builder.len() >= self.options.pack_size {
            self.close_pack().await?;
        }
        Ok(id)
    }

    /// Closes the pack that the run is building. A long run keeps its lock alive
    /// here (format.md 8.6.3).
    async fn close_pack(&mut self) -> Result<(), SyncError> {
        let builder = std::mem::replace(
            &mut self.builder,
            PackBuilder::new(self.credential, PackClass::Data),
        );
        if !builder.is_empty() {
            let pack = builder.finish(self.rng)?;
            self.report.bytes_written += pack.bytes.len() as u64;
            self.packs.push(pack);
        }
        self.lock.refresh((self.clock)()).await?;
        Ok(())
    }

    /// Reads one item and adds its objects. An error of the source is the inner
    /// result: the item is skipped. An error of the vault stops the run.
    async fn prepare(
        &mut self,
        key: ItemKey,
        item: SourceItem,
    ) -> Result<Result<Prepared, io::ErrorKind>, SyncError> {
        let SourceItem {
            native_id,
            title,
            modified,
            created,
            media_type,
            metadata,
            contents,
        } = item;
        let mut content_ids = Vec::new();
        let mut total: u64 = 0;
        for open in contents {
            let reader = match open() {
                Ok(reader) => reader,
                Err(e) => return Ok(Err(e.kind())),
            };
            let mut hasher = self.credential.domains().content_hasher();
            let mut chunk_ids = Vec::new();
            let mut size: u64 = 0;
            for chunk in ChunkReader::new(reader, self.chunker) {
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(e) => return Ok(Err(e.kind())),
                };
                size += chunk.len() as u64;
                hasher.update(&chunk);
                chunk_ids.push(self.add(CHUNK, &chunk).await?);
            }
            self.report.bytes_read += size;
            total += size;
            let content = ContentObject {
                chunks: chunk_ids,
                size,
                content_hash: ContentHash::from_bytes(hasher.finalize()),
                chunking_profile: self.options.chunking_profile,
            };
            content_ids.push(self.add(CONTENT_OBJECT, &content.encode()?).await?);
        }
        let record = ItemRecord {
            source_id: self.source,
            native_id,
            title,
            modified,
            created,
            size: total,
            media_type,
            metadata,
            content: content_ids.clone(),
        };
        let item_record = self.add(ITEM_RECORD, &record.encode()?).await?;
        Ok(Ok(Prepared {
            change: Change {
                item_key: key,
                item_record,
                content: content_ids.clone(),
            },
            content: content_ids,
        }))
    }

    /// Commits what the run has: the packs, a delta entry, and a snapshot header.
    async fn commit(
        &mut self,
        mut deleted: Vec<ItemKey>,
        cursor: Option<Vec<u8>>,
    ) -> Result<(), SyncError> {
        let mut changed = std::mem::take(&mut self.pending);
        changed.sort_by_key(|change| change.item_key);
        deleted.sort();

        let mut snapshot_bytes = [0u8; 16];
        self.rng.fill_bytes(&mut snapshot_bytes);
        let snapshot_id = SnapshotId::from_bytes(snapshot_bytes);
        let time = (self.clock)();
        let sequence = self.head.map_or(1, |head| head.sequence + 1);
        let entry = DeltaEntry {
            source_id: self.source,
            sequence,
            parent: self.head.map(|head| head.entry),
            snapshot_id,
            time,
            connector_cursor: cursor.clone(),
            changed,
            deleted,
        };
        let entry_id = self.add(DELTA_ENTRY, &entry.encode()?).await?;
        self.close_pack().await?;

        let header = SnapshotHeader {
            source_id: self.source,
            snapshot_id,
            time,
            item_map_root: None,
            parent_snapshot: self.head.map(|head| head.snapshot),
            journal_entry: entry_id,
            journal_sequence: sequence,
            statistics: None,
            vault: self.vault.config().essentials.clone(),
        };
        commit(
            self.lock,
            self.credential,
            &self.packs,
            &header,
            self.clock,
            self.rng,
        )
        .await?;
        self.packs.clear();
        self.head = Some(Head {
            entry: entry_id,
            sequence,
            snapshot: snapshot_id,
        });
        self.stored_cursor = cursor;
        self.report.commits += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::{Changes, Connector, ConnectorError};
    use crate::test_util::{Flaky, ListConnector, TestRng, block_on, read_state};
    use crate::vault_init::create_vault;
    use nilperit_crypto::RootSeed;
    use nilperit_reader::layout::LOCK_PATH;
    use nilperit_reader::{MemoryTarget, Target};

    const NOW: i64 = 1_700_000_000_000;
    const STALE: i64 = 600_000;

    fn seed() -> RootSeed {
        RootSeed::from_bytes([7; 32])
    }

    /// A vault, the credential of its node, and a source.
    fn setup() -> (MemoryTarget, Credential, SourceId) {
        let target = MemoryTarget::new();
        block_on(create_vault(&target, &seed(), &mut TestRng::new(1))).unwrap();
        let credential = Credential::from_seed(&seed());
        let source = source_id(&credential, "test").unwrap();
        (target, credential, source)
    }

    /// Takes the lock, runs the engine, and releases the lock.
    fn run<T: WriteTarget>(
        target: &T,
        credential: &Credential,
        source: SourceId,
        connector: &mut impl Connector,
        options: &SyncOptions,
        rng_seed: u64,
    ) -> Result<SyncReport, SyncError> {
        let mut rng = TestRng::new(rng_seed);
        let lock = block_on(WriterLock::acquire(target, NOW, STALE, &mut rng)).unwrap();
        let report = block_on(sync(
            &lock,
            credential,
            source,
            connector,
            options,
            || NOW,
            &mut rng,
        ));
        let _ = block_on(lock.release());
        report
    }

    fn run_default(
        target: &MemoryTarget,
        credential: &Credential,
        source: SourceId,
        connector: &mut impl Connector,
    ) -> SyncReport {
        run(
            target,
            credential,
            source,
            connector,
            &SyncOptions::default(),
            5,
        )
        .unwrap()
    }

    /// Bytes that differ from every other `seed`, and are `length` long.
    fn data(seed: u8, length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| {
                (i as u8)
                    .wrapping_mul(31)
                    .wrapping_add(seed)
                    .wrapping_add((i / 251) as u8)
            })
            .collect()
    }

    fn store_listing(target: &MemoryTarget) -> Vec<String> {
        let mut all = block_on(target.list("packs")).unwrap();
        all.extend(block_on(target.list("snapshots")).unwrap());
        all.sort();
        all
    }

    #[test]
    fn a_source_id_comes_from_the_name() {
        let credential = Credential::from_seed(&seed());
        let a = source_id(&credential, "photos").unwrap();
        assert_eq!(a, source_id(&credential, "photos").unwrap());
        assert_ne!(a, source_id(&credential, "Photos").unwrap());
        assert!(source_id(&credential, "").is_none());
    }

    #[test]
    fn the_first_run_writes_everything_and_the_reader_reads_it_back() {
        let (target, credential, source) = setup();
        let big = data(1, 600_000); // three chunks
        let mut connector = ListConnector::new(&[
            ("docs/a.bin", &big),
            ("docs/b.txt", b"short"),
            ("empty", b""),
        ]);
        let report = run_default(&target, &credential, source, &mut connector);
        assert_eq!(report.commits, 1);
        assert_eq!(
            (
                report.items_new,
                report.items_changed,
                report.items_unchanged
            ),
            (3, 0, 0)
        );
        assert_eq!(report.items_deleted, 0);
        assert!(report.failed.is_empty());
        assert_eq!(report.chunks_written, 4);
        assert_eq!(report.bytes_read, 600_005);
        assert!(report.bytes_written > 0);

        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.sequence, 1);
        assert_eq!(
            state.files,
            [
                ("docs/a.bin".to_string(), big),
                ("docs/b.txt".to_string(), b"short".to_vec()),
                ("empty".to_string(), Vec::new()),
            ]
        );
    }

    #[test]
    fn a_second_run_without_changes_writes_nothing() {
        let (target, credential, source) = setup();
        let big = data(2, 300_000);
        let items: &[(&str, &[u8])] = &[("a", &big), ("b", b"x")];
        run_default(&target, &credential, source, &mut ListConnector::new(items));
        let before = store_listing(&target);

        let report = run_default(&target, &credential, source, &mut ListConnector::new(items));
        assert_eq!(report.commits, 0);
        assert_eq!(
            (
                report.items_unchanged,
                report.items_new,
                report.items_changed
            ),
            (2, 0, 0)
        );
        assert_eq!(report.chunks_written, 0);
        assert_eq!(report.bytes_written, 0);
        assert_eq!(store_listing(&target), before);
        assert_eq!(read_state(&target, &seed(), &source).unwrap().sequence, 1);
    }

    #[test]
    fn changed_new_and_deleted_items_and_the_chunks_that_exist() {
        let (target, credential, source) = setup();
        let big = data(3, 600_000);
        run_default(
            &target,
            &credential,
            source,
            &mut ListConnector::new(&[("a", &big), ("b", b"bee"), ("keep", b"kept")]),
        );

        // `a` changes in its last chunk only, `b` is gone, `c` is new.
        let mut changed = big.clone();
        let last = changed.len() - 1;
        changed[last] ^= 0xff;
        let report = run_default(
            &target,
            &credential,
            source,
            &mut ListConnector::new(&[("a", &changed), ("c", b"sea"), ("keep", b"kept")]),
        );
        assert_eq!(report.commits, 1);
        assert_eq!(
            (
                report.items_new,
                report.items_changed,
                report.items_unchanged,
                report.items_deleted
            ),
            (1, 1, 1, 1)
        );
        // Two chunks of `a` and the chunks of `keep` exist. One chunk of `a` and the
        // chunk of `c` are new.
        assert_eq!(report.chunks_existing, 3);
        assert_eq!(report.chunks_written, 2);

        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.sequence, 2);
        assert_eq!(
            state.files,
            [
                ("a".to_string(), changed),
                ("c".to_string(), b"sea".to_vec()),
                ("keep".to_string(), b"kept".to_vec()),
            ]
        );
    }

    #[test]
    fn equal_content_is_stored_once() {
        let (target, credential, source) = setup();
        let big = data(4, 300_000);
        let report = run_default(
            &target,
            &credential,
            source,
            &mut ListConnector::new(&[("one", &big), ("two", &big), ("three", &big)]),
        );
        // Two chunks of 256 KiB and 43 KiB, stored once for three items.
        assert_eq!(report.chunks_written, 2);
        assert_eq!(report.chunks_existing, 4);
        assert_eq!(
            read_state(&target, &seed(), &source).unwrap().files.len(),
            3
        );
    }

    #[test]
    fn an_empty_source_still_makes_the_source_exist() {
        let (target, credential, source) = setup();
        let report = run_default(&target, &credential, source, &mut ListConnector::new(&[]));
        assert_eq!(report.commits, 1);
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.sequence, 1);
        assert!(state.files.is_empty());
        // The second run has nothing to write.
        let report = run_default(&target, &credential, source, &mut ListConnector::new(&[]));
        assert_eq!(report.commits, 0);
    }

    #[test]
    fn another_source_has_its_own_journal() {
        let (target, credential, source) = setup();
        let other = source_id(&credential, "other").unwrap();
        run_default(
            &target,
            &credential,
            source,
            &mut ListConnector::new(&[("a", b"1")]),
        );
        run_default(
            &target,
            &credential,
            other,
            &mut ListConnector::new(&[("b", b"2"), ("c", b"3")]),
        );
        let a = read_state(&target, &seed(), &source).unwrap();
        let b = read_state(&target, &seed(), &other).unwrap();
        assert_eq!((a.sequence, a.files.len()), (1, 1));
        assert_eq!((b.sequence, b.files.len()), (1, 2));
    }

    #[test]
    fn a_connector_with_a_cursor_reports_changes_and_deletions() {
        let (target, credential, source) = setup();
        let mut connector = ListConnector::new(&[("a", b"first"), ("b", b"second")]);
        connector.cursor = Some(vec![1]);
        run_default(&target, &credential, source, &mut connector);

        // The next run: `b` changed, `a` was deleted, nothing else is reported.
        let mut connector = ListConnector::new(&[("b", b"second, changed")]);
        connector.complete = false;
        connector.deleted = vec!["a".into(), "never-there".into()];
        connector.cursor = Some(vec![2]);
        let report = run_default(&target, &credential, source, &mut connector);
        // The connector got the cursor of the last commit.
        assert_eq!(connector.received, [Some(vec![1])]);
        assert_eq!(
            (report.items_changed, report.items_deleted, report.items_new),
            (1, 1, 0)
        );

        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.cursor, Some(vec![2]));
        assert_eq!(
            state.files,
            [("b".to_string(), b"second, changed".to_vec())]
        );
    }

    #[test]
    fn a_new_cursor_alone_is_a_commit() {
        let (target, credential, source) = setup();
        let mut connector = ListConnector::new(&[("a", b"x")]);
        connector.cursor = Some(vec![1]);
        run_default(&target, &credential, source, &mut connector);
        connector.cursor = Some(vec![2]);
        let report = run_default(&target, &credential, source, &mut connector);
        assert_eq!((report.commits, report.items_unchanged), (1, 1));
        assert_eq!(
            read_state(&target, &seed(), &source).unwrap().cursor,
            Some(vec![2])
        );
        // The same cursor again: nothing to write.
        assert_eq!(
            run_default(&target, &credential, source, &mut connector).commits,
            0
        );
    }

    #[test]
    fn an_item_that_cannot_be_read_is_reported_and_never_deleted() {
        let (target, credential, source) = setup();
        run_default(
            &target,
            &credential,
            source,
            &mut ListConnector::new(&[("locked", b"old"), ("plain", b"p")]),
        );
        let mut connector = ListConnector::new(&[("plain", b"p changed"), ("new-locked", b"")]);
        connector
            .items
            .push(("locked".into(), Err(io::ErrorKind::PermissionDenied)));
        connector.items[1].1 = Err(io::ErrorKind::PermissionDenied);
        let report = run_default(&target, &credential, source, &mut connector);

        assert_eq!(report.items_changed, 1);
        assert_eq!(report.items_deleted, 0);
        assert_eq!(
            report.failed,
            [
                FailedItem {
                    native_id: b"new-locked".to_vec(),
                    kind: io::ErrorKind::PermissionDenied
                },
                FailedItem {
                    native_id: b"locked".to_vec(),
                    kind: io::ErrorKind::PermissionDenied
                },
            ]
        );
        // The unreadable item that the vault had stays as it was.
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(
            state.files,
            [
                ("locked".to_string(), b"old".to_vec()),
                ("plain".to_string(), b"p changed".to_vec()),
            ]
        );
    }

    #[test]
    fn an_item_that_occurs_twice_is_read_once_and_reported() {
        let (target, credential, source) = setup();
        let mut connector = ListConnector::new(&[("a", b"first"), ("a", b"second")]);
        let report = run_default(&target, &credential, source, &mut connector);
        assert_eq!(report.items_new, 1);
        assert_eq!(report.failed.len(), 1);
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.files, [("a".to_string(), b"first".to_vec())]);
    }

    #[test]
    fn an_item_without_a_native_id_stops_the_run() {
        let (target, credential, source) = setup();
        let mut connector = ListConnector::new(&[("", b"x")]);
        let result = run(
            &target,
            &credential,
            source,
            &mut connector,
            &SyncOptions::default(),
            5,
        );
        assert!(matches!(result, Err(SyncError::EmptyNativeId)));
        assert!(read_state(&target, &seed(), &source).is_none());
    }

    #[test]
    fn rejects_a_chunking_profile_that_the_vault_does_not_have() {
        let (target, credential, source) = setup();
        let options = SyncOptions {
            chunking_profile: 99,
            ..SyncOptions::default()
        };
        let mut connector = ListConnector::new(&[("a", b"x")]);
        let result = run(&target, &credential, source, &mut connector, &options, 5);
        assert!(matches!(result, Err(SyncError::ChunkingProfile(99, None))));
        // The large chunking profile is in a new vault.
        let options = SyncOptions {
            chunking_profile: 2,
            ..SyncOptions::default()
        };
        let report = run(&target, &credential, source, &mut connector, &options, 5).unwrap();
        assert_eq!(report.items_new, 1);
    }

    /// The failure of a source stops the run before anything is written.
    struct Broken;

    impl Connector for Broken {
        async fn changes(&mut self, _: Option<&[u8]>) -> Result<Changes, ConnectorError> {
            Err(ConnectorError::Failed("the source is down".into()))
        }
    }

    #[test]
    fn a_source_that_fails_changes_nothing() {
        let (target, credential, source) = setup();
        let before = store_listing(&target);
        let result = run(
            &target,
            &credential,
            source,
            &mut Broken,
            &SyncOptions::default(),
            5,
        );
        assert!(matches!(result, Err(SyncError::Connector(_))));
        assert_eq!(store_listing(&target), before);
    }

    #[test]
    fn commits_at_intervals_and_stores_the_cursor_only_in_the_last_commit() {
        let (target, credential, source) = setup();
        let items: Vec<(String, Vec<u8>)> = (0..4)
            .map(|i| (format!("file-{i}"), data(10 + i, 300_000)))
            .collect();
        let list: Vec<(&str, &[u8])> = items
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let mut connector = ListConnector::new(&list);
        connector.cursor = Some(vec![9]);
        let options = SyncOptions {
            commit_size: 1,
            pack_size: 100_000,
            ..SyncOptions::default()
        };
        let report = run(&target, &credential, source, &mut connector, &options, 5).unwrap();
        // One commit for each item, and the last one carries the cursor.
        assert_eq!(report.commits, 5);
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.sequence, 5);
        assert_eq!(state.cursor, Some(vec![9]));
        assert_eq!(state.files.len(), 4);
    }

    #[test]
    fn a_run_that_stops_at_any_write_can_be_repeated() {
        // Count the writes of a whole run.
        let items: Vec<(String, Vec<u8>)> = (0..3)
            .map(|i| (format!("file-{i}"), data(20 + i, 300_000)))
            .collect();
        let list: Vec<(&str, &[u8])> = items
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let options = SyncOptions {
            commit_size: 1,
            pack_size: 200_000,
            ..SyncOptions::default()
        };
        let (target, credential, source) = setup();
        let flaky = Flaky::new(&target, usize::MAX);
        let mut connector = ListConnector::new(&list);
        connector.cursor = Some(vec![5]);
        run(&flaky, &credential, source, &mut connector, &options, 5).unwrap();
        let total = flaky.log.borrow().len();
        // One commit for each item and a last one for the cursor, with a pack and a
        // snapshot header each.
        assert_eq!(total, 8);

        // Stop the run at every write. The vault still opens and shows the last
        // commit. A new run completes it.
        for working_writes in 0..total {
            let (target, credential, source) = setup();
            let flaky = Flaky::new(&target, working_writes);
            let mut connector = ListConnector::new(&list);
            connector.cursor = Some(vec![5]);
            let result = run(&flaky, &credential, source, &mut connector, &options, 5);
            assert!(result.is_err(), "stopped after {working_writes} writes");

            // The state is a whole number of commits: every item that it shows is
            // complete.
            if let Some(partial) = read_state(&target, &seed(), &source) {
                assert!(partial.files.len() <= 3);
                for (title, bytes) in &partial.files {
                    let original = items.iter().find(|(n, _)| n == title).unwrap();
                    assert_eq!(*bytes, original.1);
                }
            }

            // The lock of the failed run is stale. The new run starts later.
            let mut connector = ListConnector::new(&list);
            connector.cursor = Some(vec![5]);
            let mut rng = TestRng::new(6);
            let later = NOW + STALE + 1;
            let lock = block_on(WriterLock::acquire(&target, later, STALE, &mut rng)).unwrap();
            let report = block_on(sync(
                &lock,
                &credential,
                source,
                &mut connector,
                &options,
                || later,
                &mut rng,
            ))
            .unwrap();
            assert!(report.commits >= 1 || working_writes == total);
            let state = read_state(&target, &seed(), &source).unwrap();
            assert_eq!(
                state.files.len(),
                3,
                "stopped after {working_writes} writes"
            );
            assert_eq!(state.cursor, Some(vec![5]));
            for (title, bytes) in &state.files {
                let original = items.iter().find(|(n, _)| n == title).unwrap();
                assert_eq!(*bytes, original.1);
            }
        }
    }

    /// A source that takes the lock from the node while the node works.
    struct Thief<'a> {
        target: &'a MemoryTarget,
    }

    impl Connector for Thief<'_> {
        async fn changes(&mut self, _: Option<&[u8]>) -> Result<Changes, ConnectorError> {
            let other = nilperit_format::LockFile {
                holder_id: nilperit_format::HolderId::from_bytes([0xee; 16]),
                heartbeat: NOW + 1,
            };
            self.target.insert(LOCK_PATH, other.encode());
            ListConnector::new(&[("a", b"x")]).changes(None).await
        }
    }

    #[test]
    fn a_node_that_lost_the_lock_commits_nothing() {
        let (target, credential, source) = setup();
        let before = store_listing(&target);
        let result = run(
            &target,
            &credential,
            source,
            &mut Thief { target: &target },
            &SyncOptions::default(),
            5,
        );
        assert!(matches!(
            result,
            Err(SyncError::Lock(LockError::Lost)
                | SyncError::Commit(CommitError::Lock(LockError::Lost)))
        ));
        assert_eq!(store_listing(&target), before);
    }
}
