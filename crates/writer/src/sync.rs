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
use crate::progress::{Counts, Progress};
use crate::target::WriteTarget;
use nilperit_crypto::{CryptoRng, SizeError};
use nilperit_format::MAX_OBJECT_SIZE;
use nilperit_format::object_type::{CHUNK, CONTENT_OBJECT, DELTA_ENTRY, ITEM_RECORD};
use nilperit_format::pack::PACKED_OBJECT_OVERHEAD;
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
    /// The size of the delta entry after which the run commits, in bytes (format.md 5.5.2). The
    /// entry has a record for every item that changed since the last commit, and an object is at
    /// most 1 GiB (format.md 6.7.6): a run that commits only by the size of the data would fail
    /// when it has many small items. The size is an estimate of the encoded size, which is a
    /// little more than the real size. The value must be far below the limit of an object.
    pub commit_entry_size: usize,
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
            commit_entry_size: 64 * 1024 * 1024,
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
    sync_with_progress(
        lock,
        credential,
        source,
        connector,
        options,
        clock,
        rng,
        &mut |_| {},
    )
    .await
}

/// Runs a source into the vault, and tells `progress` what the run is doing. The same
/// as [`sync`] in every other way.
///
/// The callback runs on the thread of the run, after every chunk, so it must be quick.
/// A report has numbers only, never a name or content (see [`Progress`]).
// A function with the callback as the eighth argument is clearer than a struct that
// only holds the arguments of this one function.
#[allow(clippy::too_many_arguments)]
pub async fn sync_with_progress<T: WriteTarget, C: Connector, R: CryptoRng>(
    lock: &WriterLock<'_, T>,
    credential: &Credential,
    source: SourceId,
    connector: &mut C,
    options: &SyncOptions,
    clock: impl Fn() -> i64,
    rng: &mut R,
    progress: &mut dyn FnMut(Progress),
) -> Result<SyncReport, SyncError> {
    // What the vault holds now.
    progress(Progress::OpeningVault);
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
            progress(Progress::ReplayingJournal);
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
    progress(Progress::ReadingSource);
    let Changes {
        complete,
        items,
        deleted,
        cursor,
    } = connector.changes(start_cursor.as_deref()).await?;

    let bytes_total = items
        .iter()
        .try_fold(0u64, |sum, item| Some(sum.saturating_add(item.size?)));
    let mut session = Session {
        progress,
        counts: Counts {
            items_done: 0,
            items_total: items.len() as u64,
            bytes_done: 0,
            bytes_total,
        },
        item_bytes: 0,
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
        pending_entry_size: 0,
        head,
        stored_cursor: start_cursor.clone(),
        report: SyncReport::default(),
    };

    session.tell(false);
    let mut seen: BTreeSet<ItemKey> = BTreeSet::new();
    for item in items {
        if item.native_id.is_empty() {
            return Err(SyncError::EmptyNativeId);
        }
        let hint = item.size;
        // The bytes of this item that the progress has counted.
        session.item_bytes = 0;
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
            session.item_finished(hint);
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
                    session.add_change(prepared.change);
                }
                None => {
                    session.report.items_new += 1;
                    session.add_change(prepared.change);
                }
            },
            // The item is gone from the source. It is dropped: with a complete list
            // it is not in `seen`, so it counts as deleted when the vault had it.
            Err(io::ErrorKind::NotFound) => {
                seen.remove(&key);
            }
            // An item that cannot be read stays as it is in the vault: it is not
            // deleted.
            Err(kind) => session.report.failed.push(FailedItem { native_id, kind }),
        }
        session.item_finished(hint);
        if session.commit_due() {
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

    // The keys of the deleted items are in the delta entry too. A source that lost millions of
    // items is deleted in several commits, with the cursor of the commit before, so that an
    // entry stays far below the limit of an object.
    let mut gone: Vec<ItemKey> = gone.into_iter().collect();
    let keys_per_entry = (options.commit_entry_size / DELETED_KEY_ENTRY_SIZE).max(1);
    while gone.len() > keys_per_entry {
        let batch: Vec<ItemKey> = gone.drain(..keys_per_entry).collect();
        session.commit(batch, session.stored_cursor.clone()).await?;
    }

    // The last commit. The first run always commits, so that the source exists in
    // the vault, also when it is empty.
    let cursor_changed = cursor != session.stored_cursor;
    if session.head.is_none() || !session.pending.is_empty() || !gone.is_empty() || cursor_changed {
        session.commit(gone, cursor).await?;
    }
    Ok(session.report)
}

/// Whether bytes of this size can be an object that does not compress, as the hashes of the
/// chunks in a content object do not: the packed object has 40 bytes more (format.md 6.7.6).
fn fits_in_an_object(length: usize) -> bool {
    length <= (MAX_OBJECT_SIZE - PACKED_OBJECT_OVERHEAD) as usize
}

/// The size of the record of a deleted item in the encoded delta entry: a byte string of 32 bytes
/// with its header.
const DELETED_KEY_ENTRY_SIZE: usize = 34;

/// An estimate of the size of a change in the encoded delta entry (format.md 5.5.2.1): the
/// array, the key and the record of the item (34 bytes each with the header of the byte
/// string), and the content objects (34 bytes each). The headers of the arrays are rounded up.
fn change_entry_size(change: &Change) -> usize {
    80 + 34 * change.content.len()
}

/// The state of one run.
struct Session<'a, T: WriteTarget, R> {
    progress: &'a mut dyn FnMut(Progress),
    counts: Counts,
    /// The bytes of the item that the run reads now, as the progress has counted them.
    item_bytes: u64,
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
    /// The estimated size of the delta entry for `pending` (see [`change_entry_size`]).
    pending_entry_size: usize,
    head: Option<Head>,
    /// The cursor that the last commit stored.
    stored_cursor: Option<Vec<u8>>,
    report: SyncReport,
}

impl<'a, T: WriteTarget, R: CryptoRng> Session<'a, T, R> {
    /// Tells the caller how far the run is.
    fn tell(&mut self, committing: bool) {
        (self.progress)(if committing {
            Progress::Committing(self.counts)
        } else {
            Progress::Reading(self.counts)
        });
    }

    /// An item is finished: read, failed or dropped. The bytes that the run did not read
    /// of it (all of them for an item that failed) are counted, so that the total of the
    /// source is reached at the end.
    fn item_finished(&mut self, hint: Option<u64>) {
        if let Some(size) = hint {
            self.counts.bytes_done += size.saturating_sub(self.item_bytes);
        }
        self.counts.items_done += 1;
        self.tell(false);
    }

    /// Keeps a change for the next commit.
    fn add_change(&mut self, change: Change) {
        self.pending_entry_size = self
            .pending_entry_size
            .saturating_add(change_entry_size(&change));
        self.pending.push(change);
    }

    /// Whether the run has enough for a commit: data that waits in memory, or changes that make
    /// a large delta entry.
    fn commit_due(&self) -> bool {
        !self.pending.is_empty()
            && (self.pending_bytes() >= self.options.commit_size
                || self.pending_entry_size >= self.options.commit_entry_size)
    }

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
            // The size is a hint for the progress. The record has the size that was read.
            size: _,
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
                self.item_bytes += chunk.len() as u64;
                self.counts.bytes_done += chunk.len() as u64;
                self.tell(false);
            }
            self.report.bytes_read += size;
            total += size;
            let content = ContentObject {
                chunks: chunk_ids,
                size,
                content_hash: ContentHash::from_bytes(hasher.finalize()),
                chunking_profile: self.options.chunking_profile,
            };
            let encoded = content.encode()?;
            // A file with so many chunks that the list of them is not an object: the item
            // cannot be stored. It is reported like any item that cannot be read, and the run
            // goes on. The chunks that it added stay: another item can use them.
            if !fits_in_an_object(encoded.len()) {
                return Ok(Err(io::ErrorKind::FileTooLarge));
            }
            content_ids.push(self.add(CONTENT_OBJECT, &encoded).await?);
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
        self.tell(true);
        let mut changed = std::mem::take(&mut self.pending);
        self.pending_entry_size = 0;
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
    fn an_item_that_is_gone_when_it_is_read_is_dropped_and_deleted() {
        let (target, credential, source) = setup();
        run_default(
            &target,
            &credential,
            source,
            &mut ListConnector::new(&[("stays", b"s"), ("goes", b"g")]),
        );
        // The source listed `goes`, but the file was deleted before it was read. A
        // file that the vault never had is dropped in the same way.
        let mut connector = ListConnector::new(&[("stays", b"s")]);
        connector
            .items
            .push(("goes".into(), Err(io::ErrorKind::NotFound)));
        connector
            .items
            .push(("never-had".into(), Err(io::ErrorKind::NotFound)));
        let report = run_default(&target, &credential, source, &mut connector);
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(
            (
                report.items_deleted,
                report.items_unchanged,
                report.items_new
            ),
            (1, 1, 0)
        );
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.files, [("stays".to_string(), b"s".to_vec())]);
    }

    #[test]
    fn an_item_that_is_gone_does_not_delete_with_a_list_that_is_not_complete() {
        // The connector names the deletions itself when the list is not complete.
        let (target, credential, source) = setup();
        let mut connector = ListConnector::new(&[("a", b"a")]);
        connector.cursor = Some(vec![1]);
        run_default(&target, &credential, source, &mut connector);
        let mut connector = ListConnector::new(&[]);
        connector.complete = false;
        connector
            .items
            .push(("a".into(), Err(io::ErrorKind::NotFound)));
        connector.cursor = Some(vec![2]);
        let report = run_default(&target, &credential, source, &mut connector);
        assert_eq!((report.items_deleted, report.failed.len()), (0, 0));
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.files.len(), 1);
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

    /// Runs the engine like `run`, and returns what it told about its progress.
    fn run_with_progress(
        target: &MemoryTarget,
        credential: &Credential,
        source: SourceId,
        connector: &mut impl Connector,
        options: &SyncOptions,
    ) -> (SyncReport, Vec<Progress>) {
        let mut rng = TestRng::new(5);
        let lock = block_on(WriterLock::acquire(target, NOW, STALE, &mut rng)).unwrap();
        let mut told = Vec::new();
        let report = block_on(sync_with_progress(
            &lock,
            credential,
            source,
            connector,
            options,
            || NOW,
            &mut rng,
            &mut |progress| told.push(progress),
        ))
        .unwrap();
        let _ = block_on(lock.release());
        (report, told)
    }

    fn counts(progress: &Progress) -> Option<Counts> {
        match progress {
            Progress::Reading(counts) | Progress::Committing(counts) => Some(*counts),
            _ => None,
        }
    }

    #[test]
    fn tells_the_steps_of_a_run_in_order() {
        let (target, credential, source) = setup();
        let big = data(1, 600_000);
        let mut connector =
            ListConnector::new(&[("a", b"alpha"), ("big", &big), ("c", b"charlie")]);
        let (_, first) = run_with_progress(
            &target,
            &credential,
            source,
            &mut connector,
            &SyncOptions::default(),
        );
        // The first run has no journal to read.
        assert_eq!(first[0], Progress::OpeningVault);
        assert_eq!(first[1], Progress::ReadingSource);
        assert!(!first.contains(&Progress::ReplayingJournal));
        // The list is known before the first item is read.
        assert_eq!(
            first[2],
            Progress::Reading(Counts {
                items_done: 0,
                items_total: 3,
                bytes_done: 0,
                bytes_total: Some(5 + 600_000 + 7),
            })
        );
        assert!(matches!(first.last(), Some(Progress::Committing(_))));

        // The next run reads the journal.
        let (_, second) = run_with_progress(
            &target,
            &credential,
            source,
            &mut connector,
            &SyncOptions::default(),
        );
        assert_eq!(
            second[..3],
            [
                Progress::OpeningVault,
                Progress::ReplayingJournal,
                Progress::ReadingSource
            ]
        );
    }

    #[test]
    fn the_counts_only_grow_and_reach_the_total() {
        let (target, credential, source) = setup();
        let big = data(2, 700_000);
        let mut connector = ListConnector::new(&[("a", b"alpha"), ("big", &big)]);
        connector
            .items
            .push(("broken".into(), Err(io::ErrorKind::PermissionDenied)));
        let (report, told) = run_with_progress(
            &target,
            &credential,
            source,
            &mut connector,
            &SyncOptions::default(),
        );
        assert_eq!(report.failed.len(), 1);
        let all: Vec<Counts> = told.iter().filter_map(counts).collect();
        for pair in all.windows(2) {
            assert!(pair[0].items_done <= pair[1].items_done, "{pair:?}");
            assert!(pair[0].bytes_done <= pair[1].bytes_done, "{pair:?}");
        }
        let last = all.last().unwrap();
        // An item that failed counts as finished.
        assert_eq!(last.items_done, 3);
        assert_eq!(last.items_total, 3);
        assert_eq!(last.bytes_done, 5 + 700_000);
        assert_eq!(last.bytes_total, Some(5 + 700_000));
    }

    #[test]
    fn a_large_item_reports_while_it_is_read() {
        let (target, credential, source) = setup();
        // Four chunks of the default profile (256 KiB) and a little more.
        let big = data(3, 1_100_000);
        let mut connector = ListConnector::new(&[("big", &big)]);
        let (_, told) = run_with_progress(
            &target,
            &credential,
            source,
            &mut connector,
            &SyncOptions::default(),
        );
        let inside: Vec<u64> = told
            .iter()
            .filter_map(counts)
            .filter(|c| c.items_done == 0 && c.bytes_done > 0)
            .map(|c| c.bytes_done)
            .collect();
        assert_eq!(inside.len(), 5, "{inside:?}");
        assert!(inside.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn the_total_of_bytes_is_unknown_when_one_item_has_no_size() {
        struct NoSizes(ListConnector);
        impl Connector for NoSizes {
            async fn changes(&mut self, cursor: Option<&[u8]>) -> Result<Changes, ConnectorError> {
                let mut changes = self.0.changes(cursor).await?;
                changes.items[1].size = None;
                Ok(changes)
            }
        }
        let (target, credential, source) = setup();
        let mut connector = NoSizes(ListConnector::new(&[("a", b"alpha"), ("b", b"bravo")]));
        let (_, told) = run_with_progress(
            &target,
            &credential,
            source,
            &mut connector,
            &SyncOptions::default(),
        );
        assert!(
            told.iter()
                .filter_map(counts)
                .all(|c| c.bytes_total.is_none())
        );
    }

    #[test]
    fn the_progress_of_a_commit_in_the_middle_of_a_run_is_told() {
        let (target, credential, source) = setup();
        let options = SyncOptions {
            commit_size: 1,
            pack_size: 1,
            ..SyncOptions::default()
        };
        let mut connector = ListConnector::new(&[("a", b"alpha"), ("b", b"bravo")]);
        let (report, told) =
            run_with_progress(&target, &credential, source, &mut connector, &options);
        let commits = told
            .iter()
            .filter(|p| matches!(p, Progress::Committing(_)))
            .count();
        assert_eq!(commits as u32, report.commits);
        assert!(commits >= 2, "{commits}");
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
    fn many_small_items_make_several_commits_so_that_a_delta_entry_stays_small() {
        let (target, credential, source) = setup();
        let names: Vec<String> = (0..10).map(|i| format!("file-{i}")).collect();
        let list: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let mut connector = ListConnector::new(&list);
        // Each change is estimated at 114 bytes: a commit after three of them. The data is
        // far below the size at which a run commits.
        let options = SyncOptions {
            commit_entry_size: 3 * 114,
            ..SyncOptions::default()
        };
        let report = run(&target, &credential, source, &mut connector, &options, 5).unwrap();
        // Items 3, 6 and 9, and the last one.
        assert_eq!(report.commits, 4);
        assert_eq!(report.items_new, 10);
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.sequence, 4);
        assert_eq!(state.files.len(), 10);
    }

    #[test]
    fn an_item_with_many_content_objects_counts_for_more() {
        // One content object: 114 bytes. Ten: 420 bytes.
        let change = |contents: usize| Change {
            item_key: ItemKey::from_bytes([1; 32]),
            item_record: ObjectId::from_bytes([2; 32]),
            content: vec![ObjectId::from_bytes([3; 32]); contents],
        };
        assert_eq!(change_entry_size(&change(1)), 114);
        assert_eq!(change_entry_size(&change(10)), 420);
    }

    #[test]
    fn the_estimate_of_a_change_is_never_less_than_the_real_size() {
        for contents in [0usize, 1, 3, 100] {
            let changed: Vec<Change> = (0..200u8)
                .map(|i| Change {
                    item_key: ItemKey::from_bytes([i; 32]),
                    item_record: ObjectId::from_bytes([i; 32]),
                    content: (0..contents)
                        .map(|c| ObjectId::from_bytes([c as u8 ^ 0x55; 32]))
                        .collect(),
                })
                .collect();
            let deleted: Vec<ItemKey> = (0..50u8)
                .map(|i| ItemKey::from_bytes([200 + i; 32]))
                .collect();
            let estimate = changed.iter().map(change_entry_size).sum::<usize>()
                + deleted.len() * DELETED_KEY_ENTRY_SIZE;
            let entry = DeltaEntry {
                source_id: SourceId::from_bytes([1; 16]),
                sequence: 1,
                parent: None,
                snapshot_id: SnapshotId::from_bytes([2; 16]),
                time: 0,
                connector_cursor: None,
                changed,
                deleted,
            };
            let real = entry.encode().unwrap().len();
            // The entry has a fixed part (the envelope and the fields): 150 bytes are enough.
            assert!(real <= estimate + 150, "{contents}: {real} {estimate}");
            // And the estimate is not far above.
            assert!(estimate <= real * 3 / 2, "{contents}: {real} {estimate}");
        }
    }

    #[test]
    fn many_deleted_items_are_deleted_in_several_commits() {
        let (target, credential, source) = setup();
        let names: Vec<String> = (0..10).map(|i| format!("file-{i}")).collect();
        let list: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let mut connector = ListConnector::new(&list);
        connector.cursor = Some(vec![1]);
        run_default(&target, &credential, source, &mut connector);

        // The source is empty now: 10 keys of 34 bytes, and an entry takes 3 of them.
        connector.items.clear();
        connector.cursor = Some(vec![2]);
        let options = SyncOptions {
            commit_entry_size: 3 * DELETED_KEY_ENTRY_SIZE,
            ..SyncOptions::default()
        };
        let report = run(&target, &credential, source, &mut connector, &options, 6).unwrap();
        assert_eq!(report.items_deleted, 10);
        // 3 + 3 + 3 + 1 keys.
        assert_eq!(report.commits, 4);
        let state = read_state(&target, &seed(), &source).unwrap();
        assert_eq!(state.sequence, 5);
        assert!(state.files.is_empty());
        // The cursor of the last commit is the new one.
        assert_eq!(state.cursor, Some(vec![2]));
    }

    #[test]
    fn a_source_with_a_cursor_deletes_in_several_commits_too() {
        let (target, credential, source) = setup();
        let names: Vec<String> = (0..7).map(|i| format!("file-{i}")).collect();
        let list: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
        let mut connector = ListConnector::new(&list);
        run_default(&target, &credential, source, &mut connector);

        // A list that is not complete: the source says which items are gone.
        let mut connector = ListConnector::new(&[]);
        connector.complete = false;
        connector.deleted = names.clone();
        let options = SyncOptions {
            commit_entry_size: 2 * DELETED_KEY_ENTRY_SIZE,
            ..SyncOptions::default()
        };
        let report = run(&target, &credential, source, &mut connector, &options, 6).unwrap();
        assert_eq!(report.items_deleted, 7);
        // 2 + 2 + 2 + 1 keys.
        assert_eq!(report.commits, 4);
        assert!(
            read_state(&target, &seed(), &source)
                .unwrap()
                .files
                .is_empty()
        );
    }

    #[test]
    fn a_list_of_chunks_that_is_not_an_object_cannot_be_stored() {
        let limit = (MAX_OBJECT_SIZE - PACKED_OBJECT_OVERHEAD) as usize;
        assert!(fits_in_an_object(0));
        assert!(fits_in_an_object(limit));
        assert!(!fits_in_an_object(limit + 1));
        assert!(!fits_in_an_object(MAX_OBJECT_SIZE as usize));
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
