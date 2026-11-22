//! A folder goes into a vault on disk and comes back out. The source, the vault and
//! the restore are all real folders. This is the first working system, in a test.

use nilperit_connector_fs::{FolderConnector, Symlinks};
use nilperit_crypto::RootSeed;
use nilperit_format::SourceId;
use nilperit_reader::Vault;
use nilperit_target_fs::FsTarget;
use nilperit_writer::{
    Credential, SyncOptions, SyncReport, WriterLock, create_vault, source_id, sync,
};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use x_wing::kem::common::rand_core::{TryCryptoRng, TryRng};

const NOW: i64 = 1_700_000_000_000;
const STALE: i64 = 600_000;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the future waits"),
    }
}

/// A "random" number generator for the test. NOT secure.
struct TestRng(u64);

impl TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.step() >> 32) as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.step())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for byte in dst {
            *byte = self.step() as u8;
        }
        Ok(())
    }
}

impl TestRng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl TryCryptoRng for TestRng {}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("nilperit-e2e-{name}-{}", std::process::id()));
        restore_permissions(&path);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        restore_permissions(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A test can leave a folder that is not readable. Remove that, so that the folder
/// can be deleted.
fn restore_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() && !entry.path().is_symlink() {
                    restore_permissions(&entry.path());
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn bytes(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| {
            (i as u8)
                .wrapping_mul(13)
                .wrapping_add(seed)
                .wrapping_add((i / 200) as u8)
        })
        .collect()
}

/// What a restore finds for one item: the bytes and the metadata.
type Restored = (Vec<u8>, Option<Vec<u8>>);

/// A vault on disk, with a node and a source.
struct Setup {
    seed: RootSeed,
    target: FsTarget,
    credential: Credential,
    source: SourceId,
    rng: TestRng,
}

impl Setup {
    fn new(vault: &Path) -> Self {
        let seed = RootSeed::from_bytes([7; 32]);
        let target = FsTarget::new(vault);
        let mut rng = TestRng(1);
        block_on(create_vault(&target, &seed, &mut rng)).unwrap();
        let credential = Credential::from_seed(&seed);
        let source = source_id(&credential, "photos").unwrap();
        Self {
            seed,
            target,
            credential,
            source,
            rng,
        }
    }

    fn sync(&mut self, connector: &mut FolderConnector, now: i64) -> SyncReport {
        let lock = block_on(WriterLock::acquire(&self.target, now, STALE, &mut self.rng)).unwrap();
        let report = block_on(sync(
            &lock,
            &self.credential,
            self.source,
            connector,
            &SyncOptions::default(),
            || now,
            &mut self.rng,
        ))
        .unwrap();
        block_on(lock.release()).unwrap();
        report
    }

    /// What a restore finds: native ID, bytes and metadata of each item.
    fn read_all(&self) -> BTreeMap<Vec<u8>, Restored> {
        let vault = block_on(Vault::open(self.target.clone(), &self.seed)).unwrap();
        let index = block_on(vault.scan_packs()).unwrap();
        assert!(index.skipped().is_empty());
        let snapshots = block_on(vault.read_snapshots()).unwrap();
        let head = snapshots.head(&self.source).unwrap();
        let state = block_on(vault.replay_journal(&index, head)).unwrap();
        let mut files = BTreeMap::new();
        for (key, item) in &state.items {
            let record = block_on(vault.read_item(&index, key, item)).unwrap();
            let mut data = Vec::new();
            for content in &record.content {
                data.extend(block_on(vault.read_content_to_vec(&index, content)).unwrap());
            }
            files.insert(record.native_id, (data, record.metadata));
        }
        files
    }
}

fn write(root: &Path, path: &str, data: &[u8]) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, data).unwrap();
}

#[test]
fn a_folder_goes_into_a_vault_and_every_file_comes_back() {
    let source = TempDir::new("source");
    let vault = TempDir::new("vault");
    let big = bytes(1, 700_000);
    write(&source.0, "docs/big.bin", &big);
    write(&source.0, "docs/deep/er/note.txt", b"a note");
    write(&source.0, "top.txt", b"top");
    write(&source.0, ".hidden", b"dot");
    write(&source.0, "empty", b"");
    fs::create_dir_all(source.0.join("empty-folder")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(source.0.join("top.txt"), fs::Permissions::from_mode(0o640)).unwrap();
        std::os::unix::fs::symlink("top.txt", source.0.join("link")).unwrap();
    }

    let mut setup = Setup::new(&vault.0);
    let report = setup.sync(&mut FolderConnector::new(&source.0), NOW);
    assert_eq!(report.commits, 1);
    assert_eq!(report.items_new, 5);
    #[cfg(unix)]
    assert_eq!(
        report.failed,
        [nilperit_writer::FailedItem {
            native_id: b"link".to_vec(),
            kind: io::ErrorKind::Unsupported
        }]
    );

    let restored = setup.read_all();
    let names: Vec<&[u8]> = restored.keys().map(Vec::as_slice).collect();
    assert_eq!(
        names,
        [
            &b".hidden"[..],
            b"docs/big.bin",
            b"docs/deep/er/note.txt",
            b"empty",
            b"top.txt"
        ]
    );
    assert_eq!(restored[&b"docs/big.bin"[..]].0, big);
    assert_eq!(restored[&b"docs/deep/er/note.txt"[..]].0, b"a note");
    assert_eq!(restored[&b"empty"[..]].0, b"");
    #[cfg(unix)]
    {
        // The mode of the file is in its metadata: `{"mode": 416}` (0o640).
        let expected = [0xa1, 0x64, b'm', b'o', b'd', b'e', 0x19, 0x01, 0xa0];
        assert_eq!(restored[&b"top.txt"[..]].1.as_deref(), Some(&expected[..]));
    }
}

#[test]
fn a_second_run_writes_only_what_changed() {
    let source = TempDir::new("source2");
    let vault = TempDir::new("vault2");
    let big = bytes(2, 700_000);
    write(&source.0, "big.bin", &big);
    write(&source.0, "old.txt", b"old");
    write(&source.0, "same.txt", b"same");

    let mut setup = Setup::new(&vault.0);
    setup.sync(&mut FolderConnector::new(&source.0), NOW);

    // Nothing changed: nothing is written.
    let report = setup.sync(&mut FolderConnector::new(&source.0), NOW + 1_000);
    assert_eq!(report.commits, 0);
    assert_eq!(report.items_unchanged, 3);

    // One byte of the big file changes, a file goes, a file is new.
    let mut changed = big.clone();
    changed[690_000] ^= 0xff;
    write(&source.0, "big.bin", &changed);
    fs::remove_file(source.0.join("old.txt")).unwrap();
    write(&source.0, "new/new.txt", b"new");
    let report = setup.sync(&mut FolderConnector::new(&source.0), NOW + 2_000);
    assert_eq!(report.commits, 1);
    assert_eq!(
        (
            report.items_new,
            report.items_changed,
            report.items_deleted,
            report.items_unchanged
        ),
        (1, 1, 1, 1)
    );
    // Two of the three chunks of the big file are in the vault already.
    assert!(report.chunks_existing >= 2, "{report:?}");

    let restored = setup.read_all();
    let names: Vec<&[u8]> = restored.keys().map(Vec::as_slice).collect();
    assert_eq!(names, [&b"big.bin"[..], b"new/new.txt", b"same.txt"]);
    assert_eq!(restored[&b"big.bin"[..]].0, changed);
}

#[test]
fn the_vault_inside_the_folder_does_not_back_itself_up() {
    let source = TempDir::new("source3");
    write(&source.0, "data/file.txt", b"data");
    let vault_folder = source.0.join("my-vault");

    let mut setup = Setup::new(&vault_folder);
    let root = source.0.canonicalize().unwrap();
    let excluded = vault_folder.canonicalize().unwrap();
    let connector = || FolderConnector::new(&root).exclude(&excluded);
    let first = setup.sync(&mut connector(), NOW);
    assert_eq!(first.items_new, 1);
    // The vault now has files. A second run does not see them as items.
    let second = setup.sync(&mut connector(), NOW + 1_000);
    assert_eq!((second.commits, second.items_unchanged), (0, 1));
    assert_eq!(setup.read_all().len(), 1);
}

#[cfg(unix)]
#[test]
fn a_folder_that_cannot_be_read_deletes_nothing_from_the_vault() {
    use std::os::unix::fs::PermissionsExt;
    let source = TempDir::new("source4");
    let vault = TempDir::new("vault4");
    write(&source.0, "locked/inside.txt", b"inside");
    write(&source.0, "open.txt", b"open");

    let mut setup = Setup::new(&vault.0);
    setup.sync(&mut FolderConnector::new(&source.0), NOW);

    fs::set_permissions(source.0.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    // The owner of the folder ignores permissions: the test makes no sense then.
    if fs::read_dir(source.0.join("locked")).is_ok() {
        return;
    }
    let report = setup.sync(&mut FolderConnector::new(&source.0), NOW + 1_000);
    // The folder is reported, and the file below it is not deleted.
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].native_id, b"locked");
    assert_eq!(report.failed[0].kind, io::ErrorKind::PermissionDenied);
    let restored = setup.read_all();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored[&b"locked/inside.txt"[..]].0, b"inside");

    // When the folder can be read again, the vault is as it was.
    fs::set_permissions(source.0.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    let report = setup.sync(&mut FolderConnector::new(&source.0), NOW + 2_000);
    assert_eq!((report.commits, report.items_unchanged), (0, 2));
}

#[cfg(unix)]
#[test]
fn a_name_that_is_not_text_comes_back_with_the_same_bytes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let source = TempDir::new("source5");
    let vault = TempDir::new("vault5");
    let name = OsString::from_vec(vec![b'o', b'd', b'd', 0xff, 0xfe]);
    fs::write(source.0.join(&name), b"odd name").unwrap();
    let mut setup = Setup::new(&vault.0);
    setup.sync(&mut FolderConnector::new(&source.0), NOW);
    let restored = setup.read_all();
    assert_eq!(
        restored.keys().next().unwrap().as_slice(),
        &[b'o', b'd', b'd', 0xff, 0xfe]
    );
}

#[cfg(unix)]
#[test]
fn links_to_files_stored_elsewhere_are_backed_up_when_the_connector_follows_them() {
    let source = TempDir::new("source6");
    let elsewhere = TempDir::new("elsewhere6");
    let vault = TempDir::new("vault6");
    write(&elsewhere.0, "Documents/contract.pdf", b"important");
    write(&elsewhere.0, "Documents/notes/todo.txt", b"todo");
    write(&source.0, "plain.txt", b"plain");
    std::os::unix::fs::symlink(elsewhere.0.join("Documents"), source.0.join("Documents")).unwrap();
    std::os::unix::fs::symlink(
        elsewhere.0.join("Documents/contract.pdf"),
        source.0.join("contract"),
    )
    .unwrap();

    let mut setup = Setup::new(&vault.0);
    // By default the links are reported, and not stored.
    let report = setup.sync(&mut FolderConnector::new(&source.0), NOW);
    assert_eq!(report.items_new, 1);
    assert_eq!(report.failed.len(), 2);

    // With the option, the files that the links point to are in the vault, under the
    // paths of the links. The first run did not store the links, so nothing is lost.
    let mut follow = FolderConnector::new(&source.0).symlinks(Symlinks::Follow);
    let report = setup.sync(&mut follow, NOW + 1_000);
    assert_eq!((report.items_new, report.items_unchanged), (3, 1));
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    let restored = setup.read_all();
    let names: Vec<&[u8]> = restored.keys().map(Vec::as_slice).collect();
    assert_eq!(
        names,
        [
            &b"Documents/contract.pdf"[..],
            b"Documents/notes/todo.txt",
            b"contract",
            b"plain.txt"
        ]
    );
    assert_eq!(restored[&b"contract"[..]].0, b"important");
    // The same bytes under two paths are stored once.
    assert_eq!(report.chunks_written, 2);

    // The disk behind the links is not mounted: nothing is deleted from the vault.
    fs::remove_dir_all(&elsewhere.0).unwrap();
    let report = setup.sync(
        &mut FolderConnector::new(&source.0).symlinks(Symlinks::Follow),
        NOW + 2_000,
    );
    assert_eq!(report.items_deleted, 0);
    assert_eq!(report.failed.len(), 2);
    assert_eq!(setup.read_all().len(), 4);
}

#[test]
fn a_file_that_goes_while_the_run_reads_it_counts_as_deleted() {
    use nilperit_writer::{Changes, Connector, ConnectorError};

    // A source that lists a file that is gone when the engine reads it.
    struct Racing(FolderConnector, PathBuf);
    impl Connector for Racing {
        async fn changes(&mut self, cursor: Option<&[u8]>) -> Result<Changes, ConnectorError> {
            let changes = self.0.changes(cursor).await;
            fs::remove_file(&self.1).unwrap();
            changes
        }
    }

    let source = TempDir::new("source7");
    let vault = TempDir::new("vault7");
    write(&source.0, "stays", b"stays");
    write(&source.0, "goes", b"goes");
    let mut setup = Setup::new(&vault.0);
    setup.sync(&mut FolderConnector::new(&source.0), NOW);
    assert_eq!(setup.read_all().len(), 2);

    // The file is deleted after the walk, before it is read.
    let mut racing = Racing(FolderConnector::new(&source.0), source.0.join("goes"));
    let lock = block_on(WriterLock::acquire(
        &setup.target,
        NOW + 1_000,
        STALE,
        &mut setup.rng,
    ))
    .unwrap();
    let report = block_on(sync(
        &lock,
        &setup.credential,
        setup.source,
        &mut racing,
        &SyncOptions::default(),
        || NOW + 1_000,
        &mut setup.rng,
    ))
    .unwrap();
    block_on(lock.release()).unwrap();
    assert!(report.failed.is_empty(), "{:?}", report.failed);
    assert_eq!((report.items_deleted, report.items_unchanged), (1, 1));
    let restored = setup.read_all();
    assert_eq!(restored.len(), 1);
    assert!(restored.contains_key(&b"stays"[..]));
}
