//! The whole stack on a real folder: make a vault, sync a source into it twice, and
//! read everything back with the reader. Nothing here is in memory except the source.

use nilperit_crypto::RootSeed;
use nilperit_reader::layout::LOCK_PATH;
use nilperit_reader::{Target, Vault};
use nilperit_target_fs::FsTarget;
use nilperit_writer::{
    Changes, Connector, ConnectorError, Credential, SourceItem, SyncOptions, WriterLock,
    create_vault, source_id, sync,
};
use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::io::Cursor;
use std::path::PathBuf;
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

impl TestRng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

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

impl TryCryptoRng for TestRng {}

/// A folder that is removed when it goes out of scope.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("nilperit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A source that is a list of files in memory.
struct Files(Vec<(String, Vec<u8>)>);

impl Connector for Files {
    async fn changes(&mut self, _: Option<&[u8]>) -> Result<Changes, ConnectorError> {
        let items = self
            .0
            .iter()
            .map(|(name, data)| {
                let data = data.clone();
                SourceItem {
                    native_id: name.as_bytes().to_vec(),
                    title: name.clone(),
                    modified: Some(NOW),
                    created: None,
                    media_type: None,
                    metadata: None,
                    contents: vec![Box::new(move || {
                        Ok(Box::new(Cursor::new(data)) as Box<dyn std::io::Read>)
                    })],
                }
            })
            .collect();
        Ok(Changes {
            complete: true,
            items,
            deleted: Vec::new(),
            cursor: None,
        })
    }
}

fn bytes(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

/// Reads every item of the source, as a restore does.
fn read_all(
    target: &FsTarget,
    seed: &RootSeed,
    source: &nilperit_format::SourceId,
) -> Vec<(String, Vec<u8>)> {
    let vault = block_on(Vault::open(target.clone(), seed)).unwrap();
    let index = block_on(vault.scan_packs()).unwrap();
    assert!(index.skipped().is_empty());
    let snapshots = block_on(vault.read_snapshots()).unwrap();
    assert!(snapshots.skipped().is_empty());
    let head = snapshots.head(source).unwrap();
    let state = block_on(vault.replay_journal(&index, head)).unwrap();
    let mut files = Vec::new();
    for (key, item) in &state.items {
        let record = block_on(vault.read_item(&index, key, item)).unwrap();
        let mut data = Vec::new();
        for content in &record.content {
            data.extend(block_on(vault.read_content_to_vec(&index, content)).unwrap());
        }
        files.push((record.title, data));
    }
    files.sort();
    files
}

#[test]
fn a_source_goes_into_a_vault_on_disk_and_comes_back() {
    let dir = TempDir::new("on-disk");
    let target = FsTarget::new(dir.0.join("vault"));
    let seed = RootSeed::from_bytes([7; 32]);
    let mut rng = TestRng(1);

    block_on(create_vault(&target, &seed, &mut rng)).unwrap();
    let credential = Credential::from_seed(&seed);
    let source = source_id(&credential, "test").unwrap();

    let big = bytes(1, 700_000);
    let sync_once = |files: Vec<(String, Vec<u8>)>, rng: &mut TestRng| {
        let lock = block_on(WriterLock::acquire(&target, NOW, STALE, rng)).unwrap();
        let report = block_on(sync(
            &lock,
            &credential,
            source,
            &mut Files(files),
            &SyncOptions::default(),
            || NOW,
            rng,
        ))
        .unwrap();
        block_on(lock.release()).unwrap();
        report
    };

    let first = sync_once(
        vec![
            ("docs/big.bin".into(), big.clone()),
            ("docs/small.txt".into(), b"hello".to_vec()),
            ("empty".into(), Vec::new()),
        ],
        &mut rng,
    );
    assert_eq!((first.commits, first.items_new), (1, 3));
    assert_eq!(
        read_all(&target, &seed, &source),
        [
            ("docs/big.bin".to_string(), big.clone()),
            ("docs/small.txt".to_string(), b"hello".to_vec()),
            ("empty".to_string(), Vec::new()),
        ]
    );

    // The files on disk are what the format says (section 7). The lock is gone.
    assert!(dir.0.join("vault/config-a").is_file());
    assert!(dir.0.join("vault/config-b").is_file());
    assert_eq!(block_on(target.list("snapshots")).unwrap().len(), 1);
    assert!(!block_on(target.list("packs")).unwrap().is_empty());
    assert!(block_on(target.len(LOCK_PATH)).is_err());
    // No temporary file stays behind.
    let all = block_on(target.list("packs")).unwrap();
    assert!(all.iter().all(|path| !path.contains("/.tmp-")), "{all:?}");

    // A second run: one file changes, one goes, one stays.
    let mut changed = big.clone();
    changed[650_000] ^= 0xff;
    let second = sync_once(
        vec![
            ("docs/big.bin".into(), changed.clone()),
            ("empty".into(), Vec::new()),
        ],
        &mut rng,
    );
    assert_eq!(
        (second.commits, second.items_changed, second.items_deleted),
        (1, 1, 1)
    );
    assert!(second.chunks_existing >= 2, "{second:?}");
    assert_eq!(
        read_all(&target, &seed, &source),
        [
            ("docs/big.bin".to_string(), changed),
            ("empty".to_string(), Vec::new()),
        ]
    );
}

#[test]
fn files_that_are_not_part_of_the_vault_do_not_disturb_it() {
    let dir = TempDir::new("junk");
    let target = FsTarget::new(dir.0.join("vault"));
    let seed = RootSeed::from_bytes([7; 32]);
    let mut rng = TestRng(2);
    block_on(create_vault(&target, &seed, &mut rng)).unwrap();
    let credential = Credential::from_seed(&seed);
    let source = source_id(&credential, "test").unwrap();

    // A temporary file that a crash left, and a file of another program.
    fs::create_dir_all(dir.0.join("vault/packs/ab")).unwrap();
    fs::write(dir.0.join("vault/packs/ab/.tmp-1-2-3"), b"half a pack").unwrap();
    fs::write(dir.0.join("vault/packs/notes.txt"), b"not a pack").unwrap();
    fs::create_dir_all(dir.0.join("vault/snapshots")).unwrap();
    fs::write(dir.0.join("vault/snapshots/.tmp-4-5-6"), b"half a header").unwrap();

    let lock = block_on(WriterLock::acquire(&target, NOW, STALE, &mut rng)).unwrap();
    let report = block_on(sync(
        &lock,
        &credential,
        source,
        &mut Files(vec![("a".into(), b"data".to_vec())]),
        &SyncOptions::default(),
        || NOW,
        &mut rng,
    ))
    .unwrap();
    block_on(lock.release()).unwrap();
    assert_eq!(report.items_new, 1);
    assert_eq!(
        read_all(&target, &seed, &source),
        [("a".to_string(), b"data".to_vec())]
    );
}

#[test]
fn a_damaged_pack_on_disk_is_skipped_and_the_rest_stays_readable() {
    let dir = TempDir::new("damage");
    let target = FsTarget::new(dir.0.join("vault"));
    let seed = RootSeed::from_bytes([7; 32]);
    let mut rng = TestRng(3);
    block_on(create_vault(&target, &seed, &mut rng)).unwrap();
    let credential = Credential::from_seed(&seed);
    let source = source_id(&credential, "test").unwrap();
    let options = SyncOptions {
        commit_size: 1,
        pack_size: 1,
        ..SyncOptions::default()
    };
    // Each file is a commit of its own, so the packs are separate.
    let lock = block_on(WriterLock::acquire(&target, NOW, STALE, &mut rng)).unwrap();
    block_on(sync(
        &lock,
        &credential,
        source,
        &mut Files(vec![
            ("a".into(), bytes(1, 1000)),
            ("b".into(), bytes(2, 1000)),
        ]),
        &options,
        || NOW,
        &mut rng,
    ))
    .unwrap();
    block_on(lock.release()).unwrap();

    // Damage the end of one pack file: its footer.
    let packs = block_on(target.list("packs")).unwrap();
    assert!(packs.len() >= 2);
    let victim = dir.0.join("vault").join(&packs[0]);
    let mut content = fs::read(&victim).unwrap();
    let last = content.len() - 1;
    content[last] ^= 1;
    fs::write(&victim, content).unwrap();

    let vault = block_on(Vault::open(target.clone(), &seed)).unwrap();
    let index = block_on(vault.scan_packs()).unwrap();
    assert_eq!(index.skipped().len(), 1);
    assert_eq!(index.packs().count(), packs.len() - 1);
}
