//! Test helpers. The library has no async runtime, so tests drive futures by hand.

use std::convert::Infallible;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use x_wing::kem::common::rand_core::{TryCryptoRng, TryRng};

/// Runs a future that never waits for anything (the in-memory target).
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the future waits"),
    }
}

/// A "random" number generator: first the bytes of a script, then SplitMix64.
/// NOT secure: only for tests.
pub struct TestRng {
    script: Vec<u8>,
    state: u64,
}

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self {
            script: Vec::new(),
            state: seed,
        }
    }

    pub fn scripted(script: Vec<u8>) -> Self {
        Self { script, state: 1 }
    }

    pub fn step(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
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
            *byte = if self.script.is_empty() {
                self.step() as u8
            } else {
                self.script.remove(0)
            };
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

use crate::target::WriteTarget;
use nilperit_reader::{MemoryTarget, Target, TargetError};
use std::cell::{Cell, RefCell};
use std::ops::Range;

/// A target that stops working after some writes, and records every write.
pub struct Flaky<'a> {
    pub inner: &'a MemoryTarget,
    /// How many writes still work. After that, a write fails and writes nothing.
    pub puts_left: Cell<usize>,
    /// The paths of the writes that worked, in order.
    pub log: RefCell<Vec<String>>,
}

impl<'a> Flaky<'a> {
    pub fn new(inner: &'a MemoryTarget, puts_left: usize) -> Self {
        Self {
            inner,
            puts_left: Cell::new(puts_left),
            log: RefCell::new(Vec::new()),
        }
    }
}

impl Target for Flaky<'_> {
    async fn len(&self, path: &str) -> Result<u64, TargetError> {
        self.inner.len(path).await
    }
    async fn read_range(&self, path: &str, range: Range<u64>) -> Result<Vec<u8>, TargetError> {
        self.inner.read_range(path, range).await
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>, TargetError> {
        self.inner.read(path).await
    }
    async fn list(&self, dir: &str) -> Result<Vec<String>, TargetError> {
        self.inner.list(dir).await
    }
}

impl WriteTarget for Flaky<'_> {
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
        // The heartbeat of the lock is not part of what the tests count.
        if path == nilperit_reader::layout::LOCK_PATH {
            return self.inner.put(path, bytes).await;
        }
        if self.puts_left.get() == 0 {
            return Err(TargetError::Other("the disk failed".into()));
        }
        self.puts_left.set(self.puts_left.get() - 1);
        self.log.borrow_mut().push(path.to_string());
        self.inner.put(path, bytes).await
    }

    async fn put_new(&self, path: &str, bytes: &[u8]) -> Result<bool, TargetError> {
        self.inner.put_new(path, bytes).await
    }

    async fn remove_lock(&self) -> Result<(), TargetError> {
        self.inner.remove_lock().await
    }
}

use crate::connector::{Changes, Connector, ConnectorError, SourceItem};
use nilperit_crypto::RootSeed;
use nilperit_format::SourceId;
use nilperit_reader::Vault;
use std::io::{self, Cursor};

/// A source that is a list in memory.
pub struct ListConnector {
    /// The items: native ID, and the content or the reason why it cannot be read.
    pub items: Vec<(String, Result<Vec<u8>, io::ErrorKind>)>,
    /// Whether the list is complete (see `Changes::complete`).
    pub complete: bool,
    /// The native IDs that the source no longer has (for a list that is not complete).
    pub deleted: Vec<String>,
    /// The cursor after the run.
    pub cursor: Option<Vec<u8>>,
    /// The cursors that the engine gave, one for each run.
    pub received: Vec<Option<Vec<u8>>>,
}

impl ListConnector {
    /// A complete list of items that can be read.
    pub fn new(items: &[(&str, &[u8])]) -> Self {
        Self {
            items: items
                .iter()
                .map(|(id, data)| ((*id).to_string(), Ok(data.to_vec())))
                .collect(),
            complete: true,
            deleted: Vec::new(),
            cursor: None,
            received: Vec::new(),
        }
    }
}

impl Connector for ListConnector {
    async fn changes(&mut self, cursor: Option<&[u8]>) -> Result<Changes, ConnectorError> {
        self.received.push(cursor.map(<[u8]>::to_vec));
        let items = self
            .items
            .iter()
            .map(|(id, data)| {
                let data = data.clone();
                SourceItem {
                    native_id: id.as_bytes().to_vec(),
                    title: id.clone(),
                    modified: Some(1_700_000_000_000),
                    created: None,
                    media_type: Some("application/octet-stream".into()),
                    // An item that cannot be read has nothing to read.
                    size: Some(data.as_ref().map_or(0, |bytes| bytes.len() as u64)),
                    metadata: None,
                    contents: vec![Box::new(move || match data {
                        Ok(bytes) => Ok(Box::new(Cursor::new(bytes)) as Box<dyn io::Read>),
                        Err(kind) => Err(io::Error::from(kind)),
                    })],
                }
            })
            .collect();
        Ok(Changes {
            complete: self.complete,
            items,
            deleted: self
                .deleted
                .iter()
                .map(|id| id.as_bytes().to_vec())
                .collect(),
            cursor: self.cursor.clone(),
        })
    }
}

/// What an owner reads from a vault for one source.
#[derive(Debug, PartialEq, Eq)]
pub struct State {
    /// The sequence number of the head of the journal.
    pub sequence: u64,
    /// The connector cursor of the head.
    pub cursor: Option<Vec<u8>>,
    /// The title and the bytes of each item, sorted.
    pub files: Vec<(String, Vec<u8>)>,
}

/// Reads a source the way a restore does. `None` when the source has no snapshot
/// header.
pub fn read_state(target: &MemoryTarget, seed: &RootSeed, source: &SourceId) -> Option<State> {
    let vault = block_on(Vault::open(target, seed)).unwrap();
    let index = block_on(vault.scan_packs()).unwrap();
    assert!(index.skipped().is_empty());
    let snapshots = block_on(vault.read_snapshots()).unwrap();
    assert!(snapshots.skipped().is_empty());
    let head = snapshots.head(source)?;
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
    Some(State {
        sequence: state.sequence,
        cursor: state.connector_cursor,
        files,
    })
}
