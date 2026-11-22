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
        if self.puts_left.get() == 0 {
            return Err(TargetError::Other("the disk failed".into()));
        }
        self.puts_left.set(self.puts_left.get() - 1);
        self.log.borrow_mut().push(path.to_string());
        self.inner.put(path, bytes).await
    }
}
