//! The keys and the small helpers that the checks use.
//!
//! The keys are those of the test vector A.8 of format.md (the pack). So the objects of
//! that pack are valid input, and the seeds are real.

use nilperit_crypto::{DedupKey, ReadKey, WriterKey};
use nilperit_reader::Keys;
use rand_core::{TryCryptoRng, TryRng};
use std::convert::Infallible;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// The writer key of A.8.2: the 32 bytes `20 21 ... 3f`.
pub fn writer_key() -> WriterKey {
    WriterKey::from_bytes(std::array::from_fn(|i| 0x20 + i as u8))
}

/// The dedup key of A.2.1: the 32 bytes `00 01 ... 1f`.
pub fn dedup_key() -> DedupKey {
    DedupKey::from_bytes(std::array::from_fn(|i| i as u8))
}

/// The keys of a reader. The read key is not part of a vector.
pub fn keys() -> Keys {
    Keys::new(writer_key(), ReadKey::from_seed([9; 32]), &dedup_key())
}

/// A "random" number generator that always gives the same byte. It makes the nonces of
/// A.8 (`03` in the object table). NOT secure: only for tests and fuzzing.
pub struct FixedRng(pub u8);

impl TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_ne_bytes([self.0; 4]))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_ne_bytes([self.0; 8]))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

/// Runs a future that never waits for anything (the in-memory target).
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a future waits: the in-memory target never waits"),
    }
}

/// Bytes from hexadecimal text.
pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hexadecimal text"))
        .collect()
}
