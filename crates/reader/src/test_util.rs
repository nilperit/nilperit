//! Test helpers. The library has no async runtime, so tests drive futures by hand.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

/// Runs a future to completion. It only works for futures that never wait for
/// something outside the future, which is true for the in-memory target.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the future waits for something that never happens"),
    }
}
