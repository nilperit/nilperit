//! A very small executor.
//!
//! The file-system target and the folder connector never wait: each `async` function
//! does its work and returns. So a future can be driven with a waker that does
//! nothing. A future that does wait is a bug here (a target on a network needs a real
//! executor), and it stops the program with a message.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a future waits: this program has no executor for that"),
    }
}
