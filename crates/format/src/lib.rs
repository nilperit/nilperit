//! Object types, deterministic CBOR encoding and schema generation.
//!
//! Layering (ADR 0014): no I/O, builds for `wasm32-unknown-unknown`, depends on
//! no other NilPerit crate.
//!
//! This crate is `no_std` (with `alloc`) so it builds for the browser.

#![no_std]

extern crate alloc;

pub mod canonical;
pub mod envelope;

pub use canonical::CanonicalError;
pub use envelope::{Envelope, EnvelopeError};
