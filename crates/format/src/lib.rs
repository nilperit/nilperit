//! Object types, deterministic CBOR encoding and schema generation.
//!
//! Layering (ADR 0014): no I/O, builds for `wasm32-unknown-unknown`, depends on
//! no other NilPerit crate.
//!
//! This crate is `no_std` (with `alloc`) so it builds for the browser.

#![no_std]

extern crate alloc;

pub mod canonical;
pub mod content_object;
pub mod envelope;
pub mod ids;
pub mod object_table;
pub mod object_type;
pub mod pack;

pub use canonical::CanonicalError;
pub use content_object::{ContentObject, ObjectError};
pub use envelope::{Envelope, EnvelopeError};
pub use ids::{ContentHash, HASH_LEN, ObjectId};
pub use object_table::{Compression, KeyClass, ObjectTable, ObjectTableEntry};
pub use pack::{Footer, Header, PackClass, PackError, Trailer};
