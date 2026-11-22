//! Object types, deterministic CBOR encoding and schema generation.
//!
//! Layering (ADR 0014): no I/O, builds for `wasm32-unknown-unknown`, depends on
//! no other NilPerit crate.
//!
//! This crate is `no_std` (with `alloc`) so it builds for the browser.

#![no_std]
// These crates read bytes that are not trusted. A panic there is a bug: the reader must give an
// error (AGENTS.md, "Damage stays local"). A site that cannot fail gets an `#[allow]` with the
// reason.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

extern crate alloc;

pub mod canonical;
pub mod content_object;
pub mod delta_entry;
pub mod envelope;
mod fields;
pub mod ids;
pub mod item_record;
pub mod lock_file;
pub mod object_table;
pub mod object_type;
pub mod pack;
pub mod snapshot_header;
pub mod vault_config;

pub use canonical::CanonicalError;
pub use content_object::{ContentObject, ObjectError};
pub use delta_entry::{Change, DeltaEntry};
pub use envelope::{Envelope, EnvelopeError};
pub use ids::{
    ContentHash, HASH_LEN, HolderId, ItemKey, ObjectId, PackName, SHORT_ID_LEN, SnapshotId,
    SourceId, VaultId,
};
pub use item_record::ItemRecord;
pub use lock_file::LockFile;
pub use object_table::{Compression, KeyClass, ObjectTable, ObjectTableEntry};
pub use pack::{Footer, Header, MAX_OBJECT_SIZE, PackClass, PackError, Trailer};
pub use snapshot_header::{SnapshotHeader, Statistics};
pub use vault_config::{
    ChunkingProfile, VaultConfig, VaultEssentials, join_config_file, split_config_file,
};
