//! Chunking, packs, commits, retention and sweep.
//!
//! Layering (ADR 0014): may depend on the reader side. Nothing on the reader
//! side may depend on this crate.

pub mod chunking;
pub mod credential;
pub mod pack_builder;

pub use credential::Credential;
pub use pack_builder::{BuildError, BuiltPack, PackBuilder};
