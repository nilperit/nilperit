//! Chunking, packs, commits, retention and sweep.
//!
//! Layering (ADR 0014): may depend on the reader side. Nothing on the reader
//! side may depend on this crate.

pub mod chunking;
pub mod commit;
pub mod credential;
pub mod pack_builder;
pub mod target;
#[cfg(test)]
mod test_util;
pub mod vault_init;

pub use commit::{CommitError, commit};
pub use credential::Credential;
pub use pack_builder::{BuildError, BuiltPack, PackBuilder};
pub use target::WriteTarget;
pub use vault_init::{InitError, create_vault};
