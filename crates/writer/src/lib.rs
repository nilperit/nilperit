//! Chunking, packs, commits, retention and sweep.
//!
//! Layering (ADR 0014): may depend on the reader side. Nothing on the reader
//! side may depend on this crate.

pub mod chunking;
pub mod commit;
pub mod connector;
pub mod credential;
pub mod lock;
pub mod pack_builder;
pub mod progress;
pub mod sync;
pub mod target;
#[cfg(test)]
mod test_util;
pub mod vault_init;

pub use commit::{CommitError, commit};
pub use connector::{Changes, Connector, ConnectorError, OpenContent, SourceItem};
pub use credential::Credential;
pub use lock::{LockError, WriterLock};
pub use pack_builder::{BuildError, BuiltPack, PackBuilder};
pub use progress::{Counts, Progress};
pub use sync::{
    FailedItem, SyncError, SyncOptions, SyncReport, source_id, sync, sync_with_progress,
};
pub use target::WriteTarget;
pub use vault_init::{InitError, check_empty, create_vault};
