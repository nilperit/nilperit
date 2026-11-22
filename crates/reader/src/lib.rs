//! Opens a vault, reads it, verifies it and salvages it.
//!
//! Layering (ADR 0014): all access to the target goes through a trait, so the browser
//! can use `fetch` and native code can use the file system. Builds for
//! `wasm32-unknown-unknown`. No network clients, no OAuth crates, no specific
//! async runtime. Must never depend on `nilperit-writer`.
//!
//! This crate is `no_std` (with `alloc`), like the format and crypto crates.

#![no_std]

extern crate alloc;

pub mod keys;
pub mod layout;
pub mod memory_target;
pub mod pack;
pub mod target;
#[cfg(test)]
mod test_util;
pub mod vault;

pub use keys::Keys;
pub use memory_target::MemoryTarget;
pub use pack::{ObjectReadError, Pack, PackOpenError};
pub use target::{Target, TargetError};
pub use vault::{Vault, VaultError};
