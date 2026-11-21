//! Opens a vault, reads it, verifies it and salvages it.
//!
//! Layering (ADR 0014): all storage access goes through a trait, so the browser
//! can use `fetch` and native code can use the file system. Builds for
//! `wasm32-unknown-unknown`. No network clients, no OAuth crates, no specific
//! async runtime. Must never depend on `nilperit-writer`.
