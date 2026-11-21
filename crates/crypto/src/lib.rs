//! Key derivation, sealing and opening of keys, and AEAD encryption.
//!
//! Layering (ADR 0014): no I/O, builds for `wasm32-unknown-unknown`, depends on
//! no other NilPerit crate. Never implement cryptographic primitives here; use
//! reviewed crates and record their audit status in the pull request.
