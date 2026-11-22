//! Key derivation, sealing and opening of keys, and AEAD encryption.
//!
//! Layering (ADR 0014): no I/O, builds for `wasm32-unknown-unknown`, depends on
//! no other NilPerit crate. Never implement cryptographic primitives here; use
//! reviewed crates and record their audit status in the pull request.
//!
//! This crate is `no_std`. It never reads the operating system's random number
//! generator: functions that need randomness take a [`CryptoRng`], and the
//! caller gives one.

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

pub mod aead;
pub mod hash;
pub mod keys;
pub mod mac;
pub mod seal;

#[cfg(test)]
mod test_rng;

pub use aead::{AeadError, decrypt, encrypt};
pub use hash::{
    ContentHasher, DedupKey, DomainKey, DomainKeys, HASH_LEN, HashDomain, SOURCE_ID_LEN, SizeError,
};
pub use keys::{AeadKey, MacKey, PhraseError, RootSeed, WriterKey};
pub use mac::{config_mac, verify_config_mac};
pub use seal::{ReadKey, ReadPublicKey, SealError, open_seal, seal_pack_key};
pub use x_wing::CryptoRng;
