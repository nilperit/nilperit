//! Checks for bytes that are not trusted.
//!
//! A vault can be damaged, or come from a replica that someone changed. Every parser of
//! NilPerit must then do one of two things with any input: accept it, and give a value
//! that holds the rules of the format, or refuse it. It must never panic, never loop, and
//! never allocate without a limit.
//!
//! This crate has one function for each place where bytes come in ([`checks`]). A function
//! takes bytes and panics when a rule is broken. Two programs call them:
//!
//! - the mutation tests of this crate (`tests/mutations.rs`), which run on every system in
//!   CI, with the test vectors of format.md as the seeds and a fixed random generator;
//! - the targets of `cargo-fuzz` (the `fuzz` folder of the repository), which run with
//!   coverage guidance and need a nightly toolchain.
//!
//! The same functions in both means that a fuzzer finds a problem, and the next run of the
//! tests catches it again.
//!
//! Layering (ADR 0014): this crate is above the writer. Nothing that ships may depend on it.

pub mod checks;
pub mod mutate;
pub mod seeds;

mod fixtures;

/// Helpers for the tests of this crate.
#[doc(hidden)]
pub mod fixtures_for_tests {
    pub use crate::fixtures::unhex;
}
