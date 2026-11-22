# Fuzzing NilPerit

Coverage-guided fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer and
the sanitizers). A fuzzer makes input that reaches new code, and a parser that gets bytes that are
not trusted must never panic, loop, or allocate without a limit, whatever it gets.

Every target in `fuzz_targets/` calls one check of the crate [`nilperit-fuzz`](../crates/fuzz).
The same checks run as mutation tests in `cargo test`, on Linux, Windows and macOS. So a fuzzer
finds a problem, and the tests catch it again (see `crates/fuzz/regressions/README.md`).

| Target | What it runs |
|---|---|
| `canonical` | the strict CBOR check, against another decoder |
| `envelope`, `content_object`, `item_record`, `delta_entry`, `snapshot_header`, `vault_config`, `lock_file`, `object_table` | the decoders: strict input, and a round trip that changes nothing |
| `pack_parts` | the header, the footer and the trailer of a pack |
| `pack_with_table` | a pack with a body, a seal and an object table that the fuzzer makes (the checks encrypt it with the keys of the test vector A.8, so the fuzzer gets past the tag) |
| `pack_with_object` | a packed object with a DEFLATE stream that the fuzzer makes (the path of ADR 0016) |
| `encryption` | `decrypt`, `open_seal` and `ReadPublicKey::from_bytes` on any input |
| `chunker` | the fixed-size chunker, for any pieces that the source gives |

## Run it on your machine

This folder is a workspace of its own, and it needs a nightly toolchain. The date is in
`rust-toolchain.toml`, and rustup installs it on the first command.

```sh
cargo install cargo-fuzz --locked --version 0.13.2
cargo run -p nilperit-fuzz --bin seed-corpus -- fuzz/corpus   # valid input to start from
cd fuzz
cargo fuzz run canonical -- -max_len=65536 -rss_limit_mb=2048 -timeout=20
```

`cargo fuzz list` shows the targets. The corpus, the artifacts and the build are not kept in the
repository (see `.gitignore`).

## In CI

The workflow `Fuzz` (`.github/workflows/fuzz.yml`) runs every target, one job each:

- every Sunday, for 10 minutes, with the corpus of the last run;
- by hand, for the number of seconds that you give;
- for a pull request that changes `fuzz/`, `crates/fuzz/` or the workflow, for 30 seconds each, to
  see that the targets still build and run.

It is not a required check. When a target fails, the input is kept as an artifact (90 days), and
the summary of the run says how to run it again. A failed run is a finding: fix the code, and copy
the input to `crates/fuzz/regressions/<target>/`.

## Add a check

1. The function in `crates/fuzz/src/checks.rs`, and its name in `TARGETS`.
2. Its seeds in `crates/fuzz/src/seeds.rs`, and its name in the list of `mutation_tests!`.
3. The target here: `fuzz_targets/<name>.rs` (copy one), and a `[[bin]]` in `Cargo.toml`.
4. The name in the matrix of `.github/workflows/fuzz.yml`.

A test of `nilperit-fuzz` fails when one of these is missing.
