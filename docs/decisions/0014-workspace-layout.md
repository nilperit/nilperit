# 0014. Workspace layout and a reader-only binary

- Status: Accepted (may adapt as the code grows)
- Date: 2026-11-21

## Context

Every vault must carry a reader (see 0011). That reader should be small, static, easy to audit, and must not contain writer, network or OAuth code. The browser needs the same reader and crypto code as WebAssembly (see 0003), and in the browser all I/O (`fetch`) is asynchronous.

## Decision

A Cargo workspace with a strict one-way dependency direction:

```
nilperit-format   ─┐  object types, CBOR, schema generation   (no I/O, builds for wasm32)
nilperit-crypto   ─┤  key derivation, seal/open, AEAD          (no I/O, builds for wasm32)
                   ▼
nilperit-reader ─────────► nilperit-wasm     wasm-bindgen wrapper around reader + crypto
  open, read, verify,  └──► nilperit-recover  reader-only binary
  salvage; I/O behind a trait; builds for wasm32
                   ▼
nilperit-writer      chunking, packs, commits, retention, sweep, replication
                   ▼
nilperit-connector-* one crate per source (fs, gmail, …)
nilperit-node        daemon: scheduler, API, reporting, embedded UI
```

Rules:
- `nilperit-format`, `nilperit-crypto` and `nilperit-reader` build for `wasm32-unknown-unknown`.
- These three crates do not depend on network clients, OAuth crates, or a specific async runtime (such as tokio). The reader's storage trait may be async, so the browser can implement it with `fetch` and native code with the file system.
- `nilperit-wasm` and `nilperit-recover` depend on the reader side only, never on the writer.

Binaries:
- `nilperit`: full CLI and node.
- `nilperit-recover`: reader only (list, extract, verify, salvage).

## Consequences

- Because of the crate split, the reader-only binary and the browser module physically cannot contain writer or network code.
- A small audit surface for the code that ships inside every vault.
- The reader must stay runtime-agnostic, which rules out some convenient crates.
- More crates to maintain than a single crate would need.

## Alternatives considered

- **One crate with Cargo features:** easy to get wrong; a feature can pull in a dependency unnoticed.
- **A synchronous-only reader:** simpler, but it cannot run in the browser, where I/O is async.
