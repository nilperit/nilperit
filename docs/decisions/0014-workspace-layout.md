# 0014. Workspace layout and a reader-only binary

- Status: Accepted (may adapt as the code grows)
- Date: 2026-11-21

## Context

Every vault must carry a reader (see 0011). That reader should be small, static, easy to audit, and must not contain writer, network or OAuth code. The browser needs the same reader and crypto code as WebAssembly.

## Decision

A Cargo workspace with a strict one-way dependency direction:

```
nilperit-format   ─┐  object types, CBOR, schema generation   (no I/O, builds for WASM)
nilperit-crypto   ─┤  key derivation, seal/open, AEAD          (no I/O, builds for WASM)
                   ▼
nilperit-reader      open a vault, read, verify, salvage       (no network, no OAuth)
                   ▼
nilperit-writer      chunking, packs, commits, retention, sweep, replication
                   ▼
nilperit-connector-* one crate per source (fs, gmail, …)
nilperit-node        daemon: scheduler, API, reporting, embedded UI
nilperit-wasm        wasm-bindgen wrapper around reader + crypto
```

Binaries:
- `nilperit`: full CLI and node.
- `nilperit-recover`: reader only (list, extract, verify, salvage).

## Consequences

- Because of the crate split, the reader-only binary physically cannot contain writer or network code.
- A small audit surface for the code that ships inside every vault.
- More crates to maintain than a single crate would need.

## Alternatives considered

- **One crate with Cargo features:** easy to get wrong; a feature can pull in a dependency unnoticed.
