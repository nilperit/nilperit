# 0011. Versioning and the bundled reader

- Status: Accepted
- Date: 2026-11-21

## Context

A vault holds history that exists nowhere else, so "start over with a fresh backup" is never acceptable after a format change. Old software may meet a newer vault (for example a USB stick that sat in a drawer). Recovery must not depend on network access or on NilPerit still being downloadable.

## Decision

- One **format version** number, no feature flags.
- Every NilPerit version **reads all older format versions**, and should upgrade them flawlessly (lazily for new data, or rewritten via the repack machinery).
- **Older software meeting a newer vault stops** and tells the user to upgrade or use the bundled reader.
- Every header carries **algorithm IDs** (crypto, hash, compression), so future versions know what to migrate.
- **Every vault carries a reader for its own format version.** An upgrade writes the new reader in the same commit. Planned contents: static `nilperit-recover` binaries for common platforms, one self-contained offline HTML file with the WebAssembly reader, the source code, `format.md` and the schema, with hashes (and later signatures).
- If compatibility with some ancient version ever has to be dropped, that is decided then, in a new ADR.

## Consequences

- No silent corruption from version mismatches.
- Readers grow over time, because they keep all old decoders.
- The reader/writer separation must exist from day one (see 0014).
- BLAKE3 is treated as near-permanent: changing the hash function breaks deduplication between old and new data.

## Alternatives considered

- **Feature flags (compat / read-only compat / incompat):** more precise, but more complex than needed.
- **Re-backup on format change:** impossible, because deleted source data cannot be fetched again.
