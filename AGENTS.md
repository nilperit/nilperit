# AGENTS.md

Instructions for AI coding agents (and a quick orientation for humans) working on NilPerit.

## What this project is

NilPerit is a personal backup system. It pulls data from cloud services and local sources into an encrypted, versioned, deduplicated vault that the user controls. Status: pre-alpha. The format is a draft and changes freely until format version 1.

## Read these first

1. [`docs/format.md`](docs/format.md) — the normative vault format. It is the source of truth for how data is stored.
2. [`docs/glossary.md`](docs/glossary.md) — every technical term. Use these terms with these meanings only.
3. [`docs/decisions/`](docs/decisions/) — architecture decision records: why things are the way they are.

If the code and `format.md` disagree, stop and ask. Do not silently follow either one.

## Non-negotiable principles

- **Nothing is lost.** No code path may remove stored data except retention via condemn → sweep (ADR 0010).
- **Truth vs cache.** Only chunks, content objects, item records, journal entries, checkpoint trees and archive trees are truth. Everything else must be rebuildable from them (ADR 0007).
- **Stable object IDs.** An object ID is a keyed hash of the stored plaintext bytes. Never decode and re-encode a stored object to hash or copy it (format.md §4.7–4.9).
- **Damage stays local.** Never design a structure where one damaged file makes unrelated data unreadable.
- **The write-only node.** Code that runs on a node must never require the private part of the read key (ADR 0004).
- **Deterministic encoding.** Objects that are hashed must always encode to the same bytes (ADR 0006).
- **Readers read every older format version.** Never break reading of an existing format version (ADR 0011).

## Workspace layout

Strict one-way dependencies (ADR 0014):

```
nilperit-format, nilperit-crypto   (no I/O; must build for wasm32)
        ▼
nilperit-reader ──────────► nilperit-wasm, nilperit-recover
(I/O behind a trait; must build for wasm32)
        ▼
nilperit-writer
        ▼
nilperit-connector-*, nilperit-node
```

- Never add a dependency that points "upward" (for example reader → writer).
- `nilperit-format`, `nilperit-crypto` and `nilperit-reader` must build for `wasm32-unknown-unknown`.
- `nilperit-format`, `nilperit-crypto` and `nilperit-reader` must not depend on network clients, OAuth crates or a specific async runtime (such as tokio). Async traits are allowed in the reader, so the browser can use async `fetch` behind the storage trait.
- `nilperit-wasm` and `nilperit-recover` depend on the reader side only, never on the writer.

## Code conventions

- Rust stable, pinned in `rust-toolchain.toml`. Format with `cargo fmt`; `cargo clippy` must pass without warnings.
- No `unsafe` unless there is no alternative; every `unsafe` block needs a `// SAFETY:` comment.
- Never log, print or include in error messages: keys, the recovery phrase, plaintext content, item titles or file names.
- Use widely used, well-reviewed crypto crates (RustCrypto, `blake3`). Check and record the audit status of a crate before it handles key material. Never implement cryptographic primitives yourself.
- Add tests with every change. For format code, add round-trip and test-vector tests.

## Documentation conventions

- `docs/format.md` and `docs/glossary.md` are written in loose ASD-STE100 Simplified Technical English with RFC 2119 keywords: short sentences, one statement per sentence, active voice, consistent terms.
- ADRs are plain English. Do not rewrite an accepted ADR; add a new one that supersedes it.
- A change to the format updates `format.md` in the same pull request.
- A new term goes into the glossary before it is used elsewhere.
- Use American English spelling in all documents and code comments.

## Git and pull requests

- Never push to `main`. Work on a branch and open a pull request; `main` only accepts squash merges.
- Pull request titles follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`). The title becomes the commit message on `main`.
- Keep pull requests small and focused on one change.

## Security rules for CI and dependencies

- GitHub Actions: pin every action to a full commit SHA; set explicit `permissions:` per workflow (read-only by default); never use `pull_request_target` with a checkout of PR code; never put `${{ github.event.* }}` directly in a `run:` script — pass it through an environment variable.
- Never add self-hosted runners.
- Never commit secrets, OAuth client secrets or tokens. Local configuration stays out of the repository.
- Frontend (when it exists): minimal dependencies, `npm ci --ignore-scripts`, a strict Content Security Policy. The frontend never handles keys or storage logic.
- Prefer few, well-maintained dependencies. Justify each new one in the pull request.
