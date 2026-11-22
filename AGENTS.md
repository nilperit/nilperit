# AGENTS.md

Instructions for AI coding agents (and a quick orientation for humans) working on NilPerit.

## What this project is

NilPerit is a personal backup system. It pulls data from cloud services and local sources into an encrypted, versioned, deduplicated vault that the user controls. Status: pre-alpha. The format is a draft and changes freely until format version 1.

## Read these first

1. [`docs/format.md`](docs/format.md) — the normative vault format. It is the source of truth for how data is stored.
2. [`docs/glossary.md`](docs/glossary.md) — every technical term. Use these terms with these meanings only.
3. [`docs/overview.md`](docs/overview.md) — an informal explainer with diagrams. Not normative, but it must match `format.md`.
4. [`docs/decisions/`](docs/decisions/) — architecture decision records: why things are the way they are.
5. [`docs/pre-v1.md`](docs/pre-v1.md) — what must be decided or checked before format version 1. Add an item there when you park a decision or find a gap that you do not fix now.
6. [`docs/roadmap.md`](docs/roadmap.md) — what we build next and in which order, and what the first working system leaves out.

If the code and `format.md` disagree, stop and ask. Do not silently follow either one.

## Non-negotiable principles

- **Nothing is lost.** No code path may remove stored data except retention via condemn → sweep (ADR 0010).
- **Truth vs cache.** Only chunks, content objects, item records, journal entries, checkpoint trees and archive trees are truth. Everything else must be rebuildable from them (ADR 0007).
- **Stable object IDs.** An object ID is a keyed hash of the stored plaintext bytes. Never decode and re-encode a stored object to hash or copy it (format.md §4.7–4.9).
- **Damage stays local.** Never design a structure where one damaged file makes unrelated data unreadable.
- **The write-only node.** Code that runs on a node must never require the private part of the read key (ADR 0004).
- **No connection secrets in the vault.** OAuth tokens, API keys and passwords of a source stay on the node, and so does the node credential. Never write them to the vault in any key class (ADR 0004).
- **Deterministic encoding.** Objects that are hashed must always encode to the same bytes (ADR 0006).
- **Readers read every older format version.** Never break reading of an existing format version (ADR 0011).

## Design preferences

These are the choices that the maintainers made again and again. Follow them when a detail is open, and say what your choice gives up.

- **Strict and simple.** A reader rejects a whole pack or object whose schema version, algorithm name or compression name it does not know. Do not add partial recovery of data from mixed versions: the newer reader is in the vault (ADR 0011). Ignoring unknown fields is resilience, not a compatibility mechanism.
- **One source of truth.** Do not store data that follows from other data, because the two can disagree. Example: a delta entry has no "added" list, because "new" follows from the state before it (ADR 0019).
- **Writer policy is not format.** The format records what a writer did, not how it decides. Example: which objects to compress and with what (ADR 0016).
- **Names carry no information.** IDs and file names are random. Put information in a name only when it has a function (ADR 0019).
- **Write accepted risks down.** Record them in an ADR or in `docs/pre-v1.md`. Do not add mechanisms against threats that the maintainers judged unlikely.

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
- Never log, print or include in error messages: keys, the recovery phrase or plaintext content. Never put item titles or file names in logs or in error values: they leave the machine in log files, mail and support bundles. The command-line program may show them as its direct output to the person at the terminal: always for `ls`, and with `-v` for `sync` and `restore`.
- Use widely used, well-reviewed crypto crates (RustCrypto, `blake3`). Check the audit status of a crate before it handles key material, and record it in the pull request (current known status: `docs/decisions/0012-post-quantum-hybrid.md`). Never implement cryptographic primitives yourself.
- Add tests with every change. For format code, add round-trip and test-vector tests.
- Tests run on Linux and on Windows (CI). A test must not assume the separator of a path of the system (a native ID and a path of the vault always use `/`), a name that every file system accepts (Windows has other rules), or Unix permission bits. Put what is only true on Unix behind `#[cfg(unix)]`.
- Make a test vector with an implementation other than the one under test (for example a Python script), so that it checks the specification and not only the code. Check that the hex in `docs/format.md` is the hex that the tests use.

## Documentation conventions

- `docs/format.md` and `docs/glossary.md` are written in loose ASD-STE100 Simplified Technical English with RFC 2119 keywords: short sentences, one statement per sentence, active voice, consistent terms.
- ADRs are plain English. Until format version 1, ADRs may be corrected in place. From format version 1 on, do not rewrite an accepted ADR; add a new one that supersedes it.
- A change to the format updates `format.md` in the same pull request, and updates `docs/overview.md` when the change affects anything the overview explains.
- `docs/overview.md` is plain English and not normative. When it and `format.md` disagree, `format.md` wins and the overview gets fixed.
- A new term goes into the glossary before it is used elsewhere.
- Use American English spelling in all documents and code comments.

## Git and pull requests

- Never push to `main`. Work on a branch and open a pull request; `main` only accepts squash merges.
- Pull request titles follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`). The title becomes the commit message on `main`.
- Keep pull requests small and focused on one change.
- Update a branch with a rebase onto `main`, and push it with `git push --force-with-lease`. Do not merge `main` into a branch. Ask first if someone else may have the branch checked out.
- Before you open a pull request, run what CI runs: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, `cargo check --locked --target wasm32-unknown-unknown -p nilperit-format -p nilperit-crypto -p nilperit-reader`, `scripts/check-layering.sh`, and `cargo deny check`.

## Security rules for CI and dependencies

- GitHub Actions: pin every action to a full commit SHA; set explicit `permissions:` per workflow (read-only by default); never use `pull_request_target` with a checkout of PR code; never put `${{ github.event.* }}` directly in a `run:` script — pass it through an environment variable.
- Never add self-hosted runners.
- Never commit secrets, OAuth client secrets or tokens. Local configuration stays out of the repository.
- Frontend (when it exists): minimal dependencies, `npm ci --ignore-scripts`, a strict Content Security Policy. The frontend never handles keys or storage logic.
- Prefer few, well-maintained dependencies. Justify each new one in the pull request.
