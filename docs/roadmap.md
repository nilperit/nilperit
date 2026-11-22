# Roadmap

> **Not normative.** This is a working plan and it changes. The rules are in [format.md](format.md). What must be settled before the format is frozen is in [pre-v1.md](pre-v1.md).

## Where we are

Pre-alpha. The format is specified far enough to build a first working system. The format crate and the crypto crate are done: the strict CBOR check, the envelope, all object types that the first system needs (content object, item record, delta entry, snapshot header, object table), the pack structure, the vault config, key derivation from the recovery phrase, authenticated encryption, and the seal. Every part has test vectors in [format.md](format.md) appendix A.

Nothing yet reads or writes a vault on disk. The reader crate and the writer crate are empty.

## The first working system

The goal is four commands: `nilperit init`, `nilperit sync <folder>`, `nilperit ls`, and `nilperit restore`. A local folder goes into a vault and comes back out.

The order of work. Each step is its own pull request:

1. **The reader** (`nilperit-reader`):
   - an async storage trait that does not depend on a runtime, so the browser can use `fetch` later (range read, read all, list, and write and rename for the writer);
   - opening a vault: the two config copies, the MAC, and the choice of the newest valid copy;
   - opening a pack: the footer, the trailer, the header, the seal, and the object table;
   - replaying the journal: snapshot headers, the head, and the delta entries;
   - reading the content of an item: item record, content object, chunks, decompression, and the check of every ID.
2. **The writer** (`nilperit-writer`): the chunker, the pack builder, the commit procedure (temporary file, sync, rename, in the order of format.md section 8), the writer lock, and the trait that connectors implement.
3. **The local folder connector and the `nilperit` binary.** The file-system storage lives in a small crate of its own, because the reader must stay free of runtimes and file-system code.

### What the first system leaves out on purpose

- Checkpoints, trees, archive trees, item maps, and index segments. They are caches or later optimizations. A reader can rebuild what it needs by scanning pack trailers and replaying delta entries.
- Retention, condemn, and sweep. Nothing is ever deleted.
- Parity data, replicas, scrub, and repair.
- The browser reader and the reader-only recovery binary.
- Sources in the vault. A source (name, connector, priority) lives in the local configuration of the node for now. The vault will get it before format version 1 (see pre-v1.md).
- Gmail and other cloud connectors. The local folder comes first.

### Decisions that are still open

- **The chunker's gear table.** The proposal is in pre-v1.md, under "Chunking".
- **The crate for command-line arguments.** The preference is `clap` with a reduced set of features (about 12 crates in total). The alternative is a small parser without dependencies, such as `lexopt`, with hand-written help text. We decide when we write the binary.

## After the first working system

- A Gmail connector (OAuth, raw messages, the history ID as connector cursor).
- Checkpoints, trees, and item maps, so that large vaults open fast.
- The browser reader (WebAssembly) and the reader-only recovery binary.
- Retention, condemn, and sweep.
- Parity data, scrub, and repair from replicas.
- Everything in [pre-v1.md](pre-v1.md), before format version 1.
