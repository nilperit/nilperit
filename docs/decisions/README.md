# Architecture decision records

This folder records the significant design decisions of NilPerit: what we decided, why, and what we gave up. The normative rules live in [format.md](../format.md); these records explain the reasoning behind them.

ADRs are written in plain English (not STE), because rationale and trade-offs read badly in a controlled language.

## Process

- One decision per file: `NNNN-short-title.md`, numbered in order.
- Copy [0000-template.md](0000-template.md) to start a new one.
- **Until format version 1**, ADRs may be corrected in place. The whole design is still a draft, and all ADRs so far were accepted together on one day; superseding them one by one would only add noise.
- **From format version 1 on**, accepted ADRs are not rewritten. To change a decision, write a new ADR that supersedes the old one, and set the old one's status to "Superseded by NNNN". Fixing typos and broken links is always allowed.

## Index

| #                                             | Title                                                       | Status   |
| --------------------------------------------- | ----------------------------------------------------------- | -------- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions                               | Accepted |
| [0002](0002-archive-first-raw-originals.md)   | Archive first, raw originals byte for byte                  | Accepted |
| [0003](0003-rust-core-svelte-ui.md)           | Rust for the core, Svelte for the UI, decrypt in the client | Accepted |
| [0004](0004-key-hierarchy-write-only-node.md) | Key hierarchy and the write-only node                       | Accepted |
| [0005](0005-content-addressed-vault.md)       | Content-addressed vault with chunking profiles              | Accepted |
| [0006](0006-cbor-and-embedded-schema.md)      | Deterministic CBOR with an embedded schema                  | Accepted |
| [0007](0007-truth-cache-journal.md)           | Truth vs cache: change journal with checkpoints             | Accepted |
| [0008](0008-packs-and-commits.md)             | Packs, commit order and not trusting the file system        | Accepted |
| [0009](0009-sources-and-priority.md)          | Sources as account plus selection, with priority            | Accepted |
| [0010](0010-retention-condemn-sweep.md)       | Two kinds of retention; condemn now, sweep later            | Accepted |
| [0011](0011-versioning-and-bundled-reader.md) | Versioning and the bundled reader                           | Accepted |
| [0012](0012-post-quantum-hybrid.md)           | Hybrid post-quantum encryption from day one                 | Accepted |
| [0013](0013-integrity-and-degradation.md)     | Integrity, optional parity and graceful degradation         | Accepted |
| [0014](0014-workspace-layout.md)              | Workspace layout and a reader-only binary                   | Accepted |
| [0015](0015-hash-domains-and-object-ids.md)   | Hash domains and object IDs                                 | Accepted |
| [0016](0016-compression.md)                   | Compression recorded per object                             | Accepted |
| [0017](0017-pack-layout.md)                   | Pack layout                                                 | Accepted |
| [0018](0018-keys-seal-and-vault-config.md)    | Keys, the seal and the vault config                         | Accepted |
| [0019](0019-item-record-journal-and-snapshot-fields.md) | The fields of the item record, delta entry and snapshot header | Accepted |
