# Roadmap

> **Not normative.** This is a working plan and it changes. The rules are in [format.md](format.md). What must be settled before the format is frozen is in [pre-v1.md](pre-v1.md).

## Where we are

Pre-alpha. The format is specified far enough to build a first working system. The format crate and the crypto crate are done: the strict CBOR check, the envelope, all object types that the first system needs (content object, item record, delta entry, snapshot header, object table), the pack structure, the vault config, key derivation from the recovery phrase, authenticated encryption, and the seal. Every part has test vectors in [format.md](format.md) appendix A.

The reader crate is done: it opens a vault and its packs, replays the journal and reads the content of an item, behind a storage trait. A node can open a vault without the read key. The writer crate has the fixed-size chunker, the pack builder, the commit, the writer lock, the creation of a vault, the connector trait and the sync engine. All of it is tested against a vault in memory, and the reader reads back what the writer wrote. The file-system target (`nilperit-target-fs`) does the same on a folder, and a test runs the whole stack on disk. The folder connector (`nilperit-connector-fs`) reads a folder, and a test takes a folder into a vault on disk and back. `nilperit init` makes a vault, shows its recovery phrase once and saves the credential of the machine, `nilperit sync` backs up a folder into it, `nilperit ls` lists the sources and the items, and `nilperit restore` writes the files back. The first working system is complete: a folder goes into a vault, and comes back out.

## The first working system

The goal is four commands: `nilperit init`, `nilperit sync <folder>`, `nilperit ls`, and `nilperit restore`. A local folder goes into a vault and comes back out.

The order of work. Each step is its own pull request:

1. **The reader** (`nilperit-reader`):
   - an async target trait that does not depend on a runtime, so the browser can use `fetch` later. The reader's trait only reads (length, range read, read all, list). The trait that writes and renames lives in the writer crate, so a reader cannot change a vault;
   - opening a vault: the two config copies, the MAC, and the choice of the newest valid copy;
   - opening a pack: the footer, the trailer, the header, the seal, and the object table;
   - replaying the journal: snapshot headers, the head, and the delta entries;
   - reading the content of an item: item record, content object, chunks, decompression, and the check of every ID.
2. **The writer** (`nilperit-writer`): the chunker (fixed-size cutting only), the pack builder, the commit procedure (temporary file, sync, rename, in the order of format.md section 8), the writer lock, and the trait that connectors implement.
3. **The local folder connector and the `nilperit` binary.** The file-system target lives in a small crate of its own, because the reader must stay free of runtimes and file-system code.

### What the first system leaves out on purpose

- Checkpoints, trees, archive trees, item maps, and index segments. They are caches or later optimizations. A reader can rebuild what it needs by scanning pack trailers and replaying delta entries.
- Retention, condemn, and sweep. Nothing is ever deleted.
- Parity data, replicas, scrub, and repair.
- The browser reader and the reader-only recovery binary.
- Restoring an older version. `restore` gives the newest state of a source. The older states are in the journal, and no command reads them yet.
- Sources in the vault. A source (name, connector, priority) lives in the local configuration of the node for now. The vault will get it before format version 1 (see pre-v1.md).
- Gmail and other cloud connectors. The local folder comes first.

### The command-line program

The plan for step 3:

- **Crates.** `nilperit-cli` (the binary `nilperit`), `nilperit-target-fs` (the file-system target), `nilperit-connector-fs` (the folder connector). The connector trait and the sync engine (scan, chunk, build packs, commit) go in `nilperit-writer`, and are tested there with an in-memory connector. Pull requests in this order: the sync engine, the file-system target, the folder connector, then the commands `init`, `sync`, `ls` and `restore`, one pull request each.
- **One binary.** `nilperit` is also what `recovery/` ships, for now. Splitting it is a requirement before version 1 (pre-v1.md).
- **No async runtime.** The file-system target never waits, so the program needs only a small `block_on`. The node daemon will need a real runtime later.
- **Keys.** `sync` uses a node credential file (the dedup key, the writer key and the public part of the read key), written with mode 0600 and refused when others can read it. `init` writes it, and a later command exports one for another machine from the recovery phrase. The path comes from `--credential` or `NILPERIT_CREDENTIAL`. `ls` and `restore` need the read key: they ask for the recovery phrase with a no-echo prompt (`rpassword`), or read it from stdin or from `--phrase-file`. The phrase is never a command-line flag or an environment variable. `init` shows the phrase once and never writes it to disk.
- **Connection secrets** of a source (later: OAuth tokens) stay in the local configuration of the node and never go into the vault (ADR 0004).
- **Source identity.** A source ID is derived: a keyed hash of a source name, in a new hash domain `source-id`. The name is the canonical folder path, and `--name` overrides it, so that a moved folder can keep its journal. The command-line program then keeps no state. A small pull request before the sync engine adds the hash domain to format.md (3.2.5, 5.4.5.1) and to the crypto crate.
- **Arguments.** `clap` with `default-features = false` and the features `std`, `help`, `usage`, `error-context` and `derive`. That adds 7 crates: `clap`, `clap_builder`, `clap_lex`, `anstyle`, and for `derive` also `clap_derive`, `heck` and a second major version of `syn` (`quote` and `proc-macro2` are shared). Without `derive` it would be 4. The default features (colors, suggestions) would add about 11, which we do not need. The same parser can stay in the lean recovery binary. Parsing lives in one module that returns a typed command.
- **Commands.** `init <vault>`, `sync <folder> --vault <vault> [--name <name>] [--follow-symlinks]`, `ls --vault <vault>`, `restore --vault <vault> <destination>`.
- **Output.** `sync` and `restore` print counts. `-v` adds the names of the items that could not be read. `ls` always shows names.
- **Progress.** A command that takes time says what it does on the error output, so that the output stays the result. It names the step (opening the vault, reading the journal, listing the folder), and for the long steps it counts items and bytes, with a percentage and an estimate of the time that is left. On a terminal it is one line that is redrawn. When the error output is not a terminal, it is a new line every 30 seconds, so that the log of a scheduled run shows that the run is alive. A command that ends quickly shows nothing. The line has numbers and fixed words only, never a name. The sync engine reports through a callback (`sync_with_progress`) and knows nothing about terminals. A source can give the size of an item (`SourceItem::size`), so that the percentage follows the bytes.
- **Exit codes.** 0 for success, 1 for an error, 2 for arguments that are not valid, and 3 for a run that finished but could not read some items, so that cron and scripts notice a partial run without treating it as a failure.
- **`restore` is safe.** It never overwrites a file, and it rejects a native ID with `..`, an absolute path or an empty part, so that a damaged or hostile vault cannot write outside the destination.

## After the first working system

- A Gmail connector (OAuth, raw messages, the history ID as connector cursor).
- Checkpoints, trees, and item maps, so that large vaults open fast.
- The browser reader (WebAssembly) and the reader-only recovery binary.
- Retention, condemn, and sweep.
- Parity data, scrub, and repair from replicas.
- Everything in [pre-v1.md](pre-v1.md), before format version 1.
