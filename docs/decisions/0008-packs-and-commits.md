# 0008. Packs, commit order and not trusting the file system

- Status: Accepted
- Date: 2026-11-21

## Context

Millions of tiny files are slow, especially on USB media. A sync can crash, and a removable medium can be pulled out mid-write. Removable media often use exFAT or FAT32, which do not guarantee atomic renames.

## Decision

- Objects are bundled in immutable **packs** of about 16 MiB (configurable per target).
- Two pack classes: **data packs** (truth) and **metadata packs** (caches). A replica that disconnected early still has the full listing with names and can show what is missing.
- A pack's name is the **hash of its encrypted bytes**, so anyone can verify it without keys.
- Objects have a **key class**: *R* (chunks, item records; only the read key opens them, via a pack key sealed to it) or *W* (content objects, journal entries, trees; the writer key opens them). One pack can hold both classes.
- The **object table** in the pack trailer (object ID, type, key class, offset, length) has key class W and holds only opaque values. A write-only node can therefore read it to rebuild the index and to sweep, without the read key.
- **Commit order:** data packs → metadata packs → index segments → snapshot header last. Each file is written under a temporary name, synced, then renamed.
- Long runs commit at intervals, so a crash loses only the last few minutes.
- **Do not trust the file system:** readers ignore packs whose hash does not match their name, and reject unauthenticated snapshot headers.
- One writer per vault (lock with heartbeat); readers need no lock because files never change.

## Consequences

- Crashes and unplugging leave only harmless orphan files.
- Correctness comes from verification, not from file system guarantees.
- The index is only a cache and can be rebuilt from pack trailers, by the node itself.
- The node learns object IDs, types, sizes and layout from object tables. That is within the trade-off of ADR 0004; it never learns titles, names or content.

## Alternatives considered

- **One file per object:** simple, but slow and wasteful on small files and removable media.
- **A database (SQLite etc.) as store:** a single point of failure and harder to replicate to untrusted targets.
