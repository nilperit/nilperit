# 0004. Key hierarchy and the write-only node

- Status: Accepted
- Date: 2026-11-21

## Context

Keys must be owned by the user, never by a cloud service. A node may run unattended on a server or in Kubernetes, so it must start without a person typing a secret. A stolen or compromised server should not expose the backup.

## Decision

- At vault creation, NilPerit generates a 32-byte **root seed**, shown once as a 24-word **recovery phrase** (BIP39). All keys derive from it.
- Derived keys: **read key** (hybrid key pair, owner only), **dedup key** (keyed hash for object IDs, item keys and content hashes, with a separate derived domain key per kind), **writer key** (symmetric; opens all W objects).
- The **node credential** (read public key, dedup key, writer key) lets a node add data but not read stored content.
- Objects get a **key class**: *R* for content and descriptive data (chunks, item records), which only the read key opens; *W* for the structure the node must read back (content objects, journal entries, trees, pack object tables), which the writer key opens. The owner can open both.
- There is **one model only**: a single-PC setup simply holds both the node credential and the read key. No separate "simple mode".
- A passphrase-encrypted copy of the seed may later be offered as a convenience, on the owner's own targets only — never on third-party storage, where it could be brute-forced offline.

## Consequences

- Recovery from any copy needs only the recovery phrase.
- A compromised node reveals opaque item keys, object IDs, sizes, sharing structure and sync times — never contents, subjects, file names or attachments.
- With the dedup key, an attacker who controls the node could test whether a specific known file is in the vault ("confirmation of file"). Outsiders without the credential (disk thieves, future peers) learn nothing.
- The dedup key on the node is unavoidable: the node must compute object IDs itself. An unkeyed hash would let *anyone* with a copy test for known files.

## Alternatives considered

- **Node holds the full key, unlocked at start:** simpler, but a stolen server means a readable backup.
- **Unkeyed content hashes:** no secret on the node, but leaks file presence to every holder of a copy.
