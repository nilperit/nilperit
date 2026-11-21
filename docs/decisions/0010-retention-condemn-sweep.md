# 0010. Two kinds of retention; condemn now, sweep later

- Status: Accepted
- Date: 2026-11-21

## Context

Thinning snapshots alone loses data: an email received and deleted between two kept snapshots would vanish. Deleting data immediately is intuitive, but chunks are shared across items, snapshots and sources, so immediate deletion needs reference counts. Reference counts must change atomically with every commit; a crash can leave them wrong, and a count that is too low deletes live data. Packs are also immutable, so freeing space inside one needs a rewrite anyway.

## Decision

- **Two kinds of retention**, per source and per target:
  - **snapshot retention**: which points in time you can return to;
  - **item retention**: how long item versions and deleted items stay (via the archive map). Thinning snapshots never removes anything from the archive.
- An object stays while any rule of any source keeps it.
- **Condemn now:** after each sync, retention writes condemnation records. Nothing is deleted, and a condemnation can be revoked (for example to abandon a failed sync and start over).
- **Sweep later:** a separate, scheduled step removes packs that are condemned past a grace period *and* unreachable from the live truth; it repacks packs with more than about 30 % waste. It never uses counters.
- When a target is full: alert, pause the lowest-priority sources first, and delete nothing automatically unless the owner opted in for that target.

## Consequences

- A hiccup at worst leaves dangling data for the next sweep; it never deletes live data.
- Sweep cost scales with metadata, not data.
- The node can sweep without the read key, because journal entries and content objects carry the IDs it needs.

## Alternatives considered

- **Immediate deletion with reference counting:** fragile under crashes; a wrong count means data loss.
- **Snapshot thinning only:** loses short-lived items.
