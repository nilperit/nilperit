# 0007. Truth vs cache: change journal with checkpoints

- Status: Accepted
- Date: 2026-11-21

## Context

Losing a piece of storage must never invalidate everything. If metadata (item maps, snapshot headers) were the only record of what exists and when, losing it would hide many items even though their data is intact. Item records alone say *what* existed, but not *when* something was deleted, and they are immutable, so they cannot be updated later. History must also be easy to cut off without affecting the current state, much like a shallow git history.

## Decision

- **Truth** is only immutable data stored with the content in data packs: chunks, content objects, item records, and **journal entries**.
- Each source has an append-only **journal**:
  - a **delta entry** per sync, with only the changes;
  - periodic **checkpoints** with the complete current state (an item map root, stored as truth, sharing unchanged subtrees like a git commit).
- **Current state = newest checkpoint + the deltas after it.** Checkpoints are written every N deltas or after a set time, so replay stays short.
- **Cutting history** = condemning everything before a chosen checkpoint. The current state never depends on entries before its checkpoint.
- Item maps, archive maps, the index and snapshot headers are **caches**, rebuildable from the truth.
- An item record lives in the same data pack as its content.

## Consequences

- Losing metadata packs costs time (a rebuild by scanning data packs), never data.
- Losing a data pack costs only the items stored in it.
- Metadata needs no special extra protection.
- Journal entries are small deltas, so the cost is low.

## Alternatives considered

- **Snapshots as the only truth:** simpler, but metadata loss hides intact data, and cutting history is harder.
- **Pure event log without checkpoints:** replay grows without bound and history cannot be cut cleanly.
