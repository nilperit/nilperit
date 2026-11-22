# 0007. Truth vs cache: change journal with checkpoints

- Status: Accepted
- Date: 2026-11-21

## Context

Losing a piece of storage must never invalidate everything. If metadata (item maps, snapshot headers) were the only record of what exists and when, losing it would hide many items even though their data is intact. Item records alone say *what* existed, but not *when* something was deleted, and they are immutable, so they cannot be updated later. History must also be easy to cut off without affecting the current state, much like a shallow git history.

## Decision

- **Truth** is only immutable data stored with the content in data packs: chunks, content objects, item records, **journal entries**, **checkpoint trees** and **archive trees**.
- Each source has an append-only **journal**:
  - a **delta entry** per sync, with only the changes;
  - periodic **checkpoints** with the complete state at that moment, including the connector cursor. A checkpoint points to two trees, both stored as truth and sharing unchanged subtrees like a git commit:
    - the **checkpoint tree**: every item that exists at that moment;
    - the **archive tree**: every item version that no longer exists but that item retention still keeps (old versions and deleted items), with first-seen and last-seen times.
- **Current state = newest checkpoint + the deltas after it.** Checkpoints are written every N deltas or after a set time, so replay stays short.
- **Cutting history** = choosing a checkpoint as the new base, making sure its archive tree holds every retained item version, then condemning everything before it. The current state and the retained archive never depend on entries before that checkpoint. The connector cursor is in every delta entry and every checkpoint, so a connector can continue after history is cut, instead of reading the source again.
- Item maps, archive maps, the index and snapshot headers are **caches**, rebuildable from the truth. Item maps and checkpoint trees share the same tree structure; the difference is that a checkpoint tree is stored as truth at checkpoint moments, while an item map is a view built for any snapshot.
- An item record lives in the same data pack as its content.

## Consequences

- Losing metadata packs costs time (a rebuild by scanning data packs), never data.
- Losing a data pack costs only the items stored in it.
- Metadata needs no special extra protection.
- Journal entries are small deltas, so the cost is low.
- Without the archive tree, cutting history would leave the archive map (a cache) as the only record of deleted items. The archive tree closes that gap.

## Alternatives considered

- **Snapshots as the only truth:** simpler, but metadata loss hides intact data, and cutting history is harder.
- **Pure event log without checkpoints:** replay grows without bound and history cannot be cut cleanly.
