# 0019. The fields of the item record, delta entry and snapshot header

- Status: Accepted
- Date: 2026-11-22

## Context

ADR 0007 and ADR 0009 describe what these three objects hold, but not their exact fields. A first working system needs them: the item record says what an item is, the delta entry says what changed in a synchronization, and the snapshot header commits it.

## Decision

- **Native IDs are byte strings, not text.** The names of files on Linux are arbitrary bytes. A connector that has text IDs (for example Gmail) puts the UTF-8 bytes in.
- **Times are integers: milliseconds since 1970, in UTC.** One representation for all objects, and it sorts. A connector that has a finer time keeps it in its own metadata field.
- **Source IDs and snapshot IDs are 16 random bytes.** They carry no information, so the objects and the file names of a vault say nothing about its owner or about when snapshots were made. The `time` field is the time, and sequence numbers give the order, because clocks can be wrong.
- **The item record has the title, the modified and created times, the size, the media type, opaque metadata, and the content object IDs.** Optional fields are absent when the source does not have them. The metadata can be any deterministic CBOR, so a connector is free in what it stores and a person can still read it with a generic CBOR tool.
- **A delta entry lists the changes in two arrays**: changed (new or a new version) and deleted. Each is sorted by item key, with each item key at most once in the entry. The sort order makes the bytes, and so the object ID, a function of the changes only. Whether an item is new follows from the state before the entry, so the entry does not store it.
- **The first entry of a journal has sequence number 1 and no parent.** The parent is present if and only if the sequence number is above 1.
- **A writer writes one delta entry for each commit.** A very large first synchronization is many delta entries, not one very large one.
- **The snapshot header has an optional item map root.** The item map is a cache that the first working system does not make, so the field is not present until it does.
- **The snapshot header repeats the essential vault config fields** under the same numbers as the config, so one description of those fields covers both.
- **A snapshot header file is named after its snapshot ID.** The files never collide, and a reader can check that a file has the name of its content.

## Consequences

- A reader can show an item from its item record alone, and can replay a journal from the delta entries and the snapshot headers alone.
- A time of millisecond precision loses finer file times. The metadata can hold them.
- A vault of millions of items has many delta entries, which a checkpoint later summarizes.

## Alternatives considered

- **Text native IDs:** easier to read, but they cannot represent every file name.
- **Seconds, or nanoseconds, since 1970:** seconds lose the precision that file systems have. Nanoseconds in a 64-bit integer only cover the years 1678 to 2262.
- **Three arrays (added, changed, deleted):** a reader sees at once what is new, but the information is redundant: it follows from the state before the entry. Redundant data can disagree with itself, and a delete plus an add of the same item would need two commits.
- **One array of changes with a kind field:** the same redundancy, and an enum code on top.
- **A time in the snapshot ID:** the file names would sort by time. That is only a convenience for people and for some file systems. It puts information in a name that has no function. Names carry no information.
- **Maps with text keys:** easier to read, but larger and slower, and the schema dictionary already gives the names of the integer keys.
