# 0017. Pack layout

- Status: Accepted
- Date: 2026-11-22

## Context

ADR 0008 chose packs with a header, a body, a trailer and a footer. The details were open: what is in the header, how an object is stored in the body, how the object table is encrypted, which keys encrypt W objects, and how a reader protects itself against a damaged or hostile table.

## Decision

- A pack is **header, body, trailer, footer**. The footer has a fixed size and sits at the end, so a reader finds the trailer with one read of the end of the file and fetches single objects by byte range. A writer streams the pack in one pass.
- The **header** is a small CBOR map: format version, pack class, and algorithm names as text strings. It repeats the algorithm names of the vault config, so salvage works when the config is lost.
- A **packed object** is a random 24-byte nonce, the ciphertext, and the tag. There are no gaps between packed objects, so the layout of a pack is fully determined.
- The **associated data** of a packed object is its object ID and type ID. A packed object that an attacker moves to another entry fails the tag check, with no hashing and without the dedup key.
- The **object table** is an enveloped object (type 3), encrypted with its own key. Its associated data is the hash of the header, so the header is authenticated. Entries are positional arrays, because the table is the most repetitive structure in the vault and has a schema version.
- The **pack key** for R objects stays random per pack and sealed. The layout treats the seal as opaque bytes with a size, so the choice of the key encapsulation algorithm does not change the layout.
- **W keys** derive from the writer key, one per purpose (pack objects, object tables). There is no per-pack derivation.
- **Limits** protect the reader from claims of a damaged or hostile table: 4 GiB per object, 256 MiB for the trailer, 64 KiB for the header and for the seal. Offsets are 64-bit. The limits do not limit the size of a file or of a vault, because content is chunked.
- **The pack is the unit of damage.** The trailer is a single point of failure for its pack.

## Consequences

- A reader opens a pack with a read of the end of the file (the footer, and usually the trailer in the same read) and a read of the start (the header). Then it needs one ranged read per object.
- A damaged trailer or footer makes the whole pack unreadable. Replicas and optional parity (ADR 0013) cover this. Any other place for the table would have the same problem: damage to a part of a file can never be fully avoided, so we draw the recovery boundary at the file.
- Because W keys do not depend on the pack, they need no salt in the header. The 192-bit random nonces make one key safe for very many objects.
- Binding the header into the associated data of the table means that a changed header makes the table unreadable. A changed header cannot silently change how a pack is read.

## Alternatives considered

- **Table and sealed key in the header:** a reader would not need the end of the file, but a writer would have to know the table before writing the body, and the pack could not be streamed.
- **A frame in front of each object:** it would let salvage rebuild the table from the body, at the cost of about 40 bytes for each object and a second copy of the data. Parity and replicas already cover this case.
- **Per-pack W keys with a salt in the header:** more moving parts for no gain. The node holds the writer key in any case.
- **Maps with integer keys for table entries:** easier to extend, but about 7 bytes larger for each entry. A new field means a new schema version anyway.
- **Numeric algorithm and key class codes:** smaller, but they need a lookup table, which a person who reads the vault without NilPerit does not have.
