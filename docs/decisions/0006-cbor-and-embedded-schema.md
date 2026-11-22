# 0006. Deterministic CBOR with an embedded schema

- Status: Accepted
- Date: 2026-11-21

## Context

Objects must stay readable for decades, possibly by tools other than NilPerit. The format must evolve without breaking old vaults. Objects are hashed for content addressing, so one object must always encode to the same bytes.

## Decision

- All objects use **CBOR (RFC 8949)** with **deterministic encoding**.
- Maps use **small integer keys** for compactness (COSE style), via the `minicbor` crate.
- Each vault carries, in plaintext, a **schema dictionary** in CDDL (RFC 8610) that maps every object type, version and field number to a name, type and description, plus a copy of `docs/format.md` named `FORMAT.md`.
- The schema dictionary is generated from the Rust types at build time; a test fails when the code and the committed schema disagree.
- **Object IDs** are keyed BLAKE3 hashes of the stored plaintext bytes, with the object type in front (see ADR 0015). They do not depend on the random encryption nonce, so the same object has the same ID in every replica.
- **Stored bytes are never re-encoded.** IDs are computed over the stored plaintext bytes, and objects are copied as bytes. Otherwise a decoder that skips unknown fields would drop them on re-encoding and silently change the ID.

## Consequences

- Self-describing: a future reader with any CBOR tool and the dictionary can decode everything.
- Additive evolution: decoders ignore unknown fields. This is only safe together with the no-re-encoding rule.
- Native byte strings for hashes and keys, without base64.
- Slightly larger than a pure binary format; the difference mostly disappears after compression.

## Alternatives considered

- **JSON:** text, no byte strings, not deterministic by default.
- **MessagePack:** similar to CBOR, but no standardized deterministic encoding.
- **postcard / bincode:** compact and deterministic, but not self-describing; the schema lives only in Rust code.
- **Protobuf:** needs schema files and code generation; deterministic encoding is not guaranteed.
