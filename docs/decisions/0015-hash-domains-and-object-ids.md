# 0015. Hash domains and object IDs

- Status: Accepted
- Date: 2026-11-22

## Context

NilPerit makes three kinds of keyed hash with the dedup key: object IDs, item keys and content hashes. A value of one kind must never equal a value of another kind. Otherwise two different things could get the same ID, and the vault would treat them as one.

Object IDs also need the object type. Most objects are CBOR envelopes that contain their type. A chunk is raw plaintext and contains no type. A chunk with the same bytes as an item record must still get a different ID.

## Decision

- Each kind of hash is a **hash domain**. For each hash domain, NilPerit derives a **domain key** with BLAKE3 `derive_key`. The key material is the dedup key. The context string names the domain.
- An **object ID** is the keyed BLAKE3 hash, with the object ID domain key, of the **type ID as a 4-byte little-endian integer followed by the stored bytes**.
- The type ID comes from the **object table** of the pack. For an enveloped object, it must equal the type in the envelope, and a reader rejects the object otherwise.
- The **chunk stays raw**: its stored bytes are the plaintext chunk before compression. A raw object type must have key class R. In this case, losing the pack trailer loses the pack key as well, so no object becomes unreadable but untyped.
- An **item key** hashes the source ID and the native ID with a 4-byte length in front of each, so the two parts cannot be moved against each other.
- The **content hash** is a keyed hash of the full plaintext in its own domain. It needs no prefix, so a writer can hash a large file as a stream.

## Consequences

- Hashes of different kinds cannot collide, whatever the data. This does not depend on careful numbering of tags.
- A new kind of hash needs a new hash domain, not a new rule in the hashing code.
- The node derives three domain keys when it starts. This is cheap.
- A reader needs the dedup key to verify an object ID. The AEAD tag already protects against damage, and the owner and the node both have the dedup key.
- The format has no multihash-style algorithm byte in IDs. A change of the hash function is a new format version (ADR 0011).
- Open: where an object records its compression. The hash uses the bytes before compression, because zstd output is not stable across versions.

## Alternatives considered

- **A fixed tag in front of the hashed data for every kind:** simple, but it needs one registry of tags for object types and the other kinds, and correct framing at every call site.
- **Wrapping chunks in an envelope:** every object would then contain its type. It would copy up to a few MiB per chunk and it would change a chunk from raw bytes to a CBOR item. The object table already has the type.
- **The type as a CBOR integer in front of the bytes:** also unambiguous, but it needs a CBOR encoder in the hashing code. A fixed 4-byte integer is simpler and follows the little-endian rule of the format.
