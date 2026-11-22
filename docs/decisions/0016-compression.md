# 0016. Compression recorded per object

- Status: Accepted
- Date: 2026-11-22

## Context

Text-like data (email, documents) compresses well. Photos, video and archives do not. The earlier draft said "compress chunks with zstd, but never already-compressed data". That fixed one algorithm and one policy in the format. It also left open where a reader finds out how an object was compressed. A reader has to know this before it can use the object.

Object IDs are keyed hashes of the bytes before compression (ADR 0015), because compressor output is not stable across versions and settings. So compression must be a storage detail that never changes an object's identity.

## Decision

- Compression happens **before encryption**. Encrypted data does not compress, and compressing first means less data to encrypt. The other order has no use.
- The **object table** records, for each object, a **compression** name (a short text string, so a person or an external tool can read it without a table of magic numbers), the **unpacked size** (the size before compression) and the **packed size** (the bytes in the pack).
- The first algorithms are `none` and `deflate` (raw DEFLATE, RFC 1951). More algorithms can follow, and risky ones can be opt-in.
- A reader checks the AEAD tag **before** it decompresses, and decompresses to **exactly the unpacked size**. It rejects any other output. This bounds the work and the memory that damaged or hostile data can cause.
- A reader **rejects a pack that has an object with an algorithm it does not know**, like it does for an unknown algorithm in the pack header. An older reader never gets this far, because it stops at a newer format version (ADR 0011). A pack that mixes versions can only come from a bug, and the newer reader is in the vault. Recovering part of such a pack is forensics, not a goal.
- **Which objects to compress, and with what, is writer policy**, not format. A writer can try several algorithms, keep the smallest result, skip data that does not shrink, or let the owner choose. The old rule "never compress already-compressed data" is gone from the format.
- Files outside packs are not compressed. They are small.
- Planned implementation: the `miniz_oxide` crate. It is pure Rust, builds for `wasm32-unknown-unknown`, and forbids `unsafe` code (checked in version 0.9.1). Its audit status is not known. Record it in the pull request that adds the crate (AGENTS.md).

## Consequences

- A reader can decode any object from its table entry alone, and a vault can be analyzed for compression ratio without a read key.
- Object IDs and replicas are unaffected: two replicas can compress the same object differently, and repair still works (ADR 0013).
- DEFLATE is readable with the standard library of nearly every language, which fits "a vault can be read without NilPerit".
- DEFLATE has a lower ratio and speed than zstd. We accept this for a first version. The object table can name another algorithm later without a format change.
- **Side channel.** The size of an encrypted object follows its compressed size, so someone who sees the packs can estimate how well a chunk compressed. The chunker seed is secret, so they do not know the chunk boundaries. This mostly tells text from already-compressed data. An attack that learns secrets from compressed sizes (like CRIME and BREACH) needs attacker-chosen text and a secret in the same compressed unit, and many guesses with visible sizes. A compressed unit is one chunk of one item and never mixes items, so we accept this risk. An owner who wants to remove it can use `none` for a source, which needs no format change.
- The object table must be CBOR (a text string field). Its exact encoding is still open.
- **Hostile compressed data.** The AEAD tag covers the compressed bytes, so outsiders cannot make data that a reader accepts. A compromised node is different: it holds the writer key and the public read key, so it can write authenticated objects with crafted compressed bytes (ADR 0004). A separate MAC would not help, because the node could compute it too, and a MAC that it cannot compute would need the private read key. The defense is in the decoder: a memory-safe decompressor (no `unsafe` code that depends on its input) and an output limit equal to the unpacked size. This is also why a decoder with custom `unsafe` code is a worse choice for the reader.
- **Residual risk.** No decompressor is free of bugs. A compromised node is already a serious event, and it exposes metadata but not contents (ADR 0004), so we accept this risk. We limit the damage with memory safety, the output limit, the sandboxed WebAssembly reader (ADR 0003), the advisory checks in CI (`cargo deny`), and, when the decoder is added, a fuzz target for the decompress-and-verify path.

## Alternatives considered

- **One compression algorithm per pack (header only):** simple, but it cannot say "this chunk did not shrink, so it is stored as is".
- **A prefix byte inside the encrypted object:** self-describing, but a reader learns the algorithm only after decryption, and it needs a magic byte table.
- **Numeric algorithm IDs:** smaller, but a person reading the table needs a lookup.
- **zstd or LZ4 first:** better ratio or speed. `ruzstd` is a decoder only and has custom `unsafe` code. `lz4_flex` is safe with its default features and is a fine later option. DEFLATE is the most widely readable.
- **Encrypt, then compress:** pointless. Ciphertext is indistinguishable from random bytes.
