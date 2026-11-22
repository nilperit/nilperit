# 0005. Content-addressed vault with chunking profiles

- Status: Accepted
- Date: 2026-11-21

## Context

Deletions at the source must not purge the backup, but storing every edit as a full copy would explode storage. Different data types (small emails, documents, video) chunk best at different sizes. The design must not assume the data fits in RAM; storage capacity is the only limit.

## Decision

- The vault is a **content-addressed chunk store**. Content is cut by the chunking algorithm of its profile; each chunk is identified by a keyed BLAKE3 hash of its plaintext, then optionally compressed (see ADR 0016) and encrypted.
- Chunk size is **not global**. The vault config holds an append-only table of **chunking profiles** (algorithm, min/avg/max). Each content object records its profile. The node chooses a profile from what the data *is* (size, media type, connector hint), never from which source it came from, so identical bytes from different sources still deduplicate.
- The first and only algorithm is `fixed`: chunks of one size, and a shorter last chunk. Initial profiles: *default* (256 KiB) and *large* (2 MiB). Content up to one chunk is one chunk, so small items such as email are not cut.
- We chose `fixed` and not a content-defined algorithm such as FastCDC. Appends and changes in place deduplicate with fixed chunks. Only bytes that move gain from content-defined cutting, for example an attachment at different offsets in different emails, or a tag at the top of a media file. We do not know yet how much that saves. The chunk boundaries are not visible in a pack (the object table is encrypted and objects have no markers), but a content-defined algorithm with a public table would let someone who sees range reads test for known files. When we add one, its table must come from a secret, which is what the reserved **chunker seed** is for (`docs/pre-v1.md`).

## Consequences

- An edit stores only the changed chunks. A deletion is only the absence of an item in the next snapshot.
- Changing profile selection rules later never breaks anything; it only affects the deduplication ratio.
- Data chunked with different profiles does not deduplicate. Selecting by data properties keeps this rare.

## Alternatives considered

- **One fixed chunk size per vault:** simpler, but a poor fit for both tiny emails and large video.
- **Side-by-side copies per version:** simple, but storage grows without bound.
