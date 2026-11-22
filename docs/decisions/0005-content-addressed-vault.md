# 0005. Content-addressed vault with chunking profiles

- Status: Accepted
- Date: 2026-11-21

## Context

Deletions at the source must not purge the backup, but storing every edit as a full copy would explode storage. Different data types (small emails, documents, video) chunk best at different sizes. The design must not assume the data fits in RAM; storage capacity is the only limit.

## Decision

- The vault is a **content-addressed chunk store**. Content is cut with FastCDC; each chunk is identified by a keyed BLAKE3 hash of its plaintext, then optionally compressed (see ADR 0016) and encrypted.
- Chunk size is **not global**. The vault config holds an append-only table of **chunking profiles** (algorithm, min/avg/max). Each content object records its profile. The node chooses a profile from what the data *is* (size, media type, connector hint), never from which source it came from, so identical bytes from different sources still deduplicate.
- Initial profiles: *small* (no cutting, below about 64 KiB), *default* (about 256 KiB average), *large* (about 2–4 MiB average).
- The **chunker seed** is secret and fixed per vault, so chunk-size patterns cannot fingerprint known files.

## Consequences

- An edit stores only the changed chunks. A deletion is only the absence of an item in the next snapshot.
- Changing profile selection rules later never breaks anything; it only affects the deduplication ratio.
- Data chunked with different profiles does not deduplicate. Selecting by data properties keeps this rare.

## Alternatives considered

- **One fixed chunk size per vault:** simpler, but a poor fit for both tiny emails and large video.
- **Side-by-side copies per version:** simple, but storage grows without bound.
