# 0002. Archive first, raw originals byte for byte

- Status: Accepted
- Date: 2026-11-21

## Context

NilPerit's purpose is that data survives whatever happens in the cloud. Two goals compete: a browsable archive ("if all fails, we still have the documents"), and the ability to restore data back into a service. Restore needs high-fidelity metadata and per-service write logic, which is a lot of work.

## Decision

- The first goal is a complete, browsable **archive**. Restoring into services is not a v1 goal.
- We store **raw originals byte for byte** (for Gmail: the raw RFC 822 message as the API returns it), plus the service metadata (labels, IDs, thread IDs) as opaque source-specific data.
- We do not split MIME messages into parts for v1.

## Consequences

- A byte-for-byte restore stays possible later, because nothing is lost or normalized.
- The same attachment in many emails deduplicates less well (it is base64-encoded inside each message). We accept this; it is a niche case.
- A later optimization can pass cut-point hints (for example MIME part boundaries) to the chunker without a format change, because content is just a list of chunks.

## Alternatives considered

- **Decompose MIME and store attachments decoded:** better deduplication, but loses byte-for-byte fidelity unless we also store a reconstruction recipe. More complexity for little gain now.
- **Restore-first:** too much scope before the core works.
