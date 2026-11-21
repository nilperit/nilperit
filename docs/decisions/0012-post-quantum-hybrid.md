# 0012. Hybrid post-quantum encryption from day one

- Status: Accepted
- Date: 2026-11-21

## Context

An archive is meant to last decades. Someone who copies an encrypted vault today could break classical key exchange (X25519) in the future with a quantum computer ("harvest now, decrypt later"). Post-quantum KEMs are now standardised (ML-KEM, FIPS 203) and available in Rust (RustCrypto `ml-kem`).

## Decision

- Pack keys are sealed with a **hybrid KEM: X25519 and ML-KEM-768 together**. Breaking the seal requires breaking both.
- Only pack keys are sealed this way; data is encrypted with XChaCha20-Poly1305. The extra cost is a few kilobytes per pack.
- Algorithm IDs in every header allow a later version to re-encrypt if needed.

## Consequences

- Protection against future quantum attacks on data written from now on.
- Copies taken before a future algorithm change cannot be protected afterwards; crypto agility only protects what comes next. We accept this.
- The exact combiner construction is still open (see format.md, open items).

## Alternatives considered

- **X25519 only:** simpler and smaller, but exposed to harvest-now-decrypt-later.
- **ML-KEM only:** loses the safety net of a mature classical algorithm if a flaw in the newer scheme is found.
