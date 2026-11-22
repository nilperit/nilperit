# 0012. Hybrid post-quantum encryption from day one

- Status: Accepted
- Date: 2026-11-21

## Context

An archive is meant to last decades. Someone who copies an encrypted vault today could break classical key exchange (X25519) in the future with a quantum computer ("harvest now, decrypt later"). Post-quantum KEMs are now standardized (ML-KEM, FIPS 203) and implemented in Rust.

## Decision

- Pack keys are sealed with a **hybrid KEM: X25519 and ML-KEM-768 together**. Breaking the seal requires breaking both.
- Only pack keys are sealed this way; data is encrypted with XChaCha20-Poly1305. The extra cost is a few kilobytes per pack.
- Algorithm IDs in every header allow a later version to re-encrypt if needed.

## Consequences

- Protection against future quantum attacks on data written from now on.
- Copies taken before a future algorithm change cannot be protected afterwards; crypto agility only protects what comes next. We accept this.
- The combiner is X-Wing (draft 06), a hybrid KEM that combines X25519 and ML-KEM-768 in one defined construction (ADR 0018). It is an Internet-Draft, so the algorithm name in a vault names the draft.
- The implementation is still open. As of November 2026, RustCrypto `ml-kem` states that it has never been independently audited. `libcrux-ml-kem` (Cryspen, formally verified) is the main alternative. For comparison: RustCrypto `chacha20poly1305` was audited by NCC Group (2020), and `curve25519-dalek` by Quarkslab (2019).

## Alternatives considered

- **X25519 only:** simpler and smaller, but exposed to harvest-now-decrypt-later.
- **ML-KEM only:** loses the safety net of a mature classical algorithm if a flaw in the newer scheme is found.
