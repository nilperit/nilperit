# 0013. Integrity, optional parity and graceful degradation

- Status: Accepted
- Date: 2026-11-21

## Context

Storage decays. A USB stick in a drawer for two years can lose bits. A local disk usually fails as a whole. Whatever happens, losing a piece of storage must never invalidate everything: we may miss some data, but the rest must stay recoverable.

## Decision

- **Detection:** an AEAD tag per object (corruption and tampering) and the pack hash as its name (checkable without keys).
- **Scrub:** periodic verification, with a rotating sample for large vaults and a quick time-limited check when a removable medium is inserted.
- **Repair** per object from any other replica; object IDs are identical everywhere, even with different packing or compression.
- **Optional parity per target** (Reed–Solomon recovery data per pack, like PAR2), chosen by the user with defaults: on for volatile media such as USB sticks and SD cards (about 10 %), off for local disks and remote targets, where whole-device failure is the bigger risk and replicas cover it.
- **Graceful degradation:** a damaged data pack only affects the items stored in it; caches are rebuilt from the truth; the vault config is mirrored and its essentials are repeated in snapshot headers and journal entries.
- **Salvage mode** in `nilperit-recover`: scan all readable packs with the recovery phrase and rebuild whatever is possible.

## Consequences

- Single damaged files have local, bounded effects.
- Parity costs space, so it is a per-target choice.

## Alternatives considered

- **Always-on parity everywhere:** wastes space where replicas already protect against the likely failure.
- **Extra protection only for metadata:** unnecessary once metadata is a cache (see 0007).
