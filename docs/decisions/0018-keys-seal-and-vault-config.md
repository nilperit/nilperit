# 0018. Keys, the seal and the vault config

- Status: Accepted
- Date: 2026-11-22

## Context

ADR 0004 and ADR 0012 chose the key hierarchy and a hybrid post-quantum seal, but left the details open: how the keys derive from the root seed, how exactly a pack key is sealed, which keys protect files outside packs, and what the vault config looks like and how it survives damage.

## Decision

- **Three keys from the root seed**, each with BLAKE3 `derive_key` and its own context string: the dedup key, the writer key, and the read key. The 32 bytes of the read key are the X-Wing decapsulation key.
- **BIP39 only maps bytes to words.** The recovery phrase is the BIP39 encoding of the 32 bytes. We do not use a BIP39 passphrase or the BIP39 seed derivation. The root seed stays the same 32 bytes, with no hidden extra input to remember.
- **X-Wing (draft 06) is the KEM.** The algorithm name in the vault is `x-wing-draft-06`, so a later final standard gets a new name. Implementation: the `x-wing` crate. It has not been independently audited (see `docs/pre-v1.md`).
- **The seal is a simple KEM-DEM.** Encapsulate to the public read key, derive a seal key from the shared secret with `derive_key`, and encrypt the 32-byte pack key with XChaCha20-Poly1305. The associated data is the hash of the pack header, so the seal belongs to one pack. The seal is 1192 bytes.
- **W keys by purpose.** Pack objects, object tables, snapshot headers, condemnation records, index segments and the config MAC each have their own key from the writer key. Files outside packs use the nonce, ciphertext and tag layout of packed objects, with empty associated data.
- **The vault config is plaintext CBOR plus a 32-byte BLAKE3 MAC**, in two copies: `config-a` and `config-b`. A config sequence number grows with each change. A reader uses the valid copy with the highest sequence. Two valid copies with the same sequence and different bytes are an error. A vault ID of 16 random bytes tells replicas of one vault apart from other vaults.
- **The chunking profile table** is in the config, with the draft values: small (one chunk up to 64 KiB), default (64 KiB to 1 MiB, average 256 KiB) and large (512 KiB to 8 MiB, average 2 MiB).

## Consequences

- Everything derives from 24 words, with no other secret to store.
- A node holds the dedup key and the writer key and can write and seal. It cannot open the seal.
- A crash while updating the config leaves two valid copies that differ by one sequence. The reader picks the newer one.
- An attacker who can replace both config copies with an older valid pair cannot be detected from the files alone. A node can keep the highest sequence it has seen (see `docs/pre-v1.md`).
- The seal construction is simple but new. It needs a review by someone with cryptography expertise before format version 1 (see `docs/pre-v1.md`).

## Alternatives considered

- **HPKE (RFC 9180) with X-Wing:** a standard construction, but it needs a KDF key schedule and another dependency, for the same result with one fixed recipient and one message.
- **X25519 only for now:** simpler, but it conflicts with ADR 0012. Data written now would not be protected against future quantum attacks.
- **The BIP39 seed (PBKDF2) as the root seed:** the usual wallet way, but it adds an optional passphrase that a person can forget and that makes recovery depend on remembering it.
- **One config file:** simpler, but one damaged file would lose the vault's essential fields. The two copies cost almost nothing, and snapshot headers repeat the essentials as well.
- **A MAC in the CBOR map:** it needs a canonical form without the MAC to compute it. A MAC after the map needs no such rule.
