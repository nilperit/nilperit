# Before format version 1

> **Not normative.** This is a working list for the maintainers. The rules are in [format.md](format.md). Section 13 of that file lists the open *format* items. This page adds the things that are not in the format text: security checks, decisions that we parked on purpose, and cleanups.

The format is a draft (format version 0) and changes freely. **From format version 1 on, NilPerit must read every older version forever** (ADR 0011), accepted ADRs are no longer rewritten, and strings like context strings and magic bytes become permanent. Everything below is cheap to fix now and expensive to fix later.

Remove an item when it is done. The history is in git.

## Security and audits

- **KEM implementation.** The format uses X-Wing draft 06 (`x-wing-draft-06`), through the `x-wing` crate (pure Rust). Its README says that it has never been independently audited. The `ml-kem` crate under it says the same (versions checked on 2026-11-22: `x-wing` 0.1.1, `ml-kem` 0.3.4). Before version 1:
  - check the current audit status of both crates;
  - decide whether to keep them or to switch to `libcrux-ml-kem` (formally verified, but then we have to write the X-Wing combiner ourselves);
  - check whether X-Wing is a final standard by then. If it is, give it a new algorithm name and update ADR 0012 and ADR 0018.
- **Review the seal construction** (section 3.3.2.2, ADR 0018). It is a simple KEM-DEM that we composed from reviewed parts, but nobody with cryptography expertise has reviewed the composition yet. This also covers the use of the header hash as associated data, and the context strings.
- **Audit status of the crates that handle keys or untrusted data** (as the crates' own READMEs say, checked on 2026-11-22). Re-check before version 1, and read which version an audit covered:
  - `chacha20poly1305` 0.11, `chacha20` 0.10 and `poly1305` 0.9: one NCC Group audit (2020), no significant findings. The `poly1305` README says that the audit predates its AVX2 backend, which has not been audited.
  - `x-wing` 0.1.1 and `ml-kem` 0.3.4: never independently audited.
  - `x25519-dalek` 3.0.0, `curve25519-dalek` 5.0.0, `bip39` 3.0.0 and `bitcoin_hashes` 0.14: the READMEs say nothing about audits. ADR 0012 mentions a Quarkslab audit of an older `curve25519-dalek`. We have not checked it. `bip39` only maps the root seed to words and back, but it handles the root seed.
  - `blake3`, `zeroize` and `minicbor` were added earlier. Still to record when they are added: `miniz_oxide` (we know that 0.9.1 forbids `unsafe` code) and `fastcdc`.
- **Fuzzing.** Add fuzz targets for the strict CBOR checker, the pack parser, and the decompress-and-verify path (ADR 0016 promises the last one).
- **Review every draft constant before it freezes.** The context strings (dated `2026-11-22`), the magic bytes and end magic of a pack, and the algorithm names. Section 3.2.7 of the format says that the context strings are fixed for a format version.

## Parked format decisions

- **Describe sources in the vault.** For the first working system a source (name, connector type, selection, priority) lives only in the node's local configuration. Before version 1 the vault needs it too, so that a person can move to a new host and a reader can show names. The likely design is a small R-class *source record* object that delta entries reference, so a rename or a priority change is versioned.
- **Rollback of the vault config.** An attacker who can replace both copies with an older valid pair cannot be detected from the files alone (section 7.2.6). A node could remember the highest config sequence that it has seen. Decide whether it should.
- **What ships in `recovery/`** (section 7.3). ADR 0014 prefers a reader-only `nilperit-recover` binary that does not depend on the writer. This is a choice for small size and easy maintenance, not a hard rule. We could ship the full `nilperit` binary, or the same binary with limited functionality. Decide when the binary sizes are known. If we ship the full binary, update ADR 0014 and the layering rule in AGENTS.md.
- **A real seal in the test vector.** The pack vector A.8 has a placeholder seal and KEM name. Replace them when the seal code exists and there is an X-Wing implementation to check against. Add the seal itself as a vector.
- **Chunking.** The profile values in section 5.2.4 are draft values. Still open: the exact text of `fastcdc-2020` and how the chunker seed makes the gear table (section 5.2.4.2).
- **Still open in `format.md` section 13:** the fields of a checkpoint, the type IDs and field numbers of the remaining object types, the schema dictionary generator, and the parity data format.
- **Very large files.** A content object lists every chunk. With the default profile, a 1 TiB file has a content object of about 143 MB. The large profile keeps this small (about 18 MB), and profiles are chosen by the data. If TB-scale files with small chunks turn out to be common, make content objects a tree in a later schema version.
- **More compression algorithms.** zstd and LZ4 as opt-in algorithms, after we have audited a decoder. A source can already use `none`.
- **The pack trailer is a single point of failure for its pack.** We accept this (ADR 0017). Revisit it only if experience shows a problem. Replicas and parity cover it.

## Cleanups

- Section 11.3.1 of the format mentions a "combined delta entry" that the glossary does not define.
- ADR 0007 says that an item record "lives" in the same pack as its content. Section 6.2 of the format says SHOULD.

## Before the first release (not about the format)

- Run `cargo deny` on a schedule, as its own small workflow. New advisories appear without any code change, and Dependabot only opens pull requests for updates. We postponed this until we get near a release.
