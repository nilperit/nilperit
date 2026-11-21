# NilPerit Vault Format

Status: **Draft**. This specification is not stable. It will change without notice until format version 1. Do not keep real data in a vault of a draft version.

Each vault contains a copy of this file with the name `FORMAT.md`. With this file, the schema dictionary, and the recovery phrase, a person can read a vault without NilPerit.

## 1. Conventions

1.1. The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY have the meanings that RFC 2119 gives them.

1.2. This document uses the terms in the [glossary](glossary.md). Each term has only the meaning that the glossary gives.

1.3. "TBD" marks a value that is not fixed yet. An implementation of a draft version MUST record the value that it uses in the schema dictionary of the vault.

1.4. All multi-byte integers outside CBOR are little-endian.

1.5. This document uses American English spelling.

## 2. Principles

2.1. **Nothing is lost.** A change or a deletion at a source MUST NOT remove data from the vault. Only retention rules can remove data.

2.2. **Truth and cache.** Truth is immutable data that NilPerit cannot make again. A cache is data that NilPerit can make again from the truth. A reader MUST be able to rebuild every cache from the truth.

2.2.1. The truth objects are: chunks, content objects, item records, journal entries, checkpoint trees, and archive trees. All other objects are caches.

2.3. **Damage stays local.** The loss of one file MUST NOT make other data unreadable. It can only make the data in that file unreadable.

2.4. **The current state is truth.** A person MUST be able to remove old history without an effect on the current state.

2.5. **No dependency on NilPerit.** A vault contains its format specification, its schema dictionary, and reader software.

## 3. Keys

### 3.1. Root seed and recovery phrase

3.1.1. When NilPerit creates a vault, it MUST make a root seed of 32 random bytes from a cryptographically secure random source.

3.1.2. NilPerit MUST show the root seed to the person as a recovery phrase of 24 words. The word list and the encoding are BIP39 (English word list).

3.1.3. NilPerit MUST NOT store the root seed in a vault in plaintext.

3.1.4. A vault MAY contain a copy of the root seed that is encrypted with a passphrase (Argon2id). NilPerit MUST NOT write this copy to a target that a third party controls.

### 3.2. Key derivation

3.2.1. NilPerit derives all keys from the root seed. Each key has its own context string (domain separation).

3.2.2. Key derivation function: BLAKE3 `derive_key` mode. TBD: final choice and exact context strings.

3.2.3. The derived keys are:

| Key | Type | Holder | Purpose |
|---|---|---|---|
| Read key | Hybrid X25519 + ML-KEM-768 key pair | Owner (private part) | Opens item records and chunks |
| Dedup key | 32-byte key for keyed BLAKE3 | Node | Makes object IDs, item keys, and content hashes |
| Writer key | 32-byte symmetric key | Node | Encrypts objects that the node reads again |
| Chunker seed | 32 bytes | Node | Selects chunk cut points |

3.2.4. The node credential is: the public part of the read key, the dedup key, the writer key, and the chunker seed. A node MUST NOT have the private part of the read key, unless the owner gives it explicitly.

### 3.3. Encryption

3.3.1. Each object has a key class. There are two key classes:

| Key class | Objects | Who can open |
|---|---|---|
| R (read) | Chunks, item records | Only the holder of the read key |
| W (writer) | Content objects, journal entries, checkpoint trees, archive trees, item map nodes, archive map nodes | The node and the owner |

3.3.2. For R objects, each pack has a random 32-byte pack key. NilPerit MUST seal the pack key to the public part of the read key. The seal uses a hybrid KEM: X25519 and ML-KEM-768 together. A reader needs both secrets to open the seal. TBD: exact combiner construction.

3.3.3. For W objects, NilPerit encrypts with a key that it derives from the writer key. TBD: per-pack derivation.

3.3.4. One pack can contain objects of both key classes. The object table (see 6.3) records the key class of each object.

3.3.5. Object encryption: XChaCha20-Poly1305 (AEAD). Each object has its own random 24-byte nonce.

3.3.6. The owner can open objects of both key classes, because all keys derive from the root seed. A party without keys can open neither class.

3.3.7. The format MUST record an algorithm ID for each algorithm that it uses: encryption, key encapsulation, hashing, and compression. This lets a later version change algorithms.

## 4. Encoding

4.1. All objects use CBOR (RFC 8949).

4.2. Encoders MUST use deterministic encoding (RFC 8949, section 4.2). The same object MUST always give the same bytes.

4.3. Maps use small unsigned integers as keys. The schema dictionary gives the name and the meaning of each key.

4.4. Each object starts with an envelope:

| Field | Meaning |
|---|---|
| type | Object type ID (unsigned integer) |
| schema | Schema version of this object type |
| body | The object fields |

4.5. A decoder MUST ignore map keys that it does not know. This lets a later schema version add fields.

4.6. The schema dictionary is in CDDL (RFC 8610). It lists each object type, each schema version, and each field: number, name, type, and description.

4.7. **Object IDs.** The ID of each object is the keyed BLAKE3 hash of its plaintext encoding. The key is the dedup key. The hash input starts with the object type ID (domain separation). Length: 32 bytes. TBD: exact framing of the type ID, and a separate derived key for object IDs.

4.8. Because the ID depends only on the plaintext, the same object has the same ID in all replicas. The random nonce of the encryption does not change the ID.

4.9. **No re-encoding.** NilPerit MUST NOT decode and encode a stored object again to compute its ID or to copy it. It MUST use the stored plaintext bytes. A decoder that ignores unknown fields (see 4.5) would otherwise remove them and change the ID.

## 5. Objects

### 5.1. Chunk (truth)

5.1.1. NilPerit cuts content into chunks with FastCDC. The chunker seed sets the gear table.

5.1.2. The chunk ID is the object ID of the chunk (see 4.7): the keyed BLAKE3 hash of the plaintext chunk. Length: 32 bytes.

5.1.3. NilPerit compresses a chunk with zstd before encryption. It MUST NOT compress data that is already compressed (for example JPEG, MP4, ZIP).

5.1.4. A chunk has key class R.

### 5.2. Chunking profiles

5.2.1. The vault config contains a table of chunking profiles. Each profile has: ID, algorithm, minimum size, average size, maximum size.

5.2.2. The table is append-only. NilPerit MUST NOT change or remove a profile.

5.2.3. NilPerit selects a profile from the properties of the data (size, media type, connector hint). It MUST NOT select a profile from the source.

5.2.4. Initial profiles (TBD: exact values):

| Name | Use | Average size |
|---|---|---|
| small | Data below approximately 64 KiB. No cutting: one chunk. | — |
| default | Documents, email with attachments, general files | approximately 256 KiB |
| large | Video, photos, archives | approximately 2–4 MiB |

### 5.3. Content object (truth)

5.3.1. Fields: list of chunk IDs (in order), total length, keyed BLAKE3 hash of the full plaintext (key: dedup key), chunking profile ID.

5.3.2. A content object has key class W. This lets the node find all chunks that an item uses, without the read key.

### 5.4. Item record (truth)

5.4.1. Fields:

- source ID and native ID of the item;
- common fields: title, timestamps, size, media type;
- source-specific metadata (opaque to the vault);
- references to content objects.

5.4.2. An item record MUST contain enough data to show the item without other objects, except its content.

5.4.3. An item record has key class R.

5.4.4. NilPerit MUST store raw originals byte for byte. Example: a Gmail message is stored as raw RFC 822 data.

### 5.5. Journal entries (truth)

5.5.1. Each source has one journal. A journal is a chain of journal entries. Each entry points to its parent entry.

5.5.2. A **delta entry** contains:

- snapshot ID and time;
- connector cursor;
- parent entry;
- changes: items added, changed, and deleted, as item key → item record ID and content object IDs.

5.5.3. A **checkpoint** contains the complete state of the source at one time. It points to two trees:

- the **checkpoint tree**: all items that exist at that time;
- the **archive tree**: all item versions that do not exist at that time but that item retention still keeps (old versions and deleted items), each with the time NilPerit saw it first and the time NilPerit saw it last.

5.5.4. Checkpoint trees and archive trees are truth. Their nodes are stored in data packs.

5.5.5. The current state of a source is the newest checkpoint plus all delta entries after it.

5.5.6. NilPerit MUST write a checkpoint after a configurable number of delta entries or after a configurable time.

5.5.7. Journal entries, checkpoint trees, and archive trees have key class W.

### 5.6. Trees

5.6.1. Checkpoint trees, archive trees, item maps, and archive maps all use the same structure: a sorted, content-addressed tree (prolly tree).

5.6.2. Trees share all unchanged subtrees. A new tree stores only the nodes that changed.

5.6.3. Leaf entries of a checkpoint tree and of an item map: item key → item record ID and content object IDs.

5.6.4. Leaf entries of an archive tree and of an archive map: item key and item record ID → content object IDs, time first seen, time last seen.

5.6.5. The item key is the keyed BLAKE3 hash of the native ID. The key is the dedup key. TBD: separate derived key for item keys.

### 5.7. Item map (cache)

5.7.1. An item map shows all items of a source at one snapshot.

5.7.2. NilPerit makes an item map from the newest checkpoint tree before that snapshot plus the delta entries up to that snapshot.

5.7.3. Item map nodes have key class W.

### 5.8. Archive map (cache)

5.8.1. An archive map shows each item version that a source ever had and that retention still keeps, with the time NilPerit saw it first and the time NilPerit saw it last.

5.8.2. NilPerit makes the archive map from the newest archive tree plus all delta entries after it.

5.8.3. Archive map nodes have key class W.

### 5.9. Snapshot header (cache)

5.9.1. Fields: source ID, time, root of the item map, parent snapshot, journal position, statistics, and a copy of the essential vault config fields.

5.9.2. NilPerit can make a snapshot header again from the journal.

## 6. Packs

6.1. A pack is an immutable file. Default target size: 16 MiB. A target MAY use a different size.

6.2. There are two pack classes:

- **Data packs** contain truth: chunks, content objects, item records, journal entries, checkpoint tree nodes, archive tree nodes. An item record SHOULD be in the same data pack as the chunks of its content.
- **Metadata packs** contain caches: item map nodes, archive map nodes, copies of item records.

6.3. Pack layout:

| Part | Content |
|---|---|
| Header | Magic bytes, format version, algorithm IDs (TBD: exact layout) |
| Body | Encrypted objects, one after the other |
| Trailer | Sealed pack key (only when the pack contains R objects); object table |
| Footer | Trailer offset and length |

6.3.1. The object table lists each object in the pack: object ID, object type, key class, offset, and length.

6.3.2. The object table has key class W. The node can read it without the read key. This lets the node rebuild the index and run a sweep.

6.3.3. The object table contains only opaque values. It MUST NOT contain titles, file names, or other plaintext data of the owner.

6.4. The name of a pack is the BLAKE3 hash of the complete encrypted file, in lowercase hexadecimal. Anyone can verify a pack without keys.

6.5. NilPerit SHOULD NOT put objects of sources with different priorities in the same pack.

## 7. Vault layout

```
vault/
  config            vault config (authenticated; mirrored)
  FORMAT.md         copy of this specification (docs/format.md)
  schema/           schema dictionary (CDDL)
  recovery/         bundled reader software
  packs/ab/ab12…    packs; subdirectory = first two characters of the name
  index/            index segments (cache)
  snapshots/        snapshot headers (cache)
  condemned/        condemnation records
  locks/            writer lock
```

7.1. FORMAT.md, schema/, and recovery/ are plaintext. They contain no data of the owner.

7.2. The vault config MUST exist in more than one copy (TBD: number and file names).

7.3. recovery/ MUST contain a reader for the format version of the vault. TBD: exact contents and file names.

## 8. Commit procedure

8.1. NilPerit writes each file with a temporary name. It syncs the file to the storage device (fsync). Then it gives the file its final name.

8.2. The order is:

1. Data packs.
2. Metadata packs.
3. Index segments.
4. Snapshot header.

8.3. The snapshot header completes the commit. Before that step, the new data is not part of the vault.

8.4. During a long synchronization, NilPerit SHOULD commit at intervals (for example every N MiB or every N minutes). A failure then loses only the work since the last commit.

8.5. A file that is not part of a commit is an orphan. An orphan is not an error. A later run can use it, or a sweep removes it.

8.6. Only one node can write to a vault at a time. The writer MUST hold the lock in locks/. The lock contains the node ID and a heartbeat time. A node MAY take a lock whose heartbeat is older than a configurable limit.

8.7. Readers do not need a lock, because files do not change.

## 9. Reading and verification

9.1. A reader MUST NOT trust the file system. Some targets (for example exFAT or FAT32 media) do not rename files atomically.

9.2. A reader MUST ignore a pack when the hash of the file does not agree with its name.

9.3. A reader MUST reject an object when its AEAD tag is not correct.

9.4. A reader MUST reject a snapshot header that it cannot authenticate.

9.5. When the format version of a vault is higher than the version that the reader knows, the reader MUST stop. It MUST tell the person to use a newer version or the bundled reader of the vault.

9.6. A reader MUST be able to read all older format versions.

## 10. Integrity and repair

10.1. A scrub reads stored data and verifies pack hashes and AEAD tags.

10.2. For a large vault, a scrub MAY verify a different sample of packs each time.

10.3. NilPerit can repair a damaged object from any other replica, because object IDs are the same in all replicas (see 4.8).

10.4. A target MAY contain parity data (Reed–Solomon) for each pack. TBD: parity format and file names.

10.5. When a data pack is damaged, NilPerit MUST mark only the items that use objects from that pack as damaged. All other items stay available.

10.6. When caches are missing or damaged, NilPerit MUST rebuild them from data packs.

10.7. Salvage: with the recovery phrase, a reader scans all readable packs. It rebuilds item records, content objects, journals, and caches as far as possible.

## 11. Retention and removal

11.1. Each source has two kinds of retention rules:

- **Snapshot retention** controls which snapshots NilPerit keeps.
- **Item retention** controls how long NilPerit keeps item versions and deleted items.

11.2. NilPerit keeps an object while any rule of any source keeps it.

11.3. NilPerit MUST NOT remove data immediately. The procedure has two steps:

1. **Condemn.** After each synchronization, NilPerit applies the retention rules. It writes a condemnation record for each expired root: a snapshot, a journal range, or an archive entry. A condemnation record does not remove data. NilPerit can revoke it.
2. **Sweep.** NilPerit starts from all live roots: snapshots, journal entries, checkpoints, and archive trees that no active condemnation record marks. It finds all objects that these roots use. An object that no live root uses is unreachable.
3. NilPerit removes a pack only when all objects in the pack are unreachable and the newest condemnation record that made them unreachable is older than the grace period. Orphan packs become eligible after the grace period too.
4. NilPerit rewrites (repacks) a pack when more than a configurable part of it (default 30 %) is unreachable.

11.4. A sweep MUST find live objects from the truth. It MUST NOT use reference counts.

11.5. A sweep MUST hold the writer lock.

11.6. A sweep MUST work without the read key. It uses object tables, content objects, journal entries, and trees, which all have key class W.

11.7. To remove old journal history, NilPerit selects a checkpoint as the new base. The archive tree of that checkpoint MUST contain each item version whose item retention has not expired, with its time first seen and time last seen. Only after that, NilPerit condemns all journal entries before that checkpoint.

11.8. When a target is full, NilPerit MUST stop synchronization of sources with the lowest priority first. It MUST NOT remove data automatically, unless the owner enabled automatic cleanup for that target.

## 12. Versions and compatibility

12.1. The vault config contains one format version number.

12.2. A newer NilPerit version MUST be able to read all older format versions. It SHOULD be able to upgrade them.

12.3. An older NilPerit version that finds a newer format version MUST stop (see 9.5).

12.4. When NilPerit upgrades a vault, it MUST write the reader software for the new format version in the same commit (see 7.3).

## 13. Open items

The items below are not fixed in this draft:

- Key derivation context strings and final KDF choice (3.2.2).
- Hybrid KEM combiner construction (3.3.2).
- Per-pack derivation of the W key (3.3.3).
- Framing of the type ID in object IDs, and a separate derived key for object IDs (4.7).
- Exact values of the chunking profiles (5.2.4).
- Separate derived key for item keys (5.6.5).
- Pack header layout and magic bytes (6.3).
- Number and names of vault config copies (7.2).
- Contents and names in recovery/ (7.3).
- Parity data format (10.4).
- Object type IDs and the field numbers of each object type (schema dictionary).
