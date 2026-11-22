# NilPerit Vault Format

Status: **Draft**. This specification is not stable. It will change without notice until format version 1. Do not keep real data in a vault of a draft version.

For an informal explanation with diagrams, see [overview.md](overview.md). That document is not normative.

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

3.1.2.1. NilPerit uses BIP39 only for the mapping between the 32 bytes and the 24 words, including the checksum. It does not use a BIP39 passphrase. It does not use the BIP39 seed derivation (PBKDF2). The root seed is the 32 bytes that the 24 words encode. A reader MUST check the checksum of the words.

3.1.3. NilPerit MUST NOT store the root seed in a vault in plaintext.

3.1.4. A vault MAY contain a copy of the root seed that is encrypted with a passphrase (Argon2id). NilPerit MUST NOT write this copy to a target that a third party controls.

### 3.2. Key derivation

3.2.1. NilPerit derives all keys from the root seed. Each key has its own context string (domain separation).

3.2.2. Key derivation function: BLAKE3 `derive_key` mode. The context strings are in 3.2.5, 3.2.9, 3.3.2.2, 3.3.3, 3.3.7, and 3.3.8.

3.2.3. The derived keys are:

| Key | Type | Holder | Purpose |
|---|---|---|---|
| Read key | X-Wing key pair (X25519 + ML-KEM-768) | Owner (private part) | Opens item records and chunks |
| Dedup key | 32-byte key | Node | Source of the domain keys (see 3.2.5) |
| Writer key | 32-byte symmetric key | Node | Encrypts objects that the node reads again |

3.2.4. The node credential is: the public part of the read key, the dedup key, and the writer key. A node MUST NOT have the private part of the read key, unless the owner gives it explicitly.

3.2.5. **Hash domains.** NilPerit makes three kinds of keyed hash with the dedup key. Each kind is a hash domain. For each hash domain, NilPerit derives a domain key: BLAKE3 `derive_key` with the context string of the domain and the dedup key as key material. The domain key is 32 bytes.

| Hash domain | Context string |
|---|---|
| Object ID | `nilperit 2026-11-22 object-id` |
| Item key | `nilperit 2026-11-22 item-key` |
| Content hash | `nilperit 2026-11-22 content-hash` |

3.2.6. A hash in a hash domain is the keyed BLAKE3 hash with the domain key of that domain. Size: 32 bytes. Because the domain keys are different, a value of one hash domain never equals a value of another hash domain.

3.2.7. A new kind of hash MUST have its own hash domain. The context strings are fixed for a format version. In a draft version, they can change.

3.2.8. A context string has the form: application, date, purpose. This is the convention of BLAKE3 for `derive_key`. The date has no meaning. It is not a version. Only the uniqueness of the string matters.

3.2.9. **Keys from the root seed.** NilPerit derives each of these keys with BLAKE3 `derive_key`. The key material is the root seed. Each key is 32 bytes:

| Key | Context string |
|---|---|
| Dedup key | `nilperit 2026-11-22 dedup-key` |
| Writer key | `nilperit 2026-11-22 writer-key` |
| Read key | `nilperit 2026-11-22 read-key` |

3.2.9.1. The 32 bytes of the read key are the decapsulation key of X-Wing (see 3.3.2.1). The public part of the read key is the encapsulation key that X-Wing makes from it.

### 3.3. Encryption

3.3.1. Each object has a key class. There are two key classes:

| Key class | Objects | Who can open |
|---|---|---|
| R (read) | Chunks, item records | Only the holder of the read key |
| W (writer) | Content objects, journal entries, checkpoint trees, archive trees, item map nodes, archive map nodes, object tables, snapshot headers, condemnation records, index segments | The node and the owner |

3.3.2. For R objects, each pack has a random 32-byte pack key. NilPerit MUST seal the pack key to the public part of the read key. The seal uses a hybrid KEM that combines X25519 and ML-KEM-768. A reader needs both secrets to open the seal.

3.3.2.1. **KEM.** The key encapsulation algorithm is X-Wing, as in version 06 of the Internet-Draft draft-connolly-cfrg-xwing-kem. Its name in a pack header and in the vault config is `x-wing-draft-06`. The read key (see 3.2.9) is the decapsulation key. The public part of the read key is 1216 bytes. An encapsulation gives a ciphertext of 1120 bytes and a shared secret of 32 bytes.

3.3.2.2. **Sealing.** A writer seals a pack key as follows:

1. It encapsulates to the public part of the read key. This gives a shared secret and a ciphertext.
2. It derives the seal key. This is BLAKE3 `derive_key` with the context string `nilperit 2026-11-22 pack-seal` and the shared secret as key material. The seal key is 32 bytes.
3. It encrypts the pack key (32 bytes) with XChaCha20-Poly1305. The key is the seal key. The nonce is 24 random bytes. The associated data is the BLAKE3 hash of the header of the pack (see 6.7.3.4).
4. The seal is: the ciphertext of the encapsulation (1120 bytes), the nonce (24 bytes), the encrypted pack key (32 bytes), and the tag (16 bytes). It is 1192 bytes.

3.3.2.3. **Opening.** A reader MUST reject a pack whose key encapsulation name is not `x-wing-draft-06`. It MUST reject a seal that is not 1192 bytes. It decapsulates the ciphertext with the read key, derives the seal key in the same way, and decrypts. It MUST reject the seal when the tag is not correct.

3.3.2.4. The associated data binds the seal to the header of its pack. A changed header makes the seal fail.

3.3.2.5. A node can seal, because it has the public part of the read key. It cannot open a seal, because it does not have the read key.

3.3.2.6. The layout of a pack treats the seal as opaque bytes with a size (see 6.7.3). A later algorithm can have a seal of another size.

3.3.3. For W objects in packs, NilPerit uses two keys. It derives them from the writer key with BLAKE3 `derive_key`. The key material is the writer key. The keys are 32 bytes:

| Key | Context string | Use |
|---|---|---|
| Pack object key | `nilperit 2026-11-22 pack-object` | W objects in the body of a pack |
| Pack table key | `nilperit 2026-11-22 pack-table` | The object table of a pack |

3.3.3.1. The keys do not depend on the pack. The random 24-byte nonces (see 3.3.5) make it safe to encrypt many objects with one key. Different purposes have different keys, so an object of one purpose is never valid for another purpose. Section 3.2.5 explains the form of the context strings.

3.3.4. One pack can contain objects of both key classes. The object table (see 6.3) records the key class of each object.

3.3.5. Object encryption: XChaCha20-Poly1305 (AEAD). Each object has its own random 24-byte nonce. The associated data of an object in a pack is in 6.7.2.3.

3.3.6. The owner can open objects of both key classes, because all keys derive from the root seed. A party without keys can open neither class.

3.3.7. Snapshot headers, condemnation records, and index segments are files outside packs. Each is one W object. Its stored bytes are an encoded envelope.

3.3.7.1. The bytes of the file are: a random nonce (24 bytes), the ciphertext, and the tag (16 bytes). The encryption is XChaCha20-Poly1305. The associated data is empty. The key depends on the kind of file. NilPerit derives it from the writer key with BLAKE3 `derive_key`. The key material is the writer key. The keys are 32 bytes:

| Kind of file | Context string |
|---|---|
| Snapshot header | `nilperit 2026-11-22 snapshot-header` |
| Condemnation record | `nilperit 2026-11-22 condemnation-record` |
| Index segment | `nilperit 2026-11-22 index-segment` |

3.3.7.2. A reader MUST reject a file when the tag is not correct (see 9.4). A reader MUST reject a file of 2^32 bytes or more before it allocates memory for it.

3.3.8. The vault config is plaintext CBOR, because a reader must read the format version and the algorithm names before it has keys. It contains no data of the owner. NilPerit MUST authenticate it with a keyed BLAKE3 MAC (see 7.2). The MAC key is 32 bytes. NilPerit derives it from the writer key with BLAKE3 `derive_key`, with the context string `nilperit 2026-11-22 config-mac` and the writer key as key material. The MAC input is the bytes of the CBOR map. The MAC is 32 bytes.

3.3.9. A node MUST compare the public part of the read key in the vault config with the value in its node credential. When they are different, the node MUST stop. An attacker who changes the config must not make the node seal data to a different key.

3.3.9.1. A reader that has the recovery phrase MUST derive the public part of the read key and compare it with the value in the vault config. When they are different, the reader MUST stop and report a changed vault config. This protects against a replica that was changed.

3.3.10. The lock file is plaintext and not authenticated. It contains only a node ID and a heartbeat time. A changed lock file can stop a node, but it cannot change data.

3.3.11. The format MUST record an algorithm ID for each algorithm that it uses: encryption, key encapsulation, hashing, and compression. This lets a later version change algorithms. The object table records the compression algorithm of each object (see 6.3.1).

## 4. Encoding

4.1. All objects use CBOR (RFC 8949).

4.2. Encoders MUST use deterministic encoding (RFC 8949, section 4.2). The same object MUST always give the same bytes.

4.3. Maps use small unsigned integers as keys. The schema dictionary gives the name and the meaning of each key.

4.4. Each object is one envelope:

| Field | Meaning |
|---|---|
| type | Object type ID (unsigned integer) |
| schema | Schema version of this object type |
| body | The object fields |

4.4.1. The envelope is a CBOR map with the keys 0 (type), 1 (schema), and 2 (body). The body is a CBOR map with unsigned integer keys. The envelope contains the body as a CBOR item. It does not wrap the body in a byte string.

4.4.2. The stored bytes of an object are the encoded envelope. See 4.9.

4.4.3. **Object type IDs.** The type ID is an unsigned integer that fits in 32 bits. NilPerit MUST NOT use type ID 0. NilPerit MUST NOT change or reuse a type ID. This draft defines these type IDs:

| Type ID | Object type | Form |
|---|---|---|
| 1 | Chunk | Raw |
| 2 | Content object | Enveloped |
| 3 | Object table | Enveloped |
| 4 | Item record | Enveloped |
| 5 | Delta entry | Enveloped |
| 6 | Snapshot header | Enveloped |

4.4.4. A raw object has a type ID, but no envelope (see 4.7.2). The type ID is only an input of its object ID. TBD: type IDs of the other object types.

4.4.5. The object table (type ID 3) is not an object in the body of a pack. It is in the trailer and has no object ID (see 6.7.3).

4.5. A decoder MUST ignore map keys that it does not know. This makes a decoder resilient, for example against fields that a later schema version no longer uses. It is not a compatibility mechanism: compatibility comes from the format version and the schema version (see 4.5.1 and section 12).

4.5.1. A decoder MUST reject an object with a schema version that it does not know. A reader of a format version knows all schema versions of that format version and of the older format versions. An object with a higher schema version can only come from a bug or from damage, because an older reader stops when it finds a newer format version (see 12.3). Objects of different schema versions can exist in one vault, because NilPerit upgrades a vault lazily (see 12.2).

4.6. The schema dictionary is in CDDL (RFC 8610). It lists each object type, each schema version, and each field: number, name, type, and description.

4.6.1. **Allowed CBOR items.** An object MUST contain only these CBOR items: unsigned integers, negative integers, byte strings, text strings, arrays, maps, false, true, and null. A decoder MUST reject tags, floating-point numbers, and other simple values. TBD: a later schema version can allow more item types.

4.6.2. **Strict decoding.** A decoder MUST reject stored bytes that are not deterministic CBOR. This includes: an integer or length that is not in the shortest form; an indefinite-length item; a map with duplicate keys or keys that are not in the order of RFC 8949, section 4.2.1; a text string that is not valid UTF-8; and bytes after the end of the object. Two different byte strings therefore cannot give the same object. A decoder MUST limit the nesting depth. The limit of this draft is 32.

4.7. **Object IDs.** The ID of each object is the hash of its stored bytes in the hash domain "object ID" (see 3.2.5). The hash input is the type ID as a 4-byte unsigned integer (little-endian), followed by the stored bytes. Size: 32 bytes.

4.7.1. The type ID comes from the object table (see 6.3.1). For an enveloped object, the type ID in the object table MUST be equal to the type in the envelope. A reader MUST reject the object when they are different.

4.7.2. Each object type is either enveloped or raw. The schema dictionary states which. The stored bytes of an enveloped object are the encoded envelope (see 4.4.2). The stored bytes of a raw object are its plaintext before compression. A raw object has no type in its bytes. For this reason, a raw object type MUST have key class R. Today, only the chunk is raw.

4.8. Because the ID depends only on the plaintext, the same object has the same ID in all replicas. The random nonce of the encryption does not change the ID.

4.9. **No re-encoding.** NilPerit MUST NOT decode and encode a stored object again to compute its ID or to copy it. It MUST use the stored plaintext bytes. A decoder that ignores unknown fields (see 4.5) would otherwise remove them and change the ID.

## 5. Objects

### 5.1. Chunk (truth)

5.1.1. NilPerit cuts content into chunks with the algorithm of a chunking profile (see 5.2). This draft defines one algorithm: `fixed`.

5.1.2. The chunk ID is the object ID of the chunk (see 4.7): the keyed BLAKE3 hash of the plaintext chunk. Size: 32 bytes.

5.1.3. NilPerit MAY compress a chunk before encryption (see 6.6). The chunk ID does not depend on compression (see 4.7.2).

5.1.4. A chunk has key class R.

### 5.2. Chunking profiles

5.2.1. The vault config contains a table of chunking profiles (see 7.2). Each profile has: ID, algorithm, minimum size, average size, maximum size.

5.2.1.1. The ID is an unsigned integer. The IDs of this draft are 1, 2, and 3. NilPerit does not use the ID 0. Each ID occurs once in the table.

5.2.1.2. The minimum, average, and maximum sizes are unsigned integers below 2^32 (see 6.7.6).

5.2.2. The table is append-only. NilPerit MUST NOT change or remove a profile.

5.2.3. NilPerit selects a profile from the properties of the data (size, media type, connector hint). It MUST NOT select a profile from the source.

5.2.4. Initial profiles. These values are for this draft. The sizes are in bytes.

| ID | Name | Use | Algorithm | Minimum size | Average size | Maximum size |
|---|---|---|---|---|---|---|
| 1 | default | Documents, email, general files | `fixed` | 0 | 0 | 262144 |
| 2 | large | Video, photos, archives | `fixed` | 0 | 0 | 2097152 |

5.2.4.1. **The algorithm `fixed`.** The content is cut into chunks of the same size, from the start to the end. The maximum size of the profile is the size of a chunk. The last chunk holds the rest and can be shorter. Content that is not larger than one chunk is one chunk. Content without data has no chunk (see 5.3.1.1). A profile with this algorithm MUST have the minimum size 0, the average size 0, and a maximum size above 0.

5.2.4.2. **Other algorithms.** The format can use other algorithms under other names. A reader does not need the chunking algorithm, because a content object lists its chunks. A content-defined algorithm, which cuts at places that depend on the content, can be added later as a new profile, for example when measurements show that it saves space for a connector (see pre-v1.md). Such an algorithm would need a secret key, which a later version derives from the root seed (see pre-v1.md).

### 5.3. Content object (truth)

5.3.1. A content object is an enveloped object with type ID 2 and schema version 1. Fields:

| Key | Field | CBOR type | Meaning |
|---|---|---|---|
| 1 | chunks | Array of byte strings | The chunk IDs, in order. Each is 32 bytes. |
| 2 | size | Unsigned integer | The total size of the plaintext content, in bytes |
| 3 | content hash | Byte string, 32 bytes | The keyed BLAKE3 hash of the full plaintext (hash domain: content hash, see 3.2.5) |
| 4 | chunking profile | Unsigned integer | The ID of the chunking profile (see 5.2.1). It fits in 32 bits. |

5.3.1.1. The same chunk ID can appear more than once in the chunk list. A content without data has an empty chunk list and size 0.

5.3.1.2. A decoder MUST reject a content object when a field is missing, or when a field has another CBOR type or size than the table gives.

5.3.2. A content object has key class W. This lets the node find all chunks that an item uses, without the read key.

### 5.4. Item record (truth)

5.4.1. An item record is an enveloped object with type ID 4 and schema version 1. The body has these fields:

| Key | Field | CBOR type | Meaning |
|---|---|---|---|
| 1 | source ID | Byte string, 16 bytes | The source of the item (see 5.4.5.1) |
| 2 | native ID | Byte string | The ID that the source gives to the item (see 5.4.5.2) |
| 3 | title | Text string | A name to show, for example the subject of an email or the name of a file. It can be empty. |
| 4 | modified | Integer | The time of the last change at the source (see 5.4.5.3). The field is not present when the source has no such time. |
| 5 | created | Integer | The time of creation at the source (see 5.4.5.3). The field is not present when the source has no such time. |
| 6 | size | Unsigned integer | The sum of the sizes of the content objects of the item, in bytes |
| 7 | media type | Text string | The media type (RFC 6838), for example `text/plain`. The field is not present when it is not known. |
| 8 | metadata | Any CBOR item | Metadata that only the connector understands. The vault does not interpret it. The field is not present when there is none. |
| 9 | content | Array of byte strings, 32 bytes each | The object IDs of the content objects of the item, in an order that the connector defines. An item without content has an empty array. |

5.4.1.1. A reader MUST reject an item record that has no field 1, 2, 3, 6, or 9, or that has a field with another CBOR type or size than the table gives.

5.4.1.2. The native ID MUST be the native ID that the writer used to make the item key (see 5.6.5).

5.4.1.3. The metadata can be any CBOR item that 4.6.1 allows. It is deterministic CBOR like all of the object.

5.4.2. An item record MUST contain enough data to show the item without other objects, except its content.

5.4.3. An item record has key class R.

5.4.4. NilPerit MUST store raw originals byte for byte. Example: a Gmail message is stored as raw RFC 822 data.

5.4.5. **Fields that more than one object uses.**

5.4.5.1. A source ID is 16 random bytes. NilPerit makes them when it adds a source. The source ID is in item records, journal entries, and snapshot headers.

5.4.5.2. A native ID is a byte string of at least 1 byte. It is not a text string, because the names of files are not always valid text. The connector defines the meaning. Examples: a Gmail message ID, or the path of a file relative to the selected folder.

5.4.5.3. A time is an integer: the number of milliseconds since 1970-01-01 00:00:00 UTC. A time before 1970 is a negative integer. A time MUST fit in a signed integer of 64 bits. A connector that knows a more exact time can put it in the metadata of the item record (see 5.4.1).

### 5.5. Journal entries (truth)

5.5.1. Each source has one journal. A journal is a chain of journal entries. Each entry points to its parent entry and has a sequence number: the sequence number of its parent plus one.

5.5.2. A **delta entry** is an enveloped object with type ID 5 and schema version 1. The body has these fields:

| Key | Field | CBOR type | Meaning |
|---|---|---|---|
| 1 | source ID | Byte string, 16 bytes | The source of the journal |
| 2 | sequence number | Unsigned integer | The sequence number of the entry (see 5.5.1). The first entry of a journal has sequence number 1. |
| 3 | parent | Byte string, 32 bytes | The object ID of the parent entry. The field is not present in the first entry of a journal. |
| 4 | snapshot ID | Byte string, 16 bytes | The ID of the snapshot that this entry belongs to (see 5.9.1.1) |
| 5 | time | Integer | The time of the snapshot (see 5.4.5.3) |
| 6 | connector cursor | Byte string | The connector cursor after this entry. The field is not present when the connector has no cursor. |
| 7 | changed | Array of changes | The items that are new or that have a new version |
| 8 | deleted | Array of byte strings, 32 bytes each | The item keys of the items that the source no longer has |

5.5.2.1. A change is an array of 3 items: the item key (a byte string of 32 bytes), the object ID of the item record (a byte string of 32 bytes), and the object IDs of the content objects (an array of byte strings of 32 bytes each, as in field 9 of the item record). A change does not say if the item is new. A reader finds this out from the state before the entry.

5.5.2.2. In each of the arrays 7 and 8, the entries are in ascending order of the bytes of the item key. An item key MUST NOT occur more than once in the whole delta entry. Then the same changes always make the same bytes.

5.5.2.3. A reader that replays a delta entry sets the item record and the content objects of each item of the array 7. It removes the items of the array 8.

5.5.2.4. The field 3 (parent) is present if and only if the sequence number is above 1. A reader that follows the chain MUST check that the sequence number of an entry is the sequence number of its parent plus 1.

5.5.2.5. A writer SHOULD write one delta entry for each commit (see 8.4). A very large first synchronization is therefore not one very large delta entry.

5.5.3. A **checkpoint** contains the complete state of the source at one time. It contains:

- the connector cursor of that state;
- the **checkpoint tree**: all items that exist at that time;
- the **archive tree**: all item versions that do not exist at that time but that item retention still keeps (old versions and deleted items), each with the time NilPerit saw it first and the time NilPerit saw it last.

5.5.3.1. The connector cursor of a checkpoint MUST be the connector cursor that the source had in the state that the checkpoint contains. A checkpoint that replaces a range of journal entries (see 11.3.1) MUST contain the connector cursor of the last entry in that range.

5.5.4. Checkpoint trees and archive trees are truth. Their nodes are stored in data packs.

5.5.5. The current state of a source is the newest checkpoint plus all delta entries after it.

5.5.5.1. The current connector cursor of a source is the connector cursor in its journal head (see 5.5.8). It does not matter if the journal head is a delta entry or a checkpoint. A connector MUST continue from this cursor. NilPerit MUST NOT use the cursor of an orphan. Without a cursor, a connector has to read the whole source again.

5.5.6. NilPerit MUST write a checkpoint after a configurable number of delta entries or after a configurable time.

5.5.7. Journal entries, checkpoint trees, and archive trees have key class W.

5.5.8. **Journal head.** The head of a journal is the journal entry that the newest authenticated snapshot header of that source names (see 5.9). A journal entry that no snapshot header names, and that is not an ancestor of the head, is an orphan (see 8.5).

5.5.8.1. The newest snapshot header is the header with the highest sequence number in its journal position. NilPerit uses the time in the header only to select between headers with the same sequence number. It MUST NOT use time alone, because clocks can be wrong.

5.5.9. A new journal entry MUST use the current head as its parent. NilPerit MUST NOT use an orphan entry as a parent.

5.5.10. When all snapshot headers of a source are missing or damaged, a reader selects the head as follows:

1. It finds all journal entries of the source whose referenced objects are all present and valid, and whose chain of parents back to a checkpoint is also valid.
2. From these entries, it selects the entry with the highest sequence number.
3. When two entries have the same sequence number, it selects the entry with the latest time.
4. All other entries that are not ancestors of the selected head are orphans.

This procedure can select an entry that was complete but not committed. That is safe, because all objects that the entry references are present and valid.

5.5.11. A **fork** is two journal entries with the same parent, where each entry is named by an authenticated snapshot header or is an ancestor of such an entry. A fork can only come from two writers or from damage. A reader MUST report a fork. It MUST NOT discard either branch. A sweep MUST NOT remove a branch of a fork until the owner decides.

5.5.12. An orphan with the same parent as a committed entry is not a fork. Example: a crash leaves an uncommitted entry E5 with parent E4. The next run writes E5′ with parent E4 and commits it. E5 stays an orphan, and a sweep removes it after the grace period (see 8.5). E5 and E5′ have the same sequence number; this is not an error.

### 5.6. Trees

5.6.1. Checkpoint trees, archive trees, item maps, and archive maps all use the same structure: a sorted, content-addressed tree (prolly tree).

5.6.2. Trees share all unchanged subtrees. A new tree stores only the nodes that changed.

5.6.3. Leaf entries of a checkpoint tree and of an item map: item key → item record ID and content object IDs.

5.6.4. Leaf entries of an archive tree and of an archive map: item key and item record ID → content object IDs, time first seen, time last seen.

5.6.5. The item key is the hash of the source ID and the native ID in the hash domain "item key" (see 3.2.5). The hash input is: the size of the source ID as a 4-byte unsigned integer (little-endian), the source ID, the size of the native ID as a 4-byte unsigned integer (little-endian), and the native ID. The sizes make the input unambiguous.

5.6.6. Object IDs, item keys, and content hashes use different hash domains (see 3.2.5).

### 5.7. Item map (cache)

5.7.1. An item map shows all items of a source at one snapshot.

5.7.2. NilPerit makes an item map from the newest checkpoint tree before that snapshot plus the delta entries up to that snapshot.

5.7.3. Item map nodes have key class W.

### 5.8. Archive map (cache)

5.8.1. An archive map shows each item version that a source ever had and that retention still keeps, with the time NilPerit saw it first and the time NilPerit saw it last.

5.8.2. NilPerit makes the archive map from the newest archive tree plus all delta entries after it.

5.8.3. Archive map nodes have key class W.

### 5.9. Snapshot header (cache)

5.9.1. A snapshot header is an enveloped object with type ID 6 and schema version 1. The body has these fields:

| Key | Field | CBOR type | Meaning |
|---|---|---|---|
| 1 | source ID | Byte string, 16 bytes | The source of the snapshot |
| 2 | snapshot ID | Byte string, 16 bytes | The ID of the snapshot (see 5.9.1.1) |
| 3 | time | Integer | The time of the snapshot (see 5.4.5.3) |
| 4 | item map root | Byte string, 32 bytes | The object ID of the root of the item map. The field is not present while the writer makes no item maps. |
| 5 | parent snapshot | Byte string, 16 bytes | The snapshot ID of the previous snapshot of the source. The field is not present in the first snapshot. |
| 6 | journal entry | Byte string, 32 bytes | The object ID of the journal entry that is the head after this snapshot |
| 7 | journal sequence | Unsigned integer | The sequence number of that journal entry. Fields 6 and 7 are the journal position. |
| 8 | statistics | Map | A map with the unsigned integer keys 1 (the number of items that exist) and 2 (the sum of their sizes in bytes). The field is not present when the writer has no statistics. |
| 9 | vault | Map | A copy of the essential fields of the vault config (see 7.2.7): the keys 1, 3, 4, 5, 6, and 7 of the map in 7.2.2, with the same values |

5.9.1.1. A snapshot ID is 16 random bytes. The writer makes a new one for each snapshot. The ID and the name of its file say nothing about the time or the order of the snapshot. The time is in the field `time`, and the sequence number gives the order (see 5.5.8.1), because clocks can be wrong.

5.9.2. A snapshot header is one W object (see 3.3.7). All its fields, including the statistics, are encrypted.

5.9.3. NilPerit can make a snapshot header again from the journal (see 5.5.10).

5.9.4. A snapshot header is a file in the directory `snapshots/` of the vault. Its name is the snapshot ID in lowercase hexadecimal (32 characters). The bytes of the file are as in 3.3.7.1.

5.9.5. A reader MUST ignore a snapshot header when the name of its file is not the snapshot ID in the header, or when its vault ID is not the vault ID of the vault config that the reader uses.

## 6. Packs

6.1. A pack is an immutable file. Default target size: 16 MiB. A target MAY use a different size.

6.2. There are two pack classes:

- **Data packs** contain truth: chunks, content objects, item records, journal entries, checkpoint tree nodes, archive tree nodes. An item record SHOULD be in the same data pack as the chunks of its content.
- **Metadata packs** contain caches: item map nodes, archive map nodes, copies of item records.

6.3. Pack layout:

| Part | Content |
|---|---|
| Header | Magic bytes, header size, and a CBOR map with the format version, the pack class, and the algorithm names (see 6.7.1) |
| Body | Packed objects, one after the other (see 6.7.2) |
| Trailer | The sealed pack key (only when the pack contains R objects) and the object table (see 6.7.3) |
| Footer | A record of 24 bytes at the end of the file (see 6.7.4) |

6.3.1. The object table lists each object in the pack. For each object, it gives:

| Field | Meaning |
|---|---|
| object ID | The object ID (see 4.7) |
| object type | The type ID (see 4.4.3) |
| key class | "R" or "W", as a text string (see 3.3.1) |
| offset | The position of the first byte of the packed object, counted from the start of the pack file |
| packed size | The size of the packed object in bytes (see 6.7.2): the nonce, the encrypted bytes, and the tag |
| compression | The name of the compression algorithm, as a text string (see 6.6) |
| unpacked size | The size of the stored bytes of the object (see 4.7.2), in bytes. This is the size before compression. |

6.3.2. The object table has key class W. The node can read it without the read key. This lets the node rebuild the index and run a sweep.

6.3.3. The object table contains only opaque values. It MUST NOT contain titles, file names, or other plaintext data of the owner.

6.4. The name of a pack is the BLAKE3 hash of the complete encrypted file, in lowercase hexadecimal. Anyone can verify a pack without keys.

6.5. NilPerit SHOULD NOT put objects of sources with different priorities in the same pack.

### 6.6. Compression

6.6.1. NilPerit compresses the stored bytes of an object before it encrypts them. After it decrypts an object, it decompresses the bytes. The object ID does not depend on compression (see 4.7.2).

6.6.2. The compression field of the object table (see 6.3.1) names the algorithm. A name is a text string of lowercase ASCII characters. This draft defines these names:

| Name | Meaning |
|---|---|
| none | The bytes are not changed. |
| deflate | One DEFLATE stream (RFC 1951). It has no zlib header and no gzip header. |

6.6.3. A reader MUST reject a pack that has an object with a compression name that it does not know. It MUST NOT guess. This is the same rule as 6.7.1.3 for the algorithm names of the header, and as 4.5.1 for schema versions: an older reader stops at a newer format version (see 12.3), so an unknown name can only come from a bug or from damage.

6.6.4. **Reading.** A reader MUST check the AEAD tag of an object before it decompresses the object (see 9.3). The tag covers the compressed bytes. A reader MUST decompress an object to exactly the unpacked size of the object table. It MUST stop and reject the object when the output is longer than the unpacked size, and when the output is shorter. For the name "none", the decrypted bytes MUST have the unpacked size. When the reader has the dedup key, it MUST then check the object ID (see 4.7).

6.6.5. The writer chooses the algorithm of each object. The format does not say how. A writer MAY keep an object uncompressed when compression does not make it smaller.

6.6.6. Two replicas can store the same object with different algorithms (see 10.3).

6.6.7. NilPerit MUST NOT compress files outside packs (see 3.3.7).

6.6.8. A node can write objects that have a correct AEAD tag, because it has the writer key and the public part of the read key. A compromised node can therefore write compressed bytes that an attacker made. A decompressor MUST be safe against such input: it MUST NOT use unsafe code that depends on the input, and it MUST limit its output to the unpacked size (see 6.6.4).

6.6.9. The unpacked size and the packed size allow a reader to report the effect of compression without a read key.

### 6.7. Pack file format

6.7.1. **Header.** A pack starts with the header:

| Part | Size | Content |
|---|---|---|
| magic bytes | 8 bytes | `89 4e 50 4b 0d 0a 1a 0a` |
| header size | 4 bytes | The size of the header map in bytes, as an unsigned integer (little-endian) |
| header map | The header size | A CBOR map (see 6.7.1.2) |

6.7.1.1. A reader MUST reject a file that does not start with the magic bytes. A reader MUST reject a header size above 65536.

6.7.1.2. The header map is deterministic CBOR (see 4.2 and 4.6.2). It has unsigned integer keys. A reader ignores keys that it does not know (see 4.5). The keys are:

| Key | Field | CBOR type | Meaning |
|---|---|---|---|
| 1 | format version | Unsigned integer | The format version of the vault (see 12.1) |
| 2 | pack class | Unsigned integer | 0 for a data pack, 1 for a metadata pack (see 6.2) |
| 3 | encryption | Text string | The AEAD algorithm. This draft defines `xchacha20-poly1305`. |
| 4 | key encapsulation | Text string | The algorithm of the seal. The header has this field only when the pack has a sealed pack key. This draft defines `x-wing-draft-06` (see 3.3.2.1). |
| 5 | hash | Text string | The hash algorithm of object IDs and pack names. This draft defines `blake3`. |

6.7.1.3. A reader MUST stop when the format version is higher than the version that it knows (see 9.5). A reader MUST reject a pack with an encryption name or a hash name that it does not know (see 6.6.3).

6.7.1.4. The header is not encrypted. It contains no data of the owner. The associated data of the object table authenticates it (see 6.7.3.4). The header repeats the algorithm names of the vault config. A reader can therefore read a pack when the vault config is lost (see 10.7).

6.7.2. **Body.** The body starts directly after the header and ends where the trailer starts. It contains the packed objects, one after the other, without gaps. A packed object is:

| Part | Size | Content |
|---|---|---|
| nonce | 24 bytes | A random value. A writer makes a new one for each packed object. |
| ciphertext | The compressed size | The XChaCha20-Poly1305 encryption of the compressed stored bytes (see 6.6.1) |
| tag | 16 bytes | The AEAD tag |

6.7.2.1. The packed size of an object is 40 bytes more than its compressed size. With the name "none", the compressed size is the unpacked size.

6.7.2.2. NilPerit encrypts an R object with the pack key. It encrypts a W object with the pack object key (see 3.3.3).

6.7.2.3. The associated data of a packed object is the object ID (32 bytes), followed by the type ID as 4 bytes (little-endian). A packed object is therefore only valid for the object ID and the type ID of its entry in the object table. When an attacker moves it to another entry, the tag check fails. A reader MUST check the tag before it decompresses the bytes (see 6.6.4).

6.7.2.4. A writer MUST NOT use the same nonce twice with the same key.

6.7.3. **Trailer.** The trailer follows the body:

| Part | Size | Content |
|---|---|---|
| seal size | 4 bytes | The size of the sealed pack key in bytes, as an unsigned integer (little-endian) |
| sealed pack key | The seal size | The pack key, sealed to the public part of the read key (see 3.3.2). The format treats it as opaque bytes. |
| object table | The rest of the trailer | A packed object (see 6.7.2) |

6.7.3.1. The seal size is 0 when the pack has no R objects. The seal size MUST NOT be above 65536. A reader MUST reject a pack that has an R object and a seal size of 0.

6.7.3.2. The plaintext of the object table is an encoded envelope (see 4.4) with type ID 3, schema version 1, and a body with one field: key 1, an array of entries. The object table is encrypted with the pack table key (see 3.3.3). It is not an object in the body of a pack. It has no object ID.

6.7.3.3. Each entry is an array of 7 items, in this order:

| Position | Field | CBOR type |
|---|---|---|
| 1 | object ID | Byte string, 32 bytes |
| 2 | object type | Unsigned integer, below 2^32 |
| 3 | key class | Text string, "R" or "W" |
| 4 | offset | Unsigned integer |
| 5 | packed size | Unsigned integer |
| 6 | compression | Text string (see 6.6.2) |
| 7 | unpacked size | Unsigned integer |

6.7.3.4. The associated data of the object table is the BLAKE3 hash of the header: all bytes from the start of the pack up to the end of the header map. The hash is 32 bytes. This authenticates the header.

6.7.3.5. The entries are in the order of the body. A reader MUST reject the pack when:

- the offset of the first entry is not the end of the header;
- the offset of another entry is not the offset of the entry before it plus the packed size of that entry;
- the last packed object does not end where the trailer starts;
- an object ID occurs more than once;
- a key class is not "R" or "W";
- a compression name is not known (see 6.6.3);
- a packed size is below 40;
- a size is above a limit of 6.7.6.

6.7.3.6. A pack can have no objects. Its object table has no entries, and its trailer starts where its header ends. Such a pack has no use, but it is not an error.

6.7.4. **Footer.** The last 24 bytes of a pack are the footer:

| Part | Size | Content |
|---|---|---|
| trailer offset | 8 bytes | The position of the first byte of the trailer, counted from the start of the file. An unsigned integer (little-endian). |
| trailer size | 4 bytes | The size of the trailer in bytes. An unsigned integer (little-endian). |
| format version | 4 bytes | The format version, as in the header. An unsigned integer (little-endian). |
| end magic | 8 bytes | `4e 50 4b 2d 45 4e 44 0a` (the ASCII text "NPK-END" and a line feed) |

6.7.4.1. A reader MUST reject a pack when: the end magic is not correct; the trailer offset plus the trailer size plus 24 is not the size of the file; the trailer offset is before the end of the header; or the format version of the footer is not the format version of the header.

6.7.4.2. With the footer, a reader finds the trailer with one read of the end of the file. It needs no other information.

6.7.5. **Reading a pack.** A reader reads a pack as follows:

1. It reads the footer and checks it (see 6.7.4.1).
2. It reads the trailer.
3. It reads the header and checks it (see 6.7.1).
4. It decrypts the object table with the pack table key and the associated data of 6.7.3.4. It rejects the pack when the tag is not correct. It decodes the envelope and the entries, and checks them (see 6.7.3.5).
5. For each object that it needs, it reads the packed object (a read of the range that its entry gives), checks the tag, decompresses the bytes, and checks the object ID (see 6.7.2 and 6.6.4).

6.7.6. **Limits.** A reader MUST check these limits before it allocates memory for the data:

| Item | Limit |
|---|---|
| Header size | At most 65536 bytes |
| Seal size | At most 65536 bytes |
| Trailer size | At most 2^28 bytes (256 MiB) |
| Packed size of an object | Below 2^32 bytes (4 GiB) |
| Unpacked size of an object | Below 2^32 bytes (4 GiB) |

6.7.6.1. Offsets in the object table and in the footer are 64-bit values. A pack can be larger than 4 GiB.

6.7.6.2. The limits do not limit the size of a file, of a vault, or the number of packs. NilPerit cuts content into chunks (see 5.1) and a pack holds many objects. The limits only reject sizes that no writer makes.

6.7.6.3. A reader MAY apply lower limits when it has little memory, for example in a browser. It then reports that an object is too large for this reader. This is not an error of the format.

6.7.7. **Damage.** The pack is the unit of damage. When a byte of a pack is damaged, the hash of the file no longer agrees with the name (see 9.2). When the trailer or the footer is damaged, a reader cannot read any object of the pack, because the object table and the sealed pack key are in the trailer. NilPerit repairs a pack from another replica or from parity data (see 10.3 and 10.4).

## 7. Vault layout

```
vault/
  config-a          vault config, first copy (plaintext, MAC-authenticated)
  config-b          vault config, second copy
  FORMAT.md         copy of this specification (docs/format.md)
  schema/           schema dictionary (CDDL)
  recovery/         bundled reader software
  packs/ab/ab12…    packs; subdirectory = first two characters of the name
  index/            index segments (cache; W)
  snapshots/        snapshot headers (cache; W)
  condemned/        condemnation records (W)
  locks/            writer lock (plaintext)
```

7.1. FORMAT.md, schema/, and recovery/ are plaintext. They contain no data of the owner.

7.2. **Vault config.** The vault config is a plaintext file. It contains no data of the owner. The vault has two copies of it, in the root of the vault: `config-a` and `config-b`.

7.2.1. A config file is the bytes of one deterministic CBOR map (see 4.2 and 4.6.2), followed by a MAC of 32 bytes (see 3.3.8). A reader MUST reject a config file of more than 1 MiB.

7.2.2. The map has unsigned integer keys. A reader ignores keys that it does not know (see 4.5). The keys are:

| Key | Field | CBOR type | Meaning |
|---|---|---|---|
| 1 | format version | Unsigned integer | The format version of the vault (see 12.1) |
| 2 | config sequence | Unsigned integer | The number of the version of the config. It is 1 when NilPerit creates the vault, and grows by 1 with each change. |
| 3 | vault ID | Byte string, 16 bytes | Random bytes that NilPerit makes when it creates the vault. They tell the replicas of one vault apart from other vaults. |
| 4 | encryption | Text string | The AEAD algorithm, as in the pack header (see 6.7.1.2) |
| 5 | hash | Text string | The hash algorithm, as in the pack header |
| 6 | key encapsulation | Text string | The algorithm of the seal (see 3.3.2.1) |
| 7 | read public key | Byte string | The public part of the read key (see 3.2.9.1). For `x-wing-draft-06` it is 1216 bytes. |
| 8 | chunking profiles | Array | The table of chunking profiles (see 5.2). Each profile is an array of 5 items: the ID, the algorithm (a text string), the minimum size, the average size, and the maximum size (unsigned integers). |

7.2.3. The table of chunking profiles is append-only (see 5.2.2). A change adds profiles at the end and grows the config sequence by 1.

7.2.4. A reader MUST stop when the format version is higher than the version that it knows (see 9.5). The config is plaintext, so a reader can read the format version and the algorithm names before it has keys. A reader without keys cannot check the MAC. It MUST NOT trust the fields for more than to learn which version and algorithms it needs.

7.2.5. **Writing.** A writer writes both copies for each change. For each copy, it writes the file with a temporary name, syncs it, and then gives it the final name (see 8.1). It writes `config-a` first and `config-b` second. After a crash, the two copies can have different config sequences.

7.2.6. **Reading.** A reader that has the keys reads the vault config as follows:

1. It reads both files. It ignores a file that is missing, that is not deterministic CBOR, or whose MAC is not correct.
2. It uses the valid file with the highest config sequence.
3. When two valid files have the same config sequence but different bytes, the reader MUST stop and report a changed vault config.
4. When no file is valid, the reader MUST stop. Salvage (see 10.7) can rebuild the essential fields from snapshot headers.

7.2.7. The essential fields are the format version, the vault ID, the three algorithm names, and the read public key. Snapshot headers contain a copy of them (see 5.9.1). The chunking profiles are not essential for reading, because only a writer needs them.

7.2.8. The check of the read public key in 3.3.9 and 3.3.9.1 applies to the vault config that the reader uses.

7.3. recovery/ MUST contain a reader for the format version of the vault. TBD: exact contents and file names.

## 8. Commit procedure

8.1. NilPerit writes each file with a temporary name. It syncs the file to the storage device (fsync). Then it gives the file its final name.

8.2. The order is:

1. Data packs.
2. Metadata packs.
3. Index segments.
4. Snapshot header.

8.3. The snapshot header completes the commit. Before that step, the new data is not part of the vault. The journal entry that the snapshot header names becomes the journal head (see 5.5.8).

8.4. During a long synchronization, NilPerit SHOULD commit at intervals (for example every N MiB or every N minutes). A failure then loses only the work since the last commit.

8.5. A file that is not part of a commit is an orphan. An orphan is not an error. A later run can use it, or a sweep removes it.

8.6. Only one node can write to a vault at a time. The writer MUST hold the lock in locks/. The lock contains the node ID and a heartbeat time. A node MAY take a lock whose heartbeat is older than a configurable limit.

8.7. Readers do not need a lock, because files do not change.

## 9. Reading and verification

9.1. A reader MUST NOT trust the file system. Some targets (for example exFAT or FAT32 media) do not rename files atomically.

9.2. A reader that reads a whole pack MUST ignore it when the hash of the file does not agree with its name. A reader that reads parts of a pack (see 6.7.5) cannot check the name. It relies on the tags, which check every part that it uses. A scrub checks the names (see 10.1).

9.3. A reader MUST reject an object when its AEAD tag is not correct.

9.4. A reader MUST reject a snapshot header, condemnation record, or index segment when its AEAD tag is not correct. It MUST reject a vault config when its MAC is not correct (see 3.3.7 and 3.3.8).

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

1. **Condemn.** After each synchronization, NilPerit applies the retention rules. It writes a condemnation record for each expired journal range. A condemnation record does not remove data. NilPerit can revoke it.
2. **Sweep.**
   1. NilPerit starts from all live roots: the journal heads, and all journal entries, checkpoints, checkpoint trees, and archive trees that no active condemnation record marks.
   2. It finds all objects that these roots use. An object that no live root uses is unreachable.
   3. It removes a pack only when all objects in the pack are unreachable and the newest condemnation record that made them unreachable is older than the grace period. Orphan packs become eligible after the grace period too.
   4. It rewrites (repacks) a pack when more than a configurable part of it (default 30 %) is unreachable.

11.3.1. Journal entries, checkpoints, and trees are immutable. NilPerit cannot remove one part of them. To remove data, NilPerit uses compaction:

1. It writes a new checkpoint (or a combined delta entry) that keeps only the state that retention still needs.
2. Then it condemns the journal range that the new checkpoint replaces.

11.3.2. NilPerit uses compaction for both kinds of retention:

- **Snapshot retention:** snapshots are caches, so they are not roots. The new checkpoint keeps the state of the snapshots that retention keeps.
- **Item retention:** to expire item versions, the new checkpoint has a smaller archive tree without the expired versions.

11.4. A sweep MUST find live objects from the live roots, which are truth. It MUST NOT use reference counts or caches.

11.5. A sweep MUST hold the writer lock.

11.6. A sweep MUST work without the read key. It uses object tables, content objects, journal entries, and trees, which all have key class W.

11.7. To remove old journal history, NilPerit selects a checkpoint as the new base. The archive tree of that checkpoint MUST contain each item version whose item retention has not expired, with its time first seen and time last seen. Only after that, NilPerit condemns all journal entries before that checkpoint.

11.8. When a target is full, NilPerit MUST stop synchronization of sources with the lowest priority first. It MUST NOT remove data automatically, unless the owner enabled automatic cleanup for that target.

## 12. Versions and compatibility

12.1. The vault config contains one format version number.

12.2. A newer NilPerit version MUST be able to read all older format versions. It SHOULD be able to upgrade them.

12.3. An older NilPerit version that finds a newer format version MUST stop (see 9.5).

12.4. When NilPerit upgrades a vault, it MUST write the reader software for the new format version in the same commit (see 7.3).

12.5. All drafts of this specification use format version 0. Until format version 1, the format can change without a change of this number.

## 13. Open items

The items below are not fixed in this draft:

- ML-KEM implementation (3.3.2.1): RustCrypto `ml-kem` has never had an independent audit; `libcrux-ml-kem` (formally verified) is the main alternative. Also whether X-Wing is a final standard, and the name of the algorithm then.
- Contents and names in recovery/ (7.3).
- Parity data format (10.4).
- Fields of a checkpoint other than the connector cursor and the two trees (5.5.3): for example its time, and whether it has a snapshot ID. A checkpoint that compaction writes (11.3.1) does not come from a synchronization.
- Type IDs and the field numbers of the object types other than the chunk, the content object, the object table, the item record, the delta entry, and the snapshot header: the checkpoint, the tree nodes, the condemnation record, and the index segment (schema dictionary).
- The schema dictionary itself (4.6): NilPerit generates it from the Rust types. Until then, the field tables in section 5 are the only definition.

## Appendix A. Test vectors

These vectors are not normative. An implementation can use them to check itself. A different BLAKE3 implementation (the Python `blake3` package) made the hash values. All values are in hexadecimal.

### A.1. Envelope

A.1.1. Type 5, schema 1, body `{1: 7, 2: "ab"}`:

```
a3 00 05 01 01 02 a2 01 07 02 62 61 62
```

### A.2. Hash domains

A.2.1. The dedup key is the 32 bytes `00 01 02 ... 1f`.

A.2.2. The domain keys (see 3.2.5):

| Hash domain | Domain key |
|---|---|
| Object ID | `7a5a3c46561ae064a4d4b3451e3da054f24dec4aabca9289bbd86ac9d2272202` |
| Item key | `0c715b92de06677df044d97ee6d42629fbb18f268799e59f5b444da951e07dc1` |
| Content hash | `a4190220377899bde0d628774ca52f067303395c2c18784c9bb99cbd9a964cb8` |

### A.3. Object IDs

A.3.1. The stored bytes are the envelope `a3 00 05 01 01 02 a0` (type 5, schema 1, empty body). The hash input is the type ID as 4 bytes (little-endian), then the stored bytes (see 4.7).

| Type ID | Stored bytes | Object ID |
|---|---|---|
| 5 | the envelope above | `d7692ea1f63147927d8aaa890330123e9c2991cb6b84b5c86379614092707744` |
| 1 | the envelope above | `c71aea3d61bec2b68e7f2de593e86ab129268d43f78314b5c21c9830993070aa` |
| 1 | empty | `6578b1b6af05c75c4b025a910b22e152925a12f526fe40dea8ca134dbb64cddf` |

A.3.2. The second row shows that the type ID changes the object ID for the same bytes.

### A.4. Item keys

A.4.1. The hash input is the size of the source ID, the source ID, the size of the native ID, and the native ID. Each size is 4 bytes (little-endian) (see 5.6.5). The IDs in the table are ASCII text.

| Source ID | Native ID | Item key |
|---|---|---|
| `ab` | `c` | `1dc64f7e4a20b22b43463d82b7a5e732ed4b375aa5c3f339705f06792910548d` |
| `a` | `bc` | `a7e0457e53fc93fdd9d3a73b29ddfbbe09bdad9f5b2ae18d3876ec296a7f60d2` |
| `gmail` | `msg-1` | `5bedc3e15a00253238b061e48e4f2323246e8941c2d9fec30c59fd706353814d` |

A.4.2. The first two rows show that moving a byte from one part to the other changes the item key.

### A.5. Content hash

A.5.1. The content hash of the 5 bytes `hello` (ASCII) is `ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e`.

### A.6. Content object

A.6.1. A content object with two chunks, size 300000, and chunking profile 1. The chunk IDs are 32 bytes of `11` and 32 bytes of `22`. The content hash is 32 bytes of `33`. The stored bytes (120 bytes) are:

| Bytes | Meaning |
|---|---|
| `a3 00 02 01 01 02` | Envelope: map of 3, type 2, schema 1, key 2 (the body) |
| `a4` | Body: map of 4 |
| `01 82` | Key 1 (chunks): array of 2 |
| `58 20`, 32 bytes of `11` | First chunk ID |
| `58 20`, 32 bytes of `22` | Second chunk ID |
| `02 1a 00 04 93 e0` | Key 2 (size): 300000 |
| `03 58 20`, 32 bytes of `33` | Key 3 (content hash) |
| `04 01` | Key 4 (chunking profile): 1 |

A.6.2. The same bytes as one hexadecimal string:

```
a30002010102a401825820111111111111111111111111111111111111111111111111111111111111111158202222222222222222222222222222222222222222222222222222222222222222021a000493e003582033333333333333333333333333333333333333333333333333333333333333330401
```

A.6.3. The object ID of these stored bytes with type ID 2 and the dedup key of A.2.1 is `449fc1f8fb06c9aefa7fe47861cdf2f20b5af3fa1d316427cf2ddd2b504cf5e3`.

### A.7. Compression

A.7.1. The five bytes `hello` (ASCII) as one DEFLATE stream (name "deflate"):

```
cb 48 cd c9 c9 07 00
```

A.7.2. A reader MUST decode these seven bytes to the five bytes `68 65 6c 6c 6f`. Different encoders make different streams for the same input. A reader MUST accept every valid DEFLATE stream.

### A.8. Pack

A.8.1. A pack with two objects: a chunk (R, DEFLATE) and a content object (W, no compression) that lists the chunk. This is a test of the layout. The seal and the name of the key encapsulation algorithm are placeholders, because the vector has no X-Wing implementation. A real pack has random nonces, a seal of 1192 bytes (see 3.3.2.2), and the name `x-wing-draft-06`.

A.8.2. Inputs, all in hexadecimal:

| Item | Value |
|---|---|
| Dedup key | The 32 bytes `00 01 ... 1f` (see A.2.1) |
| Writer key | The 32 bytes `20 21 ... 3f` |
| Pack key | The 32 bytes `40 41 ... 5f`. A reader that opens the seal gets this key. |
| Nonce of the chunk | 24 bytes of `01` |
| Nonce of the content object | 24 bytes of `02` |
| Nonce of the object table | 24 bytes of `03` |
| Seal (placeholder) | `de ad be ef` |

A.8.3. Derived values:

| Item | Value |
|---|---|
| Pack object key (see 3.3.3) | `80f42359c8d9d1116b328bc1ff160b156b538c8a70d97e7a172ff6e85acab695` |
| Pack table key (see 3.3.3) | `3e270c1ce6008461ef7d7d2e9e6227e2a957be88a725a489b01c102567eab5a2` |
| Chunk | The 5 bytes `hello`. Type ID 1. |
| Chunk, compressed | `cb48cdc9c90700` (see A.7.1) |
| Object ID of the chunk | `09c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e` |
| Content hash of `hello` | `ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e` (see A.5.1) |
| Content object (stored bytes, 82 bytes) | `a30002010102a40181582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e0205035820ba57c82d8e9d4648188e4ef7eac18ec0c841bd7f817d115e1ed84bc0c05cb20e0401` |
| Object ID of the content object | `286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e` |
| Header map | Format version 0, pack class 0, encryption `xchacha20-poly1305`, key encapsulation `placeholder`, hash `blake3` |
| Associated data of the object table (BLAKE3 of the header) | `d71209092db378d52cf1f9427be77e17f9d6b91cc3fa98068912de99feb819ba` |
| Plaintext of the object table (109 bytes) | `a30003010102a1018287582009c8888470572d682a266f04f412785427dddaa76b540dfaf6d228727e51830e016152183a182f676465666c61746505875820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e0261571869187a646e6f6e651852` |

A.8.4. Layout of the pack (408 bytes):

| Part | Position | Size |
|---|---|---|
| Header | 0 | 58 |
| Packed object: the chunk (type 1, R, deflate) | 58 | 47 |
| Packed object: the content object (type 2, W, none) | 105 | 122 |
| Trailer: seal size, seal, packed object table | 227 | 157 |
| Footer | 384 | 24 |

A.8.5. The pack as one hexadecimal string:

```
894e504b0d0a1a0a2e000000a50100020003727863686163686132302d706f6c7931333035046b706c616365686f6c6465720566626c616b65330101010101010101010101010101010101010101010101014683820b6bdd17744f45bb9c2275d3d73057e39b980765020202020202020202020202020202020202020202020202c5e12b97bd9e2e7d093d49a7a9c7db234d82f2da194b7b55517ebcb80e3a652036e81578286e7506f30dcfb8a8ea38f7111dd372053a9b7c65a12982437fe67c87390691e4e97a85f48e30a866aa17f9bebfe753881f5c03d706534a1efb54a9fd9a04000000deadbeef030303030303030303030303030303030303030303030303641136128a959b741d53c008bbdf760f87c8ed6499d7ad62b8c483c0e134ba3c269eff66bb08c01ee9baf1a4a9608275c2a7e0e252b52c3bcdb28471056b637fca99bb999c6ff11fdd451bbaba53b9db719e0eb1f81e91603528d27060f14b5036b5818c1144c0fd989adddcc5353d7ab9ab11c81e9e47dc98fba75147e3000000000000009d000000000000004e504b2d454e440a
```

A.8.6. The name of this pack (the BLAKE3 hash of the 408 bytes) is `815dfe4dc31fbd77d535dbb466deb78b72b45ff294e6c32af5d43fdf7ad2288d`.

### A.9. Keys and the vault config

A.9.1. The root seed is the 32 bytes `a0 a1 ... bf`. The recovery phrase of this root seed is (BIP39, English word list):

```
pass artist pottery enable foil fatigue pencil crystal produce grace hill garage arch sun solution note repeat saddle common install rookie gain wife theme
```

A.9.2. The keys from the root seed (see 3.2.9):

| Key | Value |
|---|---|
| Dedup key | `817539ea4e9be3fb2c37fc4e8772d525e485efa986ddef131fa2791e397c81fb` |
| Writer key | `602b54db5ed2a3c74b36a568b852de6a126d2dec9b1971ea7c1f3ec4cf422c6c` |
| Read key | `e943a3cea78674c96b2354ec08caf3064ed001589a3919e75e59a4af2a333b77` |

A.9.3. The keys from the writer key of A.9.2 (see 3.3.3, 3.3.7, and 3.3.8):

| Key | Value |
|---|---|
| Config MAC key | `b6de912a5d95d54c54ac2487914b5ab0a3976e70ea126ac390eb1e5569ee953f` |
| Snapshot header key | `6f5e6da437a1f6651279a3b50bddffada3bcfde1573ba1285b41cba6fd460f61` |
| Condemnation record key | `0a96deb444a02736cfd2c4a70e0586f1e8c11abad91b0b6ef5a193d1f3bb8777` |
| Index segment key | `0e2db11232654989fd38827244a634d1ea545f11500c7453c63419997ae7b75f` |
| Pack object key | `b51b12b1ff96580e7e9faf30f1eacfa111927612515cee94780e4d4fa8a81508` |
| Pack table key | `ddc557fb4f9ce07ae8c74f25b59982ccad494a32786ac3eb27b83fbfa59834c0` |

A.9.4. A vault config. The read public key is a placeholder of 32 bytes `00 01 ... 1f`, because the vector has no X-Wing implementation. A real read public key is 1216 bytes. The vault ID is 16 bytes of `11`. The config sequence is 1. The chunking profiles are the two profiles of 5.2.4.

| Part | Value |
|---|---|
| The CBOR map (135 bytes) | `a80100020103501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0882850165666978656400001a00040000850265666978656400001a00200000` |
| The MAC (BLAKE3 keyed with the config MAC key, over the map) | `30c8938f3fdf3772fc4c9cd43ab4e1369ba11213952739ad63557d7b79b9fc25` |

A.9.5. The config file is the map followed by the MAC (167 bytes):

```
a80100020103501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0882850165666978656400001a00040000850265666978656400001a0020000030c8938f3fdf3772fc4c9cd43ab4e1369ba11213952739ad63557d7b79b9fc25
```

### A.10. Item record, delta entry, and snapshot header

A.10.1. The three objects of a vault with one file. They use the objects of A.8: the content object of A.8.3 and its content. The dedup key is the one of A.2.1.

| Item | Value |
|---|---|
| Source ID | 16 bytes of `22` |
| Snapshot ID | 16 bytes of `33` |
| Vault ID | 16 bytes of `11` |
| Native ID | The 14 bytes of the text `docs/hello.txt`: `646f63732f68656c6c6f2e747874` |
| Item key (see 5.6.5) | `b19168afa67b7e95eb7000c5f93f73444e09b92245b5232d0d287187e6a867f6` |
| Content object ID | `286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e` (A.8.3) |

A.10.2. The item record: title `hello.txt`, modified 1700000000000, size 5, media type `text/plain`, metadata `{"mode": 420}`, and the content object above. The stored bytes (122 bytes) are:

```
a30004010102a8015022222222222222222222222222222222024e646f63732f68656c6c6f2e747874036968656c6c6f2e747874041b0000018bcfe568000605076a746578742f706c61696e08a1646d6f64651901a409815820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e
```

The object ID (type ID 4) is `25306b653396b5fc2c2fe63cadd537d25a4380bbd717db64771b54303248dd8d`.

A.10.3. The first delta entry of the journal: sequence number 1, no parent, snapshot time 1700000001000, no connector cursor, one changed item (a new one), and no deleted items. The stored bytes (163 bytes) are:

```
a30005010102a60150222222222222222222222222222222220201045033333333333333333333333333333333051b0000018bcfe56be80781835820b19168afa67b7e95eb7000c5f93f73444e09b92245b5232d0d287187e6a867f6582025306b653396b5fc2c2fe63cadd537d25a4380bbd717db64771b54303248dd8d815820286259555c0bdd521d9b571868bdd3a2f0312c337ece16c43b8d78ffc246a12e0880
```

The object ID (type ID 5) is `7e1d2bde0b19face9b813766be8fde43a9bbccfd97d1144a941f289b5ac7b071`.

A.10.4. The snapshot header: no item map root, no parent snapshot, the journal position of A.10.3 (the delta entry and sequence 1), statistics for 1 item of 5 bytes, and a copy of the essential fields of the vault config of A.9.4 (the read public key is the same 32-byte placeholder). The stored bytes (198 bytes) are:

```
a30006010102a7015022222222222222222222222222222222025033333333333333333333333333333333031b0000018bcfe56be80658207e1d2bde0b19face9b813766be8fde43a9bbccfd97d1144a941f289b5ac7b071070108a20101020509a6010003501111111111111111111111111111111104727863686163686132302d706f6c79313330350566626c616b6533066f782d77696e672d64726166742d3036075820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

A.10.5. The file of the snapshot header (see 3.3.7.1): 24 bytes of `04` as the nonce, then the encryption with the snapshot header key of A.9.3 (`6f5e6da437a1f6651279a3b50bddffada3bcfde1573ba1285b41cba6fd460f61`) and empty associated data. The file (238 bytes) has the name `33333333333333333333333333333333`:

```
0404040404040404040404040404040404040404040404043fd86957fce00c0fb675d983ef209fee009fbfc3077e3f05d185b85623368b121a82fee11d28bcd7e0f51b14d7d91e8c75ecbccdfb3af3b3df7f5ca71fb7edafee08114c58fc9201e6ada754da09da912d4629ad6ba905c2ce2d92fa8ba85b0520eb762373ff5f09a1ab845e52ecd159d9d657246ecc7d415c6e8add8f1a020e9644d3d6eb55e71b0f866203bfcc37a854c6519851dafe949c570e6085b419c273cde6d5ed6fecedf4f43e7846d1af9489577e26714b46662ca1f852040748755ef0bcc0e7bd9928830782f47d4c842bc35d1e57f2be
```
