# Glossary

This glossary defines the technical names that NilPerit uses. All other documents use these names with these meanings only.

Status: **Draft**.

## Conventions

- Each term has one meaning. Do not use a different word for the same thing.
- A term in *italics* in a definition has its own entry in this glossary.
- Use "size" for a number of bytes: the size of an object, a pack, or a chunk. Use "length" only in CBOR terms, for example "indefinite-length".

## Terms

**AEAD tag**
The authentication value that XChaCha20-Poly1305 adds to each encrypted *object*. A reader rejects the object when the AEAD tag is not correct.

**Archive map**
A *cache* that shows each *item* version that a *source* ever had and that *item retention* still keeps. For each version, it records when NilPerit saw it first and when it saw it last. NilPerit makes it from the newest *archive tree* and the *delta entries* after it.

**Archive tree**
A tree in a *checkpoint* that contains all *item* versions that do not exist at that time but that *item retention* still keeps (old versions and deleted items), with the time first seen and the time last seen. An archive tree is *truth*.

**Associated data**
Data that an AEAD algorithm authenticates but does not encrypt. For a *packed object*, the associated data is the *object ID* and the type ID. If the associated data is not correct, the *AEAD tag* is not correct.

**Body**
The CBOR map in an *envelope* that contains the fields of an *object*. The keys are unsigned integers.

**Bundled reader**
The reader software that a *vault* contains. It lets a person read the vault without network access and without other software. See *nilperit-recover*.

**Cache**
Data that NilPerit can make again from the *truth*. When a cache is missing or damaged, NilPerit rebuilds it. Examples: the *index*, *item maps*, *archive maps*, *snapshot headers*.

**Checkpoint**
A *journal entry* that contains the complete state of a *source* at one time: a *checkpoint tree*, an *archive tree*, and the *connector cursor* of that state. A checkpoint does not depend on journal entries before it.

**Checkpoint tree**
A tree in a *checkpoint* that contains all *items* that exist at that time. A checkpoint tree is *truth*.

**Chunk**
A part of the bytes of a *content*. NilPerit cuts content into chunks with content-defined chunking. Each chunk has a *chunk ID*.

**Chunk ID**
The *object ID* of a *chunk*. Identical plaintext always gives the same chunk ID in the same *vault*.

**Chunker seed**
A secret value that the chunker uses to find cut points. NilPerit derives it from the *root seed*. It is fixed for the life of a *vault*.

**Chunking profile**
A set of chunker settings: algorithm, minimum size, average size, and maximum size. The *vault config* contains a table of chunking profiles. Each *content object* records the profile that NilPerit used for it.

**Commit**
The step that makes new data part of the *vault*. A commit is complete when NilPerit has written the *snapshot header*.

**Compaction**
The way NilPerit removes history. *Journal entries* and trees are immutable, so NilPerit writes a new *checkpoint* (or a combined *delta entry*) that keeps only what retention still needs, and then condemns the *journal* range that it replaces.

**Compression algorithm**
The algorithm that a writer used to compress an *object* before encryption, as a name in the *object table*. The name "none" means that the writer did not compress the object.

**Condemnation record**
A record that marks a range of *journal entries* for removal, after *compaction* has replaced it. A condemnation record does not remove data. NilPerit can revoke it until a *sweep* runs.

**Config sequence**
A number in the *vault config*. It is 1 when NilPerit creates the vault and grows by 1 with each change. A reader uses the valid copy of the vault config with the highest config sequence.

**Connector**
The code that gets data from one kind of external service or local system, for example Gmail or a local folder.

**Connector cursor**
A value from an external service that marks how far a *connector* has read the changes of that service, for example a Gmail history ID. NilPerit stores it in each *delta entry* and in each *checkpoint*. A *connector* continues from the cursor of the *journal head*.

**Content**
The bytes of one stored thing, for example one raw email message or one file.

**Content object**
An *object* that describes one *content*: the ordered list of *chunk IDs*, the total size, a keyed hash of the full content, and the *chunking profile*.

**Context string**
The fixed string that BLAKE3 `derive_key` uses together with its key material. Each *domain key* has its own context string.

**Data pack**
A *pack* that contains *truth*: *chunks*, *content objects*, *item records*, *journal entries*, and the nodes of *checkpoint trees* and *archive trees*.

**Dedup key**
The key from which NilPerit derives the *domain keys*. The *node* has this key.

**Delta entry**
A *journal entry* that contains only the changes since the previous journal entry of the same *source*.

**Domain key**
The key of one *hash domain*. NilPerit derives it from the *dedup key* and the *context string* of the domain.

**Envelope**
The outer CBOR map of an *object*. It has the object type, the schema version, and the *body*.

**Fork**
Two *journal entries* with the same parent, where each entry is named by an authenticated *snapshot header* or is an ancestor of such an entry. A fork can only come from two writers or from damage. An *orphan* with the same parent as a committed entry is not a fork.

**Grace period**
The time that must pass after a *condemnation record* or after the creation of an *orphan* before a *sweep* can remove the data.

**Hash domain**
One kind of keyed hash: *object ID*, *item key*, or content hash. Each hash domain has its own *domain key*. A hash of one hash domain never equals a hash of another.

**Index**
A *cache* that gives the location of each object: *pack*, offset, and *packed size*.

**Item**
One thing from a *source*, for example one email message or one file.

**Item key**
The hash of the source ID and the native ID of an *item* in the hash domain for item keys, for example for a Gmail message ID or a file path.

**Item map**
A *cache* that shows all *items* of a *source* at one *snapshot*. It is a sorted, content-addressed tree. NilPerit makes it from a *checkpoint tree* and the *delta entries* after it.

**Item record**
An *object* that describes one *item*: common fields (title, timestamps, size, media type), source-specific metadata, references to its *content objects*, the source ID, and the native ID. An item record has *key class* R.

**Item retention**
The rules that control how long NilPerit keeps *item* versions and deleted items.

**Journal**
The append-only chain of *journal entries* of one *source*. The journal is *truth*.

**Journal entry**
One immutable record in a *journal*: a *delta entry* or a *checkpoint*.

**Journal head**
The newest committed *journal entry* of a *source*: the entry that the newest authenticated *snapshot header* names. The newest snapshot header is the one with the highest *sequence number* in its *journal position*. A new journal entry uses the journal head as its parent.

**Journal position**
The ID and *sequence number* of a *journal entry*. A *snapshot header* records the journal position of the *journal head* after that *snapshot*.

**Key class**
The class of key that encrypts an *object*. Class R: only the *read key* can open the object (*chunks*, *item records*). Class W: the *writer key* opens the object, so the *node* and the owner can read it (all other objects).

**Metadata pack**
A *pack* that contains *caches*, for example *item map* nodes, *archive map* nodes, and copies of *item records*.

**Native ID**
The ID that a *source* gives to an *item*, as a byte string. Examples: a Gmail message ID, or the path of a file relative to the selected folder. NilPerit makes the *item key* from the source ID and the native ID.

**nilperit-recover**
The reader-only program. It can list, extract, verify, and salvage data. It cannot write to a *vault*.

**Node**
A running NilPerit process that gets data from *sources* and writes it to a *vault*.

**Node credential**
The set of keys that a *node* needs to write: the public part of the *read key*, the *dedup key*, the *writer key*, and the *chunker seed*. With the node credential, a node can add data but cannot read stored *content*.

**Object**
One encoded unit of data in a *vault*, for example a *chunk*, a *content object*, an *item record*, a *journal entry*, or a tree node. Each object has an *object ID*, an object type, and a *key class*.

**Object ID**
The hash of the *stored bytes* of an *object* in the *hash domain* for object IDs, with the object type in front of the bytes. The same object has the same object ID in all *replicas*.

**Object table**
The list in the trailer of a *pack* that gives, for each *object* in the pack, its *object ID*, object type, *key class*, offset, *packed size*, *compression algorithm*, and *unpacked size*. The object table has *key class* W.

**Orphan**
A file that is not part of a completed *commit*, for example a *pack* from an interrupted synchronization. An orphan is not an error.

**Pack**
An immutable file that contains many encrypted objects. The name of a pack is the hash of its encrypted bytes. See *data pack* and *metadata pack*.

**Pack footer**
The last 24 bytes of a *pack*. It gives the position and the size of the *pack trailer* and ends with a fixed end marker.

**Pack header**
The start of a *pack*: fixed magic bytes, a size, and a CBOR map with the format version, the pack class, and the algorithm names.

**Pack key**
A random key for the *key class* R *objects* in one *pack*. NilPerit *seals* the pack key to the *read key*.

**Pack trailer**
The part of a *pack* after the body. It contains the sealed *pack key* (only when the pack has R *objects*) and the *object table*.

**Packed object**
The bytes that an *object* uses in the body of a *pack*: a random nonce, the encrypted bytes (after compression), and the *AEAD tag*.

**Packed size**
The size of the *packed object*.

**Parity data**
Optional Reed–Solomon recovery data for a *pack*. With parity data, NilPerit can repair some damage to the pack without another copy.

**Priority**
A number that a person gives to a *source*. Priority controls the order of synchronization, *replica* synchronization, and cleanup under storage pressure.

**Read key**
The X-Wing key pair (a hybrid of X25519 and ML-KEM-768) that opens *objects* of *key class* R. NilPerit derives it from the *root seed*. Only the owner has the private part.

**Recovery phrase**
The *root seed*, written as 24 words. With the recovery phrase and one copy of a *vault*, a person can recover all data in that copy.

**Replica**
A copy of a *vault*, or of a part of a vault, on a *target*.

**Root seed**
32 random bytes that NilPerit makes when it creates a *vault*. NilPerit derives all keys from the root seed.

**Salvage**
A recovery procedure that scans all readable *packs* and rebuilds as much data as possible without *caches*.

**Scrub**
A procedure that reads stored data and checks its integrity.

**Seal**
To encrypt a key so that only the holder of a private key can open it. NilPerit seals each *pack key* to the public part of the *read key* with X-Wing, a hybrid key encapsulation (X25519 and ML-KEM-768).

**Sequence number**
The position of a *journal entry* in its *journal*: the sequence number of its parent plus one.

**Snapshot**
The state of one *source* at one point in time.

**Snapshot header**
A small *cache* object that points to the *item map* of a *snapshot* and records the *journal position* of the *journal head*. NilPerit writes it last during a *commit*. It has *key class* W.

**Snapshot ID**
The identifier of one *snapshot*: 16 random bytes that the writer makes for each snapshot. The name of the file of a *snapshot header* is the snapshot ID in hexadecimal.

**Snapshot retention**
The rules that control which *snapshots* NilPerit keeps.

**Source**
One *connector* account with one selection, for example "Gmail, label Banking". Each source has its own *journal*, *snapshots*, retention rules (*snapshot retention* and *item retention*), and *priority*.

**Source ID**
16 random bytes that NilPerit makes when it adds a *source*. They are in *item records*, *journal entries*, and *snapshot headers*.

**Stored bytes**
The bytes of an *object* that NilPerit hashes. For an enveloped object, they are the encoded *envelope*, exactly as a writer wrote it. For a raw object (a *chunk*), they are the plaintext before compression. NilPerit computes the *object ID* from the stored bytes and never from a new encoding.

**Sweep**
A procedure that removes *packs* whose *objects* no live root uses any more, after the *grace period*. Live roots are the *journal heads*, and all *journal entries*, *checkpoints*, *checkpoint trees*, and *archive trees* that no active *condemnation record* marks. *Snapshots* are not roots, because they are *caches*.

**Target**
A storage location for a *vault* or a *replica*, for example a local disk, a USB stick, or a remote server.

**Tree**
A sorted, content-addressed tree of *objects* (a prolly tree). Trees share all unchanged subtrees. *Checkpoint trees*, *archive trees*, *item maps*, and *archive maps* are trees.

**Truth**
Immutable data that NilPerit cannot make again from other data in the *vault*: *chunks*, *content objects*, *item records*, *journal entries*, *checkpoint trees*, and *archive trees*.

**Unpacked size**
The size of the *stored bytes* of an *object*: the size before compression.

**Vault**
The complete stored data of one NilPerit installation on one *target*.

**Vault config**
The object that contains the format version, the vault ID, the public part of the *read key*, and the table of *chunking profiles*.

**Vault ID**
16 random bytes in the *vault config*. They tell the *replicas* of one *vault* apart from other vaults.

**Writer key**
A symmetric key that opens *objects* of *key class* W. The *node* uses it for objects that it must read again, for example *journal entries*, *content objects*, trees, and *object tables*.
