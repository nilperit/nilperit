# Glossary

This glossary defines the technical names that NilPerit uses. All other documents use these names with these meanings only.

Status: **Draft**.

## Conventions

- Each term has one meaning. Do not use a different word for the same thing.
- A term in *italics* in a definition has its own entry in this glossary.

## Terms

**Archive map**
A *cache* that shows each *item* version that a *source* ever had and that *item retention* still keeps. For each version, it records when NilPerit saw it first and when it saw it last. NilPerit makes it from the newest *archive tree* and the *delta entries* after it.

**Archive tree**
A tree in a *checkpoint* that contains all *item* versions that do not exist at that time but that *item retention* still keeps (old versions and deleted items), with the time first seen and the time last seen. An archive tree is *truth*.

**Bundled reader**
The reader software that a *vault* contains. It lets a person read the vault without network access and without other software. See *nilperit-recover*.

**Cache**
Data that NilPerit can make again from the *truth*. When a cache is missing or damaged, NilPerit rebuilds it. Examples: the *index*, *item maps*, *archive maps*, *snapshot headers*.

**Checkpoint**
A *journal entry* that contains the complete state of a *source* at one time: a *checkpoint tree* and an *archive tree*. A checkpoint does not depend on journal entries before it.

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

**Condemnation record**
A record that marks a range of *journal entries* for removal, after *compaction* has replaced it. A condemnation record does not remove data. NilPerit can revoke it until a *sweep* runs.

**Connector**
The code that gets data from one kind of external service or local system, for example Gmail or a local folder.

**Connector cursor**
A value from an external service that marks how far a *connector* has read the changes of that service, for example a Gmail history ID. NilPerit stores it in each *delta entry*.

**Content**
The bytes of one stored thing, for example one raw email message or one file.

**Content object**
An *object* that describes one *content*: the ordered list of *chunk IDs*, the total length, a keyed hash of the full content, and the *chunking profile*.

**Data pack**
A *pack* that contains *truth*: *chunks*, *content objects*, *item records*, *journal entries*, and the nodes of *checkpoint trees* and *archive trees*.

**Dedup key**
The key for the keyed hash that makes *object IDs* and *item keys*. The *node* has this key.

**Fork**
Two *journal entries* with the same parent, where each entry is named by an authenticated *snapshot header* or is an ancestor of such an entry. A fork can only come from two writers or from damage. An *orphan* with the same parent as a committed entry is not a fork.

**Grace period**
The time that must pass after a *condemnation record* or after the creation of an *orphan* before a *sweep* can remove the data.

**Delta entry**
A *journal entry* that contains only the changes since the previous journal entry of the same *source*.

**Index**
A *cache* that gives the location of each object: *pack*, offset, and length.

**Item**
One thing from a *source*, for example one email message or one file.

**Item key**
The keyed hash of the native ID of an *item*, for example the hash of a Gmail message ID or of a file path.

**Item map**
A *cache* that shows all *items* of a *source* at one *snapshot*. It is a sorted, content-addressed tree. NilPerit makes it from a *checkpoint tree* and the *delta entries* after it.

**Item record**
An *object* that describes one *item*: common fields (title, timestamps, size, media type), source-specific metadata, references to its *content objects*, the source ID, and the native ID. An item record has *key class* R.

**Item retention**
The rules that control how long NilPerit keeps *item* versions and deleted items.

**Journal**
The append-only chain of *journal entries* of one *source*. The journal is *truth*.

**Journal head**
The newest committed *journal entry* of a *source*: the entry that the newest authenticated *snapshot header* names. The newest snapshot header is the one with the highest *sequence number* in its *journal position*. A new journal entry uses the journal head as its parent.

**Journal entry**
One immutable record in a *journal*: a *delta entry* or a *checkpoint*.

**Journal position**
The ID and *sequence number* of a *journal entry*. A *snapshot header* records the journal position of the *journal head* after that *snapshot*.

**Key class**
The class of key that encrypts an *object*. Class R: only the *read key* can open the object (*chunks*, *item records*). Class W: the *writer key* opens the object, so the *node* and the owner can read it (all other objects).

**Metadata pack**
A *pack* that contains *caches*, for example *item map* nodes, *archive map* nodes, and copies of *item records*.

**nilperit-recover**
The reader-only program. It can list, extract, verify, and salvage data. It cannot write to a *vault*.

**Node**
A running NilPerit process that gets data from *sources* and writes it to a *vault*.

**Object**
One encoded unit of data in a *vault*, for example a *chunk*, a *content object*, an *item record*, a *journal entry*, or a tree node. Each object has an *object ID*, an object type, and a *key class*.

**Object ID**
The keyed BLAKE3 hash of the plaintext encoding of an *object*, with the object type as domain separation. The key is the *dedup key*. The same object has the same object ID in all *replicas*.

**Object table**
The list in the trailer of a *pack* that gives, for each *object* in the pack, its *object ID*, object type, *key class*, offset, and length. The object table has *key class* W.

**Orphan**
A file that is not part of a completed *commit*, for example a *pack* from an interrupted synchronization. An orphan is not an error.

**Node credential**
The set of keys that a *node* needs to write: the public part of the *read key*, the *dedup key*, the *writer key*, and the *chunker seed*. With the node credential, a node can add data but cannot read stored *content*.

**Pack**
An immutable file that contains many encrypted objects. The name of a pack is the hash of its encrypted bytes. See *data pack* and *metadata pack*.

**Pack key**
A random key for the *key class* R *objects* in one *pack*. NilPerit *seals* the pack key to the *read key*.

**Parity data**
Optional Reed–Solomon recovery data for a *pack*. With parity data, NilPerit can repair some damage to the pack without another copy.

**Priority**
A number that a person gives to a *source*. Priority controls the order of synchronization, *replica* synchronization, and cleanup under storage pressure.

**Read key**
The hybrid key pair (X25519 and ML-KEM) that opens *objects* of *key class* R. Only the owner has the private part.

**Recovery phrase**
The *root seed*, written as 24 words. With the recovery phrase and one copy of a *vault*, a person can recover all data in that copy.

**Replica**
A copy of a *vault*, or of a part of a vault, on a *target*.

**Root seed**
32 random bytes that NilPerit makes when it creates a *vault*. NilPerit derives all keys from the root seed.

**Salvage**
A recovery procedure that scans all readable *packs* and rebuilds as much data as possible without *caches*.

**Sequence number**
The position of a *journal entry* in its *journal*: the sequence number of its parent plus one.

**Seal**
To encrypt a key so that only the holder of a private key can open it. NilPerit seals each *pack key* to the public part of the *read key* with a hybrid key encapsulation (X25519 and ML-KEM).

**Scrub**
A procedure that reads stored data and checks its integrity.

**Snapshot**
The state of one *source* at one point in time.

**Snapshot ID**
The identifier of one *snapshot*.

**Snapshot header**
A small *cache* object that points to the *item map* of a *snapshot* and records the *journal position* of the *journal head*. NilPerit writes it last during a *commit*. It has *key class* W.

**Snapshot retention**
The rules that control which *snapshots* NilPerit keeps.

**Source**
One *connector* account with one selection, for example "Gmail, label Banking". Each source has its own *journal*, *snapshots*, retention rules (*snapshot retention* and *item retention*), and *priority*.

**Sweep**
A procedure that removes *packs* whose *objects* no live root uses any more, after the *grace period*. Live roots are the *journal heads*, and all *journal entries*, *checkpoints*, *checkpoint trees*, and *archive trees* that no active *condemnation record* marks. *Snapshots* are not roots, because they are *caches*.

**Target**
A storage location for a *vault* or a *replica*, for example a local disk, a USB stick, or a remote server.

**Tree**
A sorted, content-addressed tree of *objects* (a prolly tree). Trees share all unchanged subtrees. *Checkpoint trees*, *archive trees*, *item maps*, and *archive maps* are trees.

**Truth**
Immutable data that NilPerit cannot make again from other data in the *vault*: *chunks*, *content objects*, *item records*, *journal entries*, *checkpoint trees*, and *archive trees*.

**Vault**
The complete stored data of one NilPerit installation on one *target*.

**Vault config**
The object that contains the format version, the vault ID, the public part of the *read key*, and the table of *chunking profiles*.

**Writer key**
A symmetric key that opens *objects* of *key class* W. The *node* uses it for objects that it must read again, for example *journal entries*, *content objects*, trees, and *object tables*.
