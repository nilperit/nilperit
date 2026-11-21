# Glossary

This glossary defines the technical names that NilPerit uses. All other documents use these names with these meanings only.

Status: **Draft**.

## Conventions

- Each term has one meaning. Do not use a different word for the same thing.
- A term in *italics* in a definition has its own entry in this glossary.

## Terms

**Archive map**
A *cache* that shows each *item* version that a *source* ever had. For each version, it records when NilPerit saw it first and when it saw it last. *Item retention* uses the archive map.

**Bundled reader**
The reader software that a *vault* contains. It lets a person read the vault without network access and without other software. See *nilperit-recover*.

**Cache**
Data that NilPerit can make again from the *truth*. When a cache is missing or damaged, NilPerit rebuilds it. Examples: the *index*, *item maps*, *archive maps*, *snapshot headers*.

**Checkpoint**
A *journal entry* that contains the complete current state of a *source*. A checkpoint does not depend on journal entries before it.

**Chunk**
A part of the bytes of a *content*. NilPerit cuts content into chunks with content-defined chunking. Each chunk has a *chunk ID*.

**Chunk ID**
The keyed BLAKE3 hash of the plaintext of a *chunk*. The key is the *dedup key*. Identical plaintext always gives the same chunk ID in the same *vault*.

**Chunker seed**
A secret value that the chunker uses to find cut points. NilPerit derives it from the *root seed*. It is fixed for the life of a *vault*.

**Chunking profile**
A set of chunker settings: algorithm, minimum size, average size, and maximum size. The *vault config* contains a table of chunking profiles. Each *content object* records the profile that NilPerit used for it.

**Commit**
The step that makes new data part of the *vault*. A commit is complete when NilPerit has written the *snapshot header*.

**Condemnation record**
A record that marks objects for removal. A condemnation record does not remove data. NilPerit can revoke it until a *sweep* runs.

**Connector**
The code that gets data from one kind of external service or local system, for example Gmail or a local folder.

**Content**
The bytes of one stored thing, for example one raw email message or one file.

**Content object**
An object that describes one *content*: the ordered list of *chunk IDs*, the total length, a hash of the full content, and the *chunking profile*.

**Data pack**
A *pack* that contains *truth*: *chunks*, *content objects*, *item records*, and *journal entries*.

**Dedup key**
The key for the keyed hash that makes *chunk IDs*. The *node* has this key.

**Delta entry**
A *journal entry* that contains only the changes since the previous journal entry of the same *source*.

**Index**
A *cache* that gives the location of each object: *pack*, offset, and length.

**Item**
One thing from a *source*, for example one email message or one file.

**Item key**
The keyed hash of the native ID of an *item*, for example the hash of a Gmail message ID or of a file path.

**Item map**
A *cache* that shows all *items* of a *source* at one point in time. It is a sorted, content-addressed tree.

**Item record**
An object that describes one *item*: common fields (title, timestamps, size, media type), source-specific metadata, references to its *content objects*, the source ID, and the native ID. Only the *read key* can open an item record.

**Item retention**
The rules that control how long NilPerit keeps *item* versions and deleted items.

**Journal**
The append-only chain of *journal entries* of one *source*. The journal is *truth*.

**Journal entry**
One immutable record in a *journal*: a *delta entry* or a *checkpoint*.

**Metadata pack**
A *pack* that contains *caches*, for example *item map* nodes, *archive map* nodes, and copies of *item records*.

**nilperit-recover**
The reader-only program. It can list, extract, verify, and salvage data. It cannot write to a *vault*.

**Node**
A running NilPerit process that gets data from *sources* and writes it to a *vault*.

**Node credential**
The set of keys that a *node* needs to write: the public part of the *read key*, the *dedup key*, the *writer key*, and the *chunker seed*. With the node credential, a node can add data but cannot read stored *content*.

**Pack**
An immutable file that contains many encrypted objects. The name of a pack is the hash of its encrypted bytes. See *data pack* and *metadata pack*.

**Pack key**
A random key for one *pack*. NilPerit seals the pack key to the *read key*.

**Parity data**
Optional Reed–Solomon recovery data for a *pack*. With parity data, NilPerit can repair some damage to the pack without another copy.

**Priority**
A number that a person gives to a *source*. Priority controls the order of synchronization, *replica* synchronization, and cleanup under storage pressure.

**Read key**
The hybrid key pair (X25519 and ML-KEM) that opens *item records* and *chunks*. Only the owner has the private part.

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

**Snapshot**
The state of one *source* at one point in time.

**Snapshot header**
A small *cache* object that points to the *item map* of a *snapshot*. NilPerit writes it last during a *commit*.

**Snapshot retention**
The rules that control which *snapshots* NilPerit keeps.

**Source**
One *connector* account with one selection, for example "Gmail, label Banking". Each source has its own *journal*, *snapshots*, retention rules (*snapshot retention* and *item retention*), and *priority*.

**Sweep**
A procedure that removes *packs* that no live object uses and that a *condemnation record* marks, after a grace period.

**Target**
A storage location for a *vault* or a *replica*, for example a local disk, a USB stick, or a remote server.

**Truth**
Immutable data that NilPerit cannot make again from other data in the *vault*: *chunks*, *content objects*, *item records*, and *journal entries*.

**Vault**
The complete stored data of one NilPerit installation on one *target*.

**Vault config**
The object that contains the format version, the vault ID, the public part of the *read key*, and the table of *chunking profiles*.

**Writer key**
A symmetric key that the *node* uses to encrypt objects that it must read again, for example *journal entries*, *content objects*, and *item maps*.
