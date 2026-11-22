//! Reading an item and its content (format.md 5.1, 5.3, 5.4).

use crate::index::PackIndex;
use crate::journal::ItemState;
use crate::pack::ObjectReadError;
use crate::target::Target;
use crate::vault::Vault;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;
use nilperit_format::object_type::CHUNK;
use nilperit_format::{ContentObject, ItemKey, ItemRecord, ObjectError, ObjectId};

/// An item or its content cannot be read.
#[derive(Debug)]
pub enum ContentError<E = Infallible> {
    /// An object is not in any pack that opened. The value is its object ID.
    Missing(ObjectId),
    /// An object is in a pack, but it cannot be read.
    Unreadable(ObjectId, ObjectReadError),
    /// The bytes of an object are not a valid object of the expected type.
    Invalid(ObjectId, ObjectError),
    /// The objects do not fit together. The text says how.
    Inconsistent(&'static str),
    /// The sink that received the content returned an error.
    Sink(E),
}

impl<E: fmt::Display> fmt::Display for ContentError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(id) => write!(f, "object {id} is missing"),
            Self::Unreadable(id, e) => write!(f, "object {id} cannot be read: {e}"),
            Self::Invalid(id, e) => write!(f, "object {id} is not valid: {e}"),
            Self::Inconsistent(what) => write!(f, "{what}"),
            Self::Sink(e) => write!(f, "the receiver of the content failed: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for ContentError<E> {}

impl<T: Target> Vault<T> {
    /// Reads the item record of an item that the journal replay found.
    ///
    /// It checks that the item key is the key of the source and the native ID in
    /// the record (format.md 5.4.1.2), and that the content objects of the record
    /// are the ones that the journal entry names (5.5.2.1).
    pub async fn read_item(
        &self,
        index: &PackIndex,
        key: &ItemKey,
        state: &ItemState,
    ) -> Result<ItemRecord, ContentError> {
        let id = &state.item_record;
        let stored = self.read_typed(index, id, ItemRecord::TYPE_ID).await?;
        let record = ItemRecord::decode(&stored).map_err(|e| ContentError::Invalid(*id, e))?;
        let expected = self
            .keys()
            .domains()
            .item_key(record.source_id.as_bytes(), &record.native_id)
            .map_err(|_| ContentError::Inconsistent("the native ID is too large"))?;
        if expected != *key.as_bytes() {
            return Err(ContentError::Inconsistent(
                "the item key is not the key of the item record",
            ));
        }
        if record.content != state.content {
            return Err(ContentError::Inconsistent(
                "the item record and the journal entry name different content objects",
            ));
        }
        Ok(record)
    }

    /// Reads one content object and gives its bytes, chunk by chunk, to `sink`.
    ///
    /// Every chunk is checked when it is read (its tag and its object ID). The
    /// size and the content hash can only be checked after the last chunk. **The
    /// sink therefore receives data before the whole content is verified.** A
    /// caller MUST treat the output as incomplete until this function returns
    /// `Ok`, and MUST discard it when it returns an error. It returns the size.
    pub async fn read_content<E>(
        &self,
        index: &PackIndex,
        id: &ObjectId,
        mut sink: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<u64, ContentError<E>> {
        let stored = self
            .read_typed(index, id, ContentObject::TYPE_ID)
            .await
            .map_err(widen)?;
        let content = ContentObject::decode(&stored).map_err(|e| ContentError::Invalid(*id, e))?;

        let mut hasher = self.keys().domains().content_hasher();
        let mut total: u64 = 0;
        for chunk_id in &content.chunks {
            let chunk = self
                .read_typed(index, chunk_id, CHUNK)
                .await
                .map_err(widen)?;
            total += chunk.len() as u64;
            if total > content.size {
                return Err(ContentError::Inconsistent(
                    "the chunks are larger than the size of the content",
                ));
            }
            hasher.update(&chunk);
            sink(&chunk).map_err(ContentError::Sink)?;
        }
        if total != content.size {
            return Err(ContentError::Inconsistent(
                "the chunks are smaller than the size of the content",
            ));
        }
        if hasher.finalize() != *content.content_hash.as_bytes() {
            return Err(ContentError::Inconsistent(
                "the content does not have its content hash",
            ));
        }
        Ok(total)
    }

    /// Reads one content object into memory. Nothing is returned unless the whole
    /// content is verified. Use it for content that is small enough for memory.
    pub async fn read_content_to_vec(
        &self,
        index: &PackIndex,
        id: &ObjectId,
    ) -> Result<Vec<u8>, ContentError> {
        let mut out = Vec::new();
        self.read_content(index, id, |chunk| {
            out.extend_from_slice(chunk);
            Ok::<(), Infallible>(())
        })
        .await?;
        Ok(out)
    }

    async fn read_typed(
        &self,
        index: &PackIndex,
        id: &ObjectId,
        object_type: u32,
    ) -> Result<Vec<u8>, ContentError> {
        self.read_indexed(index, id, object_type)
            .await
            .map_err(|e| match e {
                ObjectReadError::NotInPack => ContentError::Missing(*id),
                e => ContentError::Unreadable(*id, e),
            })
    }
}

/// Moves an error that has no sink error into the error type of a caller.
fn widen<E>(e: ContentError) -> ContentError<E> {
    match e {
        ContentError::Missing(id) => ContentError::Missing(id),
        ContentError::Unreadable(id, e) => ContentError::Unreadable(id, e),
        ContentError::Invalid(id, e) => ContentError::Invalid(id, e),
        ContentError::Inconsistent(what) => ContentError::Inconsistent(what),
        ContentError::Sink(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        TestKeys, TestObject, block_on, build_pack, node_vault_with, test_seed, typed_object,
        vault_with,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use nilperit_format::object_type::{CONTENT_OBJECT, ITEM_RECORD};
    use nilperit_format::{ContentHash, KeyClass, SourceId};

    fn chunk(bytes: &[u8]) -> (TestObject, ObjectId) {
        typed_object(CHUNK, KeyClass::R, bytes)
    }

    fn content_hash(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = TestKeys::from_seed(&test_seed())
            .dedup
            .domain_keys()
            .content_hasher();
        hasher.update(bytes);
        hasher.finalize()
    }

    fn content(chunks: &[ObjectId], size: u64, hash: [u8; 32]) -> (TestObject, ObjectId) {
        let object = ContentObject {
            chunks: chunks.to_vec(),
            size,
            content_hash: ContentHash::from_bytes(hash),
            chunking_profile: 1,
        };
        typed_object(CONTENT_OBJECT, KeyClass::W, &object.encode().unwrap())
    }

    /// A vault with one pack that holds the objects, and its index.
    fn store(objects: Vec<TestObject>) -> (Vault<crate::MemoryTarget>, PackIndex) {
        let (bytes, _) = build_pack(&TestKeys::from_seed(&test_seed()), &objects);
        let vault = vault_with(&[&bytes], &[]);
        let index = block_on(vault.scan_packs()).unwrap();
        (vault, index)
    }

    /// Content of three chunks, the first one twice.
    fn three_chunks() -> (Vec<TestObject>, ObjectId, Vec<u8>) {
        let (a, ida) = chunk(b"first chunk ");
        let (b, idb) = chunk(b"second chunk ");
        let whole = b"first chunk second chunk first chunk ".to_vec();
        let (c, idc) = content(&[ida, idb, ida], whole.len() as u64, content_hash(&whole));
        (vec![a, b, c], idc, whole)
    }

    fn collect(
        vault: &Vault<crate::MemoryTarget>,
        index: &PackIndex,
        id: &ObjectId,
    ) -> Result<Vec<u8>, ContentError> {
        block_on(vault.read_content_to_vec(index, id))
    }

    #[test]
    fn reads_content_of_several_chunks_in_order() {
        let (objects, id, whole) = three_chunks();
        let (vault, index) = store(objects);
        assert_eq!(collect(&vault, &index, &id).unwrap(), whole);

        // The sink gets one call for each chunk, and the size comes back.
        let mut calls = Vec::new();
        let size = block_on(vault.read_content(&index, &id, |c| {
            calls.push(c.len());
            Ok::<(), Infallible>(())
        }))
        .unwrap();
        assert_eq!(size, whole.len() as u64);
        assert_eq!(calls, [12, 13, 12]);
    }

    #[test]
    fn reads_content_without_data() {
        let (c, id) = content(&[], 0, content_hash(b""));
        let (vault, index) = store(vec![c]);
        assert!(collect(&vault, &index, &id).unwrap().is_empty());
    }

    #[test]
    fn rejects_a_size_that_is_not_the_sum_of_the_chunks() {
        let (a, ida) = chunk(b"0123456789");
        for size in [9, 11] {
            let (c, id) = content(&[ida], size, content_hash(b"0123456789"));
            let (vault, index) = store(vec![a.clone(), c]);
            let result = collect(&vault, &index, &id);
            assert!(
                matches!(result, Err(ContentError::Inconsistent(_))),
                "{size}"
            );
        }
    }

    #[test]
    fn rejects_a_content_hash_that_does_not_fit() {
        let (a, ida) = chunk(b"0123456789");
        let (c, id) = content(&[ida], 10, content_hash(b"something else"));
        let (vault, index) = store(vec![a, c]);
        assert!(matches!(
            collect(&vault, &index, &id),
            Err(ContentError::Inconsistent(_))
        ));
    }

    #[test]
    fn rejects_chunks_in_the_wrong_order() {
        // Both lists have the right size, but the hash is of the other order.
        let (a, ida) = chunk(b"aaaa");
        let (b, idb) = chunk(b"bbbb");
        let (c, id) = content(&[idb, ida], 8, content_hash(b"aaaabbbb"));
        let (vault, index) = store(vec![a, b, c]);
        assert!(matches!(
            collect(&vault, &index, &id),
            Err(ContentError::Inconsistent(_))
        ));
    }

    #[test]
    fn reports_a_missing_chunk_with_its_id() {
        let (a, ida) = chunk(b"here");
        let (_, idb) = chunk(b"gone");
        let (c, id) = content(&[ida, idb], 8, content_hash(b"heregone"));
        let (vault, index) = store(vec![a, c]);
        assert!(matches!(
            collect(&vault, &index, &id),
            Err(ContentError::Missing(missing)) if missing == idb
        ));
    }

    #[test]
    fn a_chunk_id_must_name_a_chunk() {
        // The content object lists the ID of another content object as a chunk.
        let (a, ida) = chunk(b"data");
        let (inner, inner_id) = content(&[ida], 4, content_hash(b"data"));
        let (outer, outer_id) = content(&[inner_id], 4, content_hash(b"data"));
        let (vault, index) = store(vec![a, inner, outer]);
        assert!(matches!(
            collect(&vault, &index, &outer_id),
            Err(ContentError::Unreadable(_, ObjectReadError::WrongType))
        ));
    }

    #[test]
    fn an_object_that_is_not_a_content_object_is_rejected() {
        let (a, ida) = chunk(b"data");
        let (vault, index) = store(vec![a]);
        // A chunk is not a content object.
        assert!(matches!(
            collect(&vault, &index, &ida),
            Err(ContentError::Unreadable(_, ObjectReadError::WrongType))
        ));
        // Bytes that are no envelope.
        let (junk, junk_id) = typed_object(CONTENT_OBJECT, KeyClass::W, b"junk");
        let (vault, index) = store(vec![junk]);
        assert!(matches!(
            collect(&vault, &index, &junk_id),
            Err(ContentError::Invalid(_, _))
        ));
    }

    #[test]
    fn the_error_of_the_sink_stops_the_reading() {
        let (objects, id, _) = three_chunks();
        let (vault, index) = store(objects);
        let mut calls = 0;
        let result = block_on(vault.read_content(&index, &id, |_| {
            calls += 1;
            if calls == 2 { Err("disk full") } else { Ok(()) }
        }));
        assert!(matches!(result, Err(ContentError::Sink("disk full"))));
        assert_eq!(calls, 2);
    }

    fn record(native_id: &[u8], content: &[ObjectId]) -> ItemRecord {
        ItemRecord {
            source_id: SourceId::from_bytes([1; 16]),
            native_id: native_id.to_vec(),
            title: "a file".to_string(),
            modified: Some(1_700_000_000_000),
            created: None,
            size: 4,
            media_type: Some("text/plain".to_string()),
            metadata: None,
            content: content.to_vec(),
        }
    }

    fn item_key(record: &ItemRecord) -> ItemKey {
        ItemKey::from_bytes(
            TestKeys::from_seed(&test_seed())
                .dedup
                .domain_keys()
                .item_key(record.source_id.as_bytes(), &record.native_id)
                .unwrap(),
        )
    }

    #[test]
    fn reads_an_item_record_and_checks_its_key() {
        let content_ids = [ObjectId::from_bytes([5; 32])];
        let record = record(b"docs/a.txt", &content_ids);
        let (object, id) = typed_object(ITEM_RECORD, KeyClass::R, &record.encode().unwrap());
        let (vault, index) = store(vec![object]);
        let state = ItemState {
            item_record: id,
            content: content_ids.to_vec(),
        };
        let read = block_on(vault.read_item(&index, &item_key(&record), &state)).unwrap();
        assert_eq!(read, record);

        // Another item key: the record is not the record of that item.
        let other = ItemKey::from_bytes([9; 32]);
        assert!(matches!(
            block_on(vault.read_item(&index, &other, &state)),
            Err(ContentError::Inconsistent(_))
        ));

        // The journal entry names other content objects.
        let wrong = ItemState {
            item_record: id,
            content: vec![],
        };
        assert!(matches!(
            block_on(vault.read_item(&index, &item_key(&record), &wrong)),
            Err(ContentError::Inconsistent(_))
        ));
    }

    #[test]
    fn a_missing_or_invalid_item_record_is_reported() {
        let state = ItemState {
            item_record: ObjectId::from_bytes([1; 32]),
            content: vec![],
        };
        let key = ItemKey::from_bytes([2; 32]);
        let (vault, index) = store(vec![]);
        assert!(matches!(
            block_on(vault.read_item(&index, &key, &state)),
            Err(ContentError::Missing(_))
        ));
        let (junk, junk_id) = typed_object(ITEM_RECORD, KeyClass::R, b"junk");
        let (vault, index) = store(vec![junk]);
        let state = ItemState {
            item_record: junk_id,
            content: vec![],
        };
        assert!(matches!(
            block_on(vault.read_item(&index, &key, &state)),
            Err(ContentError::Invalid(_, _))
        ));
    }

    #[test]
    fn reads_a_file_from_the_snapshot_to_its_bytes() {
        use crate::test_util::{header, snapshot_entry};
        use nilperit_format::{Change, DeltaEntry, SnapshotId};

        // One file with two chunks, one delta entry, one snapshot header.
        let (a, ida) = chunk(b"hello ");
        let (b, idb) = chunk(b"world");
        let (c, content_id) = content(&[ida, idb], 11, content_hash(b"hello world"));
        let record = record(b"docs/hello.txt", &[content_id]);
        let (item, item_id) = typed_object(ITEM_RECORD, KeyClass::R, &record.encode().unwrap());
        let entry = DeltaEntry {
            source_id: record.source_id,
            sequence: 1,
            parent: None,
            snapshot_id: SnapshotId::from_bytes([0x61; 16]),
            time: 1_700_000_000_000,
            connector_cursor: None,
            changed: vec![Change {
                item_key: item_key(&record),
                item_record: item_id,
                content: vec![content_id],
            }],
            deleted: vec![],
        };
        let (entry_object, entry_id) = crate::test_util::entry_object(&entry);
        let (pack, _) = build_pack(
            &TestKeys::from_seed(&test_seed()),
            &[a, b, c, item, entry_object],
        );
        let snapshot = snapshot_entry(&header(1, 0x61, 1_700_000_000_000, entry_id, 1));
        let vault = vault_with(&[&pack], &[snapshot]);

        let index = block_on(vault.scan_packs()).unwrap();
        let snapshots = block_on(vault.read_snapshots()).unwrap();
        let head = snapshots.head(&record.source_id).unwrap();
        let state = block_on(vault.replay_journal(&index, head)).unwrap();
        assert_eq!(state.items.len(), 1);
        for (key, item) in &state.items {
            let read = block_on(vault.read_item(&index, key, item)).unwrap();
            assert_eq!(read.title, "a file");
            let mut bytes = Vec::new();
            for content_id in &read.content {
                bytes.extend(collect(&vault, &index, content_id).unwrap());
            }
            assert_eq!(bytes, b"hello world");
        }
    }

    #[test]
    fn a_node_cannot_read_items_or_content() {
        // Chunks and item records are R objects. A node has no read key.
        let (objects, id, _) = three_chunks();
        let (bytes, _) = build_pack(&TestKeys::from_seed(&test_seed()), &objects);
        let vault = node_vault_with(&[&bytes], &[]);
        let index = block_on(vault.scan_packs()).unwrap();
        // The content object is W: the node reads it. The first chunk is R.
        assert!(matches!(
            block_on(vault.read_content_to_vec(&index, &id)),
            Err(ContentError::Unreadable(_, ObjectReadError::NoReadKey))
        ));
    }
}
