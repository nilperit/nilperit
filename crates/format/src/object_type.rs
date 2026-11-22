//! Object type IDs (format.md 4.4.3).
//!
//! The type ID goes into the object ID (format.md 4.7). A new type gets a new
//! number. A number is never reused or changed.

/// A chunk. A raw object: it has no envelope.
pub const CHUNK: u32 = 1;

/// A content object (format.md 5.3).
pub const CONTENT_OBJECT: u32 = 2;

/// The object table of a pack (format.md 6.7.3). It is not an object in a pack.
pub const OBJECT_TABLE: u32 = 3;

/// An item record (format.md 5.4).
pub const ITEM_RECORD: u32 = 4;

/// A delta entry (format.md 5.5.2).
pub const DELTA_ENTRY: u32 = 5;

/// A snapshot header (format.md 5.9). It is a file outside the packs, not an object in a pack.
pub const SNAPSHOT_HEADER: u32 = 6;
