//! Object type IDs (format.md 4.4.3).
//!
//! The type ID goes into the object ID (format.md 4.7). A new type gets a new
//! number. A number is never reused or changed.

/// A chunk. A raw object: it has no envelope.
pub const CHUNK: u32 = 1;

/// A content object (format.md 5.3).
pub const CONTENT_OBJECT: u32 = 2;
