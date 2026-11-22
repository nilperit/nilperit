//! The interface between a source and the sync engine.
//!
//! A connector knows how to get items out of a source (a folder, a mailbox). It
//! does not know about chunks, packs or the vault. The sync engine does the rest
//! (format.md section 5).

use std::fmt;
use std::io::{self, Read};

/// A way to open the content of an item. Nothing is read before the engine calls
/// it, so a listing of a large source does not hold the content in memory.
///
/// The kind of the error matters. `io::ErrorKind::NotFound` (when the content is
/// opened or read) says that the item no longer exists at the source, for example
/// a file that was deleted after the listing. The engine then drops the item: it is
/// not reported, and with a complete list it counts as deleted. Every other error
/// says that the item exists and cannot be read now. The engine reports it, and the
/// vault keeps the last version that it has, so a source that is not reachable for a
/// moment (a disk that is not mounted) does not delete anything.
pub type OpenContent = Box<dyn FnOnce() -> io::Result<Box<dyn Read>>>;

/// One item of a source, as the connector reports it.
///
/// The fields are those of an item record (format.md 5.4).
pub struct SourceItem {
    /// The ID that the source gives to the item (format.md 5.4.5.2). It has at
    /// least 1 byte. For a folder it is the path relative to the folder.
    pub native_id: Vec<u8>,
    /// A name to show. It can be empty.
    pub title: String,
    /// The time of the last change at the source, in milliseconds.
    pub modified: Option<i64>,
    /// The time of creation at the source, in milliseconds.
    pub created: Option<i64>,
    /// The media type, for example `text/plain`.
    pub media_type: Option<String>,
    /// Metadata that only the connector understands: one CBOR item, already
    /// encoded as deterministic CBOR (format.md 5.4.1.3).
    pub metadata: Option<Vec<u8>>,
    /// The content objects of the item, in the order that the connector chooses.
    /// An item without content has none.
    pub contents: Vec<OpenContent>,
}

/// What a connector reports for one run.
pub struct Changes {
    /// `true` when `items` is every item that the source has. The engine then
    /// finds the deleted items itself: they are the items of the vault that are
    /// not in the list. `false` when `items` are only the items that are new or
    /// changed since the cursor, and `deleted` lists the others.
    pub complete: bool,
    /// The items. A native ID occurs once.
    pub items: Vec<SourceItem>,
    /// The native IDs of the items that the source no longer has. Only for a list
    /// that is not complete.
    pub deleted: Vec<Vec<u8>>,
    /// The connector cursor after this run (format.md 5.5.2). The next run gets it
    /// back. A source that has none gives `None`.
    pub cursor: Option<Vec<u8>>,
}

/// A connector could not get the changes of its source.
#[derive(Debug)]
pub enum ConnectorError {
    /// The source cannot be reached or does not answer. The text says why. It MUST
    /// NOT contain file names, titles, keys or content (AGENTS.md).
    Failed(String),
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(why) => write!(f, "the source failed: {why}"),
        }
    }
}

impl std::error::Error for ConnectorError {}

/// A source that the engine can synchronize.
#[allow(async_fn_in_trait)]
pub trait Connector {
    /// Reports what the source has, or what changed since `cursor`.
    ///
    /// `cursor` is the cursor of the last committed run, or `None` for the first
    /// run. A connector that cannot use a cursor ignores it and reports a complete
    /// list.
    async fn changes(&mut self, cursor: Option<&[u8]>) -> Result<Changes, ConnectorError>;
}
