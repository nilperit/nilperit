//! What a run tells the person who started it.
//!
//! The engine reports what it is doing and how far it is. It does not know how the
//! program shows this: a terminal, a log or nothing. A report has numbers only. It never
//! has a name, a title or content, so a program may show it anywhere (AGENTS.md).

/// How far a run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    /// The items that the run has finished. An item that could not be read counts as
    /// finished.
    pub items_done: u64,
    /// The items that the source listed.
    pub items_total: u64,
    /// The bytes that the run has read from the source, plus the bytes of the items that
    /// it did not read. It can be a little more than `bytes_total` when a file grew
    /// after the listing.
    pub bytes_done: u64,
    /// The size of all items, when the source gave a size for each item.
    pub bytes_total: Option<u64>,
}

/// A step of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// The run reads the packs and the snapshot headers of the vault.
    OpeningVault,
    /// The run reads the journal of the source, to know what the vault has.
    ReplayingJournal,
    /// The connector gets the list of items from the source. A source that is far away
    /// can take a long time for this.
    ReadingSource,
    /// The run reads the items. It reports after every chunk and after every item.
    Reading(Counts),
    /// The run writes the packs and the entries of a commit to the vault.
    Committing(Counts),
}
