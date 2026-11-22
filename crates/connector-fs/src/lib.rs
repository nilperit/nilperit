//! The connector for a folder on a local file system.
//!
//! It walks the folder and reports every regular file as an item. The native ID of
//! an item is the path of the file relative to the folder, with `/` between the
//! parts. The connector has no cursor: each run reports the complete list, and the
//! sync engine finds what changed (`docs/roadmap.md`).
//!
//! What the connector does with other things in the folder:
//!
//! - A socket, a pipe and a device are not regular files. They are reported as items
//!   that cannot be read (`io::ErrorKind::Unsupported`), so the run lists them as
//!   failed and never stores them.
//! - A symbolic link is, by default, treated in the same way: reported and not
//!   stored, and never followed ([`Symlinks::Skip`]). With [`Symlinks::Follow`] the
//!   connector follows it, and the item is what the link points to, under the path of
//!   the link. This is for links to files that are stored elsewhere. A link that
//!   leads back into a folder that is being walked is not followed again, so a loop
//!   ends. A link whose target cannot be reached (a disk that is not mounted) makes
//!   the list incomplete, so that nothing is deleted.
//! - A folder has no item. An empty folder is not in the vault.
//! - A folder that cannot be read is reported as an item that cannot be read, and the
//!   list is then not complete: the engine deletes nothing in that run, because the
//!   items below the folder are not known. The report of the run lists the folder, so
//!   the program can warn the person.
//! - A file that is deleted after the walk listed it fails with `NotFound` when it is
//!   read. The engine drops it: it counts as deleted when the vault had it.
//!
//! Layering (ADR 0014): a connector depends on the writer for the `Connector` trait.

mod item;
mod walk;

use crate::walk::Walk;
use nilperit_writer::{Changes, Connector, ConnectorError};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// What the connector does with a symbolic link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Symlinks {
    /// Report the link as an item that cannot be read, and do not store it. The link
    /// is not followed.
    #[default]
    Skip,
    /// Follow the link. The item is the file or the folder that it points to, under
    /// the path of the link.
    Follow,
}

/// A folder as a source.
#[derive(Clone, Debug)]
pub struct FolderConnector {
    root: PathBuf,
    excluded: Vec<PathBuf>,
    symlinks: Symlinks,
}

impl FolderConnector {
    /// A source for the folder `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            excluded: Vec::new(),
            symlinks: Symlinks::Skip,
        }
    }

    /// Sets what the connector does with a symbolic link. The default is to skip it.
    #[must_use]
    pub fn symlinks(mut self, policy: Symlinks) -> Self {
        self.symlinks = policy;
        self
    }

    /// Leaves out a path below the folder: the walk does not enter it. A program
    /// that has the vault inside the folder uses this for the folder of the vault,
    /// so that the vault does not back up itself. The path must be written in the
    /// same way as the root (for example both made absolute with `canonicalize`).
    /// A followed link is also left out when the place that it points to is below
    /// the path.
    #[must_use]
    pub fn exclude(mut self, path: impl Into<PathBuf>) -> Self {
        self.excluded.push(path.into());
        self
    }
}

impl Connector for FolderConnector {
    async fn changes(&mut self, _cursor: Option<&[u8]>) -> Result<Changes, ConnectorError> {
        let unreadable = |what: &str, kind: io::ErrorKind| {
            // The text has no path: a path can have names of the owner (AGENTS.md).
            ConnectorError::Failed(format!("{what} ({kind:?})"))
        };
        let metadata = fs::metadata(&self.root)
            .map_err(|e| unreadable("the folder cannot be read", e.kind()))?;
        if !metadata.is_dir() {
            return Err(unreadable(
                "the source is not a folder",
                io::ErrorKind::InvalidInput,
            ));
        }
        let mut walk = Walk {
            excluded: &self.excluded,
            follow: self.symlinks == Symlinks::Follow,
            // The folders that are being walked, as real paths. Only a connector that
            // follows links needs them, to find a loop.
            chain: Vec::new(),
            items: Vec::new(),
            complete: true,
        };
        if walk.follow {
            let real = fs::canonicalize(&self.root)
                .map_err(|e| unreadable("the folder cannot be read", e.kind()))?;
            walk.chain.push(real);
        }
        walk.folder(&self.root, Path::new(""))
            .map_err(|e| unreadable("the folder cannot be read", e.kind()))?;
        Ok(Changes {
            complete: walk.complete,
            items: walk.items,
            deleted: Vec::new(),
            cursor: None,
        })
    }
}

#[cfg(all(test, unix))]
mod follow_tests;
#[cfg(test)]
mod test_util;
#[cfg(test)]
mod tests;
