//! The walk through the folder: which items there are, and what to do with links.

use crate::item::{failing, file_item, native_id};
use nilperit_writer::SourceItem;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The state of one walk through the folder.
pub(crate) struct Walk<'a> {
    pub(crate) excluded: &'a [PathBuf],
    pub(crate) follow: bool,
    pub(crate) chain: Vec<PathBuf>,
    pub(crate) items: Vec<SourceItem>,
    pub(crate) complete: bool,
}

impl Walk<'_> {
    /// Walks one folder. `relative` is its path below the root. An error is for
    /// the root only: a folder below it that cannot be read is an item that fails.
    pub(crate) fn folder(&mut self, folder: &Path, relative: &Path) -> io::Result<()> {
        let entries = match fs::read_dir(folder) {
            Ok(entries) => entries,
            Err(e) if relative.as_os_str().is_empty() => return Err(e),
            // The folder is gone since the parent was listed. It has no items.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                self.complete = false;
                self.items.push(failing(native_id(relative), e.kind()));
                return Ok(());
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                // The folder cannot be listed to the end.
                self.complete = false;
                self.items
                    .push(failing(native_id(relative), io::ErrorKind::Other));
                break;
            };
            let path = entry.path();
            if self
                .excluded
                .iter()
                .any(|excluded| path.starts_with(excluded))
            {
                continue;
            }
            let child = relative.join(entry.file_name());
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if self.follow {
                    // A real folder has a real path below the real path of its parent.
                    let real = self
                        .chain
                        .last()
                        .map(|parent| parent.join(entry.file_name()));
                    self.chain.extend(real);
                    let result = self.folder(&path, &child);
                    self.chain.pop();
                    result?;
                } else {
                    self.folder(&path, &child)?;
                }
            } else if kind.is_symlink() && self.follow {
                self.link(&path, &child)?;
            } else if kind.is_file() {
                match entry.metadata() {
                    Ok(metadata) => self.items.push(file_item(path, &child, &metadata)),
                    // It is gone since the folder was listed.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => self.items.push(failing(native_id(&child), e.kind())),
                }
            } else {
                // A symbolic link, a socket, a pipe or a device.
                self.items
                    .push(failing(native_id(&child), io::ErrorKind::Unsupported));
            }
        }
        Ok(())
    }
}

impl Walk<'_> {
    /// Follows a symbolic link (the policy [`Symlinks::Follow`]).
    fn link(&mut self, path: &Path, child: &Path) -> io::Result<()> {
        let id = native_id(child);
        // The link cannot be followed: the target is not there, or it cannot be
        // reached. It can be a folder with items that the vault has, so the list is
        // not complete, and nothing is deleted. The kind is `Other` and not `NotFound`:
        // `NotFound` says that an item is gone (see `OpenContent`), and a disk that is
        // not mounted is not gone.
        let (Ok(metadata), Ok(real)) = (fs::metadata(path), fs::canonicalize(path)) else {
            self.complete = false;
            self.items.push(failing(id, io::ErrorKind::Other));
            return Ok(());
        };
        if self
            .excluded
            .iter()
            .any(|excluded| real.starts_with(excluded))
        {
            return Ok(());
        }
        if metadata.is_dir() {
            // A link to a folder that is being walked is a loop: the folder itself, one
            // above it, or the other folder of two links that point at each other.
            // It is reported and not followed. Each folder is on the chain once, so a
            // walk always ends.
            if self.chain.contains(&real) {
                self.items.push(failing(id, io::ErrorKind::Other));
                return Ok(());
            }
            self.chain.push(real);
            let result = self.folder(path, child);
            self.chain.pop();
            result
        } else if metadata.is_file() {
            self.items
                .push(file_item(path.to_path_buf(), child, &metadata));
            Ok(())
        } else {
            self.items.push(failing(id, io::ErrorKind::Unsupported));
            Ok(())
        }
    }
}
