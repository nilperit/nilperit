//! Helpers of the tests.

use crate::FolderConnector;
use nilperit_writer::{Connector, SourceItem};
use std::fs;
use std::future::Future;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the future waits"),
    }
}

/// A folder that is removed when it goes out of scope. Its path is a real path (no
/// links), so that the walk and the test agree on the names of folders.
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("nilperit-fs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A test can leave a folder that it made unreadable.
        #[cfg(unix)]
        restore_permissions(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn restore_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() && !entry.path().is_symlink() {
                restore_permissions(&entry.path());
            }
        }
    }
}

/// The items of one run: native ID, and the bytes or the error kind of the content.
pub(crate) type Listing = Vec<(Vec<u8>, Result<Vec<u8>, io::ErrorKind>)>;

/// Runs the connector and reads the content of every item. It returns whether the
/// list is complete, the listing sorted by native ID, and the items.
pub(crate) fn run(connector: &mut FolderConnector) -> (bool, Listing, Vec<SourceItem>) {
    let changes = block_on(connector.changes(None)).unwrap();
    assert!(changes.deleted.is_empty());
    assert_eq!(changes.cursor, None);
    let complete = changes.complete;
    let mut listing = Listing::new();
    let mut items = Vec::new();
    for mut item in changes.items {
        let content = item.contents.pop().map(|open| {
            open().and_then(|mut reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).map(|_| bytes)
            })
        });
        listing.push((
            item.native_id.clone(),
            content.unwrap().map_err(|e| e.kind()),
        ));
        items.append(&mut vec![item]);
    }
    listing.sort();
    (complete, listing, items)
}
