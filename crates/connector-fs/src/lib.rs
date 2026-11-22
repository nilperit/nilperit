//! The connector for a folder on a local file system.
//!
//! It walks the folder and reports every regular file as an item. The native ID of
//! an item is the path of the file relative to the folder, with `/` between the
//! parts. The connector has no cursor: each run reports the complete list, and the
//! sync engine finds what changed (`docs/roadmap.md`).
//!
//! What the connector does with other things in the folder:
//!
//! - A symbolic link, a socket, a pipe and a device are not regular files. They are
//!   reported as items that cannot be read (`io::ErrorKind::Unsupported`), so the
//!   run lists them as failed and never stores them. The connector does not follow
//!   a symbolic link, so it cannot be led out of the folder.
//! - A folder has no item. An empty folder is not in the vault.
//! - A folder that cannot be read is reported as an item that cannot be read, and the
//!   list is then not complete: the engine deletes nothing in that run, because the
//!   items below the folder are not known.
//!
//! Layering (ADR 0014): a connector depends on the writer for the `Connector` trait.

use nilperit_writer::{Changes, Connector, ConnectorError, OpenContent, SourceItem};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// A folder as a source.
#[derive(Clone, Debug)]
pub struct FolderConnector {
    root: PathBuf,
    excluded: Vec<PathBuf>,
}

impl FolderConnector {
    /// A source for the folder `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            excluded: Vec::new(),
        }
    }

    /// Leaves out a path below the folder: the walk does not enter it. A program
    /// that has the vault inside the folder uses this for the folder of the vault,
    /// so that the vault does not back up itself. The path must be written in the
    /// same way as the root (for example both made absolute with `canonicalize`).
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
            items: Vec::new(),
            complete: true,
        };
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

struct Walk<'a> {
    excluded: &'a [PathBuf],
    items: Vec<SourceItem>,
    complete: bool,
}

impl Walk<'_> {
    /// Walks one folder. `relative` is its path below the root. An error is for
    /// the root only: a folder below it that cannot be read is an item that fails.
    fn folder(&mut self, folder: &Path, relative: &Path) -> io::Result<()> {
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
                self.folder(&path, &child)?;
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

/// The native ID of a file: its path below the folder, with `/` between the parts
/// (format.md 5.4.5.2). On Unix a name is bytes and stays as it is. On Windows a name
/// is text, and a part that is not valid text is changed to text, so two such names
/// can have the same native ID. The engine reports the second one.
fn native_id(relative: &Path) -> Vec<u8> {
    let mut id = Vec::new();
    for (index, part) in relative.components().enumerate() {
        if index > 0 {
            id.push(b'/');
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            id.extend_from_slice(part.as_os_str().as_bytes());
        }
        #[cfg(not(unix))]
        id.extend_from_slice(part.as_os_str().to_string_lossy().as_bytes());
    }
    id
}

/// An item that cannot be read. The engine reports it and never deletes it.
fn failing(native_id: Vec<u8>, kind: io::ErrorKind) -> SourceItem {
    SourceItem {
        title: String::from_utf8_lossy(&native_id).into_owned(),
        native_id,
        modified: None,
        created: None,
        media_type: None,
        metadata: None,
        contents: vec![Box::new(move || Err(io::Error::from(kind)))],
    }
}

fn file_item(path: PathBuf, relative: &Path, metadata: &fs::Metadata) -> SourceItem {
    let native_id = native_id(relative);
    let open: OpenContent = Box::new(move || Ok(Box::new(File::open(path)?) as Box<dyn io::Read>));
    SourceItem {
        title: String::from_utf8_lossy(&native_id).into_owned(),
        native_id,
        modified: metadata.modified().ok().map(millis),
        created: metadata.created().ok().map(millis),
        media_type: None,
        metadata: mode_metadata(metadata),
        contents: vec![open],
    }
}

/// A time as milliseconds since 1970 (format.md 5.4.5.3). A time before 1970 is
/// negative.
fn millis(time: std::time::SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |n| -n),
    }
}

/// The metadata of an item: the permission bits of the file as the map `{"mode":
/// 420}` (the example of format.md A.10.2), in deterministic CBOR. A file system
/// without permission bits gives none.
#[cfg(unix)]
fn mode_metadata(metadata: &fs::Metadata) -> Option<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;
    Some(mode_map(metadata.permissions().mode() & 0o7777))
}

#[cfg(not(unix))]
fn mode_metadata(_: &fs::Metadata) -> Option<Vec<u8>> {
    None
}

/// The CBOR map with one entry: the text "mode" and an unsigned integer below 8192.
#[cfg_attr(not(unix), allow(dead_code))]
fn mode_map(mode: u32) -> Vec<u8> {
    // a1: a map of 1 entry. 64 6d6f6465: the text "mode".
    let mut out = vec![0xa1, 0x64, b'm', b'o', b'd', b'e'];
    match mode {
        0..=23 => out.push(mode as u8),
        24..=255 => out.extend([0x18, mode as u8]),
        _ => out.extend([0x19, (mode >> 8) as u8, mode as u8]),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::io::Read;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the future waits"),
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("nilperit-fs-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
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

    /// The items of one run: native ID, title, and the bytes or the error kind.
    type Listing = Vec<(Vec<u8>, Result<Vec<u8>, io::ErrorKind>)>;

    fn run(connector: &mut FolderConnector) -> (bool, Listing, Vec<SourceItem>) {
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
            items.push(item);
        }
        listing.sort();
        (complete, listing, items)
    }

    #[test]
    fn walks_a_folder_and_reports_every_file() {
        let dir = TempDir::new("walk");
        fs::create_dir_all(dir.0.join("docs/deep/er")).unwrap();
        fs::write(dir.0.join("a.txt"), b"alpha").unwrap();
        fs::write(dir.0.join("docs/b.txt"), b"bravo").unwrap();
        fs::write(dir.0.join("docs/deep/er/c.bin"), [0u8, 1, 2]).unwrap();
        fs::write(dir.0.join(".hidden"), b"dot").unwrap();
        fs::write(dir.0.join("empty"), b"").unwrap();
        fs::create_dir_all(dir.0.join("empty-folder")).unwrap();

        let (complete, listing, _) = run(&mut FolderConnector::new(&dir.0));
        assert!(complete);
        let expected: Listing = vec![
            (b".hidden".to_vec(), Ok(b"dot".to_vec())),
            (b"a.txt".to_vec(), Ok(b"alpha".to_vec())),
            (b"docs/b.txt".to_vec(), Ok(b"bravo".to_vec())),
            (b"docs/deep/er/c.bin".to_vec(), Ok(vec![0, 1, 2])),
            (b"empty".to_vec(), Ok(Vec::new())),
        ];
        assert_eq!(listing, expected);
    }

    #[test]
    fn an_item_has_a_title_a_time_and_the_mode() {
        let dir = TempDir::new("fields");
        fs::create_dir_all(dir.0.join("docs")).unwrap();
        fs::write(dir.0.join("docs/a.txt"), b"alpha").unwrap();
        let (_, _, items) = run(&mut FolderConnector::new(&dir.0));
        let item = &items[0];
        assert_eq!(item.title, "docs/a.txt");
        assert_eq!(item.media_type, None);
        let modified = item.modified.unwrap();
        // Written in the last minutes.
        let now = millis(std::time::SystemTime::now());
        assert!(
            (now - 600_000..=now + 1_000).contains(&modified),
            "{modified} {now}"
        );
        #[cfg(unix)]
        assert!(item.metadata.is_some());
    }

    #[test]
    fn the_mode_is_the_cbor_of_the_example_in_the_spec() {
        // Format.md A.10.2: the metadata `{"mode": 420}` is `a1 64 6d6f6465 19 01a4`.
        assert_eq!(
            mode_map(0o644),
            [0xa1, 0x64, 0x6d, 0x6f, 0x64, 0x65, 0x19, 0x01, 0xa4]
        );
        // The other sizes of an unsigned integer.
        assert_eq!(mode_map(0), [0xa1, 0x64, 0x6d, 0x6f, 0x64, 0x65, 0x00]);
        assert_eq!(mode_map(23), [0xa1, 0x64, 0x6d, 0x6f, 0x64, 0x65, 0x17]);
        assert_eq!(
            mode_map(0o70),
            [0xa1, 0x64, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x38]
        );
        assert_eq!(
            mode_map(0o7777),
            [0xa1, 0x64, 0x6d, 0x6f, 0x64, 0x65, 0x19, 0x0f, 0xff]
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_mode_of_a_file_is_in_its_metadata() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        let path = dir.0.join("script.sh");
        fs::write(&path, b"#!/bin/sh").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();
        let (_, _, items) = run(&mut FolderConnector::new(&dir.0));
        assert_eq!(items[0].metadata, Some(mode_map(0o750)));
    }

    #[test]
    fn times_before_1970_are_negative() {
        let before = UNIX_EPOCH - std::time::Duration::from_millis(1500);
        assert_eq!(millis(before), -1500);
        assert_eq!(millis(UNIX_EPOCH), 0);
        assert_eq!(
            millis(UNIX_EPOCH + std::time::Duration::from_millis(1500)),
            1500
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_name_that_is_not_text_stays_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let dir = TempDir::new("bytes");
        let name = OsString::from_vec(vec![b'f', 0xff, 0xfe, b'.', b't']);
        fs::write(dir.0.join(&name), b"odd").unwrap();
        let (_, listing, items) = run(&mut FolderConnector::new(&dir.0));
        assert_eq!(
            listing,
            [(vec![b'f', 0xff, 0xfe, b'.', b't'], Ok(b"odd".to_vec()))]
        );
        // The title is text, with the replacement character.
        assert_eq!(items[0].title, "f\u{fffd}\u{fffd}.t");
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_and_a_pipe_are_reported_and_not_followed() {
        let dir = TempDir::new("links");
        let outside = TempDir::new("links-outside");
        fs::write(outside.0.join("secret"), b"secret").unwrap();
        fs::write(dir.0.join("real"), b"real").unwrap();
        std::os::unix::fs::symlink(outside.0.join("secret"), dir.0.join("to-file")).unwrap();
        std::os::unix::fs::symlink(&outside.0, dir.0.join("to-folder")).unwrap();
        let (complete, listing, _) = run(&mut FolderConnector::new(&dir.0));
        // The list is complete: a link is known, only not stored.
        assert!(complete);
        assert_eq!(
            listing,
            [
                (b"real".to_vec(), Ok(b"real".to_vec())),
                (b"to-file".to_vec(), Err(io::ErrorKind::Unsupported)),
                (b"to-folder".to_vec(), Err(io::ErrorKind::Unsupported)),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_folder_makes_the_list_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("unreadable");
        fs::create_dir_all(dir.0.join("locked")).unwrap();
        fs::write(dir.0.join("locked/inside"), b"x").unwrap();
        fs::write(dir.0.join("open"), b"open").unwrap();
        fs::set_permissions(dir.0.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
        // The owner of the root ignores permissions: the test makes no sense then.
        if fs::read_dir(dir.0.join("locked")).is_ok() {
            return;
        }
        let (complete, listing, _) = run(&mut FolderConnector::new(&dir.0));
        assert!(!complete);
        assert_eq!(
            listing,
            [
                (b"locked".to_vec(), Err(io::ErrorKind::PermissionDenied)),
                (b"open".to_vec(), Ok(b"open".to_vec())),
            ]
        );
    }

    #[test]
    fn leaves_out_the_paths_that_the_program_excludes() {
        let dir = TempDir::new("exclude");
        fs::create_dir_all(dir.0.join("vault/packs")).unwrap();
        fs::create_dir_all(dir.0.join("data")).unwrap();
        fs::write(dir.0.join("vault/config-a"), b"c").unwrap();
        fs::write(dir.0.join("vault/packs/p"), b"p").unwrap();
        fs::write(dir.0.join("data/file"), b"d").unwrap();
        fs::write(dir.0.join("vault-notes"), b"n").unwrap();
        let mut connector = FolderConnector::new(&dir.0).exclude(dir.0.join("vault"));
        let (_, listing, _) = run(&mut connector);
        let ids: Vec<&[u8]> = listing.iter().map(|(id, _)| id.as_slice()).collect();
        // `vault-notes` is not below `vault`: the exclusion is by path parts.
        assert_eq!(ids, [&b"data/file"[..], b"vault-notes"]);
    }

    #[test]
    fn a_missing_folder_or_a_file_is_an_error_without_a_path() {
        let dir = TempDir::new("missing");
        let missing = dir.0.join("no-such-folder");
        let error = block_on(FolderConnector::new(&missing).changes(None))
            .err()
            .unwrap();
        assert!(!error.to_string().contains("no-such-folder"), "{error}");
        fs::write(dir.0.join("file"), b"x").unwrap();
        let error = block_on(FolderConnector::new(dir.0.join("file")).changes(None))
            .err()
            .unwrap();
        assert!(error.to_string().contains("not a folder"), "{error}");
        assert!(!error.to_string().contains("nilperit-fs"), "{error}");
    }

    #[test]
    fn an_empty_folder_has_no_items() {
        let dir = TempDir::new("empty");
        let (complete, listing, _) = run(&mut FolderConnector::new(&dir.0));
        assert!(complete);
        assert!(listing.is_empty());
    }

    #[test]
    fn a_file_that_goes_before_it_is_read_is_an_error_of_that_item() {
        let dir = TempDir::new("vanish");
        fs::write(dir.0.join("a"), b"x").unwrap();
        let changes = block_on(FolderConnector::new(&dir.0).changes(None)).unwrap();
        fs::remove_file(dir.0.join("a")).unwrap();
        let mut item = changes.items.into_iter().next().unwrap();
        let open = item.contents.pop().unwrap();
        assert_eq!(open().err().unwrap().kind(), io::ErrorKind::NotFound);
    }
}
