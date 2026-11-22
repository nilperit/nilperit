//! A NilPerit target on a local file system: a folder, a disk, or a USB stick.
//!
//! It implements the reader's [`Target`] and the writer's [`WriteTarget`] with
//! `std::fs`. The functions are `async` because the traits are, but they never
//! wait: each one does its work and returns. A caller can drive them with a very
//! small executor (see `docs/roadmap.md`).
//!
//! Layering (ADR 0014): this crate is above the writer. The reader and the
//! reader-only tools must not depend on it.

use nilperit_reader::layout::LOCK_PATH;
use nilperit_reader::{Target, TargetError};
use nilperit_writer::WriteTarget;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The prefix of the temporary files of a write. No pack and no snapshot header has
/// a name that starts with a dot, so a reader ignores a temporary file that a crash
/// left behind. It is an orphan (format.md 8.5).
const TEMPORARY_PREFIX: &str = ".tmp-";

/// A vault in a folder of a file system.
#[derive(Clone, Debug)]
pub struct FsTarget {
    root: PathBuf,
}

impl FsTarget {
    /// A target for the vault in the folder `root`. The folder does not need to
    /// exist yet: a write makes it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The folder of the vault.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The path of a file of the vault on the file system.
    ///
    /// A path of the vault has parts that are separated by `/`. No part is empty, `.`
    /// or `..`, and no part has a backslash, a colon or a zero byte. The reader never
    /// makes another kind of path (`nilperit_reader::layout`). This check makes sure
    /// that a path can never leave the folder of the vault.
    fn resolve(&self, path: &str) -> Result<PathBuf, TargetError> {
        let invalid = || TargetError::Other("invalid path".into());
        if path.is_empty() {
            return Err(invalid());
        }
        let mut full = self.root.clone();
        for part in path.split('/') {
            if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':', '\0']) {
                return Err(invalid());
            }
            full.push(part);
        }
        Ok(full)
    }
}

/// Turns an I/O error into a target error. The text has the kind of the error and
/// never a path: a path can have names of the owner (AGENTS.md).
fn failure(error: io::Error) -> TargetError {
    match error.kind() {
        io::ErrorKind::NotFound => TargetError::NotFound,
        kind => TargetError::Other(format!("{kind:?}")),
    }
}

/// The size of a file. A folder or another kind of file is not a file of the vault.
fn file_size(path: &Path) -> Result<u64, TargetError> {
    let metadata = fs::metadata(path).map_err(failure)?;
    if !metadata.is_file() {
        return Err(TargetError::NotFound);
    }
    Ok(metadata.len())
}

impl Target for FsTarget {
    async fn len(&self, path: &str) -> Result<u64, TargetError> {
        file_size(&self.resolve(path)?)
    }

    async fn read_range(&self, path: &str, range: Range<u64>) -> Result<Vec<u8>, TargetError> {
        let full = self.resolve(path)?;
        let size = file_size(&full)?;
        if range.start > range.end || range.end > size {
            return Err(TargetError::OutOfRange);
        }
        let length =
            usize::try_from(range.end - range.start).map_err(|_| TargetError::OutOfRange)?;
        let mut file = File::open(&full).map_err(failure)?;
        file.seek(SeekFrom::Start(range.start)).map_err(failure)?;
        let mut bytes = vec![0u8; length];
        file.read_exact(&mut bytes).map_err(failure)?;
        Ok(bytes)
    }

    async fn read(&self, path: &str) -> Result<Vec<u8>, TargetError> {
        let full = self.resolve(path)?;
        file_size(&full)?;
        fs::read(&full).map_err(failure)
    }

    async fn list(&self, dir: &str) -> Result<Vec<String>, TargetError> {
        let mut files = Vec::new();
        collect(&self.resolve(dir)?, dir, &mut files)?;
        Ok(files)
    }
}

/// Adds the regular files below `folder` to `files`, with paths that start with
/// `prefix`. A folder that does not exist has no files. A symbolic link is not a
/// file of the vault, and neither is a name that is not text.
fn collect(folder: &Path, prefix: &str, files: &mut Vec<String>) -> Result<(), TargetError> {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        // A name that is not a folder has no files below it, like a folder that is not there.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(e) => return Err(failure(e)),
    };
    for entry in entries {
        let entry = entry.map_err(failure)?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let path = format!("{prefix}/{name}");
        let kind = entry.file_type().map_err(failure)?;
        if kind.is_dir() {
            collect(&entry.path(), &path, files)?;
        } else if kind.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Whether a failure can be over in a moment. Windows refuses to rename, link or delete a
/// file for a short time after it was made or read, when something else has it open: a virus
/// scanner, the indexer of the search, or a file that waits to be deleted. The error is
/// "access denied" or "sharing violation" (the codes 5 and 32), and it passes by itself.
fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::ResourceBusy
    ) || error.raw_os_error() == Some(32)
}

/// Does `operation`, and does it again after a short wait when it fails in a way that
/// can pass (see [`transient`]), at most `attempts` times in all. The wait is `first_wait`,
/// and doubles each time up to 100 milliseconds. A failure that does not pass, and the last
/// failure, are returned as they are.
fn retry<T>(
    attempts: u32,
    first_wait: Duration,
    mut operation: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut wait = first_wait;
    let mut attempt = 1;
    loop {
        match operation() {
            Err(e) if attempt < attempts && transient(&e) => {
                std::thread::sleep(wait);
                wait = (wait * 2).min(Duration::from_millis(100));
                attempt += 1;
            }
            other => return other,
        }
    }
}

/// The retries of a file system operation on this system: on Windows a few (about half a
/// second in all), elsewhere none. A real permission problem is still an error, only later.
fn with_retries<T>(operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry(
        if cfg!(windows) { 8 } else { 1 },
        Duration::from_millis(5),
        operation,
    )
}

/// A name for a temporary file that no other write uses.
fn temporary_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!(
        "{TEMPORARY_PREFIX}{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Writes `bytes` to a new temporary file in `folder`, and syncs it to the disk
/// (format.md 8.1). It returns the path of the file.
fn write_temporary(folder: &Path, bytes: &[u8]) -> Result<PathBuf, TargetError> {
    fs::create_dir_all(folder).map_err(failure)?;
    loop {
        let path = folder.join(temporary_name());
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            // Another write has this name. Take another name.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(failure(e)),
        };
        let result = file.write_all(bytes).and_then(|()| file.sync_all());
        if let Err(e) = result {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(failure(e));
        }
        return Ok(path);
    }
}

/// Syncs a folder, so that a new name in it reaches the disk. A file system that
/// cannot do this is not an error: the file is complete either way.
fn sync_folder(folder: &Path) {
    #[cfg(unix)]
    if let Ok(folder) = File::open(folder) {
        let _ = folder.sync_all();
    }
    #[cfg(not(unix))]
    let _ = folder;
}

impl WriteTarget for FsTarget {
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<(), TargetError> {
        let full = self.resolve(path)?;
        // `resolve` gives a path with at least one part, so there is a folder.
        let folder = full.parent().unwrap_or(&self.root).to_path_buf();
        let temporary = write_temporary(&folder, bytes)?;
        if let Err(e) = with_retries(|| fs::rename(&temporary, &full)) {
            let _ = fs::remove_file(&temporary);
            return Err(failure(e));
        }
        sync_folder(&folder);
        Ok(())
    }

    async fn put_new(&self, path: &str, bytes: &[u8]) -> Result<bool, TargetError> {
        let full = self.resolve(path)?;
        let folder = full.parent().unwrap_or(&self.root).to_path_buf();
        let temporary = write_temporary(&folder, bytes)?;
        // A hard link gives the complete file its name in one step, and fails when the
        // name exists. A reader never sees a part of the file.
        let linked = with_retries(|| fs::hard_link(&temporary, &full));
        let result = match linked {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            // A file system without hard links (for example exFAT): create the name
            // and write into it. The name exists before the content is complete, but
            // only for a moment, and the create step still fails when the name exists.
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                create_in_place(&full, bytes).map_err(failure)
            }
            Err(e) => Err(failure(e)),
        };
        let _ = fs::remove_file(&temporary);
        if matches!(result, Ok(true)) {
            sync_folder(&folder);
        }
        result
    }

    async fn remove_lock(&self) -> Result<(), TargetError> {
        let lock = self.resolve(LOCK_PATH)?;
        match with_retries(|| fs::remove_file(&lock)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(failure(e)),
        }
    }
}

/// Creates `path` and writes `bytes` into it. It returns `false` when the file
/// exists.
fn create_in_place(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    /// Runs a future that never waits for anything.
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

    /// A folder that is removed when it goes out of scope.
    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new() -> Self {
            let path = std::env::temp_dir().join(format!("nilperit-test-{}", temporary_name()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn target() -> (TempDir, FsTarget) {
        let dir = TempDir::new();
        let target = FsTarget::new(dir.0.join("vault"));
        (dir, target)
    }

    #[test]
    fn writes_and_reads_a_file_in_a_new_folder() {
        let (_dir, target) = target();
        block_on(target.put("packs/ab/abcdef", b"0123456789")).unwrap();
        assert_eq!(block_on(target.len("packs/ab/abcdef")).unwrap(), 10);
        assert_eq!(
            block_on(target.read("packs/ab/abcdef")).unwrap(),
            b"0123456789"
        );
        assert_eq!(
            block_on(target.read_range("packs/ab/abcdef", 2..5)).unwrap(),
            b"234"
        );
    }

    #[test]
    fn a_missing_file_is_not_found_and_a_folder_is_not_a_file() {
        let (_dir, target) = target();
        block_on(target.put("packs/ab/x", b"x")).unwrap();
        for path in ["missing", "packs/ab/missing", "packs", "packs/ab"] {
            assert!(
                matches!(block_on(target.len(path)), Err(TargetError::NotFound)),
                "{path}"
            );
            assert!(
                matches!(block_on(target.read(path)), Err(TargetError::NotFound)),
                "{path}"
            );
        }
    }

    #[test]
    fn reads_the_ranges_that_are_inside_the_file() {
        let (_dir, target) = target();
        block_on(target.put("f", b"abcdef")).unwrap();
        assert_eq!(block_on(target.read_range("f", 0..6)).unwrap(), b"abcdef");
        assert_eq!(block_on(target.read_range("f", 6..6)).unwrap(), b"");
        assert_eq!(block_on(target.read_range("f", 0..0)).unwrap(), b"");
        for range in [0..7, 7..7, 7..9, Range { start: 4, end: 3 }] {
            assert!(
                matches!(
                    block_on(target.read_range("f", range.clone())),
                    Err(TargetError::OutOfRange)
                ),
                "{range:?}"
            );
        }
        assert!(matches!(
            block_on(target.read_range("missing", 0..1)),
            Err(TargetError::NotFound)
        ));
    }

    #[test]
    fn lists_the_files_below_a_folder_at_any_depth() {
        let (_dir, target) = target();
        for path in [
            "packs/ab/one",
            "packs/cd/two",
            "packs/three",
            "snapshots/four",
            "config-a",
        ] {
            block_on(target.put(path, b"x")).unwrap();
        }
        let mut packs = block_on(target.list("packs")).unwrap();
        packs.sort();
        assert_eq!(packs, ["packs/ab/one", "packs/cd/two", "packs/three"]);
        assert_eq!(
            block_on(target.list("snapshots")).unwrap(),
            ["snapshots/four"]
        );
        // A folder that is not there has no files, and neither has a file.
        assert!(block_on(target.list("missing")).unwrap().is_empty());
        assert!(block_on(target.list("config-a")).unwrap().is_empty());
    }

    #[test]
    fn a_write_replaces_a_file_and_leaves_no_temporary_file() {
        let (_dir, target) = target();
        block_on(target.put("packs/ab/x", b"first")).unwrap();
        block_on(target.put("packs/ab/x", b"second, longer")).unwrap();
        assert_eq!(
            block_on(target.read("packs/ab/x")).unwrap(),
            b"second, longer"
        );
        assert_eq!(block_on(target.list("packs")).unwrap(), ["packs/ab/x"]);
    }

    #[test]
    fn a_temporary_file_that_a_crash_left_is_not_a_pack_or_a_snapshot_header() {
        use nilperit_reader::layout::{parse_pack_path, parse_snapshot_path};
        let name = temporary_name();
        assert!(name.starts_with(TEMPORARY_PREFIX));
        assert!(parse_pack_path(&format!("packs/ab/{name}")).is_none());
        assert!(parse_snapshot_path(&format!("snapshots/{name}")).is_none());
        // The names of two writes differ.
        assert_ne!(temporary_name(), temporary_name());
    }

    #[test]
    fn put_new_creates_a_file_only_when_there_is_none() {
        let (_dir, target) = target();
        assert!(block_on(target.put_new("locks/writer", b"first")).unwrap());
        assert!(!block_on(target.put_new("locks/writer", b"second")).unwrap());
        assert_eq!(block_on(target.read("locks/writer")).unwrap(), b"first");
        // No temporary file stays.
        assert_eq!(block_on(target.list("locks")).unwrap(), ["locks/writer"]);
    }

    #[test]
    fn of_many_writers_that_create_the_same_file_one_wins() {
        let (_dir, target) = target();
        let wins: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|i| {
                    let target = &target;
                    scope.spawn(move || {
                        block_on(target.put_new("locks/writer", format!("writer {i}").as_bytes()))
                            .unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert_eq!(wins, 1);
        let content = block_on(target.read("locks/writer")).unwrap();
        assert!(String::from_utf8(content).unwrap().starts_with("writer "));
        assert_eq!(block_on(target.list("locks")).unwrap(), ["locks/writer"]);
    }

    #[test]
    fn create_in_place_is_the_fallback_for_a_file_system_without_hard_links() {
        let dir = TempDir::new();
        let path = dir.0.join("lock");
        assert!(create_in_place(&path, b"first").unwrap());
        assert!(!create_in_place(&path, b"second").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn remove_lock_removes_only_the_lock() {
        let (_dir, target) = target();
        block_on(target.put("locks/writer", b"lock")).unwrap();
        block_on(target.put("locks/other", b"keep")).unwrap();
        block_on(target.put("packs/ab/x", b"keep")).unwrap();
        block_on(target.remove_lock()).unwrap();
        // It is not an error when there is no lock.
        block_on(target.remove_lock()).unwrap();
        assert_eq!(block_on(target.list("locks")).unwrap(), ["locks/other"]);
        assert_eq!(block_on(target.list("packs")).unwrap(), ["packs/ab/x"]);
    }

    #[test]
    fn rejects_every_path_that_could_leave_the_folder() {
        let (dir, target) = target();
        fs::write(dir.0.join("outside"), b"secret").unwrap();
        let bad = [
            "",
            "..",
            "../outside",
            "packs/../../outside",
            "/etc/passwd",
            "packs//x",
            "packs/./x",
            "packs/x/",
            "packs\\x",
            "C:/x",
            "a\0b",
        ];
        for path in bad {
            assert!(block_on(target.len(path)).is_err(), "{path:?}");
            assert!(block_on(target.read(path)).is_err(), "{path:?}");
            assert!(block_on(target.read_range(path, 0..1)).is_err(), "{path:?}");
            assert!(block_on(target.list(path)).is_err(), "{path:?}");
            assert!(block_on(target.put(path, b"x")).is_err(), "{path:?}");
            assert!(block_on(target.put_new(path, b"x")).is_err(), "{path:?}");
        }
        // Nothing was written, and the file outside was not touched.
        assert_eq!(fs::read(dir.0.join("outside")).unwrap(), b"secret");
        assert!(!target.root().exists());
    }

    #[test]
    fn an_error_text_has_no_path() {
        let (dir, target) = target();
        // A file where a folder is needed.
        fs::create_dir_all(target.root()).unwrap();
        fs::write(target.root().join("packs"), b"a file").unwrap();
        let error = block_on(target.put("packs/ab/x", b"x")).unwrap_err();
        let text = error.to_string();
        assert!(!text.contains("nilperit-test"), "{text}");
        assert!(!text.contains(dir.0.to_str().unwrap()), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_not_a_file_of_the_vault() {
        let (dir, target) = target();
        block_on(target.put("packs/ab/real", b"x")).unwrap();
        std::os::unix::fs::symlink(
            dir.0.join("vault/packs/ab/real"),
            dir.0.join("vault/packs/ab/link"),
        )
        .unwrap();
        assert_eq!(block_on(target.list("packs")).unwrap(), ["packs/ab/real"]);
    }

    #[test]
    fn a_failure_that_passes_is_tried_again() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let result = retry(5, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            if calls.get() < 4 {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(calls.get())
            }
        });
        assert_eq!(result.unwrap(), 4);
        // A sharing violation (the code 32) passes too, and so does a busy resource.
        let calls = Cell::new(0);
        let result = retry(3, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            match calls.get() {
                1 => Err(io::Error::from_raw_os_error(32)),
                2 => Err(io::ErrorKind::ResourceBusy.into()),
                _ => Ok(()),
            }
        });
        assert!(result.is_ok());
    }

    #[test]
    fn a_failure_that_does_not_pass_is_returned_at_once_and_so_is_the_last_one() {
        use std::cell::Cell;
        let calls = Cell::new(0);
        let error = retry(5, Duration::ZERO, || -> io::Result<()> {
            calls.set(calls.get() + 1);
            Err(io::ErrorKind::NotFound.into())
        })
        .unwrap_err();
        assert_eq!((error.kind(), calls.get()), (io::ErrorKind::NotFound, 1));

        let calls = Cell::new(0);
        let error = retry(3, Duration::ZERO, || -> io::Result<()> {
            calls.set(calls.get() + 1);
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .unwrap_err();
        // A real permission problem is an error after the last try.
        assert_eq!(
            (error.kind(), calls.get()),
            (io::ErrorKind::PermissionDenied, 3)
        );

        // One attempt is one try, with no wait.
        let calls = Cell::new(0);
        assert!(
            retry(1, Duration::from_secs(60), || -> io::Result<()> {
                calls.set(calls.get() + 1);
                Err(io::ErrorKind::PermissionDenied.into())
            })
            .is_err()
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn the_wait_doubles_up_to_a_limit() {
        use std::time::Instant;
        // Five failures of an operation: waits of 1, 2, 4, 8 ms and a last try that works.
        let started = Instant::now();
        let mut failures = 4;
        retry(8, Duration::from_millis(1), || {
            if failures > 0 {
                failures -= 1;
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(())
            }
        })
        .unwrap();
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(15), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
    }
}
