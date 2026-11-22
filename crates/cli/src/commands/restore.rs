//! `nilperit restore`: write the files of a source back into a folder.
//!
//! The vault is not trusted. A damaged or hostile vault must not be able to write outside
//! the folder or over a file of the person, so:
//!
//! - **The name of an item is checked.** A native ID with an empty part, `.` or `..`, a zero
//!   byte, or (on Windows) a character or a name that Windows treats in a special way, is
//!   not restored. It is reported.
//! - **A link in the way is never followed.** Each folder on the path is checked with
//!   `symlink_metadata`. A symbolic link or a file where a folder is needed is reported, and
//!   nothing is written through it.
//! - **A file that exists is never overwritten.** It is left alone and counted. The new file
//!   is written to a temporary name, and it gets its final name with a hard link, which fails
//!   when the name exists. So a file appears under its name only when it is complete and
//!   verified, and an interrupted restore can be run again.
//! - **Everything is checked.** The content is read with the checks of the reader (tags,
//!   object IDs, size and content hash). The size must be the size of the item record.
//! - **No special bits.** The permission bits are restored with `0o777`. A setuid, setgid or
//!   sticky bit in the vault is not applied.

use super::common::{OpenVault, open_vault, parse_source_id};
use crate::cli::RestoreArgs;
use crate::display::size;
use crate::environment::Environment;
use crate::error::CliError;
use crate::exec::block_on;
use crate::phrase::read_seed;
use crate::progress::{Reporter, Status, with_reporter};
use nilperit_crypto::RootSeed;
use nilperit_format::{ItemRecord, SourceId};
use nilperit_reader::ContentError;
use nilperit_writer::{Credential, source_id};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The exit code of a run that could not restore some items.
const EXIT_WITH_WARNINGS: u8 = 3;

pub fn run(
    args: &RestoreArgs,
    env: &Environment,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut (dyn Write + Send),
) -> Result<ExitCode, CliError> {
    // Check the arguments before the person types the phrase.
    let by_id = args.source_id.as_deref().map(parse_source_id).transpose()?;
    let filter = args.path.as_deref().map(parse_filter).transpose()?;

    let seed = read_seed(args.phrase.phrase_file.as_deref(), env, stdin)?;
    // The report of the run is written when the line of progress is gone.
    let report = with_reporter(err, env.progress, |reporter| {
        restore_source(args, seed, by_id, filter.as_deref(), reporter)
    })?;
    report.show(out, err, args.verbose)?;
    Ok(
        if report.failed.is_empty() && report.unreadable_records == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(EXIT_WITH_WARNINGS)
        },
    )
}

/// Restores the items of one source, and tells how far it is. The vault is opened here, with
/// the phrase that the person gave.
fn restore_source(
    args: &RestoreArgs,
    seed: RootSeed,
    by_id: Option<SourceId>,
    filter: Option<&[u8]>,
    reporter: &Reporter<'_, '_>,
) -> Result<Report, CliError> {
    let open = open_vault(&args.vault, seed, reporter)?;
    let source = choose_source(&open, args.name.as_deref(), by_id)?;
    let head = open.snapshots.head(&source).ok_or(CliError::NoSuchSource)?;
    reporter.report(Status::step("Reading the journal"));
    let state =
        block_on(open.vault.replay_journal(&open.index, head)).map_err(CliError::Journal)?;

    // The item records give the names. Items whose record cannot be read cannot be named,
    // and so they cannot be restored.
    let mut records: Vec<ItemRecord> = Vec::new();
    let mut unreadable_records = 0u64;
    let total_records = state.items.len() as u64;
    for (done, (key, item)) in state.items.iter().enumerate() {
        reporter.report(Status::items(
            "Reading the items",
            done as u64,
            total_records,
        ));
        match block_on(open.vault.read_item(&open.index, key, item)) {
            Ok(record) => records.push(record),
            Err(_) => unreadable_records += 1,
        }
    }
    records.sort_by(|a, b| a.native_id.cmp(&b.native_id));
    if let Some(filter) = &filter {
        records.retain(|record| matches_filter(&record.native_id, filter));
        if records.is_empty() && unreadable_records == 0 {
            return Err(CliError::NothingMatches);
        }
    }

    let destination = prepare_destination(&args.destination, &args.vault)?;
    let mut report = Report {
        unreadable_records,
        ..Report::default()
    };
    let count = records.len() as u64;
    let total_bytes = records
        .iter()
        .fold(0u64, |sum, record| sum.saturating_add(record.size));
    // The bytes of the items that are finished, restored or not: an item that is left alone
    // is finished too, so that the progress reaches its end.
    let mut finished_bytes = 0u64;
    reporter.report(Status::transfer(
        "Restoring",
        (0, count),
        0,
        Some(total_bytes),
    ));
    for (done, record) in records.iter().enumerate() {
        let done = done as u64;
        let base = finished_bytes;
        let mut written = |bytes: u64| {
            reporter.report(Status::transfer(
                "Restoring",
                (done, count),
                base.saturating_add(bytes.min(record.size)),
                Some(total_bytes),
            ));
        };
        match restore_item(&open, &destination, record, &mut written) {
            Ok(Done::Restored) => {
                report.restored += 1;
                report.bytes += record.size;
            }
            Ok(Done::Existing) => report.existing.push(record.native_id.clone()),
            Err(reason) => report.failed.push((record.native_id.clone(), reason)),
        }
        finished_bytes = finished_bytes.saturating_add(record.size);
        reporter.report(Status::transfer(
            "Restoring",
            (done + 1, count),
            finished_bytes,
            Some(total_bytes),
        ));
    }
    Ok(report)
}

/// The source to restore: the one that the person named, or the only one of the vault.
fn choose_source(
    open: &OpenVault,
    name: Option<&str>,
    by_id: Option<SourceId>,
) -> Result<SourceId, CliError> {
    if let Some(name) = name {
        return source_id(&Credential::from_seed(&open.seed), name).ok_or(CliError::EmptyName);
    }
    if let Some(id) = by_id {
        return Ok(id);
    }
    let sources = open.snapshots.sources();
    match sources.as_slice() {
        [only] => Ok(*only),
        other => Err(CliError::SourceNotChosen(other.len())),
    }
}

/// The path that the person gave: parts between `/`, a trailing `/` allowed. It is bytes,
/// like a native ID.
fn parse_filter(text: &str) -> Result<Vec<u8>, CliError> {
    let trimmed = text.strip_suffix('/').unwrap_or(text);
    if trimmed.is_empty()
        || trimmed
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(CliError::BadPath);
    }
    Ok(trimmed.as_bytes().to_vec())
}

/// Whether an item is the path or is below it.
fn matches_filter(native_id: &[u8], filter: &[u8]) -> bool {
    native_id == filter
        || (native_id.len() > filter.len()
            && native_id.starts_with(filter)
            && native_id[filter.len()] == b'/')
}

/// Makes the folder to restore into, and gives its real path. It must not be inside the
/// vault: files that are restored there would be in the vault.
fn prepare_destination(destination: &Path, vault: &Path) -> Result<PathBuf, CliError> {
    fs::create_dir_all(destination).map_err(|e| CliError::Destination(e.kind()))?;
    let real = fs::canonicalize(destination).map_err(|e| CliError::Destination(e.kind()))?;
    if !real.is_dir() {
        return Err(CliError::Destination(io::ErrorKind::InvalidInput));
    }
    let vault = fs::canonicalize(vault).map_err(|e| CliError::Destination(e.kind()))?;
    if real.starts_with(&vault) {
        return Err(CliError::DestinationInVault);
    }
    Ok(real)
}

/// Why an item was not restored. The text has no name and no path.
#[derive(Debug, PartialEq, Eq)]
enum Reason {
    /// The native ID is not a safe path.
    UnsafeName,
    /// A symbolic link is where a folder must be.
    LinkInTheWay,
    /// A file is where a folder must be.
    FileInTheWay,
    /// The content cannot be read from the vault, or it does not pass the checks.
    Unreadable,
    /// The content has another size than the item record says.
    WrongSize,
    /// The file system failed.
    Io(io::ErrorKind),
}

impl Reason {
    fn text(&self) -> String {
        match self {
            Self::UnsafeName => "the name is not a safe path (it would leave the folder)".into(),
            Self::LinkInTheWay => "a symbolic link is where a folder must be".into(),
            Self::FileInTheWay => "a file is where a folder must be".into(),
            Self::Unreadable => {
                "the content cannot be read from the vault, or it is damaged".into()
            }
            Self::WrongSize => "the content has another size than the item record says".into(),
            Self::Io(kind) => format!("the file system failed ({kind:?})"),
        }
    }
}

enum Done {
    Restored,
    /// A file with the name exists. It was not changed.
    Existing,
}

#[derive(Default)]
struct Report {
    restored: u64,
    bytes: u64,
    existing: Vec<Vec<u8>>,
    failed: Vec<(Vec<u8>, Reason)>,
    unreadable_records: u64,
}

impl Report {
    fn show(&self, out: &mut dyn Write, err: &mut dyn Write, verbose: bool) -> io::Result<()> {
        writeln!(
            out,
            "Restored {} {} ({}).",
            self.restored,
            if self.restored == 1 { "item" } else { "items" },
            size(self.bytes)
        )?;
        let hint = if verbose {
            ":"
        } else {
            " (use -v to see which)"
        };
        if !self.existing.is_empty() {
            writeln!(
                out,
                "{} {} existed already and {} left alone{hint}",
                self.existing.len(),
                if self.existing.len() == 1 {
                    "file"
                } else {
                    "files"
                },
                if self.existing.len() == 1 {
                    "was"
                } else {
                    "were"
                },
            )?;
            if verbose {
                for name in &self.existing {
                    writeln!(out, "  {}", String::from_utf8_lossy(name))?;
                }
            }
        }
        if !self.failed.is_empty() {
            writeln!(
                out,
                "{} {} could not be restored{hint}",
                self.failed.len(),
                if self.failed.len() == 1 {
                    "item"
                } else {
                    "items"
                },
            )?;
            if verbose {
                for (name, reason) in &self.failed {
                    writeln!(
                        out,
                        "  {}: {}",
                        String::from_utf8_lossy(name),
                        reason.text()
                    )?;
                }
            }
        }
        out.flush()?;
        if self.unreadable_records > 0 {
            writeln!(
                err,
                "warning: {} {} could not be read from the vault, so it has no name and was not restored",
                self.unreadable_records,
                if self.unreadable_records == 1 {
                    "item"
                } else {
                    "items"
                },
            )?;
        }
        Ok(())
    }
}

/// The relative path of an item below the folder to restore into. The native ID is bytes
/// with `/` between the parts (format.md 5.4.5.2). Every part is checked. An empty part,
/// `.`, `..` and a zero byte are never allowed. Windows has more rules.
fn safe_relative(native_id: &[u8]) -> Result<PathBuf, Reason> {
    if native_id.is_empty() {
        return Err(Reason::UnsafeName);
    }
    let mut path = PathBuf::new();
    for part in native_id.split(|byte| *byte == b'/') {
        if part.is_empty() || part == b"." || part == b".." || part.contains(&0) {
            return Err(Reason::UnsafeName);
        }
        let name = os_name(part)?;
        if cfg!(windows) && windows_unsafe(name.to_str().ok_or(Reason::UnsafeName)?) {
            return Err(Reason::UnsafeName);
        }
        path.push(name);
    }
    // Every part is a plain name: the path has nothing but normal parts.
    debug_assert!(path.components().all(|c| matches!(c, Component::Normal(_))));
    Ok(path)
}

#[cfg(unix)]
fn os_name(part: &[u8]) -> Result<&OsStr, Reason> {
    use std::os::unix::ffi::OsStrExt;
    Ok(OsStr::from_bytes(part))
}

#[cfg(not(unix))]
fn os_name(part: &[u8]) -> Result<&OsStr, Reason> {
    // A name on Windows is text.
    std::str::from_utf8(part)
        .map(OsStr::new)
        .map_err(|_| Reason::UnsafeName)
}

/// Whether Windows treats a name in a special way: a character that is not allowed, a name
/// that ends with a dot or a space, or the name of a device. The function is the same on
/// every system, so that it can be tested everywhere. It is used on Windows.
fn windows_unsafe(name: &str) -> bool {
    const BAD: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    if name.chars().any(|c| BAD.contains(&c) || (c as u32) < 0x20) {
        return true;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return true;
    }
    // A device name is special with any extension: `CON.txt` is the console.
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"];
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix)
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
    };
    reserved.contains(&stem.as_str()) || numbered("COM") || numbered("LPT")
}

/// The permission bits that the connector put in the metadata: the CBOR map `{"mode": n}`,
/// as the folder connector writes it (format.md A.10.2). Another shape is not a mode.
fn parse_mode(metadata: &[u8]) -> Option<u32> {
    let rest = metadata.strip_prefix(&[0xa1, 0x64, b'm', b'o', b'd', b'e'])?;
    match rest {
        [n] if *n <= 0x17 => Some(u32::from(*n)),
        [0x18, n] => Some(u32::from(*n)),
        [0x19, high, low] => Some(u32::from(*high) << 8 | u32::from(*low)),
        _ => None,
    }
}

/// A time in milliseconds since 1970 as a `SystemTime`. `None` when it does not fit.
fn system_time(milliseconds: i64) -> Option<SystemTime> {
    let span = Duration::from_millis(milliseconds.unsigned_abs());
    if milliseconds >= 0 {
        UNIX_EPOCH.checked_add(span)
    } else {
        UNIX_EPOCH.checked_sub(span)
    }
}

/// Makes the folders for an item, one by one, and never goes through a link.
fn prepare_parents(root: &Path, relative: &Path) -> Result<PathBuf, Reason> {
    let mut current = root.to_path_buf();
    let Some(parent) = relative.parent() else {
        return Ok(current);
    };
    for part in parent.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(Reason::LinkInTheWay),
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(Reason::FileInTheWay),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|e| Reason::Io(e.kind()))?;
            }
            Err(e) => return Err(Reason::Io(e.kind())),
        }
    }
    Ok(current)
}

/// A name for a temporary file that no other restore uses.
fn temporary_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        ".nilperit-restore-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn restore_item(
    open: &OpenVault,
    root: &Path,
    record: &ItemRecord,
    written: &mut dyn FnMut(u64),
) -> Result<Done, Reason> {
    let relative = safe_relative(&record.native_id)?;
    let target = root.join(&relative);
    let folder = prepare_parents(root, &relative)?;
    // A file, a folder or a link with this name: leave it alone.
    if fs::symlink_metadata(&target).is_ok() {
        return Ok(Done::Existing);
    }

    let temporary = folder.join(temporary_name());
    let result = write_verified(open, &temporary, record, written);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return result.map(|()| Done::Restored);
    }
    // The file has its name in one step, and only when no file has it.
    let placed = match fs::hard_link(&temporary, &target) {
        Ok(()) => Ok(Done::Restored),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(Done::Existing),
        // A file system without hard links (for example exFAT): rename, after a check.
        Err(_) => {
            if fs::symlink_metadata(&target).is_ok() {
                Ok(Done::Existing)
            } else {
                fs::rename(&temporary, &target)
                    .map(|()| Done::Restored)
                    .map_err(|e| Reason::Io(e.kind()))
            }
        }
    };
    let _ = fs::remove_file(&temporary);
    placed
}

/// Writes the content of an item to a new file and checks it: the reader checks every chunk
/// and the whole content, and the size must be the size of the record. The time and the
/// permission bits are set before the file gets its name.
fn write_verified(
    open: &OpenVault,
    path: &Path,
    record: &ItemRecord,
    progress: &mut dyn FnMut(u64),
) -> Result<(), Reason> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| Reason::Io(e.kind()))?;
    let mut written: u64 = 0;
    for content in &record.content {
        let result = block_on(open.vault.read_content(&open.index, content, |chunk| {
            written += chunk.len() as u64;
            progress(written);
            file.write_all(chunk)
        }));
        match result {
            Ok(_) => {}
            Err(ContentError::Sink(e)) => return Err(Reason::Io(e.kind())),
            Err(_) => return Err(Reason::Unreadable),
        }
    }
    if written != record.size {
        return Err(Reason::WrongSize);
    }
    if let Some(time) = record.modified.and_then(system_time) {
        // A time that the file system cannot hold is not worth a failure.
        let _ = file.set_modified(time);
    }
    #[cfg(unix)]
    if let Some(mode) = record.metadata.as_deref().and_then(parse_mode) {
        use std::os::unix::fs::PermissionsExt;
        // Only the nine bits of the owner, the group and the others.
        file.set_permissions(fs::Permissions::from_mode(mode & 0o777))
            .map_err(|e| Reason::Io(e.kind()))?;
    }
    file.sync_all().map_err(|e| Reason::Io(e.kind()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(id: &[u8]) -> Result<PathBuf, Reason> {
        safe_relative(id)
    }

    #[test]
    fn a_native_id_with_plain_parts_is_a_path_below_the_folder() {
        assert_eq!(rel(b"a").unwrap(), PathBuf::from("a"));
        assert_eq!(
            rel(b"docs/deep/c.txt").unwrap(),
            PathBuf::from("docs/deep/c.txt")
        );
        // Names that look strange are names: a dot at the start, spaces inside.
        assert_eq!(rel(b".hidden").unwrap(), PathBuf::from(".hidden"));
        assert_eq!(rel(b"...x").unwrap(), PathBuf::from("...x"));
        assert_eq!(rel(b"a b/c  d").unwrap(), PathBuf::from("a b/c  d"));
    }

    #[test]
    fn a_name_of_dots_is_a_name_on_unix_and_not_on_windows() {
        // Windows removes the dots at the end of a name, so `...` would not be a file there.
        // The rule of Windows is used on Windows only.
        if cfg!(windows) {
            assert_eq!(rel(b"..."), Err(Reason::UnsafeName));
            assert_eq!(rel(b"a/b."), Err(Reason::UnsafeName));
        } else {
            assert_eq!(rel(b"...").unwrap(), PathBuf::from("..."));
            assert_eq!(rel(b"a/b.").unwrap(), PathBuf::from("a/b."));
        }
    }

    #[test]
    fn a_native_id_that_could_leave_the_folder_is_not_a_path() {
        for id in [
            &b""[..],
            b"/",
            b"/etc/passwd",
            b"a/",
            b"a//b",
            b".",
            b"..",
            b"a/.",
            b"a/..",
            b"../a",
            b"a/../b",
            b"../../etc/passwd",
            b"a\0b",
            b"a/b\0",
        ] {
            assert_eq!(
                rel(id),
                Err(Reason::UnsafeName),
                "{:?}",
                String::from_utf8_lossy(id)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn on_unix_a_name_is_bytes() {
        use std::os::unix::ffi::OsStrExt;
        // Not text, a backslash and a colon are names on Unix. They are not on Windows.
        let path = rel(b"odd\xff\xfe/back\\slash/a:b").unwrap();
        let parts: Vec<&[u8]> = path.iter().map(OsStrExt::as_bytes).collect();
        assert_eq!(parts, [&b"odd\xff\xfe"[..], b"back\\slash", b"a:b"]);
    }

    #[test]
    fn windows_has_more_rules() {
        for bad in [
            "a:b",
            "a*b",
            "a?b",
            "a<b",
            "a>b",
            "a|b",
            "a\"b",
            "a\\b",
            "bell\u{7}",
            "name.",
            "name ",
            "CON",
            "con",
            "Con.txt",
            "PRN",
            "aux",
            "NUL.tar.gz",
            "COM1",
            "com9.txt",
            "LPT1",
            "lpt9",
        ] {
            assert!(windows_unsafe(bad), "{bad:?}");
        }
        for good in [
            "name",
            "name.txt",
            "con-sole",
            "confirm.txt",
            "COM10",
            "COM0",
            "LPT",
            "a b",
            ".hidden",
            "...x",
            "é.txt",
        ] {
            assert!(!windows_unsafe(good), "{good:?}");
        }
    }

    #[test]
    fn the_mode_is_read_from_the_map_that_the_connector_writes() {
        let map = |tail: &[u8]| {
            let mut bytes = vec![0xa1, 0x64, b'm', b'o', b'd', b'e'];
            bytes.extend_from_slice(tail);
            bytes
        };
        assert_eq!(parse_mode(&map(&[0x19, 0x01, 0xa4])), Some(0o644));
        assert_eq!(parse_mode(&map(&[0x00])), Some(0));
        assert_eq!(parse_mode(&map(&[0x17])), Some(23));
        assert_eq!(parse_mode(&map(&[0x18, 0x38])), Some(0o70));
        assert_eq!(parse_mode(&map(&[0x19, 0x0f, 0xff])), Some(0o7777));
        // Another shape is no mode: another key, a longer map, text, a negative number,
        // an integer that is not the shortest, and bytes after the number.
        assert_eq!(
            parse_mode(&[0xa1, 0x64, b'm', b'o', b'd', b'x', 0x01]),
            None
        );
        assert_eq!(parse_mode(&map(&[0x01, 0x00])), None);
        assert_eq!(parse_mode(&map(&[0x61, b'a'])), None);
        assert_eq!(parse_mode(&map(&[0x20])), None);
        assert_eq!(parse_mode(&map(&[0x19, 0x01])), None);
        assert_eq!(
            parse_mode(&[0xa2, 0x64, b'm', b'o', b'd', b'e', 0x01]),
            None
        );
        assert_eq!(parse_mode(&[]), None);
        assert_eq!(parse_mode(b"mode"), None);
    }

    #[test]
    fn a_path_filter_matches_the_item_and_what_is_below_it() {
        let filter = parse_filter("docs/deep/").unwrap();
        assert_eq!(filter, b"docs/deep");
        assert!(matches_filter(b"docs/deep", &filter));
        assert!(matches_filter(b"docs/deep/c.txt", &filter));
        assert!(matches_filter(b"docs/deep/more/d", &filter));
        // A name that only starts like the path is not below it.
        assert!(!matches_filter(b"docs/deeper", &filter));
        assert!(!matches_filter(b"docs/deep-x/c", &filter));
        assert!(!matches_filter(b"docs", &filter));
        for bad in ["", "/", "a//b", "..", "a/../b", "./a", "a/."] {
            assert!(parse_filter(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn times_before_1970_and_after_are_system_times() {
        assert_eq!(system_time(0), Some(UNIX_EPOCH));
        assert_eq!(
            system_time(1500),
            Some(UNIX_EPOCH + Duration::from_millis(1500))
        );
        assert_eq!(
            system_time(-1500),
            Some(UNIX_EPOCH - Duration::from_millis(1500))
        );
    }
}
