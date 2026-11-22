//! The fields of an item: its native ID, its times and its metadata.

use nilperit_writer::{OpenContent, SourceItem};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// The native ID of a file: its path below the folder, with `/` between the parts
/// (format.md 5.4.5.2). On Unix a name is bytes and stays as it is. On Windows a name
/// is text, and a part that is not valid text is changed to text, so two such names
/// can have the same native ID. The engine reports the second one.
pub(crate) fn native_id(relative: &Path) -> Vec<u8> {
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
pub(crate) fn failing(native_id: Vec<u8>, kind: io::ErrorKind) -> SourceItem {
    SourceItem {
        title: String::from_utf8_lossy(&native_id).into_owned(),
        native_id,
        modified: None,
        created: None,
        media_type: None,
        // It has nothing to read.
        size: Some(0),
        metadata: None,
        contents: vec![Box::new(move || Err(io::Error::from(kind)))],
    }
}

pub(crate) fn file_item(path: PathBuf, relative: &Path, metadata: &fs::Metadata) -> SourceItem {
    let native_id = native_id(relative);
    let open: OpenContent = Box::new(move || Ok(Box::new(File::open(path)?) as Box<dyn io::Read>));
    SourceItem {
        title: String::from_utf8_lossy(&native_id).into_owned(),
        native_id,
        modified: metadata.modified().ok().map(millis),
        created: metadata.created().ok().map(millis),
        media_type: None,
        size: Some(metadata.len()),
        metadata: mode_metadata(metadata),
        contents: vec![open],
    }
}

/// A time as milliseconds since 1970 (format.md 5.4.5.3). A time before 1970 is
/// negative.
pub(crate) fn millis(time: std::time::SystemTime) -> i64 {
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
pub(crate) fn mode_map(mode: u32) -> Vec<u8> {
    // a1: a map of 1 entry. 64 6d6f6465: the text "mode".
    let mut out = vec![0xa1, 0x64, b'm', b'o', b'd', b'e'];
    match mode {
        0..=23 => out.push(mode as u8),
        24..=255 => out.extend([0x18, mode as u8]),
        _ => out.extend([0x19, (mode >> 8) as u8, mode as u8]),
    }
    out
}
