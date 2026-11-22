//! Tests of the connector on real folders.

use crate::FolderConnector;
use crate::item::{millis, mode_map};
use crate::test_util::{Listing, TempDir, block_on, run};
use nilperit_writer::Connector;
use std::fs;
use std::io;
use std::time::UNIX_EPOCH;

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
    // The size is known before the file is read: the progress of a run uses it.
    assert_eq!(item.size, Some(5));
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

// macOS does not allow a file name that is not valid UTF-8 (the error is EILSEQ), so the test
// cannot make the file there.
#[cfg(all(unix, not(target_os = "macos")))]
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
    let (complete, listing, items) = run(&mut FolderConnector::new(&dir.0));
    // An item that cannot be read has nothing to read, so the total of a run is still known.
    let mut sizes: Vec<_> = items.iter().map(|item| item.size).collect();
    sizes.sort();
    assert_eq!(sizes, [Some(0), Some(0), Some(4)]);
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
