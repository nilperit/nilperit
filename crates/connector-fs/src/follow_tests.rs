//! Tests of the policy that follows symbolic links.

use crate::test_util::{TempDir, run};
use crate::{FolderConnector, Symlinks};
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

fn follow(root: &Path) -> FolderConnector {
    FolderConnector::new(root).symlinks(Symlinks::Follow)
}

#[test]
fn a_link_to_a_file_stored_elsewhere_is_the_file_under_the_path_of_the_link() {
    let dir = TempDir::new("follow-file");
    let elsewhere = TempDir::new("follow-file-elsewhere");
    fs::write(elsewhere.0.join("report.pdf"), b"important").unwrap();
    fs::create_dir_all(dir.0.join("work")).unwrap();
    symlink(
        elsewhere.0.join("report.pdf"),
        dir.0.join("work/report.pdf"),
    )
    .unwrap();
    fs::write(dir.0.join("plain"), b"plain").unwrap();

    let (complete, listing, _) = run(&mut follow(&dir.0));
    assert!(complete);
    assert_eq!(
        listing,
        [
            (b"plain".to_vec(), Ok(b"plain".to_vec())),
            (b"work/report.pdf".to_vec(), Ok(b"important".to_vec())),
        ]
    );
    // The default does not follow the link.
    let (_, listing, _) = run(&mut FolderConnector::new(&dir.0));
    assert_eq!(
        listing[1],
        (b"work/report.pdf".to_vec(), Err(io::ErrorKind::Unsupported))
    );
}

#[test]
fn a_link_to_a_folder_stored_elsewhere_is_walked_under_the_path_of_the_link() {
    let dir = TempDir::new("follow-folder");
    let elsewhere = TempDir::new("follow-folder-elsewhere");
    fs::create_dir_all(elsewhere.0.join("sub")).unwrap();
    fs::write(elsewhere.0.join("a.txt"), b"a").unwrap();
    fs::write(elsewhere.0.join("sub/b.txt"), b"b").unwrap();
    symlink(&elsewhere.0, dir.0.join("Documents")).unwrap();
    let (complete, listing, _) = run(&mut follow(&dir.0));
    assert!(complete);
    assert_eq!(
        listing,
        [
            (b"Documents/a.txt".to_vec(), Ok(b"a".to_vec())),
            (b"Documents/sub/b.txt".to_vec(), Ok(b"b".to_vec())),
        ]
    );
}

#[test]
fn a_link_that_leads_back_is_reported_and_the_walk_ends() {
    let dir = TempDir::new("follow-loop");
    fs::create_dir_all(dir.0.join("a")).unwrap();
    fs::create_dir_all(dir.0.join("b")).unwrap();
    fs::write(dir.0.join("a/file"), b"a").unwrap();
    fs::write(dir.0.join("b/file"), b"b").unwrap();
    symlink(".", dir.0.join("self")).unwrap();
    symlink("..", dir.0.join("a/up")).unwrap();
    // Two links that point at each other's folder.
    symlink("../b", dir.0.join("a/to-b")).unwrap();
    symlink("../a", dir.0.join("b/to-a")).unwrap();

    let (complete, listing, _) = run(&mut follow(&dir.0));
    // Every loop is known and reported, so the list is complete.
    assert!(complete);
    let loops: Vec<&[u8]> = listing
        .iter()
        .filter(|(_, content)| *content == Err(io::ErrorKind::Other))
        .map(|(id, _)| id.as_slice())
        .collect();
    assert!(loops.contains(&&b"self"[..]), "{loops:?}");
    assert!(loops.contains(&&b"a/up"[..]), "{loops:?}");
    // The real files are there once under their own path.
    assert!(listing.contains(&(b"a/file".to_vec(), Ok(b"a".to_vec()))));
    assert!(listing.contains(&(b"b/file".to_vec(), Ok(b"b".to_vec()))));
    // The links between a and b are followed once, and then a loop ends them.
    assert!(listing.len() < 40, "{}", listing.len());
}

#[test]
fn a_link_that_goes_nowhere_makes_the_list_incomplete() {
    // A disk that is not mounted: the link is there and the target is not.
    let dir = TempDir::new("follow-dangling");
    fs::write(dir.0.join("plain"), b"plain").unwrap();
    symlink(dir.0.join("not-mounted/Documents"), dir.0.join("Documents")).unwrap();
    let (complete, listing, _) = run(&mut follow(&dir.0));
    assert!(!complete);
    // The kind is not `NotFound`, which would say that the item is gone.
    assert_eq!(
        listing,
        [
            (b"Documents".to_vec(), Err(io::ErrorKind::Other)),
            (b"plain".to_vec(), Ok(b"plain".to_vec())),
        ]
    );
    // Without following, the link is skipped as before, and the list is complete.
    let (complete, _, _) = run(&mut FolderConnector::new(&dir.0));
    assert!(complete);
}

#[test]
fn a_followed_link_into_an_excluded_path_is_left_out() {
    let dir = TempDir::new("follow-exclude");
    let vault = TempDir::new("follow-exclude-vault");
    fs::write(vault.0.join("config-a"), b"c").unwrap();
    fs::write(dir.0.join("data"), b"d").unwrap();
    symlink(&vault.0, dir.0.join("vault-link")).unwrap();
    symlink(vault.0.join("config-a"), dir.0.join("config-link")).unwrap();
    let mut connector = follow(&dir.0).exclude(&vault.0);
    let (complete, listing, _) = run(&mut connector);
    assert!(complete);
    assert_eq!(listing, [(b"data".to_vec(), Ok(b"d".to_vec()))]);
}

#[test]
fn a_link_to_a_pipe_is_not_a_file() {
    let dir = TempDir::new("follow-pipe");
    let pipe = dir.0.join("pipe");
    let made = std::process::Command::new("mkfifo").arg(&pipe).status();
    if !made.is_ok_and(|status| status.success()) {
        return;
    }
    let folder = dir.0.join("folder");
    fs::create_dir_all(&folder).unwrap();
    symlink(&pipe, folder.join("link-to-pipe")).unwrap();
    let (_, listing, _) = run(&mut follow(&folder));
    assert_eq!(
        listing,
        [(b"link-to-pipe".to_vec(), Err(io::ErrorKind::Unsupported))]
    );
}
