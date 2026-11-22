//! `nilperit restore`. A vault is made with `init`, filled with `sync` (or, for a hostile
//! vault, with the writer directly), and restored with the recovery phrase.

mod common;

use common::{Made, TempDir, block_on, env, init, nilperit, nilperit_with_input, write};
use nilperit_format::SourceId;
use nilperit_reader::Vault;
use nilperit_reader::layout::pack_path;
use nilperit_target_fs::FsTarget;
use nilperit_writer::{
    Changes, Connector, ConnectorError, Credential, SourceItem, SyncOptions, WriterLock, source_id,
    sync,
};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

fn backup(made: &Made, folder: &Path, dir: &TempDir, extra: &[&str]) {
    let mut args = vec![
        "sync",
        folder.to_str().unwrap(),
        "--vault",
        made.vault.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let outcome = nilperit(&args, &env(dir));
    assert!(outcome.succeeded(), "{} {}", outcome.out, outcome.err);
}

fn restore(made: &Made, destination: &Path, dir: &TempDir, extra: &[&str]) -> common::Outcome {
    restore_with_input(made, destination, dir, extra, &made.phrase)
}

fn restore_with_input(
    made: &Made,
    destination: &Path,
    dir: &TempDir,
    extra: &[&str],
    input: &str,
) -> common::Outcome {
    let mut args = vec![
        "restore",
        destination.to_str().unwrap(),
        "--vault",
        made.vault.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    nilperit_with_input(&args, &env(dir), input)
}

fn big(seed: u8) -> Vec<u8> {
    (0..600_000usize)
        .map(|i| {
            (i as u8)
                .wrapping_mul(17)
                .wrapping_add(seed)
                .wrapping_add((i / 250) as u8)
        })
        .collect()
}

/// All files below a folder, with their relative paths and bytes.
fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, path: &Path, files: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(path).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(root, &p, files);
            } else {
                // The parts are joined with `/` on every system, as in a native ID.
                let name = p
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push((name, fs::read(&p).unwrap()));
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    files
}

/// A source with a list of items that is given as bytes, for a vault with names that a
/// folder cannot have.
struct Items(Vec<(Vec<u8>, Vec<u8>)>);

impl Connector for Items {
    async fn changes(&mut self, _: Option<&[u8]>) -> Result<Changes, ConnectorError> {
        let items = self
            .0
            .iter()
            .map(|(native_id, data)| {
                let data = data.clone();
                SourceItem {
                    native_id: native_id.clone(),
                    title: String::from_utf8_lossy(native_id).into_owned(),
                    modified: Some(1_700_000_000_000),
                    created: None,
                    media_type: None,
                    size: None,
                    metadata: None,
                    contents: vec![Box::new(move || {
                        Ok(Box::new(Cursor::new(data)) as Box<dyn std::io::Read>)
                    })],
                }
            })
            .collect();
        Ok(Changes {
            complete: true,
            items,
            deleted: Vec::new(),
            cursor: None,
        })
    }
}

/// Puts items with these native IDs in a vault, as a source with this name.
fn sync_items(made: &Made, name: &str, items: Vec<(&[u8], &[u8])>) -> SourceId {
    let credential = Credential::from_seed(&made.seed);
    let source = source_id(&credential, name).unwrap();
    let target = FsTarget::new(&made.vault);
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let lock = block_on(WriterLock::acquire(
        &target,
        1_700_000_000_000,
        600_000,
        &mut rng,
    ))
    .unwrap();
    let mut connector = Items(
        items
            .into_iter()
            .map(|(i, d)| (i.to_vec(), d.to_vec()))
            .collect(),
    );
    block_on(sync(
        &lock,
        &credential,
        source,
        &mut connector,
        &SyncOptions::default(),
        || 1_700_000_000_000,
        &mut rng,
    ))
    .unwrap();
    block_on(lock.release()).unwrap();
    source
}

fn set_time(path: &Path, seconds: u64) {
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

fn modified_ms(path: &Path) -> u128 {
    fs::metadata(path)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

#[test]
fn restore_gives_back_every_file_with_its_time_and_mode() {
    let dir = TempDir::new("restore");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "a.txt", b"alpha");
    write(&folder, "docs/big.bin", &big(1));
    write(&folder, "docs/deep/c.txt", b"charlie");
    write(&folder, ".hidden", b"dot");
    write(&folder, "empty", b"");
    set_time(&folder.join("a.txt"), 1_700_000_000);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(folder.join("a.txt"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(
            folder.join("docs/deep/c.txt"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    backup(&made, &folder, &dir, &[]);

    let destination = dir.0.join("restored/deeper");
    let outcome = restore(&made, &destination, &dir, &[]);
    assert!(outcome.succeeded(), "{} {}", outcome.out, outcome.err);
    assert!(
        outcome.out.starts_with("Restored 5 items ("),
        "{}",
        outcome.out
    );
    assert_eq!(tree(&destination), tree(&folder));
    assert_eq!(modified_ms(&destination.join("a.txt")), 1_700_000_000_000);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| {
            fs::metadata(destination.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("a.txt"), 0o640);
        assert_eq!(mode("docs/deep/c.txt"), 0o755);
    }
    // No temporary file stays.
    assert!(
        tree(&destination)
            .iter()
            .all(|(name, _)| !name.contains(".nilperit-restore"))
    );
}

#[cfg(unix)]
#[test]
fn a_special_bit_in_the_vault_is_not_applied() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("setuid");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "tool", b"#!/bin/sh");
    fs::set_permissions(folder.join("tool"), fs::Permissions::from_mode(0o6755)).unwrap();
    assert_eq!(
        fs::metadata(folder.join("tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o6755
    );
    backup(&made, &folder, &dir, &[]);
    let destination = dir.0.join("out");
    assert!(restore(&made, &destination, &dir, &[]).succeeded());
    let mode = fs::metadata(destination.join("tool"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o755);
}

#[test]
fn a_file_that_exists_is_never_overwritten() {
    let dir = TempDir::new("exists");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "mine.txt", b"in the vault");
    write(&folder, "new.txt", b"new");
    write(&folder, "docs/b.txt", b"b");
    backup(&made, &folder, &dir, &[]);

    // The destination has a file with the same name and other content, and a file of
    // another name.
    let destination = dir.0.join("out");
    write(&destination, "mine.txt", b"MY OWN CONTENT");
    write(&destination, "other.txt", b"other");
    let quiet = restore(&made, &destination, &dir, &[]);
    assert!(quiet.succeeded(), "{} {}", quiet.out, quiet.err);
    assert!(quiet.out.contains("Restored 2 items"), "{}", quiet.out);
    assert!(
        quiet
            .out
            .contains("1 file existed already and was left alone (use -v to see which)"),
        "{}",
        quiet.out
    );
    assert!(!quiet.out.contains("mine.txt"), "{}", quiet.out);
    assert_eq!(
        fs::read(destination.join("mine.txt")).unwrap(),
        b"MY OWN CONTENT"
    );
    assert_eq!(fs::read(destination.join("other.txt")).unwrap(), b"other");
    assert_eq!(fs::read(destination.join("new.txt")).unwrap(), b"new");

    // A second run restores nothing new, and leaves everything alone. With -v the names show.
    let again = restore(&made, &destination, &dir, &["-v"]);
    assert!(again.succeeded());
    assert!(again.out.contains("Restored 0 items"), "{}", again.out);
    assert!(
        again
            .out
            .contains("3 files existed already and were left alone:"),
        "{}",
        again.out
    );
    assert!(again.out.contains("  mine.txt"), "{}", again.out);
}

#[cfg(unix)]
#[test]
fn a_link_in_the_destination_is_never_followed() {
    let dir = TempDir::new("links");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "docs/a.txt", b"a");
    write(&folder, "ok.txt", b"ok");
    backup(&made, &folder, &dir, &[]);

    // `docs` in the destination is a link to a folder somewhere else.
    let elsewhere = dir.0.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let destination = dir.0.join("out");
    fs::create_dir_all(&destination).unwrap();
    std::os::unix::fs::symlink(&elsewhere, destination.join("docs")).unwrap();

    let outcome = restore(&made, &destination, &dir, &["-v"]);
    assert!(outcome.exited_with(3), "{} {}", outcome.out, outcome.err);
    assert!(
        outcome
            .out
            .contains("docs/a.txt: a symbolic link is where a folder must be"),
        "{}",
        outcome.out
    );
    // Nothing was written through the link, and the other file was restored.
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    assert_eq!(fs::read(destination.join("ok.txt")).unwrap(), b"ok");

    // A link where a file belongs is a file that exists: it is left alone, and not followed.
    let target = dir.0.join("precious");
    fs::write(&target, b"precious").unwrap();
    let destination2 = dir.0.join("out2");
    fs::create_dir_all(&destination2).unwrap();
    std::os::unix::fs::symlink(&target, destination2.join("ok.txt")).unwrap();
    let second = restore(&made, &destination2, &dir, &[]);
    assert!(second.out.contains("left alone"), "{}", second.out);
    assert_eq!(fs::read(&target).unwrap(), b"precious");

    // A file where a folder belongs is reported.
    let destination3 = dir.0.join("out3");
    write(&destination3, "docs", b"a file");
    let third = restore(&made, &destination3, &dir, &["-v"]);
    assert!(
        third
            .out
            .contains("docs/a.txt: a file is where a folder must be"),
        "{}",
        third.out
    );
    assert_eq!(fs::read(destination3.join("docs")).unwrap(), b"a file");
}

#[test]
fn a_hostile_vault_cannot_write_outside_the_folder() {
    let dir = TempDir::new("hostile");
    let made = init(&dir, "vault");
    sync_items(
        &made,
        "evil",
        vec![
            (b"ok/file.txt", b"fine"),
            (b"../escaped.txt", b"x"),
            (b"/absolute.txt", b"x"),
            (b"a//b.txt", b"x"),
            (b"./dot.txt", b"x"),
            (b"a/../b.txt", b"x"),
            (b"nul\0byte", b"x"),
            (b"trailing/", b"x"),
            (b"..", b"x"),
        ],
    );
    let parent = dir.0.join("parent");
    let destination = parent.join("out");
    fs::create_dir_all(&parent).unwrap();
    let before: Vec<_> = fs::read_dir(&parent)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();

    let quiet = restore(&made, &destination, &dir, &[]);
    assert!(quiet.exited_with(3), "{} {}", quiet.out, quiet.err);
    assert!(quiet.out.contains("Restored 1 item "), "{}", quiet.out);
    assert!(
        quiet
            .out
            .contains("8 items could not be restored (use -v to see which)"),
        "{}",
        quiet.out
    );
    assert!(!quiet.out.contains("escaped"), "{}", quiet.out);
    // Only the safe item is there. Nothing is in the folder around the destination, or
    // above it.
    assert_eq!(
        tree(&destination),
        [("ok/file.txt".to_string(), b"fine".to_vec())]
    );
    let after: Vec<_> = fs::read_dir(&parent)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(before.len() + 1, after.len());
    for name in ["escaped.txt", "b.txt", "dot.txt"] {
        assert!(!parent.join(name).exists());
        assert!(!dir.0.join(name).exists());
    }
    assert!(!Path::new("/absolute.txt").exists());
    // With -v the names are shown, with the reason.
    let verbose = restore(&made, &dir.0.join("out2"), &dir, &["-v"]);
    assert!(
        verbose
            .out
            .contains("../escaped.txt: the name is not a safe path"),
        "{}",
        verbose.out
    );
}

#[test]
fn only_the_items_of_a_path_are_restored() {
    let dir = TempDir::new("path");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "docs/a.txt", b"a");
    write(&folder, "docs/deep/b.txt", b"b");
    write(&folder, "docs-old/c.txt", b"c");
    write(&folder, "top.txt", b"t");
    backup(&made, &folder, &dir, &[]);

    let folder_only = dir.0.join("one");
    let outcome = restore(&made, &folder_only, &dir, &["--path", "docs/"]);
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert_eq!(
        tree(&folder_only),
        [
            ("docs/a.txt".to_string(), b"a".to_vec()),
            ("docs/deep/b.txt".to_string(), b"b".to_vec())
        ]
    );
    let single = dir.0.join("two");
    assert!(restore(&made, &single, &dir, &["--path", "top.txt"]).succeeded());
    assert_eq!(tree(&single), [("top.txt".to_string(), b"t".to_vec())]);

    let none = restore(
        &made,
        &dir.0.join("three"),
        &dir,
        &["--path", "nothing/here"],
    );
    assert!(none.failed());
    assert!(none.err.contains("no item has that path"), "{}", none.err);
    assert!(!dir.0.join("three").exists());
    for bad in ["", "..", "a/../b", "a//b"] {
        let outcome = restore(&made, &dir.0.join("four"), &dir, &["--path", bad]);
        assert!(outcome.failed(), "{bad:?}");
        assert!(outcome.err.contains("a path has parts"), "{}", outcome.err);
    }
}

#[test]
fn the_source_is_chosen_by_name_by_id_or_because_it_is_the_only_one() {
    let dir = TempDir::new("choice");
    let made = init(&dir, "vault");
    let none = restore(&made, &dir.0.join("out0"), &dir, &[]);
    assert!(none.failed());
    assert!(
        none.err.contains("the vault has no sources"),
        "{}",
        none.err
    );
    assert!(!dir.0.join("out0").exists());

    let one = sync_items(&made, "one", vec![(b"a.txt", b"from one")]);
    // The only source is the one that is restored.
    let single = dir.0.join("out1");
    assert!(restore(&made, &single, &dir, &[]).succeeded());
    assert_eq!(tree(&single), [("a.txt".to_string(), b"from one".to_vec())]);

    sync_items(&made, "two", vec![(b"b.txt", b"from two")]);
    let unclear = restore(&made, &dir.0.join("out2"), &dir, &[]);
    assert!(unclear.failed());
    assert!(
        unclear.err.contains("the vault has 2 sources"),
        "{}",
        unclear.err
    );
    assert!(!dir.0.join("out2").exists());

    let by_name = dir.0.join("out3");
    assert!(restore(&made, &by_name, &dir, &["--name", "two"]).succeeded());
    assert_eq!(
        tree(&by_name),
        [("b.txt".to_string(), b"from two".to_vec())]
    );
    let by_id = dir.0.join("out4");
    assert!(restore(&made, &by_id, &dir, &["--source-id", &one.to_string()]).succeeded());
    assert_eq!(tree(&by_id), [("a.txt".to_string(), b"from one".to_vec())]);
    let unknown = restore(&made, &dir.0.join("out5"), &dir, &["--name", "three"]);
    assert!(unknown.failed());
    assert!(unknown.err.contains("no source"), "{}", unknown.err);
}

#[test]
fn the_destination_must_be_usable_and_not_in_the_vault() {
    let dir = TempDir::new("destination");
    let made = init(&dir, "vault");
    sync_items(&made, "s", vec![(b"a.txt", b"a")]);

    // A file is not a folder.
    let file = dir.0.join("a-file");
    fs::write(&file, b"x").unwrap();
    let outcome = restore(&made, &file, &dir, &[]);
    assert!(outcome.failed());
    assert!(outcome.err.contains("cannot be used"), "{}", outcome.err);
    assert!(!outcome.err.contains("a-file"), "{}", outcome.err);

    // The vault is not a place to restore into.
    let inside = made.vault.join("restored");
    let outcome = restore(&made, &inside, &dir, &[]);
    assert!(outcome.failed());
    assert!(outcome.err.contains("inside the vault"), "{}", outcome.err);
    assert!(
        fs::read_dir(&made.vault)
            .unwrap()
            .all(|e| e.unwrap().file_name() != "a.txt")
    );
}

#[test]
fn a_wrong_phrase_restores_nothing_and_makes_no_folder() {
    let dir = TempDir::new("wrongphrase");
    let made = init(&dir, "vault");
    sync_items(&made, "s", vec![(b"a.txt", b"a")]);
    let other = init(&dir, "other");
    let destination = dir.0.join("out");
    let outcome = restore_with_input(&made, &destination, &dir, &[], &other.phrase);
    assert!(outcome.failed());
    assert!(
        outcome.err.contains("not the phrase of this vault"),
        "{}",
        outcome.err
    );
    assert!(!destination.exists());
    // No phrase at all.
    let none = restore_with_input(&made, &destination, &dir, &[], "");
    assert!(none.failed());
    assert!(!destination.exists());
}

#[test]
fn a_damaged_chunk_fails_that_file_and_leaves_no_partial_file() {
    let dir = TempDir::new("damage");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "good.txt", b"good");
    write(&folder, "victim.bin", &big(5));
    backup(&made, &folder, &dir, &[]);

    // Flip a byte inside a chunk of the big file: its first chunk is the largest chunk.
    let target = FsTarget::new(&made.vault);
    let vault = block_on(Vault::open(&target, &made.seed)).unwrap();
    let index = block_on(vault.scan_packs()).unwrap();
    let (pack, entry) = index
        .packs()
        .flat_map(|pack| pack.table().entries.iter().map(move |e| (pack, e.clone())))
        .filter(|(_, e)| e.object_type == 1)
        .max_by_key(|(_, e)| e.packed_size)
        .map(|(pack, e)| (*pack.name(), e))
        .unwrap();
    let path: PathBuf = made.vault.join(pack_path(&pack));
    let mut bytes = fs::read(&path).unwrap();
    bytes[entry.offset as usize + 100] ^= 1;
    fs::write(&path, bytes).unwrap();

    let destination = dir.0.join("out");
    let outcome = restore(&made, &destination, &dir, &["-v"]);
    assert!(outcome.exited_with(3), "{} {}", outcome.out, outcome.err);
    assert!(outcome.out.contains("Restored 1 item"), "{}", outcome.out);
    assert!(
        outcome
            .out
            .contains("victim.bin: the content cannot be read from the vault, or it is damaged"),
        "{}",
        outcome.out
    );
    // The good file is there. The damaged one is not there at all, not even a part of it, and
    // no temporary file stays.
    assert_eq!(
        tree(&destination),
        [("good.txt".to_string(), b"good".to_vec())]
    );
}

#[test]
fn the_program_restores_as_a_process_with_the_phrase_on_its_input() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = TempDir::new("process");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "docs/a.txt", b"alpha");
    backup(&made, &folder, &dir, &[]);
    let destination = dir.0.join("out");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_nilperit"))
        .arg("restore")
        .arg(&destination)
        .arg("--vault")
        .arg(&made.vault)
        .env("XDG_CONFIG_HOME", dir.0.join("config"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\n", made.phrase).as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        tree(&destination),
        [("docs/a.txt".to_string(), b"alpha".to_vec())]
    );
}
