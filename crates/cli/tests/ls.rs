//! `nilperit ls`: the sources of a vault and the items of a source, with the recovery
//! phrase from the input or from a file.

mod common;

use common::{Made, TempDir, block_on, env, init, nilperit, nilperit_with_input, write};
use nilperit_format::SourceId;
use nilperit_reader::Vault;
use nilperit_reader::layout::pack_path;
use nilperit_target_fs::FsTarget;
use nilperit_writer::{Credential, source_id};
use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

fn sync(made: &Made, folder: &Path, dir: &TempDir) -> common::Outcome {
    nilperit(
        &[
            "sync",
            folder.to_str().unwrap(),
            "--vault",
            made.vault.to_str().unwrap(),
        ],
        &env(dir),
    )
}

fn ls(made: &Made, dir: &TempDir, extra: &[&str], input: &str) -> common::Outcome {
    let mut args = vec!["ls", "--vault", made.vault.to_str().unwrap()];
    args.extend_from_slice(extra);
    nilperit_with_input(&args, &env(dir), input)
}

fn id_of(made: &Made, name: &str) -> SourceId {
    source_id(&Credential::from_seed(&made.seed), name).unwrap()
}

/// Sets the modification time of a file to a time in seconds since 1970.
fn set_time(path: &Path, seconds: u64) {
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

/// A vault with one source that has a few files.
fn filled(name: &str) -> (TempDir, Made, std::path::PathBuf) {
    let dir = TempDir::new(name);
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "b.txt", b"bravo");
    write(&folder, "a.txt", &vec![1u8; 1500]);
    write(&folder, "a/z.txt", b"zulu");
    set_time(&folder.join("b.txt"), 1_700_000_000);
    let synced = sync(&made, &folder, &dir);
    assert!(synced.succeeded(), "{}", synced.err);
    (dir, made, folder)
}

#[test]
fn the_overview_shows_each_source_with_its_id_its_items_and_its_last_snapshot() {
    let (dir, made, folder) = filled("overview");
    let outcome = ls(&made, &dir, &[], &format!("{}\n", made.phrase));
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert_eq!(outcome.err, "");
    let id = id_of(&made, &folder.to_string_lossy());
    assert!(
        outcome
            .out
            .contains("Sources in the vault (1). Times are UTC."),
        "{}",
        outcome.out
    );
    assert!(outcome.out.contains(&format!("{id}")), "{}", outcome.out);
    assert!(outcome.out.contains("3 items"), "{}", outcome.out);
    let line = outcome
        .out
        .lines()
        .find(|l| l.contains(&format!("{id}")))
        .unwrap();
    // The time of the last snapshot is a date and a time.
    let time = line.split("last snapshot ").nth(1).unwrap();
    assert_eq!(time.len(), "2023-11-14 22:13".len(), "{line}");
    assert!(
        outcome.out.contains("Use --name or --source-id"),
        "{}",
        outcome.out
    );
    // The phrase is not shown again.
    assert!(!outcome.out.contains(&made.phrase));
    // No file name is in the overview.
    assert!(!outcome.out.contains("a.txt"), "{}", outcome.out);
}

#[test]
fn a_vault_without_sources_says_so() {
    let dir = TempDir::new("empty");
    let made = init(&dir, "vault");
    let outcome = ls(&made, &dir, &[], &made.phrase);
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert_eq!(outcome.out, "The vault has no sources yet.\n");
}

#[test]
fn the_items_of_a_source_are_listed_sorted_with_size_and_time() {
    let (dir, made, folder) = filled("items");
    let name = folder.to_string_lossy().into_owned();
    let outcome = ls(&made, &dir, &["--name", &name], &made.phrase);
    assert!(outcome.succeeded(), "{}", outcome.err);
    let lines: Vec<&str> = outcome.out.lines().collect();
    assert!(
        lines[0].starts_with("3 items in the source, as of "),
        "{}",
        lines[0]
    );
    // Sorted by the bytes of the name: `a.txt`, then `a/z.txt` (the dot is before the
    // slash), then `b.txt`.
    assert!(lines[1].ends_with("  a.txt"), "{}", lines[1]);
    assert!(lines[2].ends_with("  a/z.txt"), "{}", lines[2]);
    assert!(lines[3].ends_with("  b.txt"), "{}", lines[3]);
    assert!(lines[1].contains("1.5 KiB"), "{}", lines[1]);
    assert!(lines[2].contains("4 B"), "{}", lines[2]);
    // The time that the file has: 1700000000 is 2023-11-14 22:13 in UTC.
    assert!(lines[3].contains("5 B"), "{}", lines[3]);
    assert!(lines[3].contains("2023-11-14 22:13"), "{}", lines[3]);

    // The ID selects the same source, in small or capital letters.
    let id = id_of(&made, &name).to_string();
    for text in [id.clone(), id.to_uppercase()] {
        let by_id = ls(&made, &dir, &["--source-id", &text], &made.phrase);
        assert_eq!(by_id.out, outcome.out);
    }
}

#[test]
fn a_source_that_the_vault_does_not_have_and_bad_arguments_are_errors() {
    let (dir, made, _) = filled("errors");
    let unknown = ls(&made, &dir, &["--name", "nothing here"], &made.phrase);
    assert!(unknown.failed());
    assert!(unknown.err.contains("no source"), "{}", unknown.err);
    let empty = ls(&made, &dir, &["--name", ""], &made.phrase);
    assert!(empty.failed());
    // A bad ID is found before the phrase is read: the input is empty, and the error is
    // about the ID.
    for bad in [
        "zz",
        "abc",
        &"g".repeat(32),
        &"é".repeat(16),
        &"0".repeat(33),
    ] {
        let outcome = ls(&made, &dir, &["--source-id", bad], "");
        assert!(outcome.failed(), "{bad}");
        assert!(outcome.err.contains("32 hexadecimal"), "{}", outcome.err);
    }
    // Two ways to name the source are a usage error.
    let both = ls(
        &made,
        &dir,
        &["--name", "x", "--source-id", &"0".repeat(32)],
        &made.phrase,
    );
    assert!(both.exited_with(2));
    let no_vault = nilperit(&["ls"], &env(&dir));
    assert!(no_vault.exited_with(2));
}

#[test]
fn the_phrase_can_be_typed_loosely_and_must_be_the_right_one() {
    let (dir, made, _) = filled("phrase");
    // Capitals, line breaks, carriage returns and extra spaces do not matter.
    let loose = format!(
        "  {}\r\n\r\n",
        made.phrase.to_uppercase().replace(' ', "  \r\n")
    );
    assert!(ls(&made, &dir, &[], &loose).succeeded());

    // The phrase of another vault: the vault does not open, and the error says why.
    let other = init(&dir, "other-vault");
    let wrong = ls(&made, &dir, &[], &other.phrase);
    assert!(wrong.failed());
    assert!(
        wrong.err.contains("not the phrase of this vault"),
        "{}",
        wrong.err
    );
    assert!(wrong.out.is_empty());

    // No input at all, text that is not a phrase, and a phrase with a word changed.
    let none = ls(&made, &dir, &[], "");
    assert!(none.failed());
    assert!(
        none.err.contains("no recovery phrase was given"),
        "{}",
        none.err
    );
    let words: Vec<&str> = made.phrase.split(' ').collect();
    for typed in [
        "hello world".to_string(),
        made.phrase.replacen(words[0], "zzzz", 1),
    ] {
        let outcome = ls(&made, &dir, &[], &typed);
        assert!(outcome.failed());
        assert!(outcome.err.contains("recovery phrase"), "{}", outcome.err);
        // What was typed is not repeated.
        assert!(!outcome.err.contains(words[1]), "{}", outcome.err);
        assert!(!outcome.err.contains("zzzz"), "{}", outcome.err);
    }
}

#[test]
fn the_phrase_can_be_in_a_file_that_only_the_owner_reads() {
    let (dir, made, _) = filled("phrase-file");
    let file = dir.0.join("phrase.txt");
    fs::write(&file, format!("{}\n", made.phrase)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    // The file is used, and the input is not read.
    let outcome = ls(
        &made,
        &dir,
        &["--phrase-file", file.to_str().unwrap()],
        "ignored",
    );
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert!(outcome.out.contains("Sources in the vault (1)"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let open = ls(&made, &dir, &["--phrase-file", file.to_str().unwrap()], "");
        assert!(open.failed());
        assert!(open.err.contains("chmod 600"), "{}", open.err);
        assert!(!open.err.contains(&made.phrase), "{}", open.err);
    }
    let missing = ls(
        &made,
        &dir,
        &["--phrase-file", dir.0.join("nothing").to_str().unwrap()],
        "",
    );
    assert!(missing.failed());
    assert!(missing.err.contains("cannot be read"), "{}", missing.err);
}

#[test]
fn a_folder_that_is_not_a_vault_is_an_error() {
    let dir = TempDir::new("notvault");
    let made = init(&dir, "vault");
    let nothing = dir.0.join("nothing");
    fs::create_dir_all(&nothing).unwrap();
    let outcome = nilperit_with_input(
        &["ls", "--vault", nothing.to_str().unwrap()],
        &env(&dir),
        &made.phrase,
    );
    assert!(outcome.failed());
    assert!(
        outcome.err.contains("no valid vault config"),
        "{}",
        outcome.err
    );
}

#[test]
fn damage_is_reported_and_the_rest_of_the_vault_is_listed() {
    let (dir, made, folder) = filled("damage");
    let name = folder.to_string_lossy().into_owned();

    // Damage one item record: flip a byte inside its packed object. The pack, its table
    // and its footer stay valid, so the other items can still be read.
    let target = FsTarget::new(&made.vault);
    let vault = block_on(Vault::open(&target, &made.seed)).unwrap();
    let index = block_on(vault.scan_packs()).unwrap();
    let (pack, entry) = index
        .packs()
        .find_map(|pack| {
            pack.table()
                .entries
                .iter()
                .find(|e| e.object_type == 4)
                .map(|e| (pack.name(), e.clone()))
        })
        .unwrap();
    let path = made.vault.join(pack_path(pack));
    let mut bytes = fs::read(&path).unwrap();
    bytes[entry.offset as usize + 30] ^= 1;
    fs::write(&path, bytes).unwrap();

    let outcome = ls(&made, &dir, &["--name", &name], &made.phrase);
    assert!(outcome.exited_with(3), "{} {}", outcome.out, outcome.err);
    assert!(
        outcome.out.contains("3 items in the source"),
        "{}",
        outcome.out
    );
    assert_eq!(
        outcome.out.matches("(cannot be read: item ").count(),
        1,
        "{}",
        outcome.out
    );
    assert!(
        outcome.err.contains("1 item could not be read"),
        "{}",
        outcome.err
    );
    // The other two items are listed with their names.
    assert_eq!(
        outcome.out.lines().filter(|l| l.ends_with(".txt")).count(),
        2
    );
}

#[test]
fn a_vault_with_no_pack_that_opens_still_shows_its_sources() {
    let (dir, made, folder) = filled("nopacks");
    // Damage the footer of every pack: none of them opens.
    let mut packs = Vec::new();
    collect(&made.vault.join("packs"), &mut packs);
    assert!(!packs.is_empty());
    for pack in &packs {
        let mut bytes = fs::read(pack).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(pack, bytes).unwrap();
    }

    // The overview needs only the snapshot headers, and says what is wrong.
    let overview = ls(&made, &dir, &[], &made.phrase);
    assert!(overview.exited_with(3), "{} {}", overview.out, overview.err);
    assert!(
        overview.out.contains("the journal cannot be read"),
        "{}",
        overview.out
    );
    assert!(
        overview.err.contains("could not be opened"),
        "{}",
        overview.err
    );

    // The items of the source cannot be listed, and the error says why.
    let name = folder.to_string_lossy().into_owned();
    let items = ls(&made, &dir, &["--name", &name], &made.phrase);
    assert!(items.failed());
    assert!(items.err.contains("journal"), "{}", items.err);
}

fn collect(path: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(path).unwrap().flatten() {
        if entry.path().is_dir() {
            collect(&entry.path(), files);
        } else {
            files.push(entry.path());
        }
    }
}

#[test]
fn the_program_lists_as_a_process_with_the_phrase_on_its_input() {
    use std::io::Write;
    use std::process::Stdio;
    let (dir, made, folder) = filled("process");
    let name = folder.to_string_lossy().into_owned();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_nilperit"))
        .args(["ls", "--vault"])
        .arg(&made.vault)
        .args(["--name", &name])
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
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("3 items in the source"), "{out}");
    assert!(out.contains("a/z.txt"), "{out}");
}
