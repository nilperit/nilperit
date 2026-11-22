//! `nilperit sync`, run in the process and as a program. A folder goes into a vault
//! that `nilperit init` made, and the reader reads it back with the recovery phrase.

mod common;

use common::{TempDir, block_on, env, nilperit, phrase, vault_id};
use nilperit_cli::Environment;
use nilperit_crypto::RootSeed;
use nilperit_format::{LockFile, SourceId};
use nilperit_reader::Vault;
use nilperit_reader::layout::LOCK_PATH;
use nilperit_target_fs::FsTarget;
use nilperit_writer::{Credential, source_id};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// A vault that `init` made, with what the person was given.
struct Made {
    vault: std::path::PathBuf,
    seed: RootSeed,
    id: String,
}

fn init(dir: &TempDir, name: &str) -> Made {
    let vault = dir.0.join(name);
    let outcome = nilperit(&["init", vault.to_str().unwrap()], &env(dir));
    assert!(outcome.succeeded(), "{}", outcome.err);
    Made {
        vault,
        seed: RootSeed::from_phrase(&phrase(&outcome.out)).unwrap(),
        id: vault_id(&outcome.out),
    }
}

fn write(root: &Path, path: &str, data: &[u8]) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, data).unwrap();
}

/// What a restore finds in the vault for a source: native ID and bytes of each item.
fn restored(made: &Made, name: &str) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let target = FsTarget::new(&made.vault);
    let vault = block_on(Vault::open(target, &made.seed)).unwrap();
    let index = block_on(vault.scan_packs()).unwrap();
    let snapshots = block_on(vault.read_snapshots()).unwrap();
    let source: SourceId = source_id(&Credential::from_seed(&made.seed), name).unwrap();
    let Some(head) = snapshots.head(&source) else {
        return BTreeMap::new();
    };
    let state = block_on(vault.replay_journal(&index, head)).unwrap();
    let mut files = BTreeMap::new();
    for (key, item) in &state.items {
        let record = block_on(vault.read_item(&index, key, item)).unwrap();
        let mut data = Vec::new();
        for content in &record.content {
            data.extend(block_on(vault.read_content_to_vec(&index, content)).unwrap());
        }
        files.insert(record.native_id, data);
    }
    files
}

fn sync(made: &Made, folder: &Path, env: &Environment, extra: &[&str]) -> common::Outcome {
    let mut args = vec![
        "sync",
        folder.to_str().unwrap(),
        "--vault",
        made.vault.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    nilperit(&args, env)
}

fn big(seed: u8) -> Vec<u8> {
    (0..600_000usize)
        .map(|i| {
            (i as u8)
                .wrapping_mul(11)
                .wrapping_add(seed)
                .wrapping_add((i / 300) as u8)
        })
        .collect()
}

#[test]
fn sync_backs_up_a_folder_and_the_phrase_reads_it_back() {
    let dir = TempDir::new("sync");
    let made = init(&dir, "vault");
    let folder = dir.0.join("photos");
    write(&folder, "a.txt", b"alpha");
    write(&folder, "docs/b.bin", &big(1));
    write(&folder, "docs/deep/c.txt", b"charlie");
    write(&folder, "empty", b"");

    let outcome = sync(&made, &folder, &env(&dir), &[]);
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert!(
        outcome
            .out
            .contains("Items: 4 new, 0 changed, 0 unchanged, 0 deleted."),
        "{}",
        outcome.out
    );
    assert!(outcome.out.contains("1 commit"), "{}", outcome.out);
    assert_eq!(outcome.err, "");

    let name = folder.to_string_lossy().into_owned();
    let files = restored(&made, &name);
    assert_eq!(files.len(), 4);
    assert_eq!(files[&b"a.txt"[..]], b"alpha");
    assert_eq!(files[&b"docs/b.bin"[..]], big(1));
    assert_eq!(files[&b"docs/deep/c.txt"[..]], b"charlie");
    assert_eq!(files[&b"empty"[..]], b"");
}

#[test]
fn a_second_run_says_that_nothing_changed_and_then_shows_what_did() {
    let dir = TempDir::new("again");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "stays", b"stays");
    write(&folder, "changes", b"before");
    write(&folder, "goes", b"goes");
    assert!(sync(&made, &folder, &env(&dir), &[]).succeeded());

    let again = sync(&made, &folder, &env(&dir), &[]);
    assert!(again.succeeded());
    assert_eq!(
        again.out,
        "Nothing changed: 3 items are in the vault already.\n"
    );

    write(&folder, "changes", b"after, longer");
    fs::remove_file(folder.join("goes")).unwrap();
    write(&folder, "new/file", b"new");
    let third = sync(&made, &folder, &env(&dir), &[]);
    assert!(third.succeeded(), "{}", third.err);
    assert!(
        third
            .out
            .contains("Items: 1 new, 1 changed, 1 unchanged, 1 deleted."),
        "{}",
        third.out
    );
    let files = restored(&made, &folder.to_string_lossy());
    let names: Vec<&[u8]> = files.keys().map(Vec::as_slice).collect();
    assert_eq!(names, [&b"changes"[..], b"new/file", b"stays"]);
    assert_eq!(files[&b"changes"[..]], b"after, longer");
}

#[cfg(unix)]
#[test]
fn items_that_cannot_be_read_are_counted_and_named_only_with_v() {
    let dir = TempDir::new("failed");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "fine.txt", b"fine");
    write(&folder, "private-diary.txt", b"x");
    std::os::unix::fs::symlink("fine.txt", folder.join("secret-link-name")).unwrap();

    let quiet = sync(&made, &folder, &env(&dir), &[]);
    // The run finished, and some items could not be read: the exit code is 3.
    assert!(quiet.exited_with(3), "{} {}", quiet.out, quiet.err);
    assert!(
        quiet
            .out
            .contains("1 item could not be read (use -v to see which)"),
        "{}",
        quiet.out
    );
    // No name of the owner is in the output or in the messages.
    for text in [&quiet.out, &quiet.err] {
        assert!(!text.contains("secret-link-name"), "{text}");
        assert!(!text.contains("private-diary"), "{text}");
        assert!(!text.contains("fine.txt"), "{text}");
    }

    let verbose = sync(&made, &folder, &env(&dir), &["-v"]);
    assert!(verbose.exited_with(3));
    assert!(
        verbose.out.contains("secret-link-name: not a regular file"),
        "{}",
        verbose.out
    );
    // The names of the items that were read are not shown, also with -v.
    assert!(!verbose.out.contains("private-diary"), "{}", verbose.out);
    assert!(!verbose.out.contains("fine.txt"), "{}", verbose.out);
}

#[cfg(unix)]
#[test]
fn links_are_followed_on_request() {
    let dir = TempDir::new("links");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    let elsewhere = dir.0.join("elsewhere");
    write(&elsewhere, "report.pdf", b"important");
    write(&folder, "plain", b"plain");
    std::os::unix::fs::symlink(elsewhere.join("report.pdf"), folder.join("report")).unwrap();

    let outcome = sync(&made, &folder, &env(&dir), &["--follow-symlinks"]);
    assert!(outcome.succeeded(), "{} {}", outcome.out, outcome.err);
    let files = restored(&made, &folder.to_string_lossy());
    assert_eq!(files[&b"report"[..]], b"important");
}

#[test]
fn a_name_keeps_the_history_of_a_folder_that_is_moved() {
    let dir = TempDir::new("moved");
    let made = init(&dir, "vault");
    let folder = dir.0.join("old-place");
    write(&folder, "a", b"alpha");
    write(&folder, "b", b"bravo");
    assert!(sync(&made, &folder, &env(&dir), &["--name", "my-photos"]).succeeded());

    let moved = dir.0.join("new-place");
    fs::rename(&folder, &moved).unwrap();
    let same = sync(&made, &moved, &env(&dir), &["--name", "my-photos"]);
    assert_eq!(
        same.out,
        "Nothing changed: 2 items are in the vault already.\n"
    );
    assert_eq!(restored(&made, "my-photos").len(), 2);

    // Without the name, the new path is a new source, and the old one stays.
    let other = sync(&made, &moved, &env(&dir), &[]);
    assert!(other.out.contains("Items: 2 new"), "{}", other.out);
    assert_eq!(restored(&made, &moved.to_string_lossy()).len(), 2);
    assert_eq!(restored(&made, "my-photos").len(), 2);
}

#[test]
fn a_vault_inside_the_folder_does_not_back_itself_up() {
    let dir = TempDir::new("inside");
    let folder = dir.0.join("data");
    write(&folder, "file", b"data");
    let vault = folder.join("my-vault");
    let outcome = nilperit(&["init", vault.to_str().unwrap()], &env(&dir));
    assert!(outcome.succeeded());
    let made = Made {
        vault,
        seed: RootSeed::from_phrase(&phrase(&outcome.out)).unwrap(),
        id: vault_id(&outcome.out),
    };
    assert!(
        sync(&made, &folder, &env(&dir), &[])
            .out
            .contains("Items: 1 new")
    );
    let again = sync(&made, &folder, &env(&dir), &[]);
    assert_eq!(
        again.out,
        "Nothing changed: 1 item is in the vault already.\n"
    );
}

#[test]
fn the_credential_must_be_there_and_must_be_for_this_vault() {
    let dir = TempDir::new("credential");
    let a = init(&dir, "vault-a");
    let b = init(&dir, "vault-b");
    let folder = dir.0.join("data");
    write(&folder, "f", b"f");

    // No credential on this machine: the message says what to do.
    let nowhere = Environment {
        config_dir: Some(dir.0.join("another-config")),
        credential: None,
    };
    let missing = sync(&a, &folder, &nowhere, &[]);
    assert!(missing.failed());
    assert!(missing.err.contains("nilperit init"), "{}", missing.err);
    assert!(missing.err.contains("--credential"), "{}", missing.err);

    // The credential of another vault is refused, and nothing is written.
    let b_file = dir.0.join(format!("config/nilperit/{}.credential", b.id));
    let wrong = sync(
        &a,
        &folder,
        &env(&dir),
        &["--credential", b_file.to_str().unwrap()],
    );
    assert!(wrong.failed());
    assert!(wrong.err.contains("another vault"), "{}", wrong.err);
    assert!(restored(&a, &folder.to_string_lossy()).is_empty());

    // The credential file can be named with the environment, too.
    let from_env = Environment {
        config_dir: None,
        credential: Some(dir.0.join(format!("config/nilperit/{}.credential", a.id))),
    };
    assert!(sync(&a, &folder, &from_env, &[]).succeeded());

    // A credential that other users can read is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = dir.0.join(format!("config/nilperit/{}.credential", a.id));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let open = sync(&a, &folder, &env(&dir), &[]);
        assert!(open.failed());
        assert!(open.err.contains("chmod 600"), "{}", open.err);
        // The message has the path, and no key.
        let text = fs::read_to_string(&file).unwrap();
        let writer_line = text.lines().nth(3).unwrap();
        assert!(!open.err.contains(&writer_line[7..]), "{}", open.err);
    }
}

#[test]
fn a_run_that_holds_the_lock_stops_another_run_and_a_stale_lock_is_taken_over() {
    let dir = TempDir::new("lock");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "f", b"f");

    let lock = |heartbeat: i64| {
        let file = LockFile {
            holder_id: nilperit_format::HolderId::from_bytes([0xaa; 16]),
            heartbeat,
        };
        fs::create_dir_all(made.vault.join("locks")).unwrap();
        fs::write(made.vault.join(LOCK_PATH), file.encode()).unwrap();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Another run is active.
    lock(now - 5_000);
    let busy = sync(&made, &folder, &env(&dir), &[]);
    assert!(busy.failed());
    assert!(
        busy.err.contains("another run has the writer lock"),
        "{}",
        busy.err
    );
    assert!(busy.err.contains("600 s"), "{}", busy.err);
    assert!(restored(&made, &folder.to_string_lossy()).is_empty());
    // The lock of the other run was not touched.
    assert!(made.vault.join(LOCK_PATH).is_file());

    // A run that died long ago: the lock is taken over, and it is freed afterwards.
    lock(now - 3_600_000);
    let taken = sync(&made, &folder, &env(&dir), &[]);
    assert!(taken.succeeded(), "{}", taken.err);
    assert!(!made.vault.join(LOCK_PATH).exists());
}

#[test]
fn the_lock_is_freed_also_when_the_run_fails() {
    let dir = TempDir::new("freed");
    let made = init(&dir, "vault");
    let outcome = sync(&made, &dir.0.join("no-such-folder"), &env(&dir), &[]);
    assert!(outcome.failed());
    assert!(outcome.err.contains("cannot be used"), "{}", outcome.err);
    assert!(!outcome.err.contains("no-such-folder"), "{}", outcome.err);
    assert!(!made.vault.join(LOCK_PATH).exists());
}

#[test]
fn a_folder_without_a_vault_is_an_error() {
    let dir = TempDir::new("novault");
    let folder = dir.0.join("data");
    write(&folder, "f", b"f");
    let nothing = dir.0.join("nothing");
    fs::create_dir_all(&nothing).unwrap();
    let outcome = nilperit(
        &[
            "sync",
            folder.to_str().unwrap(),
            "--vault",
            nothing.to_str().unwrap(),
        ],
        &env(&dir),
    );
    assert!(outcome.failed());
    assert!(outcome.err.contains("no vault"), "{}", outcome.err);
}

#[test]
fn an_empty_name_and_missing_arguments_are_errors() {
    let dir = TempDir::new("args");
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, "f", b"f");
    let empty = sync(&made, &folder, &env(&dir), &["--name", ""]);
    assert!(empty.failed());
    assert!(
        empty.err.contains("name of the source is empty"),
        "{}",
        empty.err
    );

    let no_vault = nilperit(&["sync", folder.to_str().unwrap()], &env(&dir));
    assert!(no_vault.exited_with(2));
    assert!(no_vault.err.contains("--vault"), "{}", no_vault.err);
    let no_folder = nilperit(&["sync"], &env(&dir));
    assert!(no_folder.exited_with(2));
}

#[test]
fn the_program_syncs_as_a_process_and_exits_with_3_for_warnings() {
    let dir = TempDir::new("process");
    let vault = dir.0.join("vault");
    let folder = dir.0.join("data");
    write(&folder, "f", b"f");
    let config = dir.0.join("xdg");
    let program = || {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_nilperit"));
        command
            .env("XDG_CONFIG_HOME", &config)
            .env_remove("NILPERIT_CREDENTIAL");
        command
    };
    let init = program().arg("init").arg(&vault).output().unwrap();
    assert!(init.status.success());

    let run = program()
        .arg("sync")
        .arg(&folder)
        .arg("--vault")
        .arg(&vault)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(String::from_utf8_lossy(&run.stdout).contains("1 new"));

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("f", folder.join("link")).unwrap();
        let warned = program()
            .arg("sync")
            .arg(&folder)
            .arg("--vault")
            .arg(&vault)
            .output()
            .unwrap();
        assert_eq!(warned.status.code(), Some(3));
    }
}
