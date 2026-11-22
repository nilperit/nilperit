//! `nilperit init`, run in the process and as a program.

mod common;

use common::{Outcome, TempDir, block_on, env, nilperit, phrase, vault_id};
use nilperit_cli::Environment;
use nilperit_cli::credential::load_credential;
use nilperit_crypto::RootSeed;
use nilperit_reader::Vault;
use nilperit_target_fs::FsTarget;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn success(outcome: &Outcome) -> bool {
    outcome.code == ExitCode::SUCCESS
}

fn failure(outcome: &Outcome) -> bool {
    outcome.code == ExitCode::FAILURE
}

fn all_files(path: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                all_files(&entry.path(), files);
            } else {
                files.push(entry.path());
            }
        }
    }
}

#[test]
fn init_makes_a_vault_that_the_phrase_opens_and_a_credential_for_this_machine() {
    let dir = TempDir::new("init");
    let vault = dir.0.join("vault");
    let outcome = nilperit(&["init", vault.to_str().unwrap()], &env(&dir));
    assert!(success(&outcome), "{}", outcome.err);
    assert_eq!(outcome.err, "");

    // The 24 words open the vault.
    let seed = RootSeed::from_phrase(&phrase(&outcome.out)).unwrap();
    let opened = block_on(Vault::open(FsTarget::new(&vault), &seed)).unwrap();
    assert_eq!(
        opened.config().essentials.vault_id.to_string(),
        vault_id(&outcome.out)
    );

    // The credential is in the configuration folder, named after the vault.
    let credential = dir
        .0
        .join("config/nilperit")
        .join(format!("{}.credential", vault_id(&outcome.out)));
    assert!(outcome.out.contains(credential.to_str().unwrap()));
    let (id, node) = load_credential(&credential).unwrap();
    assert_eq!(id, opened.config().essentials.vault_id);
    // A node opens the vault with it, and cannot read an R object.
    let keys = node.reader_keys();
    assert!(keys.read().is_none());
    let as_node = block_on(Vault::open_with(FsTarget::new(&vault), keys)).unwrap();
    assert_eq!(as_node.config().essentials.vault_id, id);
}

#[test]
fn init_names_the_credential_file_when_asked() {
    let dir = TempDir::new("named");
    let vault = dir.0.join("vault");
    let file = dir.0.join("some/folder/node.credential");
    let outcome = nilperit(
        &[
            "init",
            vault.to_str().unwrap(),
            "--credential",
            file.to_str().unwrap(),
        ],
        &Environment::default(),
    );
    assert!(success(&outcome), "{}", outcome.err);
    assert!(load_credential(&file).is_ok());

    // The environment can name it too. The option is stronger.
    let second = dir.0.join("vault2");
    let from_env = dir.0.join("from-env.credential");
    let env = Environment {
        config_dir: None,
        credential: Some(from_env.clone()),
        ..Environment::default()
    };
    assert!(success(&nilperit(
        &["init", second.to_str().unwrap()],
        &env
    )));
    assert!(load_credential(&from_env).is_ok());
}

#[test]
fn nothing_secret_is_written_but_the_credential() {
    let dir = TempDir::new("secret");
    let vault = dir.0.join("vault");
    let outcome = nilperit(&["init", vault.to_str().unwrap()], &env(&dir));
    assert!(success(&outcome));
    let phrase = phrase(&outcome.out);
    let seed = RootSeed::from_phrase(&phrase).unwrap();
    let mut files = Vec::new();
    all_files(&dir.0, &mut files);
    assert!(files.len() >= 3, "{files:?}");
    for file in files {
        let bytes = fs::read(&file).unwrap();
        let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        // Neither the words, nor the first word, nor the bytes of the seed.
        assert!(!contains(phrase.as_bytes()), "{file:?}");
        assert!(!contains(seed.as_bytes()), "{file:?}");
    }
    // The program does not show the keys of the node.
    let (_, node) = load_credential(
        &dir.0
            .join("config/nilperit")
            .join(format!("{}.credential", vault_id(&outcome.out))),
    )
    .unwrap();
    let writer: String = node
        .writer()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(!outcome.out.contains(&writer));
}

#[test]
fn init_checks_everything_before_it_shows_the_phrase() {
    let dir = TempDir::new("checks");
    let vault = dir.0.join("vault");
    let first = nilperit(&["init", vault.to_str().unwrap()], &env(&dir));
    assert!(success(&first));
    let credential = dir
        .0
        .join("config/nilperit")
        .join(format!("{}.credential", vault_id(&first.out)));
    let before = fs::read(&credential).unwrap();

    // A vault that exists: no phrase, no change.
    let second = nilperit(&["init", vault.to_str().unwrap()], &env(&dir));
    assert!(failure(&second));
    assert!(second.out.is_empty(), "{}", second.out);
    assert!(second.err.starts_with("error: "), "{}", second.err);
    assert_eq!(fs::read(&credential).unwrap(), before);

    // A credential file that exists: no phrase, and no vault is made.
    let other = dir.0.join("other-vault");
    let taken = dir.0.join("taken.credential");
    fs::write(&taken, b"mine").unwrap();
    let third = nilperit(
        &[
            "init",
            other.to_str().unwrap(),
            "--credential",
            taken.to_str().unwrap(),
        ],
        &env(&dir),
    );
    assert!(failure(&third));
    assert!(third.out.is_empty(), "{}", third.out);
    assert!(!other.exists());
    assert_eq!(fs::read(&taken).unwrap(), b"mine");

    // No configuration folder and no file named: no phrase, and no vault.
    let fourth = nilperit(&["init", other.to_str().unwrap()], &Environment::default());
    assert!(failure(&fourth));
    assert!(fourth.out.is_empty(), "{}", fourth.out);
    assert!(fourth.err.contains("--credential"), "{}", fourth.err);
    assert!(!other.exists());
}

#[test]
fn each_vault_has_its_own_phrase_and_credential() {
    let dir = TempDir::new("two");
    let a = nilperit(&["init", dir.0.join("a").to_str().unwrap()], &env(&dir));
    let b = nilperit(&["init", dir.0.join("b").to_str().unwrap()], &env(&dir));
    assert!(success(&a) && success(&b));
    assert_ne!(phrase(&a.out), phrase(&b.out));
    assert_ne!(vault_id(&a.out), vault_id(&b.out));
    let credentials = fs::read_dir(dir.0.join("config/nilperit")).unwrap().count();
    assert_eq!(credentials, 2);
}

#[test]
fn wrong_arguments_are_a_usage_error() {
    let env = Environment::default();
    let none = nilperit(&[], &env);
    assert_eq!(none.code, ExitCode::from(2));
    assert!(none.err.contains("Usage"), "{}", none.err);
    let unknown = nilperit(&["frobnicate"], &env);
    assert_eq!(unknown.code, ExitCode::from(2));
    let missing = nilperit(&["init"], &env);
    assert_eq!(missing.code, ExitCode::from(2));
    let flag = nilperit(&["init", "v", "--no-such-flag"], &env);
    assert_eq!(flag.code, ExitCode::from(2));
    assert!(flag.out.is_empty());
}

#[test]
fn help_and_version_succeed() {
    let env = Environment::default();
    let help = nilperit(&["--help"], &env);
    assert!(success(&help));
    assert!(help.out.contains("init"), "{}", help.out);
    let init_help = nilperit(&["init", "--help"], &env);
    assert!(success(&init_help));
    assert!(init_help.out.contains("--credential"), "{}", init_help.out);
    let version = nilperit(&["--version"], &env);
    assert!(success(&version));
    assert!(version.out.starts_with("nilperit "), "{}", version.out);
}

/// The program itself, started as a process, with the environment of a user.
#[test]
fn the_program_runs_as_a_process() {
    let dir = TempDir::new("process");
    let vault = dir.0.join("vault");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nilperit"))
        .arg("init")
        .arg(&vault)
        .env_remove("NILPERIT_CREDENTIAL")
        .env("XDG_CONFIG_HOME", dir.0.join("xdg"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8(output.stdout).unwrap();
    let seed = RootSeed::from_phrase(&phrase(&out)).unwrap();
    assert!(block_on(Vault::open(FsTarget::new(&vault), &seed)).is_ok());
    assert!(
        dir.0
            .join("xdg/nilperit")
            .join(format!("{}.credential", vault_id(&out)))
            .is_file()
    );

    // Run again: an error, exit status 1, and a message.
    let again = std::process::Command::new(env!("CARGO_BIN_EXE_nilperit"))
        .arg("init")
        .arg(&vault)
        .env("XDG_CONFIG_HOME", dir.0.join("xdg"))
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(1));
    assert!(again.stdout.is_empty());
}
