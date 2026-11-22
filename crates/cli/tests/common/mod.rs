//! Helpers that the tests of the commands share.
#![allow(dead_code)]

use nilperit_cli::{Environment, run};
use nilperit_crypto::RootSeed;
use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::process::ExitCode;
use std::task::{Context, Poll, Waker};

pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the future waits"),
    }
}

/// A folder that is removed when it goes out of scope. Its path is a real path.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("nilperit-cli-{name}-{}", std::process::id()));
        restore_permissions(&path);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        restore_permissions(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A test can leave a folder that it made unreadable.
fn restore_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
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
    #[cfg(not(unix))]
    let _ = path;
}

pub struct Outcome {
    pub code: ExitCode,
    pub out: String,
    pub err: String,
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        self.code == ExitCode::SUCCESS
    }

    pub fn failed(&self) -> bool {
        self.code == ExitCode::FAILURE
    }

    pub fn exited_with(&self, code: u8) -> bool {
        self.code == ExitCode::from(code)
    }
}

/// Runs the program in the process, with real randomness and no input.
pub fn nilperit(args: &[&str], env: &Environment) -> Outcome {
    nilperit_with_input(args, env, "")
}

/// Runs the program in the process, with real randomness and this text as its input.
pub fn nilperit_with_input(args: &[&str], env: &Environment, input: &str) -> Outcome {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let code = run(
        std::iter::once("nilperit").chain(args.iter().copied()),
        env,
        &mut std::io::Cursor::new(input.as_bytes()),
        &mut out,
        &mut err,
        &mut rng,
    );
    Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// An environment with a configuration folder in the test folder.
pub fn env(dir: &TempDir) -> Environment {
    Environment {
        config_dir: Some(dir.0.join("config")),
        credential: None,
        ..Environment::default()
    }
}

/// The 24 words that `init` showed, in order.
pub fn phrase(out: &str) -> String {
    let words: Vec<&str> = out
        .lines()
        .filter(|line| line.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .flat_map(|line| {
            line.split_whitespace()
                .filter(|w| !w.chars().all(|c| c.is_ascii_digit()))
        })
        .collect();
    assert_eq!(words.len(), 24, "{out}");
    words.join(" ")
}

/// The vault ID that `init` showed.
pub fn vault_id(out: &str) -> String {
    out.lines()
        .find_map(|l| l.strip_prefix("Vault ID: "))
        .unwrap()
        .to_string()
}

/// A vault that `init` made, with what the person was given.
pub struct Made {
    pub vault: PathBuf,
    pub seed: RootSeed,
    pub phrase: String,
    pub id: String,
}

/// Makes a vault with `init` in the folder `name` of the test folder.
pub fn init(dir: &TempDir, name: &str) -> Made {
    let vault = dir.0.join(name);
    let outcome = nilperit(&["init", vault.to_str().unwrap()], &env(dir));
    assert!(outcome.succeeded(), "{}", outcome.err);
    let phrase = phrase(&outcome.out);
    Made {
        vault,
        seed: RootSeed::from_phrase(&phrase).unwrap(),
        phrase,
        id: vault_id(&outcome.out),
    }
}

/// Writes a file below `root`, with its folders.
pub fn write(root: &std::path::Path, path: &str, data: &[u8]) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, data).unwrap();
}
