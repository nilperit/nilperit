//! The `nilperit` program: a personal backup into an encrypted, versioned,
//! deduplicated vault.
//!
//! The program is a thin layer. It reads the arguments and the keys, calls the
//! libraries (`nilperit-writer`, `nilperit-reader`, `nilperit-target-fs`), and writes
//! what the person needs to see. [`run`] takes everything from outside (arguments,
//! environment, input, output, randomness), so that the tests can run it in the process.
//!
//! Output rules (AGENTS.md): errors never contain keys, the recovery phrase or content.
//! File names appear only as direct output to the person.

mod cli;
mod commands;
pub mod credential;
mod display;
mod environment;
mod error;
mod exec;
mod phrase;
mod secret_file;

pub use environment::Environment;
pub use error::CliError;

use clap::Parser;
use cli::{Cli, Command};
use nilperit_crypto::CryptoRng;
use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::process::ExitCode;

/// Runs the program with the given arguments (the first is the name of the program).
///
/// Normal output goes to `out`, and messages about problems to `err`. The exit code is
/// 0 for success, 1 for an error, 2 for arguments that are not valid, and 3 for a run
/// that finished but could not read some items (see `nilperit sync`).
pub fn run<R: CryptoRng>(
    args: impl IntoIterator<Item = impl Into<OsString> + Clone>,
    env: &Environment,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
    rng: &mut R,
) -> ExitCode {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version go to `out`, a usage error goes to `err`.
            let shown = e.render().to_string();
            let _ = if e.use_stderr() {
                write!(err, "{shown}")
            } else {
                write!(out, "{shown}")
            };
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
        }
    };
    let result = match cli.command {
        Command::Init(args) => {
            commands::init::run(&args, env, out, rng).map(|()| ExitCode::SUCCESS)
        }
        Command::Sync(args) => commands::sync::run(&args, env, out, rng),
        Command::Ls(args) => commands::ls::run(&args, env, stdin, out, err),
        Command::Restore(args) => commands::restore::run(&args, env, stdin, out, err),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(err, "error: {e}");
            ExitCode::FAILURE
        }
    }
}
