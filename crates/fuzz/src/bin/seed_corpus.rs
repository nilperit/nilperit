//! Writes the seeds of every check as files, for the corpus of a fuzzer.
//!
//! `cargo run -p nilperit-fuzz --bin seed-corpus -- fuzz/corpus` makes a folder for each check,
//! with one file for each seed. A fuzzer starts from valid input, and so gets past the first
//! checks at once. The files are not kept in the repository: the seeds are made from the encoders
//! and the test vectors, and this program makes them again.

use nilperit_fuzz::checks::TARGETS;
use nilperit_fuzz::seeds::seeds;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(folder) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: seed-corpus <folder>");
        return ExitCode::from(2);
    };
    for (name, _) in TARGETS {
        let target = folder.join(name);
        if let Err(e) = fs::create_dir_all(&target) {
            eprintln!("cannot make the folder of {name}: {e}");
            return ExitCode::FAILURE;
        }
        for (index, seed) in seeds(name).iter().enumerate() {
            // An empty file is not a useful seed.
            if seed.is_empty() {
                continue;
            }
            if let Err(e) = fs::write(target.join(format!("seed-{index:02}")), seed) {
                eprintln!("cannot write a seed of {name}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
