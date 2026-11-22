//! The progress that the commands show on the error output while they work.
//!
//! The result of a command stays on the output. The progress is only for the person, and it
//! has numbers and fixed words, never a name from the folder.

mod common;

use common::{Made, Outcome, TempDir, env, init, nilperit, nilperit_with_input, write};
use nilperit_cli::{Environment, ProgressMode};
use std::path::Path;
use std::time::Duration;

/// A name that must never be on a line of progress.
const SECRET: &str = "secret-name-of-a-file";

/// An environment that shows a line at every report: the commands are fast, so a real
/// interval would show nothing.
fn showing(dir: &TempDir) -> Environment {
    Environment {
        progress: ProgressMode::Heartbeat(Duration::ZERO),
        ..env(dir)
    }
}

fn big() -> Vec<u8> {
    (0..600_000usize)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add((i / 300) as u8))
        .collect()
}

fn filled(name: &str) -> (TempDir, Made, std::path::PathBuf) {
    let dir = TempDir::new(name);
    let made = init(&dir, "vault");
    let folder = dir.0.join("data");
    write(&folder, &format!("{SECRET}.txt"), b"alpha");
    write(&folder, "docs/big.bin", &big());
    write(&folder, "docs/deep/c.txt", b"charlie");
    (dir, made, folder)
}

fn sync(made: &Made, folder: &Path, env: &Environment) -> Outcome {
    nilperit(
        &[
            "sync",
            folder.to_str().unwrap(),
            "--vault",
            made.vault.to_str().unwrap(),
        ],
        env,
    )
}

#[test]
fn sync_tells_what_it_does_and_how_far_it_is() {
    let (dir, made, folder) = filled("progress-sync");
    let outcome = sync(&made, &folder, &showing(&dir));
    assert!(outcome.succeeded(), "{}", outcome.err);

    // The result is on the output, and the progress is not.
    assert!(outcome.out.contains("Items: 3 new"), "{}", outcome.out);
    assert!(!outcome.out.contains("Backing up"), "{}", outcome.out);

    // The steps, in the order of the run.
    let steps: Vec<&str> = outcome.err.lines().collect();
    let position = |text: &str| steps.iter().position(|line| line.starts_with(text));
    let opening = position("Opening the vault").expect(&outcome.err);
    let listing = position("Listing the folder").expect(&outcome.err);
    let backing_up = position("Backing up: ").expect(&outcome.err);
    assert!(opening < listing && listing < backing_up, "{}", outcome.err);

    // The size of the folder is known before the files are read, so there is a percentage.
    let total = 5 + 600_000 + 7;
    assert!(
        outcome.err.contains(&format!(
            "Backing up: 0 / 3 items, 0 B / {}, 0%",
            // 600012 bytes.
            size_text(total)
        )),
        "{}",
        outcome.err
    );
    // And it ends at the total.
    let last = outcome
        .err
        .lines()
        .rfind(|line| line.starts_with("Backing up: ") || line.starts_with("Writing"))
        .unwrap();
    assert!(
        last.contains("3 / 3 items") && last.contains("100%"),
        "{last}"
    );
}

/// The size as the program shows it, for the sizes of this test.
fn size_text(bytes: u64) -> String {
    format!("{:.1} KiB", bytes as f64 / 1024.0)
}

#[test]
fn a_file_name_is_never_on_a_line_of_progress() {
    let (dir, made, folder) = filled("progress-names");
    let outcome = sync(&made, &folder, &showing(&dir));
    assert!(outcome.succeeded());
    assert!(!outcome.err.contains(SECRET), "{}", outcome.err);
    assert!(!outcome.err.contains("big.bin"), "{}", outcome.err);
    assert!(!outcome.err.contains("docs"), "{}", outcome.err);
}

#[test]
fn a_run_that_ends_quickly_shows_nothing_on_a_terminal() {
    let (dir, made, folder) = filled("progress-quick");
    let live = Environment {
        progress: ProgressMode::Live,
        ..env(&dir)
    };
    let outcome = sync(&made, &folder, &live);
    assert!(outcome.succeeded());
    // No line, and no control character that a terminal would act on.
    assert_eq!(outcome.err, "");
}

#[test]
fn without_progress_the_error_output_is_empty() {
    let (dir, made, folder) = filled("progress-off");
    let outcome = sync(&made, &folder, &env(&dir));
    assert!(outcome.succeeded());
    assert_eq!(outcome.err, "");
}

#[test]
fn a_second_run_with_nothing_new_still_reads_the_journal() {
    let (dir, made, folder) = filled("progress-again");
    assert!(sync(&made, &folder, &env(&dir)).succeeded());
    let outcome = sync(&made, &folder, &showing(&dir));
    assert!(outcome.succeeded());
    assert!(outcome.out.contains("Nothing changed"), "{}", outcome.out);
    assert!(
        outcome.err.contains("Reading the journal..."),
        "{}",
        outcome.err
    );
    // The run reads the files again to compare them: the progress shows that too.
    assert!(outcome.err.contains("3 / 3 items"), "{}", outcome.err);
}

#[test]
fn ls_tells_how_far_it_is_in_the_items() {
    let (dir, made, folder) = filled("progress-ls");
    assert!(sync(&made, &folder, &env(&dir)).succeeded());
    let outcome = nilperit_with_input(
        &[
            "ls",
            "--vault",
            made.vault.to_str().unwrap(),
            "--name",
            folder.to_str().unwrap(),
        ],
        &showing(&dir),
        &made.phrase,
    );
    assert!(outcome.succeeded(), "{}", outcome.err);
    // The list has the names. The progress has not.
    assert!(outcome.out.contains(SECRET), "{}", outcome.out);
    assert!(!outcome.out.contains("Reading"), "{}", outcome.out);
    for step in [
        "Opening the vault",
        "Reading the packs",
        "Reading the snapshots",
        "Reading the journal",
        "Reading the items: 2 / 3 items, 66%",
    ] {
        assert!(outcome.err.contains(step), "{step}\n{}", outcome.err);
    }
    assert!(!outcome.err.contains(SECRET), "{}", outcome.err);
}

#[test]
fn ls_of_the_overview_tells_how_far_it_is_in_the_sources() {
    let (dir, made, folder) = filled("progress-ls-sources");
    assert!(sync(&made, &folder, &env(&dir)).succeeded());
    let outcome = nilperit_with_input(
        &["ls", "--vault", made.vault.to_str().unwrap()],
        &showing(&dir),
        &made.phrase,
    );
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert!(
        outcome.err.contains("Reading the sources: 0 / 1 items, 0%"),
        "{}",
        outcome.err
    );
}

#[test]
fn restore_tells_how_many_files_and_bytes_it_has_written() {
    let (dir, made, folder) = filled("progress-restore");
    assert!(sync(&made, &folder, &env(&dir)).succeeded());
    let destination = dir.0.join("restored");
    let outcome = nilperit_with_input(
        &[
            "restore",
            destination.to_str().unwrap(),
            "--vault",
            made.vault.to_str().unwrap(),
        ],
        &showing(&dir),
        &made.phrase,
    );
    assert!(outcome.succeeded(), "{}", outcome.err);
    assert!(outcome.out.contains("Restored 3 items"), "{}", outcome.out);
    assert!(!outcome.out.contains("Restoring"), "{}", outcome.out);
    assert!(
        outcome.err.contains(&format!(
            "Restoring: 0 / 3 items, 0 B / {}, 0%",
            size_text(5 + 600_000 + 7)
        )),
        "{}",
        outcome.err
    );
    let last = outcome
        .err
        .lines()
        .rfind(|line| line.starts_with("Restoring: "))
        .unwrap();
    assert!(
        last.contains("3 / 3 items") && last.ends_with("100%"),
        "{last}"
    );
    // The big file is reported while it is written: there are lines with bytes of the file
    // before the first item is finished.
    let inside = outcome
        .err
        .lines()
        .filter(|line| line.starts_with("Restoring: 0 / 3 items") && !line.contains(" 0 B /"))
        .count();
    assert!(inside >= 2, "{}", outcome.err);
    assert!(!outcome.err.contains(SECRET), "{}", outcome.err);
}

#[test]
fn an_error_after_a_line_of_progress_starts_on_a_clean_line() {
    let (dir, made, folder) = filled("progress-error");
    assert!(sync(&made, &folder, &env(&dir)).succeeded());
    // The wrong phrase: the error comes after the first step, on a line of its own.
    let outcome = nilperit_with_input(
        &["ls", "--vault", made.vault.to_str().unwrap()],
        &showing(&dir),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    );
    assert!(outcome.failed());
    assert!(outcome.err.ends_with('\n'), "{}", outcome.err);
    let last = outcome.err.lines().last().unwrap();
    assert!(last.starts_with("error: "), "{}", outcome.err);
    assert!(!outcome.err.contains('\r'), "{}", outcome.err);
}
