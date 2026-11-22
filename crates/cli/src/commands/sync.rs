//! `nilperit sync`: back up a folder into a vault.

use super::common::{load_node_credential, now_ms, read_vault_id};
use crate::cli::SyncArgs;
use crate::environment::Environment;
use crate::error::CliError;
use crate::exec::block_on;
use nilperit_connector_fs::{FolderConnector, Symlinks};
use nilperit_crypto::CryptoRng;
use nilperit_target_fs::FsTarget;
use nilperit_writer::{
    FailedItem, LockError, SyncOptions, SyncReport, WriterLock, source_id, sync,
};
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;

/// The time of silence after which a run can take over the writer lock of another run
/// (format.md 8.6.2). A run writes a sign of life at every commit and at every pack, so
/// a run that is working is never this quiet. It must be much longer than the pause of a
/// busy machine and the difference between two clocks (format.md 8.6.5).
const LOCK_STALE_AFTER_MS: i64 = 10 * 60 * 1000;

/// The exit code of a run that finished and could not read some items.
const EXIT_WITH_WARNINGS: u8 = 3;

pub fn run<R: CryptoRng>(
    args: &SyncArgs,
    env: &Environment,
    out: &mut dyn Write,
    rng: &mut R,
) -> Result<ExitCode, CliError> {
    let target = FsTarget::new(&args.vault);
    let vault_id = read_vault_id(&target)?;
    let credential = load_node_credential(args.credential.clone(), env, &vault_id)?;

    let folder = fs::canonicalize(&args.folder).map_err(|e| CliError::Folder(e.kind()))?;
    if !folder.is_dir() {
        return Err(CliError::Folder(io::ErrorKind::InvalidInput));
    }
    // The vault can be inside the folder. The walk leaves it out.
    let vault = fs::canonicalize(&args.vault).map_err(|e| CliError::Folder(e.kind()))?;

    // The name of a source is the full path of the folder, unless the person gave one. The
    // path is changed to text when it is not text (format.md 5.4.5.1).
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| folder.to_string_lossy().into_owned());
    let source = source_id(&credential, &name).ok_or(CliError::EmptyName)?;

    let mut connector =
        FolderConnector::new(&folder)
            .exclude(vault)
            .symlinks(if args.follow_symlinks {
                Symlinks::Follow
            } else {
                Symlinks::Skip
            });

    let started = now_ms();
    let lock = match block_on(WriterLock::acquire(
        &target,
        started,
        LOCK_STALE_AFTER_MS,
        rng,
    )) {
        Ok(lock) => lock,
        Err(LockError::Held { heartbeat, .. }) => {
            let seconds = |ms: i64| u64::try_from(ms.max(0) / 1000).unwrap_or(0);
            return Err(CliError::LockHeld(
                seconds(started - heartbeat),
                seconds(LOCK_STALE_AFTER_MS),
            ));
        }
        Err(e) => return Err(CliError::Lock(e)),
    };
    let result = block_on(sync(
        &lock,
        &credential,
        source,
        &mut connector,
        &SyncOptions::default(),
        now_ms,
        rng,
    ));
    // Free the lock whatever the result was. When this fails, the lock goes stale.
    let _ = block_on(lock.release());
    let report = result?;

    show(out, &report, args.verbose)?;
    Ok(if report.failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_WITH_WARNINGS)
    })
}

/// Shows what the run did. File names are shown only for `-v`, and only for the items that
/// could not be read: a name can say a lot about its owner (AGENTS.md).
fn show(out: &mut dyn Write, report: &SyncReport, verbose: bool) -> io::Result<()> {
    if report.commits == 0 && report.failed.is_empty() {
        let n = report.items_unchanged;
        let (noun, verb) = if n == 1 {
            ("item", "is")
        } else {
            ("items", "are")
        };
        writeln!(
            out,
            "Nothing changed: {n} {noun} {verb} in the vault already."
        )?;
        return out.flush();
    }
    writeln!(
        out,
        "Items: {} new, {} changed, {} unchanged, {} deleted.",
        report.items_new, report.items_changed, report.items_unchanged, report.items_deleted
    )?;
    if report.commits > 0 {
        writeln!(
            out,
            "Read {}, wrote {} in {} {}.",
            size(report.bytes_read),
            size(report.bytes_written),
            report.commits,
            if report.commits == 1 {
                "commit"
            } else {
                "commits"
            },
        )?;
    }
    if !report.failed.is_empty() {
        writeln!(
            out,
            "{} {} could not be read{}. They are not in this snapshot, and what the vault has of them stays.",
            report.failed.len(),
            if report.failed.len() == 1 {
                "item"
            } else {
                "items"
            },
            if verbose {
                ":"
            } else {
                " (use -v to see which)"
            },
        )?;
        if verbose {
            for failed in &report.failed {
                writeln!(
                    out,
                    "  {}: {}",
                    String::from_utf8_lossy(&failed.native_id),
                    why(failed)
                )?;
            }
        }
    }
    out.flush()
}

/// What a failure means for the person.
fn why(failed: &FailedItem) -> String {
    match failed.kind {
        io::ErrorKind::Unsupported => {
            "not a regular file (a link, a socket, a pipe or a device)".into()
        }
        io::ErrorKind::PermissionDenied => "permission denied".into(),
        io::ErrorKind::InvalidInput => "the same name occurs twice".into(),
        io::ErrorKind::Other => {
            "a link that cannot be followed, or a folder that cannot be listed".into()
        }
        kind => format!("{kind:?}"),
    }
}

/// A size in bytes for a person: `1.5 MiB`.
fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_short_for_a_person() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KiB");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(size(3 * 1024 * 1024 * 1024), "3.0 GiB");
        // 2^64 bytes are 2^24 TiB.
        assert_eq!(size(u64::MAX), "16777216.0 TiB");
    }
}
