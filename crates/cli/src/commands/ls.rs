//! `nilperit ls`: list the sources of a vault, or the items of one source.
//!
//! This reads item records, which only the read key opens, so it needs the recovery
//! phrase. Names are shown: this is direct output to the person, and a list of what is in
//! the vault is useless without them (AGENTS.md).

use crate::cli::LsArgs;
use crate::display::{size, time};
use crate::environment::Environment;
use crate::error::CliError;
use crate::exec::block_on;
use crate::phrase::read_seed;
use nilperit_format::SourceId;
use nilperit_reader::{Snapshots, Vault, VaultError};
use nilperit_target_fs::FsTarget;
use nilperit_writer::{Credential, source_id};
use std::io::{BufRead, Write};
use std::process::ExitCode;

/// The exit code of a run that could list, and found that part of the vault is damaged or
/// cannot be read. The same code as `sync` has for a run with warnings.
const EXIT_WITH_WARNINGS: u8 = 3;

pub fn run(
    args: &LsArgs,
    env: &Environment,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode, CliError> {
    // Check the arguments before the person types the phrase.
    let by_id = args.source_id.as_deref().map(parse_source_id).transpose()?;

    let seed = read_seed(args.phrase.phrase_file.as_deref(), env, stdin)?;
    let vault =
        block_on(Vault::open(FsTarget::new(&args.vault), &seed)).map_err(CliError::Vault)?;
    let index = block_on(vault.scan_packs()).map_err(|e| CliError::Vault(VaultError::Target(e)))?;
    let snapshots =
        block_on(vault.read_snapshots()).map_err(|e| CliError::Vault(VaultError::Target(e)))?;
    let mut warnings = Warnings {
        packs: index.skipped().len(),
        snapshots: snapshots.skipped().len(),
        unreadable: 0,
    };

    let selected = match (&args.name, by_id) {
        (Some(name), _) => {
            Some(source_id(&Credential::from_seed(&seed), name).ok_or(CliError::EmptyName)?)
        }
        (None, id) => id,
    };
    match selected {
        None => sources(out, &vault, &index, &snapshots, &mut warnings)?,
        Some(source) => items(out, &vault, &index, &snapshots, &source, &mut warnings)?,
    }
    out.flush()?;
    warnings.show(err)?;
    Ok(if warnings.any() {
        ExitCode::from(EXIT_WITH_WARNINGS)
    } else {
        ExitCode::SUCCESS
    })
}

/// A source ID is 32 lowercase or capital hexadecimal characters.
fn parse_source_id(text: &str) -> Result<SourceId, CliError> {
    if text.len() != 32 || !text.is_ascii() {
        return Err(CliError::BadSourceId);
    }
    let mut bytes = [0u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| CliError::BadSourceId)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| CliError::BadSourceId)?;
    }
    Ok(SourceId::from_bytes(bytes))
}

/// What was damaged or could not be read. The person is told on the error output.
struct Warnings {
    packs: usize,
    snapshots: usize,
    unreadable: usize,
}

impl Warnings {
    fn any(&self) -> bool {
        self.packs + self.snapshots + self.unreadable > 0
    }

    fn show(&self, err: &mut dyn Write) -> std::io::Result<()> {
        if self.packs > 0 {
            writeln!(
                err,
                "warning: {} {} of the vault could not be opened (damaged or not complete)",
                self.packs,
                if self.packs == 1 { "pack" } else { "packs" }
            )?;
        }
        if self.snapshots > 0 {
            writeln!(
                err,
                "warning: {} {} not used (damaged, or not of this vault)",
                self.snapshots,
                if self.snapshots == 1 {
                    "snapshot header was"
                } else {
                    "snapshot headers were"
                }
            )?;
        }
        if self.unreadable > 0 {
            writeln!(
                err,
                "warning: {} {} could not be read",
                self.unreadable,
                if self.unreadable == 1 {
                    "item"
                } else {
                    "items"
                }
            )?;
        }
        Ok(())
    }
}

/// The overview: each source with its ID, its number of items and the time of its last
/// snapshot. The vault does not keep the names of the sources yet, only their IDs.
fn sources(
    out: &mut dyn Write,
    vault: &Vault<FsTarget>,
    index: &nilperit_reader::PackIndex,
    snapshots: &Snapshots,
    warnings: &mut Warnings,
) -> Result<(), CliError> {
    let ids = snapshots.sources();
    if ids.is_empty() {
        writeln!(out, "The vault has no sources yet.")?;
        return Ok(());
    }
    writeln!(out, "Sources in the vault ({}). Times are UTC.", ids.len())?;
    for id in &ids {
        let Some(head) = snapshots.head(id) else {
            continue;
        };
        match block_on(vault.replay_journal(index, head)) {
            Ok(state) => writeln!(
                out,
                "  {id}  {:>7} items  last snapshot {}",
                state.items.len(),
                time(head.time)
            )?,
            Err(_) => {
                warnings.unreadable += 1;
                writeln!(
                    out,
                    "  {id}  the journal cannot be read  last snapshot {}",
                    time(head.time)
                )?;
            }
        }
    }
    writeln!(
        out,
        "Use --name or --source-id to list the items of a source."
    )?;
    Ok(())
}

/// The items of one source, sorted by name.
fn items(
    out: &mut dyn Write,
    vault: &Vault<FsTarget>,
    index: &nilperit_reader::PackIndex,
    snapshots: &Snapshots,
    source: &SourceId,
    warnings: &mut Warnings,
) -> Result<(), CliError> {
    let head = snapshots.head(source).ok_or(CliError::NoSuchSource)?;
    let state = block_on(vault.replay_journal(index, head)).map_err(CliError::Journal)?;

    // The native ID is bytes and has no order of text. Sort by it.
    let mut rows: Vec<(Vec<u8>, String)> = Vec::new();
    for (key, item) in &state.items {
        match block_on(vault.read_item(index, key, item)) {
            Ok(record) => rows.push((
                record.native_id,
                format!(
                    "{:>10}  {:<16}  {}",
                    size(record.size),
                    record.modified.map_or_else(|| "-".to_string(), time),
                    record.title
                ),
            )),
            Err(_) => {
                warnings.unreadable += 1;
                // The item key is opaque. It is not a name.
                let short = &key.to_string()[..8];
                rows.push((
                    Vec::new(),
                    format!(
                        "{:>10}  {:<16}  (cannot be read: item {short}...)",
                        "?", "?"
                    ),
                ));
            }
        }
    }
    rows.sort();
    writeln!(
        out,
        "{} {} in the source, as of {} UTC.",
        rows.len(),
        if rows.len() == 1 { "item" } else { "items" },
        time(head.time)
    )?;
    for (_, row) in rows {
        writeln!(out, "{row}")?;
    }
    Ok(())
}
