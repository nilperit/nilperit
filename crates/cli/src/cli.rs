//! The arguments of the program.
//!
//! Parsing is here and only here: it gives a typed command, and the commands know
//! nothing about the parser.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// A personal backup into an encrypted, versioned, deduplicated vault.
#[derive(Debug, Parser)]
#[command(name = "nilperit", version, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Make a new vault, show its recovery phrase once, and save the credential of this
    /// machine.
    Init(InitArgs),

    /// Back up a folder into a vault. Only what is new or changed is written.
    Sync(SyncArgs),

    /// List the sources of a vault, or the items of one source. This needs the recovery
    /// phrase.
    Ls(LsArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// The folder of the new vault. It must not hold a vault.
    pub vault: PathBuf,

    /// Where to save the node credential. It lets this machine add data to the vault
    /// and cannot read it. The default is a file in the configuration folder, named
    /// after the vault.
    #[arg(long, value_name = "FILE")]
    pub credential: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// The folder to back up.
    pub folder: PathBuf,

    /// The folder of the vault.
    #[arg(long, value_name = "FOLDER")]
    pub vault: PathBuf,

    /// The name of the source. The vault keeps the history of a source under its name.
    /// The default is the full path of the folder, so a folder that is moved starts a new
    /// source. Give the same name after a move to keep the history.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// The node credential of the vault. The default is the file that `init` made for the
    /// vault in the configuration folder.
    #[arg(long, value_name = "FILE")]
    pub credential: Option<PathBuf>,

    /// Follow symbolic links: back up what a link points to, under the path of the link.
    /// By default a link is not followed and not backed up.
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Show the names of the items that could not be read. By default only their number
    /// is shown, because a name can say a lot about its owner.
    #[arg(short, long)]
    pub verbose: bool,
}

/// Where the recovery phrase comes from. The phrase is never an argument or an
/// environment variable: both can be seen by other users and end up in logs.
#[derive(Debug, Args)]
pub struct PhraseArgs {
    /// A file with the recovery phrase. Only you may be able to read it. By default the
    /// phrase is typed in a terminal without showing it, or read from the input when
    /// there is no terminal.
    #[arg(long, value_name = "FILE")]
    pub phrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct LsArgs {
    /// The folder of the vault.
    #[arg(long, value_name = "FOLDER")]
    pub vault: PathBuf,

    /// List the items of the source with this name (see `sync --name`).
    #[arg(long, value_name = "NAME", conflicts_with = "source_id")]
    pub name: Option<String>,

    /// List the items of the source with this ID (32 hexadecimal characters, as the
    /// list of sources shows it).
    #[arg(long, value_name = "ID")]
    pub source_id: Option<String>,

    #[command(flatten)]
    pub phrase: PhraseArgs,
}
