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
