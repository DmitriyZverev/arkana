use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct IoArgs {
    /// Read password from a file instead of prompting for it
    #[arg(long, short = 'p')]
    pub password_file: Option<PathBuf>,
    /// Read input from a file instead of standard input
    #[arg(long, short = 'i', alias = "input")]
    pub input_file: Option<PathBuf>,
    /// Write output to a file instead of standard output
    #[arg(long, short = 'o', alias = "output")]
    pub output_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum SubCommand {
    /// Encrypts data from stdin or a file and writes encrypted data to stdout or a file
    Encrypt {
        #[command(flatten)]
        io: IoArgs,
    },
    /// Decrypts data from stdin or a file and writes decrypted data to stdout or a file
    Decrypt {
        #[command(flatten)]
        io: IoArgs,
    },
}

#[derive(Parser, Debug)]
pub struct CliArgs {
    /// Working directory for resolving relative paths
    #[arg(long, short = 'C')]
    pub cwd: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<SubCommand>,
}
