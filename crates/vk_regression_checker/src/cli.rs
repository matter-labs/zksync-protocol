use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(about = "Verification key regression checker")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate base and recursive keys in era-compatible layout.
    Generate(GenerateArgs),
    /// Generate keys and compare them with a reference key folder.
    Compare(CompareArgs),
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Output directory for generated keys.
    #[arg(long)]
    pub keys_dir: PathBuf,
    /// Number of verification key generation jobs.
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
}

#[derive(Debug, Args)]
pub struct CompareArgs {
    /// Directory with reference keys.
    #[arg(long)]
    pub keys_dir: PathBuf,
    /// Output directory for freshly generated keys.
    #[arg(long, default_value = "generated")]
    pub generated_dir: PathBuf,
    /// Number of verification key generation jobs.
    #[arg(long, default_value_t = 1)]
    pub jobs: usize,
}
