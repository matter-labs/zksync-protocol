mod artifacts;
mod cli;
mod comparison;
mod file_io;
mod generation;

use anyhow::Result;
use clap::Parser;
use tracing::error;

use crate::cli::{Cli, Command};

fn main() {
    init_tracing();

    if let Err(err) = run() {
        error!("vk_regression_checker failed: {err}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate(args) => generation::run_generate(&args.keys_dir, args.jobs),
        Command::Compare(args) => {
            comparison::run_compare(&args.keys_dir, &args.generated_dir, args.jobs)
        }
    }
}
