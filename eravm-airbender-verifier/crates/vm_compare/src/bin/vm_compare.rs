use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::{load_batch, resolve_batch_inputs, BatchInputFile};
use zksync_vm_compare::{CompareOptions, ComparisonOutcome};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Compare legacy and fast VM execution on framed batch inputs"
)]
struct Cli {
    #[arg(long, value_delimiter = ',', conflicts_with = "all_batches")]
    batch_files: Option<Vec<PathBuf>>,

    #[arg(long, conflicts_with = "batch_files")]
    all_batches: bool,

    #[arg(long, default_value = "testdata/era_mainnet_batches/binary")]
    batches_dir: PathBuf,

    #[arg(long, default_value_t = CompareOptions::default().max_capture_bytes)]
    max_capture_bytes: usize,

    #[arg(long)]
    no_fail_fast: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let batches_dir = cli.batches_dir.canonicalize().with_context(|| {
        format!(
            "while attempting to canonicalize {}",
            cli.batches_dir.display()
        )
    })?;
    let batch_inputs =
        resolve_batch_inputs(&batches_dir, cli.batch_files.as_deref(), cli.all_batches)
            .context("while attempting to resolve requested batches")?;
    let options = CompareOptions {
        max_capture_bytes: cli.max_capture_bytes,
        fail_fast: !cli.no_fail_fast,
    };
    let mut divergent_files = Vec::new();

    for batch_input in batch_inputs {
        let input = load_batch(&batch_input).with_context(|| {
            format!(
                "while attempting to load batch {} from {}",
                batch_input.number,
                batch_input.path.display()
            )
        })?;
        let matched = compare_batch(&batch_input, input, options)?;
        if !matched {
            divergent_files.push(batch_input.path.display().to_string());
            if options.fail_fast {
                anyhow::bail!(
                    "legacy and fast VM traces diverged for {}",
                    batch_input.path.display()
                );
            }
        }
    }

    if !divergent_files.is_empty() {
        anyhow::bail!(
            "legacy and fast VM traces diverged for {}",
            divergent_files.join(", ")
        );
    }

    Ok(())
}

fn compare_batch(
    batch_input: &BatchInputFile,
    input: AirbenderVerifierInput,
    options: CompareOptions,
) -> Result<bool> {
    let batch_number = batch_input.number;
    let batch_file = batch_input.path.display();

    let report = zksync_vm_compare::compare(input, options).with_context(|| {
        format!("while attempting to compare batch {batch_number} from {batch_file}")
    })?;

    match &report.outcome {
        ComparisonOutcome::Match => {
            println!("batch {batch_number} ({batch_file}): {report}");
            Ok(true)
        }
        ComparisonOutcome::Diverged(divergences) => {
            eprintln!("batch {batch_number} ({batch_file}): {report}");
            for (index, divergence) in divergences.iter().enumerate() {
                eprintln!(
                    "divergence {} in {} at L2 block {}, tx #{} ({:?}): {}",
                    index + 1,
                    batch_file,
                    divergence.location.l2_block_number,
                    divergence.location.tx_index_in_block,
                    divergence.location.tx_hash,
                    divergence.reason
                );
                if let Some(legacy) = &divergence.legacy {
                    eprintln!("legacy: {legacy:#?}");
                }
                if let Some(fast) = &divergence.fast {
                    eprintln!("fast: {fast:#?}");
                }
            }
            Ok(false)
        }
    }
}
