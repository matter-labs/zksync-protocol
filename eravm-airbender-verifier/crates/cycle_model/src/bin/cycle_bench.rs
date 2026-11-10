//! Airbender cycle-cost calibration bench.
//!
//! For each batch it (1) runs the fast VM natively with the feature-counting
//! tracer to get a `FeatureVector` (the cheap, sequencer-computable model
//! inputs), and (2) runs the marker-instrumented guest through the transpiler
//! to get ground-truth cycles / phases / delegations. Rows are written to
//! `dataset.{json,csv}` for the Python fit.
//!
//! Usage (needs the LFS corpus and a guest built with `--features cycle-markers`;
//! the bench itself must be built with the MATCHING `cycle-markers` feature —
//! it keeps each batch's own protocol version at load and puts the labels on
//! the host→guest channel the calibration guest expects; a production-flavour
//! bench refuses older-minor batches at load and would drive the guest with a
//! label-less channel it cannot decode):
//!
//! ```text
//! cargo airbender build --project guest -- --features cycle-markers  # → app.bin/app.text
//! ./scripts/fetch_lfs_batches.sh --all
//! # cheap pre-flight: report every batch's stored label vs what this build accepts
//! cargo run --release -p zksync_cycle_model --features cycle-markers --bin cycle_bench -- \
//!     --all-batches --check-only
//! # full measurement, parallel across cores
//! cargo run --release -p zksync_cycle_model --features cycle-markers --bin cycle_bench -- \
//!     --all-batches --app-bin-dir guest/dist/app --jobs 16 --out artifacts/cycle_model
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use rayon::prelude::*;
use zksync_cli_utils::{load_labeled_batch, resolve_batch_inputs, BatchInputFile};
use zksync_cycle_model::{
    extract_features, run_guest, write_dataset, DatasetProvenance, DatasetRow,
};

#[derive(Parser)]
#[command(about = "Airbender cycle-cost calibration: emit a (features, cycles) dataset")]
struct Args {
    /// Batch files (e.g. 506077.bin.gz). Mutually exclusive with --all-batches.
    #[arg(long, value_delimiter = ',', conflicts_with = "all_batches")]
    batch_files: Option<Vec<PathBuf>>,
    /// Process every batch in --batches-dir.
    #[arg(long, conflicts_with = "batch_files")]
    all_batches: bool,
    #[arg(long, default_value = "testdata/era_mainnet_batches/binary")]
    batches_dir: PathBuf,
    /// Directory holding the marker-enabled guest (app.bin + app.text).
    /// Required unless --check-only.
    #[arg(long)]
    app_bin_dir: Option<PathBuf>,
    #[arg(long, default_value = "artifacts/cycle_model")]
    out: PathBuf,
    /// Only verify each batch loads + carries a label this build can consume;
    /// no guest run, no dataset. Fast pre-flight compatibility check.
    #[arg(long)]
    check_only: bool,
    /// Parallel workers for the measurement run. 0 = one per available core.
    /// Each worker holds a full transpiler VM in memory, so lower this if RAM-bound.
    #[arg(long, default_value_t = 0)]
    jobs: usize,
}

/// Full measurement for one batch: native features + guest cycle measurement.
/// Returns the batch's OWN stored protocol label alongside the row — the
/// provenance stamp must report what was measured. Under `cycle-markers` the
/// conversion keeps that version in the input (so the guest replays the batch
/// under its own semantics); a production build refuses older labels, so build
/// this bench with the flavour matching the guest.
fn process_batch(app_bin_dir: &Path, bf: &BatchInputFile) -> Result<(DatasetRow, String)> {
    // Decode ONCE — this runs `--jobs N` wide alongside a transpiler VM per
    // worker, so a second full hex+gunzip+bincode pass would double both decode
    // time and peak RSS. The stored label is the honest provenance stamp in
    // either flavour; the conversion is where flavour-dependent gating applies.
    let labeled = load_labeled_batch(bf).with_context(|| format!("loading batch {}", bf.number))?;
    let version = format!("Version{}", labeled.labels().system_env_version);
    let input = labeled
        .into_verifier_input()
        .with_context(|| format!("checking the protocol labels of batch {}", bf.number))?;

    let features = extract_features(&input)
        .with_context(|| format!("extracting features for batch {}", bf.number))?;
    let guest = run_guest(app_bin_dir, &input)
        .with_context(|| format!("running guest for batch {}", bf.number))?;

    tracing::info!(batch = bf.number, raw_cycles = guest.raw_cycles, "measured");
    Ok((
        DatasetRow {
            batch_number: bf.number,
            features,
            raw_cycles: guest.raw_cycles,
            phase_cycles: guest.phase_cycles,
            delegations: guest.delegations,
        },
        version,
    ))
}

/// The protocol version(s) actually observed across the measured batches. A
/// corpus that spans versions says so — a single label would be a false stamp,
/// and this is not theoretical: the committed table's corpus is entirely
/// `Version29` while the pinned version is `Version34`.
fn describe_versions(versions: &BTreeSet<String>) -> String {
    match versions.len() {
        0 => "unknown (no batch measured)".to_string(),
        1 => versions.iter().next().cloned().unwrap_or_default(),
        _ => format!(
            "MIXED: {}",
            versions.iter().cloned().collect::<Vec<_>>().join(", ")
        ),
    }
}

/// Compact description of the measured corpus for the provenance manifest, e.g.
/// "49 batches 513601-513649".
fn describe_corpus(inputs: &[BatchInputFile]) -> String {
    match (
        inputs.iter().map(|b| b.number).min(),
        inputs.iter().map(|b| b.number).max(),
    ) {
        (Some(lo), Some(hi)) => format!("{} batches {lo}-{hi}", inputs.len()),
        _ => format!("{} batches", inputs.len()),
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let batches_dir = args
        .batches_dir
        .canonicalize()
        .with_context(|| format!("resolving batches dir {}", args.batches_dir.display()))?;
    let inputs = resolve_batch_inputs(&batches_dir, args.batch_files.as_deref(), args.all_batches)
        .context("resolving batch inputs")?;

    if args.check_only {
        return run_check(&inputs);
    }

    let app_bin_dir = args
        .app_bin_dir
        .context("--app-bin-dir is required for a measurement run (omit only with --check-only)")?;

    let jobs = if args.jobs == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        args.jobs
    };
    tracing::info!(batches = inputs.len(), jobs, "starting measurement run");
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .build()
        .context("building thread pool")?;

    // par_iter preserves input order in the collected Vec. Each batch is wrapped
    // in catch_unwind: the transpiler `panic!`s (e.g. "illegal instruction") on
    // some inputs, and an uncaught panic in a worker would abort the whole run
    // and lose every measurement. Catching turns it into a per-batch failure.
    let results: Vec<Result<(DatasetRow, String)>> = pool.install(|| {
        inputs
            .par_iter()
            .map(|bf| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    process_batch(&app_bin_dir, bf)
                }))
                .unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "transpiler panicked (illegal instruction / unsupported by this guest build)"
                    ))
                })
            })
            .collect()
    });

    let mut rows = Vec::with_capacity(results.len());
    let mut versions = BTreeSet::new();
    let mut failures = 0usize;
    for (bf, res) in inputs.iter().zip(results) {
        match res {
            Ok((row, version)) => {
                rows.push(row);
                versions.insert(version);
            }
            Err(e) => {
                failures += 1;
                tracing::error!(batch = bf.number, "failed: {e:#}");
            }
        }
    }

    write_dataset(&rows, &args.out)?;
    // Stamp WHAT was measured alongside the numbers: the fit refuses to emit an
    // unstamped cost table, and without this the operator would have to
    // reconstruct the guest/vm2 identity by hand (which is how the committed
    // table ended up unattributable).
    let provenance = DatasetProvenance::collect(
        Some(&app_bin_dir),
        describe_versions(&versions),
        describe_corpus(&inputs),
    );
    provenance.write(&args.out)?;
    tracing::info!(
        measured = rows.len(),
        failures,
        out = ?args.out,
        guest_sha256 = ?provenance.guest_sha256,
        "dataset + provenance written"
    );
    if failures > 0 {
        anyhow::bail!("{failures} batch(es) failed; see errors above");
    }
    Ok(())
}

/// Pre-flight: report each batch's STORED protocol label and whether THIS build
/// can consume it. Non-zero exit if any batch is incompatible.
///
/// The flavour-dependent criterion is deliberately NOT restated here: each batch
/// goes through the same `into_verifier_input` gate `load_batch` applies. A
/// re-implemented one inspected only `system_env.version`, missed the
/// label-agreement check, and passed `(31, 60000)` that every worker of the
/// hours-long run then rejected.
fn run_check(inputs: &[BatchInputFile]) -> Result<()> {
    let criterion = if cfg!(feature = "cycle-markers") {
        "loads + names a minor this build can replay (calibration)"
    } else {
        "loads + labels >= the pinned version"
    };

    let mut incompatible = 0usize;
    for bf in inputs {
        // Read the label before the gate consumes the labeled form, so an
        // accepted batch is reported with the version it carries.
        let checked = load_labeled_batch(bf).and_then(|labeled| {
            let version = labeled.labels().system_env_version;
            labeled.into_verifier_input().map(|_| version)
        });
        match checked {
            Ok(version) => tracing::info!(batch = bf.number, version, "ok"),
            Err(e) => {
                incompatible += 1;
                tracing::error!(batch = bf.number, criterion, "INCOMPATIBLE: {e:#}");
            }
        }
    }
    tracing::info!(
        total = inputs.len(),
        incompatible,
        criterion,
        "compatibility check complete"
    );
    if incompatible > 0 {
        anyhow::bail!("{incompatible} batch(es) incompatible");
    }
    Ok(())
}
