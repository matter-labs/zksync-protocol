//! Predict effective guest cycles for batches from the embedded cost model,
//! *without* running the guest. Feature extraction (fast VM) works even on
//! batches that OOM in-guest, so this reports what the cycle budget *would* be
//! if the batch could run — useful to see whether cycles or memory is the
//! binding constraint.
//!
//!   cargo run --release -p zksync_cycle_model --example predict_cycles -- \
//!       <batches-dir> [batch-file ...]

use anyhow::{Context, Result};
use std::path::PathBuf;
use zksync_cli_utils::{load_batch, resolve_batch_inputs};
use zksync_cycle_model::{extract_features, CostTable};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let batches_dir = PathBuf::from(
        args.next()
            .context("usage: predict_cycles <batches-dir> [batch-file ...]")?,
    )
    .canonicalize()
    .context("canonicalizing batches dir")?;
    let files: Vec<PathBuf> = args.map(PathBuf::from).collect();
    let (sel, all) = if files.is_empty() {
        (None, true)
    } else {
        (Some(files.as_slice()), false)
    };
    let inputs = resolve_batch_inputs(&batches_dir, sel, all).context("resolving batches")?;

    let table = CostTable::embedded();
    println!("batch_number,predicted_effective_cycles,untrusted,extrapolating");
    for bi in inputs {
        let input = load_batch(&bi).with_context(|| format!("loading batch {}", bi.number))?;
        let fv = extract_features(&input)
            .with_context(|| format!("extracting features for batch {}", bi.number))?;
        let est = table.estimate(&fv);
        // Both trust signals are reported, not just one. A prediction is only as good
        // as the weakest thing it rests on, and the two failure modes are different:
        // `untrusted` means an operation's PRICE is not dependable, `extrapolating`
        // means the price may be fine but this batch is outside the range it was
        // measured over.
        let fmt = |v: &[_]| {
            if v.is_empty() {
                "none".to_string()
            } else {
                format!("{v:?}")
            }
        };
        println!(
            "{},{},{},{}",
            bi.number,
            est.total,
            fmt(&est.untrusted),
            fmt(&est.extrapolating)
        );
    }
    Ok(())
}
