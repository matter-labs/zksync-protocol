//! Dump the model feature vector (JSON) for batches, WITHOUT running the guest.
//!   cargo run --release -p zksync_cycle_model --example dump_features -- <dir> [batch-file ...]
use anyhow::{Context, Result};
use std::path::PathBuf;
use zksync_cli_utils::{load_batch, resolve_batch_inputs};
use zksync_cycle_model::extract_features;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .context("usage: dump_features <dir> [batch ...]")?,
    )
    .canonicalize()?;
    let files: Vec<PathBuf> = args.map(PathBuf::from).collect();
    let (sel, all) = if files.is_empty() {
        (None, true)
    } else {
        (Some(files.as_slice()), false)
    };
    for bi in resolve_batch_inputs(&dir, sel, all)? {
        let input = load_batch(&bi)?;
        let fv = extract_features(&input)?;
        println!(
            "{{\"batch_number\":{},\"features\":{}}}",
            bi.number,
            serde_json::to_string(&fv)?
        );
    }
    Ok(())
}
