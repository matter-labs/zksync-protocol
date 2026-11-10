//! Integration test for the native feature-extraction half of the harness
//! (tracer + vm_compare run_fast_vm_with_tracer + batch-level features), run
//! against a real mainnet batch. `#[ignore]` because it needs the Git LFS
//! corpus — fetch it first:
//!
//! ```sh
//! ./scripts/fetch_lfs_batches.sh 84730.bin.gz
//! cargo test -p zksync_cycle_model --test native_features -- --ignored --nocapture
//! ```
//!
//! The batch must decode at this repo's (v31) wire format. `84730` is a v31
//! corpus batch; substitute any batch present in the testdata dir.
use std::path::PathBuf;

use zksync_cli_utils::{load_batch, resolve_batch_inputs};
use zksync_cycle_model::{extract_features, FeatureId};

#[test]
#[ignore = "requires the LFS batch corpus (fetch a v31 batch, e.g. 84730.bin.gz)"]
fn extract_features_on_real_batch() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/era_mainnet_batches/binary")
        .canonicalize()
        .expect("batches dir must exist");
    let inputs = resolve_batch_inputs(&dir, Some(&[PathBuf::from("84730.bin.gz")]), false)
        .expect("resolve batch");
    // load_batch gates on the stored label and returns the guest-facing input.
    let input = load_batch(&inputs[0]).expect("load batch 84730");

    let features = extract_features(&input).expect("feature extraction");

    let total: u64 = features.counts.values().sum();
    assert!(total > 0, "a real batch must execute opcodes");
    assert!(
        features.get(FeatureId::TransactionCount) > 0,
        "batch must contain transactions"
    );
    assert!(
        features.get(FeatureId::MerkleLeafCount) > 0,
        "batch must touch storage slots"
    );

    // Human-readable dump so the calibration engineer can eyeball the vector.
    println!("batch {} feature vector:", inputs[0].number);
    for (id, n) in &features.counts {
        println!("  {id:?}: {n}");
    }
}
