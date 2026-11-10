//! Integration test: load a real batch, run verification, check commitment output.
//!
//! Requires the test batch to be fetched via Git LFS:
//!   ./scripts/fetch_lfs_batches.sh <BATCH_NUMBER>.bin.gz

use std::path::Path;

use zksync_airbender_verifier::test_utils::crosscheck_commitment;
use zksync_airbender_verifier::Verify;
use zksync_cli_utils::{load_batch, BatchInputFile};

fn run_commitment_test(batch_number: u64) {
    let batch_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../testdata/era_mainnet_batches/binary/{batch_number}.bin.gz"
    ));

    let present = batch_path.exists()
        && std::fs::metadata(&batch_path)
            .map(|m| m.len() >= 1000)
            .unwrap_or(false);
    if !present {
        // Under CI the corpus is fetched, so a missing fixture must fail the job
        // rather than silently skip (otherwise a missing-LFS misconfiguration
        // reports green). Locally we skip for convenience (the default
        // `cargo test` doesn't fetch LFS).
        assert!(
            std::env::var_os("CI").is_none(),
            "batch {batch_number} fixture missing under CI — run ./scripts/fetch_lfs_batches.sh {batch_number}.bin.gz before `cargo test`"
        );
        eprintln!(
            "Skipping test for batch {batch_number}: fixture missing (run ./scripts/fetch_lfs_batches.sh {batch_number}.bin.gz)"
        );
        return;
    }

    // The corpus ships with a baked-in synthetic `commitment_input` (fake
    // blob/prev-batch data — see `test_utils` module docs), so we can verify
    // directly. Not L1-settlement-equivalent.
    let avi = load_batch(&BatchInputFile {
        number: batch_number,
        path: batch_path.clone(),
    })
    .expect("failed to load batch");

    println!(
        "Running verification for batch {}...",
        avi.l1_batch_env.number
    );
    let result = avi.clone().verify().expect("verification failed");
    crosscheck_commitment(&result, &avi).expect("crosscheck failed");

    assert_ne!(
        result.commitment,
        zksync_types::H256::zero(),
        "commitment should be non-zero"
    );
    assert_ne!(
        result.proof_public_input, [0u32; 8],
        "proof public input should be non-zero"
    );

    println!("Batch: {}", result.batch_number);
    println!("State root: {:?}", result.value_hash);
    println!("Commitment: {:?}", result.commitment);
    println!("Proof public input: {:?}", result.proof_public_input);
}

#[test]
fn test_batch_84730_commitment() {
    run_commitment_test(84730);
}

#[test]
fn test_batch_84731_commitment() {
    run_commitment_test(84731);
}
