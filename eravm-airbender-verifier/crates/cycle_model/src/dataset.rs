use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_vm_compare::run_fast_vm_with_tracer;

use zksync_era_airbender_cycles_estimator::{FeatureId, FeatureVector};
use zksync_era_airbender_cycles_tracer::CycleFeatureTracer;

/// One calibration sample: model-input features (native) paired with the
/// ground-truth guest measurements (RISC-V cycles / phases / delegations).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRow {
    pub batch_number: u64,
    pub features: FeatureVector,
    pub raw_cycles: u64,
    pub phase_cycles: BTreeMap<String, u64>,
    pub delegations: BTreeMap<u32, u64>,
}

/// Run the fast VM natively over `input` and collect the model-input feature
/// vector: per-opcode/precompile counts from the tracer plus batch-level
/// features derived directly from the input and finished batch.
pub fn extract_features(input: &AirbenderVerifierInput) -> anyhow::Result<FeatureVector> {
    let tracer = CycleFeatureTracer::new();
    let finished = run_fast_vm_with_tracer(input, tracer.clone())
        .context("fast VM run for feature extraction failed")?;
    let mut features = tracer.snapshot();

    let tx_count: u64 = input
        .l2_blocks_execution_data
        .iter()
        .map(|b| b.txs.len() as u64)
        .sum();
    features.add(FeatureId::TransactionCount, tx_count);
    features.add(
        FeatureId::MerkleLeafCount,
        input.merkle_paths.merkle_paths.len() as u64,
    );
    if let Some(pubdata) = finished.pubdata_input.as_ref() {
        features.add(FeatureId::PubdataBytes, pubdata.len() as u64);
    }

    // The offline-only setup/commitment drivers that used to be collected here
    // (used_bytecode_bytes/-count, storage_key_count, initial_heap_words,
    // system_log_count) are gone from the schema. They existed to make the per-phase
    // `setup` predictor fit well offline, and no online producer could supply them —
    // the sequencer passed zeros while the fit had priced them, a train/serve skew
    // that reads as an under-estimate. The per-phase predictors had no consumer, so
    // both went together.
    if let Some(state_diffs) = finished.state_diffs.as_ref() {
        features.add(FeatureId::StateDiffCount, state_diffs.len() as u64);
    }
    Ok(features)
}

/// Write the dataset as both `dataset.json` (full rows) and `dataset.csv`
/// (flat feature matrix for the Python fit).
pub fn write_dataset(rows: &[DatasetRow], out_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(out_dir).context("creating output dir")?;
    let json = serde_json::to_string_pretty(rows)?;
    std::fs::write(out_dir.join("dataset.json"), json)?;

    // Flat CSV: union of every feature id seen across rows, in a stable order.
    let mut feature_ids: Vec<FeatureId> = rows
        .iter()
        .flat_map(|r| r.features.counts.keys().copied())
        .collect();
    feature_ids.sort();
    feature_ids.dedup();

    let mut csv = String::from("batch_number,raw_cycles");
    for id in &feature_ids {
        csv.push_str(&format!(",f_{id:?}"));
    }
    csv.push('\n');
    for r in rows {
        csv.push_str(&format!("{},{}", r.batch_number, r.raw_cycles));
        for id in &feature_ids {
            csv.push_str(&format!(",{}", r.features.get(*id)));
        }
        csv.push('\n');
    }
    std::fs::write(out_dir.join("dataset.csv"), csv)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_row_json_roundtrip() {
        let mut features = FeatureVector::default();
        features.add(FeatureId::StorageWrite, 5);
        let row = DatasetRow {
            batch_number: 506077,
            features,
            raw_cycles: 1_234_567,
            phase_cycles: BTreeMap::from([("vm_execution".to_string(), 1_000_000)]),
            delegations: BTreeMap::from([(1991, 42)]),
        };
        let json = serde_json::to_string(&row).unwrap();
        let back: DatasetRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.batch_number, 506077);
        assert_eq!(back.features.get(FeatureId::StorageWrite), 5);
        assert_eq!(back.phase_cycles["vm_execution"], 1_000_000);
    }

    #[test]
    fn write_dataset_emits_csv_and_json() {
        let mut features = FeatureVector::default();
        features.add(FeatureId::FarCall, 2);
        features.add(FeatureId::Keccak256Cycles, 9);
        let rows = vec![DatasetRow {
            batch_number: 42,
            features,
            raw_cycles: 100,
            phase_cycles: BTreeMap::new(),
            delegations: BTreeMap::new(),
        }];
        let dir = std::env::temp_dir().join("cycle_model_test_write");
        write_dataset(&rows, &dir).unwrap();
        let csv = std::fs::read_to_string(dir.join("dataset.csv")).unwrap();
        assert!(csv
            .lines()
            .next()
            .unwrap()
            .starts_with("batch_number,raw_cycles,f_"));
        assert!(csv.contains("42,100,"));
        assert!(dir.join("dataset.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
