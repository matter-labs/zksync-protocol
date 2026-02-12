use std::fs;
use std::path::Path;

use anyhow::{anyhow, ensure, Context, Result};
use circuit_definitions::circuit_definitions::recursion_layer::ZkSyncRecursionLayerStorageType;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use tracing::info;
use zkevm_test_harness::compute_setups::{generate_base_layer_vks, generate_recursive_layer_vks};
use zkevm_test_harness::data_source::{
    in_memory_data_source::InMemoryDataSource, SetupDataSource, SourceResult,
};

use crate::file_io::{write_bin, write_json};

pub fn run_generate(keys_dir: &Path, jobs: usize) -> Result<()> {
    validate_jobs(jobs)?;

    info!("Generating base and recursive keys");
    info!("jobs={jobs}");
    info!("output={}", keys_dir.display());

    let source = generate_data_source(jobs)?;
    write_era_compatible_layout(&source, keys_dir)?;

    info!("Done");
    Ok(())
}

pub fn validate_jobs(jobs: usize) -> Result<()> {
    ensure!(jobs > 0, "--jobs must be at least 1");
    Ok(())
}

pub fn generate_data_source(jobs: usize) -> Result<InMemoryDataSource> {
    let mut source = InMemoryDataSource::new();

    generate_base_layer_vks(&mut source, Some(jobs), || {})
        .map_err(|err| anyhow!("{err}"))
        .context("while attempting to generate base layer verification keys")?;

    generate_recursive_layer_vks(&mut source, Some(jobs), || {})
        .map_err(|err| anyhow!("{err}"))
        .context("while attempting to generate recursive layer verification keys")?;

    Ok(source)
}

pub fn write_era_compatible_layout(source: &InMemoryDataSource, keys_dir: &Path) -> Result<()> {
    fs::create_dir_all(keys_dir).with_context(|| {
        format!(
            "while attempting to create output key directory {}",
            keys_dir.display()
        )
    })?;

    for basic_circuit_type in BaseLayerCircuitType::as_iter_u8() {
        let vk = from_source(source.get_base_layer_vk(basic_circuit_type), || {
            format!("while attempting to load base verification key {basic_circuit_type}")
        })?;
        write_json(
            &keys_dir.join(format!(
                "verification_basic_{}_key.json",
                basic_circuit_type
            )),
            &vk,
        )
        .with_context(|| {
            format!("while attempting to write base verification key {basic_circuit_type}")
        })?;

        let hint = from_source(
            source.get_base_layer_finalization_hint(basic_circuit_type),
            || format!("while attempting to load base finalization hints {basic_circuit_type}"),
        )?
        .into_inner();
        write_bin(
            &keys_dir.join(format!(
                "finalization_hints_basic_{}.bin",
                basic_circuit_type
            )),
            &hint,
        )
        .with_context(|| {
            format!("while attempting to write base finalization hints {basic_circuit_type}")
        })?;
    }

    for leaf_circuit_type in ZkSyncRecursionLayerStorageType::leafs_as_iter_u8() {
        let vk = from_source(source.get_recursion_layer_vk(leaf_circuit_type), || {
            format!("while attempting to load leaf verification key {leaf_circuit_type}")
        })?;
        write_json(
            &keys_dir.join(format!("verification_leaf_{}_key.json", leaf_circuit_type)),
            &vk,
        )
        .with_context(|| {
            format!("while attempting to write leaf verification key {leaf_circuit_type}")
        })?;

        let hint = from_source(
            source.get_recursion_layer_finalization_hint(leaf_circuit_type),
            || format!("while attempting to load leaf finalization hints {leaf_circuit_type}"),
        )?
        .into_inner();
        write_bin(
            &keys_dir.join(format!("finalization_hints_leaf_{}.bin", leaf_circuit_type)),
            &hint,
        )
        .with_context(|| {
            format!("while attempting to write leaf finalization hints {leaf_circuit_type}")
        })?;
    }

    let node_vk = from_source(source.get_recursion_layer_node_vk(), || {
        "while attempting to load node verification key".to_owned()
    })?;
    write_json(&keys_dir.join("verification_node_key.json"), &node_vk)
        .context("while attempting to write node verification key")?;

    let node_hint = from_source(source.get_recursion_layer_node_finalization_hint(), || {
        "while attempting to load node finalization hints".to_owned()
    })?
    .into_inner();
    write_bin(&keys_dir.join("finalization_hints_node.bin"), &node_hint)
        .context("while attempting to write node finalization hints")?;

    let recursion_tip_vk = from_source(source.get_recursion_tip_vk(), || {
        "while attempting to load recursion tip verification key".to_owned()
    })?;
    write_json(
        &keys_dir.join("verification_recursion_tip_key.json"),
        &recursion_tip_vk,
    )
    .context("while attempting to write recursion tip verification key")?;

    let recursion_tip_hint = from_source(source.get_recursion_tip_finalization_hint(), || {
        "while attempting to load recursion tip finalization hints".to_owned()
    })?
    .into_inner();
    write_bin(
        &keys_dir.join("finalization_hints_recursion_tip.bin"),
        &recursion_tip_hint,
    )
    .context("while attempting to write recursion tip finalization hints")?;

    let scheduler_circuit_type = ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8;
    let scheduler_vk = from_source(
        source.get_recursion_layer_vk(scheduler_circuit_type),
        || "while attempting to load scheduler verification key".to_owned(),
    )?;
    write_json(
        &keys_dir.join("verification_scheduler_key.json"),
        &scheduler_vk.into_inner(),
    )
    .context("while attempting to write scheduler verification key")?;

    let scheduler_hint = from_source(
        source.get_recursion_layer_finalization_hint(scheduler_circuit_type),
        || "while attempting to load scheduler finalization hints".to_owned(),
    )?
    .into_inner();
    write_bin(
        &keys_dir.join("finalization_hints_scheduler.bin"),
        &scheduler_hint,
    )
    .context("while attempting to write scheduler finalization hints")?;

    Ok(())
}

fn from_source<T>(source_result: SourceResult<T>, context: impl FnOnce() -> String) -> Result<T> {
    source_result
        .map_err(|err| anyhow!("{err}"))
        .with_context(context)
}
