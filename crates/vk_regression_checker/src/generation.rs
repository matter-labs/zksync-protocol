use std::fs;
use std::path::Path;

use anyhow::{anyhow, ensure, Context, Result};
use circuit_definitions::circuit_definitions::aux_layer::{
    ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionForWrapperFinalizationHint,
    ZkSyncCompressionForWrapperVerificationKey, ZkSyncCompressionLayerFinalizationHint,
    ZkSyncCompressionLayerStorage, ZkSyncCompressionLayerVerificationKey,
};
use circuit_definitions::circuit_definitions::recursion_layer::ZkSyncRecursionLayerStorageType;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use tracing::info;
use zkevm_test_harness::boojum::worker::Worker;
use zkevm_test_harness::compute_setups::{
    generate_base_layer_vks, generate_circuit_setup_data, generate_recursive_layer_vks,
};
use zkevm_test_harness::data_source::{
    in_memory_data_source::InMemoryDataSource, SetupDataSource, SourceResult,
};
use zkevm_test_harness::prover_utils::create_compression_for_wrapper_setup_data;

use crate::artifacts::{COMPRESSION_CIRCUIT_TYPES, COMPRESSION_FOR_WRAPPER_CIRCUIT_TYPES};
use crate::file_io::{write_bin, write_json};

pub fn run_generate(keys_dir: &Path, jobs: usize) -> Result<()> {
    validate_jobs(jobs)?;

    info!("Generating keys");
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

    generate_compression_layer_artifacts(&mut source)?;
    generate_compression_for_wrapper_artifacts(&mut source)?;

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

    for circuit_type in COMPRESSION_CIRCUIT_TYPES {
        let vk = from_source(source.get_compression_vk(circuit_type), || {
            format!("while attempting to load compression verification key {circuit_type}")
        })?;
        write_json(
            &keys_dir.join(format!(
                "verification_compression_{}_key.json",
                circuit_type
            )),
            &vk.into_inner(),
        )
        .with_context(|| {
            format!("while attempting to write compression verification key {circuit_type}")
        })?;

        let hint = from_source(source.get_compression_hint(circuit_type), || {
            format!("while attempting to load compression finalization hints {circuit_type}")
        })?
        .into_inner();
        write_bin(
            &keys_dir.join(format!(
                "finalization_hints_compression_{}.bin",
                circuit_type
            )),
            &hint,
        )
        .with_context(|| {
            format!("while attempting to write compression finalization hints {circuit_type}")
        })?;
    }

    for circuit_type in COMPRESSION_FOR_WRAPPER_CIRCUIT_TYPES {
        let vk = from_source(source.get_compression_for_wrapper_vk(circuit_type), || {
            format!("while attempting to load compression wrapper verification key {circuit_type}")
        })?;
        write_json(
            &keys_dir.join(format!(
                "verification_compression_wrapper_{}_key.json",
                circuit_type
            )),
            &vk.into_inner(),
        )
        .with_context(|| {
            format!("while attempting to write compression wrapper verification key {circuit_type}")
        })?;

        let hint = from_source(
            source.get_compression_for_wrapper_hint(circuit_type),
            || {
                format!(
                "while attempting to load compression wrapper finalization hints {circuit_type}"
            )
            },
        )?
        .into_inner();
        write_bin(
            &keys_dir.join(format!(
                "finalization_hints_compression_wrapper_{}.bin",
                circuit_type
            )),
            &hint,
        )
        .with_context(|| {
            format!(
                "while attempting to write compression wrapper finalization hints {circuit_type}"
            )
        })?;
    }

    Ok(())
}

fn generate_compression_layer_artifacts(source: &mut InMemoryDataSource) -> Result<()> {
    for circuit_type in COMPRESSION_CIRCUIT_TYPES {
        let setup_data = from_source(generate_circuit_setup_data(5, circuit_type, source), || {
            format!("while attempting to generate compression setup data {circuit_type}")
        })?;

        let zkevm_test_harness::compute_setups::CircuitSetupData {
            vk,
            finalization_hint,
            ..
        } = setup_data;

        let vk: ZkSyncCompressionLayerVerificationKey =
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, vk);
        source
            .set_compression_vk(vk)
            .map_err(|err| anyhow!("{err}"))
            .with_context(|| {
                format!("while attempting to store compression verification key {circuit_type}")
            })?;

        let hint: ZkSyncCompressionLayerFinalizationHint =
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, finalization_hint);
        source
            .set_compression_hint(hint)
            .map_err(|err| anyhow!("{err}"))
            .with_context(|| {
                format!("while attempting to store compression finalization hints {circuit_type}")
            })?;
    }

    Ok(())
}

fn generate_compression_for_wrapper_artifacts(source: &mut InMemoryDataSource) -> Result<()> {
    let worker = Worker::new();

    for circuit_type in COMPRESSION_FOR_WRAPPER_CIRCUIT_TYPES {
        let previous_vk = match circuit_type {
            1 => from_source(
                source.get_recursion_layer_vk(
                    ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8,
                ),
                || {
                    "while attempting to load scheduler verification key for wrapper mode 1"
                        .to_owned()
                },
            )?
            .into_inner(),
            5 => from_source(source.get_compression_vk(4), || {
                "while attempting to load compression verification key 4 for wrapper mode 5"
                    .to_owned()
            })?
            .into_inner(),
            _ => unreachable!("unsupported compression wrapper mode: {circuit_type}"),
        };

        let circuit = ZkSyncCompressionForWrapperCircuit::from_witness_and_vk(
            None,
            previous_vk,
            circuit_type,
        );
        let proof_config = circuit.proof_config_for_compression_step();
        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_compression_for_wrapper_setup_data(
                circuit,
                &worker,
                proof_config.fri_lde_factor,
                proof_config.merkle_tree_cap_size,
            );

        let vk: ZkSyncCompressionForWrapperVerificationKey =
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, vk);
        source
            .set_compression_for_wrapper_vk(vk)
            .map_err(|err| anyhow!("{err}"))
            .with_context(|| {
                format!(
                    "while attempting to store compression wrapper verification key {circuit_type}"
                )
            })?;

        let hint: ZkSyncCompressionForWrapperFinalizationHint =
            ZkSyncCompressionLayerStorage::from_inner(circuit_type, finalization_hint);
        source
            .set_compression_for_wrapper_hint(hint)
            .map_err(|err| anyhow!("{err}"))
            .with_context(|| {
                format!(
                    "while attempting to store compression wrapper finalization hints {circuit_type}"
                )
            })?;
    }

    Ok(())
}

fn from_source<T>(source_result: SourceResult<T>, context: impl FnOnce() -> String) -> Result<T> {
    source_result
        .map_err(|err| anyhow!("{err}"))
        .with_context(context)
}
