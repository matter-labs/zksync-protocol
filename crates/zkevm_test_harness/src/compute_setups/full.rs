//! Functions to compute setup and verification keys for different circuit types.

use std::sync::Arc;

use crate::zkevm_circuits::recursion::leaf_layer::input::RecursionLeafParametersWitness;
use crate::zkevm_circuits::recursion::NUM_BASE_LAYER_CIRCUITS;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::circuit_definitions::aux_layer::{
    ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionLayerCircuit,
};
use circuit_definitions::{
    circuit_definitions::{
        base_layer::{
            ZkSyncBaseLayerCircuit, ZkSyncBaseLayerFinalizationHint, ZkSyncBaseLayerVerificationKey,
        },
        ZkSyncUniformCircuitInstance,
    },
    recursion_layer_proof_config,
    zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK,
    zkevm_circuits::scheduler::aux::BaseLayerCircuitType,
    RECURSION_LAYER_CAP_SIZE, RECURSION_LAYER_FRI_LDE_FACTOR,
};

use crossbeam::atomic::AtomicCell;
use geometry_config::ProtocolGeometry;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;

use crate::toolset::GeometryConfig;

use crate::boojum::{
    algebraic_props::{round_function::AbsorptionModeOverwrite, sponge::GoldilocksPoseidon2Sponge},
    cs::{
        implementations::{
            hints::{DenseVariablesCopyHint, DenseWitnessCopyHint},
            polynomial_storage::{SetupBaseStorage, SetupStorage},
            setup::FinalizationHintsForProver,
            verifier::VerificationKey,
        },
        oracle::merkle_tree::MerkleTreeWithCap,
    },
    worker::Worker,
};

use crate::data_source::SetupDataSource;

use super::*;

use circuit_definitions::circuit_definitions::aux_layer::compression::{
    CompressionMode1Circuit, CompressionMode1ForWrapperCircuit, CompressionMode2Circuit,
    CompressionMode2ForWrapperCircuit, CompressionMode3Circuit, CompressionMode3ForWrapperCircuit,
    CompressionMode4Circuit, CompressionMode4ForWrapperCircuit, CompressionMode5Circuit,
    CompressionMode5ForWrapperCircuit, ProofCompressionFunction,
};
use circuit_definitions::circuit_definitions::aux_layer::compression_modes::{
    CompressionMode1, CompressionMode2, CompressionMode3, CompressionMode4, CompressionMode5,
};
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::*;
use circuit_definitions::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use circuit_definitions::{BASE_LAYER_CAP_SIZE, BASE_LAYER_FRI_LDE_FACTOR};
use std::collections::VecDeque;

use crate::prover_utils::*;

/// Contains all the information that prover needs to setup and verify the given circuit.
pub struct CircuitSetupData {
    pub setup_base: SetupBaseStorage<GoldilocksField, GoldilocksField>,
    pub setup: SetupStorage<GoldilocksField, GoldilocksField>,
    pub vk: VerificationKey<GoldilocksField, GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>>,
    pub setup_tree:
        MerkleTreeWithCap<GoldilocksField, GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>>,
    pub vars_hint: DenseVariablesCopyHint,
    pub wits_hint: DenseWitnessCopyHint,
    pub finalization_hint: FinalizationHintsForProver,
}

/// Generate verification, and setup keys for a given circuit type from a base layer.
/// If generating the setup data for recursion layers, the 'source' must have verification keys for basic circuits, leaf and node.
pub fn generate_circuit_setup_data(
    proving_stage: u8,
    circuit_type: u8,
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<CircuitSetupData> {
    let geometry = ProtocolGeometry::latest().config();
    let worker = Worker::new();

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) =
        match proving_stage {
            // basic circuits
            0 => {
                let circuit = get_all_basic_circuits(&geometry)
                    .iter()
                    .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                    .expect(&format!(
                        "Could not find circuit matching {:?}",
                        circuit_type
                    ))
                    .clone();

                create_base_layer_setup_data(
                    circuit,
                    &worker,
                    BASE_LAYER_FRI_LDE_FACTOR,
                    BASE_LAYER_CAP_SIZE,
                )
            }
            // recursive circuits
            1..=4 => {
                let circuit = get_all_recursive_circuits(source)?
                    .iter()
                    .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                    .expect(&format!(
                        "Could not find circuit matching {:?}",
                        circuit_type
                    ))
                    .clone();

                create_recursive_layer_setup_data(
                    circuit,
                    &worker,
                    RECURSION_LAYER_FRI_LDE_FACTOR,
                    RECURSION_LAYER_CAP_SIZE,
                )
            }
            // compression circuits
            5 => {
                let circuit = get_compression_circuits(source)
                    .iter()
                    .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                    .expect(&format!(
                        "Could not find circuit matching {:?}",
                        circuit_type
                    ))
                    .clone();

                create_compression_layer_setup_data(
                    circuit.clone(),
                    &worker,
                    circuit.clone().proof_config_for_compression_step().fri_lde_factor,
                    circuit
                        .proof_config_for_compression_step()
                        .merkle_tree_cap_size,
                )
            }
            // compression for wrapper circuits
            6 => panic!("Full generation of setup for wrapper circuits should be generated with light setup"),
            _ => unreachable!("Invalid proving stage"),
        };

    Ok(CircuitSetupData {
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        wits_hint,
        finalization_hint,
    })
}

/// For backwards compatibility (as zksync-era uses this method).
/// For new cases please use generate_base_layer_vks directly.
pub fn generate_base_layer_vks_and_proofs(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    generate_base_layer_vks(source, None, || {})
}

/// Returns number of basic verification keys.
pub fn basic_vk_count() -> usize {
    BaseLayerCircuitType::as_iter_u8().count()
}

/// Generate Verification keys for all base layer circuits.
/// num_threads control how many VKs are generated in parallel - each one takes around 30GB of RAM.
/// if not specified, will run them sequencially.
/// CB callback will be called on each finished VK (to track progress).
pub fn generate_base_layer_vks<CB: Fn() + Send + Sync>(
    source: &mut dyn SetupDataSource,
    num_threads: Option<usize>,
    cb: CB,
) -> crate::data_source::SourceResult<()> {
    let geometry = ProtocolGeometry::latest().config();
    let worker = Worker::new();

    let num_threads = num_threads.unwrap_or(1);

    let pool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let r: Vec<_> = pool.install(|| {
        get_all_basic_circuits(&geometry)
            .into_par_iter()
            .map(|circuit| {
                let result = generate_vk_and_finalization_hint(circuit, &worker);
                cb();
                result
            })
            .collect()
    });

    for (vk, hint) in r.into_iter() {
        source.set_base_layer_finalization_hint(hint)?;
        source.set_base_layer_vk(vk)?;
    }

    Ok(())
}

pub fn generate_vk_and_finalization_hint(
    circuit: ZkSyncBaseLayerCircuit,
    worker: &Worker,
) -> (
    ZkSyncBaseLayerVerificationKey,
    ZkSyncBaseLayerFinalizationHint,
) {
    let circuit_type = circuit.numeric_circuit_type();

    let (_, _, vk, _, _, _, finalization_hint) = create_base_layer_setup_data(
        circuit,
        &worker,
        BASE_LAYER_FRI_LDE_FACTOR,
        BASE_LAYER_CAP_SIZE,
    );

    let typed_vk = ZkSyncBaseLayerVerificationKey::from_inner(circuit_type, vk.clone());
    let typed_finalization_hint =
        ZkSyncBaseLayerFinalizationHint::from_inner(circuit_type, finalization_hint.clone());
    (typed_vk, typed_finalization_hint)
}

/// For backwards compatibility (as zksync-era uses this method).
/// For new cases please use generate_recursive_layer_vks directly.
pub fn generate_recursive_layer_vks_and_proofs(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    generate_recursive_layer_vks(source, None, || {})
}

fn generate_vk_and_finalization_hint_for_recursion(
    circuit: ZkSyncRecursiveLayerCircuit,
    worker: &Worker,
) -> (
    ZkSyncRecursionLayerVerificationKey,
    ZkSyncRecursionLayerFinalizationHint,
) {
    println!(
        "Computing leaf layer VK for type {:?}",
        circuit.numeric_circuit_type()
    );

    let numeric_circuit_type = circuit.numeric_circuit_type();
    let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
        create_recursive_layer_setup_data(
            circuit,
            &worker,
            RECURSION_LAYER_FRI_LDE_FACTOR,
            RECURSION_LAYER_CAP_SIZE,
        );

    let typed_vk =
        ZkSyncRecursionLayerVerificationKey::from_inner(numeric_circuit_type, vk.clone());

    let typed_finalization_hint = ZkSyncRecursionLayerFinalizationHint::from_inner(
        numeric_circuit_type,
        finalization_hint.clone(),
    );
    (typed_vk, typed_finalization_hint)
}

/// Returns number of recursive layer verification keys.
pub fn recursive_layer_vk_count() -> usize {
    // Leafs (one per base layer) + node + recursion + scheduler
    basic_vk_count() + 3
}

/// num_threads control how many VKs are generated in parallel - each one takes around 25GB of RAM.
/// if not specified, will run them sequencially.
pub fn generate_recursive_layer_vks<CB: Fn() + Send + Sync>(
    source: &mut dyn SetupDataSource,
    num_threads: Option<usize>,
    cb: CB,
) -> crate::data_source::SourceResult<()> {
    // here we rely ONLY on VKs and proofs from the setup, so we keep the geometries and circuits
    // via padding proofs
    let worker = Worker::new();
    let num_threads = num_threads.unwrap_or(1);

    println!("Computing leaf vks");

    let pool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let leaf_circuits = get_leaf_circuits(source)?;

    let r: Vec<_> = pool.install(|| {
        leaf_circuits
            .into_par_iter()
            .map(|circuit| {
                let result = generate_vk_and_finalization_hint_for_recursion(circuit, &worker);
                cb();
                result
            })
            .collect()
    });

    for (vk, hint) in r.into_iter() {
        source.set_recursion_layer_finalization_hint(hint)?;
        source.set_recursion_layer_vk(vk)?;
    }

    println!("Computing node vk");

    {
        let circuit = get_node_circuit(source)?;

        let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
            create_recursive_layer_setup_data(
                circuit,
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            );

        let typed_finalization_hint =
            ZkSyncRecursionLayerFinalizationHint::NodeLayerCircuit(finalization_hint.clone());
        source.set_recursion_layer_node_finalization_hint(typed_finalization_hint)?;
        let typed_vk = ZkSyncRecursionLayerVerificationKey::NodeLayerCircuit(vk.clone());
        source.set_recursion_layer_node_vk(typed_vk)?;
    }
    cb();

    println!("Computing recursion tip vk");
    generate_recursion_tip_vk(source)?;
    cb();

    println!("Computing scheduler vk");
    generate_scheduler_vk(source)?;
    cb();

    Ok(())
}

pub fn generate_recursion_tip_vk(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    let worker = Worker::new();
    let recursion_tip_circuit = get_recursion_tip_circuit(source)?;

    let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
        create_recursive_layer_setup_data(
            recursion_tip_circuit,
            &worker,
            RECURSION_LAYER_FRI_LDE_FACTOR,
            RECURSION_LAYER_CAP_SIZE,
        );

    source.set_recursion_tip_vk(ZkSyncRecursionLayerVerificationKey::RecursionTipCircuit(
        vk.clone(),
    ))?;
    source.set_recursion_tip_finalization_hint(
        ZkSyncRecursionLayerFinalizationHint::RecursionTipCircuit(finalization_hint.clone()),
    )?;
    Ok(())
}

pub fn generate_scheduler_vk(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<()> {
    let worker = Worker::new();
    let scheduler_circuit = get_scheduler_circuit(source)?;

    let (_setup_base, _setup, vk, _setup_tree, _vars_hint, _wits_hint, finalization_hint) =
        create_recursive_layer_setup_data(
            scheduler_circuit,
            &worker,
            RECURSION_LAYER_FRI_LDE_FACTOR,
            RECURSION_LAYER_CAP_SIZE,
        );

    source.set_recursion_layer_vk(ZkSyncRecursionLayerVerificationKey::SchedulerCircuit(
        vk.clone(),
    ))?;
    source.set_recursion_layer_finalization_hint(
        ZkSyncRecursionLayerFinalizationHint::SchedulerCircuit(finalization_hint.clone()),
    )?;

    Ok(())
}

pub fn compute_leaf_params(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<(u8, RecursionLeafParametersWitness<GoldilocksField>)>> {
    use crate::witness::recursive_aggregation::compute_leaf_params;
    let mut leaf_vk_commits = vec![];

    for circuit_type in ((BaseLayerCircuitType::VM as u8)
        ..=(BaseLayerCircuitType::ECMultiPairingNaivePrecompile as u8))
        .chain(std::iter::once(BaseLayerCircuitType::EIP4844Repack as u8))
    {
        let recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(circuit_type),
        );
        let base_vk = source.get_base_layer_vk(circuit_type)?;
        let leaf_vk = source.get_recursion_layer_vk(recursive_circuit_type as u8)?;
        let params = compute_leaf_params(circuit_type, base_vk, leaf_vk);
        leaf_vk_commits.push((circuit_type, params));
    }

    Ok(leaf_vk_commits)
}

#[cfg(test)]
mod test {
    use std::sync::Mutex;

    use indicatif::{ProgressBar, ProgressStyle};

    use crate::data_source::local_file_data_source::LocalFileDataSource;

    use super::*;

    #[ignore = "too slow"]
    #[test]
    fn test_run_create_base_layer_vks_and_proofs() {
        let mut source = LocalFileDataSource::default();
        source.create_folders_for_storing_data();
        let count = basic_vk_count();
        let progress_bar = ProgressBar::new(count as u64);
        progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos:>7}/{len:7} ({eta})")
        .progress_chars("#>-"));

        let pb = Arc::new(Mutex::new(progress_bar));

        generate_base_layer_vks(&mut source, Some(5), || {
            pb.lock().unwrap().inc(1);
        })
        .expect("must compute setup");
        pb.lock().unwrap().finish_with_message("done");
    }

    #[ignore = "too slow"]
    #[test]
    fn test_run_create_recursion_layer_vks_and_proofs() {
        let mut source = LocalFileDataSource::default();
        source.create_folders_for_storing_data();
        generate_recursive_layer_vks(&mut source, None, || {}).expect("must compute setup");
    }

    #[ignore = "too slow"]
    #[test]
    fn test_generate_recursion_tip() {
        let mut src = LocalFileDataSource::default();
        src.create_folders_for_storing_data();
        let source = &mut src;

        generate_recursion_tip_vk(source).unwrap();
    }

    #[ignore = "too slow"]
    #[test]
    fn test_generate_scheduler() {
        let mut src = LocalFileDataSource::default();
        src.create_folders_for_storing_data();
        let source = &mut src;

        generate_scheduler_vk(source).unwrap();
    }
}
