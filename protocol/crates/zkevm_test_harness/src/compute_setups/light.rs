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
use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;

use super::*;

use crate::boojum::cs::implementations::verifier::VerificationKeyCircuitGeometry;
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

use crate::prover_utils::light::{
    create_light_base_layer_setup_data, create_light_compression_for_wrapper_setup_data,
    create_light_compression_layer_setup_data, create_light_recursive_layer_setup_data,
};
use crate::prover_utils::*;

/// Contains all the information that prover needs to setup and verify the given circuit.
pub struct LightCircuitSetupData {
    pub setup_base: SetupBaseStorage<GoldilocksField, GoldilocksField>,
    pub vk_geometry: VerificationKeyCircuitGeometry,
    pub vars_hint: DenseVariablesCopyHint,
    pub wits_hint: DenseWitnessCopyHint,
    pub finalization_hint: FinalizationHintsForProver,
}

/// Generate verification, and setup keys for a given circuit type from a base layer.
/// If generating the setup data for recursion layers, the 'source' must have verification keys for basic circuits, leaf and node.
pub fn generate_light_circuit_setup_data(
    proving_stage: u8,
    circuit_type: u8,
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<LightCircuitSetupData> {
    let geometry = ProtocolGeometry::latest().config();
    let worker = Worker::new();

    let (setup_base, vk_geometry, vars_hint, wits_hint, finalization_hint) = match proving_stage {
        0 => {
            let circuit = get_all_basic_circuits(&geometry)
                .iter()
                .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                .expect(&format!(
                    "Could not find circuit matching {:?}",
                    circuit_type
                ))
                .clone();

            create_light_base_layer_setup_data(
                circuit,
                &worker,
                BASE_LAYER_FRI_LDE_FACTOR,
                BASE_LAYER_CAP_SIZE,
            )
        }
        1..=4 => {
            let circuit = get_all_recursive_circuits(source)?
                .iter()
                .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                .expect(&format!(
                    "Could not find circuit matching {:?}",
                    circuit_type
                ))
                .clone();

            create_light_recursive_layer_setup_data(
                circuit,
                &worker,
                RECURSION_LAYER_FRI_LDE_FACTOR,
                RECURSION_LAYER_CAP_SIZE,
            )
        }
        5 => {
            let circuit = get_compression_circuits(source)
                .iter()
                .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                .expect(&format!(
                    "Could not find circuit matching {:?}",
                    circuit_type
                ))
                .clone();

            create_light_compression_layer_setup_data(
                circuit.clone(),
                &worker,
                circuit
                    .clone()
                    .proof_config_for_compression_step()
                    .fri_lde_factor,
                circuit
                    .proof_config_for_compression_step()
                    .merkle_tree_cap_size,
            )
        }
        6 => {
            let circuit = get_compression_for_wrapper_circuits(source)
                .iter()
                .find(|circuit| circuit.numeric_circuit_type() == circuit_type)
                .expect(&format!(
                    "Could not find circuit matching {:?}",
                    circuit_type
                ))
                .clone();

            create_light_compression_for_wrapper_setup_data(
                circuit.clone(),
                &worker,
                circuit
                    .clone()
                    .proof_config_for_compression_step()
                    .fri_lde_factor,
                circuit
                    .proof_config_for_compression_step()
                    .merkle_tree_cap_size,
            )
        }
        _ => unreachable!("Invalid proving stage"),
    };

    Ok(LightCircuitSetupData {
        setup_base,
        vk_geometry,
        vars_hint,
        wits_hint,
        finalization_hint,
    })
}
