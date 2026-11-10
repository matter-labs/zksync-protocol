use super::*;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::config::*;
use crate::boojum::cs::implementations::hints::*;
use crate::boojum::cs::implementations::polynomial_storage::*;
use crate::boojum::cs::implementations::verifier::*;
use crate::boojum::cs::oracle::merkle_tree::*;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::worker::Worker;
use crate::GoldilocksField;

use circuit_definitions::boojum::cs::implementations::reference_cs::CSReferenceAssembly;
use circuit_definitions::circuit_definitions::aux_layer::{compression::*, *};
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::verifier_builder::dyn_verifier_builder_for_recursive_circuit_type;
use circuit_definitions::circuit_definitions::recursion_layer::*;
use circuit_definitions::circuit_definitions::verifier_builder::dyn_verifier_builder_for_circuit_type;

use circuit_definitions::ZkSyncDefaultRoundFunction;

use crate::rescue_poseidon::poseidon2::transcript::Poseidon2Transcript;
use crate::rescue_poseidon::poseidon2::Poseidon2Sponge;
use crate::snark_wrapper::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use crate::snark_wrapper::implementations::poseidon2::tree_hasher::AbsorptionModeReplacement;

type F = GoldilocksField;

use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;

pub fn create_light_base_layer_setup_data(
    circuit: ZkSyncBaseLayerCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    VerificationKeyCircuitGeometry,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_base_layer(circuit);

    let (setup_base, vk_geometry, vars_hint, witness_hint) =
        cs.get_light_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        vk_geometry,
        vars_hint,
        witness_hint,
        finalization_hint,
    )
}

pub fn create_light_recursive_layer_setup_data(
    circuit: ZkSyncRecursiveLayerCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    VerificationKeyCircuitGeometry,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_recursive_layer(circuit);

    let (setup_base, vk_geometry, vars_hint, witness_hint) =
        cs.get_light_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        vk_geometry,
        vars_hint,
        witness_hint,
        finalization_hint,
    )
}

pub fn create_light_compression_layer_setup_data(
    circuit: ZkSyncCompressionLayerCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    VerificationKeyCircuitGeometry,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_compression(circuit);
    let (setup_base, vk_geometry, vars_hint, witness_hint) =
        cs.get_light_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        vk_geometry,
        vars_hint,
        witness_hint,
        finalization_hint,
    )
}

pub fn create_light_compression_for_wrapper_setup_data(
    circuit: ZkSyncCompressionForWrapperCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    VerificationKeyCircuitGeometry,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_compression_for_wrapper(circuit);

    let (setup_base, vk_geometry, vars_hint, witness_hint) =
        cs.get_light_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        vk_geometry,
        vars_hint,
        witness_hint,
        finalization_hint,
    )
}
