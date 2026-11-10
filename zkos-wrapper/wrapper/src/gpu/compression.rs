use std::alloc::Global;

use boojum::{
    config::{ProvingCSConfig, SetupCSConfig},
    cs::{
        cs_builder::new_builder,
        cs_builder_reference::CsReferenceImplementationBuilder,
        implementations::{pow::NoPow, prover::ProofConfig, setup::FinalizationHintsForProver},
        traits::circuit::CircuitBuilder,
    },
    field::goldilocks::GoldilocksField,
    worker::Worker,
};
use shivini::{
    cs::{GpuSetup, gpu_setup_and_vk_from_base_setup_vk_params_and_hints},
    gpu_proof_config::GpuProofConfig,
    gpu_prove_from_external_witness_data,
};

use crate::{
    CompressionCircuit, CompressionProof, CompressionTranscript, CompressionTreeHasher,
    CompressionVK, RiscWrapperProof, RiscWrapperVK,
};

type GL = GoldilocksField;

pub fn get_compression_setup(
    worker: &Worker,
    risc_wrapper_vk: RiscWrapperVK,
) -> (
    GpuSetup<CompressionTreeHasher>,
    CompressionVK,
    FinalizationHintsForProver,
) {
    let start = std::time::Instant::now();

    let circuit = CompressionCircuit::new(None, risc_wrapper_vk);

    let geometry = CompressionCircuit::geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GL, GL, SetupCSConfig>::new(
        geometry,
        max_trace_len.unwrap(),
    );
    let builder = new_builder::<_, GL>(builder_impl);

    let builder = CompressionCircuit::configure_builder(builder);
    let mut cs = builder.build(num_vars.unwrap());
    // compression circuit doesn't have any tables.
    circuit.synthesize_into_cs(&mut cs);
    let (_, finalization_hint) = cs.pad_and_shrink();

    let ProofConfig {
        fri_lde_factor,
        merkle_tree_cap_size,
        ..
    } = CompressionCircuit::get_proof_config();
    let cs = cs.into_assembly::<std::alloc::Global>();

    let (setup_base, vk_params, vars_hint, witness_hints) =
        cs.get_light_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    let (gpu_setup, gpu_vk) =
        gpu_setup_and_vk_from_base_setup_vk_params_and_hints::<CompressionTreeHasher, _>(
            setup_base.clone(),
            vk_params,
            vars_hint.clone(),
            witness_hints.clone(),
            &worker,
        )
        .unwrap();

    tracing::info!(
        "compression circuit setup takes {} ms",
        start.elapsed().as_millis()
    );

    (gpu_setup, gpu_vk, finalization_hint)
}

pub fn prove_compression(
    risc_wrapper_proof: RiscWrapperProof,
    risc_wrapper_vk: RiscWrapperVK,
    finalization_hint: &FinalizationHintsForProver,
    gpu_setup: &GpuSetup<CompressionTreeHasher>,
    gpu_vk: &CompressionVK,
    worker: &Worker,
) -> CompressionProof {
    let start = std::time::Instant::now();

    let circuit = CompressionCircuit::new(Some(risc_wrapper_proof), risc_wrapper_vk);

    let geometry = CompressionCircuit::geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GL, GL, ProvingCSConfig>::new(
        geometry,
        max_trace_len.unwrap(),
    );
    let builder = new_builder::<_, GL>(builder_impl);

    let builder = CompressionCircuit::configure_builder(builder);
    let mut cs = builder.build(num_vars.unwrap());
    // compression circuit doesn't have any tables.
    circuit.synthesize_into_cs(&mut cs);
    cs.pad_and_shrink_using_hint(finalization_hint);
    let cs = cs.into_assembly::<std::alloc::Global>();

    let gpu_proof_config = GpuProofConfig::from_assembly(&cs);

    let external_witness_data = cs.witness.unwrap();

    let proof_config = CompressionCircuit::get_proof_config();

    let proof = gpu_prove_from_external_witness_data::<
        CompressionTranscript,
        CompressionTreeHasher,
        NoPow,
        Global,
    >(
        &gpu_proof_config,
        &external_witness_data,
        proof_config,
        &gpu_setup,
        &gpu_vk,
        (),
        worker,
    )
    .unwrap();

    tracing::info!(
        "compression wrapper proving takes {} ms",
        start.elapsed().as_millis()
    );

    proof.into()
}
