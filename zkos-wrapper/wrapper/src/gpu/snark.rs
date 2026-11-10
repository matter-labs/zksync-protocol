use anyhow::Context as _;
use bellman::rand;
use proof_compression::{
    PlonkSnarkWrapperLogN, ProofSystemDefinition, SnarkWrapperProofSystem,
    hardcoded_canonical_g2_bases,
    serialization::{GenericWrapper, PlonkSnarkVerifierCircuitDeviceSetupWrapper},
};
use zksync_gpu_prover::{
    AsyncSetup,
    bellman::{
        bn256::Bn256,
        kate_commitment::{Crs, CrsForMonomialForm},
        plonk::better_better_cs::{
            cs::{
                Assembly, Circuit, PlonkCsWidth4WithNextStepAndCustomGatesParams,
                SynthesisModeGenerateSetup, SynthesisModeProve,
            },
            gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
        },
    },
};

use crate::{
    CompressionProof, CompressionVK, L1_VERIFIER_DOMAIN_SIZE_LOG, SnarkWrapperCircuit,
    SnarkWrapperFunction, SnarkWrapperProof, SnarkWrapperVK,
};

type PlonkSnarkWrapper = PlonkSnarkWrapperLogN<L1_VERIFIER_DOMAIN_SIZE_LOG>;
pub(crate) type CompactRawCrs = <PlonkSnarkWrapper as SnarkWrapperProofSystem>::CRS;
type PlonkDeviceContext = <PlonkSnarkWrapper as SnarkWrapperProofSystem>::Context;
pub(crate) type PlonkDeviceManager = <PlonkDeviceContext as GenericWrapper>::Inner;

// The code below is based off the zkos-compressor code.
// Unfortunately we were not able to use zkos-compressor directly (for example PlonkSnarkWrapper) - as the Compression circuit here is different.

pub(crate) fn gpu_load_compact_raw_crs(crs_file: &str) -> anyhow::Result<CompactRawCrs> {
    let reader = std::fs::File::open(crs_file)
        .with_context(|| format!("while attempting to open compact CRS at {crs_file}"))?;

    <PlonkSnarkWrapper as SnarkWrapperProofSystem>::load_compact_raw_crs(reader)
        .context("while attempting to deserialize compact CRS")
}

pub(crate) fn gpu_create_snark_device_manager(
    crs_mons: &CompactRawCrs,
) -> anyhow::Result<PlonkDeviceManager> {
    Ok(PlonkSnarkWrapper::init_context(crs_mons)
        .context("while attempting to initialize the PLONK GPU context")?
        .into_inner())
}

/// Creates setup data (precomputations and verification key) for a given circuit.
/// crs_file must point at **compact** CRS.
pub fn gpu_create_snark_setup_data(
    compression_vk: &CompressionVK,
    crs_file: &str,
    provided_vk: Option<&SnarkWrapperVK>,
) -> (PlonkSnarkVerifierCircuitDeviceSetupWrapper, SnarkWrapperVK) {
    let crs_mons = gpu_load_compact_raw_crs(crs_file).unwrap();
    let mut device_manager = gpu_create_snark_device_manager(&crs_mons).unwrap();
    gpu_create_snark_setup_data_with_manager(compression_vk, &mut device_manager, provided_vk)
        .unwrap()
}

pub(crate) fn gpu_create_snark_setup_data_with_manager(
    compression_vk: &CompressionVK,
    device_manager: &mut PlonkDeviceManager,
    provided_vk: Option<&SnarkWrapperVK>,
) -> anyhow::Result<(PlonkSnarkVerifierCircuitDeviceSetupWrapper, SnarkWrapperVK)> {
    type PlonkAssembly<CSConfig> = Assembly<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
        CSConfig,
        zksync_gpu_prover::cuda_bindings::CudaAllocator,
    >;

    // reimplementing stuff in precompute_plonk_wrapper_circuit (as we have different compression circuit).
    let fixed_parameters = compression_vk.fixed_parameters.clone();
    let wrapper_function = SnarkWrapperFunction;
    let wrapper_circuit = SnarkWrapperCircuit {
        witness: None,
        vk: compression_vk.clone(),
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };

    let mut setup_assembly = PlonkAssembly::<SynthesisModeGenerateSetup>::new();

    wrapper_circuit
        .synthesize(&mut setup_assembly)
        .expect("must work");

    let hardcoded_finalization_hint = L1_VERIFIER_DOMAIN_SIZE_LOG;

    // It used finalization hint instead (fine - it is 24 for plonk, and 23 for fflonk).
    setup_assembly.finalize_to_size_log_2(hardcoded_finalization_hint);
    assert!(setup_assembly.is_satisfied());

    let worker = zksync_gpu_prover::bellman::worker::Worker::new();
    let mut precomputation = zksync_gpu_prover::AsyncSetup::<
        <PlonkSnarkWrapper as ProofSystemDefinition>::Allocator,
    >::allocate(1 << hardcoded_finalization_hint);
    precomputation
        .generate_from_assembly(&worker, &setup_assembly, device_manager)
        .map_err(|error| {
            anyhow::anyhow!("while attempting to generate SNARK setup precomputation: {error:?}")
        })?;

    let vk = match provided_vk {
        Some(vk) => vk.clone(),
        None => {
            let hardcoded_g2_bases = hardcoded_canonical_g2_bases();
            let mut dummy_crs = Crs::<bellman::bn256::Bn256, CrsForMonomialForm>::dummy_crs(1);
            dummy_crs.g2_monomial_bases = std::sync::Arc::new(hardcoded_g2_bases.to_vec());
            zksync_gpu_prover::compute_vk_from_assembly::<
                _,
                _,
                PlonkCsWidth4WithNextStepAndCustomGatesParams,
                SynthesisModeGenerateSetup,
            >(device_manager, &setup_assembly, &dummy_crs)
            .map_err(|error| {
                anyhow::anyhow!("while attempting to compute SNARK verification key: {error:?}")
            })?
        }
    };

    device_manager.free_all_slots();

    Ok((
        PlonkSnarkVerifierCircuitDeviceSetupWrapper::from_inner(precomputation),
        vk,
    ))
}

/// Computes the SnarkProof for a given compression proof.
pub fn gpu_snark_prove(
    precomputation: &PlonkSnarkVerifierCircuitDeviceSetupWrapper,
    snark_wrapper_vk: &SnarkWrapperVK,
    compression_proof: CompressionProof,
    compression_vk: CompressionVK,
    crs_file: &str,
    // TODO!: Remove by end of Q4 2025.
    // Currently in place to allow a easy revert in case ZK proving causes issues.
    use_zk: bool,
) -> SnarkWrapperProof {
    let crs_mons = gpu_load_compact_raw_crs(crs_file).unwrap();
    let mut device_manager = gpu_create_snark_device_manager(&crs_mons).unwrap();
    gpu_snark_prove_with_manager(
        precomputation,
        snark_wrapper_vk,
        compression_proof,
        compression_vk,
        &mut device_manager,
        use_zk,
    )
    .unwrap()
}

pub(crate) fn gpu_snark_prove_with_manager(
    precomputation: &PlonkSnarkVerifierCircuitDeviceSetupWrapper,
    snark_wrapper_vk: &SnarkWrapperVK,
    compression_proof: CompressionProof,
    compression_vk: CompressionVK,
    device_manager: &mut PlonkDeviceManager,
    // TODO!: Remove by end of Q4 2025.
    // Currently in place to allow a easy revert in case ZK proving causes issues.
    use_zk: bool,
) -> anyhow::Result<SnarkWrapperProof> {
    let finalization_hint: usize = 1 << L1_VERIFIER_DOMAIN_SIZE_LOG;
    let input_proof = compression_proof;
    // Recreate stuff from prove_plonk_snark_wrapper_step

    let fixed_parameters = compression_vk.fixed_parameters.clone();

    let wrapper_function = SnarkWrapperFunction;
    let circuit = SnarkWrapperCircuit {
        witness: Some(input_proof),
        vk: compression_vk.clone(),
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };
    type PlonkAssembly<CSConfig> = Assembly<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
        CSConfig,
        zksync_gpu_prover::cuda_bindings::CudaAllocator,
    >;

    let mut proving_assembly = PlonkAssembly::<SynthesisModeProve>::new();

    circuit
        .synthesize(&mut proving_assembly)
        .expect("must work");

    let precomputation: &AsyncSetup = precomputation.into_inner_ref();

    assert!(proving_assembly.is_satisfied());
    assert!(finalization_hint.is_power_of_two());
    if use_zk {
        tracing::info!("using zk (padding) proving");
        const NUM_PADDING_TERMS: usize = 2 + 2 + 2; // worst case witness polys are opened at 2 points, plus there are
        // indirect openings of grand product for permutation and for lookup
        let mut rng = rand::rngs::OsRng;
        proving_assembly.finalize_to_size_log_2_with_randomization(
            finalization_hint.trailing_zeros() as usize,
            NUM_PADDING_TERMS,
            &mut rng,
        );
    } else {
        tracing::info!("using non-zk (no padding) proving");
        proving_assembly.finalize_to_size_log_2(finalization_hint.trailing_zeros() as usize);
    }
    let domain_size = proving_assembly.n() + 1;
    assert!(domain_size.is_power_of_two());
    assert!(domain_size == finalization_hint);

    let worker = zksync_gpu_prover::bellman::worker::Worker::new();
    let start = std::time::Instant::now();
    let proof = zksync_gpu_prover::create_proof::<
        _,
        _,
        <PlonkSnarkWrapper as ProofSystemDefinition>::Transcript,
        _,
    >(
        &proving_assembly,
        device_manager,
        &worker,
        precomputation,
        None,
    )
    .map_err(|error| anyhow::anyhow!("while attempting to create SNARK proof: {error:?}"))?;

    tracing::info!("plonk proving takes {} s", start.elapsed().as_secs());
    device_manager.free_all_slots();

    let result = zksync_gpu_prover::bellman::plonk::better_better_cs::verifier::verify::<
        _,
        _,
        <PlonkSnarkWrapper as ProofSystemDefinition>::Transcript,
    >(snark_wrapper_vk, &proof, None)
    .map_err(|error| anyhow::anyhow!("while attempting to verify SNARK proof: {error:?}"))?;

    if !result {
        anyhow::bail!("SNARK proof failed to verify");
    }
    Ok(proof)
}
