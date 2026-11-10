#![feature(allocator_api)]
#![allow(incomplete_features)]
#![allow(unsafe_op_in_unsafe_fn)]
#![feature(generic_const_exprs)]

#[cfg(all(feature = "security_80", feature = "security_100"))]
compile_error!("features `security_80` and `security_100` are mutually exclusive in zkos-wrapper");

#[cfg(all(not(feature = "security_80"), not(feature = "security_100")))]
compile_error!("one of `security_80` or `security_100` must be enabled");

pub mod circuits;
mod inner_verifiers;
pub mod interface;
pub mod transcript;
mod wrapper;
pub mod wrapper_utils;

#[cfg(feature = "gpu")]
pub mod gpu;

#[cfg(test)]
mod tests;

use boojum::cs::implementations::witness;
use boojum::field::U64Representable;
pub use unified_reduced_machine_verifier as risc_verifier;

use bellman::rand;
use boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use boojum::config::{ProvingCSConfig, SetupCSConfig};
use boojum::cs::cs_builder::new_builder;
use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
#[cfg(feature = "gpu")]
use boojum::cs::implementations::fast_serialization::MemcopySerializable;
use boojum::cs::implementations::hints::DenseVariablesCopyHint;
use boojum::cs::implementations::hints::DenseWitnessCopyHint;
use boojum::cs::implementations::polynomial_storage::SetupBaseStorage;
use boojum::cs::implementations::polynomial_storage::SetupStorage;
use boojum::cs::implementations::pow::NoPow;
use boojum::cs::implementations::proof::Proof;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::setup::FinalizationHintsForProver;
use boojum::cs::implementations::verifier::VerificationKey;
use boojum::cs::oracle::merkle_tree::MerkleTreeWithCap;
use boojum::cs::traits::circuit::CircuitBuilder;
use boojum::cs::traits::circuit::CircuitBuilderProxy;
use boojum::dag::StCircuitResolver;
use boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;
use boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use boojum::implementations::poseidon2::Poseidon2Goldilocks;
pub use boojum::worker::Worker as BoojumWorker;
use boojum::worker::*;
use circuits::*;
use std::alloc::Global;
use std::path::Path;
use wrapper_utils::verifier_traits::CircuitBlake2sForEverythingVerifier;

use anyhow::Context as _;
pub use wrapper::{SnarkWrapper, SnarkWrapperConfig, SnarkWrapperHostCache};

pub(crate) mod active_security {
    #[cfg(feature = "security_80")]
    pub(crate) type ActiveSecurity =
        crate::risc_verifier::verifier_common::security_80::Security80Marker;
    #[cfg(feature = "security_100")]
    pub(crate) type ActiveSecurity =
        crate::risc_verifier::verifier_common::security_100::Security100Marker;

    #[cfg(feature = "security_80")]
    pub(crate) const ACTIVE_SECURITY_MODEL: crate::risc_verifier::verifier_common::SecurityModel =
        crate::risc_verifier::verifier_common::SecurityModel::Security80;
    #[cfg(feature = "security_100")]
    pub(crate) const ACTIVE_SECURITY_MODEL: crate::risc_verifier::verifier_common::SecurityModel =
        crate::risc_verifier::verifier_common::SecurityModel::Security100;
}

pub type GL = boojum::field::goldilocks::GoldilocksField;
pub type GLExt2 = boojum::field::goldilocks::GoldilocksExt2;
pub type RiscLeafInclusionVerifier = CircuitBlake2sForEverythingVerifier<GL>;
pub type RiscWrapper = RiscWrapperCircuit<GL, RiscLeafInclusionVerifier>;
pub type RiscWrapperTranscript =
    boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
pub type RiscWrapperTreeHasher = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
pub type RiscWrapperProof = Proof<GL, RiscWrapperTreeHasher, GLExt2>;
pub type RiscWrapperVK = VerificationKey<GL, RiscWrapperTreeHasher>;

pub type CircuitRiscWrapperTranscript =
    CircuitAlgebraicSpongeBasedTranscript<GL, 8, 12, 4, Poseidon2Goldilocks>;
pub type CircuitRiscWrapperTreeHasher = CircuitGoldilocksPoseidon2Sponge;

pub type RiscWrapperCircuitBuilder = CircuitBuilderProxy<GL, RiscWrapper>;

pub use rescue_poseidon::franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use rescue_poseidon::poseidon2::Poseidon2Sponge;
use rescue_poseidon::poseidon2::transcript::Poseidon2Transcript;

use snark_wrapper::implementations::poseidon2::tree_hasher::AbsorptionModeReplacement;

pub type CompressionPoW = Poseidon2Sponge<Bn256, GL, AbsorptionModeReplacement<Fr>, 2, 3>;
pub type CompressionTreeHasher = Poseidon2Sponge<Bn256, GL, AbsorptionModeReplacement<Fr>, 2, 3>;
pub type CompressionTranscript =
    Poseidon2Transcript<Bn256, GL, AbsorptionModeReplacement<Fr>, 2, 3>;

pub type CompressionProof = Proof<GL, CompressionTreeHasher, GLExt2>;
pub type CompressionVK = VerificationKey<GL, CompressionTreeHasher>;

pub type CompressionCircuitBuilder = CircuitBuilderProxy<GL, CompressionCircuit>;

use bellman::kate_commitment::{Crs, CrsForMonomialForm};
use bellman::plonk::better_better_cs::cs::Circuit as SnarkCircuit;
use bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use bellman::plonk::better_better_cs::cs::{ProvingAssembly, SetupAssembly};
use bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use bellman::plonk::better_better_cs::verifier::verify as verify_snark;
use boojum::ethereum_types::H256;
use snark_wrapper::implementations::poseidon2::CircuitPoseidon2Sponge;
use snark_wrapper::implementations::poseidon2::transcript::CircuitPoseidon2Transcript;

use bellman::worker::Worker as BellmanWorker;

pub type CircuitCompressionTreeHasher = CircuitPoseidon2Sponge<Bn256, 2, 3, 3, true>;
pub type CircuitCompressionTranscript = CircuitPoseidon2Transcript<Bn256, 2, 3, 3, true>;

pub type SnarkWrapperProof =
    bellman::plonk::better_better_cs::proof::Proof<Bn256, SnarkWrapperCircuit>;
pub type SnarkWrapperVK =
    bellman::plonk::better_better_cs::setup::VerificationKey<Bn256, SnarkWrapperCircuit>;
pub type SnarkWrapperSetup =
    bellman::plonk::better_better_cs::setup::Setup<Bn256, SnarkWrapperCircuit>;
pub type SnarkWrapperTranscript =
    bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript<Fr>;

use execution_utils::{
    ProgramProof,
    // RecursionStrategy,
    // generate_constants_for_binary
};

#[cfg(feature = "gpu")]
use proof_compression::serialization::PlonkSnarkVerifierCircuitDeviceSetupWrapper;

// RiscV -> Stark Wrapper
pub fn get_risc_wrapper_setup(
    worker: &Worker,
    binary_commitment: BinaryCommitment,
    check_aux_params: bool,
) -> (
    FinalizationHintsForProver,
    SetupBaseStorage<GL>,
    SetupStorage<GL>,
    RiscWrapperVK,
    MerkleTreeWithCap<GL, RiscWrapperTreeHasher>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
) {
    let circuit = RiscWrapper::new(None, false, binary_commitment, check_aux_params);

    let geometry = RiscWrapper::geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl =
        CsReferenceImplementationBuilder::<GL, GL, SetupCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            max_trace_len.unwrap(),
        );
    let builder = new_builder::<_, GL>(builder_impl);

    let builder = RiscWrapper::configure_builder(builder);
    let mut cs = builder.build(num_vars.unwrap());
    circuit.add_tables(&mut cs);
    circuit.synthesize_into_cs(&mut cs);
    let (_, finalization_hint) = cs.pad_and_shrink();

    let ProofConfig {
        fri_lde_factor,
        merkle_tree_cap_size,
        ..
    } = RiscWrapper::get_proof_config();
    let cs = cs.into_assembly::<Global>();
    cs.print_gate_stats();

    let (setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
        cs.get_full_setup::<RiscWrapperTreeHasher>(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        finalization_hint,
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
    )
}

pub fn prove_risc_wrapper(
    risc_wrapper_witness: RiscWrapperWitness,
    finalization_hint: &FinalizationHintsForProver,
    setup_base: &SetupBaseStorage<GL>,
    setup: &SetupStorage<GL>,
    vk: &RiscWrapperVK,
    setup_tree: &MerkleTreeWithCap<GL, RiscWrapperTreeHasher>,
    vars_hint: &DenseVariablesCopyHint,
    witness_hints: &DenseWitnessCopyHint,
    worker: &Worker,
    binary_commitment: BinaryCommitment,
    check_aux_params: bool,
) -> RiscWrapperProof {
    let circuit = RiscWrapper::new(
        Some(risc_wrapper_witness),
        true,
        binary_commitment,
        check_aux_params,
    );

    let geometry = RiscWrapper::geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl =
        CsReferenceImplementationBuilder::<GL, GL, ProvingCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            max_trace_len.unwrap(),
        );
    let builder = new_builder::<_, GL>(builder_impl);

    let builder = RiscWrapper::configure_builder(builder);
    let mut cs = builder.build(num_vars.unwrap());
    circuit.add_tables(&mut cs);
    circuit.synthesize_into_cs(&mut cs);
    cs.pad_and_shrink_using_hint(finalization_hint);
    let cs = cs.into_assembly::<Global>();

    let proof_config = RiscWrapper::get_proof_config();

    cs.prove_from_precomputations::<GLExt2, RiscWrapperTranscript, RiscWrapperTreeHasher, NoPow>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        witness_hints,
        (),
        worker,
    )
}

pub fn verify_risc_wrapper_proof(proof: &RiscWrapperProof, vk: &RiscWrapperVK) -> bool {
    let verifier_builder = RiscWrapperCircuitBuilder::dyn_verifier_builder();
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<RiscWrapperTreeHasher, RiscWrapperTranscript, NoPow>((), vk, proof)
}

// Stark -> Stark Compression
pub fn get_compression_setup(
    risc_wrapper_vk: RiscWrapperVK,
    worker: &Worker,
) -> (
    FinalizationHintsForProver,
    SetupBaseStorage<GL>,
    SetupStorage<GL>,
    CompressionVK,
    MerkleTreeWithCap<GL, CompressionTreeHasher>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
) {
    let circuit = CompressionCircuit::new(None, risc_wrapper_vk);

    let geometry = CompressionCircuit::geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl =
        CsReferenceImplementationBuilder::<GL, GL, SetupCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            max_trace_len.unwrap(),
        );
    let builder = new_builder::<_, GL>(builder_impl);

    let builder = CompressionCircuit::configure_builder(builder);
    let mut cs = builder.build(num_vars.unwrap());
    circuit.synthesize_into_cs(&mut cs);
    let (_, finalization_hint) = cs.pad_and_shrink();

    let ProofConfig {
        fri_lde_factor,
        merkle_tree_cap_size,
        ..
    } = CompressionCircuit::get_proof_config();
    let cs = cs.into_assembly::<Global>();

    let (setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
        cs.get_full_setup::<CompressionTreeHasher>(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        finalization_hint,
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
    )
}

pub fn prove_compression(
    risc_wrapper_proof: RiscWrapperProof,
    risc_wrapper_vk: RiscWrapperVK,
    finalization_hint: &FinalizationHintsForProver,
    setup_base: &SetupBaseStorage<GL>,
    setup: &SetupStorage<GL>,
    vk: &CompressionVK,
    setup_tree: &MerkleTreeWithCap<GL, CompressionTreeHasher>,
    vars_hint: &DenseVariablesCopyHint,
    witness_hints: &DenseWitnessCopyHint,
    worker: &Worker,
) -> CompressionProof {
    let circuit = CompressionCircuit::new(Some(risc_wrapper_proof), risc_wrapper_vk);

    let geometry = CompressionCircuit::geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl =
        CsReferenceImplementationBuilder::<GL, GL, ProvingCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            max_trace_len.unwrap(),
        );
    let builder = new_builder::<_, GL>(builder_impl);

    let builder = CompressionCircuit::configure_builder(builder);
    let mut cs = builder.build(num_vars.unwrap());
    circuit.synthesize_into_cs(&mut cs);
    cs.pad_and_shrink_using_hint(finalization_hint);
    let cs = cs.into_assembly::<Global>();

    let proof_config = CompressionCircuit::get_proof_config();

    cs.prove_from_precomputations::<GLExt2, CompressionTranscript, CompressionTreeHasher, NoPow>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        witness_hints,
        (),
        worker,
    )
}

pub fn verify_compression_proof(proof: &CompressionProof, vk: &CompressionVK) -> bool {
    let verifier_builder = CompressionCircuitBuilder::dyn_verifier_builder();
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<CompressionTreeHasher, CompressionTranscript, NoPow>((), vk, proof)
}

// Stark -> Snark Wrapper
pub const L1_VERIFIER_DOMAIN_SIZE_LOG: usize = 22;

pub fn create_snark_wrapper_setup(
    compression_vk: CompressionVK,
    worker: &BellmanWorker,
) -> SnarkWrapperSetup {
    let mut assembly = SetupAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fixed_parameters = compression_vk.fixed_parameters.clone();

    let wrapper_function = SnarkWrapperFunction;
    let wrapper_circuit = SnarkWrapperCircuit {
        witness: None,
        vk: compression_vk,
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };

    wrapper_circuit.synthesize(&mut assembly).unwrap();

    assembly.finalize_to_size_log_2(L1_VERIFIER_DOMAIN_SIZE_LOG);
    assert!(assembly.is_satisfied());

    let snark_setup = assembly
        .create_setup::<SnarkWrapperCircuit>(worker)
        .unwrap();

    snark_setup
}

pub fn derive_snark_wrapper_vk(
    snark_setup: &SnarkWrapperSetup,
    crs_mons: &Crs<Bn256, CrsForMonomialForm>,
    worker: &BellmanWorker,
) -> SnarkWrapperVK {
    SnarkWrapperVK::from_setup(snark_setup, worker, crs_mons).unwrap()
}

pub fn get_snark_wrapper_setup(
    compression_vk: CompressionVK,
    crs_mons: &Crs<Bn256, CrsForMonomialForm>,
    worker: &BellmanWorker,
) -> (SnarkWrapperSetup, SnarkWrapperVK) {
    let snark_setup = create_snark_wrapper_setup(compression_vk, worker);
    let snark_vk = derive_snark_wrapper_vk(&snark_setup, crs_mons, worker);

    (snark_setup, snark_vk)
}

pub fn prove_snark_wrapper(
    compression_proof: CompressionProof,
    compression_vk: CompressionVK,
    snark_setup: &SnarkWrapperSetup,
    crs_mons: &Crs<Bn256, CrsForMonomialForm>,
    worker: &BellmanWorker,
    // TODO!: Remove by end of Q4 2025.
    // Currently in place to allow a easy revert in case ZK proving causes issues.
    use_zk: bool,
) -> SnarkWrapperProof {
    let mut assembly = ProvingAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fixed_parameters = compression_vk.fixed_parameters.clone();

    let wrapper_function = SnarkWrapperFunction;
    let wrapper_circuit = SnarkWrapperCircuit {
        witness: Some(compression_proof),
        vk: compression_vk,
        fixed_parameters,
        transcript_params: (),
        wrapper_function,
    };

    wrapper_circuit.synthesize(&mut assembly).unwrap();

    if use_zk {
        tracing::info!("using zk (padding) proving");
        const NUM_PADDING_TERMS: usize = 2 + 2 + 2; // worst case witness polys are opened at 2 points, plus there are
        // indirect openings of grand product for permutation and for lookup
        let mut rng = rand::rngs::OsRng;
        assembly.finalize_to_size_log_2_with_randomization(
            L1_VERIFIER_DOMAIN_SIZE_LOG,
            NUM_PADDING_TERMS,
            &mut rng,
        );
    } else {
        tracing::info!("using non-zk (no padding) proving");
        assembly.finalize_to_size_log_2(L1_VERIFIER_DOMAIN_SIZE_LOG);
    }

    assert!(assembly.is_satisfied());

    assembly
        .create_proof::<SnarkWrapperCircuit, SnarkWrapperTranscript>(
            worker,
            snark_setup,
            crs_mons,
            None,
        )
        .unwrap()
}

pub fn verify_snark_wrapper_proof(proof: &SnarkWrapperProof, vk: &SnarkWrapperVK) -> bool {
    verify_snark::<Bn256, SnarkWrapperCircuit, SnarkWrapperTranscript>(vk, proof, None).unwrap()
}

// TODO: this should probably be moved somewhere into crypto.
pub fn calculate_verification_key_hash(verification_key: SnarkWrapperVK) -> H256 {
    use bellman::compact_bn256::Fq;
    use bellman::{CurveAffine, PrimeField, PrimeFieldRepr};
    use sha3::{Digest, Keccak256};

    let mut res = vec![];

    // gate setup commitments
    assert_eq!(8, verification_key.gate_setup_commitments.len());

    for gate_setup in verification_key.gate_setup_commitments {
        let (x, y) = gate_setup.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // gate selectors commitments
    assert_eq!(2, verification_key.gate_selectors_commitments.len());

    for gate_selector in verification_key.gate_selectors_commitments {
        let (x, y) = gate_selector.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // permutation commitments
    assert_eq!(4, verification_key.permutation_commitments.len());

    for permutation in verification_key.permutation_commitments {
        let (x, y) = permutation.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // lookup selector commitment
    let lookup_selector = verification_key.lookup_selector_commitment.unwrap();
    let (x, y) = lookup_selector.as_xy();
    x.into_repr().write_be(&mut res).unwrap();
    y.into_repr().write_be(&mut res).unwrap();

    // lookup tables commitments
    assert_eq!(4, verification_key.lookup_tables_commitments.len());

    for table_commit in verification_key.lookup_tables_commitments {
        let (x, y) = table_commit.as_xy();
        x.into_repr().write_be(&mut res).unwrap();
        y.into_repr().write_be(&mut res).unwrap();
    }

    // table type commitment
    let lookup_table = verification_key.lookup_table_type_commitment.unwrap();
    let (x, y) = lookup_table.as_xy();
    x.into_repr().write_be(&mut res).unwrap();
    y.into_repr().write_be(&mut res).unwrap();

    // flag for using recursive part
    Fq::default().into_repr().write_be(&mut res).unwrap();

    let mut hasher = Keccak256::new();
    hasher.update(&res);
    let computed_vk_hash = hasher.finalize();

    H256::from_slice(&computed_vk_hash)
}

/// Uploads trusted setup file to the RAM
pub fn get_trusted_setup(crs_file_str: &String) -> anyhow::Result<Crs<Bn256, CrsForMonomialForm>> {
    let crs_file_path = std::path::Path::new(crs_file_str);
    let crs_file = std::fs::File::open(&crs_file_path)
        .with_context(|| format!("Can't open CRS FILE: {:?}", crs_file_path))?;
    Crs::read(&crs_file).with_context(|| format!("Can't read CRS FILE: {:?}", crs_file_path))
}

pub fn serialize_to_file<T: serde::ser::Serialize>(
    content: &T,
    filename: &str,
) -> anyhow::Result<()> {
    let src =
        std::fs::File::create(filename).with_context(|| format!("Can't create file {filename}"))?;
    serde_json::to_writer_pretty(src, content)
        .with_context(|| format!("Can't serialize {filename}"))?;
    Ok(())
}

pub fn deserialize_from_file<T: serde::de::DeserializeOwned>(filename: &str) -> anyhow::Result<T> {
    let src =
        std::fs::File::open(filename).with_context(|| format!("Can't open file {filename}"))?;
    serde_json::from_reader(src)
        .with_context(|| format!("Can't deserialize the contents of file {filename}"))
}

pub fn prove_risc_wrapper_with_snark(
    risc_wrapper_proof: RiscWrapperProof,
    risc_wrapper_vk: RiscWrapperVK,
    trusted_setup_file: Option<String>,
    #[cfg(feature = "gpu")] precomputations: Option<&(
        PlonkSnarkVerifierCircuitDeviceSetupWrapper,
        SnarkWrapperVK,
    )>,
    // TODO!: Remove by end of Q4 2025.
    // Currently in place to allow a easy revert in case ZK proving causes issues.
    use_zk: bool,
) -> anyhow::Result<(SnarkWrapperProof, SnarkWrapperVK)> {
    let worker = boojum::worker::Worker::new();
    tracing::info!("=== Phase 2: Creating compression proof");

    #[cfg(feature = "gpu")]
    let (compression_proof, compression_vk) = {
        let config =
            shivini::ProverContextConfig::default().with_smallest_supported_domain_size(1 << 15);
        let _prover_context = shivini::ProverContext::create_with_config(config).unwrap();

        let (setup, compression_vk, finalization) =
            gpu::compression::get_compression_setup(&worker, risc_wrapper_vk.clone());
        let compression_proof = gpu::compression::prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk.clone(),
            &finalization,
            &setup,
            &compression_vk,
            &worker,
        );
        (compression_proof, compression_vk)
    };
    #[cfg(not(feature = "gpu"))]
    let (compression_proof, compression_vk) = {
        let (
            finalization_hint,
            setup_base,
            setup,
            compression_vk,
            setup_tree,
            vars_hint,
            witness_hints,
        ) = get_compression_setup(risc_wrapper_vk.clone(), &worker);
        let compression_proof = prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk,
            &finalization_hint,
            &setup_base,
            &setup,
            &compression_vk,
            &setup_tree,
            &vars_hint,
            &witness_hints,
            &worker,
        );
        (compression_proof, compression_vk)
    };

    let is_valid = verify_compression_proof(&compression_proof, &compression_vk);

    if !is_valid {
        return Err(anyhow::anyhow!("Compression proof is not valid"));
    }

    tracing::info!("=== Phase 3: Creating SNARK proof");

    #[cfg(feature = "gpu")]
    {
        tracing::info!("Using GPU for SNARK proof generation");
        let crs_file =
            trusted_setup_file.expect("Trusted setup must be set for GPU (and it must be compat");

        let precompute_store;

        let (setup_data, vk) = match precomputations {
            Some((setup_data, vk)) => {
                tracing::info!("Using provided precomputations");
                (setup_data, vk)
            }
            None => {
                precompute_store =
                    gpu::snark::gpu_create_snark_setup_data(&compression_vk, &crs_file, None);
                (&precompute_store.0, &precompute_store.1)
            }
        };

        let proof = crate::gpu::snark::gpu_snark_prove(
            setup_data,
            vk,
            compression_proof,
            compression_vk,
            &crs_file,
            use_zk,
        );
        Ok((proof, vk.clone()))
    }
    #[cfg(not(feature = "gpu"))]
    {
        let crs_mons = match trusted_setup_file {
            Some(ref crs_file_str) => get_trusted_setup(crs_file_str)?,
            None => Crs::<Bn256, CrsForMonomialForm>::crs_42(
                1 << L1_VERIFIER_DOMAIN_SIZE_LOG,
                &BellmanWorker::new(),
            ),
        };

        {
            let worker = BellmanWorker::new();

            let (snark_setup, snark_wrapper_vk) =
                get_snark_wrapper_setup(compression_vk.clone(), &crs_mons, &worker);

            let snark_wrapper_proof = prove_snark_wrapper(
                compression_proof,
                compression_vk,
                &snark_setup,
                &crs_mons,
                &worker,
                use_zk,
            );

            let is_valid = verify_snark_wrapper_proof(&snark_wrapper_proof, &snark_wrapper_vk);

            if !is_valid {
                return Err(anyhow::anyhow!("Snark wrapper proof is not valid"));
            }
            Ok((snark_wrapper_proof, snark_wrapper_vk))
        }
    }
}

// pub fn prove_fri_risc_wrapper(
//     program_proof: ProgramProof,
// ) -> Result<(RiscWrapperProof, RiscWrapperVK), Box<dyn std::error::Error>> {
//     tracing::info!("=== Phase 1: Creating the Risc wrapper proof");

//     let worker = boojum::worker::Worker::new();

//     let binary_commitment = BinaryCommitment {
//         end_params: program_proof.end_params,
//         aux_params: program_proof
//             .recursion_chain_hash
//             .expect("Recursion chain hash is missing only in base layer"),
//     };
//     let risc_wrapper_witness =
//         RiscWrapperWitness::from_full_proof(program_proof, &binary_commitment);

//     #[cfg(feature = "gpu")]
//     let (risc_wrapper_proof, risc_wrapper_vk) = {
//         let (setup, risc_wrapper_vk, finalization_hint) =
//             crate::gpu::risc_wrapper::get_risc_wrapper_setup(&worker, binary_commitment);
//         let risc_wrapper_proof = crate::gpu::risc_wrapper::prove_risc_wrapper(
//             risc_wrapper_witness,
//             &finalization_hint,
//             &setup,
//             &risc_wrapper_vk,
//             &worker,
//             binary_commitment,
//         );
//         (risc_wrapper_proof, risc_wrapper_vk)
//     };

//     #[cfg(not(feature = "gpu"))]
//     let (risc_wrapper_proof, risc_wrapper_vk) = {
//         let (
//             finalization_hint,
//             setup_base,
//             setup,
//             risc_wrapper_vk,
//             setup_tree,
//             vars_hint,
//             witness_hints,
//         ) = get_risc_wrapper_setup(&worker, binary_commitment.clone());

//         let risc_wrapper_proof = prove_risc_wrapper(
//             risc_wrapper_witness,
//             &finalization_hint,
//             &setup_base,
//             &setup,
//             &risc_wrapper_vk,
//             &setup_tree,
//             &vars_hint,
//             &witness_hints,
//             &worker,
//             binary_commitment,
//         );
//         (risc_wrapper_proof, risc_wrapper_vk)
//     };

//     let is_valid = verify_risc_wrapper_proof(&risc_wrapper_proof, &risc_wrapper_vk);
//     if !is_valid {
//         return Err("Risc wrapper proof is not valid".into());
//     }

//     Ok((risc_wrapper_proof, risc_wrapper_vk))
// }

// pub fn prove(
//     input: String,
//     output_dir: String,
//     trusted_setup_file: Option<String>,
//     risc_wrapper_only: bool,
//     #[cfg(feature = "gpu")] precomputations: Option<&(
//         PlonkSnarkVerifierCircuitDeviceSetupWrapper,
//         SnarkWrapperVK,
//     )>,
//     // TODO!: Remove by end of Q4 2025.
//     // Currently in place to allow a easy revert in case ZK proving causes issues.
//     use_zk: bool,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let program_proof: crate::ProgramProof = deserialize_from_file(&input);
//     let (risc_wrapper_proof, risc_wrapper_vk) = prove_fri_risc_wrapper(program_proof).unwrap();

//     if risc_wrapper_only {
//         serialize_to_file(
//             &risc_wrapper_vk,
//             &Path::new(&output_dir.clone()).join("risc_wrapper_vk.json"),
//         );
//         serialize_to_file(
//             &risc_wrapper_proof,
//             &Path::new(&output_dir.clone()).join("risc_wrapper_proof.json"),
//         );
//         return Ok(());
//     }

//     let (snark_wrapper_proof, snark_wrapper_vk) = prove_risc_wrapper_with_snark(
//         risc_wrapper_proof,
//         risc_wrapper_vk,
//         trusted_setup_file.clone(),
//         #[cfg(feature = "gpu")]
//         precomputations,
//         use_zk,
//     )
//     .unwrap();

//     serialize_to_file(
//         &snark_wrapper_proof,
//         &Path::new(&output_dir.clone()).join("snark_proof.json"),
//     );
//     serialize_to_file(
//         &snark_wrapper_vk,
//         &Path::new(&output_dir.clone()).join("snark_vk.json"),
//     );

//     Ok(())
// }

// pub fn generate_and_save_risc_wrapper_vk(
//     input_binary: String,
//     output_dir: String,
//     universal_verifier: bool,
//     recursion_mode: RecursionStrategy,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let boojum_worker = BoojumWorker::new();
//     let risc_wrapper_vk = generate_risk_wrapper_vk(
//         Some(input_binary),
//         universal_verifier,
//         recursion_mode,
//         &boojum_worker,
//     )?;

//     serialize_to_file(
//         &risc_wrapper_vk,
//         &Path::new(&output_dir.clone()).join("risc_wrapper_vk_expected.json"),
//     );
//     Ok(())
// }

// pub fn generate_risk_wrapper_vk(
//     input_binary: Option<String>,
//     universal_verifier: bool,
//     recursion_mode: RecursionStrategy,
//     boojum_worker: &Worker,
// ) -> Result<RiscWrapperVK, Box<dyn std::error::Error>> {
//     let bin = std::fs::read(input_binary.unwrap()).unwrap();

//     let (end_params, aux_params) =
//         generate_constants_for_binary(&bin, recursion_mode, universal_verifier, true);

//     let binary_commitment = BinaryCommitment {
//         end_params,
//         aux_params,
//     };

//     #[cfg(feature = "gpu")]
//     let (_, risc_wrapper_vk, _) =
//         crate::gpu::risc_wrapper::get_risc_wrapper_setup(boojum_worker, binary_commitment);

//     #[cfg(not(feature = "gpu"))]
//     let (_, _, _, risc_wrapper_vk, _, _, _) =
//         get_risc_wrapper_setup(boojum_worker, binary_commitment);
//     Ok(risc_wrapper_vk)
// }

// pub fn generate_vk(
//     input_binary: Option<String>,
//     output_dir: String,
//     trusted_setup_file: Option<String>,
//     universal_verifier: bool,
//     recursion_mode: RecursionStrategy,
// ) -> Result<H256, Box<dyn std::error::Error>> {
//     let boojum_worker = boojum::worker::Worker::new();

//     tracing::info!("=== Phase 1: Creating the Risc wrapper key");

//     let risc_wrapper_vk = generate_risk_wrapper_vk(
//         input_binary,
//         universal_verifier,
//         recursion_mode,
//         &boojum_worker,
//     )?;

//     tracing::info!("=== Phase 2: Creating the Compression key");
//     let (_, _, _, compression_vk, _, _, _) =
//         get_compression_setup(risc_wrapper_vk.clone(), &boojum_worker);

//     tracing::info!("=== Phase 3: Creating the SNARK key");

//     #[cfg(feature = "gpu")]
//     let snark_wrapper_vk = {
//         tracing::info!("Using GPU for SNARK key generation");
//         let crs_file =
//             trusted_setup_file.expect("Trusted setup must be set for GPU (and it must be compat");
//         let (preprocessing, snark_wrapper_vk) =
//             crate::gpu::snark::gpu_create_snark_setup_data(&compression_vk, &crs_file);

//         let output_file = Path::new(&output_dir).join("snark_preprocessing.bin");
//         let file = std::fs::File::create(output_file).unwrap();
//         preprocessing.write_into_buffer(file).unwrap();

//         snark_wrapper_vk
//     };
//     #[cfg(not(feature = "gpu"))]
//     let snark_wrapper_vk = {
//         let worker = BellmanWorker::new();

//         let crs_mons = match trusted_setup_file {
//             Some(ref crs_file_str) => get_trusted_setup(crs_file_str),
//             None => Crs::<Bn256, CrsForMonomialForm>::crs_42(
//                 1 << L1_VERIFIER_DOMAIN_SIZE_LOG,
//                 &BellmanWorker::new(),
//             ),
//         };

//         let (_, snark_wrapper_vk) =
//             get_snark_wrapper_setup(compression_vk.clone(), &crs_mons, &worker);
//         snark_wrapper_vk
//     };

//     serialize_to_file(
//         &snark_wrapper_vk,
//         &Path::new(&output_dir.clone()).join("snark_vk_expected.json"),
//     );

//     let verification_key = calculate_verification_key_hash(snark_wrapper_vk);
//     tracing::info!("VK key hash: {verification_key:?}");

//     Ok(verification_key)
// }

pub fn verification_hash(vk_path: String) -> anyhow::Result<()> {
    let vk = deserialize_from_file(&vk_path).context("Can't deserialize VK")?;
    let vk_hash = calculate_verification_key_hash(vk);
    tracing::info!("VK hash: {vk_hash:?}");
    Ok(())
}
