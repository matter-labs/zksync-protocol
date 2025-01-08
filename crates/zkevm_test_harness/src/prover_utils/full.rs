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
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;

type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;

use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;

pub fn create_base_layer_setup_data(
    circuit: ZkSyncBaseLayerCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    SetupStorage<F, P>,
    VerificationKey<F, H>,
    MerkleTreeWithCap<F, H>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_base_layer(circuit);

    let (setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
        cs.get_full_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
        finalization_hint,
    )
}

use crate::boojum::cs::implementations::proof::Proof;
use crate::boojum::cs::implementations::prover::ProofConfig;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;

use crate::boojum::cs::implementations::pow::PoWRunner;

pub fn prove_base_layer_circuit<POW: PoWRunner>(
    circuit: ZkSyncBaseLayerCircuit,
    worker: &Worker,
    proof_config: ProofConfig,
    setup_base: &SetupBaseStorage<F, P>,
    setup: &SetupStorage<F, P>,
    setup_tree: &MerkleTreeWithCap<F, H>,
    vk: &VerificationKey<F, H>,
    vars_hint: &DenseVariablesCopyHint,
    wits_hint: &DenseWitnessCopyHint,
    finalization_hint: &FinalizationHintsForProver,
) -> Proof<F, H, EXT> {
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, ProvingCSConfig>::new(
        geometry,
        max_trace_len.unwrap(),
    );
    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let cs = match circuit {
        ZkSyncBaseLayerCircuit::MainVM(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::ECRecover(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
    };

    cs.prove_from_precomputations::<EXT, TR, H, POW>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        wits_hint,
        (),
        worker,
    )
}

pub fn verify_base_layer_proof<POW: PoWRunner>(
    circuit: &ZkSyncBaseLayerCircuit,
    proof: &Proof<F, H, EXT>,
    vk: &VerificationKey<F, H>,
) -> bool {
    let verifier_builder = dyn_verifier_builder_for_circuit_type(circuit.numeric_circuit_type());
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<H, TR, POW>((), vk, proof)
}

pub fn verify_base_layer_proof_for_type<POW: PoWRunner>(
    circuit_type: u8,
    proof: &Proof<F, H, EXT>,
    vk: &VerificationKey<F, H>,
) -> bool {
    let verifier_builder = dyn_verifier_builder_for_circuit_type(circuit_type);
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<H, TR, POW>((), vk, proof)
}

pub fn create_recursive_layer_setup_data(
    circuit: ZkSyncRecursiveLayerCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    SetupStorage<F, P>,
    VerificationKey<F, H>,
    MerkleTreeWithCap<F, H>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_recursive_layer(circuit);

    let (setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
        cs.get_full_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
        finalization_hint,
    )
}

pub fn prove_recursion_layer_circuit<POW: PoWRunner>(
    circuit: ZkSyncRecursiveLayerCircuit,
    worker: &Worker,
    proof_config: ProofConfig,
    setup_base: &SetupBaseStorage<F, P>,
    setup: &SetupStorage<F, P>,
    setup_tree: &MerkleTreeWithCap<F, H>,
    vk: &VerificationKey<F, H>,
    vars_hint: &DenseVariablesCopyHint,
    wits_hint: &DenseWitnessCopyHint,
    finalization_hint: &FinalizationHintsForProver,
) -> Proof<F, H, EXT> {
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    let round_function = ZkSyncDefaultRoundFunction::default();

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    use crate::boojum::config::CSConfig;
    let builder_impl = CsReferenceImplementationBuilder::<
        GoldilocksField,
        P,
        ProvingCSConfig,
        crate::boojum::dag::StCircuitResolver<
            GoldilocksField,
            <ProvingCSConfig as CSConfig>::ResolverConfig,
        >,
    >::new(geometry, max_trace_len.unwrap());
    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let cs = match circuit {
        ZkSyncRecursiveLayerCircuit::SchedulerCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForMainVM(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForCodeDecommittmentsSorter(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForCodeDecommitter(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForLogDemuxer(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForKeccakRoundFunction(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForSha256RoundFunction(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForECRecover(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForRAMPermutation(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForStorageSorter(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForStorageApplication(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForEventsSorter(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForL1MessagesSorter(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForL1MessagesHasher(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForTransientStorageSorter(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForSecp256r1Verify(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForEIP4844Repack(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly::<std::alloc::Global>()
        }
    };

    cs.prove_from_precomputations::<EXT, TR, H, POW>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        wits_hint,
        (),
        worker,
    )
}

pub fn verify_recursion_layer_proof<POW: PoWRunner>(
    circuit: &ZkSyncRecursiveLayerCircuit,
    proof: &Proof<F, H, EXT>,
    vk: &VerificationKey<F, H>,
) -> bool {
    let verifier_builder = circuit.into_dyn_verifier_builder();
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<H, TR, POW>((), vk, proof)
}

pub fn verify_recursion_layer_proof_for_type<POW: PoWRunner>(
    circuit_type: ZkSyncRecursionLayerStorageType,
    proof: &Proof<F, H, EXT>,
    vk: &VerificationKey<F, H>,
) -> bool {
    let verifier_builder = dyn_verifier_builder_for_recursive_circuit_type(circuit_type);
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<H, TR, POW>((), vk, proof)
}

pub fn create_compression_layer_setup_data(
    circuit: ZkSyncCompressionLayerCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    SetupStorage<F, P>,
    VerificationKey<F, H>,
    MerkleTreeWithCap<F, H>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_compression(circuit);
    let (setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
        cs.get_full_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
        finalization_hint,
    )
}

pub fn prove_compression_layer_circuit<POW: PoWRunner>(
    circuit: ZkSyncCompressionLayerCircuit,
    worker: &Worker,
    proof_config: ProofConfig,
    setup_base: &SetupBaseStorage<F, P>,
    setup: &SetupStorage<F, P>,
    setup_tree: &MerkleTreeWithCap<F, H>,
    vk: &VerificationKey<F, H>,
    vars_hint: &DenseVariablesCopyHint,
    wits_hint: &DenseWitnessCopyHint,
    finalization_hint: &FinalizationHintsForProver,
) -> Proof<F, H, EXT> {
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    fn synthesize_inner<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
        finalization_hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<GoldilocksField, GoldilocksField, ProvingCSConfig> {
        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();

        let builder_impl =
            CsReferenceImplementationBuilder::<GoldilocksField, P, ProvingCSConfig>::new(
                geometry,
                max_trace_len.unwrap(),
            );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);

        let builder = circuit.configure_builder_proxy(builder);
        let mut cs = builder.build(num_vars.unwrap());
        circuit.add_tables(&mut cs);
        circuit.synthesize_into_cs(&mut cs);
        cs.pad_and_shrink_using_hint(finalization_hint);
        cs.into_assembly::<std::alloc::Global>()
    }

    let cs = match circuit {
        ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionLayerCircuit::CompressionMode5Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
    };

    cs.prove_from_precomputations::<EXT, TR, H, POW>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        wits_hint,
        (),
        worker,
    )
}

pub fn verify_compression_layer_proof<POW: PoWRunner>(
    circuit: &ZkSyncCompressionLayerCircuit,
    proof: &Proof<F, H, EXT>,
    vk: &VerificationKey<F, H>,
) -> bool {
    let verifier_builder = circuit.into_dyn_verifier_builder();
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<H, TR, POW>((), vk, proof)
}

pub type TreeHasherForWrapper = Poseidon2Sponge<Bn256, F, AbsorptionModeReplacement<Fr>, 2, 3>;
pub type TranscriptForWrapper = Poseidon2Transcript<Bn256, F, AbsorptionModeReplacement<Fr>, 2, 3>;

pub fn create_compression_for_wrapper_setup_data(
    circuit: ZkSyncCompressionForWrapperCircuit,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P>,
    SetupStorage<F, P>,
    VerificationKey<F, TreeHasherForWrapper>,
    MerkleTreeWithCap<F, TreeHasherForWrapper>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
) {
    let (cs, finalization_hint) = get_cs_finalization_hint_for_compression_for_wrapper(circuit);

    let (setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
        cs.get_full_setup(worker, fri_lde_factor, merkle_tree_cap_size);

    (
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
        finalization_hint,
    )
}

pub fn prove_compression_for_wrapper_circuit<POW: PoWRunner>(
    circuit: ZkSyncCompressionForWrapperCircuit,
    worker: &Worker,
    proof_config: ProofConfig,
    setup_base: &SetupBaseStorage<F, P>,
    setup: &SetupStorage<F, P>,
    setup_tree: &MerkleTreeWithCap<F, TreeHasherForWrapper>,
    vk: &VerificationKey<F, TreeHasherForWrapper>,
    vars_hint: &DenseVariablesCopyHint,
    wits_hint: &DenseWitnessCopyHint,
    finalization_hint: &FinalizationHintsForProver,
) -> Proof<F, TreeHasherForWrapper, EXT> {
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    fn synthesize_inner<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
        finalization_hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<GoldilocksField, GoldilocksField, ProvingCSConfig> {
        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();

        let builder_impl =
            CsReferenceImplementationBuilder::<GoldilocksField, P, ProvingCSConfig>::new(
                geometry,
                max_trace_len.unwrap(),
            );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);

        let builder = circuit.configure_builder_proxy(builder);
        let mut cs = builder.build(num_vars.unwrap());
        circuit.add_tables(&mut cs);
        circuit.synthesize_into_cs(&mut cs);
        cs.pad_and_shrink_using_hint(finalization_hint);
        cs.into_assembly::<std::alloc::Global>()
    }

    let cs = match circuit {
        ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode5Circuit(inner) => {
            synthesize_inner(inner, finalization_hint)
        }
    };

    cs.prove_from_precomputations::<EXT, TranscriptForWrapper, TreeHasherForWrapper, POW>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        wits_hint,
        (),
        worker,
    )
}

pub fn verify_compression_for_wrapper_proof<POW: PoWRunner>(
    circuit: &ZkSyncCompressionForWrapperCircuit,
    proof: &Proof<F, TreeHasherForWrapper, EXT>,
    vk: &VerificationKey<F, TreeHasherForWrapper>,
) -> bool {
    let verifier_builder = circuit.into_dyn_verifier_builder();
    let verifier = verifier_builder.create_verifier();
    verifier.verify::<TreeHasherForWrapper, TranscriptForWrapper, POW>((), vk, proof)
}
