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

type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;

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
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
        geometry,
        max_trace_len.unwrap(),
    );

    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let (cs, finalization_hint) = match circuit {
        ZkSyncBaseLayerCircuit::MainVM(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::ECRecover(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
    };

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
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    let round_function = ZkSyncDefaultRoundFunction::default();

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
        geometry,
        max_trace_len.unwrap(),
    );
    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let (cs, finalization_hint) = match circuit {
        ZkSyncRecursiveLayerCircuit::SchedulerCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
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
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
        ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
        }
    };

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
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    fn synthesize_inner<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
    ) -> (
        CSReferenceAssembly<GoldilocksField, GoldilocksField, SetupCSConfig>,
        FinalizationHintsForProver,
    ) {
        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();

        let builder_impl =
            CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
                geometry,
                max_trace_len.unwrap(),
            );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);

        let builder = circuit.configure_builder_proxy(builder);
        let mut cs = builder.build(num_vars.unwrap());
        circuit.add_tables(&mut cs);
        circuit.synthesize_into_cs(&mut cs);
        let (_, finalization_hint) = cs.pad_and_shrink();
        (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
    }

    let (cs, finalization_hint) = match circuit {
        ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode5Circuit(inner) => synthesize_inner(inner),
    };

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
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    fn synthesize_inner<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
    ) -> (
        CSReferenceAssembly<GoldilocksField, GoldilocksField, SetupCSConfig>,
        FinalizationHintsForProver,
    ) {
        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();

        let builder_impl =
            CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
                geometry,
                max_trace_len.unwrap(),
            );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);

        let builder = circuit.configure_builder_proxy(builder);
        let mut cs = builder.build(num_vars.unwrap());
        circuit.add_tables(&mut cs);
        circuit.synthesize_into_cs(&mut cs);
        let (_, finalization_hint) = cs.pad_and_shrink();
        (cs.into_assembly::<std::alloc::Global>(), finalization_hint)
    }

    let (cs, finalization_hint) = match circuit {
        ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(inner) => {
            synthesize_inner(inner)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(inner) => {
            synthesize_inner(inner)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(inner) => {
            synthesize_inner(inner)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(inner) => {
            synthesize_inner(inner)
        }
        ZkSyncCompressionForWrapperCircuit::CompressionMode5Circuit(inner) => {
            synthesize_inner(inner)
        }
    };

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
