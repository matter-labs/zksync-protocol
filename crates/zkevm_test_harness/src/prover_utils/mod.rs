mod full;
pub mod light;

use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;
use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;
use circuit_definitions::boojum::config::SetupCSConfig;
use circuit_definitions::boojum::cs::cs_builder::new_builder;
use circuit_definitions::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::circuit_definitions::aux_layer::compression::{
    CompressionLayerCircuit, ProofCompressionFunction,
};
use circuit_definitions::circuit_definitions::aux_layer::{
    ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionForWrapperVerificationKey,
    ZkSyncCompressionLayerCircuit, ZkSyncCompressionLayerVerificationKey,
    ZkSyncCompressionVerificationKey, ZkSyncCompressionVerificationKeyForWrapper,
};
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::{
    ZkSyncRecursionLayerProof, ZkSyncRecursionLayerVerificationKey, ZkSyncRecursionProof,
    ZkSyncRecursionVerificationKey, ZkSyncRecursiveLayerCircuit,
};
use circuit_definitions::ZkSyncDefaultRoundFunction;
pub use full::*;

type P = GoldilocksField;

fn get_cs_finalization_hint_for_base_layer(
    circuit: ZkSyncBaseLayerCircuit,
) -> (
    CSReferenceAssembly<GoldilocksField, P, SetupCSConfig>,
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

    match circuit {
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
    }
}

fn get_cs_finalization_hint_for_recursive_layer(
    circuit: ZkSyncRecursiveLayerCircuit,
) -> (
    CSReferenceAssembly<GoldilocksField, P, SetupCSConfig>,
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

    match circuit {
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
    }
}

fn get_cs_finalization_hint_for_compression(
    circuit: ZkSyncCompressionLayerCircuit,
) -> (
    CSReferenceAssembly<GoldilocksField, P, SetupCSConfig>,
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

    match circuit {
        ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(inner) => synthesize_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode5Circuit(inner) => synthesize_inner(inner),
    }
}

fn get_cs_finalization_hint_for_compression_for_wrapper(
    circuit: ZkSyncCompressionForWrapperCircuit,
) -> (
    CSReferenceAssembly<GoldilocksField, P, SetupCSConfig>,
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

    match circuit {
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
    }
}

pub fn load_scheduler_vk(path: &str) -> ZkSyncRecursionVerificationKey {
    let vk_file = std::fs::File::open(format!("{}/scheduler_recursive_vk.json", path)).unwrap();
    let vk: ZkSyncRecursionLayerVerificationKey = serde_json::from_reader(&vk_file).unwrap();
    vk.into_inner()
}

pub fn load_compression_vk(path: &str, mode: usize) -> ZkSyncRecursionVerificationKey {
    let vk_file = std::fs::File::open(format!("{}/compression_{}_vk.json", path, mode)).unwrap();
    let vk: ZkSyncRecursionVerificationKey = serde_json::from_reader(&vk_file).unwrap();

    vk
}

#[test]
fn test_cs_finalization_hint() {
    let path = "./data";

    let scheduler_vk_file =
        std::fs::File::open(format!("{}/scheduler_recursive_vk.json", path)).unwrap();
    let scheduler_vk: ZkSyncRecursionLayerVerificationKey =
        serde_json::from_reader(&scheduler_vk_file).unwrap();
    let circuit =
        ZkSyncCompressionLayerCircuit::from_witness_and_vk(None, scheduler_vk.into_inner(), 1);
    assert_eq!(
        get_cs_finalization_hint_for_compression(circuit.clone()).1,
        get_cs_finalization_hint_for_compression(circuit).1,
    );
    let vk = load_compression_vk(&path, 1);
    let circuit = ZkSyncCompressionLayerCircuit::from_witness_and_vk(None, vk, 2);
    assert_eq!(
        get_cs_finalization_hint_for_compression(circuit.clone()).1,
        get_cs_finalization_hint_for_compression(circuit).1,
    );
    let vk = load_compression_vk(&path, 2);
    let circuit = ZkSyncCompressionLayerCircuit::from_witness_and_vk(None, vk, 3);
    assert_eq!(
        get_cs_finalization_hint_for_compression(circuit.clone()).1,
        get_cs_finalization_hint_for_compression(circuit).1,
    );
    let vk = load_compression_vk(&path, 3);
    let circuit = ZkSyncCompressionLayerCircuit::from_witness_and_vk(None, vk, 4);
    assert_eq!(
        get_cs_finalization_hint_for_compression(circuit.clone()).1,
        get_cs_finalization_hint_for_compression(circuit).1,
    );
    let vk = load_compression_vk(&path, 4);
    let circuit = ZkSyncCompressionForWrapperCircuit::from_witness_and_vk(None, vk, 5);
    assert_eq!(
        get_cs_finalization_hint_for_compression_for_wrapper(circuit.clone()).1,
        get_cs_finalization_hint_for_compression_for_wrapper(circuit).1,
    );
}
