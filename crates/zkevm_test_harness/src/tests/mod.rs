use super::*;

pub mod complex_tests;
#[cfg(test)]
pub mod run_manually;
#[cfg(test)]
pub mod simple_tests;
#[cfg(test)]
pub(crate) mod storage;
#[cfg(test)]
pub(crate) mod utils;

use crate::blake2::Blake2s256;
use crate::boojum::worker::Worker;
use crate::ethereum_types::Address;
use crate::ethereum_types::H160;
use crate::ethereum_types::U256;
use crate::witness::tree::BinarySparseStorageTree;
use crate::witness::tree::ZkSyncStorageLeaf;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::bytecode_to_code_hash;
use crate::zk_evm::testing::storage::InMemoryStorage;
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::ZkSyncRecursiveLayerCircuit;
use circuit_definitions::ZkSyncDefaultRoundFunction;
use std::alloc::Global;
use std::collections::HashMap;

const ACCOUNT_CODE_STORAGE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x02,
]);

const KNOWN_CODE_HASHES_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x04,
]);

pub(crate) fn save_predeployed_contracts(
    storage: &mut InMemoryStorage,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    contracts: &HashMap<Address, Vec<[u8; 32]>>,
) {
    let mut sorted_contracts = vec![];
    let mut keys: Vec<_> = contracts.keys().cloned().collect();
    keys.sort();
    for el in keys.into_iter() {
        let v = contracts[&el].clone();

        sorted_contracts.push((el, v));
    }

    let storage_logs: Vec<(u8, Address, U256, U256)> = sorted_contracts
        .clone()
        .into_iter()
        .map(|(address, bytecode)| {
            let hash = bytecode_to_code_hash(&bytecode).unwrap();

            println!(
                "Have address {:?} with code hash {:x}",
                address,
                U256::from(hash)
            );

            vec![
                (
                    0,
                    ACCOUNT_CODE_STORAGE_ADDRESS,
                    U256::from_big_endian(address.as_bytes()),
                    U256::from(hash),
                ),
                (
                    0,
                    KNOWN_CODE_HASHES_ADDRESS,
                    U256::from(hash),
                    U256::from(1u64),
                ),
            ]
        })
        .flatten()
        .collect();

    storage.populate(storage_logs.clone());

    for (shard_id, address, key, value) in storage_logs.into_iter() {
        assert!(shard_id == 0);
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        use crate::witness::tree::EnumeratedBinaryLeaf;
        let mut leaf = ZkSyncStorageLeaf::empty();
        let mut buffer = [0u8; 32];
        value.to_big_endian(&mut buffer);
        leaf.set_value(&buffer);

        tree.insert_leaf(&index, leaf);
    }
}

pub(crate) fn base_test_circuit(circuit: ZkSyncBaseLayerCircuit) {
    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    type P = GoldilocksField;
    // type P = MixedGL;

    let worker = Worker::new();

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    use crate::boojum::config::CSConfig;
    let builder_impl = CsReferenceImplementationBuilder::<
        GoldilocksField,
        P,
        DevCSConfig,
        crate::boojum::dag::StCircuitResolver<
            GoldilocksField,
            <DevCSConfig as CSConfig>::ResolverConfig,
        >,
    >::new(geometry, max_trace_len.unwrap());
    let arg = num_vars.unwrap();
    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let mut cs = match circuit {
        ZkSyncBaseLayerCircuit::MainVM(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<Global>()
        }
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::ECRecover(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(arg);
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::Modexp(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::ECAdd(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::ECMul(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncBaseLayerCircuit::ECPairing(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables_proxy(&mut cs);
            inner.synthesize_proxy(&mut cs);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
    };

    let is_satisfied = cs.check_if_satisfied(&worker);
    assert!(is_satisfied);
}

pub(crate) fn test_recursive_circuit(circuit: ZkSyncRecursiveLayerCircuit) {
    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

    type P = GoldilocksField;
    // type P = MixedGL;

    let worker = Worker::new();

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    use crate::boojum::config::CSConfig;
    let builder_impl = CsReferenceImplementationBuilder::<
        GoldilocksField,
        P,
        DevCSConfig,
        crate::boojum::dag::StCircuitResolver<
            GoldilocksField,
            <DevCSConfig as CSConfig>::ResolverConfig,
        >,
    >::new(geometry, max_trace_len.unwrap());
    let builder = new_builder::<_, GoldilocksField>(builder_impl);
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut cs = match circuit {
        ZkSyncRecursiveLayerCircuit::SchedulerCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<Global>()
        }
        ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let _ = cs.pad_and_shrink();
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
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForEIP4844Repack(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForModexp(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForECAdd(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForECMul(inner)
        | ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForECPairing(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
        ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(inner) => {
            let builder = inner.configure_builder_proxy(builder);
            let mut cs = builder.build(num_vars.unwrap());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs, &round_function);
            let _ = cs.pad_and_shrink();
            cs.into_assembly::<std::alloc::Global>()
        }
    };

    let is_satisfied = cs.check_if_satisfied(&worker);
    assert!(is_satisfied);
}

use circuit_definitions::circuit_definitions::aux_layer::*;
pub(crate) fn test_compression_circuit(circuit: ZkSyncCompressionLayerCircuit) {
    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;
    use circuit_definitions::circuit_definitions::aux_layer::compression::CompressionLayerCircuit;
    use circuit_definitions::circuit_definitions::aux_layer::compression::ProofCompressionFunction;

    type P = GoldilocksField;
    // type P = MixedGL;

    let worker = Worker::new();

    fn test_inner<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
    ) -> CSReferenceAssembly<GoldilocksField, P, DevCSConfig> {
        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();
        let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, DevCSConfig>::new(
            geometry,
            max_trace_len.unwrap(),
        );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = circuit.configure_builder_proxy(builder);
        let mut cs = builder.build(num_vars.unwrap());
        circuit.synthesize_into_cs(&mut cs);

        cs.pad_and_shrink();
        cs.into_assembly::<std::alloc::Global>()
    }

    let mut cs = match circuit {
        ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(inner) => test_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(inner) => test_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(inner) => test_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(inner) => test_inner(inner),
        ZkSyncCompressionLayerCircuit::CompressionMode5Circuit(inner) => test_inner(inner),
    };

    let is_satisfied = cs.check_if_satisfied(&worker);
    assert!(is_satisfied);
}

pub(crate) fn test_compression_for_wrapper_circuit(circuit: ZkSyncCompressionForWrapperCircuit) {
    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;
    use circuit_definitions::circuit_definitions::aux_layer::compression::CompressionLayerCircuit;
    use circuit_definitions::circuit_definitions::aux_layer::compression::ProofCompressionFunction;

    type P = GoldilocksField;
    // type P = MixedGL;

    let worker = Worker::new();

    fn test_inner<CF: ProofCompressionFunction>(
        circuit: CompressionLayerCircuit<CF>,
    ) -> CSReferenceAssembly<GoldilocksField, P, DevCSConfig> {
        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();

        let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, DevCSConfig>::new(
            geometry,
            max_trace_len.unwrap(),
        );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = circuit.configure_builder_proxy(builder);
        let mut cs = builder.build(num_vars.unwrap());
        circuit.synthesize_into_cs(&mut cs);

        cs.pad_and_shrink();
        cs.into_assembly::<std::alloc::Global>()
    }

    let mut cs = match circuit {
        ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(inner) => test_inner(inner),
        ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(inner) => test_inner(inner),
        ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(inner) => test_inner(inner),
        ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(inner) => test_inner(inner),
        ZkSyncCompressionForWrapperCircuit::CompressionMode5Circuit(inner) => test_inner(inner),
    };

    let is_satisfied = cs.check_if_satisfied(&worker);
    assert!(is_satisfied);
}
