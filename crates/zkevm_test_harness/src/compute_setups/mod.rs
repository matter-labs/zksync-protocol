use super::*;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::data_source::SetupDataSource;
use circuit_definitions::boojum::cs::implementations::verifier::VerificationKey;
use circuit_definitions::circuit_definitions::aux_layer::compression::{
    CompressionMode1Circuit, CompressionMode1ForWrapperCircuit, CompressionMode2Circuit,
    CompressionMode2ForWrapperCircuit, CompressionMode3Circuit, CompressionMode3ForWrapperCircuit,
    CompressionMode4Circuit, CompressionMode4ForWrapperCircuit, CompressionMode5Circuit,
    CompressionMode5ForWrapperCircuit, ProofCompressionFunction,
};
use circuit_definitions::circuit_definitions::aux_layer::{
    ZkSyncCompressionForWrapperCircuit, ZkSyncCompressionLayerCircuit,
};
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::ZkSyncLeafLayerRecursiveCircuit;
use circuit_definitions::circuit_definitions::recursion_layer::{base_circuit_type_into_recursive_leaf_circuit_type, ZkSyncRecursionLayerStorageType, ZkSyncRecursiveLayerCircuit, RECURSION_ARITY, SCHEDULER_CAPACITY, circuit_def};
use circuit_definitions::circuit_definitions::ZkSyncUniformCircuitInstance;
use circuit_definitions::recursion_layer_proof_config;
use circuit_definitions::zkevm_circuits::eip_4844::input::ELEMENTS_PER_4844_BLOCK;
use circuit_definitions::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use circuit_definitions::zkevm_circuits::recursion::leaf_layer::input::RecursionLeafParametersWitness;
use circuit_definitions::zkevm_circuits::recursion::NUM_BASE_LAYER_CIRCUITS;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_sequencer_api::toolset::GeometryConfig;
use crossbeam::atomic::AtomicCell;
use std::collections::VecDeque;
use std::sync::Arc;
use circuit_definitions::circuit_definitions::aux_layer::compression_modes::{CompressionMode1, CompressionMode2, CompressionMode3, CompressionMode4};

use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;

mod full;
pub mod light;

pub use full::*;

fn get_compression_circuits(
    source: &mut dyn SetupDataSource,
) -> Vec<ZkSyncCompressionLayerCircuit> {
    vec![
        ZkSyncCompressionLayerCircuit::CompressionMode1Circuit(CompressionMode1Circuit {
            witness: None,
            config: CompressionRecursionConfig {
                proof_config: recursion_layer_proof_config(),
                // recursion circuit 1 is scheduler
                verification_key: source.get_recursion_layer_vk(1).unwrap().into_inner(),
                _marker: Default::default(),
            },
            transcript_params: (),
            _marker: Default::default(),
        }),
        ZkSyncCompressionLayerCircuit::CompressionMode2Circuit(CompressionMode2Circuit {
            witness: None,
            config: CompressionRecursionConfig {
                proof_config: CompressionMode1::proof_config_for_compression_step(),
                verification_key: source.get_compression_vk(1).unwrap().into_inner(),
                _marker: Default::default(),
            },
            transcript_params: (),
            _marker: Default::default(),
        }),
        ZkSyncCompressionLayerCircuit::CompressionMode3Circuit(CompressionMode3Circuit {
            witness: None,
            config: CompressionRecursionConfig {
                proof_config: CompressionMode2::proof_config_for_compression_step(),
                verification_key: source.get_compression_vk(2).unwrap().into_inner(),
                _marker: Default::default(),
            },
            transcript_params: (),
            _marker: Default::default(),
        }),
        ZkSyncCompressionLayerCircuit::CompressionMode4Circuit(CompressionMode4Circuit {
            witness: None,
            config: CompressionRecursionConfig {
                proof_config: CompressionMode3::proof_config_for_compression_step(),
                verification_key: source.get_compression_vk(3).unwrap().into_inner(),
                _marker: Default::default(),
            },
            transcript_params: (),
            _marker: Default::default(),
        }),
        ZkSyncCompressionLayerCircuit::CompressionMode5Circuit(CompressionMode5Circuit {
            witness: None,
            config: CompressionRecursionConfig {
                proof_config: CompressionMode4::proof_config_for_compression_step(),
                verification_key: source.get_compression_vk(4).unwrap().into_inner(),
                _marker: Default::default(),
            },
            transcript_params: (),
            _marker: Default::default(),
        }),
    ]
}

fn get_compression_for_wrapper_circuits(
    source: &mut dyn SetupDataSource,
) -> Vec<ZkSyncCompressionForWrapperCircuit> {
    vec![
        ZkSyncCompressionForWrapperCircuit::CompressionMode1Circuit(
            CompressionMode1ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: recursion_layer_proof_config(),
                    verification_key: source.get_compression_vk(1).unwrap().into_inner(),
                    _marker: Default::default(),
                },
                transcript_params: (),
                _marker: Default::default(),
            },
        ),
        ZkSyncCompressionForWrapperCircuit::CompressionMode2Circuit(
            CompressionMode2ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode1::proof_config_for_compression_step(),
                    verification_key: source.get_compression_vk(2).unwrap().into_inner(),
                    _marker: Default::default(),
                },
                transcript_params: (),
                _marker: Default::default(),
            },
        ),
        ZkSyncCompressionForWrapperCircuit::CompressionMode3Circuit(
            CompressionMode3ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode2::proof_config_for_compression_step(),
                    verification_key: source.get_compression_vk(3).unwrap().into_inner(),
                    _marker: Default::default(),
                },
                transcript_params: (),
                _marker: Default::default(),
            },
        ),
        ZkSyncCompressionForWrapperCircuit::CompressionMode4Circuit(
            CompressionMode4ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode3::proof_config_for_compression_step(),
                    verification_key: source.get_compression_vk(4).unwrap().into_inner(),
                    _marker: Default::default(),
                },
                transcript_params: (),
                _marker: Default::default(),
            },
        ),
        ZkSyncCompressionForWrapperCircuit::CompressionMode5Circuit(
            CompressionMode5ForWrapperCircuit {
                witness: None,
                config: CompressionRecursionConfig {
                    proof_config: CompressionMode4::proof_config_for_compression_step(),
                    verification_key: source.get_compression_vk(5).unwrap().into_inner(),
                    _marker: Default::default(),
                },
                transcript_params: (),
                _marker: Default::default(),
            },
        ),
    ]
}

/// Returns all types of basic circuits, with empty witnesses.
/// Can be used for things like verification key generation.
fn get_all_basic_circuits(geometry: &GeometryConfig) -> Vec<ZkSyncBaseLayerCircuit> {
    vec![
        ZkSyncBaseLayerCircuit::MainVM(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_code_decommitter_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::CodeDecommitter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),

            config: Arc::new(geometry.cycles_per_code_decommitter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::LogDemuxer(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_log_demuxer as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_keccak256_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_sha256_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::ECRecover(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_ecrecover_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::RAMPermutation(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_ram_permutation as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::StorageSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_storage_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::StorageApplication(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_storage_application as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::EventsSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_events_or_l1_messages_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::L1MessagesSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_events_or_l1_messages_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::L1MessagesHasher(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.limit_for_l1_messages_pudata_hasher as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::TransientStorageSorter(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_transient_storage_sorter as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::Secp256r1Verify(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(geometry.cycles_per_secp256r1_verify_circuit as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
        ZkSyncBaseLayerCircuit::EIP4844Repack(ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(None),
            config: Arc::new(ELEMENTS_PER_4844_BLOCK as usize),
            round_function: Arc::new(Poseidon2Goldilocks),
            expected_public_input: None,
        }),
    ]
}

/// Returns all the recursive circuits (including leaves, nodes and scheduler).
/// Source must contain the verification keys for basic layer, leaf and node.
fn get_all_recursive_circuits(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<ZkSyncRecursiveLayerCircuit>> {
    let mut result = get_leaf_circuits(source)?;

    result.push(get_node_circuit(source)?);
    result.push(get_recursion_tip_circuit(source)?);
    result.push(get_scheduler_circuit(source)?);
    return Ok(result);
}

/// Returns all the leaf circuits.
fn get_leaf_circuits(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<Vec<ZkSyncRecursiveLayerCircuit>> {
    let mut result = vec![];

    for base_circuit_type in ((BaseLayerCircuitType::VM as u8)
        ..=(BaseLayerCircuitType::Secp256r1Verify as u8))
        .chain(std::iter::once(BaseLayerCircuitType::EIP4844Repack as u8))
    {
        let _recursive_circuit_type = base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(base_circuit_type),
        );

        use crate::zkevm_circuits::recursion::leaf_layer::input::*;
        let input = RecursionLeafInput::placeholder_witness();
        let vk = source.get_base_layer_vk(base_circuit_type)?;

        use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
        let witness = RecursionLeafInstanceWitness {
            input,
            vk_witness: vk.clone().into_inner(),
            queue_witness: FullStateCircuitQueueRawWitness {
                elements: VecDeque::new(),
            },
            proof_witnesses: VecDeque::new(),
        };

        use crate::zkevm_circuits::recursion::leaf_layer::LeafLayerRecursionConfig;
        let config = LeafLayerRecursionConfig {
            proof_config: recursion_layer_proof_config(),
            vk_fixed_parameters: vk.into_inner().fixed_parameters,
            capacity: RECURSION_ARITY,
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncLeafLayerRecursiveCircuit {
            base_layer_circuit_type: BaseLayerCircuitType::from_numeric_value(base_circuit_type),
            witness: witness,
            config: config,
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncRecursiveLayerCircuit::leaf_circuit_from_base_type(
            BaseLayerCircuitType::from_numeric_value(base_circuit_type),
            circuit,
        );
        result.push(circuit);
    }
    return Ok(result);
}

/// Returns the node circuit.
fn get_node_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::recursion::node_layer::input::*;
    let input = RecursionNodeInput::placeholder_witness();
    let vk = source
        .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM as u8)?;

    // the only thing to setup here is to have proper number of split points
    use crate::boojum::gadgets::queue::QueueTailState;
    let split_points = vec![
        QueueTailState::<GoldilocksField, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder_witness();
        RECURSION_ARITY - 1
    ];
    let witness = RecursionNodeInstanceWitness {
        input,
        vk_witness: vk.clone().into_inner(),
        split_points: split_points.into(),
        proof_witnesses: VecDeque::new(),
    };

    use crate::zkevm_circuits::recursion::node_layer::NodeLayerRecursionConfig;
    use circuit_definitions::circuit_definitions::recursion_layer::node_layer::ZkSyncNodeLayerRecursiveCircuit;
    let config = NodeLayerRecursionConfig {
        proof_config: recursion_layer_proof_config(),
        vk_fixed_parameters: vk.into_inner().fixed_parameters,
        leaf_layer_capacity: RECURSION_ARITY,
        node_layer_capacity: RECURSION_ARITY,
        _marker: std::marker::PhantomData,
    };
    let circuit = ZkSyncNodeLayerRecursiveCircuit {
        witness,
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    Ok(ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(circuit))
}

/// Returns the recursion tip circuit
fn get_recursion_tip_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::recursion::recursion_tip::input::*;
    let input = RecursionTipInput::placeholder_witness();
    let vk = source.get_recursion_layer_node_vk()?.into_inner();

    let witness = RecursionTipInstanceWitness {
        input,
        vk_witness: vk.clone(),
        proof_witnesses: VecDeque::new(),
    };

    use crate::zkevm_circuits::recursion::recursion_tip::*;
    use circuit_definitions::circuit_definitions::recursion_layer::recursion_tip::*;

    let config = RecursionTipConfig {
        proof_config: recursion_layer_proof_config(),
        vk_fixed_parameters: vk.fixed_parameters,
        _marker: std::marker::PhantomData,
    };

    let circuit = RecursionTipCircuit {
        witness,
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    Ok(ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(circuit))
}

/// Returns the scheduler circuit.
/// Source must contain the leafs, node and tip verification keys.
fn get_scheduler_circuit(
    source: &mut dyn SetupDataSource,
) -> crate::data_source::SourceResult<ZkSyncRecursiveLayerCircuit> {
    use crate::zkevm_circuits::scheduler::SchedulerConfig;
    use circuit_definitions::circuit_definitions::recursion_layer::scheduler::SchedulerCircuit;

    println!("Computing leaf params");
    let leaf_layer_params = compute_leaf_params(source)?;
    println!("Obtaining node VK");
    let node_vk = source.get_recursion_layer_node_vk()?.into_inner();
    println!("Obtaining recursion tip VK");
    let recursion_tip_vk = source.get_recursion_tip_vk()?.into_inner();

    let leaf_layer_params: [RecursionLeafParametersWitness<GoldilocksField>;
        NUM_BASE_LAYER_CIRCUITS] = leaf_layer_params
        .into_iter()
        .map(|el| el.1)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let config = SchedulerConfig {
        proof_config: recursion_layer_proof_config(),
        leaf_layer_parameters: leaf_layer_params,
        node_layer_vk: node_vk,
        recursion_tip_vk: recursion_tip_vk.clone(),
        vk_fixed_parameters: recursion_tip_vk.fixed_parameters.clone(),
        capacity: SCHEDULER_CAPACITY,
        _marker: std::marker::PhantomData,
    };

    use crate::zkevm_circuits::scheduler::input::SchedulerCircuitInstanceWitness;
    let scheduler_witness = SchedulerCircuitInstanceWitness::placeholder();

    let scheduler_circuit = SchedulerCircuit {
        witness: scheduler_witness,
        config,
        transcript_params: (),
        _marker: std::marker::PhantomData,
    };

    Ok(ZkSyncRecursiveLayerCircuit::SchedulerCircuit(
        scheduler_circuit,
    ))
}
