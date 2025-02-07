use circuit_definitions::{
    base_layer_proof_config,
    circuit_definitions::base_layer::{
        ECPairingFunctionInstanceSynthesisFunction, ZkSyncBaseLayerCircuit,
    },
    ZkSyncDefaultRoundFunction, BASE_LAYER_CAP_SIZE, BASE_LAYER_FRI_LDE_FACTOR,
};
use circuit_encodings::{
    boojum::{
        cs::implementations::pow::NoPow,
        field::{goldilocks::GoldilocksField, SmallField},
        gadgets::queue::QueueStateWitness,
        worker::Worker,
    },
    ethereum_types::{Address, U256},
    memory_query::CustomMemoryQueueSimulator,
    zk_evm::{
        abstractions::{Memory, MemoryType, PrecompileCyclesWitness, PrecompilesProcessor},
        aux_structures::{
            LogQuery, MemoryIndex, MemoryLocation, MemoryPage, MemoryQuery, Timestamp,
        },
        reference_impls::memory::SimpleMemory,
        zk_evm_abstractions::precompiles::DefaultPrecompilesProcessor,
    },
    LogQueueSimulator,
};
use zkevm_assembly::zkevm_opcode_defs::{
    PrecompileCallABI, ECPAIRING_PRECOMPILE_ADDRESS, PRECOMPILE_AUX_BYTE,
};

use crate::{
    prover_utils::{
        create_base_layer_setup_data, prove_base_layer_circuit, verify_base_layer_proof,
    },
    witness::{
        artifacts::LogQueueStates,
        aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator,
        individual_circuits::memory_related::{
            ecpairing::{ecpairing_decompose_into_per_circuit_witness, ecpairing_memory_queries},
            SimulatorSnapshot,
        },
        postprocessing::CircuitMaker,
    },
};

fn fill_memory<M: Memory>(tuples: Vec<[[u8; 32]; 6]>, page: u32, memory: &mut M) -> u16 {
    let mut location = MemoryLocation {
        page: MemoryPage(page),
        index: MemoryIndex(0),
        memory_type: MemoryType::Heap,
    };

    for i in 0..tuples.len() {
        for j in 0..6 {
            let query = MemoryQuery {
                timestamp: Timestamp(0u32),
                location,
                value: U256::from_big_endian(&tuples[i][j]),
                rw_flag: true,
                value_is_pointer: false,
            };
            let _ = memory.execute_partial_query((6 * i + j) as u32, query);
            location.index.0 += 1;
        }
    }

    6 * tuples.len() as u16
}

fn get_simulator_snapshot<F: SmallField>(
    memory_queue_simulator: &mut CustomMemoryQueueSimulator<F>,
) -> SimulatorSnapshot<F, 12> {
    SimulatorSnapshot {
        head: memory_queue_simulator.head,
        tail: memory_queue_simulator.tail,
        num_items: memory_queue_simulator.num_items,
    }
}

fn simulate_subqueue(
    memory_queries: &Vec<MemoryQuery>,
    memory_states: &mut Vec<QueueStateWitness<GoldilocksField, 12>>,
    memory_queue_states_accumulator: &mut LastPerCircuitAccumulator<
        QueueStateWitness<GoldilocksField, 12>,
    >,
) -> (
    Vec<SimulatorSnapshot<GoldilocksField, 12>>,
    CustomMemoryQueueSimulator<GoldilocksField>,
) {
    let mut memory_queue_simulator = CustomMemoryQueueSimulator::<GoldilocksField>::new();
    memory_states.reserve_exact(memory_queries.len());
    let mut snapshots = vec![];
    let round_function = ZkSyncDefaultRoundFunction::default();
    snapshots.push(get_simulator_snapshot(&mut memory_queue_simulator)); // before
    for query in memory_queries.iter() {
        let (_old_tail, state_witness) =
            memory_queue_simulator.push_and_output_queue_state_witness(*query, &round_function);

        memory_states.push(state_witness.clone());
        memory_queue_states_accumulator.push(state_witness);
    }
    snapshots.push(get_simulator_snapshot(&mut memory_queue_simulator)); // after

    (snapshots, memory_queue_simulator)
}

/// Returns precompile success, and precompile returned value
fn test_ecpairing_using_tuples(tuples: Vec<[[u8; 32]; 6]>) -> (U256, U256) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<true>;

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);
    let num_pairings = tuples.len() as u64;
    let num_words_used = fill_memory(tuples, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 1,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: num_pairings,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECPAIRING_PRECOMPILE_ADDRESS as u64);

    let precompile_query = LogQuery {
        timestamp: Timestamp(1u32),
        tx_number_in_block: 0,
        shard_id: 0,
        aux_byte: PRECOMPILE_AUX_BYTE,
        address,
        key: precompile_call_params_encoded,
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let result: Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        circuit_encodings::zk_evm::abstractions::PrecompileCyclesWitness,
    )> = precompiles_processor.execute_precompile(4, precompile_query, &mut memory);
    let (_reads, writes, witness) = result.unwrap();
    assert_eq!(2, writes.len());

    let witness = match witness {
        PrecompileCyclesWitness::ECPairing(witness) => witness,
        _ => panic!(),
    };

    // simulating 'ecpairing_witness
    let ecpairing_witnesses = vec![(4, precompile_query, witness)];

    let ecpairing_memory_queries = ecpairing_memory_queries(&ecpairing_witnesses);

    let mut ecpairing_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (ecpairing_simulator_snapshots, _simulator) = simulate_subqueue(
        &ecpairing_memory_queries,
        &mut ecpairing_memory_states,
        &mut states_accumulator2,
    );

    let ecpairing_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_ecpairing_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = ecpairing_decompose_into_per_circuit_witness(
        ecpairing_memory_queries,
        ecpairing_simulator_snapshots,
        ecpairing_memory_states,
        ecpairing_witnesses,
        ecpairing_queries,
        demuxed_ecpairing_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ECPairingFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECPairingPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECPairing(basic_circuit);
        create_base_layer_setup_data(
            basic_circuit.clone(),
            &worker,
            BASE_LAYER_FRI_LDE_FACTOR,
            BASE_LAYER_CAP_SIZE,
        )
    };
    let circuits = ecpairing_circuits_data.len();

    for (i, circuit) in ecpairing_circuits_data.into_iter().enumerate() {
        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ECPairingFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECPairingPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECPairing(basic_circuit);

        println!("Proving! {} / {}   ", i + 1, circuits);
        let now = std::time::Instant::now();

        let proof = prove_base_layer_circuit::<NoPow>(
            basic_circuit.clone(),
            &worker,
            base_layer_proof_config(),
            &setup_base,
            &setup,
            &setup_tree,
            &vk,
            &vars_hint,
            &wits_hint,
            &finalization_hint,
        );

        println!("Proving is DONE, taken {:?}", now.elapsed());

        let is_valid = verify_base_layer_proof::<NoPow>(&basic_circuit, &proof, &vk);
        assert!(is_valid);
    }

    (writes[0].value, writes[1].value)
}

fn test_ecpairing_from_hex(raw_input: &str) -> (U256, U256) {
    let input_bytes = hex::decode(raw_input).unwrap();

    assert!(
        input_bytes.len() % 192 == 0,
        "number of input bytes must be divisible by 192"
    );

    let tuples_number = input_bytes.len() / 192;
    let mut tuples = vec![[[0u8; 32]; 6]; tuples_number];

    for i in 0..tuples_number {
        let x1: [u8; 32] = input_bytes[192 * i..192 * i + 32].try_into().unwrap();
        let y1: [u8; 32] = input_bytes[192 * i + 32..192 * i + 64].try_into().unwrap();
        let x2: [u8; 32] = input_bytes[192 * i + 64..192 * i + 96].try_into().unwrap();
        let y2: [u8; 32] = input_bytes[192 * i + 96..192 * i + 128].try_into().unwrap();
        let x3: [u8; 32] = input_bytes[192 * i + 128..192 * i + 160]
            .try_into()
            .unwrap();
        let y3: [u8; 32] = input_bytes[192 * i + 160..192 * i + 192]
            .try_into()
            .unwrap();

        tuples[i] = [x1, y1, x2, y2, x3, y3];
    }
    test_ecpairing_using_tuples(tuples)
}

#[test]
// Single pair - should return true.
fn ec_pairing_single_test() {
    let raw_input = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

    let (success, result) = test_ecpairing_from_hex(raw_input);
    assert_eq!(success, U256::one());
    assert_eq!(result, U256::one());
}

#[test]
// Two pairs - should return true
fn ec_pairing_test() {
    let raw_input = "2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f61fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d92bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f902fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd451971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc72a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea223a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc";

    let (success, result) = test_ecpairing_from_hex(raw_input);
    assert_eq!(success, U256::one());
    assert_eq!(result, U256::one());
}

// Two pairs, the second one doesn't belong to the g2 group.
#[test]
fn ec_pairing_not_pairing_test() {
    let raw_input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

    let (success, result) = test_ecpairing_from_hex(raw_input);
    assert_eq!(success, U256::zero());
    assert_eq!(result, U256::zero());
}

#[test]
fn ec_pairing_not_pairing_invalid_g2_subgroup_test() {
    let raw_input = "0412aa5b0805215b55a5e2dbf0662031aad0f5ef13f28b25df20b8670d1c59a616fb4b64ccff216fa5272e1e987c0616d60d8883d5834229c685949047e9411d2d81dbc969f72bc0454ff8b04735b717b725fee98a2fcbcdcf6c5b51b1dff33f075239888fc8448ab781e2a8bb85eb556469474cd707d4b913bee28679920eb61ef1c268b7c4c78959f099a043ecd5e537fe3069ac9197235f16162372848cba209cfadc22f7e80d399d1886f1c53898521a34c62918ed802305f32b4070a3c4";

    let (success, result) = test_ecpairing_from_hex(raw_input);
    assert_eq!(success, U256::zero());
    assert_eq!(result, U256::zero());
}

#[test]
fn ec_pairing_invalid_test() {
    let raw_input = "0413aa5b0805215b55a5e2dda0662031aad0f5ef13f28b25df20b8670d1c59a616fb4b64ccff216fa5272e1e987c0616d60d8883d5834229c685949047e9411d2d81dbc969f72bc0454ff8b04735b717b725fee98a2fcbcdcf6c5b51b1dff33f075239888fc8448ab781e2a8bb85eb556469474cd707d4b913bee28679920eb61ef1c268b7c4c78959f099a043ecd5e537fe3069ac9197235f16162372848cba209cfadc22f7e80d399d1886f1c53898521a34c62918ed802305f32b4070a3c4";

    let (success, result) = test_ecpairing_from_hex(raw_input);
    assert_eq!(success, U256::zero());
    assert_eq!(result, U256::zero());
}
