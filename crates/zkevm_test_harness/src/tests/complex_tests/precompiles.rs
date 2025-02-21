use std::str::FromStr;

use circuit_definitions::{
    base_layer_proof_config,
    circuit_definitions::base_layer::{
        ECAddFunctionInstanceSynthesisFunction, ECMulFunctionInstanceSynthesisFunction,
        ECPairingFunctionInstanceSynthesisFunction, ModexpFunctionInstanceSynthesisFunction,
        ZkSyncBaseLayerCircuit,
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
    PrecompileCallABI, ECADD_PRECOMPILE_ADDRESS, ECMUL_PRECOMPILE_ADDRESS,
    ECPAIRING_PRECOMPILE_ADDRESS, MODEXP_PRECOMPILE_ADDRESS, PRECOMPILE_AUX_BYTE,
};

use crate::{
    prover_utils::{
        create_base_layer_setup_data, prove_base_layer_circuit, verify_base_layer_proof,
    },
    witness::{
        artifacts::LogQueueStates,
        aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator,
        individual_circuits::memory_related::{
            ecadd::{ecadd_decompose_into_per_circuit_witness, ecadd_memory_queries},
            ecmul::{ecmul_decompose_into_per_circuit_witness, ecmul_memory_queries},
            ecpairing::{ecpairing_decompose_into_per_circuit_witness, ecpairing_memory_queries},
            modexp::{modexp_decompose_into_per_circuit_witness, modexp_memory_queries},
            SimulatorSnapshot,
        },
        postprocessing::CircuitMaker,
    },
};

fn fill_memory<M: Memory, const N: usize>(
    tuples: Vec<[[u8; 32]; N]>,
    page: u32,
    memory: &mut M,
) -> u16 {
    let mut location = MemoryLocation {
        page: MemoryPage(page),
        index: MemoryIndex(0),
        memory_type: MemoryType::Heap,
    };

    for i in 0..tuples.len() {
        for j in 0..N {
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

    (N * tuples.len()) as u16
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
        output_memory_length: 2,
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

fn test_ecadd_using_tuple(tuple: Vec<[[u8; 32]; 2]>) -> (U256, U256, U256) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<true>;

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    let num_words_used = fill_memory(tuple, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 3,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECADD_PRECOMPILE_ADDRESS as u64);

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
    assert_eq!(writes.len(), 3);

    let mut witness = match witness {
        PrecompileCyclesWitness::ECAdd(witness) => witness,
        _ => panic!(),
    };

    let ecadd_witnesses = vec![(4u32, precompile_query, witness.pop().unwrap())];

    let ecadd_memory_queries = ecadd_memory_queries(&ecadd_witnesses);

    let mut ecadd_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (ecadd_simulator_snapshots, _simulator) = simulate_subqueue(
        &ecadd_memory_queries,
        &mut ecadd_memory_states,
        &mut states_accumulator2,
    );

    let ecadd_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_ecadd_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = ecadd_decompose_into_per_circuit_witness(
        ecadd_memory_queries,
        ecadd_simulator_snapshots,
        ecadd_memory_states,
        ecadd_witnesses,
        ecadd_queries,
        demuxed_ecadd_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ECAddFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECPairingPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECAdd(basic_circuit);
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
        let basic_circuit = maker.process::<ECAddFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECAddPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECAdd(basic_circuit);

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

    (writes[0].value, writes[1].value, writes[2].value)
}

fn test_ecmul_using_tuple(tuple: Vec<[[u8; 32]; 3]>) -> (U256, U256, U256) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<true>;

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    let num_words_used = fill_memory(tuple, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 3,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECMUL_PRECOMPILE_ADDRESS as u64);

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
    assert_eq!(writes.len(), 3);

    let mut witness = match witness {
        PrecompileCyclesWitness::ECMul(witness) => witness,
        _ => panic!(),
    };

    let ecmul_witnesses = vec![(4u32, precompile_query, witness.pop().unwrap())];

    let ecmul_memory_queries = ecmul_memory_queries(&ecmul_witnesses);

    let mut ecmul_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (ecmul_simulator_snapshots, _simulator) = simulate_subqueue(
        &ecmul_memory_queries,
        &mut ecmul_memory_states,
        &mut states_accumulator2,
    );

    let ecmul_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_ecmul_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = ecmul_decompose_into_per_circuit_witness(
        ecmul_memory_queries,
        ecmul_simulator_snapshots,
        ecmul_memory_states,
        ecmul_witnesses,
        ecmul_queries,
        demuxed_ecmul_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ECMulFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECMul(basic_circuit);
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
        let basic_circuit = maker.process::<ECMulFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECMul(basic_circuit);

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

    (writes[0].value, writes[1].value, writes[2].value)
}

fn test_modexp_using_tuple(tuple: Vec<[[u8; 32]; 3]>) -> U256 {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<true>;

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    let num_words_used = fill_memory(tuple, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 1,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(MODEXP_PRECOMPILE_ADDRESS as u64);

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
    assert_eq!(writes.len(), 1);

    let mut witness = match witness {
        PrecompileCyclesWitness::Modexp(witness) => witness,
        _ => panic!(),
    };

    let modexp_witnesses = vec![(4u32, precompile_query, witness.pop().unwrap())];

    let modexp_memory_queries = modexp_memory_queries(&modexp_witnesses);

    let mut modexp_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (modexp_simulator_snapshots, _simulator) = simulate_subqueue(
        &modexp_memory_queries,
        &mut modexp_memory_states,
        &mut states_accumulator2,
    );

    let modexp_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_modexp_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = modexp_decompose_into_per_circuit_witness(
        modexp_memory_queries,
        modexp_simulator_snapshots,
        modexp_memory_states,
        modexp_witnesses,
        modexp_queries,
        demuxed_modexp_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ModexpFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::Modexp(basic_circuit);
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
        let basic_circuit = maker.process::<ModexpFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::Modexp(basic_circuit);

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

    writes[0].value
}

fn test_ecpairing_from_hex(raw_input: &str) -> (U256, U256) {
    let input_bytes = hex::decode(raw_input).unwrap();

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    let num_words_used = fill_memory(tuple, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 3,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECADD_PRECOMPILE_ADDRESS as u64);

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
    assert_eq!(writes.len(), 3);

    let mut witness = match witness {
        PrecompileCyclesWitness::ECAdd(witness) => witness,
        _ => panic!(),
    };

    let ecadd_witnesses = vec![(4u32, precompile_query, witness.pop().unwrap())];

    let ecadd_memory_queries = ecadd_memory_queries(&ecadd_witnesses);

    let mut ecadd_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (ecadd_simulator_snapshots, _simulator) = simulate_subqueue(
        &ecadd_memory_queries,
        &mut ecadd_memory_states,
        &mut states_accumulator2,
    );

    let ecadd_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_ecadd_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = ecadd_decompose_into_per_circuit_witness(
        ecadd_memory_queries,
        ecadd_simulator_snapshots,
        ecadd_memory_states,
        ecadd_witnesses,
        ecadd_queries,
        demuxed_ecadd_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ECAddFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECPairingPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECAdd(basic_circuit);
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
        let basic_circuit = maker.process::<ECAddFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECAddPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECAdd(basic_circuit);

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

    (writes[0].value, writes[1].value, writes[2].value)
}

fn test_ecmul_using_tuple(tuple: Vec<[[u8; 32]; 3]>) -> (U256, U256, U256) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<true>;

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    let num_words_used = fill_memory(tuple, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 3,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(ECMUL_PRECOMPILE_ADDRESS as u64);

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
    assert_eq!(writes.len(), 3);

    let mut witness = match witness {
        PrecompileCyclesWitness::ECMul(witness) => witness,
        _ => panic!(),
    };

    let ecmul_witnesses = vec![(4u32, precompile_query, witness.pop().unwrap())];

    let ecmul_memory_queries = ecmul_memory_queries(&ecmul_witnesses);

    let mut ecmul_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (ecmul_simulator_snapshots, _simulator) = simulate_subqueue(
        &ecmul_memory_queries,
        &mut ecmul_memory_states,
        &mut states_accumulator2,
    );

    let ecmul_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_ecmul_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = ecmul_decompose_into_per_circuit_witness(
        ecmul_memory_queries,
        ecmul_simulator_snapshots,
        ecmul_memory_states,
        ecmul_witnesses,
        ecmul_queries,
        demuxed_ecmul_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ECMulFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECMul(basic_circuit);
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
        let basic_circuit = maker.process::<ECMulFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::ECMul(basic_circuit);

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

    (writes[0].value, writes[1].value, writes[2].value)
}

fn test_modexp_using_tuple(tuple: Vec<[[u8; 32]; 3]>) -> U256 {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<true>;

    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    let num_words_used = fill_memory(tuple, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used as u32,
        output_memory_offset: num_words_used as u32,
        output_memory_length: 1,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(MODEXP_PRECOMPILE_ADDRESS as u64);

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
    assert_eq!(writes.len(), 1);

    let mut witness = match witness {
        PrecompileCyclesWitness::Modexp(witness) => witness,
        _ => panic!(),
    };

    let modexp_witnesses = vec![(4u32, precompile_query, witness.pop().unwrap())];

    let modexp_memory_queries = modexp_memory_queries(&modexp_witnesses);

    dbg!(&modexp_memory_queries);

    let mut modexp_memory_states = vec![];
    let mut states_accumulator2 = LastPerCircuitAccumulator::new(1);
    let (modexp_simulator_snapshots, _simulator) = simulate_subqueue(
        &modexp_memory_queries,
        &mut modexp_memory_states,
        &mut states_accumulator2,
    );

    let modexp_queries = vec![precompile_query];

    let num_rounds_per_circuit = 1;
    let round_function = ZkSyncDefaultRoundFunction::default();

    let mut states_accumulator = LastPerCircuitAccumulator::new(1);
    let mut simulator = LogQueueSimulator::empty();

    let (_old_tail, state_witness) =
        simulator.push_and_output_intermediate_data(precompile_query, &round_function);
    states_accumulator.push(state_witness);

    let demuxed_modexp_queue = LogQueueStates::<GoldilocksField> {
        states_accumulator,
        simulator,
    };

    let ecpairing_circuits_data = modexp_decompose_into_per_circuit_witness(
        modexp_memory_queries,
        modexp_simulator_snapshots,
        modexp_memory_states,
        modexp_witnesses,
        modexp_queries,
        demuxed_modexp_queue,
        num_rounds_per_circuit,
        &round_function,
    );

    let worker = Worker::new_with_num_threads(8);

    let (setup_base, setup, vk, setup_tree, vars_hint, wits_hint, finalization_hint) = {
        let circuit = ecpairing_circuits_data[0].clone();

        let mut maker = CircuitMaker::new(1, round_function.clone());
        let basic_circuit = maker.process::<ModexpFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::Modexp(basic_circuit);
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
        let basic_circuit = maker.process::<ModexpFunctionInstanceSynthesisFunction>(circuit, circuit_encodings::zkevm_circuits::scheduler::aux::BaseLayerCircuitType::ECMulPrecompile);
        let basic_circuit = ZkSyncBaseLayerCircuit::Modexp(basic_circuit);

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

    writes[0].value
}

fn test_ecpairing_from_hex(raw_input: &str) -> (U256, U256) {
    let mut input_bytes = hex::decode(raw_input).unwrap();

    if input_bytes.len() == 0 || input_bytes.len() % 192 != 0 {
        let padding = 192 - input_bytes.len() % 192;
        input_bytes.extend_from_slice(&vec![0u8; padding]);
    }
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

fn test_ecadd_from_hex(raw_input: &str) -> (U256, U256, U256) {
    let input_bytes = hex::decode(raw_input).unwrap();

    let x1: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let y1: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let x2: [u8; 32] = input_bytes[64..96].try_into().unwrap();
    let y2: [u8; 32] = input_bytes[96..128].try_into().unwrap();

    let tuple = vec![[x1, y1], [x2, y2]];

    test_ecadd_using_tuple(tuple)
}

fn test_ec_mul_from_hex(raw_input: &str) -> (U256, U256, U256) {
    let input_bytes = hex::decode(raw_input).unwrap();

    let x1: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let y1: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let scalar: [u8; 32] = input_bytes[64..96].try_into().unwrap();

    let tuple = vec![[x1, y1, scalar]];

    test_ecmul_using_tuple(tuple)
}

fn test_modexp_from_hex(raw_input: &str) -> U256 {
    let input_bytes = hex::decode(raw_input).unwrap();

    let a: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let b: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let c: [u8; 32] = input_bytes[64..96].try_into().unwrap();

    let tuple = vec![[a, b, c]];

    test_modexp_using_tuple(tuple)
}

#[test]
fn ec_pairing_empty_data() {
    let raw_input = "";

    let (success, result) = test_ecpairing_from_hex(raw_input);
    assert_eq!(success, U256::one());
    assert_eq!(result, U256::one());
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
    assert_eq!(success, U256::one());
    assert_eq!(result, U256::zero());
}

#[test]
fn ec_pairing_all_modules_test() {
    // [module, module, module, module, module, module]
    let raw_input = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

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

#[test]
fn ec_add_test() {
    let raw_input = "099c07c9dd1107b9c9b0836da7ecfb7202d10bea1b8d1e88bc51ca476f23d91d28351e12f9219537fc8d6cac7c6444bd7980390d0d3e203fe0d8c1b0d811995021e177a985c3db8ef1d670629972c007ae90c78fb16e3011de1d08f5a44cb6550bd68a7caa07f6adbecbf06fb1f09d32b7bed1369a2a58058d1521bebd8272ac";
    let expected_x =
        U256::from_str("25beba7ab903d641d77e5801ca4d69a7a581359959c5d2621301dddafb145044").unwrap();
    let expected_y =
        U256::from_str("19ee7a5ce8338bbcf4f74c3d3ec79d3635e837cb723ee6a0fa99269e3c6d7e23").unwrap();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_zero_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let expected_x = U256::zero();
    let expected_y = U256::zero();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_chfast1_test() {
    let raw_input = "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f3726607c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7";
    let expected_x =
        U256::from_str("2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703").unwrap();
    let expected_y =
        U256::from_str("301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915").unwrap();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_chfast2_test() {
    let raw_input = "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c91518b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266";
    let expected_x =
        U256::from_str("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7").unwrap();
    let expected_y =
        U256::from_str("21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204").unwrap();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_cdetrio1_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_cdetrio2_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_cdetrio3_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_cdetrio6_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
    let expected_x =
        U256::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let expected_y =
        U256::from_str("0000000000000000000000000000000000000000000000000000000000000002").unwrap();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_cdetrio11_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
    let expected_x =
        U256::from_str("030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3").unwrap();
    let expected_y =
        U256::from_str("15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4").unwrap();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_cdetrio13_test() {
    let raw_input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98";
    let expected_x =
        U256::from_str("15bf2bb17880144b5d1cd2b1f46eff9d617bffd1ca57c37fb5a49bd84e53cf66").unwrap();
    let expected_y =
        U256::from_str("049c797f9ce0d17083deb32b5e36f2ea2a212ee036598dd7624c168993d1355f").unwrap();

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_add_cdetrio14_test() {
    let raw_input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa92e83f8d734803fc370eba25ed1f6b8768bd6d83887b87165fc2434fe11a830cb";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_test() {
    let raw_input = "099c08c9dd1107b9c9b0836da7ecfb7202d10bea1b8d1e88cc51ca476f23d91d28351e12f9219537fc8d6cac7c6444bd7980390d0d3e203fe0d8c1b0d811995021e177a985c3db8ef1d670629972c007ae90c78fb16e3011de1d08f5a44cb6550bd68a7caa07f6adbecbf06fb1f09d32b7bed1369a2a58058d1521bebd8272ac";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_2_test() {
    let raw_input = "00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000126198c000000000000000000000000000000000000000000000000000000000001e4dc";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_3_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_4_test() {
    let raw_input = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_5_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_6_test() {
    let raw_input = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4830644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4930644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4830644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd49";
    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_add_invalid_7_test() {
    let raw_input = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4830644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let (success, x, y) = test_ecadd_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_mul_test() {
    let raw_input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f630644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
    let expected_x =
        U256::from_str("1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe3").unwrap();
    let expected_y =
        U256::from_str("163511ddc1c3f25d396745388200081287b3fd1472d8339d5fecb2eae0830451").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_invalid_test() {
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001";

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_mul_invalid_2_test() {
    // x = (0 + module), y = (0 + module), s = module
    let raw_input = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd4730644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::zero());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_mul_zero_test() {
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, U256::zero());
    assert_eq!(y, U256::zero());
}

#[test]
fn ec_mul_chfast1_test() {
    let raw_input = "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000000000000000011138ce750fa15c2";

    let expected_x =
        U256::from_str("070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c").unwrap();
    let expected_y =
        U256::from_str("031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_scalar_one_test() {
    let raw_input = "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb2040000000000000000000000000000000000000000000000000000000000000001";

    let expected_x =
        U256::from_str("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7").unwrap();
    let expected_y =
        U256::from_str("21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_chfast2_test() {
    let raw_input = "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46";

    let expected_x =
        U256::from_str("025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb").unwrap();
    let expected_y =
        U256::from_str("2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_chfast3_test() {
    let raw_input = "025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3";

    let expected_x =
        U256::from_str("14789d0d4a730b354403b5fac948113739e276c23e0258d8596ee72f9cd9d323").unwrap();
    let expected_y =
        U256::from_str("0af18a63153e0ec25ff9f2951dd3fa90ed0197bfef6e2a1a62b5095b9d2b4a27").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_cdetrio1_test() {
    let raw_input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let expected_x =
        U256::from_str("2cde5879ba6f13c0b5aa4ef627f159a3347df9722efce88a9afbb20b763b4c41").unwrap();
    let expected_y =
        U256::from_str("1aa7e43076f6aee272755a7f9b84832e71559ba0d2e0b17d5f9f01755e5b0d11").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_cdetrio6_test() {
    let raw_input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let expected_x =
        U256::from_str("29e587aadd7c06722aabba753017c093f70ba7eb1f1c0104ec0564e7e3e21f60").unwrap();
    let expected_y =
        U256::from_str("22b1143f6a41008e7755c71c3d00b6b915d386de21783ef590486d8afa8453b1").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn ec_mul_cdetrio11_test() {
    let raw_input = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    let expected_x =
        U256::from_str("00a1a234d08efaa2616607e31eca1980128b00b415c845ff25bba3afcb81dc00").unwrap();
    let expected_y =
        U256::from_str("242077290ed33906aeb8e42fd98c41bcb9057ba03421af3f2d08cfc441186024").unwrap();

    let (success, x, y) = test_ec_mul_from_hex(raw_input);

    assert_eq!(success, U256::one());
    assert_eq!(x, expected_x);
    assert_eq!(y, expected_y);
}

#[test]
fn mod_exp_test() {
    let raw_input = "8f3b7d5c187f8abbe0581dab5a37644febd35ea6d4fe3213288f9d63ab82a6b1afa9888e351dfdefd862945b0da33c9ea1de907ae830292438df1fa184447777c7e38934b1501e64e5c0bd0ab35b3354520b6e88b81a1f063c37007c65b7efd5";
    let expected_res =
        U256::from_str("45682b037d21d235bd0ed6103ce2674e5c8e983a88bfd09c847a6324e77c1ad6").unwrap();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_eip_198_1_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
    let expected_res = U256::one();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_eip_198_2_test() {
    let raw_input = "0000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
    let expected_res = U256::one();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_eip_198_3_test() {
    let raw_input = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000";
    let expected_res = U256::zero();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_zeros_test() {
    // base = 0x00, exp == 0x00, mod = 0x00
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let expected_res = U256::zero();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_modulo_zero() {
    // base = 0x05, exp == 0x04, mod = 0x00
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000";
    let expected_res = U256::zero();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_exp_zero() {
    // base = 0x05, exp == 0x00, mod = 0x0a
    let raw_input = "00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a";
    let expected_res = U256::one();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_exp_zero_mod_one() {
    // base = 0x05, exp == 0x00, mod = 0x01
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
    let expected_res = U256::zero();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_simple_test() {
    // base = 0x04, exp == 0x01, mod = 0x01
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003";
    let expected_res = U256::one();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_exp_exp_zero_mod_zero() {
    // base = 0x05, exp == 0x00, mod = 0x00
    let raw_input = "000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    let expected_res = U256::zero();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}

#[test]
fn mod_base_zero_exp_zero() {
    // base = 0x00, exp == 0x00, mod = 0x0a
    let raw_input = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a";
    let expected_res = U256::one();

    let res = test_modexp_from_hex(raw_input);

    assert_eq!(res, expected_res);
}
