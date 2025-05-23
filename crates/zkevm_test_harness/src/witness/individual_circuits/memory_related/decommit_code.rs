use super::*;
use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::witness::aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator;
use crate::witness::aux_data_structs::MemoryQueuePerCircuitSimulator;
use crate::zk_evm::aux_structures::MemoryIndex;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::ethereum_types::U256;
use crate::zkevm_circuits::base_structures::decommit_query::DecommitQueryWitness;
use crate::zkevm_circuits::base_structures::decommit_query::DECOMMIT_QUERY_PACKED_WIDTH;
use crate::zkevm_circuits::code_unpacker_sha256::input::*;
use circuit_definitions::encodings::decommittment_request::normalized_preimage_as_u256;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueSimulator;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;
use circuit_definitions::zk_evm::aux_structures::DecommittmentQuery;
use std::collections::VecDeque;

pub(crate) fn decommitter_memory_queries(
    deduplicated_decommit_requests_with_data: &Vec<(DecommittmentQuery, Vec<U256>)>,
) -> Vec<MemoryQuery> {
    let mut result = vec![];
    for (query, writes) in deduplicated_decommit_requests_with_data.iter() {
        assert!(query.is_fresh);

        // now feed the queries into it
        let as_queries_it = writes.iter().enumerate().map(|(idx, el)| MemoryQuery {
            timestamp: query.timestamp,
            location: zk_evm::aux_structures::MemoryLocation {
                memory_type: zk_evm::abstractions::MemoryType::Code,
                page: query.memory_page,
                index: MemoryIndex(idx as u32),
            },
            rw_flag: true,
            value: *el,
            value_is_pointer: false,
        });

        // and plain test memory queues
        result.extend(as_queries_it);
    }

    result
}

pub(crate) struct DecommiterCircuitProcessingInputs<F: SmallField> {
    pub deduplicated_decommittment_queue_simulator: DecommittmentQueueSimulator<F>,
    pub deduplicated_decommittment_queue_states: Vec<DecommittmentQueueState<F>>,
    pub deduplicated_decommit_requests_with_data: Vec<(DecommittmentQuery, Vec<U256>)>,
}

pub(crate) fn compute_decommitter_circuit_snapshots<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    decommitter_memory_queries: Vec<MemoryQuery>,
    decommitter_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    decommitter_memory_states: Vec<QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    final_explicit_memory_queue_state: QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    decommiter_circuit_inputs: DecommiterCircuitProcessingInputs<F>,
    round_function: &R,
    decommiter_circuit_capacity: usize,
) -> Vec<CodeDecommitterCircuitInstanceWitness<F>> {
    assert_eq!(
        decommitter_memory_queries.len(),
        decommitter_memory_states.len()
    );

    let memory_simulator_before = &decommitter_simulator_snapshots[0];
    let memory_simulator_after = &decommitter_simulator_snapshots[1];
    assert_eq!(
        decommitter_memory_queries.len(),
        memory_simulator_after.num_items as usize - memory_simulator_before.num_items as usize
    );

    let start_idx_for_memory_accumulator = 0;

    let initial_memory_queue_state = &memory_simulator_before.take_sponge_like_queue_state();

    let DecommiterCircuitProcessingInputs {
        deduplicated_decommit_requests_with_data,
        deduplicated_decommittment_queue_states,
        deduplicated_decommittment_queue_simulator,
    } = decommiter_circuit_inputs;

    // now we should start chunking the requests into separate decommittment circuits by running a micro-simulator

    assert!(
        deduplicated_decommit_requests_with_data.len() > 0,
        "we must have some decommitment requests"
    );

    // our simulator is simple: it will try to take an element from the queue, run some number of rounds, and compare the results

    let mut results: Vec<CodeDecommitterCircuitInstanceWitness<F>> = vec![];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DecommitterState {
        BeginNew,
        DecommmitMore,
        Done,
    }

    let final_deduplicated_queue_state = transform_sponge_like_queue_state(
        deduplicated_decommittment_queue_states
            .last()
            .unwrap()
            .clone(),
    );
    assert_eq!(
        deduplicated_decommit_requests_with_data.len(),
        deduplicated_decommittment_queue_states.len()
    );

    let mut current_decommittment_requests_queue_simulator =
        deduplicated_decommittment_queue_simulator.clone();

    assert_eq!(
        deduplicated_decommit_requests_with_data.len(),
        deduplicated_decommittment_queue_states.len(),
    );

    assert_eq!(
        deduplicated_decommit_requests_with_data.len(),
        deduplicated_decommittment_queue_simulator.witness.len(),
    );

    drop(deduplicated_decommittment_queue_states);

    let mut it = deduplicated_decommit_requests_with_data
        .into_iter()
        .zip(deduplicated_decommittment_queue_simulator.witness)
        .peekable();

    let mut fsm_state = DecommitterState::BeginNew;
    let mut current_memory_data_it = vec![].into_iter();
    let mut start = true;
    let mut memory_queue_state_offset = 0;

    use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Digest;
    use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::transmute_state;
    use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256;

    let mut internal_state = Sha256::default();
    let mut fsm_internals = CodeDecommittmentFSM::<F>::placeholder_witness();

    use crate::boojum::gadgets::queue::QueueState;
    let placeholder_witness = QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder_witness();

    'outer: loop {
        let mut current_circuit_witness = CodeDecommitterCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: start,
                completion_flag: false,
                observable_input: CodeDecommitterInputData::placeholder_witness(),
                observable_output: CodeDecommitterOutputData::placeholder_witness(),
                hidden_fsm_input: CodeDecommitterFSMInputOutput::placeholder_witness(),
                hidden_fsm_output: CodeDecommitterFSMInputOutput::placeholder_witness(),
            },
            sorted_requests_queue_witness: FullStateCircuitQueueRawWitness::<
                F,
                zkevm_circuits::base_structures::decommit_query::DecommitQuery<F>,
                FULL_SPONGE_QUEUE_STATE_WIDTH,
                DECOMMIT_QUERY_PACKED_WIDTH,
            > {
                elements: VecDeque::new(),
            },
            code_words: vec![],
        };

        let wintess_state = if start_idx_for_memory_accumulator + memory_queue_state_offset == 0 {
            &final_explicit_memory_queue_state
        } else {
            decommitter_memory_states
                .get(start_idx_for_memory_accumulator + memory_queue_state_offset - 1)
                .unwrap()
        };

        current_circuit_witness
            .closed_form_input
            .hidden_fsm_input
            .memory_queue_state = wintess_state.clone();

        let initial_decommittment_queue_state = results
            .last()
            .map(|el| {
                el.closed_form_input
                    .hidden_fsm_output
                    .decommittment_requests_queue_state
                    .clone()
            })
            .unwrap_or(placeholder_witness.clone());

        let initial_internal_fsm_state = results
            .last()
            .map(|el| el.closed_form_input.hidden_fsm_output.internal_fsm.clone())
            .unwrap_or(CodeDecommittmentFSM::placeholder_witness());

        current_circuit_witness
            .closed_form_input
            .hidden_fsm_input
            .internal_fsm = initial_internal_fsm_state;
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_input
            .decommittment_requests_queue_state = initial_decommittment_queue_state;

        if start {
            // set passthrough input
            start = false;
            current_circuit_witness
                .closed_form_input
                .observable_input
                .memory_queue_initial_state = initial_memory_queue_state.clone();
            current_circuit_witness
                .closed_form_input
                .observable_input
                .sorted_requests_queue_initial_state = final_deduplicated_queue_state.clone();
        } else {
            if DecommitterState::BeginNew != fsm_state {
                current_circuit_witness.code_words.push(vec![]);
            }
        }

        for _cycle_idx in 0..decommiter_circuit_capacity {
            // we will kind of fall through, so "if" instead of "match"
            if &DecommitterState::BeginNew == &fsm_state {
                internal_state = Sha256::default();

                let ((query, memory_data), wit) = it.next().unwrap();
                let (el, _intermediate_info) = current_decommittment_requests_queue_simulator
                    .pop_and_output_intermediate_data(round_function);
                debug_assert_eq!(query, el);

                assert!(memory_data.len() > 0);
                current_memory_data_it = memory_data.into_iter();

                // fill the witness
                let DecommittmentQuery {
                    header,
                    normalized_preimage,
                    timestamp,
                    memory_page,
                    decommitted_length: _,
                    is_fresh,
                } = wit.2;

                let bytecode_version = u8::from_be_bytes([header.0[0]]);
                if bytecode_version == 1 {
                    // Check that EraVM bytecode length is odd
                    let num_words = u16::from_be_bytes([header.0[2], header.0[3]]);
                    assert!(num_words & 1 == 1);
                }

                let hash_as_u256 = normalized_preimage_as_u256(&normalized_preimage);

                let as_circuit_data = DecommitQueryWitness {
                    code_hash: hash_as_u256,
                    page: memory_page.0,
                    is_first: is_fresh,
                    timestamp: timestamp.0,
                };

                let wit = (as_circuit_data, wit.1);

                current_circuit_witness
                    .sorted_requests_queue_witness
                    .elements
                    .push_back(wit);

                fsm_internals.state_get_from_queue = false;
                fsm_internals.state_decommit = true;
                fsm_internals.sha256_inner_state = boojum::gadgets::sha256::INITIAL_STATE;
                fsm_internals.current_index = 0;
                fsm_internals.current_page = memory_page.0;
                fsm_internals.timestamp = timestamp.0;
                fsm_internals.hash_to_compare_against = hash_as_u256;
                fsm_internals.num_byte32_words_processed = 0u16;

                fsm_state = DecommitterState::DecommmitMore;
                current_circuit_witness.code_words.push(vec![]);
            }

            // do the actual round
            match fsm_state {
                DecommitterState::DecommmitMore => {
                    let mut block = [0u8; 64];
                    let word0 = current_memory_data_it.next().unwrap();
                    word0.to_big_endian(&mut block[0..32]);

                    current_circuit_witness
                        .code_words
                        .last_mut()
                        .unwrap()
                        .push(word0);
                    memory_queue_state_offset += 1;
                    fsm_internals.current_index += 1;
                    fsm_internals.num_byte32_words_processed += 1;

                    let mut finished = false;
                    if let Some(word1) = current_memory_data_it.next() {
                        current_circuit_witness
                            .code_words
                            .last_mut()
                            .unwrap()
                            .push(word1);
                        word1.to_big_endian(&mut block[32..64]);

                        memory_queue_state_offset += 1;
                        fsm_internals.current_index += 1;
                        fsm_internals.num_byte32_words_processed += 1;
                    } else {
                        // we decommitted everythin
                        // pad and do not increment index
                        block[32] = 0x80;
                        let num_bits = (fsm_internals.num_byte32_words_processed as u32) * 32 * 8;
                        let length_in_bits_be = num_bits.to_be_bytes();
                        block[60..64].copy_from_slice(&length_in_bits_be);
                        finished = true;
                    }

                    // absorb
                    internal_state.update(&block);

                    if finished {
                        let mut raw_state = transmute_state(internal_state.clone());
                        raw_state[0] = 0;
                        let mut buffer = [0u8; 32];
                        for (dst, src) in buffer.array_chunks_mut::<4>().zip(raw_state.iter()) {
                            *dst = src.to_be_bytes();
                        }

                        let word = U256::from_big_endian(&buffer);

                        assert!(
                            fsm_internals.hash_to_compare_against == word,
                            "Hash in FSM is 0x{:064x}, while hash in simulator is 0x{:064x}",
                            fsm_internals.hash_to_compare_against,
                            word,
                        );

                        if it.peek().is_none() {
                            fsm_state = DecommitterState::Done;
                            fsm_internals.state_get_from_queue = false;
                            fsm_internals.state_decommit = false;
                            fsm_internals.finished = true;
                        } else {
                            fsm_state = DecommitterState::BeginNew;
                            fsm_internals.state_get_from_queue = true;
                            fsm_internals.state_decommit = false;
                        }
                    }
                }
                a @ _ => unreachable!("we should never hit the state {:?}", a),
            }

            if fsm_state == DecommitterState::Done {
                break;
            }

            // if we are done than push some data into witness
        }

        // copy the final state

        let raw_state = transmute_state(internal_state.clone());

        for (dst, src) in fsm_internals
            .sha256_inner_state
            .iter_mut()
            .zip(raw_state.into_iter())
        {
            *dst = src;
        }

        // proceed with final bits
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .decommittment_requests_queue_state = take_sponge_like_queue_state_from_simulator(
            &current_decommittment_requests_queue_simulator,
        );
        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .decommittment_requests_queue_state = take_sponge_like_queue_state_from_simulator(
            &current_decommittment_requests_queue_simulator,
        );

        let wintess_state = if start_idx_for_memory_accumulator + memory_queue_state_offset == 0 {
            &final_explicit_memory_queue_state
        } else {
            decommitter_memory_states
                .get(start_idx_for_memory_accumulator + memory_queue_state_offset - 1)
                .unwrap()
        };

        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .memory_queue_state = wintess_state.clone();

        current_circuit_witness
            .closed_form_input
            .hidden_fsm_output
            .internal_fsm = fsm_internals.clone();

        results.push(current_circuit_witness);

        if fsm_state == DecommitterState::Done {
            // mark as done and set passthrough output
            results
                .last_mut()
                .unwrap()
                .closed_form_input
                .completion_flag = true;
            let final_memory_state = results
                .last()
                .unwrap()
                .closed_form_input
                .hidden_fsm_output
                .memory_queue_state
                .clone();
            results
                .last_mut()
                .unwrap()
                .closed_form_input
                .observable_output
                .memory_queue_final_state = final_memory_state;
            break 'outer;
        }
    }

    results
}
