use super::*;

use crate::witness::artifacts::LogQueueStates;

use crate::zk_evm::zk_evm_abstractions::precompiles::ecpairing::pair;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecpairing::ECPairingRoundWitness;
use crate::zk_evm::zkevm_opcode_defs::bn254::bn256::{Fq12, Fq2, Fq6};
use crate::zk_evm::zkevm_opcode_defs::bn254::ff::Field;

use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::bn254::ec_pairing::input::{
    EcPairingCircuitFSMInputOutputWitness, EcPairingCircuitInputOutputWitness,
    EcPairingCircuitInstanceWitness, EcPairingFunctionFSM, EcPairingFunctionFSMWitness,
};
use crate::zkevm_circuits::bn254::ec_pairing::EcPairingPrecompileCallParamsWitness;
use crate::zkevm_circuits::bn254::{BN256Fq, BN256Fq12NNField, BN256Fq2NNField, BN256Fq6NNField};

use boojum::gadgets::non_native_field::implementations::implementation_u16::FFProxyValue;

use circuit_definitions::encodings::*;

use derivative::Derivative;

pub(crate) fn ecpairing_memory_queries(
    ecpairing_witnesses: &Vec<(u32, LogQuery_, Vec<ECPairingRoundWitness>)>,
) -> Vec<MemoryQuery> {
    let amount_of_queries = ecpairing_witnesses
        .iter()
        .fold(0, |mut inner, (_, _, witness)| {
            witness.iter().for_each(|el| {
                inner += el.reads.len();
                if el.writes.is_some() {
                    inner += 1;
                }
            });

            inner
        });

    let mut ecpairing_memory_queries = Vec::with_capacity(amount_of_queries);

    for (_cycle, _query, witness) in ecpairing_witnesses.iter() {
        for el in witness.iter() {
            let ECPairingRoundWitness {
                new_request: _,
                reads,
                writes,
            } = el;

            // we read, then write
            ecpairing_memory_queries.extend_from_slice(reads);

            if let Some(writes) = writes.as_ref() {
                ecpairing_memory_queries.extend_from_slice(writes);
            }
        }
    }

    ecpairing_memory_queries.shrink_to_fit();

    ecpairing_memory_queries
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ECPairingPrecompileState {
    GetRequestFromQueue,
    RunRoundFunction,
    Finished,
}

// we want to simulate splitting of data into many separate instances of the same circuit.
// So we basically need to reconstruct the FSM state on input/output, and passthrough data.
// In practice the only difficulty is buffer state, everything else is provided by out-of-circuit VM

pub(crate) fn ecpairing_decompose_into_per_circuit_witness<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    ecpairing_memory_queries: Vec<MemoryQuery>,
    ecpairing_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    ecpairing_memory_states: Vec<QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    ecpairing_witnesses: Vec<(u32, LogQuery_, Vec<ECPairingRoundWitness>)>,
    ecpairing_queries: Vec<LogQuery_>,
    mut demuxed_ecpairing_queue: LogQueueStates<F>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> Vec<EcPairingCircuitInstanceWitness<F>> {
    assert_eq!(
        ecpairing_memory_queries.len(),
        ecpairing_memory_states.len()
    );

    let memory_simulator_before = &ecpairing_simulator_snapshots[0];
    let memory_simulator_after = &ecpairing_simulator_snapshots[1];
    assert_eq!(
        ecpairing_memory_queries.len(),
        memory_simulator_after.num_items as usize - memory_simulator_before.num_items as usize
    );

    let mut result = vec![];

    let precompile_calls = ecpairing_queries;
    let simulator_witness: Vec<_> = demuxed_ecpairing_queue.simulator.witness.clone().into();
    let round_function_witness = ecpairing_witnesses;

    // check basic consistency
    assert_eq!(
        precompile_calls.len(),
        demuxed_ecpairing_queue.states_accumulator.len()
    );
    drop(demuxed_ecpairing_queue.states_accumulator);
    assert_eq!(precompile_calls.len(), round_function_witness.len());

    if precompile_calls.len() == 0 {
        return vec![];
    }

    let mut round_counter = 0;
    let num_requests = precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&demuxed_ecpairing_queue.simulator);
    let mut hidden_fsm_input_state = EcPairingFunctionFSM::<F>::placeholder_witness();
    hidden_fsm_input_state.read_precompile_call = true;
    hidden_fsm_input_state.pairing_success_flag_state = true;

    let mut memory_queries_it = ecpairing_memory_queries.into_iter();

    let mut memory_read_witnesses = vec![];

    let mut precompile_state = ECPairingPrecompileState::GetRequestFromQueue;

    let mut starting_request_idx = 0;

    let mut memory_queue_input_state = memory_simulator_before.take_sponge_like_queue_state();
    let mut current_memory_queue_state = memory_queue_input_state.clone();

    let mut memory_queue_states_it = ecpairing_memory_states.iter();

    for (request_idx, (request, per_request_work)) in precompile_calls
        .into_iter()
        .zip(round_function_witness.into_iter())
        .enumerate()
    {
        let _ = demuxed_ecpairing_queue
            .simulator
            .pop_and_output_intermediate_data(round_function);

        let mut memory_reads_per_request = vec![];

        assert_eq!(
            precompile_state,
            ECPairingPrecompileState::GetRequestFromQueue
        );

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        use crate::zk_evm::zk_evm_abstractions::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let num_rounds = precompile_request.precompile_interpreted_data as usize;
        assert_eq!(num_rounds, round_witness.len());

        let mut num_rounds_left = num_rounds;

        let is_last_request = request_idx == num_requests - 1;

        precompile_state = ECPairingPrecompileState::RunRoundFunction;

        let one_fq12 = Fq12::one();
        let zero_fq12 = Fq12::zero();

        let mut internal_state = one_fq12;
        let mut success_accumulated = true;

        for (round_idx, round) in round_witness.into_iter().enumerate() {
            if round_idx == 0 {
                assert!(round.new_request.is_some());
            }

            let mut input_pair = [U256::zero(); 6];

            for (i, read) in round.reads.iter().enumerate() {
                input_pair[i] = read.value;
                let read_query = memory_queries_it.next().unwrap();
                assert_eq!(read, &read_query);
                memory_reads_per_request.push(read_query.value);
                current_memory_queue_state = memory_queue_states_it.next().unwrap().clone();

                precompile_request.input_memory_offset += 1;
            }

            let pairing_res = pair(&input_pair);
            let ok = pairing_res.is_ok();
            if !ok {
                success_accumulated = false;
            }
            let pairing = pairing_res.unwrap_or(zero_fq12);
            internal_state.mul_assign(&pairing);

            num_rounds_left -= 1;

            let is_last_round = round_idx == num_rounds - 1;

            if is_last_round {
                assert_eq!(num_rounds_left, 0);
                assert!(round.writes.is_some());
                let [write_ok, write_res] = round.writes.unwrap();
                let write_query = memory_queries_it.next().unwrap();
                assert_eq!(write_ok, write_query);
                let write_query = memory_queries_it.next().unwrap();
                assert_eq!(write_res, write_query);

                _ = memory_queue_states_it.next().unwrap().clone();
                current_memory_queue_state = memory_queue_states_it.next().unwrap().clone();

                if is_last_request {
                    precompile_state = ECPairingPrecompileState::Finished;
                } else {
                    precompile_state = ECPairingPrecompileState::GetRequestFromQueue;
                }
            }

            round_counter += 1;

            if round_counter == num_rounds_per_circuit || (is_last_request && is_last_round) {
                let early_termination = round_counter != num_rounds_per_circuit;
                round_counter = 0;

                let finished = is_last_request && is_last_round;
                if finished {
                    assert!(memory_queries_it.next().is_none());
                }

                let input_is_empty = is_last_request;
                let nothing_left = is_last_round && input_is_empty;

                assert_eq!(nothing_left, finished);

                if early_termination {
                    assert_eq!(precompile_state, ECPairingPrecompileState::Finished);
                }

                let completed = precompile_state == ECPairingPrecompileState::Finished;
                let read_words_for_round =
                    precompile_state == ECPairingPrecompileState::RunRoundFunction;
                let read_precompile_call =
                    precompile_state == ECPairingPrecompileState::GetRequestFromQueue;

                let mut output_offset = precompile_request.output_memory_offset;
                // We increase the offset after we did the write, which happens when we
                // fully finished the precompile.
                if is_last_round {
                    output_offset += 1;
                }

                let hidden_fsm_output_state = EcPairingFunctionFSMWitness::<F> {
                    completed,
                    read_words_for_round,
                    pairing_inner_state: convert_to_witness_fq12::<F>(internal_state),
                    read_precompile_call,
                    pairing_success_flag_state: success_accumulated,
                    timestamp_to_use_for_read: request.timestamp.0,
                    timestamp_to_use_for_write: request.timestamp.0 + 1,
                    precompile_call_params: EcPairingPrecompileCallParamsWitness::<F> {
                        input_page: precompile_request.memory_page_to_read,
                        input_offset: precompile_request.input_memory_offset,
                        output_page: precompile_request.memory_page_to_write,
                        output_offset,
                        num_pairs: num_rounds_left as u32,
                    },
                };

                let range = starting_request_idx..(request_idx + 1);
                let wit: VecDeque<_> = (&simulator_witness[range])
                    .iter()
                    .map(|el| (log_query_into_circuit_log_query_witness(&el.2), el.1))
                    .collect();

                let current_reads = std::mem::take(&mut memory_reads_per_request);
                let mut current_witness = std::mem::take(&mut memory_read_witnesses);
                current_witness.push(current_reads);

                let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
                if result.len() == 0 {
                    observable_input_data.initial_memory_queue_state =
                        memory_queue_input_state.clone();
                    observable_input_data.initial_log_queue_state = log_queue_input_state.clone();
                }

                let mut observable_output_data =
                    PrecompileFunctionOutputData::placeholder_witness();
                if finished {
                    observable_output_data.final_memory_state = current_memory_queue_state.clone();
                }

                let witness = EcPairingCircuitInstanceWitness::<F> {
                    closed_form_input: EcPairingCircuitInputOutputWitness::<F> {
                        start_flag: result.len() == 0,
                        completion_flag: finished,
                        observable_input: observable_input_data,
                        observable_output: observable_output_data,
                        hidden_fsm_input: EcPairingCircuitFSMInputOutputWitness::<F> {
                            internal_fsm: hidden_fsm_input_state,
                            log_queue_state: log_queue_input_state.clone(),
                            memory_queue_state: memory_queue_input_state,
                        },
                        hidden_fsm_output: EcPairingCircuitFSMInputOutputWitness::<F> {
                            internal_fsm: hidden_fsm_output_state.clone(),
                            log_queue_state: take_queue_state_from_simulator(
                                &demuxed_ecpairing_queue.simulator,
                            ),
                            memory_queue_state: current_memory_queue_state.clone(),
                        },
                    },
                    requests_queue_witness: CircuitQueueRawWitness::<
                        F,
                        LogQuery<F>,
                        4,
                        LOG_QUERY_PACKED_WIDTH,
                    > {
                        elements: wit,
                    },
                    memory_reads_witness: current_witness.into_iter().flatten().collect(),
                };

                // make non-inclusize
                starting_request_idx = request_idx + 1;

                result.push(witness);

                log_queue_input_state =
                    take_queue_state_from_simulator(&demuxed_ecpairing_queue.simulator);
                hidden_fsm_input_state = hidden_fsm_output_state;
                memory_queue_input_state = current_memory_queue_state.clone();
            }
        }

        if !memory_reads_per_request.is_empty() {
            // we may have drained it already if it was the end of the circuit
            memory_read_witnesses.push(memory_reads_per_request);
        }
    }

    result
}

fn convert_to_witness_fq12<F: SmallField>(
    v: Fq12,
) -> <BN256Fq12NNField<F> as CSAllocatable<F>>::Witness {
    (
        convert_to_witness_fq6::<F>(v.c0),
        convert_to_witness_fq6::<F>(v.c1),
    )
}

fn convert_to_witness_fq6<F: SmallField>(
    v: Fq6,
) -> <BN256Fq6NNField<F> as CSAllocatable<F>>::Witness {
    (
        convert_to_witness_fq2::<F>(v.c0),
        convert_to_witness_fq2::<F>(v.c1),
        convert_to_witness_fq2::<F>(v.c2),
    )
}

fn convert_to_witness_fq2<F: SmallField>(
    v: Fq2,
) -> <BN256Fq2NNField<F> as CSAllocatable<F>>::Witness {
    let c0 = FFProxyValue::<BN256Fq, 17>::set(v.c0);
    let c1 = FFProxyValue::<BN256Fq, 17>::set(v.c1);

    (c0, c1)
}
