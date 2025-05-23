use self::toolset::GeometryConfig;

use super::*;
use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::witness::aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator;
use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulator;
use crate::witness::aux_data_structs::MemoryQueuePerCircuitSimulator;
use crate::witness::postprocessing::observable_witness::RamPermutationObservableWitness;
use crate::witness::postprocessing::CircuitMaker;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::ethereum_types::U256;
use crate::zkevm_circuits::{
    base_structures::memory_query::MEMORY_QUERY_PACKED_WIDTH, ram_permutation::input::*,
};
use artifacts::MemoryArtifacts;
use circuit_definitions::circuit_definitions::base_layer::{
    RAMPermutationInstanceSynthesisFunction, ZkSyncBaseLayerCircuit,
};
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::{encodings::*, Field, RoundFunction};
use memory_query::{CustomMemoryQueueSimulator, QueueWitness};
use oracle::WitnessGenerationArtifact;

use postprocessing::FirstAndLastCircuitWitness;
use rayon::prelude::*;
use snark_wrapper::boojum::field::Field as _;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use zkevm_circuits::base_structures::vm_state::QUEUE_STATE_WIDTH;

use crate::zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE;

pub(crate) fn compute_ram_circuit_snapshots(
    sorted_memory_queries_indexes: Vec<usize>,
    memory_queries: &Vec<(u32, MemoryQuery)>,
    implicit_memory_queries: &ImplicitMemoryQueries,
    memory_queue_states_accumulator: LastPerCircuitAccumulator<
        QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    >,
    sorted_memory_queue_states_accumulator: LastPerCircuitAccumulator<
        QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>,
    >,
    memory_queue_simulator: MemoryQueuePerCircuitSimulator<Field>,
    sorted_memory_queries_simulator: MemoryQueuePerCircuitSimulator<Field>,
    round_function: &RoundFunction,
    num_non_deterministic_heap_queries: usize,
    geometry: &GeometryConfig,
    artifacts_callback_sender: SyncSender<WitnessGenerationArtifact>,
) -> (
    FirstAndLastCircuitWitness<RamPermutationObservableWitness<Field>>,
    Vec<ClosedFormInputCompactFormWitness<Field>>,
) {
    let total_amount_of_queries =
        memory_queries.len() + implicit_memory_queries.amount_of_queries();

    assert_eq!(
        total_amount_of_queries,
        memory_queue_states_accumulator.len()
    );

    assert_eq!(
        total_amount_of_queries,
        sorted_memory_queue_states_accumulator.len()
    );

    assert!(
        total_amount_of_queries > 0,
        "VM should have made some memory requests"
    );

    let per_circuit_capacity = geometry.cycles_per_ram_permutation as usize;

    let amount_of_circuits =
        (total_amount_of_queries + per_circuit_capacity - 1) / per_circuit_capacity;

    let unsorted_memory_queue_chunk_final_states = memory_queue_states_accumulator.into_circuits();

    assert_eq!(
        unsorted_memory_queue_chunk_final_states.len(),
        amount_of_circuits
    );

    let sorted_memory_queue_chunk_final_states =
        sorted_memory_queue_states_accumulator.into_circuits();

    assert_eq!(
        unsorted_memory_queue_chunk_final_states.len(),
        sorted_memory_queue_chunk_final_states.len()
    );

    assert_eq!(
        sorted_memory_queries_simulator.num_items,
        memory_queue_simulator.num_items
    );

    // since encodings of the elements provide all the information necessary to perform sorting argument,
    // we use them naively

    let all_memory_queries: Vec<&MemoryQuery> = memory_queries
        .iter()
        .map(|(_, query)| query)
        .chain(implicit_memory_queries.iter())
        .collect();

    let mut all_memory_queries_sorted = Vec::with_capacity(all_memory_queries.len()); // TODO cleanup?
    for index in sorted_memory_queries_indexes.iter() {
        all_memory_queries_sorted.push(all_memory_queries[*index]);
    }

    assert_eq!(
        memory_queue_simulator.num_items as usize,
        total_amount_of_queries
    );

    let mut lhs_grand_product_chains =
        Vec::with_capacity(DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS);
    let mut rhs_grand_product_chains =
        Vec::with_capacity(DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS);
    {
        let lhs_contributions: Vec<_> = all_memory_queries
            .par_iter()
            .map(|x| x.encoding_witness())
            .collect();
        let rhs_contributions: Vec<_> = sorted_memory_queries_indexes
            .into_par_iter()
            .map(|x| lhs_contributions[x])
            .collect();

        let challenges = produce_fs_challenges::<
            Field,
            RoundFunction,
            FULL_SPONGE_QUEUE_STATE_WIDTH,
            { MEMORY_QUERY_PACKED_WIDTH + 1 },
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS,
        >(
            memory_queue_simulator.take_sponge_like_queue_state().tail,
            sorted_memory_queries_simulator
                .take_sponge_like_queue_state()
                .tail,
            round_function,
        );

        for idx in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
            let (lhs_grand_product_chain, rhs_grand_product_chain) = compute_grand_product_chains(
                &lhs_contributions,
                &rhs_contributions,
                &challenges[idx],
            );

            assert_eq!(lhs_grand_product_chain.len(), total_amount_of_queries);
            assert_eq!(rhs_grand_product_chain.len(), total_amount_of_queries);
            assert_eq!(
                lhs_grand_product_chain.len(),
                memory_queue_simulator.num_items as usize
            );
            assert_eq!(
                rhs_grand_product_chain.len(),
                sorted_memory_queries_simulator.num_items as usize
            );

            lhs_grand_product_chains.push(lhs_grand_product_chain);
            rhs_grand_product_chains.push(rhs_grand_product_chain);
        }
    }

    let transposed_lhs_chains = transpose_chunks(&lhs_grand_product_chains, per_circuit_capacity);
    let transposed_rhs_chains = transpose_chunks(&rhs_grand_product_chains, per_circuit_capacity);

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    assert_eq!(
        unsorted_memory_queue_chunk_final_states.len(),
        transposed_lhs_chains.len()
    );
    assert_eq!(
        unsorted_memory_queue_chunk_final_states.len(),
        transposed_rhs_chains.len()
    );

    let unsorted_global_final_state = unsorted_memory_queue_chunk_final_states
        .last()
        .unwrap()
        .clone();
    let sorted_global_final_state = sorted_memory_queue_chunk_final_states
        .last()
        .unwrap()
        .clone();

    assert_eq!(
        unsorted_global_final_state.tail.length,
        sorted_global_final_state.tail.length
    );

    let it = unsorted_memory_queue_chunk_final_states
        .into_iter()
        .zip(sorted_memory_queue_chunk_final_states.into_iter())
        .zip(transposed_lhs_chains.into_iter())
        .zip(transposed_rhs_chains.into_iter())
        .zip(all_memory_queries.chunks(per_circuit_capacity))
        .zip(all_memory_queries_sorted.chunks(per_circuit_capacity));

    // now trivial transformation into desired data structures,
    // and we are all good

    let num_circuits = it.len();

    let mut current_lhs_product = [Field::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut current_rhs_product = [Field::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut previous_sorting_key = [0u32; RAM_SORTING_KEY_LENGTH];
    let mut previous_comparison_key = [0u32; RAM_FULL_KEY_LENGTH];
    let mut previous_value = U256::zero();
    let mut previous_is_ptr = false;

    let mut current_number_of_nondet_writes = 0u32;

    use crate::boojum::gadgets::queue::QueueState;
    let placeholder_witness =
        QueueState::<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder_witness();
    let mut last_queue_state = (placeholder_witness.clone(), placeholder_witness);

    let circuit_type = BaseLayerCircuitType::RamValidation;
    let mut maker = CircuitMaker::new(geometry.cycles_per_ram_permutation, round_function.clone());

    for (
        idx,
        (
            (
                (
                    ((unsorted_sponge_final_state, sorted_sponge_final_state), lhs_grand_product),
                    rhs_grand_product,
                ),
                unsorted_queries_in_chunk,
            ),
            sorted_queries_in_chunk,
        ),
    ) in it.enumerate()
    {
        assert_eq!(
            lhs_grand_product.len(),
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS
        );
        assert_eq!(
            rhs_grand_product.len(),
            DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS
        );

        // now we need to have final grand product value that will also become an input for the next circuit

        let if_first = idx == 0;
        let is_last = idx == num_circuits - 1;

        let sorted_states_len = sorted_queries_in_chunk.len();
        let num_nondet_writes_in_chunk = sorted_queries_in_chunk
            .iter()
            .filter(|query| {
                query.rw_flag == true
                    && query.timestamp.0 == 0
                    && query.location.page.0 == BOOTLOADER_HEAP_PAGE
            })
            .count();
        let last_sorted_query = sorted_queries_in_chunk.last().unwrap();

        let new_num_nondet_writes =
            current_number_of_nondet_writes + (num_nondet_writes_in_chunk as u32);

        let last_unsorted_state = unsorted_sponge_final_state;
        let last_sorted_state = sorted_sponge_final_state;

        let accumulated_lhs: [Field; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS] =
            lhs_grand_product
                .into_iter()
                .map(|el| *el.last().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
        let accumulated_rhs: [Field; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS] =
            rhs_grand_product
                .into_iter()
                .map(|el| *el.last().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

        use circuit_definitions::encodings::memory_query::*;
        let sorting_key = sorting_key(&last_sorted_query);
        let comparison_key = comparison_key(&last_sorted_query);
        let is_ptr = last_sorted_query.value_is_pointer;
        let value = last_sorted_query.value;

        let (current_unsorted_queue_state, current_sorted_queue_state) = last_queue_state;

        assert_eq!(
            current_unsorted_queue_state.tail.length,
            current_sorted_queue_state.tail.length
        );

        // we use current final state as the intermediate head
        let mut final_unsorted_state = last_unsorted_state;
        final_unsorted_state.head = final_unsorted_state.tail.tail;
        final_unsorted_state.tail.tail = unsorted_global_final_state.tail.tail;
        final_unsorted_state.tail.length =
            unsorted_global_final_state.tail.length - final_unsorted_state.tail.length;

        let mut final_sorted_state = last_sorted_state;
        final_sorted_state.head = final_sorted_state.tail.tail;
        final_sorted_state.tail.tail = sorted_global_final_state.tail.tail;
        final_sorted_state.tail.length =
            sorted_global_final_state.tail.length - final_sorted_state.tail.length;

        assert_eq!(
            final_unsorted_state.tail.length,
            final_sorted_state.tail.length
        );

        let mut instance_witness = RamPermutationCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                start_flag: if_first,
                completion_flag: is_last,
                observable_input: RamPermutationInputDataWitness {
                    unsorted_queue_initial_state: unsorted_global_final_state.clone(),
                    sorted_queue_initial_state: sorted_global_final_state.clone(),
                    non_deterministic_bootloader_memory_snapshot_length:
                        num_non_deterministic_heap_queries as u32,
                },
                observable_output: (),
                hidden_fsm_input: RamPermutationFSMInputOutputWitness {
                    lhs_accumulator: current_lhs_product,
                    rhs_accumulator: current_rhs_product,
                    current_unsorted_queue_state,
                    current_sorted_queue_state,
                    previous_sorting_key: previous_sorting_key,
                    previous_full_key: previous_comparison_key,
                    previous_value: previous_value,
                    previous_is_ptr: previous_is_ptr,
                    num_nondeterministic_writes: current_number_of_nondet_writes,
                },
                hidden_fsm_output: RamPermutationFSMInputOutputWitness {
                    lhs_accumulator: accumulated_lhs,
                    rhs_accumulator: accumulated_rhs,
                    current_unsorted_queue_state: final_unsorted_state,
                    current_sorted_queue_state: final_sorted_state,
                    previous_sorting_key: sorting_key.0,
                    previous_full_key: comparison_key.0,
                    previous_value: value,
                    previous_is_ptr: is_ptr,
                    num_nondeterministic_writes: new_num_nondet_writes,
                },
            },
            // we will need witnesses to pop elements from the front of the queue
            unsorted_queue_witness: unsorted_queries_in_chunk
                .into_par_iter()
                .map(|x| x.reflect())
                .collect(),
            sorted_queue_witness: sorted_queries_in_chunk
                .into_par_iter()
                .map(|x| x.reflect())
                .collect(),
        };

        if sorted_states_len % per_circuit_capacity != 0 {
            // RAM circuit does padding, so all previous values must be reset
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_sorting_key = [0u32; RAM_SORTING_KEY_LENGTH];
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_full_key = [0u32; RAM_FULL_KEY_LENGTH];
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_value = U256::zero();
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_is_ptr = false;
        }

        current_lhs_product = accumulated_lhs;
        current_rhs_product = accumulated_rhs;

        previous_sorting_key = sorting_key.0;
        previous_comparison_key = comparison_key.0;
        previous_value = value;
        previous_is_ptr = is_ptr;

        current_number_of_nondet_writes = new_num_nondet_writes;

        let tmp = &instance_witness.closed_form_input.hidden_fsm_output;
        last_queue_state = (
            tmp.current_unsorted_queue_state.clone(),
            tmp.current_sorted_queue_state.clone(),
        );

        artifacts_callback_sender
            .send(WitnessGenerationArtifact::BaseLayerCircuit(
                ZkSyncBaseLayerCircuit::RAMPermutation(
                    maker.process(instance_witness, circuit_type),
                ),
            ))
            .unwrap();
    }

    drop(lhs_grand_product_chains);
    drop(rhs_grand_product_chains);

    let (
        ram_permutation_circuits,
        queue_simulator,
        ram_permutation_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    artifacts_callback_sender
        .send(WitnessGenerationArtifact::RecursionQueue((
            circuit_type as u64,
            queue_simulator,
            ram_permutation_circuits_compact_forms_witnesses.clone(),
        )))
        .unwrap();

    (
        ram_permutation_circuits,
        ram_permutation_circuits_compact_forms_witnesses,
    )
}

// #[test]
// fn test_parallelized_grand_product() {
//     // this is only proof of permutation, without extra login on what the permutation should be

//     use crate::ethereum_types::U256;
//     use crate::zk_evm::aux_structures::*;
//     use sync_vm::testing::Bn256;
//     use sync_vm::testing::create_test_memory_artifacts_with_optimized_gate;
//     use sync_vm::franklin_crypto::bellman::pairing::ff::ScalarEngine;
//     use sync_vm::traits::GenericHasher;

//     type E = Bn256;

//     let (_, round_function, _) = create_test_memory_artifacts_with_optimized_gate();

//     // create dummy queries

//     let mut all_queries = vec![];

//     let write = MemoryQuery {
//         timestamp: Timestamp(0),
//         location: MemoryLocation {
//             page: MemoryPage(0),
//             index: MemoryIndex(0),
//             memory_type: MemoryType::Heap,
//         },
//         rw_flag: true,
//         value: U256::from(123u64),
//         is_pended: false,
//         value_is_pointer: false,
//     };

//     all_queries.push(write);

//     for i in (1u32..(1u32<<12)).rev() {
//         let read = MemoryQuery {
//             timestamp: Timestamp(i),
//             location: MemoryLocation {
//                 page: MemoryPage(0),
//                 index: MemoryIndex(0),
//                 memory_type: MemoryType::Heap,
//             },
//             rw_flag: false,
//             value: U256::from(123u64),
//             is_pended: false,
//             value_is_pointer: false,
//         };

//         all_queries.push(read);
//     }

//     // sort by memory location, and then by timestamp
//     let mut sorted_memory_queries_accumulated = all_queries.clone();
//     sorted_memory_queries_accumulated.par_sort_by(|a, b| {
//         match a.location.cmp(&b.location) {
//             Ordering::Equal => a.timestamp.cmp(&b.timestamp),
//             a @ _ => a,
//         }
//     });

//     println!("Sorted");

//     // those two thins are parallelizable, and can be internally parallelized too

//     // now we can finish reconstruction of each sorted and unsorted memory queries

//     let mut unsorted_memory_queue_states = vec![];
//     let mut sorted_memory_queue_states = vec![];

//     let mut unsorted_memory_queries_simulator = MemoryQueueSimulator::<E>::empty();
//     for query in all_queries.iter() {
//         let (_old_tail, intermediate_info) =
//             unsorted_memory_queries_simulator.push_and_output_intermediate_data(*query, &round_function);

//             unsorted_memory_queue_states.push(intermediate_info);
//     }

//     println!("Original committed");

//     // reconstruct sorted one in full
//     let mut sorted_memory_queries_simulator = MemoryQueueSimulator::<E>::empty();
//     for query in sorted_memory_queries_accumulated.iter() {
//         let (_old_tail, intermediate_info) =
//             sorted_memory_queries_simulator.push_and_output_intermediate_data(*query, &round_function);

//         sorted_memory_queue_states.push(intermediate_info);
//     }

//     println!("Sorted committed");

//     // dbg!(&sorted_memory_queries_simulator.num_items);

//     assert_eq!(sorted_memory_queries_simulator.num_items, unsorted_memory_queries_simulator.num_items);

//     // now we should chunk it by circuits but briefly simulating their logic

//     let mut challenges = vec![];

//     let mut fs_input = vec![];
//     fs_input.extend_from_slice(&unsorted_memory_queries_simulator.tail);
//     fs_input.push(u64_to_fe(unsorted_memory_queries_simulator.num_items as u64));
//     fs_input.extend_from_slice(&sorted_memory_queries_simulator.tail);
//     fs_input.push(u64_to_fe(sorted_memory_queries_simulator.num_items as u64));

//     let sequence_of_states = round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&fs_input);
//     let final_state = sequence_of_states.last().unwrap().1;
//     use sync_vm::rescue_poseidon::RescueParams;
//     let base_fs_challenge: <E as ScalarEngine>::Fr = GenericHasher::<Bn256, RescueParams<Bn256, 2, 3>, 2, 3>::simulate_state_into_commitment(final_state);

//     let mut current = base_fs_challenge;
//     challenges.push(current);
//     current.mul_assign(&base_fs_challenge);
//     challenges.push(current);
//     current.mul_assign(&base_fs_challenge);
//     challenges.push(current);

//     // since encodings of the elements provide all the information necessary to perform soring argument,
//     // we use them naively

//     let lhs_contributions: Vec<_> = unsorted_memory_queries_simulator.witness.iter().map(|el| el.0).collect();
//     let rhs_contributions: Vec<_> = sorted_memory_queries_simulator.witness.iter().map(|el| el.0).collect();

//     assert_eq!(lhs_contributions.len(), rhs_contributions.len());

//     let mut lhs_grand_product_chain: Vec<_> = vec![<E as ScalarEngine>::Fr::zero(); lhs_contributions.len()];
//     let mut rhs_grand_product_chain: Vec<_> = vec![<E as ScalarEngine>::Fr::zero(); rhs_contributions.len()];

//     let challenges: [<E as ScalarEngine>::Fr; 3] = challenges.try_into().unwrap();

//     lhs_grand_product_chain.par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE).zip(lhs_contributions.par_chunks(RAM_PERMUTATION_CHUNK_SIZE)).for_each(
//         |(dst, src)| {
//             assert_eq!(dst.len(), src.len());
//             let mut grand_product = <E as ScalarEngine>::Fr::one();
//             for (dst, src) in dst.iter_mut().zip(src.iter()) {
//                 let mut acc = challenges[2];

//                 let mut tmp = src[0];
//                 tmp.mul_assign(&challenges[0]);
//                 acc.add_assign(&tmp);

//                 let mut tmp = src[1];
//                 tmp.mul_assign(&challenges[1]);
//                 acc.add_assign(&tmp);

//                 grand_product.mul_assign(&acc);

//                 *dst = grand_product;
//             }
//         }
//     );

//     rhs_grand_product_chain.par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE).zip(rhs_contributions.par_chunks(RAM_PERMUTATION_CHUNK_SIZE)).for_each(
//         |(dst, src)| {
//             assert_eq!(dst.len(), src.len());
//             let mut grand_product = <E as ScalarEngine>::Fr::one();
//             for (dst, src) in dst.iter_mut().zip(src.iter()) {
//                 let mut acc = challenges[2];

//                 let mut tmp = src[0];
//                 tmp.mul_assign(&challenges[0]);
//                 acc.add_assign(&tmp);

//                 let mut tmp = src[1];
//                 tmp.mul_assign(&challenges[1]);
//                 acc.add_assign(&tmp);

//                 grand_product.mul_assign(&acc);

//                 *dst = grand_product;
//             }
//         }
//     );

//     let mut grand_product = <E as ScalarEngine>::Fr::one();
//     let mut naive_lhs = vec![];
//     for src in lhs_contributions.iter() {
//         let mut acc = challenges[2];

//         let mut tmp = src[0];
//         tmp.mul_assign(&challenges[0]);
//         acc.add_assign(&tmp);

//         let mut tmp = src[1];
//         tmp.mul_assign(&challenges[1]);
//         acc.add_assign(&tmp);

//         grand_product.mul_assign(&acc);

//         naive_lhs.push(grand_product);
//     }

//     assert_eq!(naive_lhs.len(), lhs_grand_product_chain.len());

//     // elementwise products are done, now must fold

//     let mut lhs_intermediates: Vec<<E as ScalarEngine>::Fr> = lhs_grand_product_chain.par_chunks(RAM_PERMUTATION_CHUNK_SIZE).map(
//         |slice: &[<E as ScalarEngine>::Fr]| {
//             *slice.last().unwrap()
//         }
//     ).collect();

//     let mut rhs_intermediates: Vec<<E as ScalarEngine>::Fr> = rhs_grand_product_chain.par_chunks(RAM_PERMUTATION_CHUNK_SIZE).map(
//         |slice: &[<E as ScalarEngine>::Fr]| {
//             *slice.last().unwrap()
//         }
//     ).collect();

//     assert_eq!(lhs_intermediates.len(), lhs_grand_product_chain.chunks(RAM_PERMUTATION_CHUNK_SIZE).len());
//     assert_eq!(rhs_intermediates.len(), rhs_grand_product_chain.chunks(RAM_PERMUTATION_CHUNK_SIZE).len());

//     // accumulate intermediate products
//     // we should multiply element [1] by element [0],
//     // element [2] by [0] * [1],
//     // etc
//     let mut acc_lhs = <E as ScalarEngine>::Fr::one();
//     for el in lhs_intermediates.iter_mut() {
//         let tmp = *el;
//         el.mul_assign(&acc_lhs);
//         acc_lhs.mul_assign(&tmp);
//     }

//     let mut acc_rhs = <E as ScalarEngine>::Fr::one();
//     for el in rhs_intermediates.iter_mut() {
//         let tmp = *el;
//         el.mul_assign(&acc_rhs);
//         acc_rhs.mul_assign(&tmp);
//     }

//     assert_eq!(lhs_intermediates.last().unwrap(), rhs_intermediates.last().unwrap());

//     // here we skip 1 because we do not have anything to pre-accumuate
//     lhs_grand_product_chain.par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE).skip(1).zip(lhs_intermediates.par_chunks(1)).for_each(
//         |(dst, src)| {
//             assert_eq!(src.len(), 1);
//             let src = src[0];
//             for dst in dst.iter_mut() {
//                 dst.mul_assign(&src);
//             }
//         }
//     );

//     for (idx, (a, b)) in naive_lhs.iter().zip(lhs_grand_product_chain.iter()).enumerate() {
//         assert_eq!(a, b, "failed at index {}: a = {}, b = {}", idx, a, b);
//     }

//     rhs_grand_product_chain.par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE).skip(1).zip(rhs_intermediates.par_chunks(1)).for_each(
//         |(dst, src)| {
//             let src = src[0];
//             for dst in dst.iter_mut() {
//                 dst.mul_assign(&src);
//             }
//         }
//     );

//     // sanity check
//     assert_eq!(lhs_grand_product_chain.last().unwrap(), rhs_grand_product_chain.last().unwrap());
// }
