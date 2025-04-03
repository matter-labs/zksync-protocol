use super::*;
use crate::sha3::*;
use crate::zkevm_circuits::base_structures::{log_query::*, vm_state::QUEUE_STATE_WIDTH};
use crate::zkevm_circuits::linear_hasher::input::*;
use circuit_definitions::encodings::*;

pub(crate) fn compute_linear_keccak256<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    simulator: QueueSimulator<
        F,
        zk_evm::aux_structures::LogQuery,
        QUEUE_STATE_WIDTH,
        LOG_QUERY_PACKED_WIDTH,
        LOG_QUERY_ABSORBTION_ROUNDS,
    >,
    capacity: usize,
    _round_function: &R,
) -> Vec<LinearHasherCircuitInstanceWitness<F>> {
    if simulator.num_items == 0 {
        // now we can skip circuits
        return vec![];
    }

    // dbg!(&simulator.num_items);
    assert!(capacity <= u32::MAX as usize);
    let mut full_bytestring = vec![];

    // only append meaningful items
    for (_, _, el) in simulator.witness.iter() {
        let serialized = el.serialize();
        assert_eq!(serialized.len(), L2_TO_L1_MESSAGE_BYTE_LENGTH);
        full_bytestring.extend(serialized);
    }

    let pubdata_hash: [u8; 32] = Keccak256::digest(&full_bytestring)
        .as_slice()
        .try_into()
        .unwrap();

    // in general we have everything ready, just form the witness

    let mut input_passthrough_data = LinearHasherInputData::placeholder_witness();
    // we only need the state of demuxed rollup storage queue
    input_passthrough_data.queue_state = take_queue_state_from_simulator(&simulator);

    let mut output_passthrough_data = LinearHasherOutputData::placeholder_witness();
    output_passthrough_data.keccak256_hash = pubdata_hash;

    let input_queue_witness: VecDeque<_> = simulator
        .witness
        .iter()
        .map(|(_encoding, old_tail, element)| {
            let circuit_witness = element.reflect();

            (circuit_witness, *old_tail)
        })
        .collect();

    let witness = LinearHasherCircuitInstanceWitness {
        closed_form_input: ClosedFormInputWitness {
            start_flag: true,
            completion_flag: true,
            observable_input: input_passthrough_data,
            observable_output: output_passthrough_data,
            hidden_fsm_input: (),
            hidden_fsm_output: (),
        },

        queue_witness: CircuitQueueRawWitness {
            elements: input_queue_witness,
        },
    };

    vec![witness]
}
