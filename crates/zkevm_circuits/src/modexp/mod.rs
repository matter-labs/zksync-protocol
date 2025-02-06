pub mod implementation;

// Testing packages
pub mod input;
#[cfg(test)]
pub mod test;
pub mod tests_json;

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use boojum::algebraic_props::round_function::AlgebraicRoundFunction;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;

use boojum::gadgets::num::Num;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u160::UInt160;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use cs_derive::*;
use derivative::Derivative;
use zkevm_opcode_defs::system_params::PRECOMPILE_AUX_BYTE;

use crate::base_structures::log_query::*;
use crate::base_structures::memory_query::*;
use crate::bn254::utils::{
    add_query_to_queue, add_read_values_to_queue, check_precompile_meta,
    compute_final_requests_and_memory_states, create_requests_state_and_memory_state,
    hook_witness_and_generate_input_commitment,
};
use crate::ethereum_types::U256;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::modexp::implementation::u256::modexp_32_32_32;
use crate::modexp::input::{ModexpCircuitInputOutput, ModexpCircuitInstanceWitness};
use crate::storage_application::ConditionalWitnessAllocator;

use super::*;

pub const NUM_MEMORY_READS_PER_CYCLE: usize = 3;

#[derive(Derivative, CSSelectable)]
#[derivative(Clone, Debug)]
pub struct ModexpPrecompileCallParams<F: SmallField> {
    pub input_page: UInt32<F>,
    pub input_offset: UInt32<F>,
    pub output_page: UInt32<F>,
    pub output_offset: UInt32<F>,
}

impl<F: SmallField> ModexpPrecompileCallParams<F> {
    pub fn from_encoding<CS: ConstraintSystem<F>>(_cs: &mut CS, encoding: UInt256<F>) -> Self {
        let input_offset = encoding.inner[0];
        let output_offset = encoding.inner[2];
        let input_page = encoding.inner[4];
        let output_page = encoding.inner[5];

        let new = Self {
            input_page,
            input_offset,
            output_page,
            output_offset,
        };

        new
    }
}

pub fn modexp_function_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: ModexpCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let ModexpCircuitInstanceWitness {
        closed_form_input,
        requests_queue_witness,
        memory_reads_witness,
    } = witness;
    let memory_reads_witness: VecDeque<_> = memory_reads_witness.into_iter().flatten().collect();

    let mut structured_input =
        ModexpCircuitInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());
    let start_flag = structured_input.start_flag;

    let requests_queue_state_from_input = structured_input.observable_input.initial_log_queue_state;
    requests_queue_state_from_input.enforce_trivial_head(cs);

    let requests_queue_state_from_fsm = structured_input.hidden_fsm_input.log_queue_state;
    let memory_queue_state_from_fsm = structured_input.hidden_fsm_input.memory_queue_state;

    let (mut requests_queue, mut memory_queue) = create_requests_state_and_memory_state(
        cs,
        &structured_input,
        &requests_queue_state_from_input,
        &requests_queue_state_from_fsm,
        &memory_queue_state_from_fsm,
        start_flag,
        requests_queue_witness,
    );

    let read_queries_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
        witness_source: Arc::new(RwLock::new(memory_reads_witness)),
    };

    let precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::MODEXP_PRECOMPILE_FORMAL_ADDRESS,
    );

    let one_u32 = UInt32::allocated_constant(cs, 1u32);
    let zero_u256 = UInt256::zero(cs);
    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);
    let aux_byte_for_precompile = UInt8::allocated_constant(cs, PRECOMPILE_AUX_BYTE);

    for _cycle in 0..limit {
        let is_empty = requests_queue.is_empty(cs);
        let should_process = is_empty.negated(cs);
        let (request, _) = requests_queue.pop_front(cs, should_process);

        let mut precompile_call_params = ModexpPrecompileCallParams::from_encoding(cs, request.key);

        let timestamp_to_use_for_read = request.timestamp;
        let timestamp_to_use_for_write = timestamp_to_use_for_read.add_no_overflow(cs, one_u32);

        check_precompile_meta(
            cs,
            should_process,
            precompile_address,
            request,
            aux_byte_for_precompile,
        );

        let mut read_values = [zero_u256; NUM_MEMORY_READS_PER_CYCLE];

        add_read_values_to_queue::<F, CS, R>(
            cs,
            should_process,
            &mut read_values,
            &read_queries_allocator,
            &mut memory_queue,
            timestamp_to_use_for_read,
            precompile_call_params.input_page,
            &mut precompile_call_params.input_offset,
            boolean_false,
            one_u32,
        );

        let [base, exponent, modulus] = read_values;
        let result = modexp_32_32_32(cs, &base, &exponent, &modulus);

        if crate::config::CIRCUIT_VERSOBE {
            if should_process.witness_hook(cs)().unwrap() == true {
                dbg!(result.witness_hook(cs)());
            }
        }

        add_query_to_queue(
            cs,
            should_process,
            &mut memory_queue,
            timestamp_to_use_for_write,
            precompile_call_params.output_page,
            &mut precompile_call_params.output_offset,
            boolean_true,
            boolean_false,
            result,
            one_u32,
            false,
        );
    }

    let (final_requests_state, final_memory_state) = compute_final_requests_and_memory_states(
        cs,
        requests_queue,
        &mut structured_input,
        memory_queue,
    );

    structured_input.hidden_fsm_output.log_queue_state = final_requests_state;
    structured_input.hidden_fsm_output.memory_queue_state = final_memory_state;

    hook_witness_and_generate_input_commitment(
        cs,
        round_function,
        structured_input,
        closed_form_input,
    )
}
