use arrayvec::ArrayVec;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use boojum::algebraic_props::round_function::AlgebraicRoundFunction;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;

use boojum::gadgets::num::Num;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::u160::UInt160;
use boojum::gadgets::u256::UInt256;
use boojum::gadgets::u32::UInt32;
use boojum::gadgets::u8::UInt8;
use boojum::pairing::CurveAffine;
use cs_derive::*;
use derivative::Derivative;
use zkevm_opcode_defs::system_params::PRECOMPILE_AUX_BYTE;

use crate::base_structures::log_query::*;
use crate::base_structures::memory_query::*;
use crate::bn254::ec_add::input::EcAddCircuitInputOutput;
use crate::bn254::validation::{is_affine_infinity, is_on_curve, validate_in_field};
use crate::ethereum_types::U256;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::fsm_input_output::*;
use crate::storage_application::ConditionalWitnessAllocator;

use super::utils::{
    add_query_to_queue, add_read_values_to_queue, check_precompile_meta,
    compute_final_requests_and_memory_states, create_requests_state_and_memory_state,
    generate_input_commitment,
};
use super::*;

use self::ec_mul::implementation::{
    convert_field_element_to_uint256, convert_uint256_to_field_element,
};
use self::input::EcAddCircuitInstanceWitness;

pub mod implementation;
pub mod input;

pub const MEMORY_QUERIES_PER_CALL: usize = 4;
pub const NUM_MEMORY_READS_PER_CYCLE: usize = 4;
const EXCEPTION_FLAGS_ARR_LEN: usize = 6;

#[derive(Derivative, CSSelectable)]
#[derivative(Clone, Debug)]
pub struct EcAddPrecompileCallParams<F: SmallField> {
    pub input_page: UInt32<F>,
    pub input_offset: UInt32<F>,
    pub output_page: UInt32<F>,
    pub output_offset: UInt32<F>,
}

impl<F: SmallField> EcAddPrecompileCallParams<F> {
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

fn ecadd_precompile_inner<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    x1: &UInt256<F>,
    y1: &UInt256<F>,
    x2: &UInt256<F>,
    y2: &UInt256<F>,
) -> (Boolean<F>, (UInt256<F>, UInt256<F>)) {
    let base_field_params = &Arc::new(bn254_base_field_params());

    // We need to check for infinity prior to potential masking coordinates.
    let point1_is_infinity = is_affine_infinity(cs, (x1, y1));
    let point2_is_infinity = is_affine_infinity(cs, (x2, y2));

    // Coordinates are masked with zero in-place if they are not in field.
    let mut coordinates = ArrayVec::from([*x1, *y1, *x2, *y2]);
    let coordinates_are_in_field = validate_in_field(cs, &mut coordinates, base_field_params);
    let [x1, y1, x2, y2] = coordinates.into_inner().unwrap();

    let x1 = convert_uint256_to_field_element(cs, &x1, base_field_params);
    let y1 = convert_uint256_to_field_element(cs, &y1, base_field_params);

    let point1_on_curve = is_on_curve(cs, (&x1, &y1), base_field_params);
    let point1_is_valid = point1_on_curve.or(cs, point1_is_infinity);

    // Mask the point with zero in case it is not on curve.
    let zero = BN256SWProjectivePoint::zero(cs, base_field_params);
    let unchecked_point = BN256SWProjectivePoint::from_xy_unchecked(cs, x1, y1);
    let mut point1 =
        BN256SWProjectivePoint::conditionally_select(cs, point1_on_curve, &unchecked_point, &zero);

    let x2 = convert_uint256_to_field_element(cs, &x2, base_field_params);
    let y2 = convert_uint256_to_field_element(cs, &y2, base_field_params);

    let point2_on_curve = is_on_curve(cs, (&x2, &y2), base_field_params);
    let point2_is_valid = point2_on_curve.or(cs, point2_is_infinity);

    let mut result = point1.add_mixed_inf_pass(cs, &mut (x2, y2), point2_is_infinity);
    let ((mut x, mut y), _) = result.convert_to_affine_or_default(cs, BN256Affine::zero());

    x.normalize(cs);
    let x = convert_field_element_to_uint256(cs, x);
    y.normalize(cs);
    let y = convert_field_element_to_uint256(cs, y);

    let mut are_valid_inputs = ArrayVec::<_, EXCEPTION_FLAGS_ARR_LEN>::new();
    are_valid_inputs.extend(coordinates_are_in_field);
    are_valid_inputs.push(point1_is_valid);
    are_valid_inputs.push(point2_is_valid);

    let success = Boolean::multi_and(cs, &are_valid_inputs[..]);
    let x = x.mask(cs, success);
    let y = y.mask(cs, success);

    (success, (x, y))
}

pub fn ecadd_function_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: EcAddCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let EcAddCircuitInstanceWitness {
        closed_form_input,
        requests_queue_witness,
        memory_reads_witness,
    } = witness;
    let memory_reads_witness: VecDeque<_> = memory_reads_witness.into_iter().flatten().collect();

    let mut structured_input =
        EcAddCircuitInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

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
        *zkevm_opcode_defs::system_params::ECADD_PRECOMPILE_FORMAL_ADDRESS,
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

        let mut precompile_call_params = EcAddPrecompileCallParams::from_encoding(cs, request.key);

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

        let [x1, y1, x2, y2] = read_values;

        if crate::config::CIRCUIT_VERSOBE {
            if should_process.witness_hook(cs)().unwrap() == true {
                dbg!(x1.witness_hook(cs)());
                dbg!(y1.witness_hook(cs)());
                dbg!(x2.witness_hook(cs)());
                dbg!(y2.witness_hook(cs)());
            }
        }

        let (success, (x, y)) = ecadd_precompile_inner(cs, &x1, &y1, &x2, &y2);

        let success_as_u32 = unsafe { UInt32::from_variable_unchecked(success.get_variable()) };
        let mut success = zero_u256;
        success.inner[0] = success_as_u32;

        if crate::config::CIRCUIT_VERSOBE {
            if should_process.witness_hook(cs)().unwrap() == true {
                dbg!(success.witness_hook(cs)());
                dbg!(x.witness_hook(cs)());
                dbg!(y.witness_hook(cs)());
            }
        }

        for val in vec![success, x, y] {
            add_query_to_queue(
                cs,
                should_process,
                &mut memory_queue,
                timestamp_to_use_for_write,
                precompile_call_params.output_page,
                &mut precompile_call_params.output_offset,
                boolean_true,
                boolean_false,
                val,
                one_u32,
            );
        }
    }

    let (final_requests_state, final_memory_state) = compute_final_requests_and_memory_states(
        cs,
        requests_queue,
        &mut structured_input,
        memory_queue,
    );

    structured_input.hidden_fsm_output.log_queue_state = final_requests_state;
    structured_input.hidden_fsm_output.memory_queue_state = final_memory_state;

    structured_input.hook_compare_witness(cs, &closed_form_input);

    generate_input_commitment(cs, round_function, structured_input)
}
