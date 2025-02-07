use arrayvec::ArrayVec;
use boojum::pairing::bls12_381::Fq;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::gates::PublicInputGate;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;

use boojum::gadgets::num::Num;
use boojum::gadgets::queue::CircuitQueueWitness;
use boojum::gadgets::queue::QueueState;
use boojum::gadgets::traits::allocatable::{CSAllocatableExt, CSPlaceholder};
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
use crate::bn254::validation::validate_in_field;
use crate::bn254::ec_pairing::input_alternative::EcMultiPairingCircuitInputOutput;
use super::*;
use crate::base_structures::precompile_input_outputs::PrecompileFunctionOutputData;
use crate::demux_log_queue::StorageLogQueue;
use crate::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::storage_application::ConditionalWitnessAllocator;
use boojum::cs::Variable;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::encodable::WitnessVarLengthEncodable;

use self::ec_mul::implementation::convert_uint256_to_field_element;
use self::input_alternative::EcMultiPairingCircuitInstanceWitness;


pub const NUM_MEMORY_READS_PER_CYCLE: usize = 18;
pub const MEMORY_QUERIES_PER_CALL: usize = 18;
pub const EXCEPTION_FLAGS_ARR_LEN: usize = 19;
const NUM_PAIRINGS_IN_MULTIPAIRING: usize = 3;
#[derive(
    Derivative,
    CSAllocatable,
    CSSelectable,
    CSVarLengthEncodable,
    WitnessHookable,
    WitVarLengthEncodable,
)]
#[derivative(Clone, Copy, Debug)]
pub struct EcMultiPairingPrecompileCallParams<F: SmallField> {
    pub input_page: UInt32<F>,
    pub input_offset: UInt32<F>,
    pub output_page: UInt32<F>,
    pub output_offset: UInt32<F>,
    pub num_pairs: UInt32<F>,
}

impl<F: SmallField> CSPlaceholder<F> for EcMultiPairingPrecompileCallParams<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let zero_u32 = UInt32::zero(cs);
        Self {
            input_page: zero_u32,
            input_offset: zero_u32,
            output_page: zero_u32,
            output_offset: zero_u32,
            num_pairs: zero_u32,
        }
    }
}

impl<F: SmallField> EcMultiPairingPrecompileCallParams<F> {
    pub fn from_encoding<CS: ConstraintSystem<F>>(_cs: &mut CS, encoding: UInt256<F>) -> Self {
        let input_offset = encoding.inner[0];
        let output_offset = encoding.inner[2];
        let input_page = encoding.inner[4];
        let output_page = encoding.inner[5];
        let num_pairs = encoding.inner[6];

        let new = Self {
            input_page,
            input_offset,
            output_page,
            output_offset,
            num_pairs,
        };

        new
    }
}
#[derive(Clone, Debug)]
pub struct G1AffineCoord<F: SmallField> {
    pub x: UInt256<F>,
    pub y: UInt256<F>,
}
#[derive(Clone, Debug)]
pub struct G2AffineCoord<F: SmallField> {
    pub x_c0: UInt256<F>,
    pub x_c1: UInt256<F>,
    pub y_c0: UInt256<F>,
    pub y_c1: UInt256<F>,
}

fn precompile_inner<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    p_points: &[G1AffineCoord<F>],
    q_points: &[G2AffineCoord<F>],
) -> (Boolean<F>, BN256Fq12NNField<F>) {

    assert_eq!(p_points.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    assert_eq!(q_points.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let base_field_params = &Arc::new(bn254_base_field_params());

    let n = p_points.len();
    let mut coordinates: ArrayVec<UInt256<F>, 18> = ArrayVec::new();

    for i in 0..n {
        coordinates.push(p_points[i].x);
        coordinates.push(p_points[i].y);
        coordinates.push(q_points[i].x_c0);
        coordinates.push(q_points[i].x_c1);
        coordinates.push(q_points[i].y_c0);
        coordinates.push(q_points[i].y_c1);
    }
    let coordinates_are_in_field = validate_in_field(cs, &mut coordinates, base_field_params);


    let mut g1_points_in_circuit = Vec::with_capacity(n);
    let mut g2_points_in_circuit = Vec::with_capacity(n);

    for i in 0..n {
        let x = convert_uint256_to_field_element(cs, &p_points[i].x, &base_field_params);
        let y = convert_uint256_to_field_element(cs, &p_points[i].y, &base_field_params);
        use crate::bn254::ec_pairing::alternative_pairing::AffinePoint;
        let p_affine = AffinePoint::from_xy_unchecked(x, y);

        let q_x_c0_fe = convert_uint256_to_field_element(cs, &q_points[i].x_c0, &base_field_params);
        let q_x_c1_fe = convert_uint256_to_field_element(cs, &q_points[i].x_c1, &base_field_params);
        let q_y_c0_fe = convert_uint256_to_field_element(cs, &q_points[i].y_c0, &base_field_params);
        let q_y_c1_fe = convert_uint256_to_field_element(cs, &q_points[i].y_c1, &base_field_params);

        let q_x = BN256Fq2NNField::new(q_x_c0_fe, q_x_c1_fe);
        let q_y = BN256Fq2NNField::new(q_y_c0_fe, q_y_c1_fe);
        use crate::bn254::ec_pairing::alternative_pairing::TwistedCurvePoint;
        let q_affine = TwistedCurvePoint {
            x: q_x,
            y: q_y,
        };

        g1_points_in_circuit.push(p_affine);
        g2_points_in_circuit.push(q_affine);
    }
    use crate::bn254::ec_pairing::alternative_pairing::PairingInput;
    let mut pairing_inputs: Vec<PairingInput<F>> = Vec::with_capacity(n);
    for i in 0..n {
        pairing_inputs.push((
            g1_points_in_circuit[i].clone(),
            g2_points_in_circuit[i].clone(),
        ));
    }

    use crate::bn254::ec_pairing::alternative_pairing::multipairing_naive;
    let (result, _, no_exeption)  = unsafe { multipairing_naive(cs, &mut pairing_inputs) };
    let mut are_valid_inputs = ArrayVec::<_, EXCEPTION_FLAGS_ARR_LEN>::new();
    are_valid_inputs.extend(coordinates_are_in_field);
    are_valid_inputs.push(no_exeption);

    let success = Boolean::multi_and(cs, &are_valid_inputs[..]);

    (success, result)
}

pub fn ecpairing_precompile_inner<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    memory_queue: &mut MemoryQueue<F, R>,
    precompile_calls_queue: &mut StorageLogQueue<F, R>,
    memory_read_witness: ConditionalWitnessAllocator<F, UInt256<F>>,
    _round_function: &R,
    limit: usize,
)
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    assert!(limit <= u32::MAX as usize);

    let precompile_address = UInt160::allocated_constant(
        cs,
        *zkevm_opcode_defs::system_params::ECMULTIPAIRING_NAIVE_PRECOMPILE_FORMAL_ADDRESS,
    );
    let aux_byte_for_precompile = UInt8::allocated_constant(cs, PRECOMPILE_AUX_BYTE);

    let boolean_false = Boolean::allocated_constant(cs, false);
    let boolean_true = Boolean::allocated_constant(cs, true);
    let zero_u256 = UInt256::zero(cs);
    let one_u32 = UInt32::allocated_constant(cs, 1u32);
    // main work cycle
    for _cycle in 0..limit {
        if crate::config::CIRCUIT_VERSOBE {
            dbg!(_cycle);
            dbg!(precompile_calls_queue.into_state().witness_hook(cs)());
        }
        let is_empty = precompile_calls_queue.is_empty(cs);
        let should_process = is_empty.negated(cs);
        let (precompile_call, _) = precompile_calls_queue.pop_front(cs, should_process);

        let params_encoding = precompile_call.key;
        let mut call_params = EcMultiPairingPrecompileCallParams::from_encoding(cs, params_encoding);


        let timestamp_to_use_for_read = precompile_call.timestamp;
        let timestamp_to_use_for_write = timestamp_to_use_for_read.add_no_overflow(cs, one_u32);

        Num::conditionally_enforce_equal(
            cs,
            should_process,
            &Num::from_variable(precompile_call.aux_byte.get_variable()),
            &Num::from_variable(aux_byte_for_precompile.get_variable()),
        );
        for (a, b) in precompile_call
            .address
            .inner
            .iter()
            .zip(precompile_address.inner.iter())
        {
            Num::conditionally_enforce_equal(
                cs,
                should_process,
                &Num::from_variable(a.get_variable()),
                &Num::from_variable(b.get_variable()),
            );
        }

        let mut read_values = [zero_u256; NUM_MEMORY_READS_PER_CYCLE];
        let mut bias_variable = should_process.get_variable();

        for dst in read_values.iter_mut() {
            let read_query_value = memory_read_witness.conditionally_allocate_biased(
                cs,
                should_process,
                bias_variable,
            );
            bias_variable = read_query_value.inner[0].get_variable();

            *dst = read_query_value;

            let read_query = MemoryQuery {
                timestamp: timestamp_to_use_for_read,
                memory_page: call_params.input_page,
                index: call_params.input_offset,
                rw_flag: boolean_false,
                is_ptr: boolean_false,
                value: read_query_value,
            };

            let _ = memory_queue.push(cs, read_query, should_process);
            
            call_params.input_offset = call_params
                .input_offset
                .add_no_overflow(cs, one_u32);

        }

        // Prepare vectors of G1 and G2
        let mut p_points = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
        let mut q_points = Vec::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);
    
        for i in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let x = read_values[6 * i + 0].clone();
            let y = read_values[6 * i + 1].clone();
            let x_c0 = read_values[6 * i + 2].clone();
            let x_c1 = read_values[6 * i + 3].clone();
            let y_c0 = read_values[6 * i + 4].clone();
            let y_c1 = read_values[6 * i + 5].clone();
    
            let p = G1AffineCoord { x, y };
            let q = G2AffineCoord {
                x_c0,
                x_c1,
                y_c0,
                y_c1,
            };
    
            p_points.push(p);
            q_points.push(q);
        }

        let (success,  mut result) = precompile_inner(cs, &p_points, &q_points);


        let success_as_u32 = unsafe { UInt32::from_variable_unchecked(success.get_variable()) };
        let mut success = zero_u256;
        success.inner[0] = success_as_u32;

        let success_query = MemoryQuery {
            timestamp: timestamp_to_use_for_write,
            memory_page: call_params.output_page,
            index: call_params.output_offset,
            rw_flag: boolean_true,
            is_ptr: boolean_false,
            value: success,
        };

        call_params.output_offset = call_params
        .output_offset
        .add_no_overflow(cs, one_u32);

        let _ = memory_queue.push(cs, success_query, should_process);

        let one_fq12 = BN256Fq12NNField::one(cs, &Arc::new(bn254_base_field_params()));
        let paired = result.sub(cs, &mut one_fq12.clone()).is_zero(cs);
        let paired_as_u32 = unsafe { UInt32::from_variable_unchecked(paired.get_variable()) };
        let mut paired = zero_u256;
        paired.inner[0] = paired_as_u32;

        let value_query = MemoryQuery {
            timestamp: timestamp_to_use_for_write,
            memory_page: call_params.output_page,
            index: call_params.output_offset,
            rw_flag: boolean_true,
            value: paired,
            is_ptr: boolean_false,
        };

        let _ = memory_queue.push(cs, value_query, should_process);

    }
    precompile_calls_queue.enforce_consistency(cs);
}

pub fn ecmultipairing_naive_function_entry_point<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    cs: &mut CS,
    witness: EcMultiPairingCircuitInstanceWitness<F>,
    round_function: &R,
    limit: usize,
) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH]
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let EcMultiPairingCircuitInstanceWitness {
        closed_form_input,
        requests_queue_witness,
        memory_reads_witness,
    } = witness;

    let memory_reads_witness: VecDeque<_> = memory_reads_witness.into_iter().flatten().collect();

    let mut structured_input =
        EcMultiPairingCircuitInputOutput::alloc_ignoring_outputs(cs, closed_form_input.clone());

    let start_flag = structured_input.start_flag;

    let requests_queue_state_from_input = structured_input.observable_input.initial_log_queue_state;

    requests_queue_state_from_input.enforce_trivial_head(cs);

    let requests_queue_state_from_fsm = structured_input.hidden_fsm_input.log_queue_state;

    let requests_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &requests_queue_state_from_input,
        &requests_queue_state_from_fsm,
    );

    let mut requests_queue = StorageLogQueue::<F, R>::from_state(cs, requests_queue_state);
    let queue_witness = CircuitQueueWitness::from_inner_witness(requests_queue_witness);
    requests_queue.witness = Arc::new(queue_witness);

    let memory_queue_state_from_input =
        structured_input.observable_input.initial_memory_queue_state;

    memory_queue_state_from_input.enforce_trivial_head(cs);

    let memory_queue_state_from_fsm = structured_input.hidden_fsm_input.memory_queue_state;

    let memory_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &memory_queue_state_from_input,
        &memory_queue_state_from_fsm,
    );

    let mut memory_queue = MemoryQueue::<F, R>::from_state(cs, memory_queue_state);
    let read_queries_allocator = ConditionalWitnessAllocator::<F, UInt256<F>> {
        witness_source: Arc::new(RwLock::new(memory_reads_witness)),
    };

    ecpairing_precompile_inner::<F, CS, R>(
        cs,
        &mut memory_queue,
        &mut requests_queue,
        read_queries_allocator,
        round_function,
        limit,
    );

    let final_memory_state = memory_queue.into_state();
    let final_requests_state = requests_queue.into_state();

    let done = requests_queue.is_empty(cs);
    structured_input.completion_flag = done;
    structured_input.observable_output = PrecompileFunctionOutputData::placeholder(cs);

    structured_input.observable_output.final_memory_state = QueueState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &final_memory_state,
        &structured_input.observable_output.final_memory_state,
    );

    structured_input.hidden_fsm_output.log_queue_state = final_requests_state;
    structured_input.hidden_fsm_output.memory_queue_state = final_memory_state;

    structured_input.hook_compare_witness(cs, &closed_form_input);

    let compact_form =
        ClosedFormInputCompactForm::from_full_form(cs, &structured_input, round_function);
    let input_commitment = commit_variable_length_encodable_item(cs, &compact_form, round_function);
    for el in input_commitment.iter() {
        let gate = PublicInputGate::new(el.get_variable());
        gate.add_to_cs(cs);
    }

    input_commitment
}
