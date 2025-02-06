use std::sync::Arc;

use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::gates::PublicInputGate;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::num::Num;
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueue;
use boojum::gadgets::queue::{CircuitQueue, CircuitQueueRawWitness, CircuitQueueWitness, QueueState};
use boojum::gadgets::traits::allocatable::{CSAllocatable, CSAllocatableExt, CSPlaceholder};
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::traits::encodable::{CircuitVarLengthEncodable, WitnessVarLengthEncodable};
use boojum::gadgets::traits::round_function::CircuitRoundFunction;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use boojum::gadgets::{u8::UInt8, u32::UInt32, u160::UInt160, u256::UInt256, boolean::Boolean};

use crate::base_structures::log_query::LogQuery;
use crate::base_structures::memory_query::{MemoryQuery, MemoryQueue};
use crate::base_structures::precompile_input_outputs::{PrecompileFunctionInputData, PrecompileFunctionOutputData};
use crate::demux_log_queue::StorageLogQueue;
use crate::fsm_input_output::{commit_variable_length_encodable_item, ClosedFormInput, ClosedFormInputCompactForm, ClosedFormInputWitness};
use crate::storage_application::ConditionalWitnessAllocator;

pub fn check_precompile_meta<
    F: SmallField,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    should_process: Boolean<F>,
    precompile_address: UInt160<F>,    
    query: LogQuery<F>,
    aux_byte_for_precompile: UInt8<F>,
) {
    Num::conditionally_enforce_equal(
        cs,
        should_process,
        &Num::from_variable(query.aux_byte.get_variable()),
        &Num::from_variable(aux_byte_for_precompile.get_variable()),
    );
    for (a, b) in query
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
}

pub fn add_read_values_to_queue
<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>
(
    cs: &mut CS,
    should_process: Boolean<F>,
    read_values: &mut [UInt256<F>],
    read_queries_allocator: &ConditionalWitnessAllocator<F, UInt256<F>>,
    memory_queue: &mut FullStateCircuitQueue<F, MemoryQuery<F>, 8, 12, 4, 8, R>,
    timestamp_to_use_for_read: UInt32<F>,
    input_page: UInt32<F>,
    input_offset: &mut UInt32<F>,
    boolean_false: Boolean<F>,
    one_u32: UInt32<F>
)
where 
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let mut bias_variable = should_process.get_variable();

    for dst in read_values.iter_mut() {
        let read_query_value = read_queries_allocator.conditionally_allocate_biased(
            cs,
            should_process,
            bias_variable,
        );
        bias_variable = read_query_value.inner[0].get_variable();

        *dst = read_query_value;

        let read_query = MemoryQuery {
            timestamp: timestamp_to_use_for_read,
            memory_page: input_page,
            index: *input_offset,
            rw_flag: boolean_false,
            is_ptr: boolean_false,
            value: read_query_value,
        };

        let _ = memory_queue.push(cs, read_query, should_process);

        *input_offset = input_offset
            .add_no_overflow(cs, one_u32);
    }
}

pub fn compute_final_requests_and_memory_states
<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    T: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessVarLengthEncodable<F> + WitnessHookable<F> + PrettyComparison<F>,
>
(
    cs: &mut CS,
    requests_queue: CircuitQueue<F, LogQuery<F>, 8, 12, 4, 4, 20, R>,
    structured_input: &mut ClosedFormInput<F, T, PrecompileFunctionInputData<F>, PrecompileFunctionOutputData<F>>,
    memory_queue: FullStateCircuitQueue<F, MemoryQuery<F>, 8, 12, 4, 8, R>,
) -> (QueueState<F, 4>, QueueState<F, 12>)
where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{
    requests_queue.enforce_consistency(cs);

    let done = requests_queue.is_empty(cs);
    structured_input.completion_flag = done;
    structured_input.observable_output = PrecompileFunctionOutputData::<F>::placeholder(cs);

    let final_memory_state = memory_queue.into_state();
    let final_requests_state = requests_queue.into_state();

    structured_input.observable_output.final_memory_state = QueueState::conditionally_select(
        cs,
        structured_input.completion_flag,
        &final_memory_state,
        &structured_input.observable_output.final_memory_state,
    );

    (final_requests_state, final_memory_state)

}

pub fn hook_witness_and_generate_input_commitment
<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    T: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessVarLengthEncodable<F> + WitnessHookable<F> + PrettyComparison<F>,
>
(
    cs: &mut CS,
    round_function: &R,
    structured_input: ClosedFormInput<F, T, PrecompileFunctionInputData<F>, PrecompileFunctionOutputData<F>>,
    closed_form_input: ClosedFormInputWitness<F, T, PrecompileFunctionInputData<F>, PrecompileFunctionOutputData<F>>,

) -> [Num<F>; 4]
where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{
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

pub fn create_requests_state_and_memory_state
<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    T: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessVarLengthEncodable<F> + WitnessHookable<F> + PrettyComparison<F>,
>
(
    cs: &mut CS,
    structured_input: &ClosedFormInput<F, T, PrecompileFunctionInputData<F>, PrecompileFunctionOutputData<F>>,
    requests_queue_state_from_input: &QueueState<F, 4>,
    requests_queue_state_from_fsm: &QueueState<F, 4>,
    memory_queue_state_from_fsm: &QueueState<F, 12>,
    start_flag: Boolean<F>,
    requests_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, 20>,
)
-> (CircuitQueue<F, LogQuery<F>, 8, 12, 4, 4, 20, R>, FullStateCircuitQueue<F, MemoryQuery<F>, 8, 12, 4, 8, R>) where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{

    let requests_queue_state = QueueState::conditionally_select(
        cs,
        structured_input.start_flag,
        requests_queue_state_from_input,
        requests_queue_state_from_fsm,
    );

    let mut requests_queue = StorageLogQueue::<F, R>::from_state(cs, requests_queue_state);
    let queue_witness = CircuitQueueWitness::from_inner_witness(requests_queue_witness);
    requests_queue.witness = Arc::new(queue_witness);

    let memory_queue_state_from_input =
        structured_input.observable_input.initial_memory_queue_state;
    memory_queue_state_from_input.enforce_trivial_head(cs);

    let memory_queue_state = QueueState::conditionally_select(
        cs,
        start_flag,
        &memory_queue_state_from_input,
        &memory_queue_state_from_fsm,
    );

    let memory_queue = MemoryQueue::<F, R>::from_state(cs, memory_queue_state);

    (requests_queue, memory_queue)
}

pub fn add_query_to_queue
<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>
(
    cs: &mut CS,
    should_process: Boolean<F>,
    memory_queue: &mut FullStateCircuitQueue<F, MemoryQuery<F>, 8, 12, 4, 8, R>,
    timestamp: UInt32<F>,
    memory_page: UInt32<F>,
    index: &mut UInt32<F>,
    rw_flag: Boolean<F>,
    is_ptr: Boolean<F>,
    value: UInt256<F>,
    one_u32: UInt32<F>,
    should_increment_offset: bool
)
where
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    let query = MemoryQuery {
        timestamp,
        memory_page,
        index: *index,
        rw_flag,
        is_ptr,
        value,
    };

    let _ = memory_queue.push(cs, query, should_process);
    
    if should_increment_offset {
        *index = index
            .add_no_overflow(cs, one_u32);
    }
}
