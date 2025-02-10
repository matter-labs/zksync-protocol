use crate::base_structures::{register::VMRegister, vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH};
use boojum::config::*;
use boojum::cs::traits::cs::DstBuffer;

use super::*;

use crate::base_structures::vm_state::saved_context::ExecutionContextRecord;
use crate::base_structures::vm_state::QUEUE_STATE_WIDTH;
use crate::main_vm::witness_oracle::SynchronizedWitnessOracle;
use crate::main_vm::witness_oracle::WitnessOracle;
use boojum::gadgets::traits::allocatable::CSAllocatableExt;

use arrayvec::ArrayVec;

pub(crate) struct RetData<F: SmallField> {
    pub(crate) apply_ret: Boolean<F>,
    pub(crate) is_panic: Boolean<F>,
    pub(crate) did_return_from_far_call: Boolean<F>,
    pub(crate) originally_popped_context: ExecutionContextRecord<F>,
    pub(crate) new_context: ExecutionContextRecord<F>,
    pub(crate) previous_callstack_state: [Num<F>; FULL_SPONGE_QUEUE_STATE_WIDTH],
    pub(crate) new_forward_queue_tail: [Num<F>; QUEUE_STATE_WIDTH], // after we glue
    pub(crate) new_forward_queue_len: UInt32<F>,
    pub(crate) specific_registers_updates: [Option<(Boolean<F>, VMRegister<F>)>; REGISTERS_COUNT],
    pub(crate) specific_registers_zeroing: [Option<Boolean<F>>; REGISTERS_COUNT],
    pub(crate) remove_ptr_on_specific_registers: [Option<Boolean<F>>; REGISTERS_COUNT],
    pub(crate) new_pubdata_revert_counter: UInt32<F>,
}

pub(crate) fn callstack_candidate_for_ret<
    F: SmallField,
    CS: ConstraintSystem<F>,
    W: WitnessOracle<F>,
>(
    cs: &mut CS,
    draft_vm_state: &VmLocalState<F>,
    common_opcode_state: &CommonOpcodeState<F>,
    opcode_carry_parts: &AfterDecodingCarryParts<F>,
    witness_oracle: &SynchronizedWitnessOracle<F, W>,
    common_abi_parts: &CommonCallRetABI<F>,
    forwarding_data: &CallRetForwardingMode<F>,
) -> RetData<F>
where
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    // new callstack should be just the same a the old one, but we also need to update the pricing for pubdata in the rare case
    const RET_OPCODE: zkevm_opcode_defs::Opcode =
        zkevm_opcode_defs::Opcode::Ret(zkevm_opcode_defs::RetOpcode::Ok);

    let execute = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_opcode(RET_OPCODE);

    let is_ret_ok = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(zkevm_opcode_defs::Opcode::Ret(
            zkevm_opcode_defs::RetOpcode::Ok,
        ));
    // revert and panic are different only in ABI: whether we zero-out any hints (returndata) about why we reverted or not
    let is_ret_revert = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(zkevm_opcode_defs::Opcode::Ret(
            zkevm_opcode_defs::RetOpcode::Revert,
        ));
    let is_ret_panic = common_opcode_state
        .decoded_opcode
        .properties_bits
        .boolean_for_variant(zkevm_opcode_defs::Opcode::Ret(
            zkevm_opcode_defs::RetOpcode::Panic,
        ));

    let is_local_frame = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .is_local_call;

    let is_kernel_frame = draft_vm_state
        .callstack
        .current_context
        .saved_context
        .is_kernel_mode;

    if crate::config::CIRCUIT_VERSOBE {
        if execute.witness_hook(&*cs)().unwrap_or(false) {
            println!("Applying RET");
            if is_local_frame.witness_hook(&*cs)().unwrap_or(false) {
                println!("Is local RET");
            } else {
                println!("Is global RET");
            }

            if is_ret_ok.witness_hook(&*cs)().unwrap_or(false) {
                println!("Applying RET Ok");
            }
            if is_ret_revert.witness_hook(&*cs)().unwrap_or(false) {
                println!("Applying RET Revert");
            }
            if is_ret_panic.witness_hook(&*cs)().unwrap_or(false) {
                println!("Applying RET Panic");
            }
        }
    }

    // on panic, we should never return any data. in this case, zero out src0 data
    let mut src0 = common_opcode_state.src0.clone();
    src0.conditionally_erase(cs, is_ret_panic);

    let current_callstack_entry = draft_vm_state.callstack.current_context.saved_context;

    // we may want to return to label
    let is_to_label = common_opcode_state
        .decoded_opcode
        .properties_bits
        .flag_booleans[zkevm_opcode_defs::ret::RET_TO_LABEL_BIT_IDX];

    let label_pc = common_opcode_state.decoded_opcode.imm0;

    let current_depth = draft_vm_state.callstack.context_stack_depth;

    // it's a composite allocation, so we handwrite it

    let (mut new_callstack_entry, previous_callstack_state) = {
        // this applies necessary constraints
        let raw_callstack_entry = ExecutionContextRecord::create_without_value(cs);
        let raw_previous_callstack_state =
            cs.alloc_multiple_variables_without_values::<FULL_SPONGE_QUEUE_STATE_WIDTH>();

        if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
            let oracle = witness_oracle.clone();

            let dependencies = [
                current_depth.get_variable().into(),
                execute.get_variable().into(),
            ];

            let mut outputs_to_set = Vec::with_capacity(
                <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN
                    + FULL_SPONGE_QUEUE_STATE_WIDTH,
            );
            outputs_to_set.extend(Place::from_variables(
                raw_callstack_entry.flatten_as_variables(),
            ));
            outputs_to_set.extend(Place::from_variables(raw_previous_callstack_state));

            cs.set_values_with_dependencies_vararg(
                &dependencies,
                &outputs_to_set,
                move |inputs: &[F], buffer: &mut DstBuffer<'_, '_, F>| {
                    let callstack_depth =
                        <u32 as WitnessCastable<F, F>>::cast_from_source(inputs[0]);
                    let execute = <bool as WitnessCastable<F, F>>::cast_from_source(inputs[1]);

                    let mut guard = oracle.inner.write().expect("not poisoned");
                    let (record_witness, previous_state) =
                        guard.get_callstack_witness(execute, callstack_depth);
                    drop(guard);

                    ExecutionContextRecord::set_internal_variables_values(record_witness, buffer);
                    buffer.extend(previous_state);
                },
            );
        }

        let previous_callstack_state =
            raw_previous_callstack_state.map(|el| Num::from_variable(el));

        (raw_callstack_entry, previous_callstack_state)
    };

    let originally_popped_context = new_callstack_entry;

    // pass back all the ergs (after we paid the cost of "ret" itself),
    // with may be a small charge for memory growth
    let preliminary_ergs_left = opcode_carry_parts.preliminary_ergs_left;

    // resolve some exceptions over fat pointer use and memory growth

    // exceptions that are specific only to return from non-local frame
    let mut non_local_frame_exceptions = ArrayVec::<Boolean<F>, 5>::new();

    let forward_fat_pointer = forwarding_data.forward_fat_pointer;
    let do_not_forward_ptr = forward_fat_pointer.negated(cs);
    let src0_is_integer = src0.is_pointer.negated(cs);
    let is_far_return = is_local_frame.negated(cs);

    // resolve returndata pointer if forwarded
    let fat_ptr_expected_exception =
        Boolean::multi_and(cs, &[forward_fat_pointer, src0_is_integer, is_far_return]);
    non_local_frame_exceptions.push(fat_ptr_expected_exception);
    // symmetric otherwise
    let non_pointer_expected_exception =
        Boolean::multi_and(cs, &[do_not_forward_ptr, src0.is_pointer, is_far_return]);
    non_local_frame_exceptions.push(non_pointer_expected_exception);

    // we also want unidirectional movement of returndata
    // check if fat_ptr.memory_page < ctx.base_page and throw if it's the case
    let (_, uf) = common_abi_parts.fat_ptr.page.overflowing_sub(
        cs,
        draft_vm_state
            .callstack
            .current_context
            .saved_context
            .base_page,
    );

    // if we try to forward then we should be unidirectional, unless kernel knows what it's doing
    let is_usermode = is_kernel_frame.negated(cs);
    let non_unidirectional_forwarding =
        Boolean::multi_and(cs, &[forward_fat_pointer, uf, is_usermode]);

    non_local_frame_exceptions.push(non_unidirectional_forwarding);

    non_local_frame_exceptions.push(is_ret_panic); // just feed it here as a shorthand

    let exceptions_collapsed = Boolean::multi_or(cs, &non_local_frame_exceptions);

    let fat_ptr = common_abi_parts
        .fat_ptr
        .mask_into_empty(cs, exceptions_collapsed);

    // now we can modify fat ptr that is prevalidated

    let fat_ptr_adjusted_if_forward = fat_ptr.readjust(cs);

    let page = UInt32::conditionally_select(
        cs,
        forwarding_data.use_heap,
        &opcode_carry_parts.heap_page,
        &opcode_carry_parts.aux_heap_page,
    );

    let zero_u32 = UInt32::zero(cs);

    let fat_ptr_for_heaps = FatPtrInABI {
        offset: zero_u32,
        page,
        start: fat_ptr.start,
        length: fat_ptr.length,
    };

    let fat_ptr = FatPtrInABI::conditionally_select(
        cs,
        forwarding_data.forward_fat_pointer,
        &fat_ptr_adjusted_if_forward,
        &fat_ptr_for_heaps,
    );

    // potentially pay for memory growth

    let memory_region_is_not_addressable = common_abi_parts.ptr_validation_data.is_non_addressable;
    let upper_bound = common_abi_parts.upper_bound;
    // first mask to 0 if exceptions happened
    let upper_bound = upper_bound.mask_negated(cs, exceptions_collapsed);
    // then compute to penalize for out of memory access attemp

    // and penalize if pointer is fresh and not addressable
    let penalize_heap_overflow =
        Boolean::multi_and(cs, &[memory_region_is_not_addressable, do_not_forward_ptr]);
    let u32_max = UInt32::allocated_constant(cs, u32::MAX);

    let upper_bound =
        UInt32::conditionally_select(cs, penalize_heap_overflow, &u32_max, &upper_bound);

    let heap_max_accessed = upper_bound.mask(cs, forwarding_data.use_heap);
    let heap_bound = current_callstack_entry.heap_upper_bound;
    let (mut heap_growth, uf) = heap_max_accessed.overflowing_sub(cs, heap_bound);
    heap_growth = heap_growth.mask_negated(cs, uf); // of we access in bounds then it's 0
    let grow_heap = Boolean::multi_and(cs, &[forwarding_data.use_heap, execute, is_far_return]);

    let aux_heap_max_accessed = upper_bound.mask(cs, forwarding_data.use_aux_heap);
    let aux_heap_bound = current_callstack_entry.aux_heap_upper_bound;
    let (mut aux_heap_growth, uf) = aux_heap_max_accessed.overflowing_sub(cs, aux_heap_bound);
    aux_heap_growth = aux_heap_growth.mask_negated(cs, uf); // of we access in bounds then it's 0
    let grow_aux_heap =
        Boolean::multi_and(cs, &[forwarding_data.use_aux_heap, execute, is_far_return]);

    let mut growth_cost = heap_growth.mask(cs, grow_heap);
    growth_cost = UInt32::conditionally_select(cs, grow_aux_heap, &aux_heap_growth, &growth_cost);

    // subtract
    let (ergs_left_after_growth, uf) = preliminary_ergs_left.overflowing_sub(cs, growth_cost);

    let mut non_local_frame_exceptions = ArrayVec::<Boolean<F>, 4>::new();
    non_local_frame_exceptions.push(exceptions_collapsed);

    let ergs_left_after_growth = ergs_left_after_growth.mask_negated(cs, uf); // if not enough - set to 0
    non_local_frame_exceptions.push(uf);

    let ergs_left_after_growth = UInt32::conditionally_select(
        cs,
        is_local_frame,
        &preliminary_ergs_left,
        &ergs_left_after_growth,
    );

    non_local_frame_exceptions.push(is_ret_panic);

    let non_local_frame_panic = Boolean::multi_or(cs, &non_local_frame_exceptions);
    let non_local_frame_panic = Boolean::multi_and(cs, &[non_local_frame_panic, is_far_return]);
    let final_fat_ptr = fat_ptr.mask_into_empty(cs, non_local_frame_panic);

    // -----------------------------------------

    // we should subtract stipend, but only if we exit non-local frame
    let stipend_to_subtract = current_callstack_entry
        .stipend
        .mask_negated(cs, is_local_frame);
    let (ergs_after_stipend_subtraction, uf) =
        ergs_left_after_growth.overflowing_sub(cs, stipend_to_subtract);
    let ergs_after_stipend_subtraction = ergs_after_stipend_subtraction.mask_negated(cs, uf);

    // give the rest to the original caller
    let new_ergs_left =
        ergs_after_stipend_subtraction.add_no_overflow(cs, new_callstack_entry.ergs_remaining);

    new_callstack_entry.ergs_remaining = new_ergs_left;
    // NOTE: if we return from local frame (from near-call), then memory growth will not be triggered above,
    // and so panic can not happen, and we can just propagate already existing heap bound
    // to update a previous frame. If we return from the far-call then previous frame is not local, and we should
    // not affect it's upper bound at all
    new_callstack_entry.heap_upper_bound = Selectable::conditionally_select(
        cs,
        is_local_frame,
        &current_callstack_entry.heap_upper_bound,
        &new_callstack_entry.heap_upper_bound,
    );
    new_callstack_entry.aux_heap_upper_bound = Selectable::conditionally_select(
        cs,
        is_local_frame,
        &current_callstack_entry.aux_heap_upper_bound,
        &new_callstack_entry.aux_heap_upper_bound,
    );

    // resolve merging of the queues

    // most likely it's the most interesting amount all the tricks that are pulled by this VM

    // During the execution we maintain the following queue segments of what is usually called a "storage log", that is basically a sequence of bookkeeped
    // storage, events, precompiles, etc accesses
    // - global "forward" queue - all the changes (both rollbackable and not (read-like)) go in there, and it's "global" per block
    // - frame-specific "reverts" queue, where we put "canceling" state updates for all "write-like" things, like storage write, event,
    // l1 message, etc. E.g. precompilecall is pure function and doesn't rollback, and we add nothing to this segment
    // When frame ends we have to decide whether we discard it's changes or not. So we can do either:
    // - if frame does NOT revert then we PREPEND all the changes in "rollback" segment to the rollback segment of the parent queue
    // - if frame DOES revert, then we APPEND all the changes from "rollback" to the global "forward" segment
    // It's easy to notice that this behavior is:
    // - local O(1): only things like heads/tails of the queues are updated. Changes do accumulate along the O(N) potential changes in a frame, but
    // then we can apply it O(1)
    // - recursively consistent as one would expect it: if this frame does NOT revert, but parent REVERTS, then all the changes are rolled back!

    // Why one can not do simpler and just memorize the state of some "forward" queue on frame entry and return to it when revert happens? Because we can have
    // a code like
    // if (SLOAD(x)) {
    //     revert(0, 0)
    // } else {
    //     .. something useful
    // }

    // then we branch on result of SLOAD, but it is not observable (we discarded everything in "forward" queue)! So it can be maliciously manipulated!

    // if we revert then we should append rollback to forward
    // if we return ok then we should prepend to the rollback of the parent

    let should_perform_revert =
        Boolean::multi_or(cs, &[is_ret_revert, is_ret_panic, non_local_frame_panic]);
    let perform_revert = Boolean::multi_and(cs, &[execute, should_perform_revert]);

    for (a, b) in current_callstack_entry.reverted_queue_head.iter().zip(
        draft_vm_state
            .callstack
            .current_context
            .log_queue_forward_tail
            .iter(),
    ) {
        Num::conditionally_enforce_equal(cs, perform_revert, a, b);
    }

    let new_forward_queue_len_if_revert = draft_vm_state
        .callstack
        .current_context
        .log_queue_forward_part_length
        .add_no_overflow(cs, current_callstack_entry.reverted_queue_segment_len);

    let no_exceptions = non_local_frame_panic.negated(cs);

    let should_perform_ret_ok = Boolean::multi_and(cs, &[execute, is_ret_ok, no_exceptions]);

    for (a, b) in new_callstack_entry
        .reverted_queue_head
        .iter()
        .zip(current_callstack_entry.reverted_queue_tail.iter())
    {
        Num::conditionally_enforce_equal(cs, should_perform_ret_ok, a, b);
    }

    let new_rollback_queue_len_if_ok = new_callstack_entry
        .reverted_queue_segment_len
        .add_no_overflow(cs, current_callstack_entry.reverted_queue_segment_len);

    // update forward queue

    let new_forward_queue_tail = Num::parallel_select(
        cs,
        should_perform_revert, // it's only true if we DO execute and DO revert
        &current_callstack_entry.reverted_queue_tail,
        &draft_vm_state
            .callstack
            .current_context
            .log_queue_forward_tail,
    );

    let new_forward_queue_len = UInt32::conditionally_select(
        cs,
        should_perform_revert,
        &new_forward_queue_len_if_revert,
        &draft_vm_state
            .callstack
            .current_context
            .log_queue_forward_part_length,
    );

    // update rollback queue of the parent
    let new_rollback_queue_head = Num::parallel_select(
        cs,
        should_perform_ret_ok, // it's only true if we DO execute and DO return ok
        &current_callstack_entry.reverted_queue_head,
        &new_callstack_entry.reverted_queue_head,
    );

    let new_rollback_queue_len = UInt32::conditionally_select(
        cs,
        should_perform_ret_ok,
        &new_rollback_queue_len_if_ok,
        &new_callstack_entry.reverted_queue_segment_len,
    );

    new_callstack_entry.reverted_queue_head = new_rollback_queue_head;
    new_callstack_entry.reverted_queue_segment_len = new_rollback_queue_len;

    // we ignore label if we return from the root, of course
    let should_use_label = Boolean::multi_and(cs, &[is_to_label, is_local_frame]);

    // Candidates for PC to return to
    let ok_ret_pc =
        UInt16::conditionally_select(cs, should_use_label, &label_pc, &new_callstack_entry.pc);
    // but EH is stored in the CURRENT context
    let eh_pc = UInt16::conditionally_select(
        cs,
        should_use_label,
        &label_pc,
        &current_callstack_entry.exception_handler_loc,
    );

    let dst_pc = UInt16::conditionally_select(cs, perform_revert, &eh_pc, &ok_ret_pc);

    new_callstack_entry.pc = dst_pc;

    // and update registers following our ABI rules

    // everything goes into r1, and the rest is cleared
    let new_r1 = final_fat_ptr.into_register(cs);
    let update_specific_registers_on_ret = Boolean::multi_and(cs, &[execute, is_far_return]);

    let mut specific_registers_updates = [None; REGISTERS_COUNT];
    specific_registers_updates[0] = Some((update_specific_registers_on_ret, new_r1));

    let is_panic = Boolean::multi_or(cs, &[is_ret_panic, non_local_frame_panic]);

    // the rest is cleared on far return

    let mut register_zero_out = [None; REGISTERS_COUNT];

    for reg_idx in 1..REGISTERS_COUNT {
        register_zero_out[reg_idx as usize] = Some(update_specific_registers_on_ret);
    }

    // erase markers everywhere anyway
    let mut erase_ptr_markers = [None; REGISTERS_COUNT];

    for reg_idx in 1..REGISTERS_COUNT {
        erase_ptr_markers[reg_idx as usize] = Some(update_specific_registers_on_ret);
    }

    if crate::config::CIRCUIT_VERSOBE {
        if execute.witness_hook(cs)().unwrap() {
            dbg!(update_specific_registers_on_ret.witness_hook(cs)().unwrap());
            dbg!(current_callstack_entry.total_pubdata_spent.witness_hook(cs)().unwrap());
            dbg!(originally_popped_context
                .total_pubdata_spent
                .witness_hook(cs)()
            .unwrap());
            dbg!(draft_vm_state.pubdata_revert_counter.witness_hook(cs)().unwrap());
        }
    }

    // update pubdata counter in parent frame. If we panic - we do not add, otherwise add
    let new_callstack_pubdata_if_ok = i32_add_no_overflow(
        cs,
        &originally_popped_context.total_pubdata_spent,
        &current_callstack_entry.total_pubdata_spent,
    );
    let new_callstack_pubdata_if_revert = originally_popped_context.total_pubdata_spent;
    new_callstack_entry.total_pubdata_spent = UInt32::conditionally_select(
        cs,
        perform_revert,
        &new_callstack_pubdata_if_revert,
        &new_callstack_pubdata_if_ok,
    );

    // update global counter. If we revert - we subtract (no underflow)
    let pubdata_revert_counter_if_ok = draft_vm_state.pubdata_revert_counter;
    let pubdata_revert_counter_if_revert = i32_sub_no_underflow(
        cs,
        &draft_vm_state.pubdata_revert_counter,
        &current_callstack_entry.total_pubdata_spent,
    );
    let new_pubdata_revert_counter = UInt32::conditionally_select(
        cs,
        perform_revert,
        &pubdata_revert_counter_if_revert,
        &pubdata_revert_counter_if_ok,
    );

    if crate::config::CIRCUIT_VERSOBE {
        if execute.witness_hook(cs)().unwrap() {
            dbg!(new_callstack_entry.total_pubdata_spent.witness_hook(cs)().unwrap());
            dbg!(new_pubdata_revert_counter.witness_hook(cs)().unwrap());
        }
    }

    let full_data = RetData {
        apply_ret: execute,
        is_panic: is_panic,
        did_return_from_far_call: is_far_return,
        new_context: new_callstack_entry,
        originally_popped_context,
        previous_callstack_state,
        new_forward_queue_tail,
        new_forward_queue_len,
        specific_registers_updates,
        specific_registers_zeroing: register_zero_out,
        remove_ptr_on_specific_registers: erase_ptr_markers,
        new_pubdata_revert_counter: new_pubdata_revert_counter,
    };

    full_data
}
