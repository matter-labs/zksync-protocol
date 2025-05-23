use crate::witness::tracer::callstack_handler::CallstackWithAuxData;
use crate::witness::tracer::vm_snapshot::VmSnapshot;
use crate::zk_evm::abstractions::PrecompileCyclesWitness;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::aux_structures::*;
use crate::zk_evm::ethereum_types::U256;
use crate::zk_evm::vm_state::CallStackEntry;

use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;

use crate::zk_evm::abstractions::StorageAccessRefund;
use crate::zk_evm::zkevm_opcode_defs::decoding::EncodingModeProduction;
use crate::zk_evm::zkevm_opcode_defs::system_params::STORAGE_AUX_BYTE;
use crate::zk_evm::zkevm_opcode_defs::system_params::VM_INITIAL_FRAME_ERGS;
use crate::zk_evm::zkevm_opcode_defs::system_params::VM_MAX_STACK_DEPTH;
use circuit_definitions::zk_evm::zkevm_opcode_defs::system_params::TRANSIENT_STORAGE_AUX_BYTE;
use tracing;

// cycle indicators below are not timestamps!

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryMarker {
    ForwardNoRollback {
        unique_query_id: u64,
        in_frame: usize,
        index: usize,
        cycle: u32,
    },
    Forward {
        unique_query_id: u64,
        in_frame: usize,
        index: usize,
        cycle: u32,
    },
    Rollback {
        unique_query_id: u64,
        in_frame: usize,
        index: usize,
        cycle_of_declaration: u32,
        cycle_of_applied_rollback: Option<u32>,
    },
}

impl QueryMarker {
    pub fn frame_index(&self) -> usize {
        match self {
            QueryMarker::ForwardNoRollback { in_frame, .. } => *in_frame,
            QueryMarker::Forward { in_frame, .. } => *in_frame,
            QueryMarker::Rollback { in_frame, .. } => *in_frame,
        }
    }

    pub fn query_id(&self) -> u64 {
        match self {
            QueryMarker::ForwardNoRollback {
                unique_query_id, ..
            } => *unique_query_id,
            QueryMarker::Forward {
                unique_query_id, ..
            } => *unique_query_id,
            QueryMarker::Rollback {
                unique_query_id, ..
            } => *unique_query_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WitnessTracer {
    pub cycles_to_use_per_snapshot: u32,
    pub current_cycle_counter: u32,
    pub cycle_counter_of_last_snapshot: u32,
    pub memory_queries: Vec<(u32, MemoryQuery)>, // flattened memory queries, with cycle indicators
    pub storage_queries: PerCircuitAccumulatorSparse<(u32, LogQuery)>, // storage read queries with cycle indicators
    pub cold_warm_refunds_logs: PerCircuitAccumulatorSparse<(u32, LogQuery, u32)>,
    pub pubdata_cost_logs: PerCircuitAccumulatorSparse<(u32, LogQuery, PubdataCost)>,
    pub prepared_decommittment_queries: Vec<(u32, DecommittmentQuery)>,
    pub executed_decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,
    pub secp256r1_verify_witnesses: Vec<(u32, LogQuery, Secp256r1VerifyRoundWitness)>,
    pub modexp_witnesses: Vec<(u32, LogQuery, ModexpRoundWitness)>,
    pub ecadd_witnesses: Vec<(u32, LogQuery, ECAddRoundWitness)>,
    pub ecmul_witnesses: Vec<(u32, LogQuery, ECMulRoundWitness)>,
    pub ecpairing_witnesses: Vec<(u32, LogQuery, Vec<ECPairingRoundWitness>)>,
    pub monotonic_query_counter: usize,
    // pub log_frames_stack: Vec<ApplicationData<((usize, usize), (QueryMarker, u32, LogQuery))>>, // keep the unique frame index
    pub callstack_with_aux_data: CallstackWithAuxData,
    pub vm_snapshots: Vec<VmSnapshot>,
    // we need to properly preserve the information about logs. Not just flattening them into something,
    // but also keep the markers on when new frame has started and has finished, and the final frame execution
    // result, so we can properly substitute hash chain results in there for non-determinism
}

#[derive(Clone, Debug)]
pub struct NumberedApplicationData<T> {
    pub index: usize,
    pub forward: Vec<T>,
    pub rollbacks: Vec<T>,
}

impl<T> NumberedApplicationData<T> {
    pub fn new() -> Self {
        Self {
            index: 0,
            forward: vec![],
            rollbacks: vec![],
        }
    }
}

use circuit_definitions::zk_evm::zk_evm_abstractions::precompiles::ecadd::ECAddRoundWitness;
use circuit_definitions::zk_evm::zk_evm_abstractions::precompiles::ecmul::ECMulRoundWitness;
use circuit_definitions::zk_evm::zk_evm_abstractions::precompiles::ecpairing::ECPairingRoundWitness;
use circuit_definitions::zk_evm::zk_evm_abstractions::precompiles::modexp::ModexpRoundWitness;
use std::ops::Range;

#[derive(Clone, Debug)]
pub struct LogQueueFramesProcessor {
    pub frame_indexes: Vec<usize>,
    pub frames: NumberedApplicationData<(QueryMarker, LogQuery)>,
    pub ranges: NumberedApplicationData<Range<usize>>,
}

impl LogQueueFramesProcessor {
    pub fn empty() -> Self {
        Self {
            frame_indexes: vec![],
            frames: NumberedApplicationData::new(),
            ranges: NumberedApplicationData::new(),
        }
    }
}

impl WitnessTracer {
    pub fn new(cycles_per_snapshot: u32) -> Self {
        Self {
            cycles_to_use_per_snapshot: cycles_per_snapshot,
            current_cycle_counter: 0,
            cycle_counter_of_last_snapshot: 0,
            memory_queries: vec![],
            storage_queries: PerCircuitAccumulatorSparse::new(cycles_per_snapshot as usize),
            cold_warm_refunds_logs: PerCircuitAccumulatorSparse::new(cycles_per_snapshot as usize),
            pubdata_cost_logs: PerCircuitAccumulatorSparse::new(cycles_per_snapshot as usize),
            prepared_decommittment_queries: vec![],
            executed_decommittment_queries: vec![],
            keccak_round_function_witnesses: vec![],
            sha256_round_function_witnesses: vec![],
            ecrecover_witnesses: vec![],
            secp256r1_verify_witnesses: vec![],
            modexp_witnesses: vec![],
            ecadd_witnesses: vec![],
            ecmul_witnesses: vec![],
            ecpairing_witnesses: vec![],
            monotonic_query_counter: 0,
            // log_frames_stack: vec![ApplicationData::empty()],
            callstack_with_aux_data: CallstackWithAuxData::empty(),
            vm_snapshots: vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuxCallstackProto {
    // monotonic counter to enumerate frames
    pub monotonic_frame_counter: usize,
    // current frame and it's parent
    pub current: ((usize, usize), CallStackEntry), // we save PARENT index and stack entry itself
    // stack of frames, along with their parents
    pub stack: Vec<((usize, usize), CallStackEntry)>,
    // history of "actions" - VM cycle, and action direction
    pub history: Vec<(u32, (bool, usize, CallStackEntry))>,
}

impl AuxCallstackProto {
    pub fn new_with_max_ergs() -> Self {
        let mut initial_callstack = CallStackEntry::empty_context();
        initial_callstack.ergs_remaining = VM_INITIAL_FRAME_ERGS;

        Self {
            monotonic_frame_counter: 2,
            current: ((0, 1), initial_callstack),
            stack: vec![],
            history: vec![],
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    #[track_caller]
    pub fn push_entry(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_entry: CallStackEntry,
        new_entry: CallStackEntry,
    ) {
        let new_counter = self.monotonic_frame_counter;
        let current_counter = self.current.0 .1;
        self.monotonic_frame_counter += 1;
        let mut old = std::mem::replace(
            &mut self.current,
            ((current_counter, new_counter), new_entry),
        );
        assert_eq!(old.1.code_page, previous_entry.code_page);
        old.1 = previous_entry;
        self.stack.push(old);

        self.history.push((
            monotonic_cycle_counter,
            (true, current_counter, previous_entry),
        ));
        debug_assert!(self.depth() <= VM_MAX_STACK_DEPTH as usize);
    }

    #[track_caller]
    pub fn pop_entry(&mut self, monotonic_cycle_counter: u32) -> ((usize, usize), CallStackEntry) {
        let previous = self.stack.pop().unwrap();
        let old = std::mem::replace(&mut self.current, previous);

        self.history
            .push((monotonic_cycle_counter, (false, old.0 .1, old.1)));

        old
    }
}

use crate::zk_evm::vm_state::VmLocalState;
use crate::zk_evm::witness_trace::VmWitnessTracer;

use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulatorSparse;

impl VmWitnessTracer<8, EncodingModeProduction> for WitnessTracer {
    fn start_new_execution_cycle(&mut self, current_state: &VmLocalState) {
        // println!("Cycle starts");
        if self.current_cycle_counter == 0 {
            if self.current_cycle_counter != current_state.monotonic_cycle_counter {
                // adjust
                self.current_cycle_counter = current_state.monotonic_cycle_counter;
            }
            // make the initial one
            let snapshot = VmSnapshot {
                local_state: current_state.clone(),
                at_cycle: self.current_cycle_counter,
            };
            self.vm_snapshots.push(snapshot);
            tracing::debug!(
                "Made INITIAL snapshot at cycle {:?}",
                self.current_cycle_counter
            );
            self.cycle_counter_of_last_snapshot = current_state.monotonic_cycle_counter;
        }

        assert_eq!(
            self.current_cycle_counter,
            current_state.monotonic_cycle_counter
        );

        if self.current_cycle_counter
            >= self.cycle_counter_of_last_snapshot + self.cycles_to_use_per_snapshot
        {
            // do it immediatelly
            let snapshot = VmSnapshot {
                local_state: current_state.clone(),
                at_cycle: self.current_cycle_counter,
            };
            self.vm_snapshots.push(snapshot);
            tracing::debug!("Made snapshot at cycle {:?}", self.current_cycle_counter);
            // we made a snapshot now, but the cycle itself will be the first one for the next snapshot
            self.cycle_counter_of_last_snapshot = current_state.monotonic_cycle_counter;
        }

        // monotonic counter always increases
        self.current_cycle_counter += 1;
    }

    fn end_execution_cycle(&mut self, _current_state: &VmLocalState) {
        // println!("Cycle ends");
    }

    fn add_memory_query(&mut self, monotonic_cycle_counter: u32, memory_query: MemoryQuery) {
        self.memory_queries
            .push((monotonic_cycle_counter, memory_query));
    }

    fn record_refund_for_query(
        &mut self,
        monotonic_cycle_counter: u32,
        log_query: LogQuery,
        refund: StorageAccessRefund,
    ) {
        assert!(log_query.aux_byte == STORAGE_AUX_BYTE);
        self.cold_warm_refunds_logs
            .push((monotonic_cycle_counter, log_query, refund.refund()));
    }

    fn record_pubdata_cost_for_query(
        &mut self,
        monotonic_cycle_counter: u32,
        log_query: LogQuery,
        pubdata_cost: PubdataCost,
    ) {
        assert!(log_query.aux_byte == STORAGE_AUX_BYTE);
        self.pubdata_cost_logs
            .push((monotonic_cycle_counter, log_query, pubdata_cost));
    }

    fn add_log_query(&mut self, monotonic_cycle_counter: u32, log_query: LogQuery) {
        // log both reads and writes
        if log_query.aux_byte == STORAGE_AUX_BYTE
            || log_query.aux_byte == TRANSIENT_STORAGE_AUX_BYTE
        {
            self.storage_queries
                .push((monotonic_cycle_counter, log_query));
        }

        self.callstack_with_aux_data
            .add_log_query(monotonic_cycle_counter, log_query);
    }

    fn prepare_for_decommittment(
        &mut self,
        monotonic_cycle_counter: u32,
        decommittment_query: DecommittmentQuery,
    ) {
        self.prepared_decommittment_queries
            .push((monotonic_cycle_counter, decommittment_query));
    }

    fn execute_decommittment(
        &mut self,
        monotonic_cycle_counter: u32,
        decommittment_query: DecommittmentQuery,
        mem_witness: Vec<U256>,
    ) {
        self.executed_decommittment_queries.push((
            monotonic_cycle_counter,
            decommittment_query,
            mem_witness,
        ));
    }

    fn add_precompile_call_result(
        &mut self,
        monotonic_cycle_counter: u32,
        call_params: LogQuery,
        _mem_witness_in: Vec<MemoryQuery>,
        _memory_witness_out: Vec<MemoryQuery>,
        round_witness: PrecompileCyclesWitness,
    ) {
        // we bootkeep it to later on use in memory argument by opening and flattening, and in precompile circuits
        match round_witness {
            PrecompileCyclesWitness::Keccak256(wit) => {
                self.keccak_round_function_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit,
                ));
            }
            PrecompileCyclesWitness::Sha256(wit) => {
                self.sha256_round_function_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit,
                ));
            }
            PrecompileCyclesWitness::ECRecover(mut wit) => {
                assert_eq!(wit.len(), 1);
                self.ecrecover_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit.drain(..).next().unwrap(),
                ));
            }
            PrecompileCyclesWitness::Secp256r1Verify(mut wit) => {
                assert_eq!(wit.len(), 1);
                self.secp256r1_verify_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit.drain(..).next().unwrap(),
                ));
            }
            PrecompileCyclesWitness::Modexp(mut wit) => {
                assert_eq!(wit.len(), 1);
                self.modexp_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit.drain(..).next().unwrap(),
                ));
            }
            PrecompileCyclesWitness::ECAdd(mut wit) => {
                assert_eq!(wit.len(), 1);
                self.ecadd_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit.drain(..).next().unwrap(),
                ));
            }
            PrecompileCyclesWitness::ECMul(mut wit) => {
                assert_eq!(wit.len(), 1);
                self.ecmul_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit.drain(..).next().unwrap(),
                ));
            }
            PrecompileCyclesWitness::ECPairing(wit) => {
                self.ecpairing_witnesses
                    .push((monotonic_cycle_counter, call_params, wit));
            }
        }
    }

    fn add_revertable_precompile_call(
        &mut self,
        _monotonic_cycle_counter: u32,
        _call_params: LogQuery,
    ) {
        unreachable!()
    }

    fn start_new_execution_context(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_context: &CallStackEntry,
        new_context: &CallStackEntry,
    ) {
        self.callstack_with_aux_data.push_entry(
            monotonic_cycle_counter,
            *previous_context,
            *new_context,
        );
    }

    fn finish_execution_context(&mut self, monotonic_cycle_counter: u32, panicked: bool) {
        // log part

        self.callstack_with_aux_data
            .pop_entry(monotonic_cycle_counter, panicked);

        // // if we panic then we append forward and rollbacks to the forward of parent,
        // // otherwise we place rollbacks of child before rollbacks of the parent
        // let current_frame = self
        //     .log_frames_stack
        //     .pop()
        //     .expect("frame must be started before finishing");
        // let ApplicationData { forward, rollbacks } = current_frame;
        // let parent_data = self.log_frames_stack.last_mut().unwrap();
        // if panicked {
        //     parent_data.forward.extend(forward);
        //     // add to forward part, but in reverse order
        //     parent_data.forward.extend(rollbacks.into_iter().rev());
        // } else {
        //     parent_data.forward.extend(forward);
        //     // prepend to the parent's rollback queue
        //     parent_data.rollbacks.extend(rollbacks);
        // }
    }
}
