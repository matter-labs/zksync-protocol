use std::{
    cmp::min,
    sync::{Arc, Mutex},
};

use zk_evm_1_5_2::{
    tracing::{AfterExecutionData, VmLocalStateData},
    zkevm_opcode_defs::{
        FarCallOpcode, FatPointer, LogOpcode, Opcode, PtrOpcode, RetOpcode, UMAOpcode,
    },
};
use zksync_multivm::{
    interface::storage::WriteStorage,
    vm_latest::{HistoryMode, SimpleMemory, VmTracer},
    IntoOldVmTracer,
};

use crate::types::{
    CompareOptions, FrameSnapshot, MemorySummary, ObservedOpcode, ObservedStep, PointerSnapshot,
    TransactionTrace,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct TraceRecorder {
    total_steps: u64,
    observations: Vec<ObservedStep>,
}

#[derive(Debug, Clone)]
pub(crate) struct LegacyTraceTracer {
    options: CompareOptions,
    recorder: Arc<Mutex<TraceRecorder>>,
}

impl LegacyTraceTracer {
    pub(crate) fn new(options: CompareOptions) -> (Self, Arc<Mutex<TraceRecorder>>) {
        let recorder = Arc::new(Mutex::new(TraceRecorder::default()));
        (
            Self {
                options,
                recorder: recorder.clone(),
            },
            recorder,
        )
    }
}

impl IntoOldVmTracer for LegacyTraceTracer {}

impl<S, H: HistoryMode> zksync_multivm::tracers::dynamic::vm_1_5_2::DynTracer<S, SimpleMemory<H>>
    for LegacyTraceTracer
{
    fn after_execution(
        &mut self,
        state: VmLocalStateData<'_>,
        data: AfterExecutionData,
        memory: &SimpleMemory<H>,
        _storage: zksync_vm_interface::storage::StoragePtr<S>,
    ) {
        let mut recorder = self
            .recorder
            .lock()
            .expect("legacy trace recorder mutex is poisoned");
        recorder.total_steps += 1;

        if let Some(opcode) = normalize_legacy_opcode(data.opcode.variant.opcode) {
            let step = recorder.total_steps;
            recorder.observations.push(ObservedStep {
                step,
                opcode,
                // `zk_evm` keeps the current frame separately and also stores an unused bottom
                // frame in `inner`, so the live depth is exactly `inner.len()`.
                call_depth: state.vm_local_state.callstack.inner.len(),
                frame: capture_frame(&state),
                pointers: capture_pointers(&state, memory, self.options),
            });
        }
    }
}

impl<S: WriteStorage, H: HistoryMode> VmTracer<S, H> for LegacyTraceTracer {}

pub(crate) fn into_trace(
    recorder: Arc<Mutex<TraceRecorder>>,
    execution_result: zksync_vm_interface::ExecutionResult,
) -> TransactionTrace {
    let recorder = recorder
        .lock()
        .expect("legacy trace recorder mutex is poisoned")
        .clone();
    TransactionTrace {
        total_steps: recorder.total_steps,
        observations: recorder.observations,
        execution_result,
    }
}

fn normalize_legacy_opcode(opcode: Opcode) -> Option<ObservedOpcode> {
    Some(match opcode {
        Opcode::FarCall(FarCallOpcode::Normal) => ObservedOpcode::FarCallNormal,
        Opcode::FarCall(FarCallOpcode::Delegate) => ObservedOpcode::FarCallDelegate,
        Opcode::FarCall(FarCallOpcode::Mimic) => ObservedOpcode::FarCallMimic,
        Opcode::Ret(RetOpcode::Ok) => ObservedOpcode::RetOk,
        Opcode::Ret(RetOpcode::Revert) => ObservedOpcode::RetRevert,
        Opcode::Ret(RetOpcode::Panic) => ObservedOpcode::RetPanic,
        Opcode::Log(LogOpcode::Decommit) => ObservedOpcode::Decommit,
        Opcode::Log(LogOpcode::PrecompileCall) => ObservedOpcode::PrecompileCall,
        Opcode::Ptr(PtrOpcode::Add) => ObservedOpcode::PointerAdd,
        Opcode::Ptr(PtrOpcode::Sub) => ObservedOpcode::PointerSub,
        Opcode::Ptr(PtrOpcode::Pack) => ObservedOpcode::PointerPack,
        Opcode::Ptr(PtrOpcode::Shrink) => ObservedOpcode::PointerShrink,
        Opcode::UMA(UMAOpcode::HeapRead) => ObservedOpcode::HeapRead,
        Opcode::UMA(UMAOpcode::HeapWrite) => ObservedOpcode::HeapWrite,
        Opcode::UMA(UMAOpcode::AuxHeapRead) => ObservedOpcode::AuxHeapRead,
        Opcode::UMA(UMAOpcode::AuxHeapWrite) => ObservedOpcode::AuxHeapWrite,
        Opcode::UMA(UMAOpcode::FatPointerRead) => ObservedOpcode::PointerRead,
        Opcode::UMA(UMAOpcode::StaticMemoryRead) => ObservedOpcode::StaticMemoryRead,
        Opcode::UMA(UMAOpcode::StaticMemoryWrite) => ObservedOpcode::StaticMemoryWrite,
        _ => return None,
    })
}

fn capture_frame(state: &VmLocalStateData<'_>) -> FrameSnapshot {
    let current = state.vm_local_state.callstack.current;
    let base_page = current.base_memory_page.0;
    FrameSnapshot {
        address: current.this_address,
        caller: current.msg_sender,
        code_address: current.code_address,
        program_counter: Some(current.pc),
        gas: current.ergs_remaining,
        heap: base_page + 2,
        heap_bound: current.heap_bound,
        aux_heap: base_page + 3,
        aux_heap_bound: current.aux_heap_bound,
        is_static: current.is_static,
    }
}

fn capture_pointers<H: HistoryMode>(
    state: &VmLocalStateData<'_>,
    memory: &SimpleMemory<H>,
    options: CompareOptions,
) -> Vec<PointerSnapshot> {
    let mut pointers = Vec::new();
    for (register, primitive) in state.vm_local_state.registers.iter().enumerate() {
        if !primitive.is_pointer {
            continue;
        }

        let pointer = FatPointer::from_u256(primitive.value);
        let (readable, memory_summary) = summarize_pointer(pointer, options, |page, start, len| {
            memory.read_unaligned_bytes(page as usize, start as usize, len)
        });
        pointers.push(PointerSnapshot {
            // `zk_evm` stores registers `r1..r15`; there is no `r0` entry here.
            register: register as u8 + 1,
            raw: primitive.value,
            memory_page: pointer.memory_page,
            start: pointer.start,
            offset: pointer.offset,
            length: pointer.length,
            readable,
            memory: memory_summary,
        });
    }
    pointers
}

fn summarize_pointer<R>(
    pointer: FatPointer,
    options: CompareOptions,
    mut read_bytes: R,
) -> (bool, MemorySummary)
where
    R: FnMut(u32, u32, usize) -> Vec<u8>,
{
    let Some(total_length) = pointer.length.checked_sub(pointer.offset) else {
        return (
            false,
            MemorySummary {
                total_length: 0,
                head: Vec::new(),
                tail: Vec::new(),
            },
        );
    };
    let Some(start) = pointer.start.checked_add(pointer.offset) else {
        return (
            false,
            MemorySummary {
                total_length,
                head: Vec::new(),
                tail: Vec::new(),
            },
        );
    };

    let max_capture = options.max_capture_bytes;
    let head_len = min(total_length as usize, max_capture);
    let head = read_bytes(pointer.memory_page, start, head_len);
    let tail_len = min(max_capture, total_length as usize - head_len);
    let tail = if tail_len == 0 {
        Vec::new()
    } else {
        let tail_start = start + total_length - tail_len as u32;
        read_bytes(pointer.memory_page, tail_start, tail_len)
    };

    (
        true,
        MemorySummary {
            total_length,
            head,
            tail,
        },
    )
}
