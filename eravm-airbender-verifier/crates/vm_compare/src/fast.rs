use std::cmp::min;

use zk_evm_1_5_2::zkevm_opcode_defs::{
    BOOTLOADER_CODE_PAGE, NEW_MEMORY_PAGES_PER_FAR_CALL, STARTING_BASE_PAGE,
};
use zksync_multivm::vm_fast::interface::{
    CallframeInterface, CallingMode, Opcode, OpcodeType, ReturnType, ShouldStop, StateInterface,
    Tracer,
};
use zksync_types::U256;
use zksync_vm2::FatPointer;

use crate::types::{
    CompareOptions, FrameSnapshot, MemorySummary, ObservedOpcode, ObservedStep, PointerSnapshot,
    TransactionTrace,
};

const REGISTER_COUNT: u8 = 16;

#[derive(Debug, Clone)]
pub(crate) struct FastTraceTracer {
    options: CompareOptions,
    total_steps: u64,
    observations: Vec<ObservedStep>,
}

impl Default for FastTraceTracer {
    fn default() -> Self {
        Self::new(CompareOptions::default())
    }
}

impl FastTraceTracer {
    pub(crate) fn new(options: CompareOptions) -> Self {
        Self {
            options,
            total_steps: 0,
            observations: Vec::new(),
        }
    }

    pub(crate) fn into_trace(
        self,
        execution_result: zksync_vm_interface::ExecutionResult,
    ) -> TransactionTrace {
        TransactionTrace {
            total_steps: self.total_steps,
            observations: self.observations,
            execution_result,
        }
    }

    fn capture_step<S: StateInterface>(&mut self, state: &mut S, opcode: ObservedOpcode) {
        self.observations.push(ObservedStep {
            step: self.total_steps,
            opcode,
            call_depth: state.number_of_callframes(),
            frame: capture_frame(state),
            pointers: capture_pointers(state, self.options),
        });
    }
}

impl Tracer for FastTraceTracer {
    fn after_instruction<OP: OpcodeType, S: StateInterface>(
        &mut self,
        state: &mut S,
    ) -> ShouldStop {
        self.total_steps += 1;

        if let Some(opcode) = normalize_fast_opcode(OP::VALUE) {
            self.capture_step(state, opcode);
        }

        ShouldStop::Continue
    }
}

fn normalize_fast_opcode(opcode: Opcode) -> Option<ObservedOpcode> {
    Some(match opcode {
        Opcode::FarCall(CallingMode::Normal) => ObservedOpcode::FarCallNormal,
        Opcode::FarCall(CallingMode::Delegate) => ObservedOpcode::FarCallDelegate,
        Opcode::FarCall(CallingMode::Mimic) => ObservedOpcode::FarCallMimic,
        Opcode::Ret(ReturnType::Normal) => ObservedOpcode::RetOk,
        Opcode::Ret(ReturnType::Revert) => ObservedOpcode::RetRevert,
        Opcode::Ret(ReturnType::Panic) => ObservedOpcode::RetPanic,
        Opcode::Decommit => ObservedOpcode::Decommit,
        Opcode::PrecompileCall => ObservedOpcode::PrecompileCall,
        Opcode::PointerAdd => ObservedOpcode::PointerAdd,
        Opcode::PointerSub => ObservedOpcode::PointerSub,
        Opcode::PointerPack => ObservedOpcode::PointerPack,
        Opcode::PointerShrink => ObservedOpcode::PointerShrink,
        Opcode::HeapRead => ObservedOpcode::HeapRead,
        Opcode::HeapWrite => ObservedOpcode::HeapWrite,
        Opcode::AuxHeapRead => ObservedOpcode::AuxHeapRead,
        Opcode::AuxHeapWrite => ObservedOpcode::AuxHeapWrite,
        Opcode::PointerRead => ObservedOpcode::PointerRead,
        Opcode::StaticMemoryRead => ObservedOpcode::StaticMemoryRead,
        Opcode::StaticMemoryWrite => ObservedOpcode::StaticMemoryWrite,
        _ => return None,
    })
}

fn capture_frame<S: StateInterface>(state: &mut S) -> FrameSnapshot {
    let frame = state.current_frame();
    FrameSnapshot {
        address: frame.address(),
        caller: frame.caller(),
        code_address: frame.code_address(),
        program_counter: frame.program_counter(),
        gas: frame.gas(),
        heap: frame.heap().as_u32(),
        heap_bound: frame.heap_bound(),
        aux_heap: frame.aux_heap().as_u32(),
        aux_heap_bound: frame.aux_heap_bound(),
        is_static: frame.is_static(),
    }
}

fn capture_pointers<S: StateInterface>(state: &S, options: CompareOptions) -> Vec<PointerSnapshot> {
    let mut pointers = Vec::new();
    for register in 0..REGISTER_COUNT {
        let (raw, is_pointer) = state.read_register(register);
        if !is_pointer {
            continue;
        }

        let pointer = FatPointer::from(raw);
        let (readable, memory) = summarize_pointer(&pointer, options, |page, start, len| {
            let mut bytes = Vec::with_capacity(len);
            for offset in 0..len {
                bytes.push(state.read_heap_byte(page, start + offset as u32));
            }
            bytes
        });

        let memory_page = legacy_page(pointer.memory_page.as_u32());
        pointers.push(PointerSnapshot {
            register,
            raw: with_page(raw, memory_page),
            memory_page,
            start: pointer.start,
            offset: pointer.offset,
            length: pointer.length,
            readable,
            memory,
        });
    }
    pointers
}

/// Maps a vm2 page to `zk_evm`'s page for the same memory.
///
/// `Vm::custom` seeds the bootloader into vm2's first dynamic page group, while `zk_evm` keeps it
/// on `BOOTLOADER_CODE_PAGE`, so later vm2 pages are one group higher. The group's other pages have
/// no `zk_evm` counterpart and panic.
fn legacy_page(page: u32) -> u32 {
    if page < STARTING_BASE_PAGE {
        page
    } else if page == STARTING_BASE_PAGE {
        BOOTLOADER_CODE_PAGE
    } else {
        assert!(
            page >= STARTING_BASE_PAGE + NEW_MEMORY_PAGES_PER_FAR_CALL,
            "vm2 page {page} is in the bootloader seed's group, which zk_evm doesn't allocate"
        );
        page - NEW_MEMORY_PAGES_PER_FAR_CALL
    }
}

/// Replaces the page field (bits 32..64) of a fat pointer word, keeping every other bit.
fn with_page(raw: U256, page: u32) -> U256 {
    let mask = U256::from(u32::MAX) << 32;
    (raw & !mask) | (U256::from(page) << 32)
}

fn summarize_pointer<R>(
    pointer: &FatPointer,
    options: CompareOptions,
    mut read_bytes: R,
) -> (bool, MemorySummary)
where
    R: FnMut(zksync_multivm::vm_fast::interface::HeapId, u32, usize) -> Vec<u8>,
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

#[cfg(test)]
mod tests {
    use zk_evm_1_5_2::zkevm_opcode_defs::{
        BOOTLOADER_AUX_HEAP_PAGE, BOOTLOADER_CALLDATA_PAGE, BOOTLOADER_HEAP_PAGE,
        STATIC_MEMORY_PAGE,
    };

    use super::*;

    /// A fat pointer word with offset 1, start 2, length 3 and nonzero high 128 bits.
    fn pointer_word(page: u32) -> U256 {
        (U256::from(0xdead_beef_u64) << 128)
            | (U256::from(3) << 96)
            | (U256::from(2) << 64)
            | (U256::from(page) << 32)
            | U256::from(1)
    }

    #[test]
    fn fixed_pages_are_unchanged() {
        for page in [
            STATIC_MEMORY_PAGE,
            BOOTLOADER_CALLDATA_PAGE,
            BOOTLOADER_HEAP_PAGE,
            BOOTLOADER_AUX_HEAP_PAGE,
        ] {
            assert_eq!(legacy_page(page), page);
        }
    }

    #[test]
    fn seeded_bootloader_page_maps_to_its_code_page() {
        assert_eq!(legacy_page(STARTING_BASE_PAGE), BOOTLOADER_CODE_PAGE);
    }

    #[test]
    #[should_panic(expected = "bootloader seed's group")]
    fn rest_of_the_seed_group_is_rejected() {
        // Would otherwise alias `BOOTLOADER_HEAP_PAGE`.
        legacy_page(STARTING_BASE_PAGE + 2);
    }

    #[test]
    fn far_call_pages_map_down_one_group() {
        // The first far call's heap: 2058 in vm2, 2050 in zk_evm.
        let raw = pointer_word(2058);
        let mapped = with_page(raw, legacy_page(2058));
        assert_eq!(mapped, pointer_word(2050));
        assert_eq!(
            raw - mapped,
            U256::from(NEW_MEMORY_PAGES_PER_FAR_CALL) << 32
        );
    }
}
