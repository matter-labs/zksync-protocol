use std::fmt;

use zksync_types::{Address, H256, U256};
use zksync_vm_interface::ExecutionResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareOptions {
    pub max_capture_bytes: usize,
    pub fail_fast: bool,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            max_capture_bytes: 64,
            fail_fast: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComparisonReport {
    pub compared_transactions: usize,
    pub compared_l2_blocks: usize,
    pub outcome: ComparisonOutcome,
}

#[derive(Debug, Clone)]
pub enum ComparisonOutcome {
    Match,
    Diverged(Vec<Divergence>),
}

#[derive(Debug, Clone)]
pub struct Divergence {
    pub location: TxLocation,
    pub reason: String,
    pub legacy: Option<ObservedStep>,
    pub fast: Option<ObservedStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLocation {
    pub l2_block_number: u32,
    pub tx_index_in_block: usize,
    pub tx_hash: H256,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransactionTrace {
    pub total_steps: u64,
    pub observations: Vec<ObservedStep>,
    pub execution_result: ExecutionResult,
}

#[derive(Debug, Clone)]
pub struct ObservedStep {
    pub step: u64,
    pub opcode: ObservedOpcode,
    pub call_depth: usize,
    pub frame: FrameSnapshot,
    pub pointers: Vec<PointerSnapshot>,
}

impl PartialEq for ObservedStep {
    fn eq(&self, other: &Self) -> bool {
        self.step == other.step
            && self.opcode == other.opcode
            && self.call_depth == other.call_depth
            && self.frame == other.frame
            && pointers_match(self, other)
    }
}

impl Eq for ObservedStep {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedOpcode {
    FarCallNormal,
    FarCallDelegate,
    FarCallMimic,
    RetOk,
    RetRevert,
    RetPanic,
    Decommit,
    PrecompileCall,
    PointerAdd,
    PointerSub,
    PointerPack,
    PointerShrink,
    HeapRead,
    HeapWrite,
    AuxHeapRead,
    AuxHeapWrite,
    PointerRead,
    StaticMemoryRead,
    StaticMemoryWrite,
}

#[derive(Debug, Clone)]
pub struct FrameSnapshot {
    pub address: Address,
    pub caller: Address,
    pub code_address: Address,
    pub program_counter: Option<u16>,
    pub gas: u32,
    pub heap: u32,
    pub heap_bound: u32,
    pub aux_heap: u32,
    pub aux_heap_bound: u32,
    pub is_static: bool,
}

impl PartialEq for FrameSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
            && self.caller == other.caller
            && self.code_address == other.code_address
            && program_counters_match(self, other)
            && self.gas == other.gas
            // `zk_evm` memory pages and vm2 heap IDs use different internal namespaces.
            // The current frame's heap identity is not directly observable by contracts,
            // unlike fat pointers, so ignore it in semantic step comparison.
            && self.heap_bound == other.heap_bound
            && self.aux_heap_bound == other.aux_heap_bound
            && self.is_static == other.is_static
    }
}

impl Eq for FrameSnapshot {}

fn program_counters_match(this: &FrameSnapshot, other: &FrameSnapshot) -> bool {
    this.program_counter == other.program_counter
        // vm2 intentionally hides the instruction pointer while the current frame is panicking,
        // returning `None` from `program_counter()`. The legacy tracer still exposes the stale
        // post-increment PC in the same state, so treat this as equivalent when both frames have
        // already burned all gas and are otherwise compared as the same post-step panic state.
        || matches!(
            (this.program_counter, other.program_counter),
            (None, Some(_)) | (Some(_), None)
        ) && this.gas == 0
            && other.gas == 0
}

fn pointers_match(this: &ObservedStep, other: &ObservedStep) -> bool {
    this.pointers.len() == other.pointers.len()
        && this
            .pointers
            .iter()
            .zip(&other.pointers)
            .all(|(this_pointer, other_pointer)| {
                pointer_snapshots_match(this_pointer, other_pointer, &this.frame, &other.frame)
            })
}

fn pointer_snapshots_match(
    this: &PointerSnapshot,
    other: &PointerSnapshot,
    this_frame: &FrameSnapshot,
    other_frame: &FrameSnapshot,
) -> bool {
    this == other
        // A panicking frame cannot observe its implicit calldata pointer before the next
        // instruction immediately returns with panic. The legacy VM may preserve a formal empty
        // pointer here while vm2 canonicalizes it to zero, but both represent the same trivial,
        // non-dereferenceable slice.
        || this.register == other.register
            && this.readable == other.readable
            && this.memory == other.memory
            && this.offset == 0
            && other.offset == 0
            && this.length == 0
            && other.length == 0
            && this_frame.gas == 0
            && other_frame.gas == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerSnapshot {
    pub register: u8,
    pub raw: U256,
    pub memory_page: u32,
    pub start: u32,
    pub offset: u32,
    pub length: u32,
    pub readable: bool,
    pub memory: MemorySummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemorySummary {
    pub total_length: u32,
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
}

impl ComparisonReport {
    pub fn is_match(&self) -> bool {
        matches!(self.outcome, ComparisonOutcome::Match)
    }
}

impl fmt::Display for ComparisonReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.outcome {
            ComparisonOutcome::Match => write!(
                formatter,
                "matched after {} transactions across {} L2 blocks",
                self.compared_transactions, self.compared_l2_blocks
            ),
            ComparisonOutcome::Diverged(divergences) => match divergences.first() {
                Some(divergence) => write!(
                    formatter,
                    "diverged {} time(s); first at L2 block {}, tx #{} ({:?}): {}",
                    divergences.len(),
                    divergence.location.l2_block_number,
                    divergence.location.tx_index_in_block,
                    divergence.location.tx_hash,
                    divergence.reason
                ),
                None => formatter.write_str("diverged with no recorded details"),
            },
        }
    }
}

impl fmt::Display for ObservedOpcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FarCallNormal => "far_call.normal",
            Self::FarCallDelegate => "far_call.delegate",
            Self::FarCallMimic => "far_call.mimic",
            Self::RetOk => "ret.ok",
            Self::RetRevert => "ret.revert",
            Self::RetPanic => "ret.panic",
            Self::Decommit => "decommit",
            Self::PrecompileCall => "precompile_call",
            Self::PointerAdd => "pointer.add",
            Self::PointerSub => "pointer.sub",
            Self::PointerPack => "pointer.pack",
            Self::PointerShrink => "pointer.shrink",
            Self::HeapRead => "heap.read",
            Self::HeapWrite => "heap.write",
            Self::AuxHeapRead => "aux_heap.read",
            Self::AuxHeapWrite => "aux_heap.write",
            Self::PointerRead => "pointer.read",
            Self::StaticMemoryRead => "static_memory.read",
            Self::StaticMemoryWrite => "static_memory.write",
        };
        formatter.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameSnapshot, MemorySummary, ObservedOpcode, ObservedStep, PointerSnapshot};
    use zksync_types::{Address, U256};

    fn sample_frame() -> FrameSnapshot {
        FrameSnapshot {
            address: Address::zero(),
            caller: Address::zero(),
            code_address: Address::zero(),
            program_counter: Some(7),
            gas: 123,
            heap: 10,
            heap_bound: 456,
            aux_heap: 11,
            aux_heap_bound: 789,
            is_static: false,
        }
    }

    fn sample_step() -> ObservedStep {
        ObservedStep {
            step: 7,
            opcode: ObservedOpcode::FarCallNormal,
            call_depth: 2,
            frame: sample_frame(),
            pointers: vec![PointerSnapshot {
                register: 1,
                raw: U256::zero(),
                memory_page: 0,
                start: 0,
                offset: 0,
                length: 0,
                readable: true,
                memory: MemorySummary {
                    total_length: 0,
                    head: Vec::new(),
                    tail: Vec::new(),
                },
            }],
        }
    }

    #[test]
    fn frame_equality_ignores_heap_ids() {
        let mut legacy = sample_frame();
        let mut fast = sample_frame();
        fast.heap = 2;
        fast.aux_heap = 3;

        assert_eq!(legacy, fast);

        legacy.heap = 15;
        legacy.aux_heap = 16;
        assert_eq!(legacy, fast);
    }

    #[test]
    fn frame_equality_keeps_semantic_fields_strict() {
        let legacy = sample_frame();
        let mut fast = sample_frame();
        fast.heap_bound += 1;

        assert_ne!(legacy, fast);
    }

    #[test]
    fn frame_equality_tolerates_panic_program_counter_gap() {
        let mut legacy = sample_frame();
        let mut fast = sample_frame();

        legacy.gas = 0;
        fast.gas = 0;
        fast.program_counter = None;

        assert_eq!(legacy, fast);
        assert_eq!(fast, legacy);
    }

    #[test]
    fn frame_equality_keeps_program_counter_strict_outside_panic() {
        let legacy = sample_frame();
        let mut fast = sample_frame();

        fast.program_counter = None;

        assert_ne!(legacy, fast);
    }

    #[test]
    fn step_equality_tolerates_trivial_pointer_gap_in_panic_frame() {
        let mut legacy = sample_step();
        let fast = sample_step();

        legacy.frame.gas = 0;
        legacy.pointers[0].raw = U256::from_dec_str("978313774790172963290218496").unwrap();
        legacy.pointers[0].memory_page = 10;
        legacy.pointers[0].start = 53_034_496;

        let mut fast = fast;
        fast.frame.gas = 0;

        assert_eq!(legacy, fast);
        assert_eq!(fast, legacy);
    }

    #[test]
    fn step_equality_keeps_trivial_pointer_strict_outside_panic() {
        let mut legacy = sample_step();
        let fast = sample_step();

        legacy.pointers[0].raw = U256::from_dec_str("978313774790172963290218496").unwrap();
        legacy.pointers[0].memory_page = 10;
        legacy.pointers[0].start = 53_034_496;

        assert_ne!(legacy, fast);
    }

    #[test]
    fn step_equality_keeps_nontrivial_pointer_strict_in_panic_frame() {
        let mut legacy = sample_step();
        let mut fast = sample_step();

        legacy.frame.gas = 0;
        fast.frame.gas = 0;
        legacy.pointers[0].raw = U256::from(1_u64);
        legacy.pointers[0].length = 1;
        legacy.pointers[0].memory.total_length = 1;
        legacy.pointers[0].memory.head = vec![0xaa];
        fast.pointers[0].length = 1;
        fast.pointers[0].memory.total_length = 1;
        fast.pointers[0].memory.head = vec![0xaa];

        assert_ne!(legacy, fast);
    }
}
