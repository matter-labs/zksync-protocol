use zk_evm::abstractions::Storage;
use zk_evm::aux_structures::PubdataCost;
use zk_evm::reference_impls::decommitter::SimpleDecommitter;
use zk_evm::reference_impls::event_sink::InMemoryEventSink;
use zk_evm::witness_trace::{DummyTracer, VmWitnessTracer};
use zk_evm::zk_evm_abstractions::precompiles::DefaultPrecompilesProcessor;
use zk_evm::zkevm_opcode_defs::decoding::EncodingModeProduction;
use zk_evm::zkevm_opcode_defs::system_params::VM_INITIAL_FRAME_ERGS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dummy2Tracer;

impl VmWitnessTracer<8, EncodingModeProduction> for Dummy2Tracer {}

/// Set should only differ due to another storage that would be sustituted from outside,
/// and all other tools can be as simple as possible
pub struct ProvingToolset<S: Storage> {
    pub storage: S,
    pub memory: SimpleMemory,
    pub event_sink: InMemoryEventSink,
    pub precompiles_processor: DefaultPrecompilesProcessor<true>,
    pub decommittment_processor: SimpleDecommitter<true>,
    pub witness_tracer: Dummy2Tracer,
}

pub fn create_tools<S: Storage>(storage: S) -> ProvingToolset<S> {
    let memory = SimpleMemory::new_without_preallocations();
    let event_sink = InMemoryEventSink::new();
    let precompiles_processor = DefaultPrecompilesProcessor::<true>;
    let decommittment_processor = SimpleDecommitter::<true>::new();
    let witness_tracer = Dummy2Tracer;

    ProvingToolset {
        storage,
        memory,
        event_sink,
        precompiles_processor,
        decommittment_processor,
        witness_tracer,
    }
}

use crate::entry_point::initial_out_of_circuit_context;
use zk_evm::block_properties::BlockProperties;
use zk_evm::ethereum_types::Address;
use zk_evm::reference_impls::memory::SimpleMemory;
use zk_evm::vm_state::{PrimitiveValue, Version, VmState};
use zk_evm::zkevm_opcode_defs::*;

/// We expect that storage/memory/decommitter were prefilled
pub fn create_out_of_circuit_vm<S: Storage>(
    tools: ProvingToolset<S>,
    block_properties: BlockProperties,
    caller_address: Address,
    entry_point_address: Address,
) -> VmState<
    S,
    SimpleMemory,
    InMemoryEventSink,
    DefaultPrecompilesProcessor<true>,
    SimpleDecommitter<true>,
    Dummy2Tracer,
> {
    create_out_of_circuit_vm_with_subversion(
        tools,
        block_properties,
        caller_address,
        entry_point_address,
        Version::latest(),
    )
}
pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

pub fn create_out_of_circuit_vm_with_subversion<S: Storage>(
    tools: ProvingToolset<S>,
    block_properties: BlockProperties,
    caller_address: Address,
    entry_point_address: Address,
    version: Version,
) -> VmState<
    S,
    SimpleMemory,
    InMemoryEventSink,
    DefaultPrecompilesProcessor<true>,
    SimpleDecommitter<true>,
    Dummy2Tracer,
> {
    let mut vm = VmState::empty_state(
        tools.storage,
        tools.memory,
        tools.event_sink,
        tools.precompiles_processor,
        tools.decommittment_processor,
        tools.witness_tracer,
        block_properties,
        version,
    );

    let initial_context = initial_out_of_circuit_context(
        0,
        VM_INITIAL_FRAME_ERGS,
        entry_point_address,
        caller_address,
        entry_point_address,
    );

    vm.push_bootloader_context(INITIAL_MONOTONIC_CYCLE_COUNTER - 1, initial_context);

    vm.local_state.pubdata_revert_counter = PubdataCost(0i32);

    vm.local_state.timestamp = STARTING_TIMESTAMP;
    vm.local_state.memory_page_counter = STARTING_BASE_PAGE;
    vm.local_state.monotonic_cycle_counter = INITIAL_MONOTONIC_CYCLE_COUNTER;

    // we also FORMALLY mark r1 as "pointer" type, even though we will NOT have any calldata
    let formal_ptr = FatPointer {
        offset: 0,
        memory_page: zk_evm::zkevm_opcode_defs::BOOTLOADER_CALLDATA_PAGE,
        start: 0,
        length: 0,
    };
    let formal_ptr_encoding = formal_ptr.to_u256();
    vm.local_state.registers[0] = PrimitiveValue {
        value: formal_ptr_encoding,
        is_pointer: true,
    };

    vm
}
