//! A `zk_evm` reference VM and raw instruction encoding for this differential test.

use primitive_types::{H160, U256};
use zk_evm::{
    abstractions::DecommittmentProcessor,
    aux_structures::{DecommittmentQuery, MemoryPage, Timestamp},
    block_properties::BlockProperties,
    reference_impls::{decommitter::SimpleDecommitter, event_sink::InMemoryEventSink},
    testing::{create_default_testing_tools, storage::InMemoryStorage},
    tracing::{
        AfterDecodingData, AfterExecutionData, BeforeExecutionData, Tracer as ZkTracer,
        VmLocalStateData,
    },
    utils::{bytecode_to_code_hash, contract_bytecode_to_words},
    vm_state::{CallStackEntry, Version, VmState},
    witness_trace::DummyTracer,
};
use zk_evm_abstractions::precompiles::DefaultPrecompilesProcessor;
use zkevm_opcode_defs::{
    decoding::EncodingModeProduction, definitions::versioned_hash::VersionedHashLen32,
    ContractCodeSha256Format, DecodedOpcode, Opcode, OpcodeVariant, BOOTLOADER_BASE_PAGE,
    BOOTLOADER_CODE_PAGE, OPCODES_TABLE, RET_TO_LABEL_BIT_IDX, STARTING_BASE_PAGE,
    STARTING_TIMESTAMP,
};

pub(super) fn find_variant(matches: impl Fn(&OpcodeVariant) -> bool) -> OpcodeVariant {
    *OPCODES_TABLE
        .iter()
        .find(|variant| matches(variant))
        .expect("the opcode table must contain the requested variant")
}

pub(super) fn encode_ret(panic: bool) -> u64 {
    let kind = if panic {
        zkevm_opcode_defs::RetOpcode::Panic
    } else {
        zkevm_opcode_defs::RetOpcode::Ok
    };
    let variant = find_variant(|variant| {
        variant.opcode == Opcode::Ret(kind) && !variant.flags[RET_TO_LABEL_BIT_IDX]
    });
    DecodedOpcode::<8, EncodingModeProduction> {
        variant,
        condition: zkevm_opcode_defs::Condition::Always,
        src0_reg_idx: 0,
        src1_reg_idx: 0,
        dst0_reg_idx: 0,
        dst1_reg_idx: 0,
        imm_0: 0,
        imm_1: 0,
    }
    .serialize_as_integer()
}

#[derive(Debug)]
pub(super) struct ZkNoopTracer;

impl ZkTracer for ZkNoopTracer {
    type SupportedMemory = zk_evm::reference_impls::memory::SimpleMemory;
    fn before_decoding(&mut self, _: VmLocalStateData<'_>, _: &Self::SupportedMemory) {}
    fn after_decoding(
        &mut self,
        _: VmLocalStateData<'_>,
        _: AfterDecodingData,
        _: &Self::SupportedMemory,
    ) {
    }
    fn before_execution(
        &mut self,
        _: VmLocalStateData<'_>,
        _: BeforeExecutionData,
        _: &Self::SupportedMemory,
    ) {
    }
    fn after_execution(
        &mut self,
        _: VmLocalStateData<'_>,
        _: AfterExecutionData,
        _: &Self::SupportedMemory,
    ) {
    }
}

pub(super) type ZkVm = VmState<
    InMemoryStorage,
    zk_evm::reference_impls::memory::SimpleMemory,
    InMemoryEventSink,
    DefaultPrecompilesProcessor<false>,
    SimpleDecommitter<false>,
    DummyTracer,
>;

/// A `zk_evm` VM running `bytecode` at `address` in a bootloader frame, with the entry program
/// decommitted onto `BOOTLOADER_CODE_PAGE`.
pub(super) fn zk_evm_vm(bytecode: &[[u8; 32]], address: H160, gas: u32) -> ZkVm {
    let mut tools = create_default_testing_tools();
    let bytecode_hash = bytecode_to_code_hash(bytecode).expect("bytecode must hash");
    let hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    tools
        .decommittment_processor
        .populate(vec![(hash_as_u256, contract_bytecode_to_words(bytecode))]);
    let (header, normalized_preimage) =
        ContractCodeSha256Format::normalize_for_decommitment(&bytecode_hash);
    let query = DecommittmentQuery {
        header,
        normalized_preimage,
        timestamp: Timestamp(1),
        memory_page: MemoryPage(BOOTLOADER_CODE_PAGE),
        decommitted_length: u16::try_from(bytecode.len()).unwrap(),
        is_fresh: true,
    };
    let prepared = tools
        .decommittment_processor
        .prepare_to_decommit(0, query)
        .expect("must prepare the entry-point decommit");
    tools
        .decommittment_processor
        .decommit_into_memory(0, prepared, &mut tools.memory)
        .expect("must decommit the entry point");

    let mut vm = VmState::empty_state(
        tools.storage,
        tools.memory,
        tools.event_sink,
        tools.precompiles_processor,
        tools.decommittment_processor,
        tools.witness_tracer,
        // `cycle()` asserts both hashes are well-formed; the entry bytecode's own hash is a
        // convenient valid one.
        BlockProperties {
            default_aa_code_hash: hash_as_u256,
            evm_emulator_code_hash: hash_as_u256,
            zkporter_is_available: false,
        },
        Version::latest(),
    );
    let mut context = CallStackEntry::empty_context();
    context.this_address = address;
    context.code_address = address;
    context.base_memory_page = MemoryPage(BOOTLOADER_BASE_PAGE);
    context.code_page = MemoryPage(BOOTLOADER_CODE_PAGE);
    context.ergs_remaining = gas;
    context.exception_handler_location = u16::MAX;
    context.heap_bound = u32::MAX;
    context.aux_heap_bound = u32::MAX;
    vm.push_bootloader_context(0, context);
    vm.local_state.timestamp = STARTING_TIMESTAMP;
    vm.local_state.memory_page_counter = STARTING_BASE_PAGE;
    vm.local_state.monotonic_cycle_counter = 16;
    vm
}
