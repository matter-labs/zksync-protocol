#![cfg_attr(not(test), no_std)]
#![feature(allocator_api)]

extern crate alloc;

use alloc::string::ToString;
use zk_evm::{
    abstractions::{MemoryType, Storage},
    aux_structures::{
        DecommittmentQuery, MemoryIndex, MemoryLocation, MemoryPage, MemoryQuery, Timestamp,
    },
    block_properties::BlockProperties,
    bytecode_to_code_hash, contract_bytecode_to_words,
    ethereum_types::{Address, H160, H256, U256},
    reference_impls::memory::SimpleMemory,
    testing::simple_tracer::NoopTracer,
    tracing::Tracer,
    vm_state::VmLocalState,
    witness_trace::DummyTracer,
};

use crate::{
    default_tracer::DefaultTracer,
    storage_oracle::{StorageOracle, WitnessStorageOracle},
    toolset::create_tools,
    tracer::LocalTracer,
    utils::calldata_to_aligned_data,
};

mod default_tracer;
mod entry_point;
mod storage_oracle;
mod toolset;
mod tracer;
mod utils;

pub use alloc::borrow::ToOwned;
pub use alloc::string::String;
pub use zk_evm::vec;
use zk_evm::zkevm_opcode_defs::VersionedHashLen32;
pub use zk_evm::Vec;

use zk_evm::abstractions::DecommittmentProcessor;
use zk_evm::abstractions::Memory;
use zk_evm::witness_trace::VmWitnessTracer;

pub const SCHEDULER_TIMESTAMP: u32 = 1;

// Run zkEvm code - most of the logic adapted from zkevm_test_harness/src/run_vms.rs
pub fn run_vms<S: Storage>(
    caller: Address,                 // for real block must be zero
    entry_point_address: Address,    // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read block must be a bootloader code
    initial_heap_content: Vec<u8>,   // bootloader starts with non-deterministic heap
    default_aa_code_hash: U256,
    evm_emulator_code_hash: U256,
    used_bytecodes: hashbrown::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    cycle_limit: usize,
    storage: S,
    /*tree: impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>
    + 'static
    + std::marker::Send,*/
    out_of_circuit_tracer: &mut impl Tracer<SupportedMemory = SimpleMemory>,
) -> Result<VmLocalState, String> {
    // TODO: do something with the roots.
    //let initial_rollup_root = tree.root();
    //let initial_rollup_enumeration_counter = tree.next_enumeration_index();

    let bytecode_hash = bytecode_to_code_hash(&entry_point_code).unwrap();

    let mut tools = create_tools(storage);

    // fill the tools
    let mut to_fill = vec![];
    let entry_point_code_hash_as_u256 = U256::from_big_endian(&bytecode_hash);
    if !used_bytecodes.contains_key(&entry_point_code_hash_as_u256) {
        to_fill.push((
            entry_point_code_hash_as_u256,
            contract_bytecode_to_words(&entry_point_code),
        ));
    }
    for (k, v) in used_bytecodes.into_iter() {
        to_fill.push((k, contract_bytecode_to_words(&v)));
    }
    tools.decommittment_processor.populate(to_fill);

    let heap_writes = calldata_to_aligned_data(&initial_heap_content);
    let num_non_deterministic_heap_queries = heap_writes.len();

    let (header, normalized_preimage) = zk_evm::zkevm_opcode_defs::definitions::versioned_hash::ContractCodeSha256Format::normalize_for_decommitment(&bytecode_hash);

    // bootloader decommit query
    let entry_point_decommittment_query = DecommittmentQuery {
        header,
        normalized_preimage,
        timestamp: Timestamp(SCHEDULER_TIMESTAMP),
        memory_page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_CODE_PAGE),
        decommitted_length: entry_point_code.len() as u16,
        is_fresh: true,
    };

    // manually decommit entry point
    let prepared_entry_point_decommittment_query = tools
        .decommittment_processor
        .prepare_to_decommit(0, entry_point_decommittment_query)
        .expect("must prepare decommit of entry point");
    tools
        .witness_tracer
        .prepare_for_decommittment(0, entry_point_decommittment_query);
    let entry_point_decommittment_query_witness = tools
        .decommittment_processor
        .decommit_into_memory(
            0,
            prepared_entry_point_decommittment_query,
            &mut tools.memory,
        )
        .expect("must execute decommit of entry point");
    let entry_point_decommittment_query_witness = entry_point_decommittment_query_witness.unwrap();
    tools.witness_tracer.execute_decommittment(
        0,
        entry_point_decommittment_query,
        entry_point_decommittment_query_witness.clone(),
    );

    let block_properties = BlockProperties {
        default_aa_code_hash,
        evm_emulator_code_hash,
        zkporter_is_available: false,
    };

    use crate::toolset::create_out_of_circuit_vm;

    let mut out_of_circuit_vm =
        create_out_of_circuit_vm(tools, block_properties, caller, entry_point_address);

    // first there exists non-deterministic writes into the heap of the bootloader's heap and calldata
    // heap

    for (idx, el) in heap_writes.into_iter().enumerate() {
        let query = MemoryQuery {
            timestamp: Timestamp(0),
            location: MemoryLocation {
                memory_type: MemoryType::Heap,
                page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE),
                index: MemoryIndex(idx as u32),
            },
            rw_flag: true,
            value: el,
            value_is_pointer: false,
        };
        out_of_circuit_vm.witness_tracer.add_memory_query(0, query);
        out_of_circuit_vm.memory.execute_partial_query(0, query);
    }

    let mut default_tracer = DefaultTracer::new(out_of_circuit_tracer);

    // tracing::debug!("Running out of circuit for {} cycles", cycle_limit);
    //println!("Running out of circuit for {} cycles", cycle_limit);
    let mut next_snapshot_will_capture_end_of_execution = false;

    //let mut snapshots_len = None;
    for _cycle in 0..cycle_limit {
        if out_of_circuit_vm.execution_has_ended() {
            break;

            /*
            // we formally have to let VM run as it resets some of the state in a process
            if next_snapshot_will_capture_end_of_execution == false {
                next_snapshot_will_capture_end_of_execution = true;
                snapshots_len = Some(out_of_circuit_vm.witness_tracer.vm_snapshots.len());
            } else {
                if snapshots_len.unwrap() != out_of_circuit_vm.witness_tracer.vm_snapshots.len() {
                    // snapshot has captured the final state
                    break;
                }
            }*/
        }

        out_of_circuit_vm
            .cycle(&mut default_tracer)
            .expect("cycle should finish succesfully");

        // Dynamically insert newly deployed EVM contracts in decommiter

        // TODO: fix the issue with newly deployed EVM stuff.
        /*if default_tracer.evm_tracer.pending_bytecodes.len() != 0 {
            let deployed_bytecodes = default_tracer
                .evm_tracer
                .flush_bytecodes()
                .into_iter()
                .filter(|(bytecode_hash, _)| {
                    // Ignore alredy known bytecodes
                    let mut buffer = [0u8; 32];
                    bytecode_hash.to_big_endian(&mut buffer);
                    let (_, normalized) = BlobSha256Format::normalize_for_decommitment(&buffer);
                    out_of_circuit_vm
                        .decommittment_processor
                        .get_preimage_by_hash(normalized)
                        .is_none()
                })
                .collect();

            out_of_circuit_vm
                .decommittment_processor
                .populate(deployed_bytecodes);
        }*/
    }

    if !out_of_circuit_vm.execution_has_ended() {
        return Err("VM execution didn't finish".to_owned());
    }
    if out_of_circuit_vm.local_state.callstack.current.pc != 0 {
        return Err("root frame ended up with panic".to_owned());
    }

    //println!("Out of circuit tracing is complete, now running witness generation");

    let vm_local_state = out_of_circuit_vm.local_state.clone();

    Ok(vm_local_state)

    /*if !next_snapshot_will_capture_end_of_execution {
        // perform the final snapshot
        let current_cycle_counter = out_of_circuit_vm.witness_tracer.current_cycle_counter;
        use crate::witness::tracer::vm_snapshot::VmSnapshot;
        let snapshot = VmSnapshot {
            local_state: vm_local_state.clone(),
            at_cycle: current_cycle_counter,
        };
        out_of_circuit_vm.witness_tracer.vm_snapshots.push(snapshot);
    }*/

    //let witness_tracer = out_of_circuit_vm.witness_tracer.clone();
    //drop(out_of_circuit_vm);
}

#[derive(Debug, serde::Deserialize)]
pub struct WitnessStorageState {
    pub read_storage_key: Vec<(StorageKey, H256)>,
    pub is_write_initial: Vec<(StorageKey, bool)>,
}

#[derive(Debug, serde::Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccountTreeId {
    pub address: Address,
}

#[derive(Debug, serde::Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct StorageKey {
    pub account: AccountTreeId,
    pub key: H256,
}

#[derive(Debug, serde::Deserialize)]
pub enum Helper {
    Success(ProofGenerationData),
}

#[derive(Debug, serde::Deserialize)]
pub struct ProofGenerationData {
    l1_batch_number: u64,
    pub witness_input_data: WitnessInputData,
}

#[derive(Debug, serde::Deserialize)]
pub struct WitnessInputData {
    pub vm_run_data: VMRunWitnessInputData,
}

#[derive(Debug, serde::Deserialize)]
pub struct VMRunWitnessInputData {
    pub l1_batch_number: u32,
    pub used_bytecodes: alloc::collections::BTreeMap<U256, Vec<[u8; 32]>>,
    //pub used_bytecodes: std::collections::HashMap<U256, std::vec::Vec<[u8; 32]>>,
    //pub used_bytecodes: std::collections::HashMap<u64, u64>,
    pub initial_heap_content: Vec<(usize, U256)>,
    //pub protocol_version: ProtocolVersionId,
    pub bootloader_code: Vec<[u8; 32]>,
    pub default_account_code_hash: U256,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_emulator_code_hash: Option<U256>,
    pub storage_refunds: Vec<u32>,
    pub pubdata_costs: Vec<i32>,
    pub witness_block_state: WitnessStorageState,
}

pub const BOOTLOADER_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x01,
]);

pub fn expand_bootloader_contents(packed: &[(usize, U256)]) -> Vec<u8> {
    let full_length = 63_800_000;

    let mut result = vec![0u8; full_length];

    for (offset, value) in packed {
        value.to_big_endian(&mut result[(offset * 32)..(offset + 1) * 32]);
    }

    result
}

pub fn run_vms_from_json_string(buf: String) -> Result<VmLocalState, String> {
    let helper: Helper = serde_json::from_str(&buf).expect("Failed to parse JSON");

    let helper = match helper {
        Helper::Success(data) => data,
        _ => panic!("Expected success variant of Helper"),
    };

    let input = helper.witness_input_data;

    // stuff copied from zksync-era/provers/ witness_generator_service/src/rounds/basic_circuits/utils.rs

    let bootloader_contents = expand_bootloader_contents(&input.vm_run_data.initial_heap_content);
    let evm_emulator_code_hash = input.vm_run_data.evm_emulator_code_hash.unwrap();

    //println!("Helper read from file: {:?}", helper);

    // this is a 'local' (zksync-era) wrapper over the hashmap.

    // this part is VERY era specific... I need a simpler implementation here.
    /*let witness_storage = WitnessStorage::new(input.vm_run_data.witness_block_state);

    let storage_view = StorageView::new(witness_storage).to_rc_ptr();

    let vm_storage_oracle: VmStorageOracle<StorageView<WitnessStorage>, HistoryDisabled> =
        VmStorageOracle::new(storage_view.clone());*/

    let vm_storage_oracle = WitnessStorageOracle::new(input.vm_run_data.witness_block_state);

    let storage_oracle = StorageOracle::new(
        vm_storage_oracle,
        input.vm_run_data.storage_refunds,
        input.vm_run_data.pubdata_costs,
    );

    let mut tracer = LocalTracer;

    let mut new_used_bytecodes = hashbrown::HashMap::new();
    for entry in input.vm_run_data.used_bytecodes {
        new_used_bytecodes.insert(entry.0, entry.1);
    }

    run_vms(
        Address::zero(),
        BOOTLOADER_ADDRESS,
        input.vm_run_data.bootloader_code,
        bootloader_contents,
        input.vm_run_data.default_account_code_hash,
        evm_emulator_code_hash,
        new_used_bytecodes, //input.vm_run_data.used_bytecodes,
        800_000_000 as usize,
        storage_oracle,
        &mut tracer,
    )
}

#[cfg(test)]
mod tests {
    use crate::storage_oracle::{StorageOracle, WitnessStorageOracle};

    use super::*;
    use std::io::BufReader;
    use std::{fs::File, io::Read};
    use zk_evm::ethereum_types::{H160, H256};
    use zk_evm::{
        abstractions::Storage,
        ethereum_types::{Address, U256},
        testing::storage::InMemoryStorage,
    };

    #[test]
    fn test_run_vms_returns_expected_error() {
        let storage = InMemoryStorage::new();

        let caller = Address::zero();
        let entry_point_address = Address::from_low_u64_be(0x1001);
        let entry_point_code = vec![
            [
                0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x40, 0x03, 0x00,
                0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x02, 0x32, 0x04, 0x36, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x32, 0x04, 0x3A,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                0x04, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x19, 0x00, 0x00, 0x00, 0x00,
                0x05, 0x00, 0x04, 0x13,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x15, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00,
                0x09, 0x00, 0x04, 0x11,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x04, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x04, 0x2D, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x04, 0x32, 0x00, 0x00, 0x00, 0x0F,
                0x00, 0x01, 0x04, 0x2E,
            ],
            [
                0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x04, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x70, 0x04, 0x3B, 0x18, 0x0F, 0xAC, 0xA3, 0x47, 0x97, 0x28, 0x28, 0xA5, 0x8C, 0xE6,
                0x8A, 0xFB, 0xA8, 0x56, 0xB1, 0xE5, 0x32, 0x3A, 0x2D, 0x46, 0x49, 0x21, 0x49, 0xA5,
                0x61, 0x04, 0x71, 0xE8,
            ],
        ];
        let initial_heap_content = vec![];
        let empty_code_hash = U256::from_big_endian(&bytecode_to_code_hash(&[[0; 32]]).unwrap());
        let default_aa_code_hash = empty_code_hash;
        let evm_emulator_code_hash = empty_code_hash;

        let mut tracer = LocalTracer;

        run_vms(
            caller,
            entry_point_address,
            entry_point_code,
            initial_heap_content,
            default_aa_code_hash,
            evm_emulator_code_hash,
            Default::default(),
            1_000_000,
            storage,
            &mut tracer,
        );
    }

    #[test]
    fn test_load_from_json_and_run() {
        let mut file = File::open("generation_response.json").expect("Failed to open helper.json");
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();

        run_vms_from_json_string(buf);
    }
}
