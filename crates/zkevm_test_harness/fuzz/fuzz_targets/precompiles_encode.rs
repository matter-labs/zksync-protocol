#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use zkevm_assembly::zkevm_opcode_defs::PrecompileCallABI;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Arbitrary)]
pub struct PrecompileCallABIWrapper {
    pub input_memory_offset: u32,
    pub input_memory_length: u32,
    pub output_memory_offset: u32,
    pub output_memory_length: u32,
    pub memory_page_to_read: u32,
    pub memory_page_to_write: u32,
    pub precompile_interpreted_data: u64,
}

fuzz_target!(|data: PrecompileCallABIWrapper| {
    let p1 = PrecompileCallABI {
        input_memory_offset: data.input_memory_offset,
        input_memory_length: data.input_memory_length,
        output_memory_offset: data.output_memory_offset,
        output_memory_length: data.output_memory_length,
        memory_page_to_read: data.memory_page_to_read,
        memory_page_to_write: data.memory_page_to_write,
        precompile_interpreted_data: data.precompile_interpreted_data,
    };
    let u = p1.to_u256();

    let p2 = PrecompileCallABI::from_u256(u);
    assert_eq!(p1, p2)
});
