use super::*;
use zk_evm_abstractions::auxiliary::*;
use zk_evm_abstractions::queries::*;
use zk_evm_abstractions::vm::*;
use zkevm_opcode_defs::system_params::*;
use zkevm_opcode_defs::PrecompileCallABI;

fn fill_memory<M: Memory>(b: [u8; 32], e: [u8; 32], m: [u8; 32], page: u32, memory: &mut M) -> u32 {
    let mut location = MemoryLocation {
        page: MemoryPage(page),
        index: MemoryIndex(0),
        memory_type: MemoryType::Heap,
    };
    let mut counter = 0u32;
    for data in [b, e, m] {
        let query = MemoryQuery {
            timestamp: Timestamp(0u32),
            location,
            value: U256::from_big_endian(&data),
            rw_flag: true,
            value_is_pointer: false,
        };
        let _ = memory.execute_partial_query(counter, query);

        location.index.0 += 1;
        counter += 1;
    }

    counter
}

// We don't check the 'sizes' here - as this is handled by the Yul contract.
fn modexp_test_inner(
    _b_size: [u8; 32],
    _e_size: [u8; 32],
    _m_size: [u8; 32],
    b: [u8; 32],
    e: [u8; 32],
    m: [u8; 32],
    expected_result: [u8; 32],
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let mut memory = SimpleMemory::new();
    let mut precompiles_processor = DefaultPrecompilesProcessor::<false>;
    let page_number = 4u32;
    // create heap page
    memory.populate_page(vec![
        (page_number, vec![U256::zero(); 1 << 10]),
        (page_number + 1, vec![]),
    ]);

    // fill the memory
    let num_words_used = fill_memory(b, e, m, page_number, &mut memory);

    let precompile_call_params = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: num_words_used,
        output_memory_offset: num_words_used,
        output_memory_length: 1,
        memory_page_to_read: page_number,
        memory_page_to_write: page_number,
        precompile_interpreted_data: 0,
    };
    let precompile_call_params_encoded = precompile_call_params.to_u256();

    let address = Address::from_low_u64_be(MODEXP_PRECOMPILE_ADDRESS as u64);

    let precompile_query = LogQuery {
        timestamp: Timestamp(1u32),
        tx_number_in_block: 0,
        shard_id: 0,
        aux_byte: PRECOMPILE_AUX_BYTE,
        address,
        key: precompile_call_params_encoded,
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    };

    let _ = precompiles_processor.execute_precompile(4, precompile_query, &mut memory);

    let range = 0u32..(num_words_used + 1);
    let content = memory.dump_page_content(page_number, range.clone());
    let content_len = content.len();
    let output = content[content_len - 1];

    assert_eq!(&output, &expected_result);

    (content, range)
}

fn modexp_test_inner_from_raw(
    raw_input: &str,
    raw_output: &str,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    let input_bytes = hex::decode(raw_input).unwrap();
    let b_size: [u8; 32] = input_bytes[0..32].try_into().unwrap();
    let e_size: [u8; 32] = input_bytes[32..64].try_into().unwrap();
    let m_size: [u8; 32] = input_bytes[64..96].try_into().unwrap();
    let b: [u8; 32] = input_bytes[96..128].try_into().unwrap();
    let e: [u8; 32] = input_bytes[128..160].try_into().unwrap();
    let m: [u8; 32] = input_bytes[160..192].try_into().unwrap();

    let expected_result: [u8; 32] = hex::decode(raw_output).unwrap().try_into().unwrap();

    modexp_test_inner(b_size, e_size, m_size, b, e, m, expected_result)
}

fn u256_to_bytes(input: U256) -> [u8; 32] {
    let mut tmp = [0u8; 32];
    input.to_big_endian(&mut tmp);
    tmp
}

fn u64_to_bytes(input: u64) -> [u8; 32] {
    u256_to_bytes(U256::from(input))
}

fn modexp_test_inner_from_u64(
    b: u64,
    e: u64,
    m: u64,
    result: u64,
) -> (Vec<[u8; 32]>, std::ops::Range<u32>) {
    modexp_test_inner(
        u64_to_bytes(32),
        u64_to_bytes(32),
        u64_to_bytes(32),
        u64_to_bytes(b),
        u64_to_bytes(e),
        u64_to_bytes(m),
        u64_to_bytes(result),
    )
}

#[cfg(test)]
pub mod test {
    /// Tests the modexp correctness based on the valid input.
    #[test]
    fn test_simple() {
        use super::*;

        modexp_test_inner_from_u64(2, 3, 100, 8);
        // If any argument is 0 - the answer should be 0
        modexp_test_inner_from_u64(0, 3, 100, 0);
        modexp_test_inner_from_u64(2, 0, 100, 0);
        modexp_test_inner_from_u64(2, 3, 0, 0);

        modexp_test_inner_from_u64(2, 3, 8, 0);
        modexp_test_inner_from_u64(2, 3, 7, 1);
    }

    /// Tests the modexp correctness based on the valid input.
    #[test]
    fn test_valid() {
        use super::*;

        let raw_input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007f333213268023a7d3d40ea760d0e1c00d5fe99710e379193fc5973e7ad09370039d71831130091794534336679323390f4408be38cb89963ec41f4a90d6bf63ec6f05ec20e4c25420f9d6bc6800f9544ecabf5dbea80d11e0fb12c7f0517f5b";
        let raw_output = "2779a7e4d2b26461c6557a12eb86285eeeb9cf5a40155305177854b15b4ed3df";
        let (content, range) = modexp_test_inner_from_raw(raw_input, raw_output);
        pretty_print_memory_dump(&content, range);
    }
}
