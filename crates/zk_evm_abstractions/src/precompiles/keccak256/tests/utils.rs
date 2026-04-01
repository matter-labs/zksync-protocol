use zkevm_opcode_defs::ethereum_types::{Address, U256};
use zkevm_opcode_defs::PrecompileCallABI;

use crate::aux::Timestamp;
use crate::queries::{LogQuery, MemoryQuery};
use crate::vm::Memory;

use super::super::{
    execute_keccak_precompile, Keccak256RoundWitness, KeccakBackend, KECCAK_RATE_BYTES,
};

pub(super) type KeccakExecution = (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<Keccak256RoundWitness>,
    )>,
);

pub(super) const QUICKCHECK_NUM_CASES: u64 = 256;
pub(super) const QUICKCHECK_MAX_INPUT_BYTES: usize = 2048;
const KECCAK_RATE_BOUNDARY: usize = KECCAK_RATE_BYTES;

#[derive(Clone, Copy, Debug)]
pub(super) struct DeterministicKeccakCase {
    name: &'static str,
    input_length: usize,
    input_offset: u32,
    seed: u64,
}

impl DeterministicKeccakCase {
    fn input(self) -> Vec<u8> {
        let mut state = self.seed;

        (0..self.input_length)
            .map(|idx| {
                // A tiny deterministic byte stream is enough here: the goal is to keep the
                // message contents stable while making the long-message cases less uniform than
                // the usual repeated-byte fixtures.
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;

                (state as u8).wrapping_add((idx as u8).wrapping_mul(17))
            })
            .collect()
    }
}

pub(super) const DETERMINISTIC_KECCAK_CASES: &[DeterministicKeccakCase] = &[
    DeterministicKeccakCase {
        name: "empty-aligned",
        input_length: 0,
        input_offset: 0,
        seed: 0x01,
    },
    DeterministicKeccakCase {
        name: "crosses-word-boundary",
        input_length: 33,
        input_offset: 31,
        seed: 0x23,
    },
    DeterministicKeccakCase {
        name: "rate-minus-one",
        input_length: KECCAK_RATE_BOUNDARY - 1,
        input_offset: 17,
        seed: 0x45,
    },
    DeterministicKeccakCase {
        name: "rate",
        input_length: KECCAK_RATE_BOUNDARY,
        input_offset: 0,
        seed: 0x67,
    },
    DeterministicKeccakCase {
        name: "rate-plus-one",
        input_length: KECCAK_RATE_BOUNDARY + 1,
        input_offset: 1,
        seed: 0x89,
    },
    DeterministicKeccakCase {
        name: "two-rates-minus-one",
        input_length: (2 * KECCAK_RATE_BOUNDARY) - 1,
        input_offset: 5,
        seed: 0xab,
    },
    DeterministicKeccakCase {
        name: "two-rates",
        input_length: 2 * KECCAK_RATE_BOUNDARY,
        input_offset: 31,
        seed: 0xcd,
    },
    DeterministicKeccakCase {
        name: "long-512",
        input_length: 512,
        input_offset: 7,
        seed: 0x101,
    },
    DeterministicKeccakCase {
        name: "long-1024",
        input_length: 1024,
        input_offset: 13,
        seed: 0x202,
    },
    DeterministicKeccakCase {
        name: "long-1536",
        input_length: 1536,
        input_offset: 29,
        seed: 0x303,
    },
];

#[derive(Debug, Default)]
struct TestInputMemory {
    words: Vec<U256>,
}

impl TestInputMemory {
    fn for_input(input_offset: u32, input: &[u8]) -> Self {
        let total_bytes = input_offset as usize + input.len();
        let num_words = (total_bytes + 31) / 32;
        let mut bytes = vec![0u8; num_words * 32];
        let input_offset = input_offset as usize;

        bytes[input_offset..(input_offset + input.len())].copy_from_slice(input);

        let words = bytes
            .chunks(32)
            .map(U256::from_big_endian)
            .collect::<Vec<_>>();

        Self { words }
    }
}

impl Memory for TestInputMemory {
    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        mut query: MemoryQuery,
    ) -> MemoryQuery {
        if !query.rw_flag {
            query.value = self
                .words
                .get(query.location.index.0 as usize)
                .copied()
                .unwrap_or_else(U256::zero);
        }

        query
    }

    fn specialized_code_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        _query: MemoryQuery,
    ) -> MemoryQuery {
        unreachable!("keccak precompile does not issue code queries")
    }

    fn read_code_query(&self, _monotonic_cycle_counter: u32, _query: MemoryQuery) -> MemoryQuery {
        unreachable!("keccak precompile does not issue code queries")
    }
}

fn make_keccak_test_query(input_offset: u32, input_length: u32) -> LogQuery {
    let abi = PrecompileCallABI {
        input_memory_offset: input_offset,
        input_memory_length: input_length,
        output_memory_offset: 0,
        output_memory_length: 1,
        memory_page_to_read: 1,
        memory_page_to_write: 2,
        precompile_interpreted_data: 0,
    };

    LogQuery {
        timestamp: Timestamp(1),
        tx_number_in_block: 0,
        aux_byte: 0,
        shard_id: 0,
        address: Address::zero(),
        key: abi.to_u256(),
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    }
}

pub(super) fn run_keccak_precompile_test_backend<Backend: KeccakBackend>(
    input_offset: u32,
    input: &[u8],
) -> KeccakExecution {
    let query = make_keccak_test_query(input_offset, input.len() as u32);
    let mut memory = TestInputMemory::for_input(input_offset, input);
    execute_keccak_precompile::<TestInputMemory, Backend, true>(0, query, &mut memory)
}

pub(super) fn execution_output_bytes(execution: &KeccakExecution) -> [u8; 32] {
    let (_, witness) = execution;
    let (_, write_queries, _) = witness
        .as_ref()
        .expect("keccak test execution must produce witness");
    let result_query = write_queries
        .last()
        .expect("keccak test execution must include one write");

    let mut output = [0u8; 32];
    result_query.value.to_big_endian(&mut output);
    output
}

pub(super) fn reference_keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak as TinyKeccak};

    let mut state = TinyKeccak::v256();
    let mut output = [0u8; 32];
    state.update(input);
    state.finalize(&mut output);
    output
}

pub(super) fn assert_backend_matches_reference<Backend: KeccakBackend>(
    case: DeterministicKeccakCase,
) {
    let input = case.input();
    let actual = execution_output_bytes(&run_keccak_precompile_test_backend::<Backend>(
        case.input_offset,
        &input,
    ));
    let reference = reference_keccak256(&input);

    assert_eq!(
        actual, reference,
        "backend must match tiny-keccak for case='{}', offset={}, length={}",
        case.name, case.input_offset, case.input_length,
    );
}
