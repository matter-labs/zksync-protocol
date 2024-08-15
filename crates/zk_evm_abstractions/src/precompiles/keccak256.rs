use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;
pub use zkevm_opcode_defs::sha3::Keccak256;

use crate::aux::*;
use crate::queries::*;
use crate::vm::*;

use super::precompile_abi_in_log;

pub const KECCAK_RATE_BYTES: usize = 136;
pub const MEMORY_READS_PER_CYCLE: usize = 6;
pub const KECCAK_PRECOMPILE_BUFFER_SIZE: usize = MEMORY_READS_PER_CYCLE * 32;
pub const MEMORY_WRITES_PER_CYCLE: usize = 1;
pub const NUM_WORDS_PER_QUERY: usize = 4;
pub const KECCAK_RATE_IN_U64_WORDS: usize = KECCAK_RATE_BYTES / 8;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Keccak256RoundWitness {
    pub new_request: Option<LogQuery>,
    pub reads: [Option<MemoryQuery>; MEMORY_READS_PER_CYCLE],
    pub writes: Option<[MemoryQuery; MEMORY_WRITES_PER_CYCLE]>,
}

pub struct ByteBuffer<const BUFFER_SIZE: usize> {
    pub bytes: [u8; BUFFER_SIZE],
    pub filled: usize,
}

impl<const BUFFER_SIZE: usize> ByteBuffer<BUFFER_SIZE> {
    pub fn can_fill_bytes(&self, num_bytes: usize) -> bool {
        self.filled + num_bytes <= BUFFER_SIZE
    }

    pub fn fill_with_bytes<const N: usize>(
        &mut self,
        input: &[u8; N],
        offset: usize,
        meaningful_bytes: usize,
    ) {
        assert!(self.filled + meaningful_bytes <= BUFFER_SIZE);
        self.bytes[self.filled..(self.filled + meaningful_bytes)]
            .copy_from_slice(&input[offset..(offset + meaningful_bytes)]);
        self.filled += meaningful_bytes;
    }

    pub fn consume<const N: usize>(&mut self) -> [u8; N] {
        assert!(N <= BUFFER_SIZE);
        let mut result = [0u8; N];
        result.copy_from_slice(&self.bytes[..N]);
        if self.filled < N {
            self.filled = 0;
        } else {
            self.filled -= N;
        }
        let mut new_bytes = [0u8; BUFFER_SIZE];
        new_bytes[..(BUFFER_SIZE - N)].copy_from_slice(&self.bytes[N..]);
        self.bytes = new_bytes;

        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Keccak256Precompile<const B: bool>;

impl<const B: bool> Precompile for Keccak256Precompile<B> {
    type CycleWitness = Keccak256RoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        let mut full_round_padding = [0u8; KECCAK_RATE_BYTES];
        full_round_padding[0] = 0x01;
        full_round_padding[KECCAK_RATE_BYTES - 1] = 0x80;

        let precompile_call_params = query;
        // read the parameters
        let params = precompile_abi_in_log(precompile_call_params);
        let timestamp_to_read = precompile_call_params.timestamp;
        let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1); // our default timestamping agreement

        let mut input_byte_offset = params.input_memory_offset as usize;
        let mut bytes_left = params.input_memory_length as usize;

        let mut num_rounds = (bytes_left + (KECCAK_RATE_BYTES - 1)) / KECCAK_RATE_BYTES;
        let padding_space = bytes_left % KECCAK_RATE_BYTES;
        let needs_extra_padding_round = padding_space == 0;
        if needs_extra_padding_round {
            num_rounds += 1;
        }

        let source_memory_page = params.memory_page_to_read;
        let destination_memory_page = params.memory_page_to_write;
        let write_offset = params.output_memory_offset;

        let mut read_queries = if B {
            Vec::with_capacity(MEMORY_READS_PER_CYCLE * num_rounds)
        } else {
            vec![]
        };

        let mut write_queries = if B {
            Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
        } else {
            vec![]
        };

        let mut witness = if B {
            Vec::with_capacity(num_rounds)
        } else {
            vec![]
        };

        let mut input_buffer = ByteBuffer::<KECCAK_PRECOMPILE_BUFFER_SIZE> {
            bytes: [0u8; KECCAK_PRECOMPILE_BUFFER_SIZE],
            filled: 0,
        };

        let mut internal_state = Keccak256::default();

        for round in 0..num_rounds {
            let mut round_witness = Keccak256RoundWitness {
                new_request: None,
                reads: [None; MEMORY_READS_PER_CYCLE],
                writes: None,
            };

            if B && round == 0 {
                round_witness.new_request = Some(precompile_call_params);
            }

            let is_last = round == num_rounds - 1;
            let paddings_round = needs_extra_padding_round && is_last;

            let mut bytes32_buffer = [0u8; 32];
            for idx in 0..MEMORY_READS_PER_CYCLE {
                let (memory_index, unalignment) = (input_byte_offset / 32, input_byte_offset % 32);
                let at_most_meaningful_bytes_in_query = 32 - unalignment;
                let meaningful_bytes_in_query = if bytes_left >= at_most_meaningful_bytes_in_query {
                    at_most_meaningful_bytes_in_query
                } else {
                    bytes_left
                };

                let enough_buffer_space = input_buffer.can_fill_bytes(meaningful_bytes_in_query);
                let nothing_to_read = meaningful_bytes_in_query == 0;
                let should_read =
                    nothing_to_read == false && paddings_round == false && enough_buffer_space;

                let bytes_to_fill = if should_read {
                    meaningful_bytes_in_query
                } else {
                    0
                };

                if should_read {
                    input_byte_offset += meaningful_bytes_in_query;
                    bytes_left -= meaningful_bytes_in_query;

                    let data_query = MemoryQuery {
                        timestamp: timestamp_to_read,
                        location: MemoryLocation {
                            memory_type: MemoryType::FatPointer,
                            page: MemoryPage(source_memory_page),
                            index: MemoryIndex(memory_index as u32),
                        },
                        value: U256::zero(),
                        value_is_pointer: false,
                        rw_flag: false,
                    };
                    let data_query =
                        memory.execute_partial_query(monotonic_cycle_counter, data_query);
                    let data = data_query.value;
                    if B {
                        round_witness.reads[idx] = Some(data_query);
                        read_queries.push(data_query);
                    }
                    data.to_big_endian(&mut bytes32_buffer[..]);
                }

                input_buffer.fill_with_bytes(&bytes32_buffer, unalignment, bytes_to_fill)
            }

            // buffer is always large enough for us to have data

            let mut block = input_buffer.consume::<KECCAK_RATE_BYTES>();
            // apply padding
            if paddings_round {
                block = full_round_padding;
            } else if is_last {
                if padding_space == KECCAK_RATE_BYTES - 1 {
                    block[KECCAK_RATE_BYTES - 1] = 0x81;
                } else {
                    block[padding_space] = 0x01;
                    block[KECCAK_RATE_BYTES - 1] = 0x80;
                }
            }
            // update the keccak internal state
            internal_state.update(&block);

            if is_last {
                let state_inner = transmute_state(internal_state.clone());

                // take hash and properly set endianess for the output word
                let mut hash_as_bytes32 = [0u8; 32];
                hash_as_bytes32[0..8].copy_from_slice(&state_inner[0].to_le_bytes());
                hash_as_bytes32[8..16].copy_from_slice(&state_inner[1].to_le_bytes());
                hash_as_bytes32[16..24].copy_from_slice(&state_inner[2].to_le_bytes());
                hash_as_bytes32[24..32].copy_from_slice(&state_inner[3].to_le_bytes());
                let as_u256 = U256::from_big_endian(&hash_as_bytes32);
                let write_location = MemoryLocation {
                    memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                    page: MemoryPage(destination_memory_page),
                    index: MemoryIndex(write_offset),
                };

                let result_query = MemoryQuery {
                    timestamp: timestamp_to_write,
                    location: write_location,
                    value: as_u256,
                    value_is_pointer: false,
                    rw_flag: true,
                };

                let result_query =
                    memory.execute_partial_query(monotonic_cycle_counter, result_query);

                if B {
                    round_witness.writes = Some([result_query]);
                    write_queries.push(result_query);
                }
            }

            if B {
                witness.push(round_witness);
            }
        }

        let witness = if B {
            Some((read_queries, write_queries, witness))
        } else {
            None
        };

        (num_rounds, witness)
    }
}

pub fn keccak256_rounds_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<Keccak256RoundWitness>,
    )>,
) {
    let mut processor = Keccak256Precompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

pub type Keccak256InnerState = [u64; 25];

struct Sha3State {
    state: [u64; 25],
    _round_count: usize,
}

struct BlockBuffer {
    _buffer: [u8; 136],
    _pos: u8,
}

struct CoreWrapper {
    core: Sha3State,
    _buffer: BlockBuffer,
}

static_assertions::assert_eq_size!(Keccak256, CoreWrapper);

pub fn transmute_state(reference_state: Keccak256) -> Keccak256InnerState {
    // we use a trick that size of both structures is the same, and even though we do not know a stable field layout,
    // we can replicate it
    let our_wrapper: CoreWrapper = unsafe { std::mem::transmute(reference_state) };

    our_wrapper.core.state
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkevm_opcode_defs::sha2::Digest;

    #[test]
    fn test_empty_string() {
        let mut hasher = Keccak256::new();
        hasher.update(&[]);
        let result = hasher.finalize();
        println!("Empty string hash = {}", hex::encode(result.as_slice()));

        let mut our_hasher = Keccak256::default();
        let mut block = [0u8; 136];
        block[0] = 0x01;
        block[135] = 0x80;
        our_hasher.update(&block);
        let state_inner = transmute_state(our_hasher);
        for (idx, el) in state_inner.iter().enumerate() {
            println!("Element {} = 0x{:016x}", idx, el);
        }
    }
}
