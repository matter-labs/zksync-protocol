use cfg_if::cfg_if;
use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;
pub use zkevm_opcode_defs::sha3::Keccak256;

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use airbender_crypto::sha3::Keccak256 as AirbenderKeccak256;
    }
}

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

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        // ==============================================================================
        // Delegated Keccak Backend
        // ==============================================================================
        //
        // The delegated backend must preserve the legacy read cadence so witnesses and
        // cycle accounting stay stable. Once bytes have been forwarded to the delegated
        // digest, though, re-buffering them locally does not buy us anything.
        struct KeccakRoundAccumulator {
            buffered_bytes: usize,
            state: Option<AirbenderKeccak256>,
        }

        impl KeccakRoundAccumulator {
            fn new() -> Self {
                Self {
                    buffered_bytes: 0,
                    state: Some(<AirbenderKeccak256 as airbender_crypto::MiniDigest>::new()),
                }
            }

            fn can_fill_bytes(&self, num_bytes: usize) -> bool {
                self.buffered_bytes + num_bytes <= KECCAK_PRECOMPILE_BUFFER_SIZE
            }

            fn absorb_query_bytes(
                &mut self,
                input: &[u8; 32],
                offset: usize,
                meaningful_bytes: usize,
            ) {
                if meaningful_bytes == 0 {
                    return;
                }

                let end = offset + meaningful_bytes;
                airbender_crypto::MiniDigest::update(
                    self.state
                        .as_mut()
                        .expect("airbender keccak state must exist before finalization"),
                    &input[offset..end],
                );
                self.buffered_bytes += meaningful_bytes;
            }

            fn finish_round(
                &mut self,
                _full_round_padding: &[u8; KECCAK_RATE_BYTES],
                _is_last: bool,
                _paddings_round: bool,
                _padding_space: usize,
            ) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(KECCAK_RATE_BYTES);
            }

            fn finalize(&mut self) -> [u8; 32] {
                airbender_crypto::MiniDigest::finalize(
                    self.state
                        .take()
                        .expect("airbender keccak state must exist for finalization"),
                )
            }
        }
    } else {
        // ==============================================================================
        // Legacy Keccak Backend
        // ==============================================================================
        //
        // The legacy backend still absorbs complete rate-sized blocks, so it keeps the
        // explicit staging buffer that assembles aligned memory reads into keccak rounds.
        struct KeccakRoundAccumulator {
            buffer: ByteBuffer<KECCAK_PRECOMPILE_BUFFER_SIZE>,
            state: Keccak256,
        }

        impl KeccakRoundAccumulator {
            fn new() -> Self {
                Self {
                    buffer: ByteBuffer {
                        bytes: [0u8; KECCAK_PRECOMPILE_BUFFER_SIZE],
                        filled: 0,
                    },
                    state: Keccak256::default(),
                }
            }

            fn can_fill_bytes(&self, num_bytes: usize) -> bool {
                self.buffer.can_fill_bytes(num_bytes)
            }

            fn absorb_query_bytes(
                &mut self,
                input: &[u8; 32],
                offset: usize,
                meaningful_bytes: usize,
            ) {
                self.buffer.fill_with_bytes(input, offset, meaningful_bytes);
            }

            fn finish_round(
                &mut self,
                full_round_padding: &[u8; KECCAK_RATE_BYTES],
                is_last: bool,
                paddings_round: bool,
                padding_space: usize,
            ) {
                let mut block = self.buffer.consume::<KECCAK_RATE_BYTES>();
                if paddings_round {
                    block = *full_round_padding;
                } else if is_last {
                    if padding_space == KECCAK_RATE_BYTES - 1 {
                        block[KECCAK_RATE_BYTES - 1] = 0x81;
                    } else {
                        block[padding_space] = 0x01;
                        block[KECCAK_RATE_BYTES - 1] = 0x80;
                    }
                }

                self.state.update(&block);
            }

            fn finalize(&mut self) -> [u8; 32] {
                let state_inner = transmute_state(std::mem::take(&mut self.state));

                // Take the first four lanes and serialize them into the canonical digest bytes.
                let mut hash_as_bytes32 = [0u8; 32];
                hash_as_bytes32[0..8].copy_from_slice(&state_inner[0].to_le_bytes());
                hash_as_bytes32[8..16].copy_from_slice(&state_inner[1].to_le_bytes());
                hash_as_bytes32[16..24].copy_from_slice(&state_inner[2].to_le_bytes());
                hash_as_bytes32[24..32].copy_from_slice(&state_inner[3].to_le_bytes());
                hash_as_bytes32
            }
        }
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

        let mut round_accumulator = KeccakRoundAccumulator::new();

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

                let enough_buffer_space =
                    round_accumulator.can_fill_bytes(meaningful_bytes_in_query);
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

                round_accumulator.absorb_query_bytes(&bytes32_buffer, unalignment, bytes_to_fill);
            }

            round_accumulator.finish_round(
                &full_round_padding,
                is_last,
                paddings_round,
                padding_space,
            );

            if is_last {
                let hash_as_bytes32 = round_accumulator.finalize();

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
    use super::{transmute_state, Keccak256};
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

#[cfg(all(test, feature = "airbender-precompile-delegations"))]
mod airbender_backend_tests {
    use super::{
        keccak256_rounds_function, AirbenderKeccak256, Keccak256, KECCAK_PRECOMPILE_BUFFER_SIZE,
        KECCAK_RATE_BYTES, MEMORY_READS_PER_CYCLE,
    };
    use crate::aux::Timestamp;
    use crate::queries::{LogQuery, MemoryQuery};
    use crate::vm::Memory;
    use zkevm_opcode_defs::ethereum_types::{Address, U256};
    use zkevm_opcode_defs::PrecompileCallABI;

    #[derive(Debug, Default)]
    struct DeterministicMemory;

    impl Memory for DeterministicMemory {
        fn execute_partial_query(
            &mut self,
            _monotonic_cycle_counter: u32,
            mut query: MemoryQuery,
        ) -> MemoryQuery {
            if !query.rw_flag {
                query.value = U256::from(query.location.index.0 as u64);
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

        fn read_code_query(
            &self,
            _monotonic_cycle_counter: u32,
            _query: MemoryQuery,
        ) -> MemoryQuery {
            unreachable!("keccak precompile does not issue code queries")
        }
    }

    fn keccak256_digest_legacy(input: &[u8]) -> [u8; 32] {
        let digest = <Keccak256 as zkevm_opcode_defs::sha2::Digest>::digest(input);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest.as_slice());
        hash
    }

    fn keccak256_digest_airbender(input: &[u8]) -> [u8; 32] {
        <AirbenderKeccak256 as airbender_crypto::MiniDigest>::digest(input)
    }

    fn legacy_keccak_read_counts(input_offset: usize, input_length: usize) -> Vec<usize> {
        let mut input_byte_offset = input_offset;
        let mut bytes_left = input_length;
        let mut num_rounds = (bytes_left + (KECCAK_RATE_BYTES - 1)) / KECCAK_RATE_BYTES;
        let needs_extra_padding_round = bytes_left % KECCAK_RATE_BYTES == 0;
        if needs_extra_padding_round {
            num_rounds += 1;
        }

        let mut buffer_filled = 0usize;
        let mut reads_per_round = Vec::with_capacity(num_rounds);

        for round in 0..num_rounds {
            let is_last = round == num_rounds - 1;
            let paddings_round = needs_extra_padding_round && is_last;
            let mut reads_this_round = 0usize;

            for _ in 0..MEMORY_READS_PER_CYCLE {
                let unalignment = input_byte_offset % 32;
                let at_most_meaningful_bytes_in_query = 32 - unalignment;
                let meaningful_bytes_in_query = bytes_left.min(at_most_meaningful_bytes_in_query);
                let enough_buffer_space =
                    buffer_filled + meaningful_bytes_in_query <= KECCAK_PRECOMPILE_BUFFER_SIZE;
                let should_read =
                    meaningful_bytes_in_query != 0 && !paddings_round && enough_buffer_space;

                if should_read {
                    input_byte_offset += meaningful_bytes_in_query;
                    bytes_left -= meaningful_bytes_in_query;
                    buffer_filled += meaningful_bytes_in_query;
                    reads_this_round += 1;
                }
            }

            if buffer_filled < KECCAK_RATE_BYTES {
                buffer_filled = 0;
            } else {
                buffer_filled -= KECCAK_RATE_BYTES;
            }

            reads_per_round.push(reads_this_round);
        }

        reads_per_round
    }

    fn delegated_keccak_read_counts(input_offset: u32, input_length: u32) -> Vec<usize> {
        let abi = PrecompileCallABI {
            input_memory_offset: input_offset,
            input_memory_length: input_length,
            output_memory_offset: 0,
            output_memory_length: 1,
            memory_page_to_read: 1,
            memory_page_to_write: 2,
            precompile_interpreted_data: 0,
        };
        let query = LogQuery {
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
        };

        let mut memory = DeterministicMemory;
        let (_, witness) =
            keccak256_rounds_function::<DeterministicMemory, true>(0, query, &mut memory);
        let (_, _, round_witness) = witness.expect("keccak with B=true must produce witness");

        round_witness
            .iter()
            .map(|round| round.reads.iter().filter(|query| query.is_some()).count())
            .collect()
    }

    #[test]
    fn keccak256_differential_vectors() {
        let lengths = [
            0usize, 1, 2, 31, 32, 33, 63, 64, 65, 135, 136, 137, 271, 272, 273, 512,
        ];

        for length in lengths {
            let input: Vec<u8> = (0..length)
                .map(|idx| ((idx as u8).wrapping_mul(37)).wrapping_add(length as u8))
                .collect();
            let legacy = keccak256_digest_legacy(&input);
            let airbender = keccak256_digest_airbender(&input);
            assert_eq!(legacy, airbender);
        }
    }

    #[test]
    fn keccak256_delegated_read_schedule_matches_legacy_model() {
        let vectors = [
            (0u32, 0u32),
            (0, 329),
            (1, 1),
            (17, 135),
            (5, 136),
            (31, 137),
            (13, 272),
            (7, 512),
        ];

        for (input_offset, input_length) in vectors {
            let legacy_schedule =
                legacy_keccak_read_counts(input_offset as usize, input_length as usize);
            let delegated_schedule = delegated_keccak_read_counts(input_offset, input_length);

            assert_eq!(
                delegated_schedule, legacy_schedule,
                "delegated schedule must match legacy schedule for offset={input_offset}, length={input_length}",
            );
        }
    }
}
