use cfg_if::cfg_if;
use zkevm_opcode_defs::ethereum_types::U256;

use super::*;

#[cfg(feature = "airbender-precompile-delegations")]
mod airbender_backend;
#[cfg(any(not(feature = "airbender-precompile-delegations"), test))]
mod legacy_backend;
#[cfg(test)]
mod tests;

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use self::airbender_backend::DelegatedSecp256r1Backend as ActiveSecp256r1Backend;
    } else {
        use self::legacy_backend::LegacySecp256r1Backend as ActiveSecp256r1Backend;
    }
}

// We need hash, r, s, x, y.
pub const MEMORY_READS_PER_CYCLE: usize = 5;
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Secp256r1VerifyRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

trait Secp256r1Backend {
    fn verify(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        x: &[u8; 32],
        y: &[u8; 32],
    ) -> Result<bool, ()>;
}

fn execute_secp256r1_precompile<M: Memory, Backend: Secp256r1Backend, const B: bool>(
    monotonic_cycle_counter: u32,
    query: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<Secp256r1VerifyRoundWitness>,
    )>,
) {
    const NUM_ROUNDS: usize = 1;

    let precompile_call_params = query;
    let params = precompile_abi_in_log(precompile_call_params);
    let timestamp_to_read = precompile_call_params.timestamp;
    let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1);

    let mut current_read_location = MemoryLocation {
        memory_type: MemoryType::Heap,
        page: MemoryPage(params.memory_page_to_read),
        index: MemoryIndex(params.input_memory_offset),
    };

    let mut read_history = if B {
        Vec::with_capacity(MEMORY_READS_PER_CYCLE)
    } else {
        vec![]
    };
    let mut write_history = if B {
        Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
    } else {
        vec![]
    };

    let mut round_witness = Secp256r1VerifyRoundWitness {
        new_request: precompile_call_params,
        reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
        writes: [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE],
    };

    let mut input_words = [U256::zero(); MEMORY_READS_PER_CYCLE];
    for (idx, input_word) in input_words.iter_mut().enumerate() {
        let read_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let read_query = memory.execute_partial_query(monotonic_cycle_counter, read_query);
        *input_word = read_query.value;

        if B {
            round_witness.reads[idx] = read_query;
            read_history.push(read_query);
        }

        current_read_location.index.0 += 1;
    }

    let digest = u256_to_bytes32(input_words[0]);
    let r = u256_to_bytes32(input_words[1]);
    let s = u256_to_bytes32(input_words[2]);
    let x = u256_to_bytes32(input_words[3]);
    let y = u256_to_bytes32(input_words[4]);

    let result = Backend::verify(&digest, &r, &s, &x, &y);
    let output_values = match result {
        Ok(is_valid) => [U256::one(), U256::from(is_valid as u64)],
        Err(_) => [U256::zero(), U256::zero()],
    };

    let mut write_location = MemoryLocation {
        memory_type: MemoryType::Heap,
        page: MemoryPage(params.memory_page_to_write),
        index: MemoryIndex(params.output_memory_offset),
    };

    for (idx, value) in output_values.into_iter().enumerate() {
        let write_query = MemoryQuery {
            timestamp: timestamp_to_write,
            location: write_location,
            value,
            value_is_pointer: false,
            rw_flag: true,
        };
        let write_query = memory.execute_partial_query(monotonic_cycle_counter, write_query);

        if B {
            round_witness.writes[idx] = write_query;
            write_history.push(write_query);
        }

        write_location.index.0 += 1;
    }

    let witness = if B {
        Some((read_history, write_history, vec![round_witness]))
    } else {
        None
    };

    (NUM_ROUNDS, witness)
}

fn u256_to_bytes32(value: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    bytes
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Secp256r1VerifyPrecompile<const B: bool>;

impl<const B: bool> Precompile for Secp256r1VerifyPrecompile<B> {
    type CycleWitness = Secp256r1VerifyRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        execute_secp256r1_precompile::<M, ActiveSecp256r1Backend, B>(
            monotonic_cycle_counter,
            query,
            memory,
        )
    }
}

pub fn secp256r1_verify_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<Secp256r1VerifyRoundWitness>,
    )>,
) {
    execute_secp256r1_precompile::<M, ActiveSecp256r1Backend, B>(
        monotonic_cycle_counter,
        precompile_call_params,
        memory,
    )
}
