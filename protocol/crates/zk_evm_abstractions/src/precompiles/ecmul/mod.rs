use anyhow::Result;
use cfg_if::cfg_if;
use zkevm_opcode_defs::ethereum_types::U256;

use crate::utils::bn254::ECPointCoordinates;

use super::*;

#[cfg(feature = "airbender-precompile-delegations")]
mod airbender_backend;
#[cfg(any(not(feature = "airbender-precompile-delegations"), test))]
mod legacy_backend;
#[cfg(test)]
mod tests;

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use self::airbender_backend::DelegatedECMulBackend as ActiveECMulBackend;
    } else {
        use self::legacy_backend::LegacyECMulBackend as ActiveECMulBackend;
    }
}

// NOTE: We need x1, y1, and s: two coordinates of the point and the scalar.
pub const MEMORY_READS_PER_CYCLE: usize = 3;
// NOTE: We write the status marker plus the result coordinates.
pub const MEMORY_WRITES_PER_CYCLE: usize = 3;

/// The order of the group of points on the BN254 curve.
pub const EC_GROUP_ORDER: &str =
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECMulRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

trait ECMulBackend {
    fn mul(point: ECPointCoordinates, scalar: U256) -> Result<ECPointCoordinates>;
}

fn execute_ecmul_precompile<M: Memory, Backend: ECMulBackend, const B: bool>(
    monotonic_cycle_counter: u32,
    query: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<ECMulRoundWitness>)>,
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

    let mut round_witness = ECMulRoundWitness {
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

    let result = Backend::mul((input_words[0], input_words[1]), input_words[2]);
    let output_values = match result {
        Ok((x, y)) => [U256::one(), x, y],
        Err(_) => [U256::zero(), U256::zero(), U256::zero()],
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECMulPrecompile<const B: bool>;

impl<const B: bool> Precompile for ECMulPrecompile<B> {
    type CycleWitness = ECMulRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        execute_ecmul_precompile::<M, ActiveECMulBackend, B>(monotonic_cycle_counter, query, memory)
    }
}

pub fn ecmul_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<ECMulRoundWitness>)>,
) {
    execute_ecmul_precompile::<M, ActiveECMulBackend, B>(
        monotonic_cycle_counter,
        precompile_call_params,
        memory,
    )
}
