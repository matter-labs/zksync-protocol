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
        use self::airbender_backend::DelegatedECAddBackend as ActiveECAddBackend;
    } else {
        use self::legacy_backend::LegacyECAddBackend as ActiveECAddBackend;
    }
}

// NOTE: We need x1, y1, x2, y2: four coordinates of two points.
pub const MEMORY_READS_PER_CYCLE: usize = 4;
// NOTE: We write the status marker plus the result coordinates.
pub const MEMORY_WRITES_PER_CYCLE: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECAddRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

// ==============================================================================
// Backend Selection
// ==============================================================================
//
// The memory interface, witness recording, and success/error encoding are identical
// between the legacy and delegated implementations. The only meaningful variation
// is how the curve addition itself is performed, so the shared executor delegates
// just that piece to a backend trait.
trait ECAddBackend {
    fn add(point_1: ECPointCoordinates, point_2: ECPointCoordinates) -> Result<ECPointCoordinates>;
}

fn execute_ecadd_precompile<M: Memory, Backend: ECAddBackend, const B: bool>(
    monotonic_cycle_counter: u32,
    query: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<ECAddRoundWitness>)>,
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

    let mut round_witness = ECAddRoundWitness {
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

    let result = Backend::add(
        (input_words[0], input_words[1]),
        (input_words[2], input_words[3]),
    );
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
pub struct ECAddPrecompile<const B: bool>;

impl<const B: bool> Precompile for ECAddPrecompile<B> {
    type CycleWitness = ECAddRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        execute_ecadd_precompile::<M, ActiveECAddBackend, B>(monotonic_cycle_counter, query, memory)
    }
}

pub fn ecadd_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<ECAddRoundWitness>)>,
) {
    execute_ecadd_precompile::<M, ActiveECAddBackend, B>(
        monotonic_cycle_counter,
        precompile_call_params,
        memory,
    )
}
