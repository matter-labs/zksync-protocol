use cfg_if::cfg_if;
use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;
use zkevm_opcode_defs::sha2::Digest;
use zkevm_opcode_defs::{ethereum_types::U256, sha3};

use super::*;

#[cfg(feature = "airbender-precompile-delegations")]
mod airbender_backend;
#[cfg(any(not(feature = "airbender-precompile-delegations"), test))]
mod legacy_backend;
#[cfg(test)]
mod tests;

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use self::airbender_backend::DelegatedECRecoverBackend as ActiveECRecoverBackend;
    } else {
        use self::legacy_backend::LegacyECRecoverBackend as ActiveECRecoverBackend;
    }
}

// We need hash, v, r, s.
pub const MEMORY_READS_PER_CYCLE: usize = 4;
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECRecoverRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

trait ECRecoverBackend {
    fn recover(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        rec_id: u8,
    ) -> Result<VerifyingKey, ()>;
}

fn execute_ecrecover_precompile<M: Memory, Backend: ECRecoverBackend, const B: bool>(
    monotonic_cycle_counter: u32,
    query: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<ECRecoverRoundWitness>,
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

    let mut round_witness = ECRecoverRoundWitness {
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
    let rec_id_bytes = u256_to_bytes32(input_words[1]);
    let r = u256_to_bytes32(input_words[2]);
    let s = u256_to_bytes32(input_words[3]);
    let rec_id = rec_id_bytes[31];
    assert!(rec_id == 0 || rec_id == 1);

    let result = Backend::recover(&digest, &r, &s, rec_id);
    let output_values = match result {
        Ok(verifying_key) => [U256::one(), verifying_key_to_address(&verifying_key)],
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

fn verifying_key_to_address(verifying_key: &VerifyingKey) -> U256 {
    let encoded = verifying_key.to_encoded_point(false);
    let encoded_ref = encoded.as_bytes();
    let address_hash = sha3::Keccak256::digest(&encoded_ref[1..]);

    let mut address = [0u8; 32];
    address[12..].copy_from_slice(&address_hash.as_slice()[12..]);
    U256::from_big_endian(&address)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECRecoverPrecompile<const B: bool>;

impl<const B: bool> Precompile for ECRecoverPrecompile<B> {
    type CycleWitness = ECRecoverRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        execute_ecrecover_precompile::<M, ActiveECRecoverBackend, B>(
            monotonic_cycle_counter,
            query,
            memory,
        )
    }
}

pub fn ecrecover_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<ECRecoverRoundWitness>,
    )>,
) {
    execute_ecrecover_precompile::<M, ActiveECRecoverBackend, B>(
        monotonic_cycle_counter,
        precompile_call_params,
        memory,
    )
}
