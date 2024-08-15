use zkevm_opcode_defs::{ethereum_types::U256, p256};

use super::*;

// we need hash, r, s, x, y
pub const MEMORY_READS_PER_CYCLE: usize = 5;
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Secp256r1VerifyRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
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
        const NUM_ROUNDS: usize = 1;

        // read the parameters
        let precompile_call_params = query;
        let params = precompile_abi_in_log(precompile_call_params);
        let timestamp_to_read = precompile_call_params.timestamp;
        let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1); // our default timestamping agreement

        let mut current_read_location = MemoryLocation {
            memory_type: MemoryType::Heap, // we default for some value, here it's not that important
            page: MemoryPage(params.memory_page_to_read),
            index: MemoryIndex(params.input_memory_offset),
        };

        // we assume that we have
        // - hash of the message
        // - r
        // - s
        // - x
        // - y

        // NOTE: we assume system contract to do pre-checks, but anyway catch cases of invalid ranges or point
        // not on curve here

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

        let mut read_idx = 0;

        let hash_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let hash_query = memory.execute_partial_query(monotonic_cycle_counter, hash_query);
        let hash_value = hash_query.value;
        if B {
            round_witness.reads[read_idx] = hash_query;
            read_idx += 1;
            read_history.push(hash_query);
        }

        current_read_location.index.0 += 1;
        let r_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let r_query = memory.execute_partial_query(monotonic_cycle_counter, r_query);
        let r_value = r_query.value;
        if B {
            round_witness.reads[read_idx] = r_query;
            read_idx += 1;
            read_history.push(r_query);
        }

        current_read_location.index.0 += 1;
        let s_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let s_query = memory.execute_partial_query(monotonic_cycle_counter, s_query);
        let s_value = s_query.value;
        if B {
            round_witness.reads[read_idx] = s_query;
            read_idx += 1;
            read_history.push(s_query);
        }

        current_read_location.index.0 += 1;
        let x_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let x_query = memory.execute_partial_query(monotonic_cycle_counter, x_query);
        let x_value = x_query.value;
        if B {
            round_witness.reads[read_idx] = x_query;
            read_idx += 1;
            read_history.push(x_query);
        }

        current_read_location.index.0 += 1;
        let y_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let y_query = memory.execute_partial_query(monotonic_cycle_counter, y_query);
        let y_value = y_query.value;
        if B {
            round_witness.reads[read_idx] = y_query;
            // read_idx += 1;
            read_history.push(y_query);
        }

        // read everything as bytes for ecrecover purposes

        let mut buffer = [0u8; 32];
        hash_value.to_big_endian(&mut buffer[..]);
        let hash = buffer;

        r_value.to_big_endian(&mut buffer[..]);
        let r_bytes = buffer;

        s_value.to_big_endian(&mut buffer[..]);
        let s_bytes = buffer;

        x_value.to_big_endian(&mut buffer[..]);
        let x_bytes = buffer;

        y_value.to_big_endian(&mut buffer[..]);
        let y_bytes = buffer;

        let result = secp256r1_verify_inner(&hash, &r_bytes, &s_bytes, &x_bytes, &y_bytes);

        if let Ok(is_valid) = result {
            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            let ok_marker = U256::one();
            let ok_or_err_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: ok_marker,
                value_is_pointer: false,
                rw_flag: true,
            };
            let ok_or_err_query =
                memory.execute_partial_query(monotonic_cycle_counter, ok_or_err_query);

            write_location.index.0 += 1;
            let result = U256::from(is_valid as u64);
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: result,
                value_is_pointer: false,
                rw_flag: true,
            };
            let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = result_query;
                write_history.push(ok_or_err_query);
                write_history.push(result_query);
            }
        } else {
            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            let err_marker = U256::zero();
            let ok_or_err_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: err_marker,
                value_is_pointer: false,
                rw_flag: true,
            };
            let ok_or_err_query =
                memory.execute_partial_query(monotonic_cycle_counter, ok_or_err_query);

            write_location.index.0 += 1;
            let empty_result = U256::zero();
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: empty_result,
                value_is_pointer: false,
                rw_flag: true,
            };
            let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = result_query;
                write_history.push(ok_or_err_query);
                write_history.push(result_query);
            }
        }

        let witness = if B {
            Some((read_history, write_history, vec![round_witness]))
        } else {
            None
        };

        (NUM_ROUNDS, witness)
    }
}

pub fn secp256r1_verify_inner(
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    x: &[u8; 32],
    y: &[u8; 32],
) -> Result<bool, ()> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::generic_array::GenericArray;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint};

    // we expect pre-validation, so this check always works
    let signature = Signature::from_scalars(
        GenericArray::clone_from_slice(r),
        GenericArray::clone_from_slice(s),
    )
    .map_err(|_| ())?;

    let encoded_pk = EncodedPoint::from_affine_coordinates(
        &GenericArray::clone_from_slice(x),
        &GenericArray::clone_from_slice(y),
        false,
    );

    let may_be_pk_point = AffinePoint::from_encoded_point(&encoded_pk);
    if bool::from(may_be_pk_point.is_none()) {
        return Err(());
    }
    let pk_point = may_be_pk_point.unwrap();

    let verifier = VerifyingKey::from_affine(pk_point).map_err(|_| ())?;

    let result = verifier.verify_prehash(digest, &signature);

    Ok(result.is_ok())
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
    let mut processor = Secp256r1VerifyPrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}
