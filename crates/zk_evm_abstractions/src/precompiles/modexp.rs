use anyhow::Result;
use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;

use super::*;

// NOTE: We need exponent, base, and modulus, and their respective sizes
pub const MEMORY_READS_PER_CYCLE: usize = 6;
// NOTE: We need to specify the result of the exponentiation and the status of the operation
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModexpRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModexpPrecompile<const B: bool>;

impl<const B: bool> Precompile for ModexpPrecompile<B> {
    type CycleWitness = ModexpRoundWitness;

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
        // - BSize - size of the base number
        // - ESize - size of the exponent
        // - MSize - size of the modulus
        // - B - base number
        // - E - exponent
        // - M - modulus

        // we do 8 queries per precompile
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

        let mut round_witness = ModexpRoundWitness {
            new_request: precompile_call_params,
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            writes: [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE],
        };

        let mut read_idx = 0;

        let b_size_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let b_size_query = memory.execute_partial_query(monotonic_cycle_counter, b_size_query);
        let b_size_value = b_size_query.value;
        if B {
            round_witness.reads[read_idx] = b_size_query;
            read_idx += 1;
            read_history.push(b_size_query);
        }

        current_read_location.index.0 += 1;
        let e_size_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let e_size_query = memory.execute_partial_query(monotonic_cycle_counter, e_size_query);
        let e_size_value = e_size_query.value;
        if B {
            round_witness.reads[read_idx] = e_size_query;
            read_idx += 1;
            read_history.push(e_size_query);
        }

        current_read_location.index.0 += 1;
        let m_size_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let m_size_query = memory.execute_partial_query(monotonic_cycle_counter, m_size_query);
        let m_size_value = m_size_query.value;
        if B {
            round_witness.reads[read_idx] = m_size_query;
            read_idx += 1;
            read_history.push(m_size_query);
        }

        current_read_location.index.0 += 1;
        let b_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let b_query = memory.execute_partial_query(monotonic_cycle_counter, b_query);
        let b_value = b_query.value;
        if B {
            round_witness.reads[read_idx] = b_query;
            read_idx += 1;
            read_history.push(b_query);
        }

        current_read_location.index.0 += 1;
        let e_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let e_query = memory.execute_partial_query(monotonic_cycle_counter, e_query);
        let e_value = e_query.value;
        if B {
            round_witness.reads[read_idx] = e_query;
            read_idx += 1;
            read_history.push(e_query);
        }

        current_read_location.index.0 += 1;
        let m_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let m_query = memory.execute_partial_query(monotonic_cycle_counter, m_query);
        let m_value = m_query.value;
        if B {
            round_witness.reads[read_idx] = m_query;
            read_history.push(m_query);
        }

        // Perfmoring modular exponentiation
        let modexp = modexp_inner(
            b_size_value,
            e_size_value,
            m_size_value,
            b_value,
            e_value,
            m_value,
        );

        if let Ok(modexp) = modexp {
            let mut write_location = MemoryLocation {
                memory_type: MemoryType::Heap, // we default for some value, here it's not that important
                page: MemoryPage(params.memory_page_to_write),
                index: MemoryIndex(params.output_memory_offset),
            };

            // Marking that the operation was successful
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

            // Writing resultant modexp result
            write_location.index.0 += 1;

            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: modexp,
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

/// This function evaluates the `modexp(b,e,m)`. For now, b_size, e_size, and m_size are not used.
/// It uses the simplest square-and-multiply method that can be found here:
/// https://cse.buffalo.edu/srds2009/escs2009_submission_Gopal.pdf.
pub fn modexp_inner(
    _b_size: U256,
    _e_size: U256,
    _m_size: U256,
    b: U256,
    e: U256,
    m: U256,
) -> Result<U256> {
    let mut a = U256::one();

    let modmul = |a: U256, b: U256, m: U256| {
        // Computing a*b mod m
        let product: zkevm_opcode_defs::ethereum_types::U512 = a.full_mul(b);
        let (_, result) = product.div_mod(m.into());

        // Converting result in U512 to U256 format
        // TODO: Wrap an error
        let result: U256 = result.try_into().expect("U512 to U256 conversion failed");
        anyhow::Ok(result)
    };

    for i in (0..e.bits()).rev() {
        let bit = e.bit(i);

        a = modmul(a, a, m)?;
        if bit {
            a = modmul(a, b, m)?;
        }
    }

    Ok(a)
}

pub fn modexp_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<ModexpRoundWitness>)>,
) {
    let mut processor = ModexpPrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    /// Tests the correctness of the `modexp_inner` function for a specified
    /// set of inputs from https://www.evm.codes/precompiled#0x05.
    #[test]
    fn test_modexp_inner_correctness_evm_codes() {
        use super::*;

        let b = U256::from_str("0x8").unwrap();
        let e = U256::from_str("0x9").unwrap();
        let m = U256::from_str("0xa").unwrap();

        let result = modexp_inner(U256::zero(), U256::zero(), U256::zero(), b, e, m).unwrap();

        assert_eq!(result, U256::from_str("0x8").unwrap());
    }

    /// Tests the correctness of the `modexp_inner` function for randomly
    /// generated U256 integers.
    #[test]
    fn test_modexp_inner_correctness_big_ints() {
        use super::*;

        let b =
            U256::from_str("0x7f333213268023a7d3d40ea760d0e1c00d5fe99710e379193fc5973e7ad09370")
                .unwrap();
        let e = U256::from_str("0x39d71831130091794534336679323390f4408be38cb89963ec41f4a90d6bf63")
            .unwrap();
        let m =
            U256::from_str("0xec6f05ec20e4c25420f9d6bc6800f9544ecabf5dbea80d11e0fb12c7f0517f5b")
                .unwrap();

        let result = modexp_inner(U256::zero(), U256::zero(), U256::zero(), b, e, m).unwrap();

        assert_eq!(
            result,
            U256::from_str("0x2779a7e4d2b26461c6557a12eb86285eeeb9cf5a40155305177854b15b4ed3df")
                .unwrap()
        );
    }
}
