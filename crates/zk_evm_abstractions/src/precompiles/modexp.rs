use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;

use super::*;

// Base, exponent and modulus
pub const MEMORY_READS_PER_CYCLE: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModexpRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub write: MemoryQuery,
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

        let mut read_history = if B {
            Vec::with_capacity(MEMORY_READS_PER_CYCLE)
        } else {
            vec![]
        };

        let mut round_witness = ModexpRoundWitness {
            new_request: precompile_call_params,
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            write: MemoryQuery::empty(),
        };

        let b_query = MemoryQuery {
            timestamp: timestamp_to_read,
            location: current_read_location,
            value: U256::zero(),
            value_is_pointer: false,
            rw_flag: false,
        };
        let b_query = memory.execute_partial_query(monotonic_cycle_counter, b_query);
        let base = b_query.value;
        if B {
            round_witness.reads[0] = b_query;
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
        let exponent = e_query.value;
        if B {
            round_witness.reads[1] = e_query;
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
        let modulus = m_query.value;
        if B {
            round_witness.reads[2] = m_query;
            read_history.push(m_query);
        }

        let result = modexp_inner(base, exponent, modulus);

        let write_location = MemoryLocation {
            memory_type: MemoryType::Heap, // we default for some value, here it's not that important
            page: MemoryPage(params.memory_page_to_write),
            index: MemoryIndex(params.output_memory_offset),
        };

        let result_query = MemoryQuery {
            timestamp: timestamp_to_write,
            location: write_location,
            value: result,
            value_is_pointer: false,
            rw_flag: true,
        };
        let result_query = memory.execute_partial_query(monotonic_cycle_counter, result_query);

        if B {
            round_witness.write = result_query;
        }

        let witness = if B {
            Some((read_history, vec![result_query], vec![round_witness]))
        } else {
            None
        };

        (NUM_ROUNDS, witness)
    }
}

/// This function evaluates the `modexp(b,e,m)`.
/// It uses the simplest square-and-multiply method that can be found here:
/// https://cse.buffalo.edu/srds2009/escs2009_submission_Gopal.pdf.
pub fn modexp_inner(b: U256, e: U256, m: U256) -> U256 {
    // See EIP-198 for specification
    // If m = 0, everything is 0.
    if m.is_zero() {
        return U256::zero();
    }
    // Some edge cases:
    // e = 0 => b^0 mod m => generally 1, but if m == 1 => 0
    if e.is_zero() {
        return if m == U256::one() {
            U256::zero()
        } else {
            U256::one()
        };
    }

    // e = 1 => b^1 mod m => just b % m
    if e == U256::one() {
        return b % m;
    }

    // b = 0 => 0^e ( for e>0 ) => 0
    if b.is_zero() {
        return U256::zero();
    }

    // b = 1 => 1^e => 1 mod m => if m == 1 => 0, else 1
    if b == U256::one() {
        return if m == U256::one() {
            U256::zero()
        } else {
            U256::one()
        };
    }

    let mut a = U256::one();
    let modmul = |x: U256, y: U256, m: U256| {
        let product = x.full_mul(y);
        let (_, rem) = product.div_mod(m.into());
        U256::try_from(rem).unwrap()
    };

    for i in (0..256).rev() {
        let bit = e.bit(i);
        a = modmul(a, a, m);
        if bit {
            a = modmul(a, b, m);
        }
    }
    a
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

        let result = modexp_inner(b, e, m);

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

        let result = modexp_inner(b, e, m);

        assert_eq!(
            result,
            U256::from_str("0x2779a7e4d2b26461c6557a12eb86285eeeb9cf5a40155305177854b15b4ed3df")
                .unwrap()
        );
    }

    #[test]
    fn test() {
        use super::*;

        let b = U256::from_str("0x05").unwrap();
        let e = U256::from_str("0x00").unwrap();
        let m = U256::from_str("0x01").unwrap();

        let result = modexp_inner(b, e, m);
    }
}
