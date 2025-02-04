use super::*;
use crate::precompiles::ecmultipairing_naive::bn256::Bn256;
use anyhow::{Error, Result};
use zkevm_opcode_defs::bn254::bn256::miller_loop_with_prepared_lines;
use zkevm_opcode_defs::bn254::bn256::prepare_all_line_functions;
use zkevm_opcode_defs::bn254::bn256::prepare_g1_point;
use zkevm_opcode_defs::bn254::bn256::{Fq, Fq12, Fq2};
use zkevm_opcode_defs::bn254::ff::{Field, PrimeField};
use zkevm_opcode_defs::bn254::CurveAffine;
use zkevm_opcode_defs::bn254::*;
use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;

// we need 3 pairs of the points (G1, G2), total elements (2 + 4) * 3 = 18 total memory read
pub const MEMORY_READS_PER_CYCLE: usize = 18;
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;
const NUM_PAIRINGS_IN_MULTIPAIRING: usize = 3;

// x1, y1, x2, y2, x3, y3
type EcPairingInputTuple = [U256; 6];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EcMultiPairingNaiveRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EcMultiPairingNaivePrecompile<const B: bool>;

impl<const B: bool> Precompile for EcMultiPairingNaivePrecompile<B> {
    type CycleWitness = EcMultiPairingNaiveRoundWitness;

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
        let mut write_history = if B {
            Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
        } else {
            vec![]
        };

        let mut round_witness = EcMultiPairingNaiveRoundWitness {
            new_request: precompile_call_params,
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            writes: [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE],
        };

        let mut read_idx = 0;

        let mut check_tuples =
            Vec::<EcPairingInputTuple>::with_capacity(NUM_PAIRINGS_IN_MULTIPAIRING);

        for _ in 0..NUM_PAIRINGS_IN_MULTIPAIRING {
            let x = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let x = memory.execute_partial_query(monotonic_cycle_counter, x);
            let x_value = x.value;
            if B {
                round_witness.reads[read_idx] = x;
                read_idx += 1;
                read_history.push(x);
            }

            current_read_location.index.0 += 1;
            let y = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let y = memory.execute_partial_query(monotonic_cycle_counter, y);
            let y_value = y.value;
            if B {
                round_witness.reads[read_idx] = y;
                read_idx += 1;
                read_history.push(y);
            }

            current_read_location.index.0 += 1;
            let x_c0 = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let x_c0 = memory.execute_partial_query(monotonic_cycle_counter, x_c0);
            let x_c0_value = x_c0.value;
            if B {
                round_witness.reads[read_idx] = x_c0;
                read_idx += 1;
                read_history.push(x_c0);
            }

            current_read_location.index.0 += 1;
            let x_c1 = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let x_c1 = memory.execute_partial_query(monotonic_cycle_counter, x_c1);
            let x_c1_value = x_c1.value;
            if B {
                round_witness.reads[read_idx] = x_c1;
                read_idx += 1;
                read_history.push(x_c1);
            }

            current_read_location.index.0 += 1;
            let y_c0 = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let y_c0 = memory.execute_partial_query(monotonic_cycle_counter, y_c0);
            let y_c0_value = y_c0.value;
            if B {
                round_witness.reads[read_idx] = y_c0;
                read_idx += 1;
                read_history.push(y_c0);
            }

            current_read_location.index.0 += 1;
            let y_c1 = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let y_c1 = memory.execute_partial_query(monotonic_cycle_counter, y_c1);
            let y_c1_value = y_c1.value;
            if B {
                round_witness.reads[read_idx] = y_c1;
                read_idx += 1;
                read_history.push(y_c1);
            }
            // Setting check tuples
            check_tuples.push([
                x_value, y_value, x_c0_value, x_c1_value, y_c0_value, y_c1_value,
            ]);
        }

        let multipairing_naive_check = ecmultipairing_naive_inner(check_tuples.to_vec());

        if let Ok(is_valid) = multipairing_naive_check {
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

/// Each input is [x, y, x_c0, x_c1, y_c0, y_c1],
/// but for multi-pairing we expect exactly 3 of these (NUM_PAIRINGS_IN_MULTIPAIRING = 3).
pub fn ecmultipairing_naive_inner(inputs: Vec<[U256; 6]>) -> Result<bool> {
    if inputs.len() != 3 {
        return Err(Error::msg(
            "ecmultipairing_naive_inner expects exactly 3 sets of coordinates",
        ));
    }

    let mut prepared_g1s = Vec::with_capacity(inputs.len());
    let mut prepared_lines = Vec::with_capacity(inputs.len());

    for tuple in inputs {
        let (x1, y1, x2_c0, x2_c1, y2_c0, y2_c1) =
            (tuple[0], tuple[1], tuple[2], tuple[3], tuple[4], tuple[5]);

        let x1_f = Fq::from_str(&x1.to_string()).ok_or_else(|| Error::msg("invalid x1"))?;
        let y1_f = Fq::from_str(&y1.to_string()).ok_or_else(|| Error::msg("invalid y1"))?;
        let g1 = <bn256::G1Affine as CurveAffine>::from_xy_checked(x1_f, y1_f)?;

        let x_fq2 = Fq2 {
            c0: Fq::from_str(&x2_c0.to_string()).ok_or_else(|| Error::msg("invalid x2.c0"))?,
            c1: Fq::from_str(&x2_c1.to_string()).ok_or_else(|| Error::msg("invalid x2.c1"))?,
        };
        let y_fq2 = Fq2 {
            c0: Fq::from_str(&y2_c0.to_string()).ok_or_else(|| Error::msg("invalid y2.c0"))?,
            c1: Fq::from_str(&y2_c1.to_string()).ok_or_else(|| Error::msg("invalid y2.c1"))?,
        };
        let g2 = <bn256::G2Affine as CurveAffine>::from_xy_checked(x_fq2, y_fq2)?;

        let g1_prepared = prepare_g1_point(g1);
        let g2_lines = prepare_all_line_functions(g2);

        prepared_g1s.push(g1_prepared);
        prepared_lines.push(g2_lines);
    }
    let miller_loop_f = miller_loop_with_prepared_lines(&prepared_g1s, &prepared_lines);

    let final_exponent = Bn256::final_exponentiation(&miller_loop_f).unwrap();

    Ok(final_exponent.eq(&Fq12::one()))
}
pub fn ecmultipairing_naive_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<EcMultiPairingNaiveRoundWitness>,
    )>,
) {
    let mut processor = EcMultiPairingNaivePrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}
