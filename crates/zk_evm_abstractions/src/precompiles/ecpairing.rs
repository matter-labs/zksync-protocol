use anyhow::{Error, Result};
use zkevm_opcode_defs::bn254::bn256::{Fq, Fq12, Fq2, G1Affine, G2Affine};
use zkevm_opcode_defs::bn254::ff::{Field, PrimeField};
use zkevm_opcode_defs::bn254::CurveAffine;
use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;

use super::*;

// NOTE: We need x1, y1, x2, y2, x3, y3:
pub const MEMORY_READS_PER_CYCLE: usize = 6;
// NOTE: We need to specify the result of the pairing and the status of the operation
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

// x1, y1, x2, y2, x3, y3
type EcPairingInputTuple = [U256; 6];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECPairingRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECPairingPrecompile<const B: bool>;

impl<const B: bool> Precompile for ECPairingPrecompile<B> {
    type CycleWitness = ECPairingRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        // EC pairing might take arbitrary number of inputs, so we just set 16 as a default
        const NUM_ROUNDS: usize = 16;

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

        // we do 8*NUM_ROUNDS queries per precompile
        let mut read_history = if B {
            Vec::with_capacity(NUM_ROUNDS * MEMORY_READS_PER_CYCLE)
        } else {
            vec![]
        };
        let mut write_history = if B {
            Vec::with_capacity(NUM_ROUNDS * MEMORY_WRITES_PER_CYCLE)
        } else {
            vec![]
        };

        let mut round_witness = ECPairingRoundWitness {
            new_request: precompile_call_params,
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            writes: [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE],
        };
        let mut read_idx = 0;

        let mut check_tuples: [EcPairingInputTuple; NUM_ROUNDS] = [[U256::zero(); 6]; NUM_ROUNDS];

        // Doing NUM_ROUNDS
        for i in 0..NUM_ROUNDS {
            // we assume that we have
            // - x1 as U256 as a first coordinate of the first point (32 bytes)
            // - y1 as U256 as a second coordinate of the first point (32 bytes)
            // - x2 as U256 as a c0 component of first coordinate of the second point (32 bytes)
            // - y2 as U256 as a c1 component of first coordinate of the second point (32 bytes)
            // - x3 as U256 as a c0 component of second coordinate of the second point (32 bytes)
            // - y3 as U256 as a c1 component of second coordinate of the second point (32 bytes)

            let x1_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let x1_query = memory.execute_partial_query(monotonic_cycle_counter, x1_query);
            let x1_value = x1_query.value;
            if B {
                round_witness.reads[read_idx] = x1_query;
                read_idx += 1;
                read_history.push(x1_query);
            }

            current_read_location.index.0 += 1;
            let y1_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let y1_query = memory.execute_partial_query(monotonic_cycle_counter, y1_query);
            let y1_value = y1_query.value;
            if B {
                round_witness.reads[read_idx] = y1_query;
                read_idx += 1;
                read_history.push(y1_query);
            }

            current_read_location.index.0 += 1;
            let x2_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let x2_query = memory.execute_partial_query(monotonic_cycle_counter, x2_query);
            let x2_value = x2_query.value;
            if B {
                round_witness.reads[read_idx] = x2_query;
                read_idx += 1;
                read_history.push(x2_query);
            }

            current_read_location.index.0 += 1;
            let y2_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let y2_query = memory.execute_partial_query(monotonic_cycle_counter, y2_query);
            let y2_value = y2_query.value;
            if B {
                round_witness.reads[read_idx] = y2_query;
                read_idx += 1;
                read_history.push(y2_query);
            }

            current_read_location.index.0 += 1;
            let x3_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let x3_query = memory.execute_partial_query(monotonic_cycle_counter, x3_query);
            let x3_value = x3_query.value;
            if B {
                round_witness.reads[read_idx] = x3_query;
                read_idx += 1;
                read_history.push(x3_query);
            }

            current_read_location.index.0 += 1;
            let y3_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let y3_query = memory.execute_partial_query(monotonic_cycle_counter, y3_query);
            let y3_value = y3_query.value;
            if B {
                round_witness.reads[read_idx] = y3_query;
                read_history.push(y3_query);
            }
            current_read_location.index.0 += 1;

            // Setting check tuples
            check_tuples[i] = [x1_value, y1_value, x2_value, y2_value, x3_value, y3_value];
        }

        // Performing ecpairing check
        let pairing_check = ecpairing_inner(check_tuples.to_vec());

        if let Ok(result) = pairing_check {
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

            // Converting result to one if true and zero otherwise
            let mut output_value = U256::zero();
            if result {
                output_value = U256::one();
            }

            write_location.index.0 += 1;
            let result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: output_value,
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

/// This function checks whether the pairing of two points on the elliptic curve
/// produces one.
///
/// If the points are not on the curve or coordinates are not valid field elements,
/// the function will return an error.
pub fn ecpairing_inner(inputs: Vec<EcPairingInputTuple>) -> Result<bool> {
    // If input is empty, return true according to EIP-197
    if inputs.len() == 0 {
        return Ok(true);
    }

    let mut total_pairing = Fq12::one();
    for input in inputs {
        // Setting variables for the coordinates of the points
        let (x1, y1, x2, y2, x3, y3) = (input[0], input[1], input[2], input[3], input[4], input[5]);

        // Converting coordinates to the finite field format
        // and validating that the conversion is successful
        let x1_field = Fq::from_str(x1.to_string().as_str()).ok_or(Error::msg("invalid x1"))?;
        let y1_field = Fq::from_str(y1.to_string().as_str()).ok_or(Error::msg("invalid y1"))?;
        let x2_field = Fq::from_str(x2.to_string().as_str()).ok_or(Error::msg("invalid x2"))?;
        let y2_field = Fq::from_str(y2.to_string().as_str()).ok_or(Error::msg("invalid y2"))?;
        let x3_field = Fq::from_str(x3.to_string().as_str()).ok_or(Error::msg("invalid x3"))?;
        let y3_field = Fq::from_str(y3.to_string().as_str()).ok_or(Error::msg("invalid y3"))?;

        // Setting both points.
        // NOTE: If one of the points is zero, then both coordinates are zero,
        // which aligns with the from_xy_checked method implementation.
        let point_1 = G1Affine::from_xy_checked(x1_field, y1_field)?;

        // NOTE: In EIP-192 spec, 3rd and 5th positions correspond to imaginary part, while 4th and 6th to real ones.
        // Thus, it might be confusing why we switch the order below.
        let point_2_x = Fq2 {
            c0: y2_field,
            c1: x2_field,
        };
        let point_2_y = Fq2 {
            c0: y3_field,
            c1: x3_field,
        };
        let point_2 = G2Affine::from_xy_checked(point_2_x, point_2_y)?;

        // Calculating the pairing operation and returning
        let pairing = point_1.pairing_with(&point_2);
        total_pairing.mul_assign(&pairing);
    }

    Ok(total_pairing.eq(&Fq12::one()))
}

pub fn ecpairing_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<ECPairingRoundWitness>,
    )>,
) {
    let mut processor = ECPairingPrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

#[cfg(test)]
pub mod tests {
    /// Tests the correctness of the `ecpairing_inner` by providing two valid points on the curve
    /// that do not produce one as an output.
    #[test]
    fn test_ecpairing_inner_correctness_false() {
        use super::*;

        let x1 = U256::from_str_radix(
            "0x412aa5b0805215b55a5e2dbf0662031aad0f5ef13f28b25df20b8670d1c59a6",
            16,
        )
        .unwrap();
        let y1 = U256::from_str_radix(
            "0x16fb4b64ccff216fa5272e1e987c0616d60d8883d5834229c685949047e9411d",
            16,
        )
        .unwrap();

        let x2 = U256::from_str_radix(
            "0x2d81dbc969f72bc0454ff8b04735b717b725fee98a2fcbcdcf6c5b51b1dff33f",
            16,
        )
        .unwrap();
        let y2 = U256::from_str_radix(
            "0x75239888fc8448ab781e2a8bb85eb556469474cd707d4b913bee28679920eb6",
            16,
        )
        .unwrap();

        let x3 = U256::from_str_radix(
            "0x1ef1c268b7c4c78959f099a043ecd5e537fe3069ac9197235f16162372848cba",
            16,
        )
        .unwrap();
        let y3 = U256::from_str_radix(
            "0x209cfadc22f7e80d399d1886f1c53898521a34c62918ed802305f32b4070a3c4",
            16,
        )
        .unwrap();

        let result = ecpairing_inner(vec![[x1, y1, x2, y2, x3, y3]]).unwrap();
        assert_eq!(result, false);
    }

    /// Tests the correctness of the `ecpairing_inner` by providing four valid points on the curve
    /// that do not produce one as an output. Example is taken from https://www.evm.codes/precompiled#0x08
    #[test]
    fn test_ecpairing_inner_correctness_true() {
        use super::*;

        let x1_1 = U256::from_str_radix(
            "0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da",
            16,
        )
        .unwrap();
        let y1_1 = U256::from_str_radix(
            "0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6",
            16,
        )
        .unwrap();

        let x2_1 = U256::from_str_radix(
            "0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc",
            16,
        )
        .unwrap();
        let y2_1 = U256::from_str_radix(
            "0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9",
            16,
        )
        .unwrap();

        let x3_1 = U256::from_str_radix(
            "0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90",
            16,
        )
        .unwrap();
        let y3_1 = U256::from_str_radix(
            "0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e",
            16,
        )
        .unwrap();

        let x1_2 = U256::from_str_radix(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            16,
        )
        .unwrap();
        let y1_2 = U256::from_str_radix(
            "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
            16,
        )
        .unwrap();

        let x2_2 = U256::from_str_radix(
            "0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4",
            16,
        )
        .unwrap();
        let y2_2 = U256::from_str_radix(
            "0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7",
            16,
        )
        .unwrap();

        let x3_2 = U256::from_str_radix(
            "0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2",
            16,
        )
        .unwrap();
        let y3_2 = U256::from_str_radix(
            "0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc",
            16,
        )
        .unwrap();

        let result = ecpairing_inner(vec![
            [x1_1, y1_1, x2_1, y2_1, x3_1, y3_1],
            [x1_2, y1_2, x2_2, y2_2, x3_2, y3_2],
        ])
        .unwrap();

        println!(
            "{:?}",
            vec![
                [x1_1, y1_1, x2_1, y2_1, x3_1, y3_1],
                [x1_2, y1_2, x2_2, y2_2, x3_2, y3_2],
            ]
        );

        assert_eq!(result, true);
    }

    /// Tests the correctness of the `ecpairing_inner` by providing four valid points on the curve
    /// and the rest are empty points. Example is taken from https://www.evm.codes/precompiled#0x08.
    #[test]
    fn test_ecpairing_inner_correctness_zero_inputs() {
        use super::*;

        let x1_1 = U256::from_str_radix(
            "0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da",
            16,
        )
        .unwrap();
        let y1_1 = U256::from_str_radix(
            "0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6",
            16,
        )
        .unwrap();

        let x2_1 = U256::from_str_radix(
            "0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc",
            16,
        )
        .unwrap();
        let y2_1 = U256::from_str_radix(
            "0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9",
            16,
        )
        .unwrap();

        let x3_1 = U256::from_str_radix(
            "0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90",
            16,
        )
        .unwrap();
        let y3_1 = U256::from_str_radix(
            "0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e",
            16,
        )
        .unwrap();

        let x1_2 = U256::from_str_radix(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            16,
        )
        .unwrap();
        let y1_2 = U256::from_str_radix(
            "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
            16,
        )
        .unwrap();

        let x2_2 = U256::from_str_radix(
            "0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4",
            16,
        )
        .unwrap();
        let y2_2 = U256::from_str_radix(
            "0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7",
            16,
        )
        .unwrap();

        let x3_2 = U256::from_str_radix(
            "0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2",
            16,
        )
        .unwrap();
        let y3_2 = U256::from_str_radix(
            "0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc",
            16,
        )
        .unwrap();

        let empty_input = [U256::zero(); 6];

        let result = ecpairing_inner(vec![
            [x1_1, y1_1, x2_1, y2_1, x3_1, y3_1],
            [x1_2, y1_2, x2_2, y2_2, x3_2, y3_2],
            empty_input,
            empty_input,
            empty_input,
            empty_input,
        ])
        .unwrap();

        assert_eq!(result, true);
    }

    /// Tests that the function does not allow to input a wrong first point.
    #[test]
    #[should_panic]
    fn test_ecpairing_invalid_point_1() {
        use super::*;

        // (x1, y1) does not lie on the curve
        let x1 = U256::from_str_radix("5", 10).unwrap();
        let y1 = U256::from_str_radix("10", 10).unwrap();

        let x2 = U256::from_str_radix(
            "0x16342ef5343ae56e96dafd3fc43aaf6a715642f376327cf2bdb813cf41a0b55b",
            16,
        )
        .unwrap();
        let y2 = U256::from_str_radix(
            "0x237e8c97323c9032ce9e05af4b1597881131d137b5313182c9ef1b2576c9f3f1",
            16,
        )
        .unwrap();

        let x3 = U256::from_str_radix(
            "0x9c316c01492b5d4e2521d897b66de1e47438adf83a320054f8fc763935dc754",
            16,
        )
        .unwrap();
        let y3 = U256::from_str_radix(
            "0xe1bf45145e9ee5372a81f2ad50b81830e3bb26400a5a72999fac2f73d768089",
            16,
        )
        .unwrap();

        let _ = ecpairing_inner(vec![[x1, y1, x2, y2, x3, y3]]).unwrap();
    }

    /// Tests that the function does not allow to input a wrong second point.
    #[test]
    #[should_panic]
    fn test_ecpairing_invalid_point_2() {
        use super::*;

        let x1 = U256::from_str_radix(
            "0x412aa5b0805215b55a5e2dbf0662031aad0f5ef13f28b25df20b8670d1c59a6",
            16,
        )
        .unwrap();
        let y1 = U256::from_str_radix(
            "0x16fb4b64ccff216fa5272e1e987c0616d60d8883d5834229c685949047e9411d",
            16,
        )
        .unwrap();

        // ((x2,y2), (x3,y3)) does not lie on the curve
        let x2 = U256::from_str_radix("0", 10).unwrap();
        let y2 = U256::from_str_radix("1", 10).unwrap();

        let x3 = U256::from_str_radix("2", 10).unwrap();
        let y3 = U256::from_str_radix("3", 10).unwrap();

        let _ = ecpairing_inner(vec![[x1, y1, x2, y2, x3, y3]]).unwrap();
    }
}