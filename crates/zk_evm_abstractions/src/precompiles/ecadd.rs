use anyhow::{Error, Result};
use zkevm_opcode_defs::bn254::bn256::{Fq, G1Affine};
use zkevm_opcode_defs::bn254::ff::PrimeField;
use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};
use zkevm_opcode_defs::ethereum_types::U256;
pub use zkevm_opcode_defs::sha2::Digest;

use crate::utils::bn254::{point_to_u256_tuple, validate_values_in_field, ECPointCoordinates};

use super::*;

// NOTE: We need x1, y1, x2, y2: four coordinates of two points
pub const MEMORY_READS_PER_CYCLE: usize = 4;
// NOTE: We need to specify the result of the addition and the status of the operation
pub const MEMORY_WRITES_PER_CYCLE: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECAddRoundWitness {
    pub new_request: LogQuery,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: [MemoryQuery; MEMORY_WRITES_PER_CYCLE],
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
        // - x1 as U256 as a first coordinate of the first point (32 bytes)
        // - y1 as U256 as a second coordinate of the first point (32 bytes)
        // - x2 as U256 as a first coordinate of the second point (32 bytes)
        // - y2 as U256 as a second coordinate of the second point (32 bytes)

        // we do 7 queries per precompile
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

        let mut read_idx = 0;

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
            read_history.push(y2_query);
        }

        // Performing addition
        let points_sum = ecadd_inner((x1_value, y1_value), (x2_value, y2_value));

        if let Ok((x, y)) = points_sum {
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

            // Writing resultant x coordinate
            write_location.index.0 += 1;

            let x_result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: x,
                value_is_pointer: false,
                rw_flag: true,
            };
            let x_result_query =
                memory.execute_partial_query(monotonic_cycle_counter, x_result_query);

            // Writing resultant y coordinate
            write_location.index.0 += 1;

            let y_result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: y,
                value_is_pointer: false,
                rw_flag: true,
            };
            let y_result_query =
                memory.execute_partial_query(monotonic_cycle_counter, y_result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = x_result_query;
                round_witness.writes[2] = y_result_query;
                write_history.push(ok_or_err_query);
                write_history.push(x_result_query);
                write_history.push(y_result_query);
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
            let x_result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: empty_result,
                value_is_pointer: false,
                rw_flag: true,
            };
            let x_result_query =
                memory.execute_partial_query(monotonic_cycle_counter, x_result_query);

            write_location.index.0 += 1;

            let y_result_query = MemoryQuery {
                timestamp: timestamp_to_write,
                location: write_location,
                value: empty_result,
                value_is_pointer: false,
                rw_flag: true,
            };
            let y_result_query =
                memory.execute_partial_query(monotonic_cycle_counter, y_result_query);

            if B {
                round_witness.writes[0] = ok_or_err_query;
                round_witness.writes[1] = x_result_query;
                round_witness.writes[2] = y_result_query;
                write_history.push(ok_or_err_query);
                write_history.push(x_result_query);
                write_history.push(y_result_query);
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

/// This function adds two points (x1,y1) and (x2,y2) on the BN254 curve.
/// It returns the result as a G1Affine point.
///
/// If the points are not on the curve or coordinates are not valid field elements,
/// the function will return an error.
pub fn ecadd_inner(
    (x1, y1): ECPointCoordinates,
    (x2, y2): ECPointCoordinates,
) -> Result<ECPointCoordinates> {
    if !validate_values_in_field(&[
        &x1.to_string(),
        &y1.to_string(),
        &x2.to_string(),
        &y2.to_string(),
    ]) {
        return Err(Error::msg("invalid values"));
    }

    // Converting coordinates to the finite field format
    // and validating that the conversion is successful
    let x1_field = Fq::from_str(x1.to_string().as_str()).ok_or(Error::msg("invalid x1"))?;
    let y1_field = Fq::from_str(y1.to_string().as_str()).ok_or(Error::msg("invalid y1"))?;
    let x2_field = Fq::from_str(x2.to_string().as_str()).ok_or(Error::msg("invalid x2"))?;
    let y2_field = Fq::from_str(y2.to_string().as_str()).ok_or(Error::msg("invalid y2"))?;

    dbg!(&x1_field);
    dbg!(&y1_field);
    dbg!(&x2_field);
    dbg!(&y2_field);

    // If one of the points is zero, then both coordinates are zero,
    // which aligns with the from_xy_checked method implementation.
    // However, if some point does not lie on the curve, the method will return an error.
    let point_1 = G1Affine::from_xy_checked(x1_field, y1_field)?;
    let point_2 = G1Affine::from_xy_checked(x2_field, y2_field)?;

    let mut point_1_projective = point_1.into_projective();
    point_1_projective.add_assign_mixed(&point_2);

    let point_1 = point_1_projective.into_affine();
    let coordinates = point_to_u256_tuple(point_1);
    Ok(coordinates)
}

pub fn ecadd_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<ECAddRoundWitness>)>,
) {
    let mut processor = ECAddPrecompile::<B>;
    processor.execute_precompile(monotonic_cycle_counter, precompile_call_params, memory)
}

#[cfg(test)]
pub mod tests {
    /// Tests the correctness of the `ecadd_inner` function for a specified point
    /// inside the test.
    #[test]
    fn test_ecadd_inner_correctness() {
        use super::*;

        // Got:
        let x1 = U256::from_str_radix(
            "0x1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad",
            16,
        )
        .unwrap();
        let y1 = U256::from_str_radix(
            "0xbac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d",
            16,
        )
        .unwrap();
        let x2 = U256::from_str_radix(
            "0x251edb9081aba0cb29a45e4565ab2a2136750be5c893000e35e031ee123889e8",
            16,
        )
        .unwrap();
        let y2 = U256::from_str_radix(
            "0x24a972b009ad5986a7e14781d4e0c2d11aff281004712470811ec9b4fcb7c569",
            16,
        )
        .unwrap();
        let (x, y) = ecadd_inner((x1, y1), (x2, y2)).unwrap();

        // Expected:
        let expected_x = U256::from_str_radix(
            "16722044054529980026630802318818607593549086552476606668453035265973506741708",
            10,
        )
        .unwrap();
        let expected_y = U256::from_str_radix(
            "5777135421494458653665242593020841953920930780504228016288089286576416057645",
            10,
        )
        .unwrap();

        // Validation:
        assert_eq!(x, expected_x, "x coordinates are not equal");
        assert_eq!(y, expected_y, "y coordinates are not equal");
    }

    /// Tests the correctness of the `ecadd_inner` function when given
    /// two opposite points.
    #[test]
    fn test_ecadd_inner_point_at_infinity_1() {
        use super::*;

        // Got:
        let x1 = U256::from_str_radix(
            "0x1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad",
            16,
        )
        .unwrap();
        let y1 = U256::from_str_radix(
            "0xbac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d",
            16,
        )
        .unwrap();
        let x2 = x1.clone();
        // y2 = -y1 in Fr
        let y2 = U256::from_str_radix(
            "0x24b83e5b5404c77f1d054cb33b65b94730bf50c369bf0f2f2f48beb251d9d2da",
            16,
        )
        .unwrap();
        let (x, y) = ecadd_inner((x1, y1), (x2, y2)).unwrap();

        // Expected:
        let expected_x = U256::zero();
        let expected_y = U256::zero();

        // Validation:
        assert_eq!(x, expected_x, "x coordinates are not equal");
        assert_eq!(y, expected_y, "y coordinates are not equal");
    }

    /// Tests the correctness of the `ecadd_inner` function when given
    /// two points at infinity
    #[test]
    fn test_ecadd_inner_point_at_infinity_2() {
        use super::*;

        // Got:
        let zero = U256::zero();
        let (x, y) = ecadd_inner((zero, zero), (zero, zero)).unwrap();

        // Expected:
        let expected_x = U256::zero();
        let expected_y = U256::zero();

        // Validation:
        assert_eq!(x, expected_x, "x coordinates are not equal");
        assert_eq!(y, expected_y, "y coordinates are not equal");
    }

    /// Tests the correctness of the `ecadd_inner` function for a specified point
    /// taken from https://www.evm.codes/precompiled#0x06
    #[test]
    fn test_ecadd_inner_correctness_evm_codes() {
        use super::*;

        // Got:
        let x1 = U256::from_str_radix("1", 10).unwrap();
        let y1 = U256::from_str_radix("2", 10).unwrap();
        let x2 = U256::from_str_radix("1", 10).unwrap();
        let y2 = U256::from_str_radix("2", 10).unwrap();
        let (x, y) = ecadd_inner((x1, y1), (x2, y2)).unwrap();

        // Expected:
        let expected_x = U256::from_str_radix(
            "1368015179489954701390400359078579693043519447331113978918064868415326638035",
            10,
        )
        .unwrap();
        let expected_y = U256::from_str_radix(
            "9918110051302171585080402603319702774565515993150576347155970296011118125764",
            10,
        )
        .unwrap();

        // Validation:
        assert_eq!(x, expected_x, "x coordinates are not equal");
        assert_eq!(y, expected_y, "y coordinates are not equal");
    }

    /// Tests that the function does not allow point (x1, y1) that does not lie on the curve.
    #[test]
    #[should_panic]
    fn test_ecadd_inner_invalid_x1y1() {
        use super::*;

        // (x1, y1) does not lie on the curve
        let x1 = U256::from_str_radix("1", 10).unwrap();
        let y1 = U256::from_str_radix("3", 10).unwrap();
        let x2 = U256::from_str_radix(
            "0x251edb9081aba0cb29a45e4565ab2a2136750be5c893000e35e031ee123889e8",
            16,
        )
        .unwrap();
        let y2 = U256::from_str_radix(
            "0x24a972b009ad5986a7e14781d4e0c2d11aff281004712470811ec9b4fcb7c569",
            16,
        )
        .unwrap();

        // This should panic:
        let _ = ecadd_inner((x1, y1), (x2, y2)).unwrap();
    }

    /// Tests that the function does not allow point (x2, y2) that does not lie on the curve.
    #[test]
    #[should_panic]
    fn test_ecadd_inner_invalid_x2y2() {
        use super::*;

        let x1 = U256::from_str_radix(
            "0x1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad",
            10,
        )
        .unwrap();
        let y1 = U256::from_str_radix(
            "0xbac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d",
            10,
        )
        .unwrap();

        // (x2, y2) does not lie on the curve
        let x2 = U256::from_str_radix("1", 16).unwrap();
        let y2 = U256::from_str_radix("10", 16).unwrap();

        // This should panic:
        let _ = ecadd_inner((x1, y1), (x2, y2)).unwrap();
    }
}
