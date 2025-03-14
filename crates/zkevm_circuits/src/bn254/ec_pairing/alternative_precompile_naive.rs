use arrayvec::ArrayVec;
use std::sync::Arc;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;

use boojum::gadgets::u256::UInt256;

use super::*;

use crate::bn254::validation::validate_in_field;

use self::ec_mul::implementation::convert_uint256_to_field_element;

pub use self::alternative_pairing::NUM_PAIRINGS_IN_MULTIPAIRING;

pub const NUM_MEMORY_READS_PER_CYCLE: usize = NUM_PAIRINGS_IN_MULTIPAIRING * 6;
pub const MEMORY_QUERIES_PER_CALL: usize = NUM_PAIRINGS_IN_MULTIPAIRING * 6;
pub const COORDINATES: usize = NUM_PAIRINGS_IN_MULTIPAIRING * 6;
pub const EXCEPTION_FLAGS_ARR_LEN: usize = NUM_PAIRINGS_IN_MULTIPAIRING * 6 + 1;

#[derive(Clone, Debug)]
pub struct G1AffineCoord<F: SmallField> {
    pub x: UInt256<F>,
    pub y: UInt256<F>,
}
#[derive(Clone, Debug)]
pub struct G2AffineCoord<F: SmallField> {
    pub x_c0: UInt256<F>,
    pub x_c1: UInt256<F>,
    pub y_c0: UInt256<F>,
    pub y_c1: UInt256<F>,
}

pub fn compute_pair<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    p: G1AffineCoord<F>,
    q: G2AffineCoord<F>,
) -> (Boolean<F>, BN256Fq12NNField<F>) {
    precompile_inner(cs, &[p], &[q])
}

fn precompile_inner<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    p_points: &[G1AffineCoord<F>],
    q_points: &[G2AffineCoord<F>],
) -> (Boolean<F>, BN256Fq12NNField<F>) {
    assert_eq!(p_points.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    assert_eq!(q_points.len(), NUM_PAIRINGS_IN_MULTIPAIRING);
    let base_field_params = &Arc::new(bn254_base_field_params());

    let n = p_points.len();

    let mut coordinates: ArrayVec<UInt256<F>, COORDINATES> = ArrayVec::new();

    for i in 0..n {
        coordinates.push(p_points[i].x);
        coordinates.push(p_points[i].y);
        coordinates.push(q_points[i].x_c0);
        coordinates.push(q_points[i].x_c1);
        coordinates.push(q_points[i].y_c0);
        coordinates.push(q_points[i].y_c1);
    }
    let coordinates_are_in_field = validate_in_field(cs, &mut coordinates, base_field_params);

    let mut g1_points_in_circuit = Vec::with_capacity(n);
    let mut g2_points_in_circuit = Vec::with_capacity(n);

    for i in 0..n {
        let x = convert_uint256_to_field_element(cs, &p_points[i].x, &base_field_params);
        let y = convert_uint256_to_field_element(cs, &p_points[i].y, &base_field_params);
        use crate::bn254::ec_pairing::alternative_pairing::AffinePoint;
        let p_affine = AffinePoint::from_xy_unchecked(x, y);

        let q_x_c0_fe = convert_uint256_to_field_element(cs, &q_points[i].x_c0, &base_field_params);
        let q_x_c1_fe = convert_uint256_to_field_element(cs, &q_points[i].x_c1, &base_field_params);
        let q_y_c0_fe = convert_uint256_to_field_element(cs, &q_points[i].y_c0, &base_field_params);
        let q_y_c1_fe = convert_uint256_to_field_element(cs, &q_points[i].y_c1, &base_field_params);

        let q_x = BN256Fq2NNField::new(q_x_c0_fe, q_x_c1_fe);
        let q_y = BN256Fq2NNField::new(q_y_c0_fe, q_y_c1_fe);
        use crate::bn254::ec_pairing::alternative_pairing::TwistedCurvePoint;
        let q_affine = TwistedCurvePoint { x: q_x, y: q_y };

        g1_points_in_circuit.push(p_affine);
        g2_points_in_circuit.push(q_affine);
    }
    use crate::bn254::ec_pairing::alternative_pairing::PairingInput;
    let mut pairing_inputs: Vec<PairingInput<F>> = Vec::with_capacity(n);
    for i in 0..n {
        pairing_inputs.push((
            g1_points_in_circuit[i].clone(),
            g2_points_in_circuit[i].clone(),
        ));
    }

    use crate::bn254::ec_pairing::alternative_pairing::multipairing_naive;
    let (result, _, no_exception) = multipairing_naive(cs, &mut pairing_inputs);
    let mut are_valid_inputs = ArrayVec::<_, EXCEPTION_FLAGS_ARR_LEN>::new();
    are_valid_inputs.extend(coordinates_are_in_field);
    are_valid_inputs.push(no_exception);

    let success = Boolean::multi_and(cs, &are_valid_inputs[..]);

    (success, result)
}
