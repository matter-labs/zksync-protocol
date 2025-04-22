//! Helper functions and types for working with elliptic curves.

use std::str::FromStr;

use zkevm_opcode_defs::{
    bn254::{bn256::G1Affine, ff::PrimeField, CurveAffine},
    ethereum_types::U256,
};

const P: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";

pub type ECPointCoordinates = (U256, U256);

/// This function converts a [`G1Affine`] point into a tuple of two [`U256`].
///
/// If the point is zero, the function will return `(0,0)` compared to the
/// `from_xy_checked` method implementation which returns `(0,1)`.
pub fn point_to_u256_tuple(point: G1Affine) -> ECPointCoordinates {
    if point.is_zero() {
        return (U256::zero(), U256::zero());
    }

    let (x, y) = point.into_xy_unchecked();
    let x = U256::from_str(format!("{}", x.into_repr()).as_str()).unwrap();
    let y = U256::from_str(format!("{}", y.into_repr()).as_str()).unwrap();
    (x, y)
}

/// Validate that all the values are less than the modulus.
pub fn validate_values_in_field(values: &[&str]) -> bool {
    for value in values {
        let value = U256::from_str_radix(value, 10).unwrap();
        if value >= U256::from_str_radix(P, 10).unwrap() {
            return false;
        }
    }
    true
}

#[cfg(test)]
pub mod test {
    /// Verifies that the `point_to_u256_tuple` function returns the correct
    /// values for a point at infinity, that is (0, 0) according to
    /// evm codes spec.
    #[test]
    fn point_at_infinity_to_u256_tuple() {
        use super::*;
        let point = G1Affine::zero();
        let (x, y) = point_to_u256_tuple(point);
        assert_eq!(x, U256::zero());
        assert_eq!(y, U256::zero());
    }

    #[test]
    fn regular_point_to_u256_tuple() {
        use super::*;
        let point = G1Affine::one();
        let (x, y) = point_to_u256_tuple(point);
        assert_eq!(x, U256::from_str("1").unwrap());
        assert_eq!(y, U256::from_str("2").unwrap());
    }
}
