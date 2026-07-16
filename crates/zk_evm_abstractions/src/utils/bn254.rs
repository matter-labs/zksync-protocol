//! Helper functions and types for working with elliptic curves.

use std::str::FromStr;

use zkevm_opcode_defs::{
    bn254::{bn256::G1Affine, ff::PrimeField, CurveAffine},
    ethereum_types::U256,
};

/// BN254 base field modulus `P`, as little-endian `u64` limbs. Equality with the
/// decimal modulus is asserted in `test::field_modulus_matches_decimal`.
const FIELD_MODULUS: U256 = U256([
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

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

/// Validate that all the values are less than the base field modulus.
///
/// Takes `U256`s and compares them directly against [`FIELD_MODULUS`]. The
/// previous signature took decimal `&str`s and callers passed `u256.to_string()`,
/// so every coordinate incurred a `U256` -> decimal-string -> `U256` round-trip
/// (~10M guest cycles per call, dominating the precompile) — cheap per erg for
/// an attacker and a prover-DoS vector. Direct `U256` comparison is a handful of
/// cycles and involves no string formatting or parsing.
pub fn validate_values_in_field(values: &[U256]) -> bool {
    values.iter().all(|value| *value < FIELD_MODULUS)
}

#[cfg(test)]
pub mod test {
    /// BN254 base field modulus `P` in decimal, used to check [`super::FIELD_MODULUS`].
    const P: &str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";

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

    #[test]
    fn field_modulus_matches_decimal() {
        use super::*;
        assert_eq!(FIELD_MODULUS, U256::from_str_radix(P, 10).unwrap());
    }

    #[test]
    fn validate_values_in_field_boundary() {
        use super::*;
        let modulus = U256::from_str_radix(P, 10).unwrap();
        assert!(validate_values_in_field(&[U256::zero(), modulus - 1]));
        assert!(!validate_values_in_field(&[modulus]));
        assert!(!validate_values_in_field(&[U256::MAX]));
        assert!(!validate_values_in_field(&[U256::one(), modulus]));
    }
}
