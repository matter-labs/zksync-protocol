use airbender_crypto::ark_ec::AffineRepr;
use airbender_crypto::ark_ff::{BigInteger as AirBigInteger, PrimeField as AirPrimeField};
use airbender_crypto::bn254::{Fq as AirFq, Fr as AirFr, G1Affine as AirG1Affine};
use anyhow::{Error, Result};
use zkevm_opcode_defs::ethereum_types::U256;

use crate::utils::bn254::ECPointCoordinates;

pub(crate) fn airbender_field_element_to_u256<F: AirPrimeField>(value: F) -> U256 {
    let bytes = value.into_bigint().to_bytes_be();
    let mut padded = [0u8; 32];
    let write_offset = padded
        .len()
        .checked_sub(bytes.len())
        .expect("field element byte representation must not exceed 32 bytes");
    padded[write_offset..].copy_from_slice(&bytes);
    U256::from_big_endian(&padded)
}

pub(crate) fn airbender_point_to_u256_tuple(point: AirG1Affine) -> ECPointCoordinates {
    if point.is_zero() {
        return (U256::zero(), U256::zero());
    }

    let (x, y) = point
        .xy()
        .expect("non-infinity BN254 G1 point must expose coordinates");
    (
        airbender_field_element_to_u256(x),
        airbender_field_element_to_u256(y),
    )
}

fn u256_to_be_bytes(value: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    bytes
}

/// Maps a `U256` into the BN254 base field, reducing modulo the field modulus.
///
/// Constructs the element from big-endian bytes instead of
/// `AirFq::from_str(value.to_string())`. ark's decimal `from_str` also reduces
/// modulo the modulus (it never rejects a valid decimal), but routes through
/// num-bigint's radix parser, whose `f64 log2(radix)` buffer sizing links
/// soft-float intrinsics into the RISC-V proving guest.
/// `from_be_bytes_mod_order` performs the identical reduction with pure field
/// arithmetic and no floating point. Out-of-field coordinates are rejected
/// upstream by `validate_values_in_field` in the precompile backends.
pub(crate) fn airbender_fq_from_u256(value: U256) -> AirFq {
    AirFq::from_be_bytes_mod_order(&u256_to_be_bytes(value))
}

pub(crate) fn airbender_g1_from_coordinates((x, y): ECPointCoordinates) -> Result<AirG1Affine> {
    if x.is_zero() && y.is_zero() {
        return Ok(AirG1Affine::zero());
    }

    let point = AirG1Affine::new_unchecked(airbender_fq_from_u256(x), airbender_fq_from_u256(y));

    if !point.is_on_curve() {
        return Err(Error::msg("point is not on curve"));
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::msg("point is not in subgroup"));
    }

    Ok(point)
}

/// Maps a `U256` scalar into the BN254 scalar field, reducing modulo the group
/// order. Byte-based construction for the same float-free reason as
/// [`airbender_fq_from_u256`]; `from_be_bytes_mod_order` subsumes the explicit
/// reduction the string path did before parsing.
pub(crate) fn airbender_fr_from_u256(scalar: U256) -> AirFr {
    AirFr::from_be_bytes_mod_order(&u256_to_be_bytes(scalar))
}
