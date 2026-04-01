use std::str::FromStr;

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

pub(crate) fn airbender_fq_from_u256(value: U256, err: &'static str) -> Result<AirFq> {
    AirFq::from_str(value.to_string().as_str()).map_err(|_| Error::msg(err))
}

pub(crate) fn airbender_g1_from_coordinates(
    (x, y): ECPointCoordinates,
    invalid_x_err: &'static str,
    invalid_y_err: &'static str,
) -> Result<AirG1Affine> {
    if x.is_zero() && y.is_zero() {
        return Ok(AirG1Affine::zero());
    }

    let x = airbender_fq_from_u256(x, invalid_x_err)?;
    let y = airbender_fq_from_u256(y, invalid_y_err)?;
    let point = AirG1Affine::new_unchecked(x, y);

    if !point.is_on_curve() {
        return Err(Error::msg("point is not on curve"));
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::msg("point is not in subgroup"));
    }

    Ok(point)
}

pub(crate) fn airbender_fr_from_u256(
    mut scalar: U256,
    group_order_hex: &str,
    invalid_scalar_err: &'static str,
) -> Result<AirFr> {
    let group_order = U256::from_str(group_order_hex).expect("group order constant must parse");
    while scalar >= group_order {
        scalar -= group_order;
    }

    AirFr::from_str(scalar.to_string().as_str()).map_err(|_| Error::msg(invalid_scalar_err))
}
