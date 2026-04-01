use airbender_crypto::ark_ec::pairing::Pairing as AirPairing;
use airbender_crypto::ark_ec::AffineRepr as AirAffineRepr;
use airbender_crypto::ark_ff::{One as AirOne, Zero as AirZero};
use airbender_crypto::bn254::{
    curves::Bn254 as AirBn254, Fq12 as AirFq12, Fq2 as AirFq2, G1Affine as AirG1Affine,
    G2Affine as AirG2Affine,
};
use anyhow::{Error, Result};

use crate::utils::airbender_bn254::airbender_fq_from_u256;
use crate::utils::bn254::validate_values_in_field;

use super::{ECPairingBackend, EcPairingInputTuple};

// ==============================================================================
// Delegated Backend
// ==============================================================================
pub(super) struct DelegatedECPairingBackend;

impl ECPairingBackend for DelegatedECPairingBackend {
    fn pairing(inputs: Vec<EcPairingInputTuple>) -> Result<bool> {
        if inputs.is_empty() {
            return Ok(true);
        }

        let mut total_pairing = AirFq12::one();
        for input in inputs {
            let pairing = pair_airbender(&input)?;
            total_pairing *= &pairing;
        }

        Ok(total_pairing.eq(&AirFq12::one()))
    }
}

fn pair_airbender(input: &EcPairingInputTuple) -> Result<AirFq12> {
    let (x1, y1, x2, y2, x3, y3) = (input[0], input[1], input[2], input[3], input[4], input[5]);

    if !validate_values_in_field(&[
        &x1.to_string(),
        &y1.to_string(),
        &x2.to_string(),
        &y2.to_string(),
        &x3.to_string(),
        &y3.to_string(),
    ]) {
        return Err(Error::msg("invalid values"));
    }

    let x1_field = airbender_fq_from_u256(x1, "invalid x1")?;
    let y1_field = airbender_fq_from_u256(y1, "invalid y1")?;
    let x2_field = airbender_fq_from_u256(x2, "invalid x2")?;
    let y2_field = airbender_fq_from_u256(y2, "invalid y2")?;
    let x3_field = airbender_fq_from_u256(x3, "invalid x3")?;
    let y3_field = airbender_fq_from_u256(y3, "invalid y3")?;

    let point_1 = if x1.is_zero() && y1.is_zero() {
        AirG1Affine::zero()
    } else {
        let point = AirG1Affine::new_unchecked(x1_field, y1_field);
        if !point.is_on_curve() {
            return Err(Error::msg("G1 point is not on curve"));
        }
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(Error::msg("G1 point is not in subgroup"));
        }
        point
    };

    // NOTE: In EIP-197, the tuple stores the imaginary component before the real one.
    let point_2_x = AirFq2::new(y2_field, x2_field);
    let point_2_y = AirFq2::new(y3_field, x3_field);

    let point_2 = if point_2_x.is_zero() && point_2_y.is_zero() {
        AirG2Affine::zero()
    } else {
        let point = AirG2Affine::new_unchecked(point_2_x, point_2_y);
        if !point.is_on_curve() {
            return Err(Error::msg("G2 point is not on curve"));
        }
        if !point.is_in_correct_subgroup_assuming_on_curve() {
            anyhow::bail!("G2 not on the subgroup");
        }
        point
    };

    Ok(<AirBn254 as AirPairing>::pairing(point_1, point_2).0)
}
