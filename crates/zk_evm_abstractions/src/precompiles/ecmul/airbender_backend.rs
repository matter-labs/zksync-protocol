use airbender_crypto::ark_ec::{AffineRepr, CurveGroup};
use airbender_crypto::ark_ff::PrimeField as AirPrimeField;
use anyhow::{Error, Result};
use zkevm_opcode_defs::ethereum_types::U256;

use crate::utils::airbender_bn254::{
    airbender_fr_from_u256, airbender_g1_from_coordinates, airbender_point_to_u256_tuple,
};
use crate::utils::bn254::{validate_values_in_field, ECPointCoordinates};

use super::{ECMulBackend, EC_GROUP_ORDER};

// ==============================================================================
// Delegated Backend
// ==============================================================================
pub(super) struct DelegatedECMulBackend;

impl ECMulBackend for DelegatedECMulBackend {
    fn mul((x1, y1): ECPointCoordinates, scalar: U256) -> Result<ECPointCoordinates> {
        if !validate_values_in_field(&[&x1.to_string(), &y1.to_string()]) {
            return Err(Error::msg("invalid values"));
        }

        let point = airbender_g1_from_coordinates((x1, y1), "invalid x1", "invalid y1")?;
        let scalar = airbender_fr_from_u256(scalar, EC_GROUP_ORDER, "invalid scalar")?;
        let multiplied = point.mul_bigint(scalar.into_bigint()).into_affine();

        Ok(airbender_point_to_u256_tuple(multiplied))
    }
}
