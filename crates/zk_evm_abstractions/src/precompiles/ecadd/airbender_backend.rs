use airbender_crypto::ark_ec::{AffineRepr, CurveGroup};
use anyhow::{Error, Result};

use crate::utils::airbender_bn254::{airbender_g1_from_coordinates, airbender_point_to_u256_tuple};
use crate::utils::bn254::{validate_values_in_field, ECPointCoordinates};

use super::ECAddBackend;

// ==============================================================================
// Delegated Backend
// ==============================================================================
//
// Delegated execution uses Airbender's BN254 implementation, but the caller still
// expects the same `(ok, x, y)` encoding and witness shape as the legacy path.
pub(super) struct DelegatedECAddBackend;

impl ECAddBackend for DelegatedECAddBackend {
    fn add(
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

        let point_1 = airbender_g1_from_coordinates((x1, y1), "invalid x", "invalid y")?;
        let point_2 = airbender_g1_from_coordinates((x2, y2), "invalid x", "invalid y")?;

        let mut sum = point_1.into_group();
        sum += point_2;

        Ok(airbender_point_to_u256_tuple(sum.into_affine()))
    }
}
