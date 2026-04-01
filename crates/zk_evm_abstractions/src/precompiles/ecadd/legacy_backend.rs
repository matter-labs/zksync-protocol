use anyhow::{Error, Result};
use zkevm_opcode_defs::bn254::bn256::{Fq, G1Affine};
use zkevm_opcode_defs::bn254::ff::PrimeField;
use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};

use crate::utils::bn254::{point_to_u256_tuple, validate_values_in_field, ECPointCoordinates};

use super::ECAddBackend;

// ==============================================================================
// Legacy Backend
// ==============================================================================
//
// The legacy implementation uses the in-tree BN254 arithmetic and remains the
// reference behavior for both the default build and the delegated differential tests.
pub(super) struct LegacyECAddBackend;

impl ECAddBackend for LegacyECAddBackend {
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

        let x1_field = Fq::from_str(x1.to_string().as_str()).ok_or(Error::msg("invalid x1"))?;
        let y1_field = Fq::from_str(y1.to_string().as_str()).ok_or(Error::msg("invalid y1"))?;
        let x2_field = Fq::from_str(x2.to_string().as_str()).ok_or(Error::msg("invalid x2"))?;
        let y2_field = Fq::from_str(y2.to_string().as_str()).ok_or(Error::msg("invalid y2"))?;

        let point_1 = G1Affine::from_xy_checked(x1_field, y1_field)?;
        let point_2 = G1Affine::from_xy_checked(x2_field, y2_field)?;

        let mut point_1_projective = point_1.into_projective();
        point_1_projective.add_assign_mixed(&point_2);

        Ok(point_to_u256_tuple(point_1_projective.into_affine()))
    }
}
