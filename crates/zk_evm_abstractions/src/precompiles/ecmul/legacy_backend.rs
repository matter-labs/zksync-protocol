use anyhow::{Error, Result};
use zkevm_opcode_defs::bn254::bn256::{Fq, Fr, G1Affine};
use zkevm_opcode_defs::bn254::ff::PrimeField;
use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};
use zkevm_opcode_defs::ethereum_types::U256;

use crate::utils::bn254::{point_to_u256_tuple, validate_values_in_field, ECPointCoordinates};

use super::{ECMulBackend, EC_GROUP_ORDER};

// ==============================================================================
// Legacy Backend
// ==============================================================================
//
// The legacy backend preserves the existing BN254 multiplication semantics and
// serves as the oracle for delegated differential tests.
pub(super) struct LegacyECMulBackend;

impl ECMulBackend for LegacyECMulBackend {
    fn mul((x1, y1): ECPointCoordinates, s: U256) -> Result<ECPointCoordinates> {
        if !validate_values_in_field(&[&x1.to_string(), &y1.to_string()]) {
            return Err(Error::msg("invalid values"));
        }

        let x1_field = Fq::from_str(x1.to_string().as_str()).ok_or(Error::msg("invalid x1"))?;
        let y1_field = Fq::from_str(y1.to_string().as_str()).ok_or(Error::msg("invalid y1"))?;
        let s_field = u256_to_scalar(s);

        let point = G1Affine::from_xy_checked(x1_field, y1_field)?;
        Ok(point_to_u256_tuple(point.mul(s_field).into_affine()))
    }
}

fn u256_to_scalar(value: U256) -> Fr {
    let group_order = U256::from_str_radix(EC_GROUP_ORDER.trim_start_matches("0x"), 16)
        .expect("group order constant must parse");
    let mut reduced = value;

    // NOTE: `2^256 / r` is about 5.29, so six subtractions are sufficient here.
    while reduced >= group_order {
        reduced -= group_order;
    }

    Fr::from_str(reduced.to_string().as_str())
        .expect("reduced scalar must fit into the BN254 scalar field")
}
