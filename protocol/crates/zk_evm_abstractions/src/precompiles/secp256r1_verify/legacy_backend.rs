use zkevm_opcode_defs::p256;

use super::Secp256r1Backend;

// ==============================================================================
// Legacy Backend
// ==============================================================================
pub(super) struct LegacySecp256r1Backend;

impl Secp256r1Backend for LegacySecp256r1Backend {
    fn verify(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        x: &[u8; 32],
        y: &[u8; 32],
    ) -> Result<bool, ()> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::elliptic_curve::generic_array::GenericArray;
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::{AffinePoint, EncodedPoint};

        let signature = Signature::from_scalars(
            GenericArray::clone_from_slice(r),
            GenericArray::clone_from_slice(s),
        )
        .map_err(|_| ())?;

        let encoded_key = EncodedPoint::from_affine_coordinates(
            &GenericArray::clone_from_slice(x),
            &GenericArray::clone_from_slice(y),
            false,
        );

        let public_key_point = AffinePoint::from_encoded_point(&encoded_key);
        if bool::from(public_key_point.is_none()) {
            return Err(());
        }

        let verifying_key = VerifyingKey::from_affine(public_key_point.unwrap()).map_err(|_| ())?;
        Ok(verifying_key.verify_prehash(digest, &signature).is_ok())
    }
}
