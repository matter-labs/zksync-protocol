use super::Secp256r1Backend;
use zkevm_opcode_defs::p256;

// ==============================================================================
// Delegated Backend
// ==============================================================================
pub(super) struct DelegatedSecp256r1Backend;

impl Secp256r1Backend for DelegatedSecp256r1Backend {
    fn verify(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        x: &[u8; 32],
        y: &[u8; 32],
    ) -> Result<bool, ()> {
        validate_public_key(x, y)?;

        match airbender_crypto::secp256r1::verify(digest, r, s, x, y) {
            Ok(is_valid) => Ok(is_valid),
            // A recovered point at infinity is an invalid ECDSA signature, not
            // malformed precompile input. Legacy completes verification and
            // returns `false`, which writes the successful-but-invalid output
            // word pair `[1, 0]`.
            Err(airbender_crypto::secp256r1::Secp256r1Err::RecoveredInfinity) => Ok(false),
            Err(_) => Err(()),
        }
    }
}

fn validate_public_key(x: &[u8; 32], y: &[u8; 32]) -> Result<(), ()> {
    use p256::elliptic_curve::generic_array::GenericArray;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint};

    // Legacy rejects malformed public keys before verification. Keeping the
    // same parse boundary lets the delegated backend reserve
    // `RecoveredInfinity` for the verification result instead of conflating it
    // with invalid key coordinates.
    let encoded_key = EncodedPoint::from_affine_coordinates(
        &GenericArray::clone_from_slice(x),
        &GenericArray::clone_from_slice(y),
        false,
    );
    let public_key_point = AffinePoint::from_encoded_point(&encoded_key);

    // `public_key_point.is_none()` returns `Choice`, not `bool`
    if bool::from(public_key_point.is_none()) {
        Err(())
    } else {
        Ok(())
    }
}
