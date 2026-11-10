use zkevm_opcode_defs::k256;
use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;

use super::ECRecoverBackend;

// ==============================================================================
// Legacy Backend
// ==============================================================================
pub(super) struct LegacyECRecoverBackend;

impl ECRecoverBackend for LegacyECRecoverBackend {
    fn recover(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        rec_id: u8,
    ) -> Result<VerifyingKey, ()> {
        use k256::ecdsa::{RecoveryId, Signature};

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(r);
        signature[32..].copy_from_slice(s);
        let signature = Signature::try_from(&signature[..]).map_err(|_| ())?;
        let recovery_id = RecoveryId::try_from(rec_id).unwrap();

        recover_no_malleability_check(digest, signature, recovery_id)
    }
}

fn recover_no_malleability_check(
    digest: &[u8; 32],
    signature: k256::ecdsa::Signature,
    recovery_id: k256::ecdsa::RecoveryId,
) -> Result<VerifyingKey, ()> {
    use k256::ecdsa::hazmat::bits2field;
    use k256::elliptic_curve::bigint::CheckedAdd;
    use k256::elliptic_curve::generic_array::GenericArray;
    use k256::elliptic_curve::ops::Invert;
    use k256::elliptic_curve::ops::LinearCombination;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::DecompressPoint;
    use k256::elliptic_curve::Curve;
    use k256::elliptic_curve::FieldBytesEncoding;
    use k256::elliptic_curve::PrimeField;
    use k256::AffinePoint;
    use k256::ProjectivePoint;
    use k256::Scalar;

    let (r, s) = signature.split_scalars();
    let z = <Scalar as Reduce<k256::U256>>::reduce_bytes(
        &bits2field::<k256::Secp256k1>(digest).map_err(|_| ())?,
    );

    let mut r_bytes: GenericArray<u8, <k256::Secp256k1 as Curve>::FieldBytesSize> = r.to_repr();
    if recovery_id.is_x_reduced() {
        match Option::<k256::U256>::from(
            <k256::U256 as FieldBytesEncoding<k256::Secp256k1>>::decode_field_bytes(&r_bytes)
                .checked_add(&k256::Secp256k1::ORDER),
        ) {
            Some(restored) => {
                r_bytes = <k256::U256 as FieldBytesEncoding<k256::Secp256k1>>::encode_field_bytes(
                    &restored,
                )
            }
            None => return Err(()),
        };
    }

    let recovered_point =
        AffinePoint::decompress(&r_bytes, u8::from(recovery_id.is_y_odd()).into());
    if recovered_point.is_none().into() {
        return Err(());
    }

    let recovered_point = ProjectivePoint::from(recovered_point.unwrap());
    let r_inv: Scalar = *r.invert();
    let u1 = -(r_inv * z);
    let u2 = r_inv * *s;
    let public_key =
        ProjectivePoint::lincomb(&ProjectivePoint::GENERATOR, &u1, &recovered_point, &u2);
    let verifying_key = VerifyingKey::from_affine(public_key.into()).map_err(|_| ())?;

    let field = bits2field::<k256::Secp256k1>(digest).map_err(|_| ())?;
    let _ = k256::ecdsa::hazmat::verify_prehashed(
        &verifying_key.as_affine().into(),
        &field,
        &signature,
    )
    .map_err(|_| ())?;

    Ok(verifying_key)
}
