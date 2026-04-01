use zkevm_opcode_defs::k256;
use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;

use super::ECRecoverBackend;

// ==============================================================================
// Delegated Backend
// ==============================================================================
pub(super) struct DelegatedECRecoverBackend;

impl ECRecoverBackend for DelegatedECRecoverBackend {
    fn recover(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        rec_id: u8,
    ) -> Result<VerifyingKey, ()> {
        use airbender_crypto::k256::ecdsa::{RecoveryId, Signature};
        use airbender_crypto::k256::elliptic_curve::ops::Reduce;
        use airbender_crypto::k256::{ecdsa::hazmat::bits2field, Scalar};
        use airbender_crypto::secp256k1;

        let signature = Signature::from_scalars(*r, *s).map_err(|_| ())?;
        let recovery_id = RecoveryId::try_from(rec_id).unwrap();

        let mut signature_bytes = [0u8; 64];
        signature_bytes[..32].copy_from_slice(r);
        signature_bytes[32..].copy_from_slice(s);
        let legacy_signature =
            k256::ecdsa::Signature::try_from(&signature_bytes[..]).map_err(|_| ())?;

        let message = <Scalar as Reduce<airbender_crypto::k256::U256>>::reduce_bytes(
            &bits2field::<airbender_crypto::k256::Secp256k1>(digest).map_err(|_| ())?,
        );

        let recovered_key =
            secp256k1::recover(&message, &signature, &recovery_id).map_err(|_| ())?;
        let encoded = recovered_key.to_encoded_point(false);
        let verifying_key = VerifyingKey::from_sec1_bytes(encoded.as_bytes()).map_err(|_| ())?;

        let field = k256::ecdsa::hazmat::bits2field::<k256::Secp256k1>(digest).map_err(|_| ())?;
        let _ = k256::ecdsa::hazmat::verify_prehashed(
            &verifying_key.as_affine().into(),
            &field,
            &legacy_signature,
        )
        .map_err(|_| ())?;

        Ok(verifying_key)
    }
}
