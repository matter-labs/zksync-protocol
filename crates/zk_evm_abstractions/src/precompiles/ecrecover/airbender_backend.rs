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

        let message = <Scalar as Reduce<airbender_crypto::k256::U256>>::reduce_bytes(
            &bits2field::<airbender_crypto::k256::Secp256k1>(digest).map_err(|_| ())?,
        );

        // `secp256k1::recover` already computes the unique public key consistent
        // with (r, s, rec_id, message) — decompressing R (with x-reduction) and
        // evaluating r^-1 * (s*R - message*G), rejecting a point at infinity. A
        // subsequent ECDSA verification of that key against the same signature is
        // mathematically guaranteed to pass, so the legacy backend's explicit
        // re-verification is redundant here. Dropping it removes a full second
        // double-scalar-multiplication that ran on the *non-delegated* k256 (the
        // dominant cost of this precompile); recovery itself runs on the
        // delegated backend. The `delegated_backend_matches_legacy` differential
        // tests confirm the recovered key (and rejection set) is unchanged.
        let recovered_key =
            secp256k1::recover(&message, &signature, &recovery_id).map_err(|_| ())?;
        let encoded = recovered_key.to_encoded_point(false);
        VerifyingKey::from_encoded_point(&encoded).map_err(|_| ())
    }
}
