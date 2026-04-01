use super::Secp256r1Backend;

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
        airbender_crypto::secp256r1::verify(digest, r, s, x, y).map_err(|_| ())
    }
}
