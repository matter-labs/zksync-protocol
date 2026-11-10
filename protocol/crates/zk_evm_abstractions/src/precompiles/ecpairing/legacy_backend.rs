use anyhow::Result;
use zkevm_opcode_defs::bn254::bn256::Fq12;
use zkevm_opcode_defs::bn254::ff::Field;

use super::{pair, ECPairingBackend, EcPairingInputTuple};

// ==============================================================================
// Legacy Backend
// ==============================================================================
pub(super) struct LegacyECPairingBackend;

impl ECPairingBackend for LegacyECPairingBackend {
    fn pairing(inputs: Vec<EcPairingInputTuple>) -> Result<bool> {
        if inputs.is_empty() {
            return Ok(true);
        }

        let mut total_pairing = Fq12::one();
        for input in inputs {
            let pairing = pair(&input)?;
            total_pairing.mul_assign(&pairing);
        }

        Ok(total_pairing.eq(&Fq12::one()))
    }
}
