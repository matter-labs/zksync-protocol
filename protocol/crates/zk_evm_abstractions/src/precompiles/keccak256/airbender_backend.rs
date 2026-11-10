use airbender_crypto::sha3::Keccak256 as AirbenderKeccak256;

use super::{KeccakBackend, KECCAK_PRECOMPILE_BUFFER_SIZE, KECCAK_RATE_BYTES};

// ==============================================================================
// Delegated Backend
// ==============================================================================
//
// The delegated backend must preserve the legacy read cadence so witnesses and
// cycle accounting stay stable. Once bytes have been forwarded to the delegated
// digest, re-buffering them locally does not buy us anything.
pub(super) struct DelegatedKeccakBackend {
    buffered_bytes: usize,
    state: Option<AirbenderKeccak256>,
}

impl KeccakBackend for DelegatedKeccakBackend {
    fn new() -> Self {
        Self {
            buffered_bytes: 0,
            state: Some(<AirbenderKeccak256 as airbender_crypto::MiniDigest>::new()),
        }
    }

    fn can_fill_bytes(&self, num_bytes: usize) -> bool {
        self.buffered_bytes + num_bytes <= KECCAK_PRECOMPILE_BUFFER_SIZE
    }

    fn absorb_query_bytes(&mut self, input: &[u8; 32], offset: usize, meaningful_bytes: usize) {
        if meaningful_bytes == 0 {
            return;
        }

        let end = offset + meaningful_bytes;
        airbender_crypto::MiniDigest::update(
            self.state
                .as_mut()
                .expect("airbender keccak state must exist before finalization"),
            &input[offset..end],
        );
        self.buffered_bytes += meaningful_bytes;
    }

    fn finish_round(
        &mut self,
        _full_round_padding: &[u8; KECCAK_RATE_BYTES],
        _is_last: bool,
        _paddings_round: bool,
        _padding_space: usize,
    ) {
        self.buffered_bytes = self.buffered_bytes.saturating_sub(KECCAK_RATE_BYTES);
    }

    fn finalize(&mut self) -> [u8; 32] {
        airbender_crypto::MiniDigest::finalize(
            self.state
                .take()
                .expect("airbender keccak state must exist for finalization"),
        )
    }
}
