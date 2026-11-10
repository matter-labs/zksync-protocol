use super::{
    transmute_state, ByteBuffer, Digest, Keccak256, KeccakBackend, KECCAK_PRECOMPILE_BUFFER_SIZE,
    KECCAK_RATE_BYTES,
};

// ==============================================================================
// Legacy Backend
// ==============================================================================
//
// The legacy implementation absorbs complete rate-sized blocks, so it keeps the
// explicit staging buffer that assembles aligned memory reads into keccak rounds.
pub(super) struct LegacyKeccakBackend {
    buffer: ByteBuffer<KECCAK_PRECOMPILE_BUFFER_SIZE>,
    state: Keccak256,
}

impl LegacyKeccakBackend {
    fn finalize_state(state: Keccak256) -> [u8; 32] {
        let state_inner = transmute_state(state);

        // Take the first four lanes and serialize them into the canonical digest bytes.
        let mut hash_as_bytes32 = [0u8; 32];
        hash_as_bytes32[0..8].copy_from_slice(&state_inner[0].to_le_bytes());
        hash_as_bytes32[8..16].copy_from_slice(&state_inner[1].to_le_bytes());
        hash_as_bytes32[16..24].copy_from_slice(&state_inner[2].to_le_bytes());
        hash_as_bytes32[24..32].copy_from_slice(&state_inner[3].to_le_bytes());
        hash_as_bytes32
    }
}

impl KeccakBackend for LegacyKeccakBackend {
    fn new() -> Self {
        Self {
            buffer: ByteBuffer {
                bytes: [0u8; KECCAK_PRECOMPILE_BUFFER_SIZE],
                filled: 0,
            },
            state: Keccak256::default(),
        }
    }

    fn can_fill_bytes(&self, num_bytes: usize) -> bool {
        self.buffer.can_fill_bytes(num_bytes)
    }

    fn absorb_query_bytes(&mut self, input: &[u8; 32], offset: usize, meaningful_bytes: usize) {
        self.buffer.fill_with_bytes(input, offset, meaningful_bytes);
    }

    fn finish_round(
        &mut self,
        full_round_padding: &[u8; KECCAK_RATE_BYTES],
        is_last: bool,
        paddings_round: bool,
        padding_space: usize,
    ) {
        let mut block = self.buffer.consume::<KECCAK_RATE_BYTES>();
        if paddings_round {
            block = *full_round_padding;
        } else if is_last {
            if padding_space == KECCAK_RATE_BYTES - 1 {
                block[KECCAK_RATE_BYTES - 1] = 0x81;
            } else {
                block[padding_space] = 0x01;
                block[KECCAK_RATE_BYTES - 1] = 0x80;
            }
        }

        self.state.update(&block);
    }

    fn finalize(&mut self) -> [u8; 32] {
        Self::finalize_state(std::mem::take(&mut self.state))
    }
}
