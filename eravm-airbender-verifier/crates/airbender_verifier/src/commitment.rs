//! Batch commitment computation for EraVM-on-Airbender.
//!
//! Computes the 3-layer Era VM commitment hash tree (matching
//! `Committer.sol::_createBatchCommitment()` on L1) by delegating to upstream
//! `L1BatchCommitment::hash()`. Airbender deviates from Boojum inside
//! `auxiliaryOutputHash`:
//! - `bootloaderHeapInitialContentsHash` uses Blake2s (vs Poseidon2-Goldilocks).
//! - `eventsQueueStateHash` is `bytes32(0)`.
//!
//! Both deviations are encoded as direct field values on
//! `L1BatchAuxiliaryOutput::PostBoojum`, so upstream's `to_bytes()` emits the
//! Airbender variant verbatim.
//!
//! L1 reference: `era-contracts/l1-contracts/contracts/state-transition/chain-deps/facets/Executor.sol`
//!
//! Upstream Rust reference: `zksync_types::commitment::L1BatchCommitment` in
//! `zksync-era/core/lib/types/src/commitment/mod.rs`.

use zksync_types::{
    commitment::{BlobHash, L1BatchPassThroughData, RootState},
    web3::keccak256,
    H256, U256,
};

use crate::types::TOTAL_BLOBS_IN_COMMITMENT;

/// Compute the passthrough data hash for a batch. Used for the current
/// batch's commitment and for the prev-batch binding check.
pub fn compute_pass_through_data_hash(enumeration_index: u64, state_root: H256) -> H256 {
    L1BatchPassThroughData {
        shared_states: vec![
            RootState {
                last_leaf_index: enumeration_index,
                root_hash: state_root,
            },
            // zkPorter shared state — reserved, always zero.
            RootState {
                last_leaf_index: 0,
                root_hash: H256::zero(),
            },
        ],
    }
    .hash()
    .expect("two RootStates must serialize to 80 bytes")
}

/// Compute the full batch commitment from its three sub-hashes. Matches
/// `Committer.sol::_createBatchCommitment()`. Also used by the prev-batch
/// binding check to reconstruct the previous commitment.
pub fn compute_commitment(
    pass_through_data_hash: H256,
    metadata_hash: H256,
    auxiliary_output_hash: H256,
) -> H256 {
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(pass_through_data_hash.as_bytes());
    data[32..64].copy_from_slice(metadata_hash.as_bytes());
    data[64..96].copy_from_slice(auxiliary_output_hash.as_bytes());
    H256(keccak256(&data))
}

/// Compute the proof public input: `keccak256(prev || current)` packed as 8
/// **little-endian** u32 words (see `bytes32_to_u32x8` for why LE is the
/// contract with `zkos-wrapper`). The SNARK wrapper packs the guest's output
/// registers 10..=16 — the first 28 of these 32 bytes — as the public input,
/// dropping the digest's last 4 bytes (BN254's scalar field is ~254 bits), so
/// the SNARK public input equals `keccak(...) >> 32` exactly as L1 computes it
/// in `Executor.sol::_getBatchProofPublicInput`. We emit all 256 bits so the
/// guest stays shift-agnostic; the wrapper handles the truncation.
///
/// `test_proof_public_input_matches_l1_shift` pins the contract.
pub fn compute_proof_public_input(
    prev_batch_commitment: H256,
    current_commitment: H256,
) -> [u32; 8] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(prev_batch_commitment.as_bytes());
    data[32..].copy_from_slice(current_commitment.as_bytes());
    bytes32_to_u32x8(keccak256(&data))
}

/// Size of a single blob chunk in ZKsync's encoding (31 bytes per field element).
const BLOB_CHUNK_SIZE: usize = 31;

/// Number of field elements per EIP-4844 blob.
const ELEMENTS_PER_4844_BLOCK: usize = 4096;

/// Total blob data size: 31 * 4096 = 126976 bytes.
pub const ZK_SYNC_BYTES_PER_BLOB: usize = BLOB_CHUNK_SIZE * ELEMENTS_PER_4844_BLOCK;

/// Return blob `i`'s bytes from `pubdata` zero-padded to
/// `ZK_SYNC_BYTES_PER_BLOB`. Returns `None` when `i` is past pubdata's blob
/// count.
pub fn padded_blob_for(pubdata: &[u8], i: usize) -> Option<Vec<u8>> {
    let start = i * ZK_SYNC_BYTES_PER_BLOB;
    if start >= pubdata.len() {
        return None;
    }
    let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
    let mut padded = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
    padded[..end - start].copy_from_slice(&pubdata[start..end]);
    Some(padded)
}

/// Compute blob linear hashes from pubdata: keccak256 of each blob-sized chunk,
/// zero-padded for the last partial chunk. Returns `TOTAL_BLOBS_IN_COMMITMENT`
/// entries; unused slots are `H256::zero()`.
///
/// Mirrors `pubdata_to_blob_linear_hashes` in
/// `zksync-era/core/node/commitment_generator/src/utils.rs`.
pub fn compute_blob_linear_hashes(pubdata: &[u8]) -> Vec<H256> {
    let mut result = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];
    for (i, slot) in result.iter_mut().enumerate() {
        if let Some(blob) = padded_blob_for(pubdata, i) {
            *slot = H256(keccak256(&blob));
        }
    }
    result
}

/// Compute the EIP-4844 opening commitment for a single padded blob.
///
/// Steps (matching Boojum's `EIP4844Repack` sub-circuit and the host-side
/// reference in `zksync-protocol/crates/zkevm_circuits/src/eip_4844/mod.rs`):
/// 1. evaluation_point = `keccak256(linear_hash || versioned_hash)[16..32]`
/// 2. opening_value = `polynomial(evaluation_point)` over the BLS12-381 scalar
///    field, where the polynomial is the blob bytes interpreted as 31-byte
///    little-endian coefficients with the highest-degree coefficient first.
/// 3. opening_commitment = `keccak256(versioned_hash || eval_point[16..32] || opening_value)`
///
/// `blob_bytes` must be exactly `ZK_SYNC_BYTES_PER_BLOB` long; callers are
/// responsible for zero-padding partial blobs.
pub fn compute_blob_opening_commitment(
    blob_bytes: &[u8],
    versioned_hash: H256,
    linear_hash: H256,
) -> H256 {
    use ark_bls12_381::Fr as Bls12_381Fr;
    use ark_ff::{BigInteger, PrimeField, Zero};

    debug_assert_eq!(
        blob_bytes.len(),
        ZK_SYNC_BYTES_PER_BLOB,
        "compute_blob_opening_commitment expects a fully-padded blob"
    );

    // Step 1.
    let eval_hash = {
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(linear_hash.as_bytes());
        preimage[32..].copy_from_slice(versioned_hash.as_bytes());
        keccak256(&preimage)
    };
    let mut evaluation_point_bytes = [0u8; 32];
    evaluation_point_bytes[16..32].copy_from_slice(&eval_hash[16..32]);
    let evaluation_point = Bls12_381Fr::from_be_bytes_mod_order(&evaluation_point_bytes);

    // Step 2: Horner's rule, forward iteration treats first chunk as
    // highest-degree coefficient.
    let mut opening_value = Bls12_381Fr::zero();
    let mut buf = [0u8; 32];
    for chunk in blob_bytes.chunks(BLOB_CHUNK_SIZE) {
        buf[..BLOB_CHUNK_SIZE].copy_from_slice(chunk);
        // 31 bytes LE is always below the BLS12-381 modulus.
        let coeff = Bls12_381Fr::from_le_bytes_mod_order(&buf);
        opening_value *= evaluation_point;
        opening_value += coeff;
    }

    // Step 3.
    let opening_value_bytes: [u8; 32] = opening_value
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("BLS12-381 Fr should be 32 bytes BE");

    let mut preimage = [0u8; 32 + 16 + 32];
    preimage[..32].copy_from_slice(versioned_hash.as_bytes());
    preimage[32..48].copy_from_slice(&eval_hash[16..32]);
    preimage[48..].copy_from_slice(&opening_value_bytes);
    H256(keccak256(&preimage))
}

/// Verify both linear hashes and opening commitments for every blob in a
/// single pass, reusing one scratch buffer for the padded blob bytes.
///
/// Mirrors the self-degeneration in Boojum's `EIP4844Repack` sub-circuit
/// (`zksync-protocol/crates/zkevm_circuits/src/eip_4844/mod.rs`): a slot
/// whose claimed `linear_hash` is zero is treated as "no blob in this slot"
/// and skipped — what non-Rollup DA modes always look like. For non-zero
/// claims we recompute both the linear hash and the opening commitment from
/// the VM-emitted pubdata, requiring exact matches.
pub fn verify_blob_hashes(
    pubdata: &[u8],
    versioned_hashes: &[H256],
    blob_hashes: &[BlobHash],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        versioned_hashes.len() == blob_hashes.len(),
        "blob array length mismatch: versioned={}, blob_hashes={}",
        versioned_hashes.len(),
        blob_hashes.len(),
    );

    let num_blobs_from_pubdata = pubdata.len().div_ceil(ZK_SYNC_BYTES_PER_BLOB);
    // Scratch buffer for the (at most one) partial blob; allocated lazily so
    // the typical all-full-blobs case does no padding work at all.
    let mut padded_scratch: Option<Vec<u8>> = None;

    for (i, blob_hash) in blob_hashes.iter().enumerate() {
        if blob_hash.linear_hash == H256::zero() {
            anyhow::ensure!(
                blob_hash.commitment == H256::zero(),
                "blob {i}: linear hash is zero but opening commitment is non-zero"
            );
            continue;
        }
        anyhow::ensure!(
            i < num_blobs_from_pubdata,
            "blob {i}: claimed non-zero linear hash but no pubdata for this slot"
        );

        let start = i * ZK_SYNC_BYTES_PER_BLOB;
        let end = ((i + 1) * ZK_SYNC_BYTES_PER_BLOB).min(pubdata.len());
        let blob_bytes: &[u8] = if end - start == ZK_SYNC_BYTES_PER_BLOB {
            // Full slot — hash directly from pubdata, no copy.
            &pubdata[start..end]
        } else {
            // Partial slot — pad into scratch.
            let buf = padded_scratch.get_or_insert_with(|| vec![0u8; ZK_SYNC_BYTES_PER_BLOB]);
            buf[..end - start].copy_from_slice(&pubdata[start..end]);
            buf[end - start..].fill(0);
            buf.as_slice()
        };

        let computed_linear = H256(keccak256(blob_bytes));
        anyhow::ensure!(
            blob_hash.linear_hash == computed_linear,
            "blob {i} linear hash mismatch: computed {computed_linear:?}, claimed {:?}",
            blob_hash.linear_hash
        );

        let computed_commitment =
            compute_blob_opening_commitment(blob_bytes, versioned_hashes[i], blob_hash.linear_hash);
        anyhow::ensure!(
            blob_hash.commitment == computed_commitment,
            "blob {i} opening commitment mismatch: computed {computed_commitment:?}, claimed {:?}",
            blob_hash.commitment
        );
    }
    Ok(())
}

/// Expand sparse bootloader heap content to a full byte buffer.
///
/// Mirrors `expand_memory_contents` in
/// `zksync-era/core/node/commitment_generator/src/utils.rs` (private there).
pub fn expand_bootloader_heap(
    initial_heap_content: &[(usize, U256)],
    memory_size_bytes: usize,
) -> Vec<u8> {
    let mut result = vec![0u8; memory_size_bytes];
    for &(offset, value) in initial_heap_content {
        let start = offset * 32;
        let end = start + 32;
        assert!(
            end <= memory_size_bytes,
            "bootloader heap entry at offset {offset} (byte {start}..{end}) exceeds memory size {memory_size_bytes}"
        );
        value.to_big_endian(&mut result[start..end]);
    }
    result
}

/// Split a 32-byte hash into 8 u32 words, each read **little-endian** from its
/// 4-byte chunk.
///
/// The endianness is a contract with `zkos-wrapper`: in `check_aux_params` mode
/// its `prepare_and_allocate_public_inputs` builds the SNARK public input by
/// decomposing the guest's output registers into bytes in RISC-V (little-endian)
/// order and reading the resulting stream as a big-endian integer. Only when the
/// registers hold LE chunks of the digest does that reconstruct the digest
/// itself, making the SNARK public input equal L1's
/// `uint256(keccak256(...)) >> PUBLIC_INPUT_SHIFT` (Executor.sol). With BE words
/// here, every 4-byte group of the digest arrives byte-swapped on the SNARK side
/// and the proof rejects L1's public input.
fn bytes32_to_u32x8(hash: [u8; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    for (i, chunk) in hash.as_chunks::<4>().0.iter().enumerate() {
        result[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_bootloader_heap() {
        let content = vec![(0, U256::from(42)), (2, U256::from(100))];
        let expanded = expand_bootloader_heap(&content, 128);
        assert_eq!(expanded.len(), 128);

        let mut expected = [0u8; 32];
        U256::from(42).to_big_endian(&mut expected);
        assert_eq!(&expanded[0..32], &expected);
        assert_eq!(&expanded[32..64], &[0u8; 32]);
        U256::from(100).to_big_endian(&mut expected);
        assert_eq!(&expanded[64..96], &expected);
    }

    #[test]
    #[should_panic(expected = "bootloader heap entry at offset")]
    fn test_expand_bootloader_heap_out_of_range() {
        let content = vec![(1000, U256::from(1))]; // offset 1000 * 32 = 32000 > 128
        expand_bootloader_heap(&content, 128);
    }

    #[test]
    fn test_bytes32_to_u32x8() {
        assert_eq!(bytes32_to_u32x8([0u8; 32]), [0u32; 8]);
        let mut hash = [0u8; 32];
        hash[0] = 0xFF;
        // Words are little-endian chunks: the digest's first byte is the
        // word's LOW byte (see `bytes32_to_u32x8` for why).
        assert_eq!(bytes32_to_u32x8(hash)[0], 0x000000FF);
    }

    #[test]
    fn test_pass_through_data_hash_encoding() {
        // abi.encodePacked(uint64, bytes32, uint64, bytes32)
        let hash = compute_pass_through_data_hash(42, H256([0xAB; 32]));
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&42u64.to_be_bytes());
        expected_input.extend_from_slice(&[0xAB; 32]);
        expected_input.extend_from_slice(&0u64.to_be_bytes());
        expected_input.extend_from_slice(&[0u8; 32]);
        assert_eq!(hash, H256(keccak256(&expected_input)));
    }

    #[test]
    fn test_proof_public_input_encoding() {
        let prev = H256([0x55; 32]);
        let current = H256([0xAB; 32]);
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(prev.as_bytes());
        preimage[32..].copy_from_slice(current.as_bytes());
        assert_eq!(
            compute_proof_public_input(prev, current),
            bytes32_to_u32x8(keccak256(&preimage)),
        );
    }

    /// Pins the wrapper contract: `zkos-wrapper`'s `prepare_and_allocate_public_inputs`
    /// (in `check_aux_params` mode) decomposes output registers 10..=16 into bytes in
    /// RISC-V little-endian order and reads the 28-byte stream as a big-endian integer.
    /// Modelling exactly that packing over the first 7 words of
    /// `compute_proof_public_input` must reproduce `uint256(keccak(prev || curr)) >> 32`
    /// — the value L1's `Executor.sol::_getBatchProofPublicInput` computes. If this
    /// breaks, the on-wire `[u32; 8]` encoding, the wrapper's packing, or L1's shift
    /// constant changed — all require coordinated changes.
    #[test]
    fn test_proof_public_input_matches_l1_shift() {
        const PUBLIC_INPUT_SHIFT: u32 = 32;
        let prev = H256([0x55; 32]);
        let current = H256([0xAB; 32]);

        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(prev.as_bytes());
        preimage[32..].copy_from_slice(current.as_bytes());
        let l1_input = U256::from_big_endian(&keccak256(&preimage)) >> PUBLIC_INPUT_SHIFT;

        let words = compute_proof_public_input(prev, current);
        // The wrapper reads each register's bytes little-endian; the resulting
        // 28-byte stream forms the big-endian integer public input.
        let mut wrapper_bytes = [0u8; 32];
        for (i, word) in words[..7].iter().enumerate() {
            wrapper_bytes[4 + i * 4..4 + (i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        let wrapper_input = U256::from_big_endian(&wrapper_bytes);

        assert_eq!(
            wrapper_input, l1_input,
            "wrapper-packed proof_public_input words must equal L1's keccak >> 32"
        );
    }
}
