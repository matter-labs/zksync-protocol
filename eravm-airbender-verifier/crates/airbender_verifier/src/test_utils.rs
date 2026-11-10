//! Test utilities for generating a **synthetic, self-consistent** `CommitmentInput`.
//!
//! The values produced here do **not** match what the sequencer / L1 would supply for
//! a real batch:
//! - `prev_meta_hash` / `prev_aux_hash` are forced to zero, so the recomputed
//!   `prev_batch_commitment` trivially matches the binding check (`lib.rs` binding
//!   branch is exercised but cannot catch a real mainnet mismatch here).
//! - `blob_versioned_hashes` are fabricated from `keccak([i] || b"test_versioned_hash")`
//!   with version byte `0x01` — they are not KZG-derived EIP-4844 versioned hashes.
//! - `blob_opening_commitments` are derived from the fake versioned hashes, so the
//!   blob opening check is self-consistent but does not prove mainnet compatibility.
//!
//! In production, `CommitmentInput` comes from the sequencer (prev_batch_commitment
//! from DB, blob data from L1 transactions). Use this only to exercise the verifier
//! pipeline end-to-end; for byte-for-byte L1 equivalence, pin values against real
//! sequencer output.

pub mod read_proofs;

use anyhow::Context;
use zksync_types::{
    commitment::{
        AuxCommitments, BlobHash, CommitmentCommonInput,
        CommitmentInput as SequencerCommitmentInput, L1BatchCommitment,
    },
    web3::keccak256,
    H256,
};

use crate::commitment::{compute_commitment, compute_pass_through_data_hash};
use crate::types::{AirbenderVerifierInput, CommitmentInput, TOTAL_BLOBS_IN_COMMITMENT};
use crate::VerificationResult;

/// Replace `input.commitment_input` with a **synthetic, self-consistent** value
/// so that the verifier pipeline can be exercised end-to-end without real
/// sequencer/L1 inputs. Any pre-existing `commitment_input` is overwritten.
///
/// What's produced:
/// - `blob_hashes` carry real linear hashes (derived from the VM's pubdata) and
///   fabricated opening commitments derived from synthetic versioned hashes.
/// - `blob_versioned_hashes` are fabricated deterministically so the blob
///   opening check passes.
/// - `prev_meta_hash` / `prev_aux_hash` are forced to zero, and `prev_batch_commitment`
///   is derived from those zeros so the binding check is satisfied tautologically.
///
/// See the module-level docs for why this is **not** L1-settlement-equivalent.
/// Only use this for testing the verifier pipeline.
pub fn augment_with_synthetic_commitment(
    mut input: AirbenderVerifierInput,
) -> anyhow::Result<AirbenderVerifierInput> {
    // We need the VM's pubdata to derive synthetic blob hashes. The rest of
    // the execution state is discarded; the caller's `verify()` re-runs
    // `execute` end-to-end on the augmented input.
    let preliminary = crate::execute(input.clone())?;
    let pubdata = preliminary.pubdata();
    let (blob_versioned_hashes, blob_hashes) = compute_blob_opening_data(pubdata);

    // Compute a self-consistent prev_batch_commitment from old_root_hash and
    // enumeration_index so that the prev_batch_commitment binding check passes.
    // In production these come from L1; for tests we derive them from the input.
    let old_root_hash = input.l1_batch_env.previous_batch_hash.context(
        "previous_batch_hash is missing — genesis batches are not supported by this helper",
    )?;
    let enumeration_index = input.merkle_paths.next_enumeration_index();
    let prev_meta_hash = H256::zero();
    let prev_aux_hash = H256::zero();
    let prev_passthrough = compute_pass_through_data_hash(enumeration_index, old_root_hash);
    let prev_batch_commitment = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);

    input.commitment_input = Some(CommitmentInput {
        prev_batch_commitment,
        prev_meta_hash,
        prev_aux_hash,
        blob_hashes,
        blob_versioned_hashes,
    });
    Ok(input)
}

/// Compute self-consistent blob versioned hashes and `BlobHash` (linear +
/// opening commitment) pairs for testing.
///
/// In production, versioned hashes come from L1 blob transactions and opening
/// commitments are computed by the sequencer. For tests, we derive linear
/// hashes from the VM's pubdata, fabricate deterministic versioned hashes,
/// and call the same [`crate::commitment::compute_blob_opening_commitment`]
/// the verifier uses, so the resulting commitments pass the verifier's check
/// by construction.
pub fn compute_blob_opening_data(pubdata: &[u8]) -> (Vec<H256>, Vec<BlobHash>) {
    let linear_hashes = crate::commitment::compute_blob_linear_hashes(pubdata);
    let mut versioned_hashes = vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT];
    let mut blob_hashes = vec![BlobHash::default(); TOTAL_BLOBS_IN_COMMITMENT];

    for i in 0..TOTAL_BLOBS_IN_COMMITMENT {
        if linear_hashes[i] == H256::zero() {
            continue;
        }
        let Some(blob) = crate::commitment::padded_blob_for(pubdata, i) else {
            continue;
        };

        // Deterministic fake versioned hash.
        let mut vh = H256(keccak256(
            &[&[i as u8][..], b"test_versioned_hash"].concat(),
        ));
        vh.0[0] = 0x01; // EIP-4844 version byte
        versioned_hashes[i] = vh;

        let commitment = crate::commitment::compute_blob_opening_commitment(
            &blob,
            versioned_hashes[i],
            linear_hashes[i],
        );
        blob_hashes[i] = BlobHash {
            linear_hash: linear_hashes[i],
            commitment,
        };
    }

    (versioned_hashes, blob_hashes)
}

/// Reconstruct the batch commitment via upstream `L1BatchCommitment::new()`
/// and assert the verifier's sub-hashes agree.
///
/// The hash math is shared upstream code, so this catches struct-construction
/// mistakes in `verify_commitment` (e.g. fields swapped in the struct literal)
/// rather than encoding bugs.
pub fn crosscheck_commitment(
    result: &VerificationResult,
    input: &AirbenderVerifierInput,
) -> anyhow::Result<()> {
    // Reconstruct at the version `execute` committed under. Asking the shared
    // helper rather than hardcoding the pin is what stops the calibration
    // flavour firing the `metadataHash` assertion below — blaming the verifier
    // for a harness bug.
    let protocol_version = crate::stf_protocol_version(&input.system_env);
    let base = &input.system_env.base_system_smart_contracts;
    let evm_emulator_code_hash = base.evm_emulator.as_ref().map(|e| e.hash);

    let sequencer_input = SequencerCommitmentInput::PostBoojum {
        common: CommitmentCommonInput {
            l2_to_l1_logs: vec![],
            rollup_last_leaf_index: result.new_enumeration_index,
            rollup_root_hash: result.value_hash,
            bootloader_code_hash: base.bootloader.hash,
            default_aa_code_hash: base.default_aa.hash,
            evm_emulator_code_hash,
            protocol_version,
        },
        system_logs: result.system_logs.clone(),
        state_diffs: result.state_diffs.clone(),
        aux_commitments: AuxCommitments {
            events_queue_commitment: H256::zero(),
            // Boojum's `bootloader_initial_content_commitment` is Poseidon2;
            // the constructor doesn't recompute it, so passing the verifier's
            // Blake2s value reproduces the Airbender variant exactly.
            bootloader_initial_content_commitment: result.bootloader_heap_hash,
        },
        blob_hashes: input
            .commitment_input
            .as_ref()
            .context("crosscheck_commitment requires commitment_input to be Some")?
            .blob_hashes
            .clone(),
        aggregation_root: H256::zero(),
    };
    let seq_hashes = L1BatchCommitment::new(sequencer_input, true)
        .context("constructing sequencer L1BatchCommitment")?
        .hash()
        .context("hashing sequencer L1BatchCommitment")?;

    anyhow::ensure!(
        result.pass_through_data_hash == seq_hashes.pass_through_data,
        "passThroughDataHash mismatch: guest {:?} vs sequencer {:?}",
        result.pass_through_data_hash,
        seq_hashes.pass_through_data
    );
    // The sequencer's `L1BatchMetaParameters::to_bytes()` differs from the L1 contract
    // encoding when `evm_emulator_code_hash` is `None` (sequencer falls back to
    // `default_aa`; L1 uses zero) or pre-1.5.0 protocols (sequencer truncates to 64 bytes).
    // Only cross-check when both ends agree — modern protocol with an explicit emulator.
    if evm_emulator_code_hash.is_some() && protocol_version.is_post_1_5_0() {
        anyhow::ensure!(
            result.metadata_hash == seq_hashes.meta_parameters,
            "metadataHash mismatch: guest {:?} vs sequencer {:?}",
            result.metadata_hash,
            seq_hashes.meta_parameters
        );
    }
    anyhow::ensure!(
        result.auxiliary_output_hash == seq_hashes.aux_output,
        "auxiliaryOutputHash mismatch: guest {:?} vs sequencer {:?}",
        result.auxiliary_output_hash,
        seq_hashes.aux_output
    );

    Ok(())
}
