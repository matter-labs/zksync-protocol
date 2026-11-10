//! Tee verifier
//!
//! Verifies that a L1Batch has the expected root hash after executing the VM
//! and verifying all the accessed memory slots by their merkle path, and
//! computes the Era VM batch commitment together with the proof public input
//! hash that the Airbender → PLONK SNARK wrapper feeds to L1 settlement.

pub mod commitment;
#[doc(hidden)]
pub mod test_utils;
pub mod types;

mod merkle_witness;

use anyhow::{Context, Result};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_crypto_primitives::hasher::Hasher;
use zksync_merkle_tree::{BlockOutputWithProofs, TreeInstruction, TreeLogEntry, ValueHash};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        ExecutionResult, FinishedL1Batch, L2BlockEnv, TxExecutionMode, VmInterfaceExt,
        VmInterfaceHistoryEnabled,
    },
    pubdata_builders::pubdata_params_to_builder,
    utils::get_used_bootloader_memory_bytes,
    FastVmInstance,
};
// Referenced only by the calibration flavour's FastVM guard, the
// `pinned_version_is_supported_by_fast_vm` change detector, and the host loader.
#[cfg(any(test, feature = "cycle-markers"))]
pub use zksync_multivm::is_supported_by_fast_vm;
use zksync_types::{
    block::L2BlockExecutionData,
    bytecode::{BytecodeHash, BytecodeMarker},
    commitment::{
        serialize_commitments, AuxCommitments, L1BatchAuxiliaryCommonOutput,
        L1BatchAuxiliaryOutput, L1BatchCommitment, L1BatchMetaParameters, L1BatchPassThroughData,
        L2PubdataValidator, PubdataParams, RootState,
    },
    u256_to_h256,
    web3::keccak256,
    writes::StateDiffRecord,
    L1BatchNumber, ProtocolVersionId, StorageLog, Transaction, H256, U256,
};

use crate::commitment::expand_bootloader_heap;
#[cfg(test)]
use crate::merkle_witness::get_bowp;
use crate::merkle_witness::{build_view_from_merkle_paths, extend_view_with_read_proofs};
use crate::types::{
    AirbenderVerifierInput, CommitmentInput, SystemEnvInput, TOTAL_BLOBS_IN_COMMITMENT,
};

/// A structure to hold the result of verification.
pub struct VerificationResult {
    /// The root hash of the batch that was verified.
    pub value_hash: ValueHash,
    /// The batch number that was verified.
    pub batch_number: L1BatchNumber,
    /// The proof public input preimage `keccak256(prev || curr)`, packed as 8
    /// little-endian u32 words — the byte order `zkos-wrapper` expects in the
    /// guest's output registers (see `commitment::bytes32_to_u32x8`). See
    /// [`commitment::compute_proof_public_input`] for the L1
    /// `PUBLIC_INPUT_SHIFT` contract and the wrapper's responsibility.
    pub proof_public_input: [u32; 8],
    /// The computed batch commitment.
    pub commitment: H256,
    /// The new Merkle tree enumeration index after all insertions.
    pub new_enumeration_index: u64,
    /// Sub-hashes for debugging / cross-checking against the sequencer.
    pub pass_through_data_hash: H256,
    pub metadata_hash: H256,
    pub auxiliary_output_hash: H256,
    /// Intermediate hashes for cross-checking.
    pub system_logs_hash: H256,
    pub state_diff_hash: H256,
    pub bootloader_heap_hash: H256,
    /// Raw data for independent cross-checking by tests.
    pub system_logs: Vec<zksync_types::l2_to_l1_log::SystemL2ToL1Log>,
    pub state_diffs: Vec<zksync_types::writes::StateDiffRecord>,
    /// Pubdata produced by VM execution, for blob hash computation.
    pub pubdata_input: Option<Vec<u8>>,
}

/// A trait for the computations that can be verified in TEE.
pub trait Verify {
    fn verify(self) -> anyhow::Result<VerificationResult>;
}

/// Emit an Airbender cycle-marker boundary when the `cycle-markers` feature is
/// enabled; a no-op otherwise. The offline cycle-cost calibration harness turns
/// the feature on for its bench guest build only — markers must never ship in a
/// proved guest. The fixed sequence of calls (start, then the three phase
/// boundaries, then end = 5 markers over one `verify()`) is the contract the
/// host uses to attribute per-phase cycles; keep it in lockstep with the
/// harness's `PHASE_LABELS`.
#[inline(always)]
fn phase_marker() {
    #[cfg(feature = "cycle-markers")]
    airbender::guest::cycle_marker();
}

impl Verify for AirbenderVerifierInput {
    /// Run the VM, verify the new state root, and compute the batch commitment.
    /// Requires `commitment_input` to be `Some`.
    /// Panics as [`execute`] does on a slot outside the proven view.
    fn verify(self) -> anyhow::Result<VerificationResult> {
        verify_inner(self, GapPolicy::Strict)
    }
}

/// [`Verify::verify`] that serves declared but unproven slots as empty, for
/// fixtures without read proofs. Calibration builds only.
#[cfg(feature = "legacy-unproven-gaps")]
pub fn verify_legacy_unproven_gaps(
    input: AirbenderVerifierInput,
) -> anyhow::Result<VerificationResult> {
    verify_inner(input, GapPolicy::LegacyUnprovenGaps)
}

fn verify_inner(
    mut input: AirbenderVerifierInput,
    policy: GapPolicy,
) -> anyhow::Result<VerificationResult> {
    // `execute` ignores `commitment_input`, so move it out first to avoid
    // cloning the blob hash vectors.
    let commitment_input = input.commitment_input.take().context(
        "AirbenderVerifierInput::verify requires `commitment_input`; \
         use `execute(...)` directly for VM-only flows",
    )?;
    let state = execute_inner(input, policy)?;
    verify_commitment(state, commitment_input)
}

/// A private parameter rather than a feature-switched `execute`, so feature
/// unification cannot weaken [`execute`] or [`Verify::verify`].
#[derive(Clone, Copy, PartialEq)]
enum GapPolicy {
    /// Unproven slots are absent from the view; the VM panics on them.
    Strict,
    /// Declared but unproven slots are served empty.
    #[cfg(feature = "legacy-unproven-gaps")]
    LegacyUnprovenGaps,
}

/// The only protocol version this verifier models; every version-gated decision
/// (VM subversion, bootloader heap layout, pubdata builder, blob count, L2-block
/// rules, commitment shape) is taken at this value.
///
/// The operator cannot choose it: the input types carry no version field at all
/// — `execute` injects this constant at `SystemEnvInput::into_system_env`, the
/// single place a version enters the STF. It lives here rather than in
/// `zksync_basic_types` because that crate is a vendored era port with no
/// upstream counterpart for this constant, and rather than tracking
/// [`ProtocolVersionId::latest()`] so a dependency bump cannot silently move
/// the modelled semantics.
///
/// Bump it only when an Era minor changes one of the behaviours above; a minor
/// that changes none needs no guest change, since a divergence that moves a hash
/// L1 reconstructs fails closed there. Not a proof of equivalence — L1 takes the
/// new state root from the operator rather than deriving it, so per-version
/// guest + VK deployment is the real control.
///
/// Residual: a change confined to a parameter no commitment binds — illustrative,
/// not exhaustive. `default_validation_computational_gas_limit`, `fee_input` and
/// `execution_mode` are pinned or triaged in `execute`; `bootloader_gas_limit` is
/// unbound but work-bound, not semantic.
pub const PINNED_PROTOCOL_VERSION: ProtocolVersionId = ProtocolVersionId::Version34;

/// Oldest batch label the host accepts; such batches are proved under
/// [`PINNED_PROTOCOL_VERSION`]. v31..v33 share the pin's bootloader layout and
/// commitment shape. They cannot set the force-fail bit, so they execute here as
/// under the pin.
pub const OLDEST_PROVABLE_LABEL: ProtocolVersionId = ProtocolVersionId::Version31;

/// The version this build runs an input under, and therefore commits at: the pin
/// in production (the input types cannot carry one), the batch's own under
/// `cycle-markers`.
///
/// The single definition: a drifted copy reconstructs a commitment at the wrong
/// version. Costs the guest +165 instructions vs binding the constant inline in
/// `execute` — optimisation ordering, not a lost constant-fold, so don't chase
/// it (`#[inline(always)]` and a whole-input parameter both change nothing).
#[cfg(not(feature = "cycle-markers"))]
#[inline]
pub fn stf_protocol_version(_system_env: &SystemEnvInput) -> ProtocolVersionId {
    PINNED_PROTOCOL_VERSION
}

/// Calibration arm of [`stf_protocol_version`].
#[cfg(feature = "cycle-markers")]
#[inline]
pub fn stf_protocol_version(system_env: &SystemEnvInput) -> ProtocolVersionId {
    system_env.version
}

/// Whether this build is the calibration flavour, so a consumer can refuse it
/// at compile time.
///
/// Building the guest without `cycle-markers` is not enough: `guest` is a
/// workspace member, so one cargo invocation that also selects a
/// `cycle-markers` package unifies the feature into the guest's copy of this
/// crate — a guest that takes its protocol version from the operator's wire —
/// while the guest's own feature list still reads empty. `guest/src/main.rs`
/// asserts on this so that leak is a build error.
pub const CALIBRATION_FLAVOUR: bool = cfg!(feature = "cycle-markers");

type VerifierStorage = StorageSnapshot;
type FastVerifierVm = FastVmInstance<VerifierStorage>;

/// Intermediate state after VM execution and merkle proof verification,
/// before any commitment-input-dependent checks.
pub struct VmExecutionState {
    batch_number: zksync_types::L1BatchNumber,
    protocol_version: ProtocolVersionId,
    old_root_hash: H256,
    prev_enumeration_index: u64,
    new_root_hash: H256,
    new_enumeration_index: u64,
    system_logs: Vec<zksync_types::l2_to_l1_log::SystemL2ToL1Log>,
    state_diffs: Vec<StateDiffRecord>,
    pubdata_input: Option<Vec<u8>>,
    expanded_heap: Vec<u8>,
    zk_porter_available: bool,
    bootloader_code_hash: H256,
    default_aa_code_hash: H256,
    evm_emulator_code_hash: Option<H256>,
}

impl VmExecutionState {
    /// Pubdata produced by the VM. Empty when the VM did not emit a pubdata
    /// input (e.g. pre-gateway protocols).
    pub fn pubdata(&self) -> &[u8] {
        self.pubdata_input.as_deref().unwrap_or(&[])
    }
}

/// Canonical account-validation gas limit for the Airbender proving path. The
/// producer hardcodes `u32::MAX` (unlimited) for every batch — see
/// zksync-era `airbender_request_processor.rs` (`validation_computational_gas_limit
/// = u32::MAX`). The field is operator-supplied and bound by no commitment, yet
/// it gates account-abstraction validation accept/reject: a smaller value would
/// OOG-fail validations that pass under the canonical (unlimited) limit, yielding
/// a different valid batch. Pin it.
///
/// (Note: this is *not* the state-keeper `StateKeeperConfig` default of 300_000;
/// the witness generator deliberately disables the limit for proving.)
const VALIDATION_COMPUTATIONAL_GAS_LIMIT: u32 = u32::MAX;

/// Run the VM, verify the new state root via merkle proofs, and return the
/// intermediate state needed to compute the batch commitment.
///
/// Commitment-input-dependent checks (prev binding, blob verification) are
/// not performed here — `input.commitment_input` is ignored. `Verify::verify`
/// runs this and then `verify_commitment` to complete the pipeline.
///
/// Panics, rather than erring, if the VM reads a slot outside the proven
/// pre-batch view.
pub fn execute(input: AirbenderVerifierInput) -> anyhow::Result<VmExecutionState> {
    execute_inner(input, GapPolicy::Strict)
}

/// [`execute`] with [`verify_legacy_unproven_gaps`]'s storage view.
#[cfg(feature = "legacy-unproven-gaps")]
pub fn execute_legacy_unproven_gaps(
    input: AirbenderVerifierInput,
) -> anyhow::Result<VmExecutionState> {
    execute_inner(input, GapPolicy::LegacyUnprovenGaps)
}

#[cfg_attr(not(feature = "legacy-unproven-gaps"), allow(unused_variables))]
fn execute_inner(
    mut input: AirbenderVerifierInput,
    policy: GapPolicy,
) -> anyhow::Result<VmExecutionState> {
    phase_marker(); // marker 0: begin `setup`

    // Must be the FIRST statement that touches the input: the legacy delta form is
    // self-describing only through entry 0's stored length, which this call overwrites.
    //
    // Reclaiming here rather than at fold time is what bounds the memory: the
    // witness stays resident until the Merkle fold at the end, so it is additive
    // with every execution-time sink. The legacy surplus per entry is
    // `depth(entry 0) - depth(entry i)`, and entry 0 is the smallest
    // `(address, key)` touched — so one slot ground next to it would otherwise
    // inflate every entry.
    //
    // Fail-closed: also validates the wire form (path length `<= TREE_DEPTH` and the
    // legacy-form contract), so a malformed witness is rejected here rather than
    // aborting a later fold. Runs before the version pin — nothing downstream sees an
    // unvalidated path.
    input.merkle_paths.normalize_stored_paths()?;

    // The STF assigns the version it models; the input cannot express one, so
    // there is nothing to check against — except under `cycle-markers`, where the
    // never-shipped channel puts the field back and the wire chooses.
    let protocol_version = stf_protocol_version(&input.system_env);

    // Static in production (see `pinned_version_is_supported_by_fast_vm`),
    // load-bearing only where the wire chooses.
    #[cfg(feature = "cycle-markers")]
    anyhow::ensure!(
        is_supported_by_fast_vm(protocol_version),
        "protocol version {protocol_version:?} is not supported by the FastVM verifier",
    );

    // The single place a version enters the STF.
    let system_env = input.system_env.into_system_env(protocol_version);

    let old_root_hash = input
        .l1_batch_env
        .previous_batch_hash
        .context("previous_batch_hash is missing — genesis batches are not supported")?;
    let enumeration_index = input.merkle_paths.next_enumeration_index();
    let batch_number = input.l1_batch_env.number;
    let zk_porter_available = system_env.zk_porter_available;

    // `enforced_base_fee` is an `eth_call`/`estimateGas` simulation override; the
    // batch-execution path always leaves it `None`. Pin it here so the verifier is
    // fail-closed locally rather than relying on the bootloader's base-fee assert.
    anyhow::ensure!(
        input.l1_batch_env.enforced_base_fee.is_none(),
        "enforced_base_fee must be None for a proved batch; got {:?}",
        input.l1_batch_env.enforced_base_fee,
    );
    // `vm_run_data` carries operator-supplied copies of values the verifier also
    // derives from the canonical batch/system env. Bind the redundant copies that
    // have an authoritative counterpart so a malicious witness cannot disagree with
    // the environment the VM actually executes against.
    anyhow::ensure!(
        input.vm_run_data.l1_batch_number == batch_number,
        "vm_run_data.l1_batch_number {:?} does not match l1_batch_env.number {batch_number:?}",
        input.vm_run_data.l1_batch_number,
    );
    // Bootloader memory encoding reads the validator back by shape —
    // `l2_da_validator().expect(...)` pre-medium-interop,
    // `l2_da_commitment_scheme().expect(...)` after — so either mismatched
    // combination panics deep inside multivm. Reject both directions here so
    // a hostile payload yields an error instead.
    anyhow::ensure!(
        protocol_version.is_pre_medium_interop()
            == matches!(
                input.pubdata_params.pubdata_validator(),
                L2PubdataValidator::Address(_)
            ),
        "protocol {protocol_version:?} is incompatible with L2 pubdata validator {:?}: \
         pre-medium-interop requires the address shape, post-medium-interop the \
         commitment scheme",
        input.pubdata_params.pubdata_validator(),
    );
    // The verifier proves a settled batch, which the sequencer executed in
    // `VerifyExecute`. `EstimateFee` ignores AA-validation errors and `EthCall`
    // uses mimic-calls (no signature checks), so an operator-chosen mode could
    // prove transactions that bypass validation. `execution_mode` is
    // operator-supplied and not otherwise bound — pin it.
    anyhow::ensure!(
        system_env.execution_mode == TxExecutionMode::VerifyExecute,
        "system_env.execution_mode must be VerifyExecute for proving, got {:?}",
        system_env.execution_mode,
    );
    // `default_validation_computational_gas_limit` is operator-supplied and bound
    // by no commitment, but it gates account-abstraction validation accept/reject.
    // Pin it to the canonical Era value so a non-canonical limit can't yield a
    // different valid batch.
    anyhow::ensure!(
        system_env.default_validation_computational_gas_limit
            == VALIDATION_COMPUTATIONAL_GAS_LIMIT,
        "system_env.default_validation_computational_gas_limit {} does not match the canonical Era value {}",
        system_env.default_validation_computational_gas_limit,
        VALIDATION_COMPUTATIONAL_GAS_LIMIT,
    );
    // `vm_run_data.{initial_heap_content, storage_refunds, pubdata_costs}` are
    // populated by the witness generator for the legacy proving path and are not
    // consumed here: the verifier recomputes the bootloader heap it commits to from
    // VM execution and derives refunds/pubdata itself. They are intentionally left
    // unconstrained — real witnesses carry non-empty values for these fields.

    if let Some(first) = input.l2_blocks_execution_data.first() {
        let canonical = &input.l1_batch_env.first_l2_block;
        anyhow::ensure!(
            first.number.0 == canonical.number
                && first.timestamp == canonical.timestamp
                && first.prev_block_hash == canonical.prev_block_hash
                && first.virtual_blocks == canonical.max_virtual_blocks_to_create
                && first.interop_roots == canonical.interop_roots,
            "l2_blocks_execution_data[0] metadata must equal l1_batch_env.first_l2_block",
        );
    }

    // Source all metadata-bound code hashes from system_env.base_system_smart_contracts.
    // That's what the VM actually loads — verifying any other copy (vm_run_data's
    // bootloader_code, default_account_code_hash, evm_emulator_code_hash) leaves a
    // window for a malicious witness to lie: ship a legitimate bytecode in
    // vm_run_data while the VM runs a different one from system_env.
    let base = &system_env.base_system_smart_contracts;
    let bootloader_code_hash = base.bootloader.hash;
    let default_aa_code_hash = base.default_aa.hash;
    let evm_emulator_code_hash = base.evm_emulator.as_ref().map(|e| e.hash);

    // Verify the bytecodes the VM consumes match the hashes that flow into
    // metadata_hash (and thus the batch commitment). System contracts are
    // EraVM bytecodes in practice; `verify_bytecode_hash` dispatches on the
    // marker byte so it works uniformly with user contracts in factory_deps.
    let h256_to_u256 = |h: H256| U256::from_big_endian(h.as_bytes());
    verify_bytecode_hash(h256_to_u256(bootloader_code_hash), &base.bootloader.code)
        .context("verifying bootloader bytecode")?;
    verify_bytecode_hash(h256_to_u256(default_aa_code_hash), &base.default_aa.code)
        .context("verifying default_aa bytecode")?;
    if let Some(emu) = &base.evm_emulator {
        verify_bytecode_hash(h256_to_u256(emu.hash), &emu.code)
            .context("verifying evm_emulator bytecode")?;
    }

    // Enforce that vm_run_data's redundant copies match system_env. The
    // verifier doesn't *use* these (system_env is the source of truth) but a
    // mismatch is a malformed witness and we'd rather catch it here than
    // have it propagate silently.
    {
        let vm_run_default_aa = u256_to_h256(input.vm_run_data.default_account_code_hash);
        anyhow::ensure!(
            vm_run_default_aa == default_aa_code_hash,
            "vm_run_data.default_account_code_hash {vm_run_default_aa:?} does not match \
             system_env.base_system_smart_contracts.default_aa.hash {default_aa_code_hash:?}",
        );

        let vm_run_evm_emulator = input.vm_run_data.evm_emulator_code_hash.map(u256_to_h256);
        anyhow::ensure!(
            vm_run_evm_emulator == evm_emulator_code_hash,
            "vm_run_data.evm_emulator_code_hash {vm_run_evm_emulator:?} does not match \
             system_env.base_system_smart_contracts.evm_emulator hash {evm_emulator_code_hash:?}",
        );

        let vm_run_bootloader_bytes: Vec<u8> = input
            .vm_run_data
            .bootloader_code
            .iter()
            .flat_map(|word| word.as_slice())
            .copied()
            .collect();
        anyhow::ensure!(
            vm_run_bootloader_bytes == base.bootloader.code,
            "vm_run_data.bootloader_code does not match system_env.base_system_smart_contracts.bootloader.code \
             (lengths: {} vs {})",
            vm_run_bootloader_bytes.len(),
            base.bootloader.code.len(),
        );
    }

    // Pre-batch view: `merkle_paths ∪ prestate_read_proofs`, both proven against
    // `old_root_hash` (`merkle_paths` by the streaming fold below). A slot outside
    // it panics in `StorageSnapshot`, failing closed. Read proofs are needed even
    // with no net write: a rolled-back write is priced from the old value, and the
    // price shows through the pubdata counter.
    //
    // Declared key sets are ignored: they come from the legacy VM and overshoot
    // what FastVM reads.
    let mut storage = build_view_from_merkle_paths(&input.merkle_paths.merkle_paths)?;
    extend_view_with_read_proofs(
        &mut storage,
        std::mem::take(&mut input.prestate_read_proofs),
        old_root_hash,
    )?;
    #[cfg(feature = "legacy-unproven-gaps")]
    if policy == GapPolicy::LegacyUnprovenGaps {
        let witness_block_state = &input.vm_run_data.witness_block_state;
        for key in witness_block_state
            .read_storage_key
            .keys()
            .chain(witness_block_state.is_write_initial.keys())
        {
            storage.entry(key.hashed_key()).or_insert(None);
        }
    }

    // Verify user-contract bytecodes (factory_deps) match their claimed hashes.
    // VM-internal contracts (bootloader/default_aa/evm_emulator) are loaded from
    // system_env, not from factory_deps, so they're verified separately above.
    let factory_deps = input
        .vm_run_data
        .used_bytecodes
        .into_iter()
        .map(|(claimed_hash, words)| {
            let flat_bytes = words.into_flattened();
            verify_bytecode_hash(claimed_hash, &flat_bytes)?;
            Ok((u256_to_h256(claimed_hash), flat_bytes))
        })
        .collect::<anyhow::Result<std::collections::BTreeMap<H256, Vec<u8>>>>()?;

    let storage_snapshot = StorageSnapshot::new(storage, factory_deps);
    let storage_view = StorageView::new(storage_snapshot).to_rc_ptr();
    phase_marker(); // marker 1: end `setup`, begin `vm_execution`
    let vm = FastVerifierVm::fast(input.l1_batch_env, system_env, storage_view);

    let mut vm_out = execute_vm(
        input.l2_blocks_execution_data,
        vm,
        input.pubdata_params,
        protocol_version,
    )?;

    // `execute_vm` already enforced that batch finalization succeeded (rejecting a
    // `Halt`ed block tip), so `vm_out` here is a successfully-finalized batch.

    // Take fields out of vm_out before the streaming Merkle verification / bootloader-heap commitment consume the rest.
    // The tree-instructions path only reads final_execution_state.deduplicated_storage_logs.
    let system_logs = std::mem::take(&mut vm_out.final_execution_state.system_logs);
    let pubdata_input = vm_out.pubdata_input.take();
    let state_diffs = vm_out
        .state_diffs
        .take()
        .context("state_diffs missing from VM output — required for commitment")?;
    // The final bootloader memory is what the VM actually executed (initial layout
    // built from `l1_batch_env` + transactions, plus pubdata appended in-flight).
    // Hashing the witness's `vm_run_data.initial_heap_content` would let a malicious
    // proof commit a heap that was never executed; this comes from the VM itself.
    let final_bootloader_memory = vm_out.final_bootloader_memory.take().context(
        "VM output is missing final_bootloader_memory — required for the bootloader heap commitment",
    )?;

    phase_marker(); // marker 2: end `vm_execution`, begin `merkle_verification`
    let vm_logs = std::mem::take(&mut vm_out.final_execution_state.deduplicated_storage_logs);
    let prev_enumeration_index = enumeration_index; // = input.merkle_paths.next_enumeration_index()
                                                    // NOTE: do not wrap this call with `.with_context(...)`. It surfaces the
                                                    // classify / key-binding / fold errors directly, and callers (and the
                                                    // `fail_closed` regression tests) match on those inner messages via
                                                    // `err.to_string()`, which shows only the outermost context.
    let (new_root_hash, new_enumeration_index) = crate::merkle_witness::verify_paths_and_new_root(
        input.merkle_paths,
        vm_logs,
        old_root_hash,
        prev_enumeration_index,
    )?;

    let bootloader_memory_size = get_used_bootloader_memory_bytes(protocol_version.into());
    let expanded_heap = expand_bootloader_heap(&final_bootloader_memory, bootloader_memory_size);

    Ok(VmExecutionState {
        batch_number,
        protocol_version,
        old_root_hash,
        prev_enumeration_index,
        new_root_hash,
        new_enumeration_index,
        system_logs,
        state_diffs,
        pubdata_input,
        expanded_heap,
        zk_porter_available,
        bootloader_code_hash,
        default_aa_code_hash,
        evm_emulator_code_hash,
    })
}

/// Run commitment-input-dependent checks (zk_porter sanity, prev-batch binding,
/// blob verification) against the post-execution state, then compute the batch
/// commitment and the proof public input.
pub fn verify_commitment(
    state: VmExecutionState,
    commitment_input: CommitmentInput,
) -> anyhow::Result<VerificationResult> {
    phase_marker(); // marker 3: end `merkle_verification`, begin `commitment`
    anyhow::ensure!(
        state.zk_porter_available == zksync_system_constants::ZKPORTER_IS_AVAILABLE,
        "zk_porter_available from witness ({}) does not match the L1 chain constant ({}) — \
         the resulting commitment would never match L1 settlement",
        state.zk_porter_available,
        zksync_system_constants::ZKPORTER_IS_AVAILABLE,
    );

    // Verify that prev_batch_commitment is consistent with old_root_hash.
    // This binds the previous state root to the previous commitment inside the proof,
    // preventing a malicious operator from supplying a correct prev_batch_commitment
    // with a fake old_root_hash. Matches Boojum's scheduler circuit behavior.
    let prev_passthrough = commitment::compute_pass_through_data_hash(
        state.prev_enumeration_index,
        state.old_root_hash,
    );
    let expected_prev_commitment = commitment::compute_commitment(
        prev_passthrough,
        commitment_input.prev_meta_hash,
        commitment_input.prev_aux_hash,
    );
    anyhow::ensure!(
        expected_prev_commitment == commitment_input.prev_batch_commitment,
        "prev_batch_commitment binding failed: recomputed {expected_prev_commitment:?} \
         != claimed {:?}. old_root_hash={:?}, enumeration_index={}",
        commitment_input.prev_batch_commitment,
        state.old_root_hash,
        state.prev_enumeration_index,
    );

    // Verify blob hashes against pubdata produced by execution.
    //
    // Slots self-degenerate for non-Rollup DA modes the same way Boojum's
    // `EIP4844Repack` does: when a chain uses Validium / NoDA / external DA,
    // the L2 DA validator emits zero `linear_hash` for every slot.
    // `verify_blob_hashes` skips those slots — both checks trivially pass
    // while the auxiliary-output hash still includes the (zero) blob slots,
    // matching what L1 expects.
    //
    // Post-gateway VMs always populate `pubdata_input`; if it is missing
    // here, treat it as a malformed input.
    let pubdata = state
        .pubdata_input
        .as_deref()
        .context("VM output is missing pubdata_input — required for blob verification")?;
    commitment::verify_blob_hashes(
        pubdata,
        &commitment_input.blob_versioned_hashes,
        &commitment_input.blob_hashes,
    )?;

    let system_logs_hash = H256(keccak256(&serialize_commitments(&state.system_logs)));
    let state_diff_hash = H256(keccak256(&serialize_commitments(&state.state_diffs)));
    let bootloader_heap_hash = Blake2Hasher.hash_bytes(&state.expanded_heap);

    anyhow::ensure!(
        commitment_input.blob_hashes.len() == TOTAL_BLOBS_IN_COMMITMENT,
        "blob_hashes length mismatch: got {}, expected {TOTAL_BLOBS_IN_COMMITMENT}",
        commitment_input.blob_hashes.len()
    );

    // `to_bytes()` for `PostBoojum` ignores `common`, `state_diffs_compressed`,
    // `aggregation_root`, and `local_root`, so we fill them with zeros.
    let commitment = L1BatchCommitment {
        pass_through_data: L1BatchPassThroughData {
            shared_states: vec![
                RootState {
                    last_leaf_index: state.new_enumeration_index,
                    root_hash: state.new_root_hash,
                },
                // zkPorter shared state — reserved, always zero.
                RootState {
                    last_leaf_index: 0,
                    root_hash: H256::zero(),
                },
            ],
        },
        meta_parameters: L1BatchMetaParameters {
            zkporter_is_available: state.zk_porter_available,
            bootloader_code_hash: state.bootloader_code_hash,
            default_aa_code_hash: state.default_aa_code_hash,
            // For an emulator-disabled chain, commit an explicit `bytes32(0)` to
            // match L1. A bare `None` is not equivalent: `L1BatchMetaParameters::
            // to_bytes` substitutes `default_aa_code_hash` for `None`, which would
            // diverge from L1 and reject the honest proof. A chain with an emulator
            // passes its hash through unchanged.
            evm_emulator_code_hash: Some(state.evm_emulator_code_hash.unwrap_or_default()),
            protocol_version: Some(state.protocol_version),
        },
        auxiliary_output: L1BatchAuxiliaryOutput::PostBoojum {
            common: L1BatchAuxiliaryCommonOutput {
                l2_l1_logs_merkle_root: H256::zero(),
                protocol_version: state.protocol_version,
            },
            system_logs_linear_hash: system_logs_hash,
            state_diffs_compressed: vec![],
            state_diffs_hash: state_diff_hash,
            aux_commitments: AuxCommitments {
                // Post-Boojum commitments do not compute an events queue hash: the slot
                // is still serialized into the auxiliary output hash, but this pipeline
                // pins it to zero. Events are recoverable from the bound transaction
                // heap, system logs, state diffs, and blob hashes, so the legacy
                // commitment is left unused.
                events_queue_commitment: H256::zero(),
                bootloader_initial_content_commitment: bootloader_heap_hash,
            },
            blob_hashes: commitment_input.blob_hashes,
            aggregation_root: H256::zero(),
            local_root: H256::zero(),
        },
    };
    let hashes = commitment
        .hash()
        .expect("L1BatchCommitment with two RootStates always succeeds");
    let proof_public_input = commitment::compute_proof_public_input(
        commitment_input.prev_batch_commitment,
        hashes.commitment,
    );

    phase_marker(); // marker 4: end `commitment`
    Ok(VerificationResult {
        value_hash: state.new_root_hash,
        batch_number: state.batch_number,
        proof_public_input,
        commitment: hashes.commitment,
        new_enumeration_index: state.new_enumeration_index,
        pass_through_data_hash: hashes.pass_through_data,
        metadata_hash: hashes.meta_parameters,
        auxiliary_output_hash: hashes.aux_output,
        system_logs_hash,
        state_diff_hash,
        bootloader_heap_hash,
        system_logs: state.system_logs,
        state_diffs: state.state_diffs,
        pubdata_input: state.pubdata_input,
    })
}

/// Verify that a bytecode's content matches its claimed hash.
///
/// Dispatches on the marker byte via upstream `BytecodeHash::try_from`,
/// which validates the marker and exposes the encoded length so we don't
/// re-parse the hash by hand.
fn verify_bytecode_hash(claimed_hash: U256, flat_bytecode: &[u8]) -> anyhow::Result<()> {
    let claimed_h256 = u256_to_h256(claimed_hash);
    let claimed = BytecodeHash::try_from(claimed_h256)?;

    let computed = match claimed.marker() {
        BytecodeMarker::EraVm => BytecodeHash::for_bytecode(flat_bytecode),
        BytecodeMarker::Evm => {
            BytecodeHash::for_evm_bytecode(claimed.len_in_bytes(), flat_bytecode)
        }
    };

    anyhow::ensure!(
        computed == claimed,
        "bytecode hash mismatch: claimed {claimed_h256:?}, computed {:?}",
        computed.value(),
    );
    Ok(())
}

/// Executes the VM and returns `FinishedL1Batch` on success.
fn execute_vm<VM>(
    l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    mut vm: VM,
    pubdata_params: PubdataParams,
    protocol_version: ProtocolVersionId,
) -> anyhow::Result<FinishedL1Batch>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
{
    anyhow::ensure!(
        l2_blocks_execution_data
            .last()
            .is_none_or(|block| block.txs.is_empty()),
        "Last L2 block's txs are never executed; populating them is a malformed witness",
    );

    let next_l2_blocks_data = l2_blocks_execution_data.iter().skip(1);

    let l2_blocks_data = l2_blocks_execution_data.iter().zip(next_l2_blocks_data);

    for (l2_block_data, next_l2_block_data) in l2_blocks_data {
        tracing::trace!(
            "Started execution of l2_block: {:?}, executing {:?} transactions",
            l2_block_data.number,
            l2_block_data.txs.len(),
        );
        for tx in &l2_block_data.txs {
            tracing::trace!("Started execution of tx: {tx:?}");
            execute_tx(tx, &mut vm)
                .context("failed to execute transaction in AirbenderVerifierInputProducer")?;
            tracing::trace!("Finished execution of tx: {tx:?}");
        }

        tracing::trace!("finished l2_block {l2_block_data:?}");
        tracing::trace!("about to vm.start_new_l2_block {next_l2_block_data:?}");

        vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_l2_block_data));

        tracing::trace!("Finished execution of l2_block: {:?}", l2_block_data.number);
    }

    tracing::trace!("about to vm.finish_batch()");

    let finished = vm.finish_batch(pubdata_params_to_builder(pubdata_params, protocol_version));

    // The bootloader must have finalized the batch successfully. `finish_batch`
    // returns a `FinishedL1Batch` even when the batch-tip execution Halts, so
    // without this check we could commit a public input for a batch that canonical
    // execution would reject or never fully finalized.
    anyhow::ensure!(
        matches!(
            finished.block_tip_execution_result.result,
            ExecutionResult::Success { .. }
        ),
        "batch finalization did not succeed: {:?}",
        finished.block_tip_execution_result.result,
    );

    Ok(finished)
}

/// Map `LogQuery` and `TreeLogEntry` to a `TreeInstruction`. `key` is the
/// storage log's hashed key, passed in so the caller (which already computed it
/// to bind against `leaf_hashed_key`) doesn't hash it twice.
pub(crate) fn map_log_tree(
    key: U256,
    storage_log: &StorageLog,
    tree_log_entry: &TreeLogEntry,
    idx: &mut u64,
) -> anyhow::Result<TreeInstruction> {
    let tree_instruction = match (storage_log.is_write(), *tree_log_entry) {
        (true, TreeLogEntry::Updated { leaf_index, .. }) => {
            TreeInstruction::write(key, leaf_index, H256(storage_log.value.into()))
        }
        (true, TreeLogEntry::Inserted) => {
            let leaf_index = *idx;
            *idx += 1;
            TreeInstruction::write(key, leaf_index, H256(storage_log.value.into()))
        }
        (false, TreeLogEntry::Read { value, .. }) => {
            if storage_log.value != value {
                tracing::error!(
                    ?storage_log,
                    ?tree_log_entry,
                    "Failed to map LogQuery to TreeInstruction: read value {:#?} != {:#?}",
                    storage_log.value,
                    value
                );
                anyhow::bail!("Failed to map LogQuery to TreeInstruction");
            }
            TreeInstruction::Read(key)
        }
        (false, TreeLogEntry::ReadMissingKey) => TreeInstruction::Read(key),
        (true, TreeLogEntry::Read { .. })
        | (true, TreeLogEntry::ReadMissingKey)
        | (false, TreeLogEntry::Inserted)
        | (false, TreeLogEntry::Updated { .. }) => {
            tracing::error!(
                ?storage_log,
                ?tree_log_entry,
                "Failed to map LogQuery to TreeInstruction"
            );
            anyhow::bail!("Failed to map LogQuery to TreeInstruction");
        }
    };

    Ok(tree_instruction)
}

/// Generates the `TreeInstruction`s from the VM executions.
///
/// Superseded in production by `merkle_witness::verify_paths_and_new_root`
/// (the streaming pass); kept as part of the differential-test oracle
/// (`get_bowp` + this + `verify_proofs` + `root_hash()`) — see
/// `merkle_witness::streaming_tests`.
#[cfg_attr(not(test), allow(dead_code))]
fn generate_tree_instructions(
    mut idx: u64,
    bowp: &BlockOutputWithProofs,
    leaf_keys: &[U256],
    vm_logs: Vec<StorageLog>,
) -> anyhow::Result<Vec<TreeInstruction>> {
    anyhow::ensure!(
        vm_logs.len() == bowp.logs.len() && bowp.logs.len() == leaf_keys.len(),
        "VM deduplicated storage logs count mismatch with merkle proofs: vm_logs={}, merkle_logs={}",
        vm_logs.len(),
        bowp.logs.len(),
    );

    vm_logs
        .into_iter()
        .zip(bowp.logs.iter())
        .zip(leaf_keys.iter())
        .map(|((log_query, tree_log_entry), &leaf_hashed_key)| {
            // Bind the proof to the slot the VM actually touched: the Merkle path
            // is verified against `vm_key`, but the storage view was seeded by
            // `leaf_hashed_key`. If they differ, the operator could prove a write
            // against one slot's real pre-state while having fed the VM a forged
            // value for that slot (served empty via the gap fallback). They must
            // refer to the same slot.
            let vm_key = log_query.key.hashed_key_u256();
            anyhow::ensure!(
                leaf_hashed_key == vm_key,
                "merkle_paths leaf_hashed_key {leaf_hashed_key:?} does not match \
                 VM storage-log key {vm_key:?}",
            );
            map_log_tree(vm_key, &log_query, &tree_log_entry.base, &mut idx)
        })
        .collect::<Result<Vec<_>, _>>()
}

fn execute_tx<VM>(tx: &Transaction, vm: &mut VM) -> anyhow::Result<()>
where
    VM: VmInterfaceHistoryEnabled + VmInterfaceExt,
{
    // Attempt to run VM with bytecode compression on.
    vm.make_snapshot();
    let (compression, result) = vm.execute_transaction_with_bytecode_compression(tx.clone(), true);
    if compression.is_ok() {
        // The compression result and the execution result are independent: a tx
        // can compress fine yet root-level `Halt`. A `Halt` means the bootloader
        // could not execute the tx, so accepting it would commit a post-failure
        // VM state. (A `Revert` is a normal committed outcome and is kept.)
        ensure_not_halted(&result.result)?;
        vm.pop_snapshot_no_rollback();
        return Ok(());
    }

    // If failed with bytecode compression, attempt to run without bytecode compression.
    vm.rollback_to_the_latest_snapshot();
    let (compression, result) = vm.execute_transaction_with_bytecode_compression(tx.clone(), false);
    if compression.is_err() {
        anyhow::bail!("compression can't fail if we don't apply it");
    }
    ensure_not_halted(&result.result)?;
    Ok(())
}

/// Reject a transaction whose bootloader execution `Halt`ed. A sealed batch's
/// transactions were accepted by the sequencer, so a `Halt` on re-execution means
/// the witness diverges from canonical execution — committing it would attest to
/// a batch that never validly executed.
fn ensure_not_halted(result: &ExecutionResult) -> anyhow::Result<()> {
    if let ExecutionResult::Halt { reason } = result {
        anyhow::bail!("transaction halted during re-execution: {reason}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::types::SystemEnvInput;
    use airbender_codec::{AirbenderCodec, AirbenderCodecV0};
    use zksync_contracts::{BaseSystemContracts, SystemContractCode};
    use zksync_multivm::interface::{L1BatchEnv, TxExecutionMode};
    use zksync_types::{
        commitment::{BlobHash, L2DACommitmentScheme, L2PubdataValidator, PubdataParams},
        settlement::SettlementLayer,
        Address,
    };

    use super::*;
    use crate::commitment::ZK_SYNC_BYTES_PER_BLOB;
    use crate::merkle_witness::{classify_witness_leaf, WitnessLeaf};
    use crate::types::{
        AirbenderVerifierInput, StorageLogMetadata, VMRunWitnessInputData, WitnessInputMerklePaths,
    };

    fn key(n: u64) -> zksync_types::StorageKey {
        use zksync_types::{AccountTreeId, Address};
        zksync_types::StorageKey::new(
            AccountTreeId::new(Address::from_low_u64_be(n)),
            H256::zero(),
        )
    }

    fn meta(
        key: zksync_types::StorageKey,
        is_write: bool,
        first_write: bool,
        leaf_enumeration_index: u64,
        value_read: H256,
    ) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: [0u8; 32],
            is_write,
            first_write,
            merkle_paths: vec![],
            leaf_hashed_key: key.hashed_key_u256(),
            leaf_enumeration_index,
            value_written: [0u8; 32],
            value_read: value_read.0,
        }
    }

    #[test]
    fn classify_rejects_read_marked_first_write() {
        assert!(classify_witness_leaf(&meta(key(1), false, true, 0, H256::zero())).is_err());
    }

    #[test]
    fn classify_rejects_repeated_write_zero_index() {
        assert!(classify_witness_leaf(&meta(key(2), true, false, 0, H256::zero())).is_err());
    }

    #[test]
    fn classify_maps_existing_read() {
        let v = H256::from_low_u64_be(0x9);
        match classify_witness_leaf(&meta(key(3), false, false, 7, v)).unwrap() {
            WitnessLeaf::Existing {
                is_write,
                index,
                value,
            } => {
                assert!(!is_write);
                assert_eq!(index, 7);
                assert_eq!(value, v);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn classify_maps_empty_first_write() {
        assert!(matches!(
            classify_witness_leaf(&meta(key(4), true, true, 0, H256::zero())).unwrap(),
            WitnessLeaf::Empty { is_write: true }
        ));
    }

    #[test]
    fn get_bowp_rejects_repeated_write_with_zero_index() {
        let mut paths = WitnessInputMerklePaths::new(1);
        paths.push_merkle_path(meta(key(0x3001), true, false, 0, H256::zero()));
        assert!(get_bowp(paths).is_err());
    }

    #[test]
    fn get_bowp_rejects_read_marked_first_write() {
        let mut paths = WitnessInputMerklePaths::new(1);
        paths.push_merkle_path(meta(key(0x3002), false, true, 0, H256::zero()));
        assert!(get_bowp(paths).is_err());
    }

    #[test]
    fn absent_evm_emulator_commits_zero_not_default_aa() {
        // For an emulator-disabled chain, `verify_commitment` sets the metadata's
        // EVM-emulator hash to an explicit zero (`Some(state.evm_emulator_code_hash
        // .unwrap_or_default())` when the state's value is `None` —
        // `H256::default() == H256::zero()`). `L1BatchMetaParameters::to_bytes` must
        // then serialize zero — matching L1 — and NOT fall back to
        // `default_aa_code_hash` (its behavior for a bare `None`).
        let default_aa = H256::repeat_byte(0xAB);
        let meta = L1BatchMetaParameters {
            zkporter_is_available: false,
            bootloader_code_hash: H256::repeat_byte(0x11),
            default_aa_code_hash: default_aa,
            // What `verify_commitment` emits when `state.evm_emulator_code_hash` is `None`.
            evm_emulator_code_hash: Some(H256::zero()),
            protocol_version: Some(ProtocolVersionId::Version27), // post-1.5.0
        };
        let bytes = meta.to_bytes();
        let slot = &bytes[bytes.len() - 32..];
        assert_eq!(slot, [0u8; 32], "absent emulator must serialize as zero");
        assert_ne!(
            slot,
            default_aa.as_bytes(),
            "must not fall back to default_aa"
        );
    }

    #[test]
    fn test_verify_bytecode_hash_valid() {
        let bytecode = vec![0u8; 32];
        let hash = BytecodeHash::for_bytecode(&bytecode);
        verify_bytecode_hash(hash.value_u256(), &bytecode).unwrap();
    }

    #[test]
    fn ensure_not_halted_rejects_only_halt() {
        use zksync_multivm::interface::VmRevertReason;
        // Success and Revert are valid committed outcomes.
        ensure_not_halted(&ExecutionResult::Success { output: vec![] }).unwrap();
        ensure_not_halted(&ExecutionResult::Revert {
            output: VmRevertReason::VmError,
        })
        .unwrap();
        // A root-level Halt must be rejected.
        assert!(ensure_not_halted(&ExecutionResult::Halt {
            reason: Halt::FromIsNotAnAccount,
        })
        .is_err());
    }

    use zksync_multivm::interface::Halt;

    /// Minimal VM that drives `execute_tx`/`execute_vm` to the halt-rejection
    /// paths without needing a real (halting) batch.
    /// - `Tx`: the first (with-compression) attempt halts → `execute_tx` Path A.
    /// - `RetryHalt`: the first attempt's *compression* fails (forcing a rollback +
    ///   no-compression retry), and the retry halts → `execute_tx` Path B.
    /// - `BlockTip`: txs succeed but the batch tip halts at `finish_batch`.
    #[derive(Clone, Copy)]
    enum HaltAt {
        Tx,
        RetryHalt,
        BlockTip,
    }

    struct HaltMockVm {
        halt_at: HaltAt,
        /// Number of `inspect_transaction_with_bytecode_compression` calls so far
        /// (so `RetryHalt` can fail the first attempt and halt the second).
        calls: u32,
    }

    impl zksync_multivm::interface::VmInterface for HaltMockVm {
        type TracerDispatcher = ();

        fn push_transaction(
            &mut self,
            _tx: Transaction,
        ) -> zksync_multivm::interface::PushTransactionResult<'_> {
            unimplemented!("unused by execute_tx/execute_vm")
        }

        fn inspect(
            &mut self,
            _: &mut Self::TracerDispatcher,
            _: zksync_multivm::interface::InspectExecutionMode,
        ) -> zksync_multivm::interface::VmExecutionResultAndLogs {
            unimplemented!("unused by execute_tx/execute_vm")
        }

        fn start_new_l2_block(&mut self, _: L2BlockEnv) {}

        fn inspect_transaction_with_bytecode_compression(
            &mut self,
            _: &mut Self::TracerDispatcher,
            _tx: Transaction,
            _with_compression: bool,
        ) -> (
            zksync_multivm::interface::BytecodeCompressionResult<'_>,
            zksync_multivm::interface::VmExecutionResultAndLogs,
        ) {
            use zksync_multivm::interface::BytecodeCompressionError;
            self.calls += 1;
            // `RetryHalt` fails compression on the first attempt so `execute_tx`
            // rolls back and retries without compression (Path B); that retry
            // halts. Otherwise compression succeeds and the result is independent
            // (a tx can compress fine yet `Halt`).
            let compression = if matches!(self.halt_at, HaltAt::RetryHalt) && self.calls == 1 {
                Err(BytecodeCompressionError::BytecodeCompressionFailed)
            } else {
                Ok(std::borrow::Cow::Borrowed(&[][..]))
            };
            let result = match self.halt_at {
                HaltAt::Tx => ExecutionResult::Halt {
                    reason: Halt::FromIsNotAnAccount,
                },
                // First call is the failed-compression attempt (result ignored
                // since compression is `Err`); the retry halts.
                HaltAt::RetryHalt => ExecutionResult::Halt {
                    reason: Halt::FromIsNotAnAccount,
                },
                HaltAt::BlockTip => ExecutionResult::Success { output: vec![] },
            };
            (
                compression,
                zksync_multivm::interface::VmExecutionResultAndLogs::new(result),
            )
        }

        fn finish_batch(
            &mut self,
            _: std::rc::Rc<dyn zksync_multivm::interface::pubdata::PubdataBuilder>,
        ) -> FinishedL1Batch {
            let block_tip = match self.halt_at {
                HaltAt::BlockTip => ExecutionResult::Halt {
                    reason: Halt::FromIsNotAnAccount,
                },
                // These variants halt at the tx, not the tip; `finish_batch` isn't
                // reached in their tests, but the match must stay exhaustive.
                HaltAt::Tx | HaltAt::RetryHalt => ExecutionResult::Success { output: vec![] },
            };
            FinishedL1Batch {
                block_tip_execution_result:
                    zksync_multivm::interface::VmExecutionResultAndLogs::new(block_tip),
                final_execution_state: zksync_multivm::interface::CurrentExecutionState {
                    events: vec![],
                    deduplicated_storage_logs: vec![],
                    used_contract_hashes: vec![],
                    system_logs: vec![],
                    user_l2_to_l1_logs: vec![],
                    storage_refunds: vec![],
                    pubdata_costs: vec![],
                },
                final_bootloader_memory: None,
                pubdata_input: None,
                state_diffs: None,
            }
        }
    }

    impl zksync_multivm::interface::VmInterfaceHistoryEnabled for HaltMockVm {
        fn make_snapshot(&mut self) {}
        fn rollback_to_the_latest_snapshot(&mut self) {}
        fn pop_snapshot_no_rollback(&mut self) {}
        fn pop_front_snapshot_no_rollback(&mut self) {}
    }

    fn dummy_l1_tx() -> Transaction {
        use zksync_types::{l1::L1TxCommonData, Execute, ExecuteTransactionCommon};
        Transaction {
            common_data: ExecuteTransactionCommon::L1(L1TxCommonData::default()),
            execute: Execute::default(),
            received_timestamp_ms: 0,
            raw_bytes: None,
        }
    }

    // e2e: a tx whose bootloader execution `Halt`s must be rejected by `execute_tx`
    // on the with-compression path (Path A), even though the (independent)
    // bytecode-compression result is `Ok`.
    #[test]
    fn execute_tx_rejects_halted_transaction() {
        let mut vm = HaltMockVm {
            halt_at: HaltAt::Tx,
            calls: 0,
        };
        let err = execute_tx(&dummy_l1_tx(), &mut vm).unwrap_err();
        assert!(
            err.to_string().contains("halted during re-execution"),
            "unexpected error: {err}"
        );
    }

    // e2e: the first (with-compression) attempt fails compression, so `execute_tx`
    // rolls back and retries without compression — and that retry `Halt`s. The
    // second `ensure_not_halted` (Path B) must reject it.
    #[test]
    fn execute_tx_rejects_halt_on_uncompressed_retry() {
        let mut vm = HaltMockVm {
            halt_at: HaltAt::RetryHalt,
            calls: 0,
        };
        let err = execute_tx(&dummy_l1_tx(), &mut vm).unwrap_err();
        assert_eq!(vm.calls, 2, "should have retried without compression");
        assert!(
            err.to_string().contains("halted during re-execution"),
            "unexpected error: {err}"
        );
    }

    // e2e: txs succeed but the batch tip `Halt`s at `finish_batch`; `execute_vm`
    // must reject the batch. An empty block list reaches `finish_batch` directly.
    #[test]
    fn execute_vm_rejects_halted_block_tip() {
        let vm = HaltMockVm {
            halt_at: HaltAt::BlockTip,
            calls: 0,
        };
        let err = execute_vm(
            vec![],
            vm,
            PubdataParams::genesis(),
            PINNED_PROTOCOL_VERSION,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("batch finalization did not succeed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_bytecode_hash_tampered() {
        let bytecode = vec![0u8; 32];
        let hash = BytecodeHash::for_bytecode(&bytecode);
        let mut tampered = bytecode.clone();
        tampered[0] = 0xFF;
        let err = verify_bytecode_hash(hash.value_u256(), &tampered).unwrap_err();
        assert!(
            err.to_string().contains("bytecode hash mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_bytecode_hash_unknown_marker() {
        let bytecode = vec![0u8; 32];
        // Construct a hash with marker = 0xFF (unknown).
        let mut fake_hash = [0u8; 32];
        fake_hash[0] = 0xFF;
        let err = verify_bytecode_hash(U256::from_big_endian(&fake_hash), &bytecode).unwrap_err();
        assert!(
            err.to_string().contains("unknown bytecode hash marker"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_blob_hashes_linear_tampered() {
        // Wrong linear hash → fails on linear check before commitment check.
        let pubdata = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash: H256([0xFF; 32]),
            commitment: H256::zero(),
        };
        let versioned_hashes = vec![H256::zero(); 16];
        let err =
            commitment::verify_blob_hashes(&pubdata, &versioned_hashes, &blob_hashes).unwrap_err();
        assert!(
            err.to_string().contains("linear hash mismatch"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_verify_blob_hashes_no_pubdata() {
        // Non-zero claim but no pubdata → fails before hash checks.
        let pubdata = vec![];
        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash: H256([0xFF; 32]),
            commitment: H256::zero(),
        };
        let versioned_hashes = vec![H256::zero(); 16];
        let err =
            commitment::verify_blob_hashes(&pubdata, &versioned_hashes, &blob_hashes).unwrap_err();
        assert!(err.to_string().contains("no pubdata"), "unexpected: {err}");
    }

    #[test]
    fn test_verify_blob_hashes_valid() {
        use crate::commitment::{verify_blob_hashes, ZK_SYNC_BYTES_PER_BLOB};
        use ark_bls12_381::Fr as Bls12_381Fr;
        use ark_ff::{BigInteger, PrimeField, Zero};

        // Create deterministic blob data.
        let mut blob_data = vec![0u8; ZK_SYNC_BYTES_PER_BLOB];
        for (i, b) in blob_data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        // Compute linear_hash = keccak256(blob_data).
        let linear_hash = H256(keccak256(&blob_data));

        // Create a fake versioned_hash (would normally come from KZG commitment).
        let mut versioned_hash = H256(keccak256(b"test_versioned_hash"));
        versioned_hash.0[0] = 0x01; // EIP-4844 version byte

        // Step 1: Parse polynomial (same logic as verify_blob_hashes).
        let poly: Vec<Bls12_381Fr> = blob_data
            .chunks(31)
            .rev()
            .map(|chunk| {
                let mut buf = [0u8; 32];
                buf[..chunk.len()].copy_from_slice(chunk);
                Bls12_381Fr::from_le_bytes_mod_order(&buf)
            })
            .collect();

        // Step 2: Compute evaluation_point.
        let eval_point_hash = {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(linear_hash.as_bytes());
            preimage.extend_from_slice(versioned_hash.as_bytes());
            keccak256(&preimage)
        };
        let mut eval_point_bytes = [0u8; 32];
        eval_point_bytes[16..32].copy_from_slice(&eval_point_hash[16..32]);
        let evaluation_point = Bls12_381Fr::from_be_bytes_mod_order(&eval_point_bytes);

        // Step 3: Evaluate polynomial (Horner's rule).
        let mut opening_value = Bls12_381Fr::zero();
        for coeff in poly.iter().rev() {
            opening_value *= evaluation_point;
            opening_value += coeff;
        }

        // Step 4: Serialize opening value.
        let opening_value_bytes = {
            let repr = opening_value.into_bigint();
            let be = repr.to_bytes_be();
            let mut buf = [0u8; 32];
            for (j, b) in be.iter().enumerate() {
                if j < 32 {
                    buf[j] = *b;
                }
            }
            buf
        };

        // Step 5: Compute output_hash.
        let output_hash = {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(versioned_hash.as_bytes());
            preimage.extend_from_slice(&eval_point_hash[16..32]);
            preimage.extend_from_slice(&opening_value_bytes);
            H256(keccak256(&preimage))
        };

        // Now verify — should pass.
        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash,
            commitment: output_hash,
        };
        let mut versioned_hashes = vec![H256::zero(); 16];
        versioned_hashes[0] = versioned_hash;

        verify_blob_hashes(&blob_data, &versioned_hashes, &blob_hashes).unwrap();
    }

    #[test]
    fn test_verify_blob_hashes_commitment_tampered() {
        use crate::commitment::{verify_blob_hashes, ZK_SYNC_BYTES_PER_BLOB};

        let blob_data = vec![0xAB_u8; ZK_SYNC_BYTES_PER_BLOB];
        let linear_hash = H256(keccak256(&blob_data));
        let versioned_hash = H256([0x01; 32]);

        let mut blob_hashes = vec![BlobHash::default(); 16];
        blob_hashes[0] = BlobHash {
            linear_hash,
            commitment: H256([0xFF; 32]), // wrong commitment
        };
        let mut versioned_hashes = vec![H256::zero(); 16];
        versioned_hashes[0] = versioned_hash;

        let err = verify_blob_hashes(&blob_data, &versioned_hashes, &blob_hashes).unwrap_err();
        assert!(
            err.to_string().contains("opening commitment mismatch"),
            "unexpected: {err}"
        );
    }

    fn sample_vm_run_data() -> VMRunWitnessInputData {
        VMRunWitnessInputData {
            l1_batch_number: Default::default(),
            used_bytecodes: Default::default(),
            initial_heap_content: vec![],
            bootloader_code: vec![],
            default_account_code_hash: Default::default(),
            evm_emulator_code_hash: Some(Default::default()),
            storage_refunds: vec![],
            pubdata_costs: vec![],
            witness_block_state: Default::default(),
        }
    }

    fn sample_first_l2_block() -> L2BlockEnv {
        L2BlockEnv {
            number: 0,
            timestamp: 0,
            prev_block_hash: H256([1; 32]),
            max_virtual_blocks_to_create: 0,
            interop_roots: vec![],
        }
    }

    // `_version` feeds the calibration flavour's wire field only; the
    // production `SystemEnvInput` cannot hold a version at all.
    fn sample_system_env(_version: ProtocolVersionId) -> SystemEnvInput {
        SystemEnvInput {
            zk_porter_available: false,
            #[cfg(feature = "cycle-markers")]
            version: _version,
            base_system_smart_contracts: BaseSystemContracts {
                bootloader: SystemContractCode {
                    code: vec![1; 32],
                    hash: H256([1; 32]),
                },
                default_aa: SystemContractCode {
                    code: vec![1; 32],
                    hash: H256([1; 32]),
                },
                evm_emulator: None,
            },
            bootloader_gas_limit: 0,
            execution_mode: TxExecutionMode::VerifyExecute,
            default_validation_computational_gas_limit: 0,
            chain_id: Default::default(),
        }
    }

    /// The composition gap behind `upgrade_id`'s former strict codec: the first
    /// batch of a new minor carries an upgrade tx naming that minor, so the whole
    /// payload aborted inside serde before anything could report it — this is a
    /// protocol minor *inside a transaction*, not a top-level label.
    #[test]
    fn payload_with_unnameable_upgrade_tx_minor_decodes() {
        use zksync_types::protocol_upgrade::ProtocolUpgradeTxCommonData;
        use zksync_types::protocol_version::{ProtocolUpgradeId, MAX_KNOWN_PROTOCOL_VERSION};
        use zksync_types::{Execute, ExecuteTransactionCommon, Transaction};

        let raw = MAX_KNOWN_PROTOCOL_VERSION as u16 + 1;
        assert!(
            ProtocolVersionId::try_from(raw).is_err(),
            "pick a minor this build cannot name"
        );

        let mut input = sample_payload(
            PINNED_PROTOCOL_VERSION,
            L2PubdataValidator::Address(H256::zero().into()),
        );
        input.l2_blocks_execution_data = vec![L2BlockExecutionData {
            number: Default::default(),
            timestamp: 0,
            prev_block_hash: H256::zero(),
            virtual_blocks: 0,
            txs: vec![Transaction {
                common_data: ExecuteTransactionCommon::ProtocolUpgrade(
                    ProtocolUpgradeTxCommonData {
                        upgrade_id: ProtocolUpgradeId::from(raw),
                        ..Default::default()
                    },
                ),
                execute: Execute::default(),
                received_timestamp_ms: 0,
                raw_bytes: None,
            }],
            interop_roots: vec![],
        }];

        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&input, cfg).expect("encode");
        let (decoded, read) =
            bincode::serde::decode_from_slice::<AirbenderVerifierInput, _>(&bytes, cfg)
                .expect("the whole payload must decode");
        assert_eq!(read, bytes.len(), "trailing bytes");

        let ExecuteTransactionCommon::ProtocolUpgrade(common) =
            &decoded.l2_blocks_execution_data[0].txs[0].common_data
        else {
            panic!("expected a protocol-upgrade tx");
        };
        assert_eq!(common.upgrade_id.raw(), raw, "upgrade_id must be lossless");
    }

    fn sample_payload(
        version: ProtocolVersionId,
        pubdata_validator: L2PubdataValidator,
    ) -> AirbenderVerifierInput {
        AirbenderVerifierInput {
            vm_run_data: sample_vm_run_data(),
            merkle_paths: WitnessInputMerklePaths::new(0),
            l2_blocks_execution_data: vec![],
            l1_batch_env: L1BatchEnv {
                previous_batch_hash: Some(H256([1; 32])),
                number: Default::default(),
                timestamp: 0,
                fee_input: Default::default(),
                interop_fee: U256::zero(),
                fee_account: Default::default(),
                enforced_base_fee: None,
                first_l2_block: sample_first_l2_block(),
                settlement_layer: SettlementLayer::default(),
            },
            system_env: sample_system_env(version),
            pubdata_params: PubdataParams::new(pubdata_validator, Default::default()).unwrap(),
            commitment_input: None,
            prestate_read_proofs: vec![],
        }
    }

    /// Canonical v31 fixture: post-medium-interop protocol with the
    /// `CommitmentScheme` validator.
    fn sample_input() -> AirbenderVerifierInput {
        sample_payload(
            ProtocolVersionId::Version31,
            L2PubdataValidator::CommitmentScheme(L2DACommitmentScheme::BlobsAndPubdataKeccak256),
        )
    }

    /// Pins the bincode wire so future struct changes can't silently alter the
    /// on-disk corpus layout. Uses the same bincode config (`bincode 2`, varint
    /// `standard()`) that `cli_utils::load_batch` decodes against.
    #[test]
    fn test_serialization_roundtrip() {
        let input = sample_input();
        let bytes =
            bincode::serde::encode_to_vec(&input, bincode::config::standard()).expect("serialize");
        let (decoded, _): (AirbenderVerifierInput, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                .expect("deserialize");
        assert_eq!(input, decoded);
    }

    /// `execute` calls its FastVM invariant static in a shipped build; this is
    /// the change detector that keeps it one.
    #[test]
    fn pinned_version_is_supported_by_fast_vm() {
        assert!(is_supported_by_fast_vm(PINNED_PROTOCOL_VERSION));
    }

    /// Change detector for the pin's VALUE — nothing else asserts it, and
    /// `pinned_version_is_supported_by_fast_vm` passes for 34 and 35 alike, so
    /// a stray bump would otherwise sail through CI.
    #[test]
    fn pinned_protocol_version_is_v34() {
        assert_eq!(
            PINNED_PROTOCOL_VERSION,
            ProtocolVersionId::Version34,
            "the pin moved: a guest-semantics change — re-read the bump policy, \
             re-audit the version-gated decisions, and expect a new VK"
        );
    }

    /// The pubdata-validator guard above is evaluated at the pin's
    /// `is_pre_medium_interop`. Couple them so a pin or label floor below it
    /// cannot invert that guard silently.
    #[test]
    fn pin_is_post_medium_interop() {
        assert!(OLDEST_PROVABLE_LABEL <= PINNED_PROTOCOL_VERSION);
        assert!(!OLDEST_PROVABLE_LABEL.is_pre_medium_interop());
        assert!(
            !PINNED_PROTOCOL_VERSION.is_pre_medium_interop(),
            "the pin dropped below the medium-interop boundary; `execute` now \
             expects the Address validator and refuses every CommitmentScheme batch"
        );
    }

    /// The types cannot express a version, so there is nothing to strip: this
    /// pins the sample's wire bytes instead, which a version field would move.
    #[cfg(not(feature = "cycle-markers"))]
    #[test]
    fn version_fields_are_absent_from_the_production_wire() {
        /// `encode_to_vec(&sample_input(), standard()).len()`.
        const GOLDEN_SAMPLE_WIRE_LEN: usize = 496;
        /// `keccak256` of those bytes, lowercase hex.
        const GOLDEN_SAMPLE_WIRE_KECCAK: &str =
            "53dea500614658c821e683c5be0d0b4e2fadff45952658ab5a0cd5749d70e905";

        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(sample_input(), cfg).expect("encode");
        assert_eq!(bytes.len(), GOLDEN_SAMPLE_WIRE_LEN, "wire length moved");
        assert_eq!(
            format!("{:x}", H256(keccak256(&bytes))),
            GOLDEN_SAMPLE_WIRE_KECCAK,
            "wire bytes moved"
        );

        let (decoded, read) =
            bincode::serde::decode_from_slice::<AirbenderVerifierInput, _>(&bytes, cfg)
                .expect("decode");
        assert_eq!(read, bytes.len(), "trailing bytes");
        assert_eq!(decoded, sample_input(), "round trip");
    }

    /// The calibration wire keeps `system_env.version` (the `vm_run_data`
    /// mirror is deleted in all flavours); its corpus (older minors measured
    /// under their own semantics) must round-trip it losslessly.
    #[cfg(feature = "cycle-markers")]
    #[test]
    fn version_fields_survive_the_calibration_wire() {
        let cfg = bincode::config::standard();
        let mut input = sample_input();
        input.system_env.version = ProtocolVersionId::Version29;

        let bytes = bincode::serde::encode_to_vec(&input, cfg).expect("encode");
        let (decoded, read) =
            bincode::serde::decode_from_slice::<AirbenderVerifierInput, _>(&bytes, cfg)
                .expect("decode");
        assert_eq!(read, bytes.len(), "trailing bytes");
        assert_eq!(decoded.system_env.version, ProtocolVersionId::Version29);
    }

    /// Only the calibration flavour can express a version on the input at all;
    /// there the FastVM guard is load-bearing (the wire chooses the version).
    #[cfg(feature = "cycle-markers")]
    #[test]
    fn execute_rejects_version_unsupported_by_fast_vm() {
        let mut input = fastvm_input_with_execution_mode(TxExecutionMode::VerifyExecute);
        // Version23 maps to `Vm1_5_0SmallBootloaderMemory`, which the FastVM does
        // not implement. The guard fires before any of the `vm_run_data`
        // cross-checks, so the otherwise-minimal input is never run.
        input.system_env.version = ProtocolVersionId::Version23;
        // `VmExecutionState` isn't `Debug`, so match rather than `unwrap_err`.
        let err = match execute(input) {
            Ok(_) => panic!("expected the FastVM guard to reject Version23"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("is not supported by the FastVM verifier"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn execute_rejects_enforced_base_fee() {
        let mut input = fastvm_input_with_execution_mode(TxExecutionMode::VerifyExecute);
        // A proved batch must leave `enforced_base_fee` None; `Some(_)` is rejected.
        input.l1_batch_env.enforced_base_fee = Some(42);
        let err = match execute(input) {
            Ok(_) => panic!("expected the enforced_base_fee pin to reject Some(_)"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("enforced_base_fee must be None"),
            "unexpected error: {err}"
        );
    }

    /// Pins the host↔guest channel wire: inputs cross into the guest encoded
    /// with `AirbenderCodecV0`.
    #[test]
    fn test_codec_roundtrip() {
        let input = sample_input();
        let serialized =
            AirbenderCodecV0::encode(&input).expect("Failed to serialize AirbenderVerifierInput.");
        let deserialized: AirbenderVerifierInput = AirbenderCodecV0::decode(&serialized)
            .expect("Failed to deserialize AirbenderVerifierInput.");
        assert_eq!(input, deserialized);
    }

    // A pre-medium-interop version paired with a `CommitmentScheme` validator is
    // unrepresentable in production: the input types carry no version, so the
    // guard always evaluates at the (post-medium) pin. Only the post-medium
    // direction below remains reachable.

    /// The opposite mismatch panics too (`l2_da_commitment_scheme().expect`
    /// in the post-interop bootloader branch) and is reachable through the
    /// legacy-field JSON leniency on `PubdataParams`; `execute` must reject
    /// it the same way.
    #[test]
    fn test_execute_rejects_address_validator_post_medium_interop() {
        let payload = sample_payload(
            ProtocolVersionId::Version31,
            L2PubdataValidator::Address(Address::zero()),
        );
        let err = match execute(payload) {
            Ok(_) => panic!("execute accepted a post-medium-interop Address validator"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("incompatible with L2 pubdata validator"),
            "unexpected: {err}"
        );
    }

    /// Minimal input on the target version, valid enough to reach the early
    /// `system_env` checks in `execute()` (it errors out there, before any VM run,
    /// so the otherwise-empty witness is fine). The validator/protocol combination
    /// is kept consistent so the pubdata-validator guard passes.
    fn fastvm_input_with_execution_mode(mode: TxExecutionMode) -> AirbenderVerifierInput {
        let mut input = sample_payload(
            PINNED_PROTOCOL_VERSION,
            L2PubdataValidator::CommitmentScheme(L2DACommitmentScheme::BlobsAndPubdataKeccak256),
        );
        input.system_env.execution_mode = mode;
        input
    }

    #[test]
    fn execute_rejects_non_verify_execute_mode() {
        for mode in [TxExecutionMode::EstimateFee, TxExecutionMode::EthCall] {
            let mode_str = format!("{mode:?}");
            let err = match execute(fastvm_input_with_execution_mode(mode)) {
                Ok(_) => panic!("{mode_str} should have been rejected"),
                Err(e) => e,
            };
            assert!(
                err.to_string()
                    .contains("execution_mode must be VerifyExecute"),
                "{mode_str}: unexpected error: {err}"
            );
        }
    }

    /// Exercises the binding logic with non-zero `prev_meta_hash` / `prev_aux_hash`:
    /// a claimed `prev_batch_commitment` recomputed from consistent inputs must
    /// match, and tampering with any input must cause a mismatch (which
    /// `verify_with_vm` turns into an error via `anyhow::ensure!`).
    #[test]
    fn view_from_merkle_paths_maps_prestate() {
        let read = key(0x11);
        let updated = key(0x12);
        let inserted = key(0x13);
        let missing = key(0x14);
        let v = H256::from_low_u64_be(0x9);
        let v2 = H256::from_low_u64_be(0xA);
        let paths = vec![
            meta(read, false, false, 7, v),
            meta(updated, true, false, 9, v2),
            meta(inserted, true, true, 0, H256::zero()),
            meta(missing, false, false, 0, H256::zero()),
        ];
        let view = build_view_from_merkle_paths(&paths).unwrap();
        assert_eq!(view.get(&read.hashed_key()), Some(&Some((v, 7))));
        assert_eq!(view.get(&updated.hashed_key()), Some(&Some((v2, 9))));
        assert_eq!(view.get(&inserted.hashed_key()), Some(&None));
        assert_eq!(view.get(&missing.hashed_key()), Some(&None));
    }

    #[test]
    fn view_from_merkle_paths_rejects_conflicting_duplicate() {
        let k = key(0x15);
        let paths = vec![
            meta(k, false, false, 7, H256::from_low_u64_be(1)),
            meta(k, false, false, 7, H256::from_low_u64_be(2)),
        ];
        assert!(build_view_from_merkle_paths(&paths).is_err());
    }

    #[test]
    fn view_from_merkle_paths_accepts_consistent_duplicate() {
        let k = key(0x16);
        let v = H256::from_low_u64_be(3);
        let paths = vec![meta(k, false, false, 7, v), meta(k, true, false, 7, v)];
        let view = build_view_from_merkle_paths(&paths).unwrap();
        assert_eq!(view.get(&k.hashed_key()), Some(&Some((v, 7))));
    }

    #[test]
    fn test_prev_commitment_binding_rejects_mismatch() {
        use crate::commitment::{compute_commitment, compute_pass_through_data_hash};

        let old_root_hash = H256([0xAA; 32]);
        let enumeration_index: u64 = 4242;
        let prev_meta_hash = H256([0xBB; 32]);
        let prev_aux_hash = H256([0xCC; 32]);

        let prev_passthrough = compute_pass_through_data_hash(enumeration_index, old_root_hash);
        let valid_prev = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);

        // Sanity: passing the matching triple reconstructs the same commitment.
        let recomputed_match = compute_commitment(prev_passthrough, prev_meta_hash, prev_aux_hash);
        assert_eq!(recomputed_match, valid_prev);

        // Tampering the meta hash must produce a different commitment.
        let recomputed_bad_meta =
            compute_commitment(prev_passthrough, H256([0xDE; 32]), prev_aux_hash);
        assert_ne!(recomputed_bad_meta, valid_prev);

        // Tampering the aux hash must produce a different commitment.
        let recomputed_bad_aux =
            compute_commitment(prev_passthrough, prev_meta_hash, H256([0xAD; 32]));
        assert_ne!(recomputed_bad_aux, valid_prev);

        // Tampering the enumeration index must produce a different passthrough,
        // which yields a different commitment.
        let bad_passthrough = compute_pass_through_data_hash(enumeration_index + 1, old_root_hash);
        let recomputed_bad_enum =
            compute_commitment(bad_passthrough, prev_meta_hash, prev_aux_hash);
        assert_ne!(recomputed_bad_enum, valid_prev);

        // Tampering the old root hash likewise.
        let bad_passthrough = compute_pass_through_data_hash(enumeration_index, H256([0xEE; 32]));
        let recomputed_bad_root =
            compute_commitment(bad_passthrough, prev_meta_hash, prev_aux_hash);
        assert_ne!(recomputed_bad_root, valid_prev);
    }
}
