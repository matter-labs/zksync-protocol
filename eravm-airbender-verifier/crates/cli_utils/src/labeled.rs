//! Host-side boundary between the stored/era form of the verifier input, which
//! still carries the two protocol-version labels, and the guest shape
//! [`AirbenderVerifierInput`], whose types carry no version field at all (see
//! `PINNED_PROTOCOL_VERSION`).
//!
//! [`LabeledVerifierInput`] decodes the stored form — byte-identical to every
//! existing fixture, so no corpus migration — exposes the labels for
//! diagnostics ([`LabeledVerifierInput::labels`]), and
//! [`LabeledVerifierInput::into_verifier_input`] strips them: a label below
//! `OLDEST_PROVABLE_LABEL` is refused (it ran under rules the guest does not
//! model; otherwise it would surface only as a late commitment mismatch), any
//! other label that is not the pin warns and proves under the pinned semantics.
//!
//! Labels are typed [`ProtocolUpgradeId`] — byte-identical to the derived
//! `ProtocolVersionId` codec — so a fixture naming an unnameable minor still
//! decodes and the gate reports it, rather than a serde error in the payload.
//!
//! The `cycle-markers` flavour inverts the gate (each batch keeps its own
//! nameable version, replaying under its own semantics) and matches the
//! calibration guest's channel; the stored form read here is flavour-independent.

use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zksync_airbender_verifier::types::{
    AirbenderVerifierInput, CommitmentInput, StorageReadProof, SystemEnvInput,
    VMRunWitnessInputData, WitnessInputMerklePaths,
};
#[cfg(not(feature = "cycle-markers"))]
use zksync_airbender_verifier::{OLDEST_PROVABLE_LABEL, PINNED_PROTOCOL_VERSION};
use zksync_contracts::BaseSystemContracts;
use zksync_types::protocol_version::ProtocolUpgradeId;
use zksync_types::{
    block::L2BlockExecutionData, commitment::PubdataParams,
    witness_block_state::WitnessStorageState, L1BatchNumber, L2ChainId, U256,
};
use zksync_vm_interface::{L1BatchEnv, TxExecutionMode};

#[cfg(feature = "cycle-markers")]
use zksync_types::ProtocolVersionId;

/// Mirror of [`VMRunWitnessInputData`] with the version label present, exactly
/// as zksync-era serializes it. Field order and serde attributes must match
/// that struct 1:1 (minus the label's type) — the bincode wire is positional.
/// A REORDER is the drift the compiler cannot see (adding or dropping a field
/// breaks the struct literals below); `stored_wire_bytes_are_pinned` guards it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LabeledVmRunData {
    pub l1_batch_number: L1BatchNumber,
    pub used_bytecodes: HashMap<U256, Vec<[u8; 32]>>,
    pub initial_heap_content: Vec<(usize, U256)>,
    /// Raw, lossless label; encodes byte-identically to the `ProtocolVersionId`
    /// this slot held historically.
    pub protocol_version: ProtocolUpgradeId,
    pub bootloader_code: Vec<[u8; 32]>,
    pub default_account_code_hash: U256,
    /// Mirrors [`VMRunWitnessInputData::evm_emulator_code_hash`], including the
    /// deliberate absence of `skip_serializing_if`.
    #[serde(default)]
    pub evm_emulator_code_hash: Option<U256>,
    pub storage_refunds: Vec<u32>,
    pub pubdata_costs: Vec<i32>,
    pub witness_block_state: WitnessStorageState,
}

/// Mirror of [`zksync_vm_interface::SystemEnv`] with the version label present.
/// Same 1:1 layout contract as [`LabeledVmRunData`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LabeledSystemEnv {
    pub zk_porter_available: bool,
    /// Raw, lossless label; see [`LabeledVmRunData::protocol_version`].
    pub version: ProtocolUpgradeId,
    pub base_system_smart_contracts: BaseSystemContracts,
    pub bootloader_gas_limit: u32,
    pub execution_mode: TxExecutionMode,
    pub default_validation_computational_gas_limit: u32,
    pub chain_id: L2ChainId,
}

/// The stored/era form of the verifier input — see the module doc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LabeledVerifierInput {
    pub vm_run_data: LabeledVmRunData,
    pub merkle_paths: WitnessInputMerklePaths,
    pub l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: LabeledSystemEnv,
    pub pubdata_params: PubdataParams,
    pub commitment_input: Option<CommitmentInput>,
    /// `default` covers JSON only; bincode payloads without the field decode via
    /// [`LegacyLabeledVerifierInput`].
    #[serde(default)]
    pub prestate_read_proofs: Vec<StorageReadProof>,
}

/// The stored layout without `prestate_read_proofs`, which the fixtures on disk
/// use. Bincode is positional, so it needs its own type.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LegacyLabeledVerifierInput {
    vm_run_data: LabeledVmRunData,
    merkle_paths: WitnessInputMerklePaths,
    l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    l1_batch_env: L1BatchEnv,
    system_env: LabeledSystemEnv,
    pubdata_params: PubdataParams,
    commitment_input: Option<CommitmentInput>,
}

impl From<LegacyLabeledVerifierInput> for LabeledVerifierInput {
    fn from(legacy: LegacyLabeledVerifierInput) -> Self {
        Self {
            vm_run_data: legacy.vm_run_data,
            merkle_paths: legacy.merkle_paths,
            l2_blocks_execution_data: legacy.l2_blocks_execution_data,
            l1_batch_env: legacy.l1_batch_env,
            system_env: legacy.system_env,
            pubdata_params: legacy.pubdata_params,
            commitment_input: legacy.commitment_input,
            prestate_read_proofs: vec![],
        }
    }
}

/// The two raw labels of a stored batch, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchLabels {
    pub system_env_version: u16,
    pub vm_run_data_protocol_version: u16,
}

/// The label both stored slots get on write-back. A guest-shaped input is by
/// construction a batch at the version this build runs it under, so the honest
/// stamp is whatever `execute` would commit at.
fn stamp_for(input: &AirbenderVerifierInput) -> ProtocolUpgradeId {
    ProtocolUpgradeId::from(zksync_airbender_verifier::stf_protocol_version(
        &input.system_env,
    ))
}

impl LabeledVerifierInput {
    /// The operator's labels, before any gating.
    pub fn labels(&self) -> BatchLabels {
        BatchLabels {
            system_env_version: self.system_env.version.raw(),
            vm_run_data_protocol_version: self.vm_run_data.protocol_version.raw(),
        }
    }

    /// The labels [`Self::from_verifier_input`] would stamp, without building the
    /// stored form — it consumes by value, so recovering two u16s through it
    /// deep-copied the whole witness.
    pub fn stamped_labels(input: &AirbenderVerifierInput) -> BatchLabels {
        let raw = stamp_for(input).raw();
        BatchLabels {
            system_env_version: raw,
            vm_run_data_protocol_version: raw,
        }
    }

    /// Strip the labels and produce the guest-facing input.
    ///
    /// Production flavour: refuses a label older than the pin and warns about a
    /// newer one; nothing is assigned — the guest types have no version field
    /// to carry a label. Calibration flavour (`cycle-markers`): keeps each
    /// batch's own `system_env` version on the input, refusing a minor this
    /// build cannot name or the FastVM cannot run (it could not be replayed
    /// under its own semantics); the `vm_run_data` label has no destination in
    /// any flavour.
    ///
    /// Both flavours first require the two labels to agree. They are redundant
    /// copies of one fact and `execute` used to cross-bind them; that check
    /// went with the fields, so it lives here — otherwise `(31, 60000)` loads
    /// and the tools reading the two slots disagree about what was measured.
    pub fn into_verifier_input(self) -> Result<AirbenderVerifierInput> {
        {
            let labels = self.labels();
            anyhow::ensure!(
                labels.system_env_version == labels.vm_run_data_protocol_version,
                "stored protocol labels disagree: system_env.version names minor {}, \
                 vm_run_data.protocol_version names {}; they are redundant copies of \
                 one fact and a batch cannot be both",
                labels.system_env_version,
                labels.vm_run_data_protocol_version,
            );
        }

        // One check, not two: the equality gate above already proved the labels
        // identical, so iterating both would only duplicate the warning.
        #[cfg(not(feature = "cycle-markers"))]
        {
            let raw = self.labels().system_env_version;
            let pin = PINNED_PROTOCOL_VERSION as u16;
            let oldest = OLDEST_PROVABLE_LABEL as u16;
            anyhow::ensure!(
                raw >= oldest,
                "batch labels protocol minor {raw}, which predates the oldest provable label \
                 {oldest} for the pinned version {pin} this verifier models; it cannot be \
                 proved by this guest. A tool that only needs to READ the batch should use \
                 `load_labeled_batch` instead of `load_batch`, which skips this proving gate.",
            );
            if raw != pin {
                // Without the batch number a warning from a 49-batch run is
                // unattributable; `load_batch`'s context attaches only on `Err`.
                tracing::warn!(
                    batch = self.l1_batch_env.number.0,
                    minor = raw,
                    pinned = pin,
                    "batch labels a protocol minor other than the pinned version; it will be \
                     proved under the pinned semantics. A difference is caught only where it \
                     moves a hash L1 reconstructs, and the new state root is operator-supplied \
                     on both sides — a diagnostic, not a proof of equivalence"
                );
            }
        }

        #[cfg(feature = "cycle-markers")]
        let system_env_version = {
            let named =
                ProtocolVersionId::try_from(self.system_env.version).map_err(anyhow::Error::msg)?;
            // The same guard `execute` applies, so a pre-flight cannot admit a
            // batch every worker of the run then rejects.
            anyhow::ensure!(
                zksync_airbender_verifier::is_supported_by_fast_vm(named),
                "protocol version {named:?} is not supported by the FastVM verifier",
            );
            named
        };

        Ok(AirbenderVerifierInput {
            vm_run_data: VMRunWitnessInputData {
                l1_batch_number: self.vm_run_data.l1_batch_number,
                used_bytecodes: self.vm_run_data.used_bytecodes,
                initial_heap_content: self.vm_run_data.initial_heap_content,
                bootloader_code: self.vm_run_data.bootloader_code,
                default_account_code_hash: self.vm_run_data.default_account_code_hash,
                evm_emulator_code_hash: self.vm_run_data.evm_emulator_code_hash,
                storage_refunds: self.vm_run_data.storage_refunds,
                pubdata_costs: self.vm_run_data.pubdata_costs,
                witness_block_state: self.vm_run_data.witness_block_state,
            },
            merkle_paths: self.merkle_paths,
            l2_blocks_execution_data: self.l2_blocks_execution_data,
            l1_batch_env: self.l1_batch_env,
            system_env: SystemEnvInput {
                zk_porter_available: self.system_env.zk_porter_available,
                #[cfg(feature = "cycle-markers")]
                version: system_env_version,
                base_system_smart_contracts: self.system_env.base_system_smart_contracts,
                bootloader_gas_limit: self.system_env.bootloader_gas_limit,
                execution_mode: self.system_env.execution_mode,
                default_validation_computational_gas_limit: self
                    .system_env
                    .default_validation_computational_gas_limit,
                chain_id: self.system_env.chain_id,
            },
            pubdata_params: self.pubdata_params,
            commitment_input: self.commitment_input,
            prestate_read_proofs: self.prestate_read_proofs,
        })
    }

    /// Inverse of [`Self::into_verifier_input`] for writing fixtures. The input
    /// carries no labels to copy, so both stored label slots are stamped from
    /// the one authoritative source: in production, the pin — a guest-shaped
    /// input is by construction a pin-semantics batch; under `cycle-markers`,
    /// the input's own `system_env.version`.
    ///
    /// The round trip is ASYMMETRIC. `load(save(x)) == x` holds; in production
    /// `save(load(f)) == f` does NOT for a non-pin fixture — the label does
    /// not survive into the typed input, so re-encoding restamps `Version31` to
    /// `Version34`, and `encode_batch`'s self-check compares the typed form the
    /// label is absent from. To preserve labels, stay in the labeled domain
    /// ([`crate::load_labeled_batch`]). Pinned by `above_pin_label_is_restamped`.
    pub fn from_verifier_input(input: AirbenderVerifierInput) -> Self {
        let label = stamp_for(&input);

        Self {
            vm_run_data: LabeledVmRunData {
                l1_batch_number: input.vm_run_data.l1_batch_number,
                used_bytecodes: input.vm_run_data.used_bytecodes,
                initial_heap_content: input.vm_run_data.initial_heap_content,
                protocol_version: label,
                bootloader_code: input.vm_run_data.bootloader_code,
                default_account_code_hash: input.vm_run_data.default_account_code_hash,
                evm_emulator_code_hash: input.vm_run_data.evm_emulator_code_hash,
                storage_refunds: input.vm_run_data.storage_refunds,
                pubdata_costs: input.vm_run_data.pubdata_costs,
                witness_block_state: input.vm_run_data.witness_block_state,
            },
            merkle_paths: input.merkle_paths,
            l2_blocks_execution_data: input.l2_blocks_execution_data,
            l1_batch_env: input.l1_batch_env,
            system_env: LabeledSystemEnv {
                zk_porter_available: input.system_env.zk_porter_available,
                version: label,
                base_system_smart_contracts: input.system_env.base_system_smart_contracts,
                bootloader_gas_limit: input.system_env.bootloader_gas_limit,
                execution_mode: input.system_env.execution_mode,
                default_validation_computational_gas_limit: input
                    .system_env
                    .default_validation_computational_gas_limit,
                chain_id: input.system_env.chain_id,
            },
            pubdata_params: input.pubdata_params,
            commitment_input: input.commitment_input,
            prestate_read_proofs: input.prestate_read_proofs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zksync_airbender_verifier::PINNED_PROTOCOL_VERSION;
    use zksync_contracts::SystemContractCode;
    use zksync_types::commitment::{L2DACommitmentScheme, L2PubdataValidator};
    use zksync_types::settlement::SettlementLayer;
    use zksync_types::H256;
    use zksync_vm_interface::L2BlockEnv;

    /// Same-encoding fields carry DISTINCT values on purpose: four empty vectors
    /// all encode as one zero byte, so with defaults a transposition moves nothing
    /// and `stored_wire_bytes_are_pinned` passes vacuously (verified by planting
    /// one).
    fn sample(label: u16) -> LabeledVerifierInput {
        let contract = SystemContractCode {
            code: vec![1; 32],
            hash: H256([1; 32]),
        };
        LabeledVerifierInput {
            vm_run_data: LabeledVmRunData {
                l1_batch_number: L1BatchNumber(11),
                used_bytecodes: Default::default(),
                initial_heap_content: vec![(1, U256::from(2))],
                protocol_version: ProtocolUpgradeId::from(label),
                bootloader_code: vec![[3; 32]],
                default_account_code_hash: U256::from(4),
                evm_emulator_code_hash: Some(U256::from(5)),
                storage_refunds: vec![6],
                pubdata_costs: vec![-7],
                witness_block_state: Default::default(),
            },
            merkle_paths: WitnessInputMerklePaths::new(4),
            l2_blocks_execution_data: vec![],
            l1_batch_env: L1BatchEnv {
                previous_batch_hash: Some(H256([1; 32])),
                number: L1BatchNumber(11),
                timestamp: 0,
                fee_input: Default::default(),
                interop_fee: U256::zero(),
                fee_account: Default::default(),
                enforced_base_fee: None,
                first_l2_block: L2BlockEnv {
                    number: 0,
                    timestamp: 0,
                    prev_block_hash: H256([1; 32]),
                    max_virtual_blocks_to_create: 0,
                    interop_roots: vec![],
                },
                settlement_layer: SettlementLayer::default(),
            },
            system_env: LabeledSystemEnv {
                zk_porter_available: false,
                version: ProtocolUpgradeId::from(label),
                base_system_smart_contracts: BaseSystemContracts {
                    bootloader: contract.clone(),
                    default_aa: contract,
                    evm_emulator: None,
                },
                bootloader_gas_limit: 8,
                execution_mode: TxExecutionMode::VerifyExecute,
                default_validation_computational_gas_limit: u32::MAX,
                chain_id: Default::default(),
            },
            pubdata_params: PubdataParams::new(
                L2PubdataValidator::CommitmentScheme(
                    L2DACommitmentScheme::BlobsAndPubdataKeccak256,
                ),
                Default::default(),
            )
            .unwrap(),
            commitment_input: None,
            prestate_read_proofs: vec![],
        }
    }

    fn force_fail_sample() -> LabeledVerifierInput {
        use zksync_types::{Execute, ExecuteTransactionCommon, L1TxCommonData, Transaction};
        let mut input = sample(34);
        let tx = |force_fail| Transaction {
            common_data: ExecuteTransactionCommon::L1(L1TxCommonData {
                force_fail,
                ..Default::default()
            }),
            execute: Execute::default(),
            received_timestamp_ms: 0,
            raw_bytes: None,
        };
        input.l2_blocks_execution_data = vec![
            L2BlockExecutionData {
                number: zksync_types::L2BlockNumber(1),
                timestamp: 0,
                prev_block_hash: H256::zero(),
                virtual_blocks: 1,
                txs: vec![tx(false), tx(true)],
                interop_roots: vec![],
            },
            L2BlockExecutionData {
                number: zksync_types::L2BlockNumber(2),
                timestamp: 1,
                prev_block_hash: H256::zero(),
                virtual_blocks: 1,
                txs: vec![tx(true), tx(false)],
                interop_roots: vec![],
            },
        ];
        input
    }

    #[test]
    fn force_fail_survives_json_file_and_guest_wire() {
        let json = serde_json::to_vec(&force_fail_sample()).unwrap();
        let input = serde_json::from_slice::<LabeledVerifierInput>(&json)
            .unwrap()
            .into_verifier_input()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        for filename in ["1.bin", "1.bin.gz"] {
            let path = dir.path().join(filename);
            crate::save_batch(&input, &path).unwrap();
            let decoded = crate::load_batch(&crate::BatchInputFile { number: 1, path }).unwrap();
            assert_eq!(decoded, input);
            let cfg = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(&decoded, cfg).unwrap();
            let (guest, read): (AirbenderVerifierInput, _) =
                bincode::serde::decode_from_slice(&bytes, cfg).unwrap();
            assert_eq!(read, bytes.len());
            assert_eq!(guest, input);
        }
    }

    #[test]
    fn versioned_stored_payload_rejects_corruption() {
        let input = force_fail_sample();
        let encode = |positions: Vec<(u32, u32)>| {
            let mut bytes = crate::STORED_MAGIC.to_vec();
            bytes.push(crate::STORED_VERSION);
            bincode::serde::encode_into_std_write(
                (&input, positions),
                &mut bytes,
                bincode::config::standard(),
            )
            .unwrap();
            bytes
        };
        let valid = encode(vec![(0, 1), (1, 0)]);
        assert_eq!(crate::decode_labeled_payload(&valid).unwrap(), input);
        for positions in [
            vec![(1, 0), (0, 1)],
            vec![(0, 1), (0, 1)],
            vec![(2, 0)],
            vec![(0, 2)],
        ] {
            assert!(crate::decode_labeled_payload(&encode(positions)).is_err());
        }
        let mut unknown_version = valid.clone();
        unknown_version[crate::STORED_MAGIC.len()] += 1;
        assert!(crate::decode_labeled_payload(&unknown_version)
            .unwrap_err()
            .to_string()
            .contains("unsupported stored format"));
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(crate::decode_labeled_payload(&trailing).is_err());
        for end in crate::STORED_MAGIC.len()..valid.len() {
            assert!(
                crate::decode_labeled_payload(&valid[..end]).is_err(),
                "truncation at {end}"
            );
        }
    }

    const PIN: u16 = PINNED_PROTOCOL_VERSION as u16;
    #[cfg(not(feature = "cycle-markers"))]
    const OLDEST: u16 = zksync_airbender_verifier::OLDEST_PROVABLE_LABEL as u16;
    /// Fixed label for the wire goldens, so a pin bump does not move them.
    const GOLDEN_LABEL: u16 = 31;

    /// Production gate: a label at the pin passes (the typed input has no
    /// version field to inspect); the labeled → typed → labeled round trip is
    /// exact — `from_verifier_input` re-stamps both label slots with the pin.
    #[cfg(not(feature = "cycle-markers"))]
    #[test]
    fn pinned_label_round_trips() {
        let labeled = sample(PIN);
        let input = labeled
            .clone()
            .into_verifier_input()
            .expect("pinned label must be accepted");
        assert_eq!(LabeledVerifierInput::from_verifier_input(input), labeled);
    }

    /// Production gate: a label below the floor is refused with the fail-fast
    /// message — that batch ran under rules the guest does not model.
    #[cfg(not(feature = "cycle-markers"))]
    #[test]
    fn older_label_is_refused() {
        let err = sample(OLDEST - 1)
            .into_verifier_input()
            .expect_err("a label below the floor must be refused");
        assert!(
            err.to_string()
                .contains("predates the oldest provable label"),
            "unexpected error: {err}"
        );
    }

    /// Production gate: labels from the floor up to the pin are accepted and
    /// proved under the pinned semantics.
    #[cfg(not(feature = "cycle-markers"))]
    #[test]
    fn labels_from_the_floor_are_accepted_as_the_pin() {
        for label in OLDEST..PIN {
            let input = sample(label)
                .into_verifier_input()
                .unwrap_or_else(|e| panic!("label {label} must be accepted: {e}"));
            let restamped = LabeledVerifierInput::from_verifier_input(input).labels();
            assert_eq!(restamped.system_env_version, PIN);
        }
    }

    /// Production gate: a newer label — even one this build cannot name — is
    /// accepted (with a warning) and proved under the pinned semantics; the
    /// resulting typed input carries no version at all.
    #[cfg(not(feature = "cycle-markers"))]
    #[test]
    fn newer_and_unnameable_labels_are_accepted_as_the_pin() {
        for label in [PIN + 1, PIN + 100, u16::MAX] {
            sample(label)
                .into_verifier_input()
                .unwrap_or_else(|e| panic!("label {label} must be accepted: {e}"));
        }
    }

    /// The documented asymmetry: an above-pin fixture survives `load`, but the
    /// label does not, so re-encoding restamps it to the pin.
    #[cfg(not(feature = "cycle-markers"))]
    #[test]
    fn above_pin_label_is_restamped() {
        let original = sample(PIN + 1);
        let input = original
            .clone()
            .into_verifier_input()
            .expect("an above-pin label is accepted");
        let round_tripped = LabeledVerifierInput::from_verifier_input(input);

        assert_eq!(round_tripped.labels().system_env_version, PIN);
        assert_eq!(round_tripped.labels().vm_run_data_protocol_version, PIN);
        assert_ne!(
            round_tripped, original,
            "the restamp must be observable in the stored form"
        );
    }

    /// Redundant copies of one fact: `execute` used to cross-bind them and no
    /// longer can, so disagreement must be refused here.
    #[test]
    fn disagreeing_labels_are_refused() {
        let mut labeled = sample(PIN);
        labeled.vm_run_data.protocol_version = ProtocolUpgradeId::from(60_000);
        let err = labeled
            .into_verifier_input()
            .expect_err("disagreeing labels must be refused");
        assert!(
            err.to_string().contains("stored protocol labels disagree"),
            "unexpected error: {err}"
        );
    }

    /// Calibration flavour: each batch keeps its own (nameable) `system_env`
    /// version, and an unnameable one is refused — it could not replay under
    /// its own semantics. (The `vm_run_data` label has no typed destination in
    /// any flavour.)
    #[cfg(feature = "cycle-markers")]
    #[test]
    fn calibration_keeps_the_batch_version() {
        use zksync_types::ProtocolVersionId;

        let input = sample(ProtocolVersionId::Version29 as u16)
            .into_verifier_input()
            .expect("a nameable older minor must be accepted for calibration");
        assert_eq!(input.system_env.version, ProtocolVersionId::Version29);

        assert!(
            sample(u16::MAX).into_verifier_input().is_err(),
            "an unnameable minor cannot be replayed under its own semantics"
        );
        // Version23 is nameable but maps to a VM the FastVM cannot run.
        assert!(
            sample(ProtocolVersionId::Version23 as u16)
                .into_verifier_input()
                .is_err(),
            "a minor the FastVM cannot run must be refused at load, not mid-run"
        );
    }

    /// Calibration writes the corpus, so its stamping arm — reading the input's
    /// own version, not the pin — must round-trip a below-pin batch exactly.
    /// Here `save(load(f)) == f` DOES hold for a nameable label.
    #[cfg(feature = "cycle-markers")]
    #[test]
    fn calibration_from_verifier_input_preserves_the_batch_version() {
        use zksync_types::ProtocolVersionId;

        let original = sample(ProtocolVersionId::Version29 as u16);
        let input = original
            .clone()
            .into_verifier_input()
            .expect("a nameable older minor is accepted for calibration");
        let round_tripped = LabeledVerifierInput::from_verifier_input(input);

        let expected = ProtocolVersionId::Version29 as u16;
        assert_eq!(round_tripped.labels().system_env_version, expected);
        assert_eq!(
            round_tripped.labels().vm_run_data_protocol_version,
            expected
        );
        assert_eq!(round_tripped, original, "calibration must not relabel");
    }

    /// The stored layout is byte-identical to the historical one, in which the
    /// label slots held the `ProtocolVersionId` enum: no fixture re-encoding.
    /// (The u16↔enum byte identity itself is pinned in `zksync_basic_types`;
    /// this pins the struct-level round trip through the framed hex format.)
    #[test]
    fn stored_bytes_round_trip() {
        let labeled = sample(PIN);
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&labeled, cfg).expect("encode");
        let (decoded, read) =
            bincode::serde::decode_from_slice::<LabeledVerifierInput, _>(&bytes, cfg)
                .expect("decode");
        assert_eq!(read, bytes.len(), "trailing bytes");
        assert_eq!(decoded, labeled);
    }

    /// Golden pin on the STORED wire, mirroring the typed side's
    /// `version_fields_are_absent_from_the_production_wire`. Catches the one drift
    /// nothing else does — a REORDER: `stored_bytes_round_trip` compares the
    /// mirror against ITSELF, so swapping `storage_refunds` with `pubdata_costs`
    /// would decode cleanly and silently transpose the corpus. Fixture-free, so
    /// it cannot pass vacuously on an LFS-pointer checkout.
    #[test]
    fn stored_wire_bytes_are_pinned() {
        /// `encode_to_vec(&sample(GOLDEN_LABEL), standard()).len()`, captured here.
        const GOLDEN_STORED_WIRE_LEN: usize = 540;
        /// `keccak256` of those bytes, lowercase hex.
        const GOLDEN_STORED_WIRE_KECCAK: &str =
            "48349bc07b547d181cf4b1958ce78a527598a45f8fccc6cc55e4d47cce959d8c";

        let bytes =
            bincode::serde::encode_to_vec(sample(GOLDEN_LABEL), bincode::config::standard())
                .expect("encode");
        assert_eq!(
            bytes.len(),
            GOLDEN_STORED_WIRE_LEN,
            "stored wire length moved"
        );
        assert_eq!(
            format!("{:x}", H256(zksync_types::web3::keccak256(&bytes))),
            GOLDEN_STORED_WIRE_KECCAK,
            "stored wire bytes moved: a field was reordered, retyped or its \
             serde attributes changed — the on-disk corpus no longer decodes"
        );
    }

    /// The layout without `prestate_read_proofs` must still load.
    #[test]
    fn legacy_stored_layout_still_decodes() {
        /// `sample(GOLDEN_LABEL)` in the legacy layout.
        const LEGACY_WIRE_LEN: usize = 539;
        const LEGACY_WIRE_KECCAK: &str =
            "3db4f3b880d62350065e199c5deef9d10a9c94fb1e9106fa3293a7ffdbbc5032";

        let labeled = sample(GOLDEN_LABEL);
        let mut bytes =
            bincode::serde::encode_to_vec(&labeled, bincode::config::standard()).expect("encode");
        // Dropping the empty proof list's length byte gives the legacy layout.
        assert_eq!(bytes.pop(), Some(0));
        assert_eq!(bytes.len(), LEGACY_WIRE_LEN);
        assert_eq!(
            format!("{:x}", H256(zksync_types::web3::keccak256(&bytes))),
            LEGACY_WIRE_KECCAK
        );

        assert_eq!(crate::decode_labeled_payload(&bytes).unwrap(), labeled);

        bytes.push(0xff);
        assert!(
            crate::decode_labeled_payload(&bytes).is_err(),
            "a payload neither layout consumes exactly must be refused"
        );
    }

    #[test]
    fn stored_read_proofs_round_trip() {
        let mut labeled = sample(PIN);
        labeled.prestate_read_proofs = vec![StorageReadProof {
            leaf_hashed_key: U256::from(12),
            leaf_enumeration_index: 13,
            value: [14; 32],
            merkle_path: vec![[15; 32]; 3],
        }];
        let bytes =
            bincode::serde::encode_to_vec(&labeled, bincode::config::standard()).expect("encode");
        let decoded = crate::decode_labeled_payload(&bytes).unwrap();
        assert_eq!(decoded, labeled);
        let input = decoded.into_verifier_input().unwrap();
        assert_eq!(input.prestate_read_proofs, labeled.prestate_read_proofs);
        assert_eq!(LabeledVerifierInput::from_verifier_input(input), labeled);
    }
}
