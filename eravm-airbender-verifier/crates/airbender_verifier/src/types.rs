use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zksync_contracts::BaseSystemContracts;
use zksync_types::{
    block::L2BlockExecutionData,
    commitment::{BlobHash, PubdataParams},
    witness_block_state::WitnessStorageState,
    L1BatchNumber, L2ChainId, ProtocolVersionId, H256, U256,
};
use zksync_vm_interface::{L1BatchEnv, SystemEnv, TxExecutionMode};

pub use zksync_merkle_tree::{StorageLogMetadata, WitnessInputMerklePaths};

pub(crate) const HASH_LEN: usize = 32;

/// Number of blob hash/commitment pairs in the auxiliary output.
///
/// Must stay in sync with the L1 source of truth: `IExecutor.sol`'s
/// `TOTAL_BLOBS_IN_COMMITMENT`. `test_total_blobs_in_commitment_matches_l1`
/// pins the value.
pub const TOTAL_BLOBS_IN_COMMITMENT: usize = 16;

#[cfg(test)]
mod blob_constant_tests {
    /// Change detector: if L1's `TOTAL_BLOBS_IN_COMMITMENT` ever changes, this constant
    /// must be updated in lockstep with the contract and the sequencer.
    #[test]
    fn test_total_blobs_in_commitment_matches_l1() {
        assert_eq!(super::TOTAL_BLOBS_IN_COMMITMENT, 16);
    }
}

/// The operator-facing shape of the execution environment: [`SystemEnv`] minus
/// the protocol version, which is not an input — `execute` injects
/// `PINNED_PROTOCOL_VERSION` at [`SystemEnvInput::into_system_env`].
///
/// Field order is the bincode wire order. Under `cycle-markers` `version` sits
/// at position 2 as it does in [`SystemEnv`]; the calibration channel still
/// moved overall, since [`VMRunWitnessInputData`]'s mirror is gone in every
/// flavour, so a calibration guest must be rebuilt alongside its host.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemEnvInput {
    pub zk_porter_available: bool,
    /// Calibration-only: each corpus batch replays under its own semantics.
    /// Structurally absent from the production build — not just skipped.
    #[cfg(feature = "cycle-markers")]
    pub version: ProtocolVersionId,
    pub base_system_smart_contracts: BaseSystemContracts,
    pub bootloader_gas_limit: u32,
    pub execution_mode: TxExecutionMode,
    pub default_validation_computational_gas_limit: u32,
    pub chain_id: L2ChainId,
}

impl SystemEnvInput {
    /// The single place a version enters the STF. `execute` passes
    /// `PINNED_PROTOCOL_VERSION`; the calibration flavour passes the batch's
    /// own.
    pub fn into_system_env(self, version: ProtocolVersionId) -> SystemEnv {
        SystemEnv {
            zk_porter_available: self.zk_porter_available,
            version,
            base_system_smart_contracts: self.base_system_smart_contracts,
            bootloader_gas_limit: self.bootloader_gas_limit,
            execution_mode: self.execution_mode,
            default_validation_computational_gas_limit: self
                .default_validation_computational_gas_limit,
            chain_id: self.chain_id,
        }
    }
}

// Mirrors `SystemEnv`'s manual impl: print contract hashes, not the bytecodes.
impl std::fmt::Debug for SystemEnvInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SystemEnvInput");
        s.field("zk_porter_available", &self.zk_porter_available);
        #[cfg(feature = "cycle-markers")]
        s.field("version", &self.version);
        s.field(
            "base_system_smart_contracts",
            &self.base_system_smart_contracts.hashes(),
        )
        .field("gas_limit", &self.bootloader_gas_limit)
        .field(
            "default_validation_computational_gas_limit",
            &self.default_validation_computational_gas_limit,
        )
        .field("execution_mode", &self.execution_mode)
        .field("chain_id", &self.chain_id)
        .finish()
    }
}

/// VM execution witness used by verifier input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VMRunWitnessInputData {
    pub l1_batch_number: L1BatchNumber,
    pub used_bytecodes: HashMap<U256, Vec<[u8; HASH_LEN]>>,
    pub initial_heap_content: Vec<(usize, U256)>,
    pub bootloader_code: Vec<[u8; HASH_LEN]>,
    pub default_account_code_hash: U256,
    /// `None` on an EVM-emulator-disabled chain, which `verify_commitment`
    /// supports.
    ///
    /// NOT `skip_serializing_if`: bincode reads a fixed field count, so
    /// `default` never fires and an omitted field left the `None` payload
    /// undecodable. `default` stays for the JSON path; `Some` encodes
    /// identically either way, so the corpus is unaffected.
    #[serde(default)]
    pub evm_emulator_code_hash: Option<U256>,
    pub storage_refunds: Vec<u32>,
    pub pubdata_costs: Vec<i32>,
    pub witness_block_state: WitnessStorageState,
}

/// Data required for L1 batch commitment computation that is not produced by
/// VM execution and must be provided externally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitmentInput {
    /// The `storedBatchInfo.commitment` of the previous batch (stored on L1).
    /// Used to construct the proof public input: `keccak256(prev || curr) >> 32`.
    /// If the operator provides the wrong value, the proof will not match L1's
    /// reconstruction and will be rejected.
    pub prev_batch_commitment: H256,
    /// The metadata hash of the previous batch. Together with `prev_aux_hash`,
    /// used to verify that `prev_batch_commitment` is consistent with the
    /// previous state root (old_root_hash).
    pub prev_meta_hash: H256,
    /// The auxiliary output hash of the previous batch.
    pub prev_aux_hash: H256,
    /// `(linear_hash, opening_commitment)` pairs that go into the auxiliary
    /// output. Length must equal `TOTAL_BLOBS_IN_COMMITMENT`; unused slots are
    /// `BlobHash::default()`.
    pub blob_hashes: Vec<BlobHash>,
    /// EIP-4844 versioned hashes for each blob (from the L1 blob transaction).
    /// Length must equal `TOTAL_BLOBS_IN_COMMITMENT`. Used to derive opening
    /// points; not part of the auxiliary-output bytes.
    pub blob_versioned_hashes: Vec<H256>,
}

impl Default for CommitmentInput {
    fn default() -> Self {
        Self {
            prev_batch_commitment: H256::zero(),
            prev_meta_hash: H256::zero(),
            prev_aux_hash: H256::zero(),
            blob_hashes: vec![BlobHash::default(); TOTAL_BLOBS_IN_COMMITMENT],
            blob_versioned_hashes: vec![H256::zero(); TOTAL_BLOBS_IN_COMMITMENT],
        }
    }
}

/// Verifier input payload — the guest-facing shape, bincode-encoded on the
/// host↔guest channel.
///
/// The wire cannot express a protocol version: [`SystemEnvInput`] has no
/// version field and [`VMRunWitnessInputData`]'s mirror is deleted. `execute`
/// injects `PINNED_PROTOCOL_VERSION` — the STF chooses, not the operator. The
/// era export and on-disk corpus keep the historical labels host-side
/// (`zksync_cli_utils::labeled`); the only minor on the wire is an upgrade tx's
/// `upgrade_id` (batch content). Under `cycle-markers` the wire also carries
/// `system_env.version`, so the calibration guest replays each batch under its
/// own semantics.
///
/// `commitment_input` carries the L1 chain context the verifier needs to
/// produce a `proof_public_input` bound to L1 settlement; `Verify::verify`
/// requires it to be `Some`. The field is `Option<...>` so VM-only flows
/// (e.g., the serialization roundtrip test) can construct an input without
/// fabricating commitment data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AirbenderVerifierInput {
    pub vm_run_data: VMRunWitnessInputData,
    pub merkle_paths: WitnessInputMerklePaths,
    #[serde(with = "l2_blocks_wire")]
    pub l2_blocks_execution_data: Vec<L2BlockExecutionData>,
    pub l1_batch_env: L1BatchEnv,
    pub system_env: SystemEnvInput,
    pub pubdata_params: PubdataParams,
    pub commitment_input: Option<CommitmentInput>,
    /// Pre-batch proofs for declared slots `merkle_paths` does not cover, in
    /// strictly ascending `leaf_hashed_key` order. `default` only helps JSON;
    /// bincode is positional.
    #[serde(default)]
    pub prestate_read_proofs: Vec<StorageReadProof>,
}

/// Codec for [`AirbenderVerifierInput::l2_blocks_execution_data`]. JSON is the plain block list,
/// with `forceFail` inside each L1 tx. The binary `L1TxCommonData` codec omits that flag, so the
/// binary form appends the `(block, tx)` positions of force-failed txs, strictly ascending.
pub mod l2_blocks_wire {
    use serde::{
        de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer,
    };
    use zksync_types::{block::L2BlockExecutionData, ExecuteTransactionCommon};

    pub type Position = (u32, u32);

    pub(super) fn serialize<S: Serializer>(
        blocks: &Vec<L2BlockExecutionData>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            return blocks.serialize(s);
        }
        let force_failed = force_failed_positions(blocks).map_err(S::Error::custom)?;
        (blocks, force_failed).serialize(s)
    }

    pub fn force_failed_positions(
        blocks: &[L2BlockExecutionData],
    ) -> Result<Vec<Position>, &'static str> {
        let mut positions = Vec::new();
        for (block_idx, block) in blocks.iter().enumerate() {
            for (tx_idx, tx) in block.txs.iter().enumerate() {
                if matches!(&tx.common_data, ExecuteTransactionCommon::L1(data) if data.force_fail)
                {
                    positions.push((
                        u32::try_from(block_idx).map_err(|_| "block index exceeds u32")?,
                        u32::try_from(tx_idx).map_err(|_| "transaction index exceeds u32")?,
                    ));
                }
            }
        }
        Ok(positions)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<L2BlockExecutionData>, D::Error> {
        if d.is_human_readable() {
            return Vec::deserialize(d);
        }
        let (mut blocks, force_failed) =
            <(Vec<L2BlockExecutionData>, Vec<Position>)>::deserialize(d)?;
        restore_force_failed_positions(&mut blocks, force_failed).map_err(D::Error::custom)?;
        Ok(blocks)
    }

    pub fn restore_force_failed_positions(
        blocks: &mut [L2BlockExecutionData],
        force_failed: Vec<Position>,
    ) -> Result<(), &'static str> {
        let mut prev: Option<Position> = None;
        for pos @ (block_idx, tx_idx) in force_failed {
            if prev.is_some_and(|prev| prev >= pos) {
                return Err("force-failed positions are not strictly ascending");
            }
            prev = Some(pos);
            let tx = blocks
                .get_mut(block_idx as usize)
                .and_then(|block| block.txs.get_mut(tx_idx as usize))
                .ok_or("force-failed position out of range")?;
            match &mut tx.common_data {
                ExecuteTransactionCommon::L1(data) => data.force_fail = true,
                _ => return Err("force-failed position is not an L1 tx"),
            }
        }
        Ok(())
    }
}

/// Read-only Merkle proof of a slot's pre-batch state against the previous
/// batch root. Mirrored by hand in zksync-era's `airbender_prover_interface`,
/// which pins the same JSON literal as `storage_read_proof_json_is_pinned`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageReadProof {
    /// `StorageKey::hashed_key_u256()`, as in [`StorageLogMetadata::leaf_hashed_key`].
    pub leaf_hashed_key: U256,
    /// 0 = missing leaf; then `value` must be zero.
    pub leaf_enumeration_index: u64,
    pub value: [u8; HASH_LEN],
    /// Leaf-to-root, empty-subtree hashes at the bottom omitted, at most 256 entries.
    pub merkle_path: Vec<[u8; HASH_LEN]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vm_run_data(evm_emulator_code_hash: Option<U256>) -> VMRunWitnessInputData {
        VMRunWitnessInputData {
            l1_batch_number: Default::default(),
            used_bytecodes: Default::default(),
            initial_heap_content: vec![],
            bootloader_code: vec![],
            default_account_code_hash: Default::default(),
            evm_emulator_code_hash,
            storage_refunds: vec![],
            pubdata_costs: vec![],
            witness_block_state: Default::default(),
        }
    }

    /// Regression: `skip_serializing_if` left the `None` payload one field
    /// short and undecodable. The `Some` arm pins that dropping it kept the
    /// corpus wire byte-identical.
    #[test]
    fn evm_emulator_none_round_trips() {
        let cfg = bincode::config::standard();
        for value in [Some(U256::zero()), None] {
            let input = sample_vm_run_data(value);
            let bytes = bincode::serde::encode_to_vec(&input, cfg).expect("encode");
            let (decoded, read) =
                bincode::serde::decode_from_slice::<VMRunWitnessInputData, _>(&bytes, cfg)
                    .unwrap_or_else(|e| panic!("{value:?} must decode: {e}"));
            assert_eq!(read, bytes.len(), "trailing bytes for {value:?}");
            assert_eq!(decoded, input, "round trip differs for {value:?}");
        }
    }

    #[test]
    fn storage_read_proof_json_is_pinned() {
        const GOLDEN: &str = r#"{"leaf_hashed_key":"0x1234","leaf_enumeration_index":7,"value":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9],"merkle_path":[[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]]}"#;
        let mut value = [0; HASH_LEN];
        value[31] = 9;
        let proof = StorageReadProof {
            leaf_hashed_key: U256::from(0x1234),
            leaf_enumeration_index: 7,
            value,
            merkle_path: vec![[1; HASH_LEN]],
        };
        assert_eq!(serde_json::to_string(&proof).unwrap(), GOLDEN);
        assert_eq!(
            serde_json::from_str::<StorageReadProof>(GOLDEN).unwrap(),
            proof
        );
    }

    #[test]
    fn witness_merkle_paths_roundtrip() {
        let zero_hash = [0_u8; HASH_LEN];
        let logs = (0_u64..10).map(|i| {
            let mut merkle_paths = vec![zero_hash; 255];
            merkle_paths.push([i as u8; HASH_LEN]);
            StorageLogMetadata {
                root_hash: zero_hash,
                is_write: i.is_multiple_of(2),
                first_write: i.is_multiple_of(3),
                merkle_paths,
                leaf_hashed_key: U256::from(i),
                leaf_enumeration_index: i + 1,
                value_written: [i as u8; HASH_LEN],
                value_read: [0; HASH_LEN],
            }
        });
        let logs: Vec<_> = logs.collect();

        let mut witness = WitnessInputMerklePaths::new(4);
        witness.reserve(logs.len());
        for log in &logs {
            witness.push_merkle_path(log.clone());
        }

        // These siblings are not empty-subtree constants, so nothing is stripped:
        // each path is stored exactly as pushed, independently of the others. (The
        // old delta form stored `[256, 1, 1, …]` here — every later entry's size
        // was a function of entry 0.)
        for log in &witness.merkle_paths {
            assert_eq!(log.merkle_paths.len(), 256);
        }

        let logs_from_witness: Vec<_> = witness.into_merkle_paths().collect();
        assert_eq!(logs_from_witness, logs);
    }

    mod force_fail_wire {
        use zksync_types::{
            protocol_upgrade::ProtocolUpgradeTxCommonData, Execute, ExecuteTransactionCommon,
            L1TxCommonData, Transaction,
        };

        use super::*;

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Blocks(#[serde(with = "l2_blocks_wire")] Vec<L2BlockExecutionData>);

        fn tx(common_data: ExecuteTransactionCommon) -> Transaction {
            Transaction {
                common_data,
                execute: Execute::default(),
                received_timestamp_ms: 0,
                raw_bytes: None,
            }
        }

        fn l1_tx(force_fail: bool) -> Transaction {
            tx(ExecuteTransactionCommon::L1(L1TxCommonData {
                force_fail,
                ..Default::default()
            }))
        }

        fn blocks(txs: Vec<Vec<Transaction>>) -> Blocks {
            Blocks(
                txs.into_iter()
                    .enumerate()
                    .map(|(i, txs)| L2BlockExecutionData {
                        number: zksync_types::L2BlockNumber(i as u32),
                        timestamp: 0,
                        prev_block_hash: H256::zero(),
                        virtual_blocks: 1,
                        txs,
                        interop_roots: vec![],
                    })
                    .collect(),
            )
        }

        fn sample() -> Blocks {
            blocks(vec![
                vec![l1_tx(false), l1_tx(true)],
                vec![tx(ExecuteTransactionCommon::ProtocolUpgrade(
                    ProtocolUpgradeTxCommonData::default(),
                ))],
                vec![l1_tx(true)],
            ])
        }

        #[test]
        fn binary_round_trip_keeps_force_fail() {
            let cfg = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(sample(), cfg).expect("encode");
            let (decoded, read) =
                bincode::serde::decode_from_slice::<Blocks, _>(&bytes, cfg).expect("decode");
            assert_eq!(read, bytes.len());
            assert_eq!(decoded, sample());
        }

        #[test]
        fn json_round_trip_keeps_force_fail() {
            let json = serde_json::to_string(&sample()).expect("encode");
            assert_eq!(json.matches("\"forceFail\":true").count(), 2);
            assert!(!json.contains("\"forceFail\":false"));
            assert_eq!(
                serde_json::from_str::<Blocks>(&json).expect("decode"),
                sample()
            );
        }

        /// Stored fixtures are binary `L1TxCommonData`; the flag must not move their layout.
        #[test]
        fn binary_l1_common_data_omits_force_fail() {
            let cfg = bincode::config::standard();
            let encode = |force_fail| {
                bincode::serde::encode_to_vec(
                    L1TxCommonData {
                        force_fail,
                        ..Default::default()
                    },
                    cfg,
                )
                .expect("encode")
            };
            assert_eq!(encode(true), encode(false));
        }

        fn decode_with_positions(positions: Vec<(u32, u32)>) -> Result<Blocks, String> {
            let cfg = bincode::config::standard();
            let Blocks(plain) = blocks(vec![
                vec![l1_tx(false), l1_tx(false)],
                vec![tx(ExecuteTransactionCommon::ProtocolUpgrade(
                    ProtocolUpgradeTxCommonData::default(),
                ))],
            ]);
            let bytes = bincode::serde::encode_to_vec((plain, positions), cfg).expect("encode");
            bincode::serde::decode_from_slice::<Blocks, _>(&bytes, cfg)
                .map(|(blocks, _)| blocks)
                .map_err(|err| err.to_string())
        }

        #[test]
        fn binary_rejects_invalid_positions() {
            assert!(decode_with_positions(vec![(0, 1)]).is_ok());
            for (positions, expected) in [
                (vec![(0, 1), (0, 0)], "strictly ascending"),
                (vec![(0, 0), (0, 0)], "strictly ascending"),
                (vec![(0, 2)], "out of range"),
                (vec![(2, 0)], "out of range"),
                (vec![(1, 0)], "not an L1 tx"),
            ] {
                let err = decode_with_positions(positions.clone()).unwrap_err();
                assert!(err.contains(expected), "{positions:?}: {err}");
            }
        }
    }
}
