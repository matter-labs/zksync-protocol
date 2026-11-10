use std::{fs::File, path::Path};

use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;
use zksync_airbender_verifier::{types::AirbenderVerifierInput, Verify};
use zksync_cli_utils::{labeled::LabeledVerifierInput, load_batch, save_batch, BatchInputFile};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        InspectExecutionMode, L2BlockEnv, VmInterface, VmInterfaceExt,
    },
    pubdata_builders::pubdata_params_to_builder,
    FastVmInstance,
};
use zksync_types::{ExecuteTransactionCommon, ProtocolVersionId, H256, U256};

#[derive(Deserialize)]
struct Fixture {
    input: LabeledVerifierInput,
    expected: Value,
}

fn fixture(name: &str) -> Fixture {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../testdata/v34/{name}.json.gz"));
    serde_json::from_reader(GzDecoder::new(File::open(path).unwrap())).unwrap()
}

fn verify_fixture(name: &str) {
    let fixture = fixture(name);
    assert_eq!(fixture.input.labels().system_env_version, 34);
    let input = fixture.input.into_verifier_input().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("1.bin.gz");
    save_batch(&input, &path).unwrap();
    let stored = load_batch(&BatchInputFile { number: 1, path }).unwrap();
    assert_eq!(stored, input);
    let cfg = bincode::config::standard();
    let bytes = bincode::serde::encode_to_vec(&stored, cfg).unwrap();
    let (guest, read): (AirbenderVerifierInput, _) =
        bincode::serde::decode_from_slice(&bytes, cfg).unwrap();
    assert_eq!(read, bytes.len());
    assert_eq!(guest, input);
    let result = guest.verify().unwrap();
    let expected = fixture.expected;
    macro_rules! compare {
        ($field:ident) => {
            assert_eq!(
                serde_json::to_value(&result.$field).unwrap(),
                expected[stringify!($field)],
                stringify!($field)
            );
        };
    }
    assert_eq!(
        serde_json::to_value(result.value_hash).unwrap(),
        expected["state_root"]
    );
    compare!(commitment);
    compare!(proof_public_input);
    compare!(new_enumeration_index);
    compare!(pass_through_data_hash);
    compare!(metadata_hash);
    compare!(auxiliary_output_hash);
    compare!(bootloader_heap_hash);
    compare!(system_logs);
    compare!(state_diffs);
    compare!(pubdata_input);
}

#[test]
fn normal_batch_matches_era_v34() {
    verify_fixture("normal");
}

#[test]
fn mixed_force_fail_batch_matches_era_v34() {
    verify_fixture("mixed");
}

#[test]
fn removing_force_fail_does_not_match_era_witness() {
    let mut input = fixture("mixed").input.into_verifier_input().unwrap();
    let mut cleared = 0;
    for block in &mut input.l2_blocks_execution_data {
        for tx in &mut block.txs {
            if let ExecuteTransactionCommon::L1(data) = &mut tx.common_data {
                cleared += usize::from(data.force_fail);
                data.force_fail = false;
            }
        }
    }
    assert_eq!(cleared, 1);
    assert!(input.verify().is_err());
}

#[test]
fn transaction_results_match_era_v34() {
    for name in ["normal", "mixed"] {
        let fixture = fixture(name);
        let input = fixture.input.into_verifier_input().unwrap();
        let key = |value: U256| {
            let mut bytes = [0; 32];
            value.to_little_endian(&mut bytes);
            H256(bytes)
        };
        let mut slots = std::collections::BTreeMap::new();
        for proof in &input.merkle_paths.merkle_paths {
            let value = (!proof.first_write && proof.leaf_enumeration_index != 0)
                .then_some((H256(proof.value_read), proof.leaf_enumeration_index));
            slots.insert(key(proof.leaf_hashed_key), value);
        }
        for proof in &input.prestate_read_proofs {
            slots.insert(
                key(proof.leaf_hashed_key),
                (proof.leaf_enumeration_index != 0)
                    .then_some((H256(proof.value), proof.leaf_enumeration_index)),
            );
        }
        let deps = input
            .vm_run_data
            .used_bytecodes
            .iter()
            .map(|(hash, words)| {
                let mut bytes = [0; 32];
                hash.to_big_endian(&mut bytes);
                (H256(bytes), words.clone().into_flattened())
            })
            .collect();
        let storage = StorageView::new(StorageSnapshot::new(slots, deps)).to_rc_ptr();
        let mut vm = FastVmInstance::<_>::fast(
            input.l1_batch_env,
            input
                .system_env
                .into_system_env(ProtocolVersionId::Version34),
            storage,
        );
        let expected = fixture.expected["transactions"].as_array().unwrap();
        let txs = &input.l2_blocks_execution_data[0].txs;
        assert_eq!(txs.len(), expected.len());
        for (tx, expected) in txs.iter().zip(expected) {
            vm.push_transaction(tx.clone());
            let result = vm.execute(InspectExecutionMode::OneTx);
            assert_eq!(
                result.result.is_failed(),
                expected["failed"].as_bool().unwrap()
            );
            assert_eq!(
                serde_json::to_value(result.logs.user_l2_to_l1_logs).unwrap(),
                expected["user_l2_to_l1_logs"]
            );
        }
        vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(
            input.l2_blocks_execution_data.last().unwrap(),
        ));
        let finished = vm.finish_batch(pubdata_params_to_builder(
            input.pubdata_params,
            ProtocolVersionId::Version34,
        ));
        assert!(!finished.block_tip_execution_result.result.is_failed());
        assert_eq!(
            serde_json::to_value(finished.final_execution_state.user_l2_to_l1_logs).unwrap(),
            fixture.expected["user_l2_to_l1_logs"]
        );
    }
}
