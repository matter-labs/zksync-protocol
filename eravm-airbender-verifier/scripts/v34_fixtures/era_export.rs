use ethabi::Token;
use zksync_test_contracts::{TestContract, TxType};
use zksync_types::{Execute, ExecuteTransactionCommon, H256, U256};

use super::{
    default_pubdata_builder, default_system_env, TestedVm, VmTesterBuilder, BASE_SYSTEM_CONTRACTS,
};
use crate::{
    interface::{InspectExecutionMode, TxExecutionMode, VmFactory, VmInterface, VmInterfaceExt},
    vm_latest::{HistoryEnabled, Vm},
};

#[test]
#[ignore]
fn export_v34_fixtures() {
    let output = std::path::PathBuf::from(std::env::var("V34_FIXTURE_OUTPUT").unwrap());
    std::fs::create_dir_all(&output).unwrap();
    for force_fail in [false, true] {
        let mut system_env = default_system_env();
        system_env.default_validation_computational_gas_limit = u32::MAX;
        let mut tester = VmTesterBuilder::new()
            .with_system_env(system_env)
            .with_base_system_smart_contracts(BASE_SYSTEM_CONTRACTS.clone())
            .with_execution_mode(TxExecutionMode::VerifyExecute)
            .with_l1_base_token_minting(H256::repeat_byte(0x11))
            .with_rich_accounts(1)
            .build::<Vm<_, HistoryEnabled>>();
        assert_eq!(tester.system_env.version as u16, 34);
        let initial_storage =
            serde_json::to_value(tester.storage.borrow_mut().inner_mut()).unwrap();
        tester.l1_batch_env.previous_batch_hash = Some(prestate_root(&initial_storage));
        tester.vm = Vm::new(
            tester.l1_batch_env.clone(),
            tester.system_env.clone(),
            tester.storage.clone(),
        );
        let account = &mut tester.rich_accounts[0];
        let deploy = account.get_deploy_tx(
            TestContract::counter().bytecode,
            None,
            TxType::L1 { serial_id: 0 },
        );
        let target = deploy.address;
        let mut transactions = vec![deploy.tx];
        for serial_id in 1..=2 {
            let calldata = TestContract::counter()
                .abi
                .function("incrementWithRevertPayable")
                .unwrap()
                .encode_input(&[Token::Uint(U256::one()), Token::Bool(false)])
                .unwrap();
            let mut tx = account.get_l1_tx(
                Execute {
                    contract_address: Some(target),
                    calldata,
                    value: U256::from(10),
                    factory_deps: vec![TestContract::load_test().bytecode.to_vec()],
                },
                serial_id,
            );
            let ExecuteTransactionCommon::L1(data) = &mut tx.common_data else {
                unreachable!()
            };
            data.force_fail = force_fail && serial_id == 1;
            transactions.push(tx);
        }
        for tx in &mut transactions {
            tx.received_timestamp_ms = 0;
        }
        let mut results = vec![];
        for (index, tx) in transactions.iter().enumerate() {
            tester.vm.push_transaction(tx.clone());
            let result = tester.vm.execute(InspectExecutionMode::OneTx);
            assert_eq!(
                result.result.is_failed(),
                force_fail && index == 1,
                "{result:?}"
            );
            results.push(serde_json::json!({
                "failed": result.result.is_failed(),
                "user_l2_to_l1_logs": result.logs.user_l2_to_l1_logs,
            }));
        }
        let first = &tester.l1_batch_env.first_l2_block;
        let next = crate::interface::L2BlockEnv {
            number: first.number + 1,
            timestamp: first.timestamp + 1,
            prev_block_hash: tester.vm.last_l2_block_hash(),
            max_virtual_blocks_to_create: 1,
            interop_roots: vec![],
        };
        tester.vm.start_new_l2_block(next.clone());
        let blocks = vec![
            zksync_types::block::L2BlockExecutionData {
                number: zksync_types::L2BlockNumber(first.number),
                timestamp: first.timestamp,
                prev_block_hash: first.prev_block_hash,
                virtual_blocks: first.max_virtual_blocks_to_create,
                txs: transactions.clone(),
                interop_roots: vec![],
            },
            zksync_types::block::L2BlockExecutionData {
                number: zksync_types::L2BlockNumber(next.number),
                timestamp: next.timestamp,
                prev_block_hash: next.prev_block_hash,
                virtual_blocks: next.max_virtual_blocks_to_create,
                txs: vec![],
                interop_roots: vec![],
            },
        ];
        let finished = tester.vm.finish_batch(default_pubdata_builder());
        assert!(!finished.block_tip_execution_result.result.is_failed());
        let chain_count = tester.vm.read_storage(zksync_types::StorageKey::new(
            zksync_types::AccountTreeId::new(zksync_system_constants::L2_MESSAGE_ROOT_ADDRESS),
            H256::from_low_u64_be(zksync_system_constants::message_root::CHAIN_COUNT_KEY as u64),
        ));
        assert!(chain_count.is_zero());
        // MessageRootBase returns this empty-tree hash when chainCount is zero.
        let aggregation_root = H256(zksync_types::web3::keccak256(&[0u8; 96]));
        let state = &finished.final_execution_state;
        let accessed_keys: Vec<_> = tester
            .storage
            .borrow()
            .cache()
            .read_storage_keys()
            .keys()
            .map(|key| key.hashed_key_u256())
            .collect();
        let storage_logs: Vec<_> = state.deduplicated_storage_logs.iter().map(|log| serde_json::json!({
            "key": log.key.hashed_key_u256(), "is_write": log.is_write(), "value": log.value,
        })).collect();
        let fixture = serde_json::json!({
            "system_env": tester.system_env,
            "l1_batch_env": tester.l1_batch_env,
            "l2_blocks_execution_data": blocks,
            "pubdata_params": zksync_types::commitment::PubdataParams::new(
                zksync_types::commitment::L2PubdataValidator::CommitmentScheme(
                    zksync_types::commitment::L2DACommitmentScheme::BlobsAndPubdataKeccak256),
                Default::default()).unwrap(),
            "initial_storage": initial_storage,
            "accessed_keys": accessed_keys,
            "expected": {
                "aggregation_root": aggregation_root,
                "transactions": results,
                "system_logs": state.system_logs,
                "user_l2_to_l1_logs": state.user_l2_to_l1_logs,
                "storage_logs": storage_logs,
                "state_diffs": finished.state_diffs,
                "pubdata_input": finished.pubdata_input,
                "bootloader_memory": finished.final_bootloader_memory,
                "storage_refunds": state.storage_refunds,
                "pubdata_costs": state.pubdata_costs,
            },
        });
        let name = if force_fail { "mixed" } else { "normal" };
        std::fs::write(
            output.join(format!("{name}.json")),
            serde_json::to_vec(&fixture).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore]
fn finalize_v34_fixture_commitments() {
    use zksync_crypto_primitives::hasher::{blake2::Blake2Hasher, Hasher};
    use zksync_l1_contract_interface::i_executor::commit::kzg::{
        pubdata_to_blob_commitments, pubdata_to_blob_linear_hashes,
        pubdata_to_blob_versioned_hashes,
    };
    use zksync_types::{commitment::*, web3::keccak256, ProtocolVersionId};
    let output = std::path::PathBuf::from(std::env::var("V34_FIXTURE_OUTPUT").unwrap());
    for name in ["normal", "mixed"] {
        let path = output.join(format!("{name}.prepared.json"));
        let mut fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let input = &fixture["input"];
        let expected = &fixture["expected"];
        let pubdata: Vec<u8> = serde_json::from_value(expected["pubdata_input"].clone()).unwrap();
        let commitments = pubdata_to_blob_commitments(16, &pubdata);
        let versioned = pubdata_to_blob_versioned_hashes(16, &pubdata);
        let linear = pubdata_to_blob_linear_hashes(16, pubdata);
        let blob_json: Vec<_> = commitments.iter().zip(&linear).map(|(commitment, linear_hash)|
            serde_json::json!({"commitment": commitment, "linear_hash": linear_hash})).collect();
        let blobs = commitments
            .into_iter()
            .zip(linear)
            .map(|(commitment, linear_hash)| BlobHash {
                commitment,
                linear_hash,
            })
            .collect();
        let base: zksync_contracts::BaseSystemContracts =
            serde_json::from_value(input["system_env"]["base_system_smart_contracts"].clone())
                .unwrap();
        let heap: Vec<(usize, U256)> =
            serde_json::from_value(expected["bootloader_memory"].clone()).unwrap();
        let mut memory =
            vec![
                0u8;
                crate::utils::get_used_bootloader_memory_bytes(ProtocolVersionId::Version34.into())
            ];
        for (offset, value) in heap {
            value.to_big_endian(&mut memory[offset * 32..(offset + 1) * 32]);
        }
        let heap_hash = Blake2Hasher.hash_bytes(&memory);
        let state_diffs = serde_json::from_value(expected["state_diffs"].clone()).unwrap();
        let system_logs = serde_json::from_value(expected["system_logs"].clone()).unwrap();
        let commitment = L1BatchCommitment::new(
            CommitmentInput::PostBoojum {
                common: CommitmentCommonInput {
                    l2_to_l1_logs: serde_json::from_value(expected["user_l2_to_l1_logs"].clone())
                        .unwrap(),
                    rollup_last_leaf_index: expected["new_enumeration_index"].as_u64().unwrap(),
                    rollup_root_hash: serde_json::from_value(expected["state_root"].clone())
                        .unwrap(),
                    bootloader_code_hash: base.bootloader.hash,
                    default_aa_code_hash: base.default_aa.hash,
                    evm_emulator_code_hash: base.evm_emulator.map(|e| e.hash),
                    protocol_version: ProtocolVersionId::Version34,
                },
                system_logs,
                state_diffs,
                aux_commitments_both: AuxCommitmentsBoth {
                    boojum: AuxCommitments {
                        events_queue_commitment: H256::zero(),
                        bootloader_initial_content_commitment: H256::zero(),
                    },
                    airbender: Some(AuxCommitments {
                        events_queue_commitment: H256::zero(),
                        bootloader_initial_content_commitment: heap_hash,
                    }),
                },
                blob_hashes: blobs,
                aggregation_root: serde_json::from_value(expected["aggregation_root"].clone())
                    .unwrap(),
            },
            false,
        )
        .unwrap();
        let shared_hashes = commitment.hash().unwrap();
        let commitment = commitment.airbender_artifacts().unwrap().unwrap();
        let old_root: H256 =
            serde_json::from_value(input["l1_batch_env"]["previous_batch_hash"].clone()).unwrap();
        let next_index = input["merkle_paths"]["next_enumeration_index"]
            .as_u64()
            .unwrap();
        let prev = H256(keccak256(
            &[
                &next_index.to_be_bytes()[..],
                old_root.as_bytes(),
                &[0u8; 40],
            ]
            .concat(),
        ));
        let previous_commitment = H256(keccak256(&[prev.as_bytes(), &[0u8; 64]].concat()));
        let public_input = keccak256(
            &[
                previous_commitment.as_bytes(),
                commitment.commitment.as_bytes(),
            ]
            .concat(),
        );
        fixture["input"]["commitment_input"] = serde_json::json!({
            "prev_batch_commitment": previous_commitment,
            "prev_meta_hash": H256::zero(), "prev_aux_hash": H256::zero(),
            "blob_hashes": blob_json, "blob_versioned_hashes": versioned,
        });
        fixture["expected"]["commitment"] = serde_json::json!(commitment.commitment);
        fixture["expected"]["proof_public_input"] = serde_json::json!(public_input
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>());
        fixture["expected"]["bootloader_heap_hash"] = serde_json::json!(heap_hash);
        fixture["expected"]["pass_through_data_hash"] =
            serde_json::json!(shared_hashes.pass_through_data);
        fixture["expected"]["metadata_hash"] = serde_json::json!(shared_hashes.meta_parameters);
        fixture["expected"]["auxiliary_output_hash"] = serde_json::json!(commitment.aux_data_hash);
        std::fs::write(path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    }
}

fn prestate_root(storage: &serde_json::Value) -> H256 {
    use std::collections::BTreeMap;
    use zksync_crypto_primitives::hasher::{blake2::Blake2Hasher, Hasher};
    let mut nodes: BTreeMap<U256, H256> = storage["state"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, entry)| {
            let key: H256 = key.parse().unwrap();
            let value: H256 = serde_json::from_value(entry[0].clone()).unwrap();
            let index = entry[1].as_u64().unwrap();
            (
                U256::from_little_endian(key.as_bytes()),
                Blake2Hasher.hash_bytes(&[&index.to_be_bytes()[..], value.as_bytes()].concat()),
            )
        })
        .collect();
    let mut empty = Blake2Hasher.hash_bytes(&[0; 40]);
    for _ in 0..256 {
        let mut parents = BTreeMap::new();
        for &key in nodes.keys() {
            let left = key & !U256::one();
            let right = left + U256::one();
            let hash = Blake2Hasher.hash_bytes(
                &[
                    nodes.get(&left).unwrap_or(&empty).as_bytes(),
                    nodes.get(&right).unwrap_or(&empty).as_bytes(),
                ]
                .concat(),
            );
            parents.insert(key >> 1, hash);
        }
        empty = Blake2Hasher.hash_bytes(&[empty.as_bytes(), empty.as_bytes()].concat());
        nodes = parents;
    }
    nodes[&U256::zero()]
}
