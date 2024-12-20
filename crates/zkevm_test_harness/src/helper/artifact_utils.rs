use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::ethereum_types::Address;
use serde::{Deserialize, Serialize};
use zkevm_assembly::zkevm_opcode_defs::{BlobSha256, VersionedHashGeneric};
use std::collections::HashMap;

use crate::blake2::Blake2s256;
use crate::ethereum_types::{H160, U256};
use crate::witness::tree::{BinarySparseStorageTree, ZkSyncStorageLeaf};
use crate::zk_evm::bytecode_to_code_hash;
use crate::zk_evm::testing::storage::InMemoryStorage;

pub const ACCOUNT_CODE_STORAGE_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x02,
]);

pub const KNOWN_CODE_HASHES_ADDRESS: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x04,
]);

pub fn save_predeployed_contracts(
    storage: &mut InMemoryStorage,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    contracts: &HashMap<Address, Vec<[u8; 32]>>,
) {
    let mut sorted_contracts = vec![];
    let mut keys: Vec<_> = contracts.keys().cloned().collect();
    keys.sort();
    for el in keys.into_iter() {
        let v = contracts[&el].clone();

        sorted_contracts.push((el, v));
    }

    let storage_logs: Vec<(u8, Address, U256, U256)> = sorted_contracts
        .into_iter()
        .map(|(address, bytecode)| {
            let hash = bytecode_to_code_hash(&bytecode).unwrap();

            println!(
                "Have address {:?} with code hash {:x}",
                address,
                U256::from(hash)
            );

            vec![
                (
                    0,
                    ACCOUNT_CODE_STORAGE_ADDRESS,
                    U256::from_big_endian(address.as_bytes()),
                    U256::from(hash),
                ),
                (
                    0,
                    KNOWN_CODE_HASHES_ADDRESS,
                    U256::from(hash),
                    U256::from(1u64),
                ),
            ]
        })
        .flatten()
        .collect();

    populate_storage(storage, tree, storage_logs);
}

pub fn save_predeployed_evm_contract_stubs(
    storage: &mut InMemoryStorage,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    contracts: &Vec<Address>,
) {
    let mut sorted_contracts = contracts.clone();
    sorted_contracts.sort();

    let empty_code_hash = U256::from_big_endian(&bytecode_to_code_hash(&[[0; 32]]).unwrap());
    let versioned_hash =
    VersionedHashGeneric::<BlobSha256>::from_digest_and_preimage_length(
        empty_code_hash.into(),
        0,
    );

    let evm_stub_hash = U256::from_big_endian(&versioned_hash.serialize().unwrap());

    let storage_logs: Vec<(u8, Address, U256, U256)> = sorted_contracts
        .into_iter()
        .map(|address| {
            let hash = evm_stub_hash.clone();

            println!(
                "Have address {:?} in EVM mode with code hash {:x}",
                address,
                U256::from(hash)
            );

            vec![
                (
                    0,
                    ACCOUNT_CODE_STORAGE_ADDRESS,
                    U256::from_big_endian(address.as_bytes()),
                    U256::from(hash),
                ),
                (
                    0,
                    KNOWN_CODE_HASHES_ADDRESS,
                    U256::from(hash),
                    U256::from(1u64),
                ),
            ]
        })
        .flatten()
        .collect();

    populate_storage(storage, tree, storage_logs);
}

fn populate_storage(
    storage: &mut InMemoryStorage,
    tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    storage_logs: Vec<(u8, Address, U256, U256)>
) {
    storage.populate(storage_logs.clone());

    for (shard_id, address, key, value) in storage_logs.into_iter() {
        assert!(shard_id == 0);
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        use crate::witness::tree::EnumeratedBinaryLeaf;
        let mut leaf = ZkSyncStorageLeaf::empty();
        let mut buffer = [0u8; 32];
        value.to_big_endian(&mut buffer);
        leaf.set_value(&buffer);

        tree.insert_leaf(&index, leaf);
    } 
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestArtifact {
    pub entry_point_address: Address,
    pub entry_point_code: Vec<[u8; 32]>,
    pub default_account_code: Vec<[u8; 32]>,
    pub evm_simulator_code: Vec<[u8; 32]>,
    pub predeployed_contracts: HashMap<Address, Vec<[u8; 32]>>,
}
