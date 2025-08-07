use zk_evm::{
    abstractions::{Storage, StorageAccessRefund},
    aux_structures::{LogQuery, PubdataCost, Timestamp},
    ethereum_types::{H256, U256},
    zkevm_opcode_defs::system_params::{STORAGE_AUX_BYTE, TRANSIENT_STORAGE_AUX_BYTE},
};

use alloc::vec;
use alloc::vec::Vec;

use crate::{AccountTreeId, StorageKey, WitnessStorageState};

// Due to traces, we've noticed in the past that storage_refunds and pubdata_costs can be different than actual state_keeper's run.
// Whilst this may not be true today, the storage oracle implementation in witness_generator guards us from such issues in the future.
#[derive(Debug)]
pub struct StorageOracle<T> {
    inn: T,
    storage_refunds: vec::IntoIter<u32>,
    pubdata_costs: vec::IntoIter<i32>,
}

impl<T> StorageOracle<T> {
    pub fn new(inn: T, storage_refunds: Vec<u32>, pubdata_costs: Vec<i32>) -> Self {
        Self {
            inn,
            // storage_refunds as precalculated in state_keeper
            storage_refunds: storage_refunds.into_iter(),
            // pubdata_costs as precalculated in state_keeper
            pubdata_costs: pubdata_costs.into_iter(),
        }
    }
}

impl<T: Storage> Storage for StorageOracle<T> {
    fn get_access_refund(
        &mut self,
        _monotonic_cycle_counter: u32,
        partial_query: &LogQuery,
    ) -> StorageAccessRefund {
        if partial_query.aux_byte == TRANSIENT_STORAGE_AUX_BYTE {
            // Any transient access is warm. Also, no refund needs to be provided as it is already cheap
            StorageAccessRefund::Warm { ergs: 0 }
        } else if partial_query.aux_byte == STORAGE_AUX_BYTE {
            let storage_refunds = self.storage_refunds.next().expect("Missing refund");
            if storage_refunds == 0 {
                StorageAccessRefund::Cold
            } else {
                StorageAccessRefund::Warm {
                    ergs: storage_refunds,
                }
            }
        } else {
            unreachable!()
        }
    }

    fn start_new_tx(&mut self, timestamp: Timestamp) {
        self.inn.start_new_tx(timestamp)
    }

    fn execute_partial_query(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
    ) -> (LogQuery, PubdataCost) {
        let (query, _) = self
            .inn
            .execute_partial_query(monotonic_cycle_counter, query);
        let pubdata_cost = self.pubdata_costs.next().expect("Missing pubdata cost");
        (query, PubdataCost(pubdata_cost))
    }

    fn finish_frame(&mut self, timestamp: Timestamp, panicked: bool) {
        self.inn.finish_frame(timestamp, panicked)
    }

    fn start_frame(&mut self, timestamp: Timestamp) {
        self.inn.start_frame(timestamp)
    }
}

#[derive(Debug)]
pub struct WitnessStorageOracle {
    pub slots: hashbrown::HashMap<StorageKey, H256>,
}

impl WitnessStorageOracle {
    pub fn new(data: WitnessStorageState) -> Self {
        let mut slots = hashbrown::HashMap::new();
        for (key, value) in data.read_storage_key {
            slots.insert(key, value);
        }
        Self { slots }
    }
}
pub fn h256_to_u256(num: H256) -> U256 {
    U256::from_big_endian(num.as_bytes())
}
pub fn u256_to_h256(num: U256) -> H256 {
    let mut bytes = [0u8; 32];
    num.to_big_endian(&mut bytes);
    H256::from_slice(&bytes)
}

// This is super hacky -- I am not handling any transient storage, or failures.
impl Storage for WitnessStorageOracle {
    fn get_access_refund(
        &mut self, // to avoid any hacks inside, like prefetch
        monotonic_cycle_counter: u32,
        partial_query: &LogQuery,
    ) -> StorageAccessRefund {
        // this should never get called.
        todo!()
    }

    fn execute_partial_query(
        &mut self,
        monotonic_cycle_counter: u32,
        mut query: LogQuery,
    ) -> (LogQuery, PubdataCost) {
        assert!(!query.rollback);
        assert_eq!(query.aux_byte, STORAGE_AUX_BYTE);

        let storage_key = StorageKey {
            account: AccountTreeId {
                address: query.address,
            },
            key: u256_to_h256(query.key),
        };
        let read_value = self.slots.get(&storage_key).cloned().unwrap_or_default();
        // do I need to track 'initial value'??

        query.read_value = h256_to_u256(read_value);
        // pubdata costs can be ignored here.
        if query.rw_flag {
            // if it is a write, we need to update the storage.
            self.slots
                .insert(storage_key, u256_to_h256(query.written_value));
        }

        (query, PubdataCost(0)) // pubdata cost is not relevant here.
    }

    fn start_frame(&mut self, timestamp: Timestamp) {
        // Nothing to do. (until we get transient stuff).
    }

    fn finish_frame(&mut self, timestamp: Timestamp, panicked: bool) {
        // Nothing to do. (until we get transient stuff).
    }

    fn start_new_tx(&mut self, timestamp: Timestamp) {
        // Nothing to do. (until we get transient stuff).
    }
}
