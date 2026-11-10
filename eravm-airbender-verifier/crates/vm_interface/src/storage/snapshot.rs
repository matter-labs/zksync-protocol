use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zksync_types::{web3, StorageKey, StorageValue, H256};

use super::ReadStorage;

/// Self-sufficient or almost self-sufficient storage snapshot for a particular VM execution (e.g., executing a single L1 batch).
///
/// `StorageSnapshot` is immutable and represents a complete or almost complete storage image
/// for a particular VM execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageSnapshot {
    // `Option` encompasses entire map value for more efficient serialization
    storage: BTreeMap<H256, Option<(H256, u64)>>,
    // `Bytes` are used to have efficient serialization
    factory_deps: BTreeMap<H256, web3::Bytes>,
}

impl StorageSnapshot {
    /// Creates a new storage snapshot.
    ///
    /// # Arguments
    ///
    /// - `storage` should contain all storage slots accessed during VM execution, i.e. protective reads + initial / repeated writes
    ///   for batch execution, keyed by the hashed storage key. `None` map values correspond to accessed slots without an assigned enum index
    ///   and 0 values. There may be slots w/o an index and non-zero value if the snapshot captures execution from a middle of batch;
    ///   in this case, you should supply `Some(_, 0)`.
    pub fn new(
        storage: BTreeMap<H256, Option<(H256, u64)>>,
        factory_deps: BTreeMap<H256, Vec<u8>>,
    ) -> Self {
        Self {
            storage,
            factory_deps: factory_deps
                .into_iter()
                .map(|(hash, bytecode)| (hash, web3::Bytes(bytecode)))
                .collect(),
        }
    }
}

/// When used as a storage, a snapshot is assumed to be *complete*; [`ReadStorage`] methods will panic when called
/// with storage slots not present in the snapshot.
impl ReadStorage for StorageSnapshot {
    fn read_value(&mut self, key: &StorageKey) -> StorageValue {
        let entry = self
            .storage
            .get(&key.hashed_key())
            .unwrap_or_else(|| panic!("attempted to read from unknown storage slot: {key:?}"));
        entry.unwrap_or_default().0
    }

    fn is_write_initial(&mut self, key: &StorageKey) -> bool {
        let entry = self.storage.get(&key.hashed_key()).unwrap_or_else(|| {
            panic!("attempted to check initialness for unknown storage slot: {key:?}")
        });
        entry.is_none_or(|(_, idx)| idx == 0)
    }

    fn load_factory_dep(&mut self, hash: H256) -> Option<Vec<u8>> {
        self.factory_deps.get(&hash).map(|bytes| bytes.0.clone())
    }

    fn get_enumeration_index(&mut self, key: &StorageKey) -> Option<u64> {
        let entry = self.storage.get(&key.hashed_key()).unwrap_or_else(|| {
            panic!("attempted to get enum index for unknown storage slot: {key:?}")
        });
        entry.and_then(|(_, idx)| (idx > 0).then_some(idx))
    }
}
