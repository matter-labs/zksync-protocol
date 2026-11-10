use std::{cell::RefCell, collections::HashMap, fmt, rc::Rc};

use zksync_types::{StorageKey, StorageValue, H256};

use super::{ReadStorage, StoragePtr, WriteStorage};

/// Statistics for [`StorageView`].
#[derive(Debug, Default, Clone, Copy)]
struct StorageViewStats {
    /// Number of read / write ops for which the value was read from the underlying storage.
    pub storage_invocations_missed: usize,
}

/// `StorageView` is a buffer for `StorageLog`s between storage and transaction execution code.
///
/// In order to commit transactions logs should be submitted to the underlying storage
/// after a transaction is executed.
///
/// When executing transactions as a part of L2 block / L1 batch creation,
/// a single `StorageView` is used for the entire L1 batch.
/// One `StorageView` must not be used for multiple L1 batches;
/// otherwise, [`Self::is_write_initial()`] will return incorrect values because of the caching.
///
/// When executing transactions in the API sandbox, a dedicated view is used for each transaction;
/// the only shared part is the read storage keys cache.
#[derive(Debug)]
pub struct StorageView<S> {
    storage_handle: S,
    // Used for caching and to get the list/count of modified keys
    modified_storage_keys: HashMap<StorageKey, StorageValue>,
    cache: StorageViewCache,
    stats: StorageViewStats,
}

/// `StorageViewCache` is a struct for caching storage reads and `contains_key()` checks.
#[derive(Debug, Default, Clone)]
struct StorageViewCache {
    // Used purely for caching
    read_storage_keys: HashMap<StorageKey, StorageValue>,
    // Cache for `contains_key()` checks. The cache is only valid within one L1 batch execution.
    initial_writes: HashMap<StorageKey, bool>,
}

impl<S> ReadStorage for Box<S>
where
    S: ReadStorage + ?Sized,
{
    fn read_value(&mut self, key: &StorageKey) -> StorageValue {
        (**self).read_value(key)
    }

    fn is_write_initial(&mut self, key: &StorageKey) -> bool {
        (**self).is_write_initial(key)
    }

    fn load_factory_dep(&mut self, hash: H256) -> Option<Vec<u8>> {
        (**self).load_factory_dep(hash)
    }

    fn is_bytecode_known(&mut self, bytecode_hash: &H256) -> bool {
        (**self).is_bytecode_known(bytecode_hash)
    }

    fn get_enumeration_index(&mut self, key: &StorageKey) -> Option<u64> {
        (**self).get_enumeration_index(key)
    }
}

impl<S: ReadStorage> StorageView<S> {
    /// Creates a new storage view based on the underlying storage.
    pub fn new(storage_handle: S) -> Self {
        Self {
            storage_handle,
            modified_storage_keys: HashMap::new(),
            cache: StorageViewCache {
                read_storage_keys: HashMap::new(),
                initial_writes: HashMap::new(),
            },
            stats: StorageViewStats::default(),
        }
    }

    fn get_value_no_log(&mut self, key: &StorageKey) -> StorageValue {
        // let started_at = Instant::now();

        let cached_value = self
            .modified_storage_keys
            .get(key)
            .or_else(|| self.cache.read_storage_keys.get(key));
        cached_value.copied().unwrap_or_else(|| {
            let value = self.storage_handle.read_value(key);
            self.cache.read_storage_keys.insert(*key, value);
            // self.stats.time_spent_on_storage_missed += started_at.elapsed();
            self.stats.storage_invocations_missed += 1;
            value
        })
    }

    /// Make a Rc RefCell ptr to the storage
    pub fn to_rc_ptr(self) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(self))
    }
}

impl<S: ReadStorage + fmt::Debug> ReadStorage for StorageView<S> {
    fn read_value(&mut self, key: &StorageKey) -> StorageValue {
        let value = self.get_value_no_log(key);

        tracing::trace!(
            "read value {:?} {:?} ({:?}/{:?})",
            key.hashed_key().0,
            value.0,
            key.address(),
            key.key()
        );

        // self.stats.time_spent_on_get_value += started_at.elapsed();
        value
    }

    /// Only keys contained in the underlying storage will return `false`. If a key was
    /// inserted using [`Self::set_value()`], it will still return `true`.
    fn is_write_initial(&mut self, key: &StorageKey) -> bool {
        if let Some(&is_write_initial) = self.cache.initial_writes.get(key) {
            is_write_initial
        } else {
            let is_write_initial = self.storage_handle.is_write_initial(key);
            self.cache.initial_writes.insert(*key, is_write_initial);
            is_write_initial
        }
    }

    fn load_factory_dep(&mut self, hash: H256) -> Option<Vec<u8>> {
        self.storage_handle.load_factory_dep(hash)
    }

    fn get_enumeration_index(&mut self, key: &StorageKey) -> Option<u64> {
        self.storage_handle.get_enumeration_index(key)
    }
}

impl<S: ReadStorage + fmt::Debug> WriteStorage for StorageView<S> {
    fn read_storage_keys(&self) -> &HashMap<StorageKey, StorageValue> {
        &self.cache.read_storage_keys
    }

    fn set_value(&mut self, key: StorageKey, value: StorageValue) -> StorageValue {
        let original = self.get_value_no_log(&key);

        tracing::trace!(
            "write value {:?} value: {:?} original value: {:?} ({:?}/{:?})",
            key.hashed_key().0,
            value,
            original,
            key.address(),
            key.key()
        );
        self.modified_storage_keys.insert(key, value);
        // self.stats.time_spent_on_set_value += started_at.elapsed();

        original
    }

    fn modified_storage_keys(&self) -> &HashMap<StorageKey, StorageValue> {
        &self.modified_storage_keys
    }

    fn missed_storage_invocations(&self) -> usize {
        self.stats.storage_invocations_missed
    }
}

/// Immutable wrapper around [`StorageView`] for direct reads.
///
/// Reads directly from the underlying storage ignoring any modifications in the [`StorageView`].
/// Used by the fast VM, which has its own internal management of writes.
#[derive(Debug)]
pub struct ImmutableStorageView<S>(StoragePtr<StorageView<S>>);

impl<S: ReadStorage> ImmutableStorageView<S> {
    /// Creates a new view based on the provided storage pointer.
    pub fn new(ptr: StoragePtr<StorageView<S>>) -> Self {
        Self(ptr)
    }

    #[doc(hidden)] // can easily break invariants if not used carefully
    pub fn to_rc_ptr(&self) -> StoragePtr<StorageView<S>> {
        self.0.clone()
    }
}

// All methods other than `read_value()` do not read back modified storage slots, so we proxy them as-is.
impl<S: ReadStorage> ReadStorage for ImmutableStorageView<S> {
    fn read_value(&mut self, key: &StorageKey) -> StorageValue {
        // let started_at = Instant::now();
        let mut this = self.0.borrow_mut();
        let cached_value = this.read_storage_keys().get(key);
        cached_value.copied().unwrap_or_else(|| {
            let value = this.storage_handle.read_value(key);
            this.cache.read_storage_keys.insert(*key, value);
            // this.stats.time_spent_on_storage_missed += started_at.elapsed();
            this.stats.storage_invocations_missed += 1;
            value
        })
    }

    fn is_write_initial(&mut self, key: &StorageKey) -> bool {
        self.0.borrow_mut().is_write_initial(key)
    }

    fn load_factory_dep(&mut self, hash: H256) -> Option<Vec<u8>> {
        self.0.borrow_mut().load_factory_dep(hash)
    }

    fn get_enumeration_index(&mut self, key: &StorageKey) -> Option<u64> {
        self.0.borrow_mut().get_enumeration_index(key)
    }
}
