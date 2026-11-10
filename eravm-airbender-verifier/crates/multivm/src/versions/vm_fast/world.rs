use std::collections::HashMap;

use zk_evm_1_5_2::zkevm_opcode_defs::ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS;
use zksync_contracts::SystemContractCode;
use zksync_system_constants::{BOOTLOADER_ADDRESS, L2_BASE_TOKEN_ADDRESS};
use zksync_types::{
    address_to_u256, get_code_key, h256_to_u256, u256_to_h256,
    utils::key_for_eth_balance,
    writes::{
        compression::compress_with_best_strategy, BYTES_PER_DERIVED_KEY,
        BYTES_PER_ENUMERATION_INDEX,
    },
    AccountTreeId, Address, StorageKey, H160, H256, U256,
};
use zksync_vm2::{
    interface::{CycleStats, Tracer},
    precompiles::{LegacyPrecompiles, PrecompileMemoryReader, PrecompileOutput, Precompiles},
    Program, StorageSlot,
};

use super::tracers::DynamicBytecodes;
use crate::{interface::storage::ReadStorage, vm_latest::bootloader::EcRecoverCall};

#[derive(Debug)]
pub(super) struct World<S, T> {
    pub(super) storage: S,
    pub(super) dynamic_bytecodes: DynamicBytecodes,
    program_cache: HashMap<U256, Program<T, Self>>,
    pub(super) bytecode_cache: HashMap<U256, Vec<u8>>,
    pub(super) precompiles: OptimizedPrecompiles,
}

impl<S: ReadStorage, T: Tracer> World<S, T> {
    pub(super) fn new(storage: S, program_cache: HashMap<U256, Program<T, Self>>) -> Self {
        Self {
            storage,
            dynamic_bytecodes: DynamicBytecodes::default(),
            program_cache,
            bytecode_cache: HashMap::default(),
            precompiles: OptimizedPrecompiles::default(),
        }
    }

    pub(super) fn convert_system_contract_code(
        code: &SystemContractCode,
        is_bootloader: bool,
    ) -> (U256, Program<T, Self>) {
        (
            h256_to_u256(code.hash),
            Program::new(&code.code, is_bootloader),
        )
    }

    pub(super) fn decommit_dynamic_bytecodes(
        &self,
        candidate_hashes: impl Iterator<Item = H256>,
    ) -> HashMap<H256, Vec<u8>> {
        let bytecodes = candidate_hashes.filter_map(|hash| {
            let bytecode = self
                .dynamic_bytecodes
                .map(h256_to_u256(hash), <[u8]>::to_vec)?;
            Some((hash, bytecode))
        });
        bytecodes.collect()
    }

    /// Checks whether the specified `address` uses the default AA.
    pub(super) fn has_default_aa(&mut self, address: &Address) -> bool {
        // The code storage slot is always read during tx validation / execution anyway.
        self.storage.read_value(&get_code_key(address)).is_zero()
    }

    /// Resolves the raw bytecode for `hash` from the byte-level sources, in the order
    /// `decommit()` established: pushed transactions' factory deps and the bootloader
    /// (`bytecode_cache`), EVM bytecodes published in this run (`dynamic_bytecodes`),
    /// then the storage fallback. This is the single copy of that chain — `decommit()`
    /// and `decommit_code()` must resolve identically, so neither duplicates it.
    ///
    /// Does NOT consult `program_cache`. The pre-seeded system contracts (default AA,
    /// and the EVM emulator when configured) exist *only* there, and no byte-level
    /// source is *guaranteed* to contain them — the factory-dep witness usually ships
    /// what the batch decommits, but nothing the guest checks enforces that for the
    /// pre-seeded pair — so a caller that can be queried for those hashes must check
    /// `program_cache` first or this can panic.
    fn raw_bytecode(&mut self, hash: U256) -> Vec<u8> {
        self.bytecode_cache
            .get(&hash)
            .cloned()
            .or_else(|| self.dynamic_bytecodes.map(hash, <[u8]>::to_vec))
            .unwrap_or_else(|| {
                // Deliberately not written back to `bytecode_cache`; see the docs on
                // the `zksync_vm2::World` impl below.
                self.storage
                    .load_factory_dep(u256_to_h256(hash))
                    .unwrap_or_else(|| {
                        panic!("VM tried to decommit nonexistent bytecode: {hash:?}");
                    })
            })
    }

    /// Re-encodes a decoded program's code page as bytes. The code page holds whole
    /// 32-byte words only (`Program::new` chunks the bytecode with `chunks_exact(32)`),
    /// so this returns `bytecode[..len - len % 32]` for the original bytecode.
    fn code_page_bytes(program: &Program<T, Self>) -> Vec<u8> {
        program
            .code_page()
            .as_ref()
            .iter()
            .flat_map(|word| {
                let mut buffer = [0u8; 32];
                word.to_big_endian(&mut buffer);
                buffer
            })
            .collect()
    }
}

impl<S: ReadStorage, T: Tracer> zksync_vm2::StorageInterface for World<S, T> {
    fn read_storage(&mut self, contract: H160, key: U256) -> StorageSlot {
        let key = &StorageKey::new(AccountTreeId::new(contract), u256_to_h256(key));
        let value = U256::from_big_endian(self.storage.read_value(key).as_bytes());
        // `is_write_initial` value can be true even if the slot has previously been written to / has non-zero value!
        // This can happen during oneshot execution (i.e., executing a single transaction) since it emulates
        // execution starting in the middle of a batch in the general case. Hence, a slot that was first written to in the batch
        // must still be considered an initial write by the refund logic.
        let is_write_initial = self.storage.is_write_initial(key);
        StorageSlot {
            value,
            is_write_initial,
        }
    }

    fn read_storage_value(&mut self, contract: H160, key: U256) -> U256 {
        let key = &StorageKey::new(AccountTreeId::new(contract), u256_to_h256(key));
        U256::from_big_endian(self.storage.read_value(key).as_bytes())
    }

    fn cost_of_writing_storage(&mut self, slot: StorageSlot, new_value: U256) -> u32 {
        if slot.value == new_value {
            return 0;
        }

        // Since we need to publish the state diffs onchain, for each of the updated storage slot
        // we basically need to publish the following pair: `(<storage_key, compressed_new_value>)`.
        // For key we use the following optimization:
        //   - The first time we publish it, we use 32 bytes.
        //         Then, we remember a 8-byte id for this slot and assign it to it. We call this initial write.
        //   - The second time we publish it, we will use the 4/5 byte representation of this 8-byte instead of the 32
        //     bytes of the entire key.
        // For value compression, we use a metadata byte which holds the length of the value and the operation from the
        // previous state to the new state, and the compressed value. The maximum for this is 33 bytes.
        // Total bytes for initial writes then becomes 65 bytes and repeated writes becomes 38 bytes.
        let compressed_value_size = compress_with_best_strategy(slot.value, new_value).len() as u32;

        if slot.is_write_initial {
            (BYTES_PER_DERIVED_KEY as u32) + compressed_value_size
        } else {
            (BYTES_PER_ENUMERATION_INDEX as u32) + compressed_value_size
        }
    }

    fn is_free_storage_slot(&self, contract: &H160, key: &U256) -> bool {
        contract == &zksync_system_constants::SYSTEM_CONTEXT_ADDRESS
            || contract == &L2_BASE_TOKEN_ADDRESS
                && u256_to_h256(*key) == key_for_eth_balance(&BOOTLOADER_ADDRESS)
    }
}

/// It may look like that an append-only cache for EVM bytecodes / `Program`s can lead to the following scenario:
///
/// 1. A transaction deploys an EVM bytecode with hash `H`, then reverts.
/// 2. A following transaction in the same VM run queries a bytecode with hash `H` and gets it.
///
/// This would be incorrect behavior because bytecode deployments must be reverted along with transactions.
///
/// In reality, this cannot happen because both `decommit()` and `decommit_code()` calls perform storage-based checks
/// before a decommit:
///
/// - `decommit_code()` is called from the `CodeOracle` system contract, which checks that the decommitted bytecode is known.
/// - `decommit()` is called during far calls, which obtains address -> bytecode hash mapping beforehand.
///
/// Thus, if storage is reverted correctly, additional EVM bytecodes occupy the cache, but are unreachable.
///
/// The cache keys are additionally bound to the cached content at insertion
/// time: `TransactionData::new` computes factory-dep hashes from the supplied
/// bytecodes; `insert_bytecodes_with_hashes` assumes the provided hashes match,
/// and the EVM deploy tracer hashes the published bytecode before inserting it.
/// Only the verifier path checks the bootloader's key (`verify_bytecode_hash` in
/// `airbender_verifier::execute`).
/// No path re-verifies content when serving a cache hit — reachability is gated
/// by the storage checks above — but a leftover entry from a reverted
/// transaction attempt can only return the same bytecode the requesting hash
/// already resolves to. For that reason these caches are intentionally left out
/// of VM snapshot/rollback — there is nothing to undo.
///
/// Diverges from zksync-era: the storage fallback in `decommit()` does not write
/// the loaded bytecode back into `bytecode_cache`. That write-back kept one
/// `Vec<u8>` per distinct decommitted contract, never evicted, duplicating bytes
/// the storage snapshot already holds. Upstream syncs must not reinstate it;
/// `tests::storage_loaded_bytecode_is_not_cached` pins this.
///
/// So `bytecode_cache` holds only pushed transactions' factory deps
/// (`insert_bytecodes_with_hashes`, from `push_transaction_inner` before each
/// execution attempt), which the snapshot need not contain yet, and the
/// bootloader, which `Vm::custom` seeds because the witness omits it. Neither
/// reader looks up anything else: `published_bytecodes` takes its hashes from
/// `BytecodeL1PublicationRequested`, which the bootloader emits only for the
/// emitting transaction's own `factoryDeps`; `has_unpublished_bytecodes` reads
/// that transaction's compressed-bytecode list. In the latter the
/// `is_bytecode_known` disjunct is always false — the list is pre-filtered to
/// hashes unknown at push time, and `storage` does not observe in-VM writes — so
/// the cache lookup alone decides it.
///
/// Snapshot reads and decoding are deterministic, and `program_cache` is
/// unbounded, so each far-called bytecode is decoded at most once per batch.
/// Giving that cache an eviction policy would make a re-decode reachable.
///
/// Diverges from zksync-era: `decommit_code()` does not decode. Upstream routes
/// it through `decommit()`, decoding the bytecode and pinning the resulting
/// program in `program_cache`; here it serves an already-decoded program's code
/// page if one exists (which also keeps the pre-seeded system contracts
/// reachable — see `raw_bytecode`) and raw bytes otherwise, deferring the
/// decode until a far call actually needs it. Repeat queries for a bytecode
/// that is never far-called re-resolve the bytes each time — O(len) per query,
/// the same order as the code-page re-encode upstream performs on its
/// `program_cache` hit, and decommit pricing lives in vm2's `WorldDiff`, not
/// here — so this changes cost distribution, never bytes, gas, or committed
/// outputs. `tests::decommit_code_serves_preseeded_system_contracts` and
/// `tests::decommit_code_fetches_raw_bytes_without_decoding` pin this.
impl<S: ReadStorage, T: Tracer> zksync_vm2::World<T> for World<S, T> {
    fn decommit(&mut self, hash: U256) -> Program<T, Self> {
        if let Some(program) = self.program_cache.get(&hash) {
            return program.clone();
        }
        let program = Program::new(&self.raw_bytecode(hash), false);
        self.program_cache.insert(hash, program.clone());
        program
    }

    fn decommit_code(&mut self, hash: U256) -> Vec<u8> {
        // An already-decoded program is authoritative: the pre-seeded system contracts
        // (default AA / EVM emulator) exist *only* in `program_cache`, and the byte
        // sources are not guaranteed to carry them (nothing the guest checks enforces
        // it), so this must not fall through for them. Same source priority as
        // `decommit()`.
        if let Some(program) = self.program_cache.get(&hash) {
            return Self::code_page_bytes(program);
        }

        // Serve raw bytes WITHOUT building a `Program`: decoding every 8-byte word
        // into an `Instruction` is wasted work for a bytecode queried this way — in
        // particular EVM contract bytecode, which reaches the VM only through this
        // path (the interpreter reads it as data) and previously paid a full
        // instruction decode plus a `program_cache` slot for a program that never
        // runs. The decode is deferred, not eliminated: if the same bytecode is
        // far-called later, `decommit()` decodes it then.
        let mut code = self.raw_bytecode(hash);
        // Reproduce the code-page view exactly: whole 32-byte words only. Bytecodes
        // are word-aligned (`validate_bytecode` gates every source), so this is a
        // no-op in practice.
        code.truncate(code.len() - code.len() % 32);
        code
    }

    fn precompiles(&self) -> &impl Precompiles {
        &self.precompiles
    }
}

/// Precompiles implementation that may shortcut an `ecrecover` call made during L2 transaction validation.
#[derive(Debug, Default)]
pub(super) struct OptimizedPrecompiles {
    pub(super) expected_ecrecover_call: Option<EcRecoverCall>,
    #[cfg(test)]
    pub(super) expected_calls: std::cell::Cell<usize>,
}

impl Precompiles for OptimizedPrecompiles {
    fn call_precompile(
        &self,
        address_low: u16,
        memory: PrecompileMemoryReader<'_>,
        aux_input: u64,
    ) -> PrecompileOutput {
        if address_low == ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS {
            if let Some(call) = &self.expected_ecrecover_call {
                let memory_input = memory.clone().assume_offset_in_words();
                if call.input.iter().copied().eq(memory_input) {
                    // Return the predetermined address instead of ECDSA recovery
                    #[cfg(test)]
                    self.expected_calls.set(self.expected_calls.get() + 1);
                    // By convention, the recovered address is left-padded to a 32-byte word and is preceded
                    // by the success marker.
                    return PrecompileOutput::from([U256::one(), address_to_u256(&call.output)])
                        .with_cycle_stats(CycleStats::EcRecover(1));
                }
            }
        }
        LegacyPrecompiles.call_precompile(address_low, memory, aux_input)
    }
}

#[cfg(test)]
mod tests {
    use zksync_types::{StorageKey, StorageValue};
    use zksync_vm2::World as _;

    use super::*;

    /// Minimal [`ReadStorage`] serving one factory dep and counting the loads.
    #[derive(Debug, Default)]
    struct CountingStorage {
        factory_deps: HashMap<H256, Vec<u8>>,
        loads: usize,
    }

    impl ReadStorage for CountingStorage {
        fn read_value(&mut self, _key: &StorageKey) -> StorageValue {
            H256::zero()
        }

        fn is_write_initial(&mut self, _key: &StorageKey) -> bool {
            true
        }

        fn load_factory_dep(&mut self, hash: H256) -> Option<Vec<u8>> {
            self.loads += 1;
            self.factory_deps.get(&hash).cloned()
        }

        fn get_enumeration_index(&mut self, _key: &StorageKey) -> Option<u64> {
            None
        }
    }

    /// A storage-resident bytecode is served from the snapshot and never written
    /// back into `bytecode_cache`. Guards the divergence documented on the impl.
    #[test]
    fn storage_loaded_bytecode_is_not_cached() {
        let hash = U256::from(1);
        let mut storage = CountingStorage::default();
        storage
            .factory_deps
            .insert(u256_to_h256(hash), vec![0_u8; 32]);

        let mut world = World::<_, ()>::new(storage, HashMap::new());
        let program = world.decommit(hash);

        assert_eq!(world.storage.loads, 1);
        assert!(
            world.bytecode_cache.is_empty(),
            "storage-loaded bytecode must not be retained in `bytecode_cache`"
        );

        // `program_cache` memoizes, so a second decommit neither re-reads storage
        // nor re-decodes.
        let again = world.decommit(hash);
        assert_eq!(world.storage.loads, 1);
        assert_eq!(program.code_page(), again.code_page());
        assert!(world.bytecode_cache.is_empty());
    }

    /// A bytecode present only in `program_cache` — how `Vm::custom` seeds the
    /// default AA and the EVM emulator — must be served by `decommit_code` without
    /// touching storage: the factory-dep witness is not guaranteed to contain base
    /// system contracts, so `decommit_code` must never rely on it for pre-seeded
    /// hashes. Pins the `program_cache`-first source priority.
    #[test]
    fn decommit_code_serves_preseeded_system_contracts() {
        let mut code = vec![1_u8; 32];
        code.extend_from_slice(&[2_u8; 32]);
        let hash = U256::from(0x0100);
        let program_cache = HashMap::from([(hash, Program::new(&code, false))]);
        // Storage deliberately lacks the factory dep, like the guest's snapshot.
        let mut world = World::<_, ()>::new(CountingStorage::default(), program_cache);

        assert_eq!(world.decommit_code(hash), code);
        assert_eq!(
            world.storage.loads, 0,
            "a pre-seeded program must be served without consulting storage"
        );
    }

    /// `decommit_code` serves a storage-resident bytecode as raw bytes: no decode,
    /// no `program_cache` entry, no `bytecode_cache` retention — and byte-identical
    /// to the whole-word view `decommit`'s code page exposes.
    #[test]
    fn decommit_code_fetches_raw_bytes_without_decoding() {
        let hash = U256::from(1);
        let mut code = vec![3_u8; 32];
        code.extend_from_slice(&[4_u8; 32]);
        let mut storage = CountingStorage::default();
        storage
            .factory_deps
            .insert(u256_to_h256(hash), code.clone());
        let mut world = World::<_, ()>::new(storage, HashMap::new());

        let bytes = world.decommit_code(hash);
        assert_eq!(bytes, code);
        assert!(
            world.program_cache.is_empty(),
            "the raw fetch must not decode the bytecode or pin a `Program`"
        );
        assert!(world.bytecode_cache.is_empty());

        // The raw view must match what a far-call decommit exposes...
        let program = world.decommit(hash);
        assert_eq!(
            bytes,
            World::<CountingStorage, ()>::code_page_bytes(&program)
        );
        // ...and once decoded, `decommit_code` serves the decoded program instead of
        // re-reading storage.
        assert_eq!(world.decommit_code(hash), code);
        assert_eq!(world.storage.loads, 2);
    }

    /// Pushed transactions' factory deps (`bytecode_cache`) are served before the
    /// storage fallback, without a storage load. Keys are content-bound to the bytes
    /// in production; the two sources differ here only to make the priority
    /// observable.
    #[test]
    fn decommit_code_prefers_cached_bytecode_over_storage() {
        let hash = U256::from(3);
        let cached = vec![6_u8; 32];
        let mut storage = CountingStorage::default();
        storage
            .factory_deps
            .insert(u256_to_h256(hash), vec![7_u8; 32]);
        let mut world = World::<_, ()>::new(storage, HashMap::new());
        world.bytecode_cache.insert(hash, cached.clone());

        assert_eq!(world.decommit_code(hash), cached);
        assert_eq!(world.storage.loads, 0);
    }

    /// The raw path exposes whole 32-byte words only, exactly like the code-page
    /// view it replaces (`chunks_exact(32)` drops a partial trailing word). Real
    /// bytecodes are word-aligned; this pins the behavior should that ever change.
    #[test]
    fn decommit_code_exposes_whole_words_only() {
        let hash = U256::from(2);
        let mut storage = CountingStorage::default();
        storage
            .factory_deps
            .insert(u256_to_h256(hash), vec![5_u8; 65]);
        let mut world = World::<_, ()>::new(storage, HashMap::new());

        assert_eq!(world.decommit_code(hash), vec![5_u8; 64]);
    }

    /// A rolled-back write is priced from the pre-state: an existing leaf, even one
    /// holding zero, is a repeated write; only a missing one is initial.
    #[test]
    fn rolled_back_write_prices_from_proven_prestate() {
        use zksync_vm2::StorageInterface as _;

        use crate::interface::storage::StorageSnapshot;

        let contract = H160::repeat_byte(0x42);
        let slot_key =
            |n: u64| StorageKey::new(AccountTreeId::new(contract), H256::from_low_u64_be(n));
        let (existing, zero_valued, missing) = (slot_key(1), slot_key(2), slot_key(3));
        let value = H256::from_low_u64_be(7);
        let snapshot = StorageSnapshot::new(
            [
                (existing.hashed_key(), Some((value, 5))),
                (zero_valued.hashed_key(), Some((H256::zero(), 6))),
                (missing.hashed_key(), None),
            ]
            .into(),
            Default::default(),
        );
        let mut world = World::<_, ()>::new(snapshot, HashMap::new());

        let new_value = U256::from(9);
        let mut price = |key: &StorageKey| {
            let slot = world.read_storage(contract, h256_to_u256(*key.key()));
            let old = slot.value;
            (
                slot.is_write_initial,
                old,
                world.cost_of_writing_storage(slot, new_value),
            )
        };
        let repeated = |old: U256| {
            BYTES_PER_ENUMERATION_INDEX as u32
                + compress_with_best_strategy(old, new_value).len() as u32
        };
        let initial = |old: U256| {
            BYTES_PER_DERIVED_KEY as u32 + compress_with_best_strategy(old, new_value).len() as u32
        };

        assert_eq!(
            price(&existing),
            (false, h256_to_u256(value), repeated(h256_to_u256(value)))
        );
        assert_eq!(
            price(&zero_valued),
            (false, U256::zero(), repeated(U256::zero()))
        );
        assert_eq!(price(&missing), (true, U256::zero(), initial(U256::zero())));
        assert_ne!(repeated(U256::zero()), initial(U256::zero()));
    }
}
