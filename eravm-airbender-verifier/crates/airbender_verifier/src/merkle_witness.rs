//! Interpretation of the committed `merkle_paths` witness: classifying each
//! leaf's pre-state, building the pre-batch storage view, and streaming each
//! Merkle path through `verify_paths_and_new_root` to fold-verify it against
//! the pre-batch root. Kept out of `lib.rs` (and out of the vendored
//! `merkle_tree` crate, which shouldn't carry verifier policy) so the
//! soundness-relevant leaf-shape rules live in one place.

use anyhow::Result;
use zksync_merkle_tree::{
    blake2_fold_merkle_path, BlockOutputWithProofs, TreeEntry, TreeInstruction, TreeLogEntry,
    TreeLogEntryWithProof, ValueHash, TREE_DEPTH,
};
use zksync_types::{StorageLog, H256, U256};

use crate::map_log_tree;
use crate::types::{StorageLogMetadata, StorageReadProof, WitnessInputMerklePaths, HASH_LEN};

/// The pre-state a single Merkle-witness leaf encodes, after rejecting shapes
/// the tree never emits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WitnessLeaf {
    /// Empty leaf: value 0, no enumeration index (a read of a missing key, or a
    /// first write / insertion of a previously-empty slot).
    Empty { is_write: bool },
    /// Existing leaf at `index > 0` with pre-state `value`.
    Existing {
        is_write: bool,
        index: u64,
        value: H256,
    },
}

/// Classify a Merkle-witness leaf, rejecting malformed shapes the tree never
/// produces: a read flagged `first_write`, and a repeated write to enum index 0.
pub(crate) fn classify_witness_leaf(log: &StorageLogMetadata) -> anyhow::Result<WitnessLeaf> {
    let key = log.leaf_hashed_key;
    match (log.is_write, log.first_write, log.leaf_enumeration_index) {
        (false, true, _) => {
            anyhow::bail!("witness read entry for leaf {key:x} is marked first_write")
        }
        (false, _, 0) => Ok(WitnessLeaf::Empty { is_write: false }),
        (false, false, index) => Ok(WitnessLeaf::Existing {
            is_write: false,
            index,
            value: H256(log.value_read),
        }),
        (true, true, _) => Ok(WitnessLeaf::Empty { is_write: true }),
        (true, false, 0) => {
            anyhow::bail!("witness repeated write to leaf {key:x} has enumeration index 0")
        }
        (true, false, index) => Ok(WitnessLeaf::Existing {
            is_write: true,
            index,
            value: H256(log.value_read),
        }),
    }
}

/// Build the storage view from the committed `merkle_paths` witness: each entry's
/// classified pre-state (empty leaf -> `None`, existing leaf -> `Some((value,
/// index))`), keyed by its hashed key (a little-endian `U256`). Every entry is
/// proven against `old_root_hash` by the later streaming Merkle fold
/// (`verify_paths_and_new_root`), so this only translates shapes — rejecting
/// malformed leaves (via the classifier) and any conflicting duplicate
/// (`merkle_paths` is deduplicated to one entry per slot).
pub(crate) fn build_view_from_merkle_paths(
    merkle_paths: &[StorageLogMetadata],
) -> anyhow::Result<std::collections::BTreeMap<H256, Option<(H256, u64)>>> {
    use std::collections::btree_map::Entry;

    let mut view = std::collections::BTreeMap::new();
    for log in merkle_paths {
        let prestate = match classify_witness_leaf(log)? {
            WitnessLeaf::Empty { .. } => None,
            WitnessLeaf::Existing { index, value, .. } => Some((value, index)),
        };
        let mut key_bytes = [0u8; 32];
        log.leaf_hashed_key.to_little_endian(&mut key_bytes);
        match view.entry(H256(key_bytes)) {
            Entry::Vacant(slot) => {
                slot.insert(prestate);
            }
            Entry::Occupied(slot) => anyhow::ensure!(
                *slot.get() == prestate,
                "merkle_paths has a conflicting pre-state for slot {:?}: {:?} vs {prestate:?}",
                slot.key(),
                slot.get(),
            ),
        }
    }
    Ok(view)
}

/// Fold each read proof against `old_root_hash` and add its pre-state to `view`.
/// Keys must be strictly ascending, which rules out duplicates that would only cost
/// cycles. Takes `proofs` by value so each path is freed once folded: the guest
/// heap is tight.
pub(crate) fn extend_view_with_read_proofs(
    view: &mut std::collections::BTreeMap<H256, Option<(H256, u64)>>,
    proofs: Vec<StorageReadProof>,
    old_root_hash: ValueHash,
) -> anyhow::Result<()> {
    use std::collections::btree_map::Entry;

    let mut path = Vec::with_capacity(TREE_DEPTH);
    let mut previous_key = None;
    for proof in proofs {
        let key = proof.leaf_hashed_key;
        anyhow::ensure!(
            previous_key.is_none_or(|previous| previous < key),
            "read proof for leaf {key:x} is not in strictly ascending key order",
        );
        previous_key = Some(key);
        // Checked first: the fold asserts on an over-long path.
        anyhow::ensure!(
            proof.merkle_path.len() <= TREE_DEPTH,
            "read proof for leaf {key:x} is longer than TREE_DEPTH: {} > {TREE_DEPTH}",
            proof.merkle_path.len(),
        );
        let index = proof.leaf_enumeration_index;
        let value = H256(proof.value);
        anyhow::ensure!(
            index != 0 || value.is_zero(),
            "read proof for missing leaf {key:x} carries a non-zero value",
        );
        load_path_into(&proof.merkle_path, &mut path);
        let root = blake2_fold_merkle_path(&path, TreeEntry::new(key, index, value));
        anyhow::ensure!(
            root == old_root_hash,
            "read proof for leaf {key:x} does not fold to the old root ({root:?} vs {old_root_hash:?})",
        );

        // Index >= 1 with a zero value is an existing leaf: a repeated write.
        let prestate = (index != 0).then_some((value, index));
        let mut key_bytes = [0u8; 32];
        key.to_little_endian(&mut key_bytes);
        match view.entry(H256(key_bytes)) {
            Entry::Vacant(slot) => {
                slot.insert(prestate);
            }
            Entry::Occupied(slot) => anyhow::ensure!(
                *slot.get() == prestate,
                "read proof has a conflicting pre-state for slot {:?}: {:?} vs {prestate:?}",
                slot.key(),
                slot.get(),
            ),
        }
    }
    Ok(())
}

/// Classify a witness leaf and map it to its `TreeLogEntry` base. Shared by
/// `get_bowp` (oracle) and `verify_paths_and_new_root` (streaming) so the two
/// can never disagree on classification.
fn tree_log_entry_from_witness(log: &StorageLogMetadata) -> anyhow::Result<TreeLogEntry> {
    Ok(match classify_witness_leaf(log)? {
        WitnessLeaf::Empty { is_write: false } => TreeLogEntry::ReadMissingKey,
        WitnessLeaf::Empty { is_write: true } => TreeLogEntry::Inserted,
        WitnessLeaf::Existing {
            is_write: false,
            index,
            value,
        } => TreeLogEntry::Read {
            leaf_index: index,
            value: value.0.into(),
        },
        WitnessLeaf::Existing {
            is_write: true,
            index,
            value,
        } => TreeLogEntry::Updated {
            leaf_index: index,
            previous_value: value.0.into(),
        },
    })
}

/// Builds `BlockOutputWithProofs` from the merkle witness, paired with each
/// entry's `leaf_hashed_key` in order.
///
/// The keys are returned separately because `BlockOutputWithProofs` doesn't
/// carry them, yet `generate_tree_instructions` must bind each proof to the VM's
/// storage-log key. `verify_proofs` checks the Merkle path against the VM key
/// (via the `TreeInstruction`), while the storage view is seeded by
/// `leaf_hashed_key`; if those two keys are allowed to differ, a proof for one
/// slot's pre-state could be paired with a VM that read a *different* value for
/// that slot. Binding them keeps the proven slot and the executed slot the same.
///
/// Superseded in production by `verify_paths_and_new_root` (the streaming
/// pass); kept as part of the differential-test oracle (this +
/// `generate_tree_instructions` + `verify_proofs` + `root_hash()`) — see
/// `streaming_tests` below.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn get_bowp(
    witness_input_merkle_paths: WitnessInputMerklePaths,
) -> Result<(BlockOutputWithProofs, Vec<U256>)> {
    let entries: Vec<(TreeLogEntryWithProof, U256)> = witness_input_merkle_paths
        .into_merkle_paths()
        .map(|log| -> anyhow::Result<(TreeLogEntryWithProof, U256)> {
            let root_hash = log.root_hash.into();
            let leaf_hashed_key = log.leaf_hashed_key;
            // Same classifier as the storage-view derivation, so the two can
            // never disagree on which witness shapes are valid. `value_written`
            // is intentionally unused: the verifier derives the written value
            // from VM execution, not from the witness.
            let base = tree_log_entry_from_witness(&log)?;
            let merkle_path = log.merkle_paths.into_iter().map(|x| x.into()).collect();
            Ok((
                TreeLogEntryWithProof {
                    base,
                    merkle_path,
                    root_hash,
                },
                leaf_hashed_key,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let (logs, leaf_keys): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
    Ok((
        BlockOutputWithProofs {
            logs,
            leaf_count: 0,
        },
        leaf_keys,
    ))
}

/// Copy one entry's stored path into `out` (cleared first) as `ValueHash`es.
///
/// No reconstruction: the fold prepends `empty_subtree_hash(d)` for every level a
/// short path omits, which is exactly what the per-path form leaves out, and any
/// cross-entry reconstruction happened in
/// `WitnessInputMerklePaths::normalize_stored_paths`. The caller-owned buffer keeps
/// Pass 2 at one live path, no per-entry alloc.
fn load_path_into(stored: &[[u8; HASH_LEN]], out: &mut Vec<ValueHash>) {
    out.clear();
    out.extend(stored.iter().map(|h| ValueHash::from(*h)));
}

/// Verifies the committed `merkle_paths` witness against `old_root_hash` and
/// returns the post-batch `(root_hash, enumeration_index)`. Streams one path at
/// a time — `O(1)` live paths instead of expanding all of them at once — which
/// is what keeps peak memory bounded on read-heavy batches.
///
/// Two passes over the entries:
/// - Pass 1: classify each witness leaf, bind it to the VM storage-log key, map
///   it to a `TreeInstruction`, and bound its path length. No Merkle path is
///   loaded.
/// - Pass 2: load each path lazily and fold it against the running root via
///   `merkle_tree`'s own `blake2_fold_merkle_path` — the consensus-critical fold
///   lives there, not here. It is the fused blake2s specialization of
///   `HashTree::fold_merkle_path`, byte-identical to it (pinned by differential
///   tests in `merkle_tree`) and blake2s-only, which is why this function takes
///   no hasher: the protocol tree hasher *is* blake2s, and hardcoding it removes
///   any chance of folding with the wrong one.
///
/// Running all of Pass 1 before any fold guarantees a witness-shape or binding
/// error surfaces before a cryptographic fold error.
///
/// Correctness is pinned by a differential-test oracle (see `streaming_tests`):
/// identical accept/reject and, on accept, identical returned values. Error
/// *ordering* is not identical — on a multi-fault witness both reject
/// (fail-closed) but may surface different errors (see
/// `streaming_and_oracle_diverge_on_multi_fault_error_ordering`).
pub(crate) fn verify_paths_and_new_root(
    witness: WitnessInputMerklePaths,
    vm_logs: Vec<StorageLog>,
    old_root_hash: ValueHash,
    mut enumeration_index: u64,
) -> anyhow::Result<(ValueHash, u64)> {
    let metas = witness.merkle_paths;
    // Reject mismatched counts explicitly: the `zip` below would otherwise
    // silently truncate to the shorter side.
    anyhow::ensure!(
        metas.len() == vm_logs.len(),
        "VM deduplicated storage logs count mismatch with merkle proofs: vm_logs={}, merkle_logs={}",
        vm_logs.len(),
        metas.len(),
    );
    // Empty input: mirror the oracle, whose `root_hash()` is `None` here and
    // surfaces this same message.
    anyhow::ensure!(
        !metas.is_empty(),
        "root_hash unavailable after verify_proofs",
    );
    // Pass 2 folds each stored path as-is, correct only for the per-path form. An
    // un-normalised legacy witness would be silently mis-folded on the shape where
    // its stripped prefix holds real sibling hashes (see
    // `WitnessInputMerklePaths::normalize_stored_paths`), so reject instead of
    // documenting the ordering. `execute` normalises as its first statement; this
    // fires only if that call is removed or reordered.
    //
    // `==`, not `>=`: an over-long entry 0 is malformed, not legacy, and the
    // per-entry bound below owns that case and its message.
    anyhow::ensure!(
        metas[0].merkle_paths.len() != TREE_DEPTH,
        "merkle_paths is in the legacy delta-compacted form (entry 0 stored at the \
         full TREE_DEPTH); `normalize_stored_paths` must run before any fold",
    );
    // Pass 1: classify, key-bind, and map every entry to a `TreeInstruction`
    // before any fold, so a shape/binding error can't be preempted by a fold
    // error. Only the small per-entry `(TreeLogEntry, TreeInstruction)` is kept
    // — no Merkle path is loaded yet.
    let mut instructions: Vec<(TreeLogEntry, TreeInstruction)> = Vec::with_capacity(metas.len());
    for (meta, vm_log) in metas.iter().zip(vm_logs.iter()) {
        // (0) bound the path length. Load-bearing: `extend_merkle_path` computes
        // `TREE_DEPTH - path.len()`, and `blake2_fold_merkle_path` *asserts* on an
        // over-long path — checking here turns that abort into a fail-closed
        // rejection, before any fold runs.
        anyhow::ensure!(
            meta.merkle_paths.len() <= TREE_DEPTH,
            "Merkle path for leaf {:x} is longer than TREE_DEPTH: {} > {TREE_DEPTH}",
            meta.leaf_hashed_key,
            meta.merkle_paths.len(),
        );
        // (1) classify the witness leaf.
        let base = tree_log_entry_from_witness(meta)?;
        // (2) bind the proof to the slot the VM actually touched.
        let key = meta.leaf_hashed_key;
        let vm_key = vm_log.key.hashed_key_u256();
        anyhow::ensure!(
            key == vm_key,
            "merkle_paths leaf_hashed_key {key:?} does not match \
             VM storage-log key {vm_key:?}",
        );
        // (3) map to a `TreeInstruction` (advances `enumeration_index` on insert).
        let instruction = map_log_tree(key, vm_log, &base, &mut enumeration_index)?;
        instructions.push((base, instruction));
    }

    // Pass 2 (reproduces `verify_proofs` exactly): fold every entry's proof
    // against the running root, in order, loading one path at a time into a
    // single reused buffer so only one ≤8 KiB path is ever live and there is no
    // per-entry allocation.
    let mut root_hash = old_root_hash;
    let mut full = Vec::with_capacity(TREE_DEPTH);
    for (meta, (base, instruction)) in metas.iter().zip(instructions) {
        load_path_into(&meta.merkle_paths, &mut full);
        let op_root = ValueHash::from(meta.root_hash);
        if matches!(instruction, TreeInstruction::Read(_)) {
            anyhow::ensure!(
                op_root == root_hash,
                "Condition failed: `op.root_hash == root_hash` ({op_root:?} vs {root_hash:?})",
            );
            anyhow::ensure!(base.is_read());
        } else {
            anyhow::ensure!(!base.is_read());
        }
        let prev_entry = match base {
            TreeLogEntry::Inserted | TreeLogEntry::ReadMissingKey => {
                TreeEntry::empty(instruction.key())
            }
            TreeLogEntry::Updated {
                leaf_index,
                previous_value: value,
            }
            | TreeLogEntry::Read { leaf_index, value } => {
                TreeEntry::new(instruction.key(), leaf_index, value)
            }
        };
        let prev_hash = blake2_fold_merkle_path(&full, prev_entry);
        anyhow::ensure!(
            prev_hash == root_hash,
            "Condition failed: `prev_hash == root_hash` ({prev_hash:?} vs {root_hash:?})",
        );
        if let TreeInstruction::Write(new_entry) = instruction {
            let next_hash = blake2_fold_merkle_path(&full, new_entry);
            anyhow::ensure!(
                next_hash == op_root,
                "Condition failed: `next_hash == op.root_hash` ({next_hash:?} vs {op_root:?})",
            );
        }
        root_hash = op_root;
    }
    Ok((root_hash, enumeration_index))
}

#[cfg(test)]
mod streaming_tests {
    use super::*;

    #[test]
    fn load_path_reuses_the_buffer_and_copies_verbatim() {
        // No reconstruction: the stored path is what gets folded, and the fold
        // supplies the omitted (empty-subtree) levels itself.
        let mut out = vec![ValueHash::repeat_byte(0xFF); 9];
        let stored = vec![[1u8; HASH_LEN], [2; HASH_LEN], [3; HASH_LEN]];
        load_path_into(&stored, &mut out);
        assert_eq!(
            out,
            stored
                .iter()
                .map(|h| ValueHash::from(*h))
                .collect::<Vec<_>>()
        );
    }

    // ---------------------------------------------------------------------
    // Differential oracle test for `verify_paths_and_new_root`.
    //
    // The oracle is the exact previous three-step production path
    // (`get_bowp` + `generate_tree_instructions` + `BlockOutputWithProofs::
    // verify_proofs` + `root_hash()`); `verify_paths_and_new_root` fuses those
    // into a single streaming pass. On every input the two MUST agree on the
    // returned `(new_root, new_enumeration_index)` and on accept/reject.
    // ---------------------------------------------------------------------
    use anyhow::Context;
    use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
    // The oracle still folds through the generic `HashTree` path; production no
    // longer does, so the trait is imported here rather than at module scope.
    // `StorageLog`, `H256` come in via `use super::*`.
    use zksync_merkle_tree::HashTree;
    use zksync_types::{AccountTreeId, StorageKey, H160};

    use crate::generate_tree_instructions;

    /// Oracle: the exact previous three-step path, threaded like the production
    /// caller in `lib.rs` (enum index advances by the number of `Inserted`
    /// leaves; `root_hash()` is `None` when there are no logs).
    fn reference(
        witness: WitnessInputMerklePaths,
        vm_logs: Vec<StorageLog>,
        old_root: ValueHash,
        idx: u64,
    ) -> anyhow::Result<(ValueHash, u64)> {
        let (bowp, leaf_keys) = get_bowp(witness)?;
        let instructions = generate_tree_instructions(idx, &bowp, &leaf_keys, vm_logs)?;
        bowp.verify_proofs(&Blake2Hasher, old_root, &instructions)?;
        let num_insertions = bowp
            .logs
            .iter()
            .filter(|log| matches!(log.base, TreeLogEntry::Inserted))
            .count() as u64;
        let new_root = bowp
            .root_hash()
            .context("root_hash unavailable after verify_proofs")?;
        Ok((new_root, idx + num_insertions))
    }

    /// Run both paths on identical inputs and assert they agree exactly.
    fn assert_equivalent(
        witness: WitnessInputMerklePaths,
        vm_logs: Vec<StorageLog>,
        old_root: ValueHash,
        idx: u64,
    ) {
        let expect = reference(witness.clone(), vm_logs.clone(), old_root, idx);
        let got = verify_paths_and_new_root(witness, vm_logs, old_root, idx);
        match (expect, got) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "streaming result diverged from oracle"),
            (Err(_), Err(_)) => {}
            (a, b) => panic!("accept/reject diverged: oracle={a:?} streaming={b:?}"),
        }
    }

    fn empty_root() -> ValueHash {
        HashTree::empty_tree_hash(&Blake2Hasher)
    }

    /// A `(leaf_hashed_key, read StorageLog)` pair whose hashed key is
    /// self-consistent (the log's own `hashed_key_u256()`), so key-binding
    /// passes unless deliberately broken.
    fn read_pair(addr: u8, slot: u8, value: H256) -> (U256, StorageLog) {
        let key = StorageKey::new(
            AccountTreeId::new(H160::repeat_byte(addr)),
            H256::repeat_byte(slot),
        );
        (key.hashed_key_u256(), StorageLog::new_read_log(key, value))
    }

    #[allow(clippy::too_many_arguments)]
    fn entry(
        is_write: bool,
        first_write: bool,
        enum_index: u64,
        leaf_hashed_key: U256,
        root: ValueHash,
        value_read: H256,
        paths: Vec<[u8; HASH_LEN]>,
    ) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: root.to_fixed_bytes(),
            is_write,
            first_write,
            merkle_paths: paths,
            leaf_hashed_key,
            leaf_enumeration_index: enum_index,
            value_written: [0; HASH_LEN],
            value_read: value_read.to_fixed_bytes(),
        }
    }

    /// Build a witness directly from metadata entries, bypassing
    /// `push_merkle_path`'s normalisation. The entries are taken as the
    /// already-stored form, exactly as the streaming pass and `into_merkle_paths`
    /// consume them — which lets a test construct shapes `push_merkle_path` would
    /// have trimmed, e.g. an over-long path.
    fn witness_of(metas: Vec<StorageLogMetadata>) -> WitnessInputMerklePaths {
        let mut witness = WitnessInputMerklePaths::new(0);
        witness.merkle_paths = metas;
        witness
    }

    /// A key agreeing with `target` on the top `c` bits, so `target`'s populated
    /// depth becomes `c + 1` once it is inserted — equivalently, the returned key
    /// lands in `target`'s sibling subtree at fold index `255 - c`.
    fn neighbour_sharing_top_bits(target: U256, c: usize) -> U256 {
        let mut out = U256([0x5157_9CE9_1F0B_A3D1; 4]); // arbitrary low bits
        let diverge = TREE_DEPTH - 1 - c;
        for bit in diverge..TREE_DEPTH {
            let (limb, mask) = (bit / 64, 1u64 << (bit % 64));
            let set = if bit == diverge {
                !target.bit(bit)
            } else {
                target.bit(bit)
            };
            if set {
                out.0[limb] |= mask;
            } else {
                out.0[limb] &= !mask;
            }
        }
        out
    }

    /// Leading (MSB-first) bits on which `a` and `b` agree. Two keys agreeing on the
    /// top `p` bits share every ancestor at fold index `> 255 - p`.
    fn shared_top_bits(a: U256, b: U256) -> usize {
        (0..TREE_DEPTH)
            .take_while(|i| a.bit(TREE_DEPTH - 1 - i) == b.bit(TREE_DEPTH - 1 - i))
            .count()
    }

    /// `(hashed_key, read StorageLog)` for a fully specified `(address, slot)`.
    /// `read_pair`'s `repeat_byte` addressing is too coarse to search the slot space.
    fn read_pair_at(addr: H160, slot: H256, value: H256) -> (U256, StorageLog) {
        let key = StorageKey::new(AccountTreeId::new(addr), slot);
        (key.hashed_key_u256(), StorageLog::new_read_log(key, value))
    }

    /// First slot of `addr` whose hashed key shares an `accept`-able number of leading
    /// bits with `target`.
    ///
    /// Test-scale stand-in for the attacker's offline grind: they own the contract, so
    /// the 32-byte slot is free and `hashed_key = blake2s(pad12(address) ‖ slot)` needs
    /// no chain state. Single-digit bit counts here, so a few hundred hashes against
    /// the 2^28-2^31 a mainnet-depth tree would need.
    fn grind_slot(addr: H160, target: U256, accept: impl Fn(usize) -> bool) -> (U256, H256) {
        for n in 0u32..1 << 20 {
            let mut bytes = [0u8; 32];
            bytes[28..].copy_from_slice(&n.to_be_bytes());
            let slot = H256(bytes);
            let (hashed, _) = read_pair_at(addr, slot, H256::zero());
            if accept(shared_top_bits(hashed, target)) {
                return (hashed, slot);
            }
        }
        panic!("no slot found in the search space");
    }

    // --- Real ACCEPT case: single missing-key read on the empty tree. --------

    #[test]
    fn streaming_matches_oracle_on_missing_key_read() {
        let (key, log) = read_pair(0x11, 0x22, H256::zero());
        // is_write=false, first_write=false, enum_index=0 -> ReadMissingKey.
        // Empty path + empty entry folds to the empty-tree root, and
        // old_root == op.root_hash == empty_tree_hash, so both paths ACCEPT.
        let meta = entry(false, false, 0, key, empty_root(), H256::zero(), vec![]);
        let witness = witness_of(vec![meta]);

        // Prove it is a genuine ACCEPT (not merely a matching reject).
        let got = verify_paths_and_new_root(witness.clone(), vec![log], empty_root(), 5)
            .expect("missing-key read on empty tree must verify");
        assert_eq!(
            got,
            (empty_root(), 5),
            "root unchanged, enum index unchanged"
        );

        assert_equivalent(witness, vec![log], empty_root(), 5);
    }

    // --- Logic-agreement rejects (both paths Err). ---------------------------

    #[test]
    fn streaming_matches_oracle_on_count_mismatch() {
        let (key, _log) = read_pair(1, 2, H256::zero());
        let meta = entry(false, false, 1, key, empty_root(), H256::zero(), vec![]);
        // One merkle path, zero VM logs.
        assert_equivalent(witness_of(vec![meta]), vec![], empty_root(), 0);
    }

    /// The `verify_paths_and_new_root` doc no longer claims error *ordering*
    /// matches the oracle (only accept/reject and, on accept, returned values).
    /// This pins WHY: on a *multi-fault* witness both paths reject (fail-closed —
    /// the sound part is preserved) but surface DIFFERENT errors, and the
    /// differential harness `assert_equivalent` (which treats any `(Err, Err)` as
    /// agreement) passes anyway, so it cannot catch the divergence.
    ///
    /// Multi-fault input:
    /// - entry 0 classifies fine (existing read, index 1) but its
    ///   `leaf_hashed_key` != the VM key → a KEY-BIND fault (checked in Pass 1 /
    ///   `generate_tree_instructions`).
    /// - entry 1 is a read marked `first_write` → a CLASSIFY fault (checked in
    ///   `classify_witness_leaf`, reached inside `get_bowp`).
    ///
    /// Oracle: `get_bowp` classifies ALL entries before any key-bind, so entry
    /// 1's classify error surfaces first. Streaming: Pass 1 interleaves
    /// classify→bind per entry, so entry 0's key-bind error surfaces first.
    #[test]
    fn streaming_and_oracle_diverge_on_multi_fault_error_ordering() {
        // entry 0 — valid classify, but leaf_hashed_key (0xdead_beef) != VM key.
        let (_vmkey0, log0) = read_pair(1, 2, H256::from_low_u64_be(9));
        let meta0 = entry(
            false,
            false,
            1,
            U256::from(0xdead_beef_u64),
            empty_root(),
            H256::from_low_u64_be(9),
            vec![],
        );
        // entry 1 — classify fault: a read marked first_write.
        let (key1, log1) = read_pair(3, 4, H256::zero());
        let meta1 = entry(false, true, 0, key1, empty_root(), H256::zero(), vec![]);

        let witness = witness_of(vec![meta0, meta1]);
        let vm_logs = vec![log0, log1];

        let oracle_err = reference(witness.clone(), vm_logs.clone(), empty_root(), 0)
            .expect_err("oracle must reject the multi-fault witness");
        let streaming_err =
            verify_paths_and_new_root(witness.clone(), vm_logs.clone(), empty_root(), 0)
                .expect_err("streaming must reject the multi-fault witness");

        let oracle_msg = oracle_err.to_string();
        let streaming_msg = streaming_err.to_string();

        // The oracle surfaces entry 1's CLASSIFY fault first...
        assert!(
            oracle_msg.contains("first_write"),
            "oracle should surface entry 1's classify error, got: {oracle_msg}"
        );
        // ...while the streaming pass surfaces entry 0's KEY-BIND fault first.
        assert!(
            streaming_msg.contains("leaf_hashed_key") && streaming_msg.contains("does not match"),
            "streaming should surface entry 0's key-bind error, got: {streaming_msg}"
        );
        // => the surfaced errors are NOT identical: exact error-ordering
        //    equivalence does not hold (the sound guarantee is accept/reject).
        assert_ne!(
            oracle_msg, streaming_msg,
            "error ordering diverges between the streaming path and the oracle"
        );

        // Yet the differential harness treats both as an agreeing `(Err, Err)`
        // and PASSES — both reject (fail-closed), which is what matters.
        assert_equivalent(witness, vm_logs, empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_key_binding_mismatch() {
        // Valid read classification, but leaf_hashed_key != VM key.
        let (_vmkey, log) = read_pair(1, 2, H256::from_low_u64_be(9));
        let meta = entry(
            false,
            false,
            1,
            U256::from(0xdead_beef_u64),
            empty_root(),
            H256::from_low_u64_be(9),
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_read_marked_first_write() {
        // classify rejects: a read flagged first_write.
        let (key, log) = read_pair(3, 4, H256::zero());
        let meta = entry(false, true, 0, key, empty_root(), H256::zero(), vec![]);
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_repeated_write_index_zero() {
        // classify rejects: a repeated write with enumeration index 0.
        let key = StorageKey::new(
            AccountTreeId::new(H160::repeat_byte(5)),
            H256::repeat_byte(6),
        );
        let log = StorageLog::new_write_log(key, H256::from_low_u64_be(1));
        let meta = entry(
            true,
            false,
            0,
            key.hashed_key_u256(),
            empty_root(),
            H256::zero(),
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_read_value_mismatch() {
        // map_log_tree rejects: witnessed pre-state value != VM-read value.
        let (vmkey, log) = read_pair(7, 8, H256::from_low_u64_be(3));
        let meta = entry(
            false,
            false,
            1,
            vmkey,
            empty_root(),
            H256::from_low_u64_be(7), // witnessed value_read != VM value (3)
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_corrupted_root_hash() {
        // fold rejects: a read op whose root_hash does not equal the running root.
        let (vmkey, log) = read_pair(9, 10, H256::zero());
        let meta = entry(
            false,
            false,
            0,
            vmkey,
            H256::repeat_byte(0xAB), // corrupted op root
            H256::zero(),
            vec![],
        );
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    #[test]
    fn streaming_matches_oracle_on_wrong_prestate_root() {
        // fold rejects at the prev_hash check: an existing-leaf read whose
        // pre-state (index 1, non-zero value) cannot fold to the empty root.
        let value = H256::from_low_u64_be(77);
        let (vmkey, log) = read_pair(11, 12, value);
        let meta = entry(false, false, 1, vmkey, empty_root(), value, vec![]);
        assert_equivalent(witness_of(vec![meta]), vec![log], empty_root(), 0);
    }

    /// The legacy encoder stored an entry whose padded path equalled entry 0's as an
    /// EMPTY vec — the degenerate `fui == TREE_DEPTH` case, so the splice restores
    /// entry 0's populated path. Folding it as-is would instead assert every level is
    /// an empty subtree and reject a valid batch.
    ///
    /// The fold knows none of this: after normalisation an empty stored path means
    /// populated depth 0 and nothing else.
    #[test]
    fn legacy_wholly_compacted_entry_normalises_to_entry_0s_path() {
        // Entry 0 padded to TREE_DEPTH — the legacy discriminator — with a populated
        // tail of three real hashes.
        let tail = [[7u8; HASH_LEN], [8; HASH_LEN], [9; HASH_LEN]];
        let mut first: Vec<[u8; HASH_LEN]> = (0..TREE_DEPTH - tail.len())
            .map(|d| Blake2Hasher.empty_subtree_hash(d).0)
            .collect();
        first.extend(tail);

        let mut witness = witness_of(vec![
            entry(
                false,
                false,
                0,
                U256::zero(),
                empty_root(),
                H256::zero(),
                first,
            ),
            // Wholly compacted: byte-identical to entry 0's padded path.
            entry(
                false,
                false,
                0,
                U256::one(),
                empty_root(),
                H256::zero(),
                vec![],
            ),
            // An entry whose delta boundary lands exactly on entry 0's populated
            // start: it already holds its whole populated path, so it is left alone.
            // (A *shorter* stored path here would mean it shares entry 0's real
            // siblings, and the splice would correctly restore them.)
            entry(
                false,
                false,
                0,
                U256::from(2),
                empty_root(),
                H256::zero(),
                vec![[1u8; HASH_LEN], [2; HASH_LEN], [3; HASH_LEN]],
            ),
        ]);
        assert!(witness.is_legacy_delta_form());
        let (reclaimed, restored) = witness.normalize_stored_paths().unwrap();

        let stored: Vec<&[[u8; HASH_LEN]]> = witness
            .merkle_paths
            .iter()
            .map(|m| m.merkle_paths.as_slice())
            .collect();
        assert_eq!(stored[0], tail, "entry 0 keeps only its populated depth");
        assert_eq!(
            stored[1], tail,
            "a wholly-compacted entry must be restored to entry 0's path, not left all-empty"
        );
        assert_eq!(
            stored[2],
            [[1u8; HASH_LEN], [2; HASH_LEN], [3; HASH_LEN]],
            "an entry that already holds its populated path needs neither splice nor trim"
        );
        assert_eq!((reclaimed, restored), (TREE_DEPTH - tail.len(), tail.len()));
        assert_eq!(
            witness.normalize_stored_paths().unwrap(),
            (0, 0),
            "normalisation is idempotent"
        );
    }

    /// A per-path witness whose entry 0 is empty (legal on a ~empty tree) is not the
    /// legacy form, so nothing is spliced and an empty entry stays empty — populated
    /// depth 0 now means exactly that.
    #[test]
    fn empty_entry_0_is_not_mistaken_for_the_legacy_form() {
        let mut witness = witness_of(vec![
            entry(
                false,
                false,
                0,
                U256::zero(),
                empty_root(),
                H256::zero(),
                vec![],
            ),
            entry(
                false,
                false,
                0,
                U256::one(),
                empty_root(),
                H256::zero(),
                vec![],
            ),
        ]);
        assert!(!witness.is_legacy_delta_form());
        assert_eq!(witness.normalize_stored_paths().unwrap(), (0, 0));
        assert!(witness.merkle_paths[1].merkle_paths.is_empty());
    }

    /// The ordering guard: a legacy witness that reaches the fold un-normalised must
    /// be rejected outright, not silently mis-folded.
    #[test]
    fn fold_rejects_an_un_normalised_legacy_witness() {
        let (key, log) = read_pair(0x11, 0x22, H256::zero());
        let full: Vec<[u8; HASH_LEN]> = (0..TREE_DEPTH)
            .map(|d| Blake2Hasher.empty_subtree_hash(d).0)
            .collect();
        let meta = entry(false, false, 0, key, empty_root(), H256::zero(), full);

        let err = verify_paths_and_new_root(witness_of(vec![meta]), vec![log], empty_root(), 5)
            .expect_err("entry 0 stored at the full TREE_DEPTH is the legacy form");
        assert!(
            err.to_string().contains("legacy delta-compacted form"),
            "unexpected error: {err}"
        );
    }

    // --- Over-long path: rejected before any fold. ---------------------------

    #[test]
    fn streaming_rejects_path_longer_than_tree_depth() {
        // `blake2_fold_merkle_path` *asserts* on an over-long path; Pass 1's bound
        // must turn that abort into a fail-closed rejection. (A path longer than
        // the first one is no longer malformed — entries are independent now.)
        let (k0, log0) = read_pair(13, 0, H256::zero());
        let m0 = entry(
            false,
            false,
            0,
            k0,
            empty_root(),
            H256::zero(),
            vec![[1u8; HASH_LEN]; TREE_DEPTH + 1],
        );

        let err = verify_paths_and_new_root(witness_of(vec![m0]), vec![log0], empty_root(), 0)
            .expect_err("an over-long path must be rejected, not folded");
        assert!(
            err.to_string().contains("longer than TREE_DEPTH"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn streaming_accepts_a_path_longer_than_the_first_entrys() {
        // The legacy format made this shape impossible ("the first path is not the
        // longest one"); with per-path storage it is ordinary and must verify.
        // Two missing-key reads on the empty tree: entry 0 stores nothing, entry 1
        // stores one hash that must fold to the empty root. Paths are bottom-up
        // and the omitted levels are the bottom ones, so that single hash sits at
        // the *top* level and has to be `empty_subtree_hash(TREE_DEPTH - 1)`.
        let (k0, log0) = read_pair(13, 0, H256::zero());
        let (k1, log1) = read_pair(13, 1, H256::zero());
        let level0_empty = Blake2Hasher.empty_subtree_hash(TREE_DEPTH - 1).0;
        let m0 = entry(false, false, 0, k0, empty_root(), H256::zero(), vec![]);
        let m1 = entry(
            false,
            false,
            0,
            k1,
            empty_root(),
            H256::zero(),
            vec![level0_empty],
        );

        let got =
            verify_paths_and_new_root(witness_of(vec![m0, m1]), vec![log0, log1], empty_root(), 5)
                .expect("a longer-than-first path is a legal shape");
        assert_eq!(got, (empty_root(), 5));
    }

    // --- Legacy-format compatibility, against a REAL tree. --------------------

    /// The compatibility property the upgrade rests on: a witness serialised in
    /// the **legacy** delta-compacted form and the same witness in the **per-path
    /// truncated** form verify identically — same accept, same returned root and
    /// enumeration index — against proofs from a real populated `MerkleTree`.
    ///
    /// This is what lets the reader ship before (or without) the producer: the
    /// delta form only ever stripped the shared empty-subtree run, so folding the
    /// stored path directly reproduces the same 256-level sibling sequence.
    ///
    /// The tree is set up the way the reported attack does it — one leaf planted
    /// next to the *first* entry's key — so the test doubles as the regression for
    /// it: the legacy encoding blows up with the plant, the per-path one does not,
    /// and both must still verify to the same root.
    #[test]
    fn legacy_and_truncated_witnesses_verify_identically() {
        use zksync_merkle_tree::{MerkleTree, PatchSet, TreeInstruction as TI};

        // Missing-key reads: the shape a far-call protective read produces. Reads
        // leave the root unchanged, so `old_root == op.root_hash == root`.
        let pairs: Vec<(U256, StorageLog)> = (0..24u8)
            .map(|i| read_pair(0x40 + i, i, H256::zero()))
            .collect();

        // A populated tree, so the proofs below have a real (non-trivial) tail...
        let mut tree = MerkleTree::new(PatchSet::default()).expect("tree");
        let mut leaves: Vec<TreeEntry> = (1..=512u64)
            .map(|i| {
                TreeEntry::new(
                    U256::from_big_endian(&H256::from_low_u64_be(i.wrapping_mul(0x9E37_79B9)).0),
                    i,
                    H256::repeat_byte(0x11),
                )
            })
            .collect();
        // ...plus the planted neighbour of the first read key, which is what makes
        // entry 0's populated zone deep (41 levels against 2-6 organically).
        const PLANTED_PREFIX_BITS: usize = 40;
        leaves.push(TreeEntry::new(
            neighbour_sharing_top_bits(pairs[0].0, PLANTED_PREFIX_BITS),
            513,
            H256::repeat_byte(0x22),
        ));
        tree.extend(leaves).expect("extend");
        let root = tree.latest_root_hash();

        let out = tree
            .extend_with_proofs(pairs.iter().map(|(k, _)| TI::Read(*k)).collect())
            .expect("extend_with_proofs");

        // The plant landed: entry 0 is far deeper than the rest, which is exactly
        // the floor the legacy encoding charged every other entry for.
        let depths: Vec<usize> = out.logs.iter().map(|l| l.merkle_path.len()).collect();
        assert_eq!(depths[0], PLANTED_PREFIX_BITS + 1, "depths: {depths:?}");
        assert!(
            depths[1..].iter().all(|&d| d < depths[0]),
            "depths: {depths:?}"
        );

        let build = |truncated: bool| {
            let metas: Vec<StorageLogMetadata> = out
                .logs
                .iter()
                .zip(&pairs)
                .enumerate()
                .map(|(i, (log, (key, _)))| {
                    let own: Vec<[u8; HASH_LEN]> = log.merkle_path.iter().map(|h| h.0).collect();
                    let merkle_paths = if truncated {
                        own
                    } else {
                        // Legacy encoder, reproduced exactly (era's
                        // `WitnessInputMerklePaths::push_merkle_path`, which is
                        // byte-identical to the copy this change deleted): pad to
                        // TREE_DEPTH, store entry 0 UNCOMPACTED, and cut every
                        // later entry at its longest common prefix with entry 0 —
                        // which for distinct keys is `max(d_first, d_i)` hashes.
                        let mut padded: Vec<[u8; HASH_LEN]> = (0..TREE_DEPTH - own.len())
                            .map(|d| Blake2Hasher.empty_subtree_hash(d).0)
                            .collect();
                        padded.extend(own);
                        if i == 0 {
                            padded
                        } else {
                            let stored_len = depths[i].max(depths[0]);
                            padded[TREE_DEPTH - stored_len..].to_vec()
                        }
                    };
                    entry(false, false, 0, *key, root, H256::zero(), merkle_paths)
                })
                .collect();
            witness_of(metas)
        };
        let vm_logs: Vec<StorageLog> = pairs.iter().map(|(_, log)| *log).collect();

        let truncated = verify_paths_and_new_root(build(true), vm_logs.clone(), root, 7)
            .expect("per-path-truncated witness must verify against the real root");
        assert_eq!(truncated, (root, 7));

        // The legacy form must reach the fold through the normaliser — as it does in
        // `execute` — and then agree with the per-path form exactly.
        let mut legacy_witness = build(false);
        let (reclaimed, restored) = legacy_witness.normalize_stored_paths().unwrap();
        let legacy = verify_paths_and_new_root(legacy_witness, vm_logs, root, 7)
            .expect("legacy delta-compacted witness must still verify once normalised");
        assert_eq!(legacy, truncated, "the two encodings must agree");

        // The regression itself: under the plant the legacy encoding charges every
        // entry entry-0's depth, the per-path one charges each its own.
        let stored = |w: &WitnessInputMerklePaths| -> usize {
            w.merkle_paths.iter().map(|m| m.merkle_paths.len()).sum()
        };
        assert_eq!(
            stored(&build(false)),
            TREE_DEPTH + depths[1..].iter().map(|&d| d.max(depths[0])).sum::<usize>()
        );
        assert_eq!(stored(&build(true)), depths.iter().sum::<usize>());
        assert!(
            stored(&build(false)) > 2 * stored(&build(true)),
            "the plant must inflate the legacy encoding (legacy {} vs per-path {})",
            stored(&build(false)),
            stored(&build(true)),
        );

        // On this shape (all reads, so every entry is delta'd strictly inside entry
        // 0's empty run) normalising is a pure reclaim: nothing to splice back, and
        // the result is byte-identical to the per-path form.
        let mut normalised = build(false);
        assert_eq!(
            normalised.normalize_stored_paths().unwrap(),
            (stored(&build(false)) - stored(&build(true)), 0),
            "normalising must reclaim exactly the plant's surplus and splice nothing"
        );
        assert_eq!(
            (reclaimed, restored),
            (stored(&build(false)) - stored(&build(true)), 0),
            "the witness folded above went through the same normalisation"
        );
        assert_eq!(
            normalised.normalize_stored_paths().unwrap(),
            (0, 0),
            "normalisation is idempotent"
        );
        assert_eq!(
            normalised.merkle_paths,
            build(true).merkle_paths,
            "normalising the legacy form must yield the per-path form"
        );
    }

    /// Regression against a real tree for the shape where the legacy delta form needs
    /// a decode rather than a trim, i.e. where `fui > TREE_DEPTH - d_i` and the
    /// stripped prefix holds real sibling hashes. Reached by
    /// `shared_top_bits(k_0, k_i) >= d_i` plus an intervening write; see
    /// `WitnessInputMerklePaths::normalize_stored_paths` for why that happens.
    ///
    /// `legacy_and_truncated_witnesses_verify_identically` cannot reach it: reads-only
    /// (an unmutated tree keeps `fui` inside the empty run), it plants a neighbour
    /// forcing `d_0 != d_i`, and its legacy arm comes from the `max(d_0, d_i)`
    /// formula rather than the real `position`-based encoder.
    #[test]
    fn legacy_delta_form_survives_an_intervening_write() {
        use zksync_merkle_tree::{MerkleTree, PatchSet, TreeInstruction as TI};

        // Fold index `j` is the sibling combined at `key.bit(j)`: j=255 is a child of
        // the root, j=0 is leaf-adjacent, and a path of depth `d` occupies
        // `j in [TREE_DEPTH - d, 255]`.
        //
        // Layout, picked so every quantity below is exact rather than probabilistic:
        //   neighbours planted at shared-top-bits {0,1,2,4} => k_i's siblings at
        //     j = 255,254,253,251 are non-empty and j=252 is EMPTY, so d_0 == d_i == 5.
        //   shared_top_bits(k_0, k_i) == 8 >= d_i => ancestors coincide for j >= 248,
        //     so the siblings match across the whole populated region.
        //   shared_top_bits(k_w, k_i) == 3 => the write lands in the j=252 hole.
        // => fui == 252 > TREE_DEPTH - d_i == 251: 4 stored hashes against a true
        //    depth of 5, the dropped one being the planted neighbour's real hash.
        const PLANT_BITS: usize = 4;
        const SHARED_BITS: usize = 8;
        const WRITE_BITS: usize = 3;

        // Entry 0 is the batch's smallest raw `(address, key)` — on Era the
        // AccountCodeStorage far-call read — then a system-contract write, then the
        // attacker's contract, whose ~random 160-bit address sorts last. Witness order
        // is raw `(shard_id, address, key)` per `sort_storage_access_queries`, so
        // ordering by address is faithful and independent of the ground slot values.
        let (addr0, addr_w, addr_i) = (
            H160::from_low_u64_be(0x8002),
            H160::from_low_u64_be(0x8003),
            H160::from_low_u64_be(0xdead_beef),
        );
        let (k0, log0) = read_pair_at(addr0, H256::zero(), H256::zero());
        // The attacker grinds their own slot against entry 0's fixed hashed key.
        let (ki, slot_i) = grind_slot(addr_i, k0, |n| n == SHARED_BITS);
        let (kw, slot_w) = grind_slot(addr_w, ki, |n| n == WRITE_BITS);
        assert_eq!(shared_top_bits(k0, ki), SHARED_BITS);
        assert_eq!(shared_top_bits(kw, ki), WRITE_BITS);

        // A ladder of planted neighbours, deliberately skipping `WRITE_BITS` so the
        // write has an empty sibling to create.
        let mut tree = MerkleTree::new(PatchSet::default()).expect("tree");
        let planted: Vec<usize> = (0..=PLANT_BITS).filter(|c| *c != WRITE_BITS).collect();
        let leaves: Vec<TreeEntry> = planted
            .iter()
            .enumerate()
            .map(|(n, &c)| {
                TreeEntry::new(
                    neighbour_sharing_top_bits(ki, c),
                    n as u64 + 1,
                    H256::repeat_byte(0x11),
                )
            })
            .collect();
        let next_index = leaves.len() as u64 + 1;
        tree.extend(leaves).expect("extend");
        let old_root = tree.latest_root_hash();

        // Entry 0: missing-key read. Entry 1: the intervening insert. Entry 2: the
        // attacker's missing-key read, ground next to entry 0.
        let (_, log_i) = read_pair_at(addr_i, slot_i, H256::zero());
        let written = H256::repeat_byte(0x77);
        let log_w =
            StorageLog::new_write_log(StorageKey::new(AccountTreeId::new(addr_w), slot_w), written);
        let out = tree
            .extend_with_proofs(vec![
                TI::Read(k0),
                TI::Write(TreeEntry::new(kw, next_index, written)),
                TI::Read(ki),
            ])
            .expect("extend_with_proofs");

        // The layout landed as designed: equal populated depths, and the write did
        // not move entry 2's depth (its shared prefix is shorter than the plant's).
        let depths: Vec<usize> = out.logs.iter().map(|l| l.merkle_path.len()).collect();
        assert_eq!(
            (depths[0], depths[2]),
            (PLANT_BITS + 1, PLANT_BITS + 1),
            "depths: {depths:?}"
        );

        // `padded_x[j]` is the sibling the fold uses at index `j`.
        let pad = |own: &[ValueHash]| -> Vec<[u8; HASH_LEN]> {
            let mut padded: Vec<[u8; HASH_LEN]> = (0..TREE_DEPTH - own.len())
                .map(|d| Blake2Hasher.empty_subtree_hash(d).0)
                .collect();
            padded.extend(own.iter().map(|h| h.0));
            padded
        };
        let padded: Vec<Vec<[u8; HASH_LEN]>> =
            out.logs.iter().map(|l| pad(&l.merkle_path)).collect();

        // The real deleted encoder: entry 0 uncompacted, every later entry cut at
        // its common-prefix boundary with entry 0. No `max(d_0, d_i)` shortcut.
        let legacy_stored = |i: usize| -> Vec<[u8; HASH_LEN]> {
            if i == 0 {
                return padded[0].clone();
            }
            let fui = padded[i]
                .iter()
                .zip(&padded[0])
                .position(|(h, h0)| h != h0)
                .unwrap_or(TREE_DEPTH);
            padded[i][fui..].to_vec()
        };

        // The defect, stated as arithmetic: the common prefix reaches PAST entry 2's
        // own empty run, so the stripped bytes are not all empty-subtree constants.
        let fui = TREE_DEPTH - legacy_stored(2).len();
        assert!(
            fui > TREE_DEPTH - depths[2],
            "the shape under test needs fui ({fui}) > TREE_DEPTH - d_i ({}); \
             depths: {depths:?}",
            TREE_DEPTH - depths[2],
        );
        assert_ne!(
            legacy_stored(2)[0],
            Blake2Hasher.empty_subtree_hash(fui).0,
            "the stored path must begin with a REAL sibling, or the splice is not \
             being exercised and a plain trim would have sufficed"
        );

        let build = |truncated: bool| {
            let metas: Vec<StorageLogMetadata> = out
                .logs
                .iter()
                .enumerate()
                .map(|(i, log)| {
                    let paths = if truncated {
                        log.merkle_path.iter().map(|h| h.0).collect()
                    } else {
                        legacy_stored(i)
                    };
                    let (key, is_write) = [(k0, false), (kw, true), (ki, false)][i];
                    entry(
                        is_write,
                        is_write,
                        0,
                        key,
                        log.root_hash,
                        H256::zero(),
                        paths,
                    )
                })
                .collect();
            witness_of(metas)
        };
        let vm_logs = vec![log0, log_w, log_i];
        let new_root = out.logs[2].root_hash;

        // Decode layer: normalising — what `execute` does first — must reproduce the
        // true padded paths. No fold involved, so a failure localises the defect.
        // Index-by-index, because `assert_eq!` on the nested `Vec` dumps three
        // 256-element hash arrays (~150 KB) without saying where it diverged.
        let mut normalised = build(false);
        assert!(normalised.is_legacy_delta_form());
        let (_, restored) = normalised.normalize_stored_paths().unwrap();
        assert_eq!(
            restored,
            fui - (TREE_DEPTH - depths[0]),
            "the splice must restore exactly the real siblings the delta stripped"
        );
        let decoded: Vec<Vec<[u8; HASH_LEN]>> = normalised
            .clone()
            .into_merkle_paths()
            .map(|m| m.merkle_paths)
            .collect();
        for (i, (got, want)) in decoded.iter().zip(&padded).enumerate() {
            assert_eq!(
                got.len(),
                want.len(),
                "entry {i}: decoded to a wrong length"
            );
            let diff = got.iter().zip(want).position(|(a, b)| a != b);
            assert!(
                diff.is_none(),
                "entry {i}: the legacy delta form decoded to the wrong sibling at fold \
                 index {} — stored {} hashes against a populated depth of {}, so the \
                 stripped prefix was NOT all empty-subtree constants and the fold \
                 would substitute `empty_subtree_hash` for a real sibling",
                diff.unwrap(),
                legacy_stored(i).len(),
                depths[i],
            );
        }
        // Normalisation is the identity on the per-path form, so the two arms end up
        // byte-identical — the property that lets one reader serve both wire forms.
        assert_eq!(
            normalised.merkle_paths,
            build(true).merkle_paths,
            "the normalised legacy form must equal the per-path form"
        );

        // Fold layer: both encodings must verify, and to the same result.
        let truncated =
            verify_paths_and_new_root(build(true), vm_logs.clone(), old_root, next_index)
                .expect("per-path-truncated witness must verify against the real root");
        assert_eq!(truncated, (new_root, next_index + 1));

        let legacy = verify_paths_and_new_root(normalised, vm_logs, old_root, next_index)
            .expect("legacy delta-compacted witness must verify once normalised");
        assert_eq!(legacy, truncated, "the two encodings must agree");
    }
}

#[cfg(test)]
mod read_proof_tests {
    use std::collections::BTreeMap;

    use zksync_merkle_tree::{MerkleTree, PatchSet};

    use super::*;

    type View = BTreeMap<H256, Option<(H256, u64)>>;

    const EXISTING: u64 = 0x1001;
    const ZERO_VALUED: u64 = 0x1002;
    const MISSING: u64 = 0x1003;

    fn key(n: u64) -> U256 {
        U256::from_big_endian(&H256::from_low_u64_be(n.wrapping_mul(0x9E37_79B9_7F4A_7C15)).0)
    }

    fn view_key(key: U256) -> H256 {
        let mut bytes = [0u8; 32];
        key.to_little_endian(&mut bytes);
        H256(bytes)
    }

    /// A populated tree holding `EXISTING` (non-zero value) and `ZERO_VALUED`
    /// (an existing leaf whose value is zero), with genuine proofs for those two
    /// and for the never-written `MISSING`.
    fn tree_proofs() -> (ValueHash, Vec<StorageReadProof>) {
        let mut tree = MerkleTree::new(PatchSet::default()).expect("tree");
        let mut leaves: Vec<TreeEntry> = (1..=64u64)
            .map(|i| TreeEntry::new(key(i), i, H256::repeat_byte(0x11)))
            .collect();
        leaves.push(TreeEntry::new(key(EXISTING), 65, H256::repeat_byte(0x42)));
        leaves.push(TreeEntry::new(key(ZERO_VALUED), 66, H256::zero()));
        tree.extend(leaves).expect("extend");
        let version = tree.latest_version().expect("version");
        let keys = [key(EXISTING), key(ZERO_VALUED), key(MISSING)];
        let proofs = tree
            .entries_with_proofs(version, &keys)
            .expect("proofs")
            .into_iter()
            .map(|entry| StorageReadProof {
                leaf_hashed_key: entry.base.key,
                leaf_enumeration_index: entry.base.leaf_index,
                value: entry.base.value.0,
                merkle_path: entry.merkle_path.iter().map(|h| h.0).collect(),
            })
            .collect();
        (tree.latest_root_hash(), proofs)
    }

    fn proof_for(n: u64) -> (ValueHash, StorageReadProof) {
        let (root, proofs) = tree_proofs();
        let proof = proofs
            .into_iter()
            .find(|p| p.leaf_hashed_key == key(n))
            .unwrap();
        (root, proof)
    }

    fn extend(proofs: Vec<StorageReadProof>, root: ValueHash) -> anyhow::Result<View> {
        let mut view = View::new();
        extend_view_with_read_proofs(&mut view, proofs, root)?;
        Ok(view)
    }

    fn assert_rejected(proofs: Vec<StorageReadProof>, root: ValueHash, needle: &str) {
        let err = extend(proofs, root).expect_err("must be rejected");
        assert!(err.to_string().contains(needle), "unexpected error: {err}");
    }

    #[test]
    fn read_proof_existing_leaf_enters_view() {
        let (root, proof) = proof_for(EXISTING);
        let view = extend(vec![proof], root).unwrap();
        assert_eq!(
            view.get(&view_key(key(EXISTING))),
            Some(&Some((H256::repeat_byte(0x42), 65)))
        );
    }

    /// Value 0 at an existing index is a repeated write, not initial.
    #[test]
    fn read_proof_zero_value_existing_leaf_is_not_initial() {
        let (root, proof) = proof_for(ZERO_VALUED);
        let view = extend(vec![proof], root).unwrap();
        assert_eq!(
            view.get(&view_key(key(ZERO_VALUED))),
            Some(&Some((H256::zero(), 66)))
        );
    }

    #[test]
    fn read_proof_missing_leaf_is_none() {
        let (root, proof) = proof_for(MISSING);
        assert_eq!(proof.leaf_enumeration_index, 0);
        let view = extend(vec![proof], root).unwrap();
        assert_eq!(view.get(&view_key(key(MISSING))), Some(&None));
    }

    #[test]
    fn read_proof_all_shapes_together() {
        let (root, mut proofs) = tree_proofs();
        proofs.sort_by_key(|proof| proof.leaf_hashed_key);
        assert_eq!(extend(proofs, root).unwrap().len(), 3);
    }

    #[test]
    fn read_proof_rejects_unsorted_and_duplicate_keys() {
        let (root, mut proofs) = tree_proofs();
        proofs.sort_by_key(|proof| proof.leaf_hashed_key);
        let duplicate = vec![proofs[0].clone(), proofs[0].clone()];
        assert_rejected(duplicate, root, "strictly ascending");
        proofs.reverse();
        assert_rejected(proofs, root, "strictly ascending");
    }

    #[test]
    fn read_proof_rejects_forged_value() {
        let (root, mut proof) = proof_for(EXISTING);
        proof.value[0] ^= 1;
        assert_rejected(vec![proof], root, "does not fold to the old root");
    }

    #[test]
    fn read_proof_rejects_forged_index() {
        let (root, mut proof) = proof_for(EXISTING);
        proof.leaf_enumeration_index += 1;
        assert_rejected(vec![proof], root, "does not fold to the old root");
    }

    #[test]
    fn read_proof_rejects_wrong_root() {
        let (root, proof) = proof_for(EXISTING);
        let wrong = H256(std::array::from_fn(|i| root.0[i] ^ 0xff));
        assert_rejected(vec![proof], wrong, "does not fold to the old root");
    }

    #[test]
    fn read_proof_rejects_path_longer_than_tree_depth() {
        let (root, mut proof) = proof_for(EXISTING);
        proof.merkle_path = vec![[0; HASH_LEN]; TREE_DEPTH + 1];
        assert_rejected(vec![proof], root, "longer than TREE_DEPTH");
    }

    #[test]
    fn read_proof_rejects_missing_leaf_with_value() {
        let (root, mut proof) = proof_for(MISSING);
        proof.value[31] = 1;
        assert_rejected(vec![proof], root, "carries a non-zero value");
    }

    /// Two proofs for one key that fold to different roots can't both pass, so
    /// the conflict is set up on a view that already holds the key.
    #[test]
    fn read_proof_rejects_duplicate_key_with_different_prestate() {
        let (root, proof) = proof_for(EXISTING);
        let mut view = View::new();
        view.insert(view_key(key(EXISTING)), None);
        let err = extend_view_with_read_proofs(&mut view, vec![proof], root).unwrap_err();
        assert!(err.to_string().contains("conflicting pre-state"), "{err}");
    }

    #[test]
    fn read_proof_rejects_disagreeing_merkle_paths_entry() {
        let (root, proof) = proof_for(EXISTING);
        let log = StorageLogMetadata {
            root_hash: root.0,
            is_write: false,
            first_write: false,
            merkle_paths: vec![],
            leaf_hashed_key: key(EXISTING),
            leaf_enumeration_index: 65,
            value_written: [0; HASH_LEN],
            value_read: [0x43; HASH_LEN],
        };
        let mut view = build_view_from_merkle_paths(std::slice::from_ref(&log)).unwrap();
        let err = extend_view_with_read_proofs(&mut view, vec![proof.clone()], root).unwrap_err();
        assert!(err.to_string().contains("conflicting pre-state"), "{err}");

        // Agreeing overlap is fine.
        let agreeing = StorageLogMetadata {
            value_read: [0x42; HASH_LEN],
            ..log
        };
        let mut view = build_view_from_merkle_paths(&[agreeing]).unwrap();
        extend_view_with_read_proofs(&mut view, vec![proof], root).unwrap();
    }
}
