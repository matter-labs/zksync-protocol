//! Old-root read proofs built from a batch's own witness, so a stored fixture can
//! be turned into an input that carries `prestate_read_proofs`.

use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_merkle_tree::{HashTree, ValueHash, TREE_DEPTH};
use zksync_types::{H256, U256};

use crate::types::{StorageLogMetadata, StorageReadProof, WitnessInputMerklePaths};

/// `meta`'s pre-batch leaf as `(enumeration index, value)`.
fn pre_state(meta: &StorageLogMetadata) -> (u64, [u8; 32]) {
    if meta.first_write || meta.leaf_enumeration_index == 0 {
        (0, [0; 32])
    } else {
        (meta.leaf_enumeration_index, meta.value_read)
    }
}

/// A read proof of entry `i`'s pre-state against the old root. Stored paths are
/// taken against the running root, so each sibling subtree an earlier write touched
/// is rebuilt from the first such write's pre-state, whose own lower siblings are
/// still old. `metas` must be normalised.
pub fn old_root_read_proof(metas: &[StorageLogMetadata], i: usize) -> StorageReadProof {
    let hasher: &dyn HashTree = &Blake2Hasher;
    let full_path = |meta: &StorageLogMetadata| -> Vec<ValueHash> {
        (0..TREE_DEPTH - meta.merkle_paths.len())
            .map(|depth| hasher.empty_subtree_hash(depth))
            .chain(meta.merkle_paths.iter().map(|h| ValueHash::from(*h)))
            .collect()
    };
    let key = metas[i].leaf_hashed_key;
    let mut path = full_path(&metas[i]);
    for (depth, sibling) in path.iter_mut().enumerate() {
        let in_sibling_subtree = |other: U256| {
            other >> (depth + 1) == key >> (depth + 1) && other.bit(depth) != key.bit(depth)
        };
        let Some(write) = metas[..i]
            .iter()
            .find(|m| m.is_write && in_sibling_subtree(m.leaf_hashed_key))
        else {
            continue;
        };
        let (index, value) = pre_state(write);
        let mut hash = hasher.hash_leaf(&H256(value), index);
        for (d, lower) in full_path(write)[..depth].iter().enumerate() {
            hash = if write.leaf_hashed_key.bit(d) {
                hasher.hash_branch(lower, &hash)
            } else {
                hasher.hash_branch(&hash, lower)
            };
        }
        *sibling = hash;
    }
    let (index, value) = pre_state(&metas[i]);
    StorageReadProof {
        leaf_hashed_key: key,
        leaf_enumeration_index: index,
        value,
        merkle_path: path.into_iter().map(|h| h.0).collect(),
    }
}

/// Old-root read proofs for every `merkle_paths` entry, in the ascending key order
/// the verifier requires.
pub fn old_root_read_proofs(
    merkle_paths: &WitnessInputMerklePaths,
) -> anyhow::Result<Vec<StorageReadProof>> {
    let mut normalized = merkle_paths.clone();
    normalized.normalize_stored_paths()?;
    let metas = &normalized.merkle_paths;
    let mut proofs: Vec<_> = (0..metas.len())
        .map(|i| old_root_read_proof(metas, i))
        .collect();
    proofs.sort_by_key(|proof| proof.leaf_hashed_key);
    Ok(proofs)
}
