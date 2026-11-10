//! Consistency verification for the Merkle tree.

use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::{
    errors::DeserializeError,
    hasher::{HashTree, HasherWithStats},
    types::{LeafNode, Nibbles, Node, NodeKey, Root},
    Database, Key, MerkleTree, ValueHash,
};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConsistencyError {
    #[error("failed deserializing node from DB: {0}")]
    Deserialize(#[from] DeserializeError),
    #[error("tree version {0} does not exist")]
    MissingVersion(u64),
    #[error("missing root for tree version {0}")]
    MissingRoot(u64),
    #[error(
        "missing {node_str} at {key}",
        node_str = if *is_leaf { "leaf" } else { "internal node" }
    )]
    MissingNode { key: NodeKey, is_leaf: bool },
    #[error("internal node at terminal tree level {key}")]
    TerminalInternalNode { key: NodeKey },
    #[error("tree root specifies that tree has {expected} leaves, but it actually has {actual}")]
    LeafCountMismatch { expected: u64, actual: u64 },
    #[error(
        "internal node at {key} specifies that child hash at `{nibble:x}` \
         is {expected}, but it actually is {actual}"
    )]
    HashMismatch {
        key: NodeKey,
        nibble: u8,
        expected: ValueHash,
        actual: ValueHash,
    },
    #[error(
        "leaf at {key} specifies its full key as {full_key}, which doesn't start with the node key"
    )]
    FullKeyMismatch { key: NodeKey, full_key: Key },
    #[error("leaf with key {full_key} has zero index, while leaf indices must start with 1")]
    ZeroIndex { full_key: Key },
    #[error(
        "leaf with key {full_key} has index {index}, which is greater than \
         leaf count {leaf_count} specified at tree root"
    )]
    LeafIndexOverflow {
        index: u64,
        leaf_count: u64,
        full_key: Key,
    },
    #[error("leaf with key {full_key} has same index {index} as another key")]
    DuplicateLeafIndex { index: u64, full_key: Key },
    #[error("internal node with key {key} does not have children")]
    EmptyInternalNode { key: NodeKey },
    #[error(
        "internal node with key {key} should have version {expected_version} (max among child ref versions)"
    )]
    KeyVersionMismatch { key: NodeKey, expected_version: u64 },
    #[error("root node should have version >={max_child_version} (max among child ref versions)")]
    RootVersionMismatch { max_child_version: u64 },
}

impl<DB: Database, H: HashTree> MerkleTree<DB, H> {
    /// Verifies the internal tree consistency as stored in the database.
    ///
    /// If `validate_indices` flag is set, it will be checked that indices for all tree leaves are unique
    /// and are sequentially assigned starting from 1.
    ///
    /// # Errors
    ///
    /// Returns an error (the first encountered one if there are multiple).
    pub fn verify_consistency(
        &self,
        version: u64,
        validate_indices: bool,
    ) -> Result<(), ConsistencyError> {
        let manifest = self.db.try_manifest()?;
        let manifest = manifest.ok_or(ConsistencyError::MissingVersion(version))?;
        if version >= manifest.version_count {
            return Err(ConsistencyError::MissingVersion(version));
        }

        let root = self
            .db
            .try_root(version)?
            .ok_or(ConsistencyError::MissingRoot(version))?;
        let (leaf_count, root_node) = match root {
            Root::Empty => return Ok(()),
            Root::Filled { leaf_count, node } => (leaf_count.get(), node),
        };

        // We want to perform a depth-first walk of the tree in order to not keep
        // much in memory.
        let root_key = Nibbles::EMPTY.with_version(version);
        let leaf_data = validate_indices.then(|| LeafConsistencyData::new(leaf_count));
        self.validate_node(&root_node, root_key, leaf_data.as_ref())?;
        if let Some(leaf_data) = leaf_data {
            leaf_data.validate_count()?;
        }
        Ok(())
    }

    fn validate_node(
        &self,
        node: &Node,
        key: NodeKey,
        leaf_data: Option<&LeafConsistencyData>,
    ) -> Result<ValueHash, ConsistencyError> {
        match node {
            Node::Leaf(leaf) => {
                let full_key_nibbles = Nibbles::new(&leaf.full_key, key.nibbles.nibble_count());
                if full_key_nibbles != key.nibbles {
                    return Err(ConsistencyError::FullKeyMismatch {
                        key,
                        full_key: leaf.full_key,
                    });
                }
                if let Some(leaf_data) = leaf_data {
                    leaf_data.insert_leaf(leaf)?;
                }
            }

            Node::Internal(node) => {
                let expected_version = node.child_refs().map(|child_ref| child_ref.version).max();
                let Some(expected_version) = expected_version else {
                    return Err(ConsistencyError::EmptyInternalNode { key });
                };
                if !key.is_empty() && expected_version != key.version {
                    return Err(ConsistencyError::KeyVersionMismatch {
                        key,
                        expected_version,
                    });
                } else if key.is_empty() && expected_version > key.version {
                    return Err(ConsistencyError::RootVersionMismatch {
                        max_child_version: expected_version,
                    });
                }

                // `.into_par_iter()` below is the only place where `rayon`-based parallelism
                // is used in tree verification.
                let children: Vec<_> = node.children().collect();
                children
                    .into_par_iter()
                    .try_for_each(|(nibble, child_ref)| {
                        let child_key = key
                            .nibbles
                            .push(nibble)
                            .ok_or(ConsistencyError::TerminalInternalNode { key })?;
                        let child_key = child_key.with_version(child_ref.version);
                        let child = self
                            .db
                            .try_tree_node(&child_key, child_ref.is_leaf)?
                            .ok_or(ConsistencyError::MissingNode {
                                key: child_key,
                                is_leaf: child_ref.is_leaf,
                            })?;

                        // Recursion here is OK; the tree isn't that deep (approximately 8 nibbles for a tree with
                        // approximately 1B entries).
                        let child_hash = self.validate_node(&child, child_key, leaf_data)?;
                        if child_hash == child_ref.hash {
                            Ok(())
                        } else {
                            Err(ConsistencyError::HashMismatch {
                                key,
                                nibble,
                                expected: child_ref.hash,
                                actual: child_hash,
                            })
                        }
                    })?;
            }
        }

        let level = key.nibbles.nibble_count() * 4;
        Ok(node.hash(&mut HasherWithStats::new(&self.hasher), level))
    }
}

#[derive(Debug)]
struct LeafConsistencyData {
    expected_leaf_count: u64,
    actual_leaf_count: AtomicU64,
    leaf_indices_set: AtomicBitSet,
}

#[allow(clippy::cast_possible_truncation)] // expected leaf count is quite small
impl LeafConsistencyData {
    fn new(expected_leaf_count: u64) -> Self {
        Self {
            expected_leaf_count,
            actual_leaf_count: AtomicU64::new(0),
            leaf_indices_set: AtomicBitSet::new(expected_leaf_count as usize),
        }
    }

    fn insert_leaf(&self, leaf: &LeafNode) -> Result<(), ConsistencyError> {
        if leaf.leaf_index == 0 {
            return Err(ConsistencyError::ZeroIndex {
                full_key: leaf.full_key,
            });
        }
        if leaf.leaf_index > self.expected_leaf_count {
            return Err(ConsistencyError::LeafIndexOverflow {
                index: leaf.leaf_index,
                leaf_count: self.expected_leaf_count,
                full_key: leaf.full_key,
            });
        }

        let index = (leaf.leaf_index - 1) as usize;
        if self.leaf_indices_set.set(index) {
            return Err(ConsistencyError::DuplicateLeafIndex {
                index: leaf.leaf_index,
                full_key: leaf.full_key,
            });
        }
        self.actual_leaf_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn validate_count(mut self) -> Result<(), ConsistencyError> {
        let actual_leaf_count = *self.actual_leaf_count.get_mut();
        if actual_leaf_count == self.expected_leaf_count {
            Ok(())
        } else {
            Err(ConsistencyError::LeafCountMismatch {
                expected: self.expected_leaf_count,
                actual: actual_leaf_count,
            })
        }
    }
}

/// Primitive atomic bit set implementation that only supports setting bits.
#[derive(Debug)]
struct AtomicBitSet {
    bits: Vec<AtomicU64>,
}

impl AtomicBitSet {
    const BITS_PER_ATOMIC: usize = 64;

    fn new(len: usize) -> Self {
        let atomic_count = len.div_ceil(Self::BITS_PER_ATOMIC);
        let mut bits = Vec::with_capacity(atomic_count);
        bits.resize_with(atomic_count, AtomicU64::default);
        Self { bits }
    }

    /// Returns the previous bit value.
    fn set(&self, bit_index: usize) -> bool {
        let atomic_index = bit_index / Self::BITS_PER_ATOMIC;
        let shift_in_atomic = bit_index % Self::BITS_PER_ATOMIC;
        let atomic = &self.bits[atomic_index];
        let mask = 1 << (shift_in_atomic as u64);
        let prev_value = atomic.fetch_or(mask, Ordering::SeqCst);
        prev_value & mask != 0
    }
}
