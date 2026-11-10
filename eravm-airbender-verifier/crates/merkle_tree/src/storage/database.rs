//! `Database` trait and its implementations.

use std::{any::Any, ops};

use crate::{
    errors::DeserializeError,
    storage::patch::PatchSet,
    types::{Manifest, Node, NodeKey, ProfiledTreeOperation, Root},
};

/// Slice of node keys together with an indicator whether a node at the requested key is a leaf.
/// Used in [`Database::tree_nodes()`].
pub type NodeKeys = [(NodeKey, bool)];

/// Generic database functionality. Its main implementation is [`RocksDB`].
pub trait Database: Send + Sync {
    /// Tries to read the tree [`Manifest`].
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if any.
    fn try_manifest(&self) -> Result<Option<Manifest>, DeserializeError>;
    /// Returns the tree manifest.
    ///
    /// # Panics
    ///
    /// Panics on deserialization errors.
    fn manifest(&self) -> Option<Manifest> {
        self.try_manifest().unwrap_or_else(|err| panic!("{err}"))
    }

    /// Tries to obtain a root from this storage.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if any.
    fn try_root(&self, version: u64) -> Result<Option<Root>, DeserializeError>;
    /// Obtains a root from the tree storage.
    ///
    /// # Panics
    ///
    /// Panics on deserialization errors.
    fn root(&self, version: u64) -> Option<Root> {
        self.try_root(version).unwrap_or_else(|err| panic!("{err}"))
    }

    /// Obtains a node with the specified key from the tree storage. Root nodes are obtained
    /// using [`Self::root()`], never this method.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if any.
    fn try_tree_node(&self, key: &NodeKey, is_leaf: bool)
        -> Result<Option<Node>, DeserializeError>;
    /// Obtains a node with the specified key from the tree storage.
    ///
    /// # Panics
    ///
    /// Panics on deserialization errors.
    fn tree_node(&self, key: &NodeKey, is_leaf: bool) -> Option<Node> {
        self.try_tree_node(key, is_leaf)
            .unwrap_or_else(|err| panic!("{err}"))
    }

    /// Obtains nodes with the specified keys from the tree storage. The nodes
    /// are returned in a `Vec` in the same order as requested.
    ///
    /// # Panics
    ///
    /// Panics on deserialization errors.
    fn tree_nodes(&self, keys: &NodeKeys) -> Vec<Option<Node>> {
        let nodes = keys
            .iter()
            .map(|(key, is_leaf)| self.try_tree_node(key, *is_leaf));
        nodes
            .collect::<Result<_, _>>()
            .unwrap_or_else(|err| panic!("{err}"))
    }

    /// Starts profiling I/O operations and returns a thread-local guard to be dropped when profiling should be finished.
    fn start_profiling(&self, operation: ProfiledTreeOperation) -> Box<dyn Any>;

    /// Applies changes in the `patch` to this database. This operation should be atomic.
    ///
    /// # Errors
    ///
    /// Returns I/O errors.
    fn apply_patch(&mut self, patch: PatchSet) -> anyhow::Result<()>;
}

impl<DB: Database + ?Sized> Database for &mut DB {
    fn try_manifest(&self) -> Result<Option<Manifest>, DeserializeError> {
        (**self).try_manifest()
    }

    fn try_root(&self, version: u64) -> Result<Option<Root>, DeserializeError> {
        (**self).try_root(version)
    }

    fn try_tree_node(
        &self,
        key: &NodeKey,
        is_leaf: bool,
    ) -> Result<Option<Node>, DeserializeError> {
        (**self).try_tree_node(key, is_leaf)
    }

    fn tree_nodes(&self, keys: &NodeKeys) -> Vec<Option<Node>> {
        (**self).tree_nodes(keys)
    }

    fn start_profiling(&self, operation: ProfiledTreeOperation) -> Box<dyn Any> {
        (**self).start_profiling(operation)
    }

    fn apply_patch(&mut self, patch: PatchSet) -> anyhow::Result<()> {
        (**self).apply_patch(patch)
    }
}

impl Database for PatchSet {
    fn try_manifest(&self) -> Result<Option<Manifest>, DeserializeError> {
        Ok(Some(self.manifest.clone()))
    }

    fn try_root(&self, version: u64) -> Result<Option<Root>, DeserializeError> {
        let Some(patch) = self.patches_by_version.get(&version) else {
            return Ok(None);
        };
        Ok(patch.root.clone())
    }

    fn try_tree_node(
        &self,
        key: &NodeKey,
        is_leaf: bool,
    ) -> Result<Option<Node>, DeserializeError> {
        let patch_with_node = self.patches_by_version.get(&key.version);
        let node = patch_with_node.and_then(|patch| patch.nodes.get(key));
        let Some(node) = node.cloned() else {
            return Ok(None);
        };
        debug_assert_eq!(
            matches!(node, Node::Leaf(_)),
            is_leaf,
            "Internal check failed: node at {key:?} is requested as {ty}, \
             but has the opposite type",
            ty = if is_leaf { "leaf" } else { "internal node" }
        );
        Ok(Some(node))
    }

    fn start_profiling(&self, _operation: ProfiledTreeOperation) -> Box<dyn Any> {
        Box::new(()) // no stats are collected
    }

    fn apply_patch(&mut self, mut other: PatchSet) -> anyhow::Result<()> {
        if let Some(other_updated_version) = other.updated_version {
            if let Some(updated_version) = self.updated_version {
                anyhow::ensure!(
                    other_updated_version == updated_version,
                    "Cannot merge patches with different updated versions"
                );

                let patch = self.patches_by_version.get_mut(&updated_version).unwrap();
                let other_patch = other.patches_by_version.remove(&updated_version).unwrap();
                // ^ `unwrap()`s are safe by design.
                patch.merge(other_patch);
            } else {
                anyhow::ensure!(
                    self.patches_by_version.keys().all(|&ver| ver > other_updated_version),
                    "Cannot update {self:?} from {other:?}; this would break the update version invariant \
                     (the update version being lesser than all inserted versions)"
                );
                self.updated_version = Some(other_updated_version);
            }
        }

        let new_version_count = other.manifest.version_count;
        if new_version_count < self.manifest.version_count {
            // Remove obsolete sub-patches from the patch.
            self.patches_by_version
                .retain(|&version, _| version < new_version_count);
        }
        self.manifest = other.manifest;
        self.patches_by_version.extend(other.patches_by_version);
        for (version, stale_keys) in other.stale_keys_by_version {
            self.stale_keys_by_version
                .entry(version)
                .or_default()
                .extend(stale_keys);
        }
        // `PatchSet` invariants hold by construction: the updated version (if set) is still lower
        // than all other versions by design.
        Ok(())
    }
}

/// Wrapper for a [`Database`] that also contains in-memory [`PatchSet`] on top of it.
// We need to be careful to not over-delegate to the wrapped DB when the `PatchSet` contains
// an instruction to truncate tree versions. In order to do this, we use the
// `is_responsible_for_version()` in `PatchSet`, which is based not only on the contained
// tree roots, but on the manifest as well.
#[derive(Debug)]
pub struct Patched<DB> {
    inner: DB,
    patch: Option<PatchSet>,
}

impl<DB: Database> Patched<DB> {
    /// Wraps the provided database.
    pub fn new(inner: DB) -> Self {
        Self { inner, patch: None }
    }

    pub(crate) fn patched_versions(&self) -> Vec<u64> {
        self.patch.as_ref().map_or_else(Vec::new, |patch| {
            patch.patches_by_version.keys().copied().collect()
        })
    }

    /// Returns the value from the patch and a flag whether this value is final (i.e., a DB lookup
    /// is not required).
    fn lookup_patch(&self, key: &NodeKey, is_leaf: bool) -> (Option<Node>, bool) {
        let Some(patch) = &self.patch else {
            return (None, false);
        };
        if patch.is_new_version(key.version) {
            return (patch.tree_node(key, is_leaf), true);
        }
        let could_be_in_updated_patch = patch.updated_version == Some(key.version);
        if could_be_in_updated_patch {
            // Unlike with new versions, we must look both in the update patch and in the original DB.
            if let Some(node) = patch.tree_node(key, is_leaf) {
                return (Some(node), true);
            }
        }
        (None, false)
    }

    /// Provides readonly access to the wrapped DB.
    pub(crate) fn inner(&self) -> &DB {
        &self.inner
    }

    /// Provides access to the wrapped DB. Should not be used to mutate DB data.
    pub(crate) fn inner_mut(&mut self) -> &mut DB {
        &mut self.inner
    }

    /// Flushes changes from RAM to the wrapped database.
    ///
    /// # Errors
    ///
    /// Proxies database I/O errors.
    pub fn flush(&mut self) -> anyhow::Result<()> {
        if let Some(patch) = self.patch.take() {
            self.inner.apply_patch(patch)?;
        }
        Ok(())
    }

    /// Forgets about changes held in RAM.
    pub fn reset(&mut self) {
        self.patch = None;
    }

    /// Returns the wrapped database.
    ///
    /// # Panics
    ///
    /// Panics if the database contains uncommitted changes. Call [`Self::flush()`]
    /// or [`Self::reset()`] beforehand to avoid this panic.
    pub fn into_inner(self) -> DB {
        assert!(
            self.patch.is_none(),
            "The `Patched` database contains uncommitted changes"
        );
        self.inner
    }
}

impl<DB: Database> Database for Patched<DB> {
    fn try_manifest(&self) -> Result<Option<Manifest>, DeserializeError> {
        if let Some(patch) = &self.patch {
            Ok(Some(patch.manifest.clone()))
        } else {
            self.inner.try_manifest()
        }
    }

    fn try_root(&self, version: u64) -> Result<Option<Root>, DeserializeError> {
        if let Some(patch) = &self.patch {
            let has_root = patch.is_new_version(version) || patch.updated_version == Some(version);
            if has_root {
                return patch.try_root(version);
            }
        }
        self.inner.try_root(version)
    }

    fn try_tree_node(
        &self,
        key: &NodeKey,
        is_leaf: bool,
    ) -> Result<Option<Node>, DeserializeError> {
        let (patch_node, is_final) = self.lookup_patch(key, is_leaf);
        if is_final {
            Ok(patch_node)
        } else if let Some(node) = patch_node {
            Ok(Some(node))
        } else {
            self.inner.try_tree_node(key, is_leaf)
        }
    }

    fn tree_nodes(&self, keys: &NodeKeys) -> Vec<Option<Node>> {
        if self.patch.is_none() {
            return self.inner.tree_nodes(keys);
        }

        let mut is_in_patch = vec![false; keys.len()];
        let mut patch_values = vec![];
        for (i, (key, is_leaf)) in keys.iter().enumerate() {
            let (patch_node, is_final) = self.lookup_patch(key, *is_leaf);
            if is_final {
                patch_values.push(patch_node);
                is_in_patch[i] = true;
            } else if let Some(node) = patch_node {
                patch_values.push(Some(node));
                is_in_patch[i] = true;
            }
        }
        let db_keys: Vec<_> = keys
            .iter()
            .zip(&is_in_patch)
            .filter_map(|(&key, &is_in_patch)| (!is_in_patch).then_some(key))
            .collect();

        let mut patch_values = patch_values.into_iter();
        let mut db_values = self.inner.tree_nodes(&db_keys).into_iter();
        let values = is_in_patch.into_iter().map(|is_in_patch| {
            if is_in_patch {
                patch_values.next().unwrap()
            } else {
                db_values.next().unwrap()
            }
        });
        values.collect()
    }

    fn start_profiling(&self, operation: ProfiledTreeOperation) -> Box<dyn Any> {
        self.inner.start_profiling(operation)
    }

    fn apply_patch(&mut self, patch: PatchSet) -> anyhow::Result<()> {
        if let Some(existing_patch) = &mut self.patch {
            existing_patch.apply_patch(patch)?;
        } else {
            self.patch = Some(patch);
        }
        Ok(())
    }
}

/// Analogue of [`PatchSet`] used when pruning past versions of the Merkle tree.
#[derive(Debug)]
pub struct PrunePatchSet {
    /// Keys that need to be removed from the tree. Logically, the version of each key
    /// should be less than `min_retained_version`.
    pub(super) pruned_node_keys: Vec<NodeKey>,
    /// Range of replacing versions for stale keys that need to be removed.
    pub(super) deleted_stale_key_versions: ops::Range<u64>,
}

impl PrunePatchSet {
    pub(crate) fn new(
        pruned_node_keys: Vec<NodeKey>,
        deleted_stale_key_versions: ops::Range<u64>,
    ) -> Self {
        Self {
            pruned_node_keys,
            deleted_stale_key_versions,
        }
    }
}

/// Functionality to prune past versions of the Merkle tree.
pub trait PruneDatabase: Database {
    /// Returns the minimum new version for stale keys present in this database, or `None`
    /// if there are no stale keys.
    fn min_stale_key_version(&self) -> Option<u64>;

    /// Returns a list of node keys obsoleted in the specified `version` of the tree.
    fn stale_keys(&self, version: u64) -> Vec<NodeKey>;

    /// Atomically prunes the tree and updates information about the minimum retained version.
    ///
    /// # Errors
    ///
    /// Propagates database I/O errors.
    fn prune(&mut self, patch: PrunePatchSet) -> anyhow::Result<()>;

    /// Atomically truncates the specified range of versions and stale keys.
    ///
    /// # Errors
    ///
    /// Propagates database I/O errors.
    fn truncate(
        &mut self,
        manifest: Manifest,
        truncated_versions: ops::RangeTo<u64>,
    ) -> anyhow::Result<()>;
}

impl<T: PruneDatabase + ?Sized> PruneDatabase for &mut T {
    fn min_stale_key_version(&self) -> Option<u64> {
        (**self).min_stale_key_version()
    }

    fn stale_keys(&self, version: u64) -> Vec<NodeKey> {
        (**self).stale_keys(version)
    }

    fn prune(&mut self, patch: PrunePatchSet) -> anyhow::Result<()> {
        (**self).prune(patch)
    }

    fn truncate(
        &mut self,
        manifest: Manifest,
        truncated_versions: ops::RangeTo<u64>,
    ) -> anyhow::Result<()> {
        (**self).truncate(manifest, truncated_versions)
    }
}

impl PruneDatabase for PatchSet {
    fn min_stale_key_version(&self) -> Option<u64> {
        self.stale_keys_by_version
            .iter()
            .filter_map(|(&version, keys)| (!keys.is_empty()).then_some(version))
            .min()
    }

    fn stale_keys(&self, version: u64) -> Vec<NodeKey> {
        self.stale_keys_by_version
            .get(&version)
            .cloned()
            .unwrap_or_default()
    }

    fn prune(&mut self, patch: PrunePatchSet) -> anyhow::Result<()> {
        for key in &patch.pruned_node_keys {
            let Some(patch) = self.patches_by_version.get_mut(&key.version) else {
                continue;
            };
            if key.is_empty() {
                patch.root = None;
            } else {
                patch.nodes.remove(key);
            }
        }

        self.stale_keys_by_version
            .retain(|version, _| !patch.deleted_stale_key_versions.contains(version));
        Ok(())
    }

    fn truncate(
        &mut self,
        manifest: Manifest,
        truncated_versions: ops::RangeTo<u64>,
    ) -> anyhow::Result<()> {
        self.manifest = manifest;
        self.stale_keys_by_version
            .retain(|version, _| !truncated_versions.contains(version));
        Ok(())
    }
}
