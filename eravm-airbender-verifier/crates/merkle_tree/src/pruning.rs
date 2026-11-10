//! Tree pruning logic.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Weak,
    },
    time::Duration,
};

use crate::{
    metrics::PruningStats,
    storage::{PruneDatabase, PrunePatchSet},
};

/// Error returned by [`MerkleTreePrunerHandle::set_target_retained_version()`].
#[derive(Debug)]
pub struct PrunerStoppedError(());

impl fmt::Display for PrunerStoppedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Merkle tree pruner stopped")
    }
}

/// Handle for a [`MerkleTreePruner`] allowing to abort its operation.
///
/// The pruner is aborted once the handle is dropped.
#[must_use = "Pruner is aborted once handle is dropped"]
#[derive(Debug)]
pub struct MerkleTreePrunerHandle {
    _aborted_sender: mpsc::Sender<()>,
    target_retained_version: Weak<AtomicU64>,
}

impl MerkleTreePrunerHandle {
    /// Sets the version of the tree the pruner should attempt to prune to. Calls should provide
    /// monotonically increasing versions; call with a lesser version will have no effect.
    ///
    /// Returns the previously set target retained version.
    ///
    /// # Errors
    ///
    /// If the pruner has stopped (e.g., due to a panic), this method will return an error.
    pub fn set_target_retained_version(&self, new_version: u64) -> Result<u64, PrunerStoppedError> {
        if let Some(version) = self.target_retained_version.upgrade() {
            Ok(version.fetch_max(new_version, Ordering::Relaxed))
        } else {
            Err(PrunerStoppedError(()))
        }
    }
}

/// Component responsible for Merkle tree pruning, i.e. removing nodes not referenced by new versions
/// of the tree.
///
/// A pruner should be instantiated using a [`Clone`] of the tree database, possibly
/// configured and then [`run()`](Self::run()) on its own thread. [`MerkleTreePrunerHandle`] provides
/// a way to gracefully shut down the pruner.
///
/// # Implementation details
///
/// Pruning works by recording stale node keys each time the Merkle tree is updated; in RocksDB,
/// stale keys are recorded in a separate column family. A pruner takes stale keys that were produced
/// by a certain range of tree versions, and removes the corresponding nodes from the tree
/// (in RocksDB, this uses simple pointwise `delete_cf()` operations). The range of versions
/// depends on pruning policies; for now, it's passed via the pruner handle.
pub struct MerkleTreePruner<DB> {
    db: DB,
    target_pruned_key_count: usize,
    poll_interval: Duration,
    aborted_receiver: mpsc::Receiver<()>,
    target_retained_version: Arc<AtomicU64>,
}

impl<DB> fmt::Debug for MerkleTreePruner<DB> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MerkleTreePruner")
            .field("target_pruned_key_count", &self.target_pruned_key_count)
            .field("poll_interval", &self.poll_interval)
            .field("target_retained_version", &self.target_retained_version)
            .finish_non_exhaustive()
    }
}

impl<DB: PruneDatabase> MerkleTreePruner<DB> {
    /// Creates a pruner with the specified database.
    ///
    /// # Return value
    ///
    /// Returns the created pruner and a handle to it. *The pruner will be aborted when its handle is dropped.*
    pub fn new(db: DB) -> (Self, MerkleTreePrunerHandle) {
        let (aborted_sender, aborted_receiver) = mpsc::channel();
        let target_retained_version = Arc::new(AtomicU64::new(0));
        let handle = MerkleTreePrunerHandle {
            _aborted_sender: aborted_sender,
            target_retained_version: Arc::downgrade(&target_retained_version),
        };
        let this = Self {
            db,
            target_pruned_key_count: 500_000,
            poll_interval: Duration::from_mins(1),
            aborted_receiver,
            target_retained_version,
        };
        (this, handle)
    }

    /// Sets the target number of stale keys pruned on a single iteration. This limits the size of
    /// a produced RocksDB `WriteBatch` and the RAM consumption of the pruner. At the same time,
    /// larger values can lead to more efficient RocksDB compaction.
    ///
    /// Reasonable values are order of 100k – 1M. The default value is 500k.
    pub fn set_target_pruned_key_count(&mut self, count: usize) {
        self.target_pruned_key_count = count;
    }

    /// Sets the sleep duration when the pruner cannot progress. This time should be enough
    /// for the tree to produce enough stale keys.
    ///
    /// The default value is 60 seconds.
    pub fn set_poll_interval(&mut self, poll_interval: Duration) {
        self.poll_interval = poll_interval;
    }

    /// Returns max version number that can be safely pruned, so that there is at least one version present after pruning.
    #[doc(hidden)] // Used in integration tests; logically private
    pub fn last_prunable_version(&self) -> Option<u64> {
        let manifest = self.db.manifest()?;
        manifest.version_count.checked_sub(1)
    }

    #[doc(hidden)] // Used in integration tests; logically private
    #[allow(clippy::range_plus_one)] // exclusive range is required by `PrunePatchSet` constructor
    pub fn prune_up_to(
        &mut self,
        target_retained_version: u64,
    ) -> anyhow::Result<Option<PruningStats>> {
        let Some(min_stale_key_version) = self.db.min_stale_key_version() else {
            return Ok(None);
        };

        // We must retain at least one tree version.
        let Some(last_prunable_version) = self.last_prunable_version() else {
            tracing::debug!("Nothing to prune; skipping");
            return Ok(None);
        };
        let target_retained_version = last_prunable_version.min(target_retained_version);
        let stale_key_new_versions = min_stale_key_version..=target_retained_version;
        if stale_key_new_versions.is_empty() {
            tracing::debug!(
                "No Merkle tree versions can be pruned; min stale key version is {min_stale_key_version}, \
                 target retained version is {target_retained_version}"
            );
            return Ok(None);
        }
        tracing::info!("Collecting stale keys with new versions in {stale_key_new_versions:?}");

        // let load_stale_keys_latency = PRUNING_TIMINGS.load_stale_keys.start();
        let mut pruned_keys = vec![];
        let mut max_stale_key_version = min_stale_key_version;
        for version in stale_key_new_versions {
            max_stale_key_version = version;
            pruned_keys.extend_from_slice(&self.db.stale_keys(version));
            if pruned_keys.len() >= self.target_pruned_key_count {
                break;
            }
        }
        // let load_stale_keys_latency = load_stale_keys_latency.observe();

        if pruned_keys.is_empty() {
            tracing::debug!("No stale keys to remove; skipping");
            return Ok(None);
        }
        let deleted_stale_key_versions = min_stale_key_version..(max_stale_key_version + 1);
        // tracing::info!(
        //     "Collected {} stale keys with new versions in {deleted_stale_key_versions:?} in {load_stale_keys_latency:?}",
        //     pruned_keys.len()
        // );

        let stats = PruningStats {
            target_retained_version,
            pruned_key_count: pruned_keys.len(),
            deleted_stale_key_versions: deleted_stale_key_versions.clone(),
        };
        let patch = PrunePatchSet::new(pruned_keys, deleted_stale_key_versions);
        // let apply_patch_latency = PRUNING_TIMINGS.apply_patch.start();
        self.db.prune(patch)?;
        // let apply_patch_latency = apply_patch_latency.observe();
        // tracing::info!("Pruned stale keys in {apply_patch_latency:?}: {stats:?}");
        Ok(Some(stats))
    }

    fn wait_for_abort(&mut self, timeout: Duration) -> bool {
        match self.aborted_receiver.recv_timeout(timeout) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The pruner handle is alive and wasn't used to abort the pruner.
                false
            }
        }
    }

    /// Runs this pruner indefinitely until it is aborted, or a database error occurs.
    ///
    /// # Errors
    ///
    /// Propagates database I/O errors.
    pub fn run(mut self) -> anyhow::Result<()> {
        tracing::info!("Started Merkle tree pruner {self:?}");

        let mut wait_interval = Duration::ZERO;
        while !self.wait_for_abort(wait_interval) {
            let retained_version = self.target_retained_version.load(Ordering::Relaxed);
            wait_interval = if let Some(stats) = self.prune_up_to(retained_version)? {
                tracing::debug!(
                    "Performed pruning for target retained version {retained_version}: {stats:?}"
                );
                // stats.report();
                if stats.has_more_work() {
                    // Continue pruning right away instead of waiting for abort.
                    Duration::ZERO
                } else {
                    self.poll_interval
                }
            } else {
                tracing::debug!(
                    "Pruning was not performed; waiting {:?}",
                    self.poll_interval
                );
                self.poll_interval
            };
        }
        tracing::info!("Stop request received, tree pruning is shut down");
        Ok(())
    }
}

impl PruningStats {
    fn has_more_work(&self) -> bool {
        self.target_retained_version + 1 > self.deleted_stale_key_versions.end
    }
}
