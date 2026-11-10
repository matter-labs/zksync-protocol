use std::convert::TryInto;

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zksync_crypto_primitives::hasher::blake2::Blake2Hasher;
use zksync_types::U256;

use crate::{
    hasher::{empty_subtree_prefix_len, HashTree},
    types::TREE_DEPTH,
};

const HASH_LEN: usize = 32;

/// Metadata emitted by the Merkle tree after processing a single storage log.
#[allow(missing_docs)]
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageLogMetadata {
    #[serde_as(as = "Bytes")]
    pub root_hash: [u8; HASH_LEN],
    pub is_write: bool,
    pub first_write: bool,
    #[serde_as(as = "Vec<Bytes>")]
    pub merkle_paths: Vec<[u8; HASH_LEN]>,
    pub leaf_hashed_key: U256,
    pub leaf_enumeration_index: u64,
    // **NB.** For compatibility reasons, `#[serde_as(as = "Bytes")]` attributes are not added below.
    pub value_written: [u8; HASH_LEN],
    pub value_read: [u8; HASH_LEN],
}

impl StorageLogMetadata {
    /// Returns `leaf_hashed_key` as a fixed-size little-endian byte array.
    pub fn leaf_hashed_key_array(&self) -> [u8; HASH_LEN] {
        let mut result = [0_u8; HASH_LEN];
        self.leaf_hashed_key.to_little_endian(&mut result);
        result
    }

    /// Converts Merkle paths into a fixed-size array.
    ///
    /// Call this on entries produced by
    /// [`WitnessInputMerklePaths::into_merkle_paths()`], which restores the full
    /// `TREE_DEPTH` form; the *stored* form of an entry is truncated to its own
    /// populated depth and will not match `PATH_LEN`.
    ///
    /// # Panics
    ///
    /// Panics if the stored Merkle path length differs from `PATH_LEN`.
    pub fn into_merkle_paths_array<const PATH_LEN: usize>(self) -> Box<[[u8; HASH_LEN]; PATH_LEN]> {
        let actual_len = self.merkle_paths.len();
        self.merkle_paths.try_into().unwrap_or_else(|_| {
            panic!(
                "Unexpected length of Merkle paths in `StorageLogMetadata`: expected {PATH_LEN}, got {actual_len}"
            );
        })
    }
}

/// Witness data produced by the Merkle tree after processing a single block.
///
/// # Stored path form
///
/// Each entry stores its path truncated to its own populated depth, omitting the
/// leading `empty_subtree_hash` run the fold regenerates for any path shorter than
/// [`TREE_DEPTH`]. [`Self::into_merkle_paths()`] restores the full form.
///
/// This replaces a scheme that padded to `TREE_DEPTH` and delta-compacted against
/// the **first** stored path, charging every entry `max(depth(first), depth(i))` —
/// so one leaf planted next to entry 0's key inflated the whole witness. The
/// per-path form has no cross-entry coupling and is never larger.
///
/// The two forms are not interchangeable, and the legacy one is self-describing only
/// through entry 0's stored length ([`Self::is_legacy_delta_form()`]). Convert it
/// with [`Self::normalize_stored_paths()`] before folding.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessInputMerklePaths {
    pub merkle_paths: Vec<StorageLogMetadata>,
    pub(crate) next_enumeration_index: u64,
}

impl WitnessInputMerklePaths {
    /// Creates a new witness with the specified leaf index and no paths.
    pub fn new(next_enumeration_index: u64) -> Self {
        Self {
            merkle_paths: vec![],
            next_enumeration_index,
        }
    }

    /// Returns the next leaf index at the beginning of the block.
    pub fn next_enumeration_index(&self) -> u64 {
        self.next_enumeration_index
    }

    /// Reserves additional capacity for Merkle paths.
    pub fn reserve(&mut self, additional_capacity: usize) {
        self.merkle_paths.reserve(additional_capacity);
    }

    /// Pushes a path, stored truncated to its own populated depth.
    ///
    /// Accepts either the tree's own truncated path or a `TREE_DEPTH`-padded one —
    /// the empty-subtree run is stripped either way, so the stored form is
    /// canonical and the call idempotent. Never inspects other entries, so no
    /// entry can inflate another's stored length.
    pub fn push_merkle_path(&mut self, mut path: StorageLogMetadata) {
        let empty_prefix = empty_subtree_prefix_len(&path.merkle_paths);
        if empty_prefix > 0 {
            path.merkle_paths.drain(..empty_prefix);
            path.merkle_paths.shrink_to_fit();
        }
        self.merkle_paths.push(path);
    }

    /// True iff entry 0 is stored at exactly [`TREE_DEPTH`]: the legacy encoder had
    /// nothing to delta it against and stored it padded, whereas reaching
    /// `TREE_DEPTH` in the per-path form needs entry 0's nearest neighbour to share
    /// 255 hashed-key bits with it.
    ///
    /// `==`, not `>=`: an over-long entry 0 is malformed, not legacy, and the
    /// consumer's `len <= TREE_DEPTH` bound owns that case.
    ///
    /// A *length* signal only: [`Self::normalize_stored_paths()`] additionally
    /// requires entry 0 to carry the padded shape (a leading empty-subtree run)
    /// before decoding against it, so a full-length but non-padded entry 0 fails
    /// closed there rather than being mis-interpreted as legacy here.
    pub fn is_legacy_delta_form(&self) -> bool {
        self.merkle_paths
            .first()
            .is_some_and(|first| first.merkle_paths.len() == TREE_DEPTH)
    }

    /// Rewrites every stored path to its own populated depth, decoding the legacy
    /// delta form first if that is what arrived. Returns `(reclaimed, restored)`:
    /// hashes dropped as empty-subtree padding, hashes spliced back from entry 0.
    /// Idempotent; the only place either wire form is interpreted.
    ///
    /// # Errors
    ///
    /// This is the single place the operator's stored-path encoding is interpreted,
    /// and — since it also *mutates* that encoding — the single place it is
    /// validated, before any transform runs. Fails closed on:
    ///
    /// * a stored path longer than [`TREE_DEPTH`] (occupies no defined levels and
    ///   would later abort the fold); or
    /// * a full-length entry 0 that is not the legacy *padded* form. The legacy
    ///   encoder padded entry 0 to `TREE_DEPTH`, so a genuine one has real depth
    ///   `< TREE_DEPTH` and thus a leading empty-subtree run; its absence means the
    ///   `== TREE_DEPTH` length was about to be trusted as "legacy" on a non-padded
    ///   shape. Necessary, not sufficient — the commitment fold remains the ultimate
    ///   arbiter; this just makes the mis-interpretation a clear error at the decode
    ///   point.
    ///
    /// # Why a trim is not enough
    ///
    /// The legacy encoder stored `padded_i[fui..]` with `fui` = the **common-prefix**
    /// length of `padded_i` and `padded_0`. That prefix is pure padding — trimmable,
    /// and foldable as-is — only while entries 0 and `i` sit at *different* sibling
    /// positions at index `fui`. If `k_0` and `k_i` share `>= depth(i)` leading bits,
    /// their ancestors coincide over the whole populated region, so
    /// `depth(0) == depth(i)` and the padded paths are equal element-wise; the first
    /// difference then comes from an intervening *write* mutating one shared sibling
    /// near the root, putting `fui` ABOVE `TREE_DEPTH - depth(i)`. The stripped
    /// prefix is real sibling hashes, which a trim cannot see and a fold would
    /// replace with `empty_subtree_hash`, missing the root.
    ///
    /// Hence the splice, from entry 0's *populated* part only. Every entry ends at
    /// `depth(i)` in both forms, so the memory win is unaffected: an entry inherits
    /// entry 0's depth only where the two are equal anyway.
    pub fn normalize_stored_paths(&mut self) -> anyhow::Result<(usize, usize)> {
        // Validate the wire form before interpreting or mutating it (see # Errors).
        // Over-long paths are rejected up front, before the splice or the VM runs.
        for log in &self.merkle_paths {
            anyhow::ensure!(
                log.merkle_paths.len() <= TREE_DEPTH,
                "Merkle path longer than TREE_DEPTH before normalisation: {} > {TREE_DEPTH}",
                log.merkle_paths.len(),
            );
        }

        let (mut reclaimed, mut restored) = (0, 0);

        if self.is_legacy_delta_form() {
            // Prefix source for every later entry, so read it before mutating
            // anything: one ~8 KiB clone, not one per entry.
            let prefix = self.merkle_paths[0].merkle_paths.clone();
            let populated_from = empty_subtree_prefix_len(&prefix);
            // Require the padded *shape*, not just the length, before splicing from
            // entry 0: a genuine legacy entry 0 has a non-empty empty-subtree prefix.
            // Its absence means this is not the padded form; fail closed (see # Errors).
            anyhow::ensure!(
                populated_from > 0,
                "entry 0 is stored at TREE_DEPTH but carries no empty-subtree padding, \
                 so it is not the legacy delta form; refusing to delta-decode against it",
            );
            for log in &mut self.merkle_paths[1..] {
                // `fui` follows from the stored length: the encoder cut `padded_i`,
                // always `TREE_DEPTH` long, at `fui`.
                let fui = TREE_DEPTH.saturating_sub(log.merkle_paths.len());
                if fui > populated_from {
                    log.merkle_paths
                        .splice(0..0, prefix[populated_from..fui].iter().copied());
                    restored += fui - populated_from;
                }
            }
        }

        for log in &mut self.merkle_paths {
            let empty_prefix = empty_subtree_prefix_len(&log.merkle_paths);
            if empty_prefix > 0 {
                log.merkle_paths.drain(..empty_prefix);
                reclaimed += empty_prefix;
            }
            // `drain` alone keeps the original allocation; the point is to hand the
            // memory back before the VM runs. Unconditional — the splice above may
            // have over-allocated too.
            log.merkle_paths.shrink_to_fit();
        }

        Ok((reclaimed, restored))
    }

    /// Expands every stored path to its full [`TREE_DEPTH`] form.
    ///
    /// Prefixes each with the canonical empty-subtree hashes for the levels it
    /// omits — the constants a fold would substitute. Expects the per-path form and
    /// does NOT decode the legacy delta form; run
    /// [`Self::normalize_stored_paths()`] first. Over-long paths pass through
    /// unchanged for the caller's length check to reject.
    pub fn into_merkle_paths(self) -> impl ExactSizeIterator<Item = StorageLogMetadata> {
        self.merkle_paths.into_iter().map(|mut log| {
            let missing = TREE_DEPTH.saturating_sub(log.merkle_paths.len());
            if missing > 0 {
                log.merkle_paths.splice(
                    0..0,
                    (0..missing).map(|depth| Blake2Hasher.empty_subtree_hash(depth).0),
                );
            }
            log
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(depth: usize) -> [u8; HASH_LEN] {
        Blake2Hasher.empty_subtree_hash(depth).0
    }

    /// A `TREE_DEPTH`-padded path whose populated (non-empty) depth is `d`, i.e.
    /// exactly what the tree + the old `domain.rs` padding produced.
    fn padded(d: usize, tag: u8) -> Vec<[u8; HASH_LEN]> {
        let mut path: Vec<_> = (0..TREE_DEPTH - d).map(empty).collect();
        // Sibling hashes of non-empty subtrees; `| 0x80` keeps them clear of the
        // empty constants (a match would be a blake2s collision).
        let mut byte = tag;
        path.extend(
            std::iter::repeat_with(|| {
                byte = byte.wrapping_add(37);
                [byte | 0x80; HASH_LEN]
            })
            .take(d),
        );
        path
    }

    fn meta(merkle_paths: Vec<[u8; HASH_LEN]>) -> StorageLogMetadata {
        StorageLogMetadata {
            root_hash: [0; HASH_LEN],
            is_write: false,
            first_write: false,
            merkle_paths,
            leaf_hashed_key: U256::zero(),
            leaf_enumeration_index: 0,
            value_written: [0; HASH_LEN],
            value_read: [0; HASH_LEN],
        }
    }

    /// Depths chosen so the first entry is *deeper* than the second — the shape
    /// the old delta format charged every later entry for.
    const DEPTHS: [usize; 4] = [24, 9, 40, 11];
    /// One distinct sibling-byte seed per entry, so no two paths collide.
    const TAGS: [u8; 4] = [17, 34, 51, 68];

    fn padded_paths() -> Vec<Vec<[u8; HASH_LEN]>> {
        DEPTHS
            .iter()
            .zip(TAGS)
            .map(|(&d, tag)| padded(d, tag))
            .collect()
    }

    #[test]
    fn stored_form_is_each_paths_own_depth() {
        let mut witness = WitnessInputMerklePaths::new(1);
        for path in padded_paths() {
            witness.push_merkle_path(meta(path));
        }

        let stored: Vec<_> = witness
            .merkle_paths
            .iter()
            .map(|m| m.merkle_paths.len())
            .collect();
        assert_eq!(stored, DEPTHS);
        // The old delta scheme would have stored `[TREE_DEPTH, 24, 40, 24]` here:
        // entry 0 uncompacted and every later entry floored at entry 0's depth.
        let legacy_total: usize =
            TREE_DEPTH + DEPTHS[1..].iter().map(|&d| d.max(DEPTHS[0])).sum::<usize>();
        assert!(stored.iter().sum::<usize>() < legacy_total);
    }

    #[test]
    fn into_merkle_paths_restores_the_padded_form() {
        let paths = padded_paths();
        let mut witness = WitnessInputMerklePaths::new(1);
        for path in paths.clone() {
            witness.push_merkle_path(meta(path));
        }

        let restored: Vec<_> = witness
            .into_merkle_paths()
            .map(|m| m.merkle_paths)
            .collect();
        assert_eq!(restored, paths);
    }

    /// The deleted encoder, verbatim: entry 0 uncompacted, every later entry cut at
    /// its **common-prefix boundary** with entry 0 (`Iterator::position`) — not at
    /// `max(depth_0, depth_i)`, which is only where that boundary lands for unrelated
    /// keys.
    fn legacy_form(paths: &[Vec<[u8; HASH_LEN]>]) -> WitnessInputMerklePaths {
        let mut legacy = WitnessInputMerklePaths::new(1);
        legacy.merkle_paths.push(meta(paths[0].clone()));
        for path in &paths[1..] {
            let fui = path
                .iter()
                .zip(&paths[0])
                .position(|(h, h0)| h != h0)
                .unwrap_or(TREE_DEPTH);
            legacy.merkle_paths.push(meta(path[fui..].to_vec()));
        }
        legacy
    }

    /// The load-bearing compatibility property: a witness serialised in the legacy
    /// delta form normalises to exactly the per-path form, hence expands to exactly
    /// the same full paths — so one reader serves both wire forms.
    #[test]
    fn normalize_decodes_the_legacy_delta_form() {
        let paths = padded_paths();
        let mut legacy = legacy_form(&paths);
        assert!(legacy.is_legacy_delta_form());
        legacy.normalize_stored_paths().unwrap();

        let restored: Vec<_> = legacy.into_merkle_paths().map(|m| m.merkle_paths).collect();
        assert_eq!(restored, paths);
    }

    /// The shape a trim cannot decode: entry `i` shares a **populated** prefix with
    /// entry 0, so the delta boundary lands inside real sibling hashes. Reachable
    /// whenever two hashed keys agree on `>= depth` leading bits — the tree then gives
    /// them equal depths and identical siblings, and only an intervening write
    /// separates the paths.
    ///
    /// Entries 0 and 1 here share every populated hash but the topmost, so
    /// `fui = TREE_DEPTH - 1` against a true depth of `DEPTH`: the delta strips
    /// `DEPTH - 1` real hashes, and a trim would leave the path 1 hash long.
    #[test]
    fn normalize_restores_real_hashes_the_delta_stripped() {
        const DEPTH: usize = 12;
        let shared = padded(DEPTH, 200);
        // Same populated depth, differing only in the hash at the top level — what a
        // write to some third leaf near the root does to an otherwise identical path.
        let mut mutated = shared.clone();
        mutated[TREE_DEPTH - 1] = [0xC3; HASH_LEN];
        let paths = vec![shared, mutated];

        let mut legacy = legacy_form(&paths);
        assert_eq!(
            legacy.merkle_paths[1].merkle_paths.len(),
            1,
            "the delta must have stripped into the populated region for this to bite"
        );
        assert_eq!(
            empty_subtree_prefix_len(&legacy.merkle_paths[1].merkle_paths),
            0,
            "a trim cannot see the stripped hashes — they are not empty constants"
        );

        assert_eq!(
            legacy.normalize_stored_paths().unwrap(),
            (TREE_DEPTH - DEPTH, DEPTH - 1)
        );
        let stored: Vec<usize> = legacy
            .merkle_paths
            .iter()
            .map(|m| m.merkle_paths.len())
            .collect();
        assert_eq!(stored, [DEPTH, DEPTH], "both entries keep their own depth");
        assert_eq!(
            legacy
                .into_merkle_paths()
                .map(|m| m.merkle_paths)
                .collect::<Vec<_>>(),
            paths
        );
    }

    #[test]
    fn normalize_reclaims_the_legacy_padding_and_is_idempotent() {
        let paths = padded_paths();
        // The real legacy shape: entry 0 padded to TREE_DEPTH, every later entry
        // cut to `max(depth_0, depth_i)` — i.e. *partially* stripped, so the
        // surplus sits at depths `TREE_DEPTH - stored_len ..`, not at depth 0.
        let mut legacy = WitnessInputMerklePaths::new(1);
        legacy.merkle_paths.push(meta(paths[0].clone()));
        let mut surplus = TREE_DEPTH - DEPTHS[0];
        for (path, &depth) in paths.iter().zip(&DEPTHS).skip(1) {
            let stored_len = depth.max(DEPTHS[0]);
            surplus += stored_len - depth;
            legacy
                .merkle_paths
                .push(meta(path[TREE_DEPTH - stored_len..].to_vec()));
        }

        assert!(legacy.is_legacy_delta_form());
        // These depths are all distinct, so every entry is delta'd strictly inside
        // entry 0's empty run: nothing to splice back, pure reclaim.
        assert_eq!(legacy.normalize_stored_paths().unwrap(), (surplus, 0));
        // The point is to give the memory BACK, not just to shorten `len`: `drain`
        // alone leaves the original allocation intact. Assert the capacity actually
        // shrank, or a dropped `shrink_to_fit` would silently turn this into a no-op
        // with every test still green.
        for log in &legacy.merkle_paths {
            assert_eq!(
                log.merkle_paths.capacity(),
                log.merkle_paths.len(),
                "normalising must release the surplus allocation, not just shorten len"
            );
        }
        let stored: Vec<_> = legacy
            .merkle_paths
            .iter()
            .map(|m| m.merkle_paths.len())
            .collect();
        assert_eq!(stored, DEPTHS);
        // Idempotent, and it did not lose information: the full form still comes back.
        let mut again = legacy.clone();
        assert_eq!(again.normalize_stored_paths().unwrap(), (0, 0));
        assert_eq!(
            legacy
                .into_merkle_paths()
                .map(|m| m.merkle_paths)
                .collect::<Vec<_>>(),
            paths
        );
    }

    /// An over-long path is passed through untouched for the caller's length
    /// bound to reject, rather than panicking or silently truncating.
    #[test]
    fn over_long_paths_are_passed_through() {
        let long = vec![[0xAB; HASH_LEN]; TREE_DEPTH + 5];
        let mut witness = WitnessInputMerklePaths::new(1);
        witness.merkle_paths.push(meta(long.clone()));
        let restored: Vec<_> = witness
            .into_merkle_paths()
            .map(|m| m.merkle_paths)
            .collect();
        assert_eq!(restored, vec![long]);
    }

    /// An over-long stored path is rejected up front, before any mutation.
    #[test]
    fn normalize_rejects_an_over_long_path() {
        let mut witness = WitnessInputMerklePaths::new(1);
        witness.merkle_paths.push(meta(padded(5, 11)));
        witness
            .merkle_paths
            .push(meta(vec![[0xAB; HASH_LEN]; TREE_DEPTH + 1]));
        let err = witness
            .normalize_stored_paths()
            .expect_err("an over-long path must be rejected before normalisation");
        assert!(
            err.to_string().contains("longer than TREE_DEPTH"),
            "unexpected error: {err}"
        );
    }

    /// A full-length entry 0 with no empty-subtree padding (real depth TREE_DEPTH —
    /// a 255-bit key collision, unreachable for a genuine witness) is not the legacy
    /// form and must fail closed rather than be delta-decoded against.
    #[test]
    fn normalize_rejects_a_full_length_entry_0_without_padding() {
        let mut witness = WitnessInputMerklePaths::new(1);
        // Full-length AND fully non-empty ⇒ `is_legacy_delta_form()` fires but the
        // padding prefix is empty.
        witness
            .merkle_paths
            .push(meta(vec![[0xAB; HASH_LEN]; TREE_DEPTH]));
        witness.merkle_paths.push(meta(vec![]));
        assert!(witness.is_legacy_delta_form());
        assert_eq!(
            empty_subtree_prefix_len(&witness.merkle_paths[0].merkle_paths),
            0
        );
        let err = witness
            .normalize_stored_paths()
            .expect_err("a full-length entry 0 without padding is not the legacy form");
        assert!(
            err.to_string().contains("not the legacy delta form"),
            "unexpected error: {err}"
        );
    }
}
