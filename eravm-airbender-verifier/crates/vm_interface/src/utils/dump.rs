//! Trimmed-down mirror of `zksync-era/core/lib/vm_interface/src/utils/dump.rs`.
//!
//! Upstream this file holds `VmDump` plus internal helpers for re-running the
//! VM on a captured input. We keep just the pieces our verifier consumes.

use zksync_types::H256;

/// Compresses a value + enum index into an `Option<_>` so that it's more
/// efficiently serializable.
pub fn compress_value_and_index(value: H256, enum_index: Option<u64>) -> Option<(H256, u64)> {
    match (value, enum_index) {
        (value, Some(idx)) => Some((value, idx)),
        (value, None) if value.is_zero() => None,
        // There may be non-zero values w/o an assigned enum index if the VM
        // execution starts in the middle of an L1 batch. We mark such values
        // with an enum index 0, which is not a legal value.
        (value, None) => Some((value, 0)),
    }
}
