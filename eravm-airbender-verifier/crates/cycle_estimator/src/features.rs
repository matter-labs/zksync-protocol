use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Stable, ordered identifier for one calibration feature (a model INPUT —
/// something the sequencer can compute natively from a vm2 trace).
///
/// Opcode-family variants mirror the buckets in
/// `crates/multivm/src/versions/vm_fast/tracers/circuits.rs`; crypto/size
/// variants add Airbender-relevant dimensions that tracer omits.
#[derive(
    strum::EnumIter,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FeatureId {
    // vm2 opcode-family counts (from `after_instruction`)
    // Arithmetic bucket, split by MEASURED cost class (2026-08-21). Grouping is by
    // isolated per-op cost, not by opcode taxonomy: two opcodes share a feature
    // only if they cost about the same.
    /// Single-word ALU and control flow: `Nop`/`Add`/`Sub`/`Jump`/`Xor`/`And`/`Or`.
    ArithCheapOp,
    /// `ShiftLeft`/`ShiftRight`/`RotateLeft`/`RotateRight`.
    ArithShiftOp,
    /// `Mul` — 256x256 -> 512, materially dearer than the cheap class.
    ArithMulOp,
    /// `Div` — 512/256 long division, the most expensive opcode in the VM per erg
    /// and the reason this split exists.
    ArithDivOp,
    /// Fat-pointer arithmetic: `PointerAdd`/`PointerSub`/`PointerPack`/`PointerShrink`.
    ArithPtrOp,
    AverageOp,
    StorageRead,
    StorageWrite,
    TransientStorageRead,
    TransientStorageWrite,
    Event,
    PrecompileCall,
    /// DECOMMIT opcode executions, fresh and repeat together. Only the repeat
    /// count is priced by this feature — see [`FeatureId::DecommitCycles`], which
    /// exists so the two can be separated. A fresh decommit's real cost is O(len)
    /// and is priced by [`FeatureId::DecommitCycles`]; a repeat does O(len) work
    /// that no counter reports, so it can only be BOUNDED, and bounding the
    /// combined count taxed every fresh decommit for the sins of the repeats.
    Decommit,
    /// REPEAT decommits — a DECOMMIT opcode for a hash already decommitted in this
    /// VM run. Counted by observing that vm2 emits `CycleStats::Decommit` only when
    /// a decommit is FRESH, so a DECOMMIT instruction that produced no such stat
    /// was a repeat.
    ///
    /// It has its own feature because the two halves of `Decommit` have completely
    /// different cost structure. A fresh decommit's cost is O(len) and is priced
    /// exactly, per 64 bytes, by [`FeatureId::DecommitCycles`]. A repeat does O(len)
    /// work that no counter reports — the ergs are even refunded — so it can only be
    /// BOUNDED, and bounding the combined count charged every fresh decommit at the
    /// worst-case repeat price, over-predicting a small-contract batch elevenfold.
    DecommitRepeat,
    FarCall,
    UmaWrite,
    UmaRead,
    // crypto complexity (from `on_extra_prover_cycles`, value = cycles/rounds)
    Keccak256Cycles,
    Sha256Cycles,
    EcRecoverCycles,
    Secp256r1VerifyCycles,
    ModExpCycles,
    EcAddCycles,
    EcMulCycles,
    EcPairingCycles,
    DecommitCycles,
    StorageApplication,
    // batch-level features
    TransactionCount,
    NearCallCount,
    PubdataBytes,
    MerkleLeafCount,
    StateDiffCount,
}

pub const VM_TRACE_FEATURES: &[FeatureId] = &[
    FeatureId::ArithCheapOp,
    FeatureId::ArithShiftOp,
    FeatureId::ArithMulOp,
    FeatureId::ArithDivOp,
    FeatureId::ArithPtrOp,
    FeatureId::AverageOp,
    FeatureId::StorageRead,
    FeatureId::StorageWrite,
    FeatureId::Event,
    FeatureId::PrecompileCall,
    FeatureId::Decommit,
    FeatureId::FarCall,
    FeatureId::UmaWrite,
    FeatureId::UmaRead,
];

/// A calibration feature vector: model INPUTS only (no measured cycles).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureVector {
    pub counts: BTreeMap<FeatureId, u64>,
}

impl FeatureVector {
    /// Accumulate `n` occurrences of `id`.
    pub fn add(&mut self, id: FeatureId, n: u64) {
        *self.counts.entry(id).or_insert(0) += n;
    }

    /// Current count for `id` (0 if never added).
    pub fn get(&self, id: FeatureId) -> u64 {
        self.counts.get(&id).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_accumulates_and_get_defaults_zero() {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::StorageRead, 3);
        fv.add(FeatureId::StorageRead, 4);
        assert_eq!(fv.get(FeatureId::StorageRead), 7);
        assert_eq!(fv.get(FeatureId::FarCall), 0);
    }

    #[test]
    fn json_roundtrip_is_stable() {
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::Keccak256Cycles, 42);
        let json = serde_json::to_string(&fv).unwrap();
        let back: FeatureVector = serde_json::from_str(&json).unwrap();
        assert_eq!(fv, back);
        assert!(json.contains("keccak256_cycles"));
    }
}
