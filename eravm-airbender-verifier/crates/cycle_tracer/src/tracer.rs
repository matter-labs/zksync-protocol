use std::sync::{Arc, Mutex};

use zksync_era_airbender_cycles_estimator::{FeatureId, FeatureVector};
use zksync_vm2::interface::{
    CycleStats, GlobalStateInterface, Opcode, OpcodeType, ShouldStop, Tracer,
};

/// Passive vm2 tracer that counts calibration features into a shared recorder.
///
/// Modeled on `crates/multivm/src/versions/vm_fast/tracers/circuits.rs`, but
/// emits RAW counts (the per-feature cycle weights are learned by the offline
/// fit, never baked in here). Every hook only observes — it returns
/// [`ShouldStop::Continue`] and mutates no VM state — so a batch executed with
/// this tracer runs identically to the proved guest.
///
/// Cloning shares one recorder: clone the tracer per transaction (matching how
/// the fast VM's tuple `TracerDispatcher` is fed) and all counts accumulate into
/// the same [`FeatureVector`].
///
/// # If you are porting the OTHER producer, read this first
///
/// zksync-era has its own legacy-VM tracer filling the same vector
/// (`core/lib/multivm/src/tracers/cycle_estimator/vm_latest/mod.rs`), and it currently
/// maps `Add`/`Sub`/`Mul`/`Div`/`Jump`/`Binop`/`Shift`/`Ptr` into a single
/// `RichAddressingOp` arm. This schema has no such feature: those opcodes measure 145 to
/// 15,474 cycles apiece, so they are five separate axes and the port has to split that arm
/// the way the `match` below does. `DecommitRepeat` likewise has to be derived, from the
/// absence of a fresh-decommit stat.
///
/// Getting it wrong is quiet. Every trust signal in the estimator keys on `count > 0`, so
/// an axis a producer never fills is indistinguishable from an axis the batch never used:
/// renaming the lumped arm to `ArithCheapOp` compiles, and then a batch of 4.6M divisions
/// the correct mapping puts at 1.06x of the proving ceiling is priced at 0.028x of it —
/// 37x under, trusted. The one case that is detectable — a large `arith_cheap_op` with all
/// four dearer arithmetic axes at zero — is caught by `CostTable::producer_gap`; nothing
/// catches the general case, so re-measure a batch through both producers after any change
/// here.
#[derive(Debug, Clone, Default)]
pub struct CycleFeatureTracer {
    recorder: Arc<Mutex<FeatureVector>>,
    /// Set when the instruction currently executing emitted
    /// `CycleStats::Decommit`, which vm2 does only for a FRESH decommit. Read in
    /// `after_instruction` to tell a fresh decommit from a repeat.
    ///
    /// **It must be cleared after every instruction, not just after a DECOMMIT.**
    /// vm2 emits that stat from two sites: `WorldDiff::decommit_opcode`, behind the
    /// DECOMMIT opcode, and `WorldDiff::pay_for_decommit`, behind *every far call*.
    /// A far call that freshly decommits its callee therefore sets this flag too, and
    /// clearing it only inside the DECOMMIT arm let it survive until the next DECOMMIT
    /// opcode — which then read a far call's flag as its own and scored a repeat as
    /// fresh. That is the unsafe direction: it silently under-counts the one feature
    /// whose whole purpose is to price an attacker's dead work.
    ///
    /// This is the only state the tracer keeps, and it is per-clone rather than
    /// shared: `on_extra_prover_cycles` and `after_instruction` for one instruction
    /// always run on the same tracer instance, so a shared flag would let
    /// concurrent clones clear each other's.
    fresh_decommit_seen: bool,
}

impl CycleFeatureTracer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume the fresh-decommit flag for the instruction that just finished.
    ///
    /// Factored out only so the sequencing can be unit-tested: vm2's `DummyState` is
    /// `pub(crate)`, and hand-rolling a `StateInterface` to drive `after_instruction`
    /// would be far more test than subject. The property that actually matters —
    /// that this is called for EVERY opcode rather than only for DECOMMIT — is
    /// structural, enforced by the single unconditional call at the top of
    /// `after_instruction`.
    fn take_fresh_decommit(&mut self) -> bool {
        std::mem::take(&mut self.fresh_decommit_seen)
    }

    /// Handle to the shared recorder, for callers that want to read counts
    /// after driving the VM through a clone of this tracer.
    pub fn recorder(&self) -> Arc<Mutex<FeatureVector>> {
        Arc::clone(&self.recorder)
    }

    /// Snapshot the accumulated feature counts.
    pub fn snapshot(&self) -> FeatureVector {
        self.recorder.lock().unwrap().clone()
    }

    fn bump(&self, id: FeatureId, n: u64) {
        self.recorder.lock().unwrap().add(id, n);
    }
}

impl Tracer for CycleFeatureTracer {
    fn after_instruction<OP: OpcodeType, S: GlobalStateInterface>(
        &mut self,
        _state: &mut S,
    ) -> ShouldStop {
        // Opcode → feature-family mapping mirrors `circuits.rs`'s bucketing so
        // the offline categories line up with the sequencer's existing model.
        // Take the flag for THIS instruction and clear it unconditionally, so a far
        // call's fresh decommit cannot be mistaken for a later DECOMMIT's.
        let fresh_decommit = self.take_fresh_decommit();
        let id = match OP::VALUE {
            // The arithmetic bucket is split by MEASURED cost class, not by opcode
            // taxonomy: isolated measurement put `add` at 137, `mul` at 734 and
            // `div` at 7,515 effective cycles per op, so opcodes share a feature
            // only when they cost about the same. Adding a new arithmetic opcode
            // here means deciding which class it measures into — do not default it
            // to the cheap one.
            Opcode::Nop
            | Opcode::Add
            | Opcode::Sub
            | Opcode::Jump
            | Opcode::Xor
            | Opcode::And
            | Opcode::Or => FeatureId::ArithCheapOp,
            Opcode::ShiftLeft | Opcode::ShiftRight | Opcode::RotateLeft | Opcode::RotateRight => {
                FeatureId::ArithShiftOp
            }
            Opcode::Mul => FeatureId::ArithMulOp,
            Opcode::Div => FeatureId::ArithDivOp,
            Opcode::PointerAdd
            | Opcode::PointerSub
            | Opcode::PointerPack
            | Opcode::PointerShrink => FeatureId::ArithPtrOp,
            Opcode::This
            | Opcode::Caller
            | Opcode::CodeAddress
            | Opcode::ContextMeta
            | Opcode::ErgsLeft
            | Opcode::SP
            | Opcode::ContextU128
            | Opcode::SetContextU128
            | Opcode::AuxMutating0
            | Opcode::IncrementTxNumber
            | Opcode::Ret(_) => FeatureId::AverageOp,
            // Deliberately counted TWICE: once into `average_op` (it pays the same
            // dispatch as any context op) and once into `near_call_count` (the
            // frame push/pop on top of that). The two rates are therefore
            // additive — a near call costs `average_op + near_call_count`,
            // 107 + 926 = 1,033 on the committed table — and `near_call_count`
            // was MEASURED against this same double-count, so there is no
            // train/serve skew. Do not "fix" this by making the mapping
            // exclusive without re-measuring: that silently reprices every near
            // call by the `average_op` rate.
            Opcode::NearCall => {
                self.bump(FeatureId::NearCallCount, 1);
                FeatureId::AverageOp
            }
            Opcode::StorageRead => FeatureId::StorageRead,
            Opcode::StorageWrite => FeatureId::StorageWrite,
            Opcode::TransientStorageRead => FeatureId::TransientStorageRead,
            Opcode::TransientStorageWrite => FeatureId::TransientStorageWrite,
            Opcode::L2ToL1Message | Opcode::Event => FeatureId::Event,
            Opcode::PrecompileCall => FeatureId::PrecompileCall,
            Opcode::Decommit => {
                // `on_extra_prover_cycles` runs inside the opcode handler, so by now
                // the flag reflects this instruction: no stat means this DECOMMIT
                // repeated a hash already decommitted in this run.
                if !fresh_decommit {
                    self.bump(FeatureId::DecommitRepeat, 1);
                }
                FeatureId::Decommit
            }
            Opcode::FarCall(_) => FeatureId::FarCall,
            Opcode::AuxHeapWrite | Opcode::HeapWrite | Opcode::StaticMemoryWrite => {
                FeatureId::UmaWrite
            }
            Opcode::AuxHeapRead
            | Opcode::HeapRead
            | Opcode::PointerRead
            | Opcode::StaticMemoryRead => FeatureId::UmaRead,
        };
        self.bump(id, 1);
        ShouldStop::Continue
    }

    fn on_extra_prover_cycles(&mut self, stats: CycleStats) {
        // Same categories as `circuits.rs::on_extra_prover_cycles`; the payload
        // is the operation's complexity (hashing rounds / circuit cycles), which
        // we keep as the crypto size feature rather than a plain call count.
        match stats {
            CycleStats::Keccak256(c) => self.bump(FeatureId::Keccak256Cycles, c as u64),
            CycleStats::Sha256(c) => self.bump(FeatureId::Sha256Cycles, c as u64),
            CycleStats::EcRecover(c) => self.bump(FeatureId::EcRecoverCycles, c as u64),
            CycleStats::Secp256r1Verify(c) => self.bump(FeatureId::Secp256r1VerifyCycles, c as u64),
            CycleStats::Decommit(c) => {
                self.fresh_decommit_seen = true;
                self.bump(FeatureId::DecommitCycles, c as u64)
            }
            CycleStats::StorageRead => self.bump(FeatureId::StorageApplication, 1),
            CycleStats::StorageWrite => self.bump(FeatureId::StorageApplication, 2),
            CycleStats::EcAdd(c) => self.bump(FeatureId::EcAddCycles, c as u64),
            CycleStats::ModExp(c) => self.bump(FeatureId::ModExpCycles, c as u64),
            CycleStats::EcMul(c) => self.bump(FeatureId::EcMulCycles, c as u64),
            CycleStats::EcPairing(c) => self.bump(FeatureId::EcPairingCycles, c as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_recorder() {
        let t1 = CycleFeatureTracer::new();
        let t2 = t1.clone();
        t1.bump(FeatureId::FarCall, 2);
        t2.bump(FeatureId::FarCall, 3);
        assert_eq!(t1.snapshot().get(FeatureId::FarCall), 5);
    }

    /// A fresh decommit belongs to the instruction that caused it, and to no other.
    ///
    /// vm2 emits `CycleStats::Decommit` from two sites — `decommit_opcode`, behind the
    /// DECOMMIT opcode, and `pay_for_decommit`, behind *every far call*. When this
    /// flag was cleared only inside the DECOMMIT arm, a far call's fresh decommit
    /// survived until the next DECOMMIT opcode, which read it as its own and scored a
    /// repeat as fresh. That under-counts `decommit_repeat`, and under-counting is the
    /// unsafe direction for the one feature whose purpose is to price dead work an
    /// attacker pays nothing for.
    ///
    /// The empirical check on this lives in the isolation corpus rather than here:
    /// batches 900208/900212/900216 report n or n-1 repeats out of n DECOMMITs (the
    /// missing one being the far call that first decommitted the target), and their
    /// per-repeat slopes reproduce vm2 PR #130's independently measured
    /// 83,583 + 2.3435/byte to three significant figures.
    #[test]
    fn a_far_calls_fresh_decommit_does_not_leak_to_the_next_instruction() {
        let mut t = CycleFeatureTracer::new();

        // The far call decommits its callee for the first time.
        t.on_extra_prover_cycles(CycleStats::Decommit(223));
        assert!(
            t.take_fresh_decommit(),
            "the instruction that caused the decommit must see it as fresh"
        );

        // The DECOMMIT opcode that follows caused no decommit of its own, so it must
        // NOT inherit the far call's. This is the assertion the bug failed.
        assert!(
            !t.take_fresh_decommit(),
            "a later instruction inherited an earlier one's fresh-decommit flag, so a \
             repeat would be scored as fresh and priced at zero"
        );
    }

    /// And the flag survives no longer than one instruction even when nothing reads it
    /// as fresh — two decommit stats in a row are two fresh decommits, not one.
    #[test]
    fn each_fresh_decommit_is_counted_once() {
        let mut t = CycleFeatureTracer::new();
        for _ in 0..3 {
            t.on_extra_prover_cycles(CycleStats::Decommit(64));
            assert!(t.take_fresh_decommit());
        }
        assert_eq!(
            t.snapshot().get(FeatureId::DecommitCycles),
            192,
            "the per-unit fresh cost must accumulate across instructions"
        );
    }
}
