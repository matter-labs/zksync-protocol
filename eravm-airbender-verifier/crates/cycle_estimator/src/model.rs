//! The cost table and cycle prediction.
//!
//! # This is a cost table, not a regression
//!
//! An estimate is `base + Σ rate(op) · count(op)` — arithmetic over per-operation
//! rates that were *measured*, one operation at a time, on synthetic batches that
//! isolate it. It is deliberately not a fit over whole batches, and the reason is
//! structural rather than stylistic: in real traffic every feature moves with every
//! other, so the design matrix is near-singular (`far_call` had multiple R² =
//! 0.999988 against the rest) and no quantity of additional organic data identifies
//! a per-operation rate. Batch-level fitting produced a table that was accurate in
//! total and wrong on every axis an attacker can isolate — one arithmetic
//! coefficient covering opcodes measured 67× apart, from `jump` at 102 cycles per
//! op to `div` at 7,711.
//!
//! So the model is linear in counts, which is the physics rather than an assumption
//! — guest work genuinely is a sum over executed operations — and every rate comes
//! from a designed experiment. What remains of statistics is one number, the base,
//! and even that is measured: it is what a near-empty batch costs.
//!
//! # Input-dependent costs live in the choice of unit
//!
//! Several operations cost more for larger inputs, and that needs no non-linear
//! machinery: **price a unit the cost is linear in.** `keccak256` and `sha256` are
//! priced per *round*, `ec_pairing` per *pair*, `decommit_cycles` per *64 bytes* —
//! and in each case vm2's `CycleStats` payload already reports that unit, so the
//! estimate is exact rather than bounded.
//!
//! Where the payload reports only a call count, no input-dependent rate can be
//! deployed however good the model is, because the sequencer cannot supply the
//! parameter. Those entries are [`Provenance::Bounded`] at the worst input instead.
//! That is a limit of the observable interface, not of the model class, and it is
//! the ceiling on how accurate this crate can become.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

use crate::estimator::CycleEstimate;
use strum::IntoEnumIterator;

use crate::features::{FeatureId, FeatureVector, VM_TRACE_FEATURES};

/// Airbender's hard cycle ceiling: `MAX_NUMBER_OF_CYCLES`, from
/// `zksync-airbender` `cs/src/definitions/constants.rs`, where it is derived from the RAM
/// timestamp column width. A batch beyond it cannot be proved.
///
/// Exported because the consumer's own budget must be DERIVED from this, not configured
/// independently — and independently is how it is configured today. era's
/// `max_cycles_per_batch` defaults to 1e15, which is **14,552x this value**, so the gate
/// can never fire; one sample config uses 5e8, which is below the per-batch base and would
/// seal every batch immediately. Neither is the ceiling, and nothing in the tree told the
/// operator what the ceiling was.
///
/// It bounds MAIN-TRACE cycles, i.e. [`CostTable::predict_raw`]. Comparing
/// [`CostTable::predict`] (effective) against it is strictly more conservative, since
/// `effective >= raw` always.
pub const PROVING_CYCLE_CEILING: u64 = 1 << 36;

/// The committed cost table, embedded at compile time so a deployed sequencer needs
/// no model file on disk.
pub const EMBEDDED_COST_TABLE: &str = include_str!("../model/cost_table.json");

/// Slack on a calibrated domain before a count counts as extrapolation. A domain is
/// the largest count an entry was measured over — a sample, not a bound — so it
/// needs headroom for legitimately larger batches.
///
/// Public because it is part of the trip point, not an implementation detail: the largest
/// count an axis is trusted at is `domain_max * DOMAIN_SLACK`, and both
/// `scripts/cycle_model/build_cost_table.py` and `tests/gate_reachability.rs` have to
/// compute it. It was duplicated by hand in the script before this.
pub const DOMAIN_SLACK: f64 = 1.8;

/// Axis groups where an all-zero sibling set is a PRODUCER signature rather than a batch
/// shape — see [`CostTable::producer_gap`].
///
/// Each entry is `(heavy axis, siblings a real execution always accompanies it with,
/// count above which their joint absence is not credible)`. The threshold is what keeps
/// this from being a heuristic: across the 52-batch organic corpus every one of the five
/// arithmetic axes is non-zero in every batch, at 64 to 179 cheap ops per division, so a
/// batch retiring a million cheap ops has never had fewer than ~5,600 divisions. One
/// million with *none* is not a shape, it is a producer that folded the classes together.
///
/// Deliberately NOT extended to `decommit`/`decommit_repeat`, though losing
/// `decommit_repeat` in a port is the more expensive mistake (2.01e6 cycles per unit).
/// A batch whose every DECOMMIT is fresh is a legitimate shape — `decommit_fresh_4blobs`
/// in the adversarial fixture is exactly that — so a zero there would distrust real
/// batches. Nothing in the trace separates that from a missing producer.
const PRODUCER_COVERAGE: &[(FeatureId, &[FeatureId], u64)] = &[(
    FeatureId::ArithCheapOp,
    &[
        FeatureId::ArithShiftOp,
        FeatureId::ArithMulOp,
        FeatureId::ArithDivOp,
        FeatureId::ArithPtrOp,
    ],
    1_000_000,
)];

/// Where a rate came from. Two kinds, and deliberately no third.
///
/// An earlier version had a `Fitted` variant for rates inferred by regressing whole
/// batches. A batch-level fit cannot identify a per-operation rate — in real traffic every
/// feature moves with every other — so what it produces is not a weaker measurement but a
/// fabrication with a plausible magnitude, and it failed in both directions: six axes at
/// exactly 0 and `sha256_cycles` at 114,364 cycles/round, all predicting the corpus well.
/// An axis with no measurement is therefore ABSENT, because an absence is detectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Measured on an isolated single-axis batch, in the unit the cost is linear
    /// in. Trustworthy for a gate decision.
    Measured,
    /// A deliberate upper bound, where the cost-determining input is not observable
    /// to the tracer or the cost varies with operands. Trustworthy for a gate
    /// decision *because* it over-estimates; costs throughput, never safety.
    Bounded,
}

/// One priced operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostEntry {
    /// Effective cycles per unit of the feature — the quantity the gate compares
    /// against the 2^36 proving ceiling.
    pub cycles_per_unit: f64,
    /// RAW main-trace cycles per unit, excluding delegation-circuit cost.
    ///
    /// `effective = raw + 16*blake2 + 4*bigint + 4*keccak`, and those weights have no
    /// authoritative source in this tree, so accuracy measured against `effective` is
    /// partly a statement about an unsourced constant. `raw` is what the prover reports
    /// directly. The delegation share differs sharply by axis, so a weight revision
    /// re-ranks the table rather than scaling it.
    #[serde(default)]
    pub raw_cycles_per_unit: f64,
    pub kind: Provenance,
    /// Largest count this entry was calibrated over. `None` means uncalibrated, and
    /// is treated as extrapolating on any non-zero count — so a new entry fails
    /// loud rather than silently claiming coverage it has not got.
    #[serde(default)]
    pub domain_max: Option<u64>,
}

impl CostEntry {
    /// Whether `count` is outside the range this entry was calibrated over.
    ///
    /// The absent-domain case splits on provenance, and getting it wrong fails CLOSED: a
    /// `Bounded` entry carries no domain, so treating a missing domain as "no coverage" for
    /// every entry declared `arith_div_op` out-of-domain on the smallest batch in the
    /// corpus — a gate that declines everything while looking healthy. A bound holds
    /// outside the range it was taken over; a `Measured` entry with no domain is a number
    /// with no stated evidence, so any use of it is extrapolation.
    ///
    /// # What that makes the domain-free `Bounded` case, deliberately
    ///
    /// `Bounded` axes carry no domain, so they never extrapolate, so they are the ONLY
    /// axes that can carry an estimate into a consumer's magnitude branch while the
    /// estimate is still trusted. Every domain-carrying axis trips its domain first:
    /// driving all of them at once to `1.8 x domain_max` reaches 0.61 of the ceiling
    /// (0.79 after the table's margin), below the 0.95 at which the deployed consumer
    /// closes a batch. `gate_reachability.rs` asserts it, so the claim is checked rather
    /// than stated.
    ///
    /// Two consequences, both intended, and neither of them free:
    ///
    /// 1. **The domain guard is the effective seal condition** for measured axes. A flood
    ///    on one of them is answered by distrust, not by magnitude, and the deployed
    ///    consumer answers distrust with `IncludeAndSeal` — so the configured cycle budget
    ///    only ever fires through a `Bounded` axis. That is the honest description of the
    ///    gate, not an accident of the numbers.
    /// 2. **A bound is sound to seal on and lossy to refuse on.** `conservative()` is an
    ///    over-estimate by construction, which is exactly right when the answer is "seal
    ///    early" and costs throughput when the answer is "refuse this transaction".
    ///    `arith_div_op` is the live case: 15,474 is the worst operand shape, the cheapest
    ///    measured shape is 1,162 (`div_fast_flood`), and the operands are gone by the
    ///    time a count is recorded, so a tx of ~3.17M cheap divisions is refused at a true
    ///    cost of 7% of the ceiling. [`CycleEstimate::bounded`] is reported so a consumer
    ///    can see when a refusal rests on that rather than on a measurement.
    ///
    /// Giving `arith_div_op` a domain — the obvious fix for the over-refusal — was tried
    /// and rejected: it moves the *worst* shape onto the distrust branch too, and distrust
    /// means `IncludeAndSeal`, so the one flood that genuinely exceeds 2^36 would be
    /// admitted and sealed. The over-refusal costs a sender a transaction; that trade
    /// costs the chain a batch it cannot prove. Closing the gap for real needs the operand
    /// shape to become observable (price per quotient digit, which is what the cost tracks)
    /// — and vm2's `Tracer` cannot see an instruction's operands, so it needs a vm2 change,
    /// not a table change.
    fn extrapolates(&self, count: u64) -> bool {
        match (self.domain_max, self.kind) {
            (Some(max), _) => count as f64 > max as f64 * DOMAIN_SLACK,
            (None, Provenance::Bounded) => false,
            (None, Provenance::Measured) => count > 0,
        }
    }
}

/// What a near-empty batch costs: bootloader and setup work not attributable to any
/// counted operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    pub cycles: f64,
    /// The same constant measured against raw main-trace cycles.
    #[serde(default)]
    pub raw_cycles: f64,
}

/// Identity of the guest the table was calibrated against.
///
/// Without it a stale table is invisible: every guest optimisation raises the
/// table's real error while a frozen-fixture test stays green, which is how a
/// predecessor reached 2.05× over-prediction undetected.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TableProvenance {
    #[serde(default)]
    pub guest_sha256: Option<String>,
    #[serde(default)]
    pub verifier_commit: Option<String>,
    #[serde(default)]
    pub vm2_rev: Option<String>,
    #[serde(default)]
    pub measured_on: Option<String>,
    #[serde(default)]
    pub corpus: Option<String>,
}

impl TableProvenance {
    /// Blank strings do not count: `""` satisfies `is_some()` while identifying
    /// nothing, which would let an unstamped table pass a stamp check.
    pub fn is_stamped(&self) -> bool {
        [
            &self.guest_sha256,
            &self.verifier_commit,
            &self.vm2_rev,
            &self.measured_on,
        ]
        .iter()
        .all(|f| f.as_deref().is_some_and(|v| !v.trim().is_empty()))
    }
}

/// The full cost table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostTable {
    pub base: Base,
    /// Per-operation rates, keyed by the typed [`FeatureId`], so a table naming a
    /// feature the schema does not have fails to parse.
    pub ops: BTreeMap<FeatureId, CostEntry>,
    /// Features that are deliberately not priced, because another entry already
    /// charges their work.
    ///
    /// This exists to separate a CORRECT absence from a missing rate. `decommit` counts
    /// fresh and repeat decommits together and both halves are priced individually
    /// (`decommit_cycles` per 64-byte unit, `decommit_repeat` per call), so charging the
    /// total as well would double-charge. Without this list the estimator would have to
    /// treat every absence alike, and would either decline batches over a deliberate
    /// omission or trust batches with a genuinely unpriced axis.
    #[serde(default)]
    pub unpriced: BTreeSet<FeatureId>,
    /// The single safety factor.
    ///
    /// One explicit number, rather than conservatism smuggled into per-operation
    /// rates: an inflated rate stops being a cost, and the model then extrapolates
    /// to unseen batch shapes using numbers that describe nothing.
    pub margin: f64,
    #[serde(default)]
    pub provenance: TableProvenance,
}

impl CostTable {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// The committed table, parsed once.
    pub fn embedded() -> &'static CostTable {
        static TABLE: OnceLock<CostTable> = OnceLock::new();
        TABLE.get_or_init(|| {
            CostTable::from_json(EMBEDDED_COST_TABLE).expect(
                "embedded cost_table.json is malformed — rebuild it with build_cost_table.py",
            )
        })
    }

    /// Predicted effective cycles.
    pub fn predict(&self, fv: &FeatureVector) -> u64 {
        let mut acc = self.base.cycles;
        for (id, entry) in &self.ops {
            acc += entry.cycles_per_unit * fv.get(*id) as f64;
        }
        acc.max(0.0).round() as u64
    }

    /// Predicted cycles for this feature vector EXCLUDING the per-batch base.
    ///
    /// This is what a per-transaction screen must use. [`Self::predict`] adds a per-BATCH
    /// constant — currently ~1.15e9 cycles, 1.7% of the ceiling — so pricing one
    /// transaction with it charges that transaction for the whole batch's fixed cost. A
    /// batch estimate counts the base once, correctly; a per-tx screen using the same
    /// function counts it again for every transaction it looks at.
    ///
    /// era's `CyclesCriterion` does exactly that today in its reject path. It is currently
    /// harmless only because the configured limit never fires (see
    /// [`PROVING_CYCLE_CEILING`]), which is not a property to rely on.
    pub fn predict_marginal(&self, fv: &FeatureVector) -> u64 {
        let mut acc = 0.0;
        for (id, entry) in &self.ops {
            acc += entry.cycles_per_unit * fv.get(*id) as f64;
        }
        acc.max(0.0).round() as u64
    }

    /// Full estimate, with the signals a caller needs to decide whether to trust it.
    pub fn estimate(&self, fv: &FeatureVector) -> CycleEstimate {
        CycleEstimate {
            total: self.predict(fv),
            marginal: self.predict_marginal(fv),
            margin: self.margin,
            raw: self.predict_raw(fv),
            bounded: self.predict_bounded(fv),
            untrusted: self.untrusted_pricing(fv),
            extrapolating: self.extrapolating(fv),
            trace_missing: Self::trace_missing(fv),
            producer_gap: Self::producer_gap(fv),
        }
    }

    /// The part of [`Self::predict`] that comes from [`Provenance::Bounded`] rates.
    ///
    /// A bound is an upper bound at the worst input an attacker can choose, and for the
    /// operand-dependent axes the true cost sits far below it — `arith_div_op` is priced
    /// at 15,474 against a measured 1,162 for the cheapest shape. Over-estimating is the
    /// safe direction for a SEAL decision and the lossy one for a REFUSE decision, so a
    /// consumer about to refuse a transaction needs to know how much of the number it is
    /// refusing on is a bound. That is what this is for; nothing in the gate arithmetic
    /// uses it.
    pub fn predict_bounded(&self, fv: &FeatureVector) -> u64 {
        let acc: f64 = self
            .ops
            .iter()
            .filter(|(_, e)| e.kind == Provenance::Bounded)
            .map(|(id, e)| e.cycles_per_unit * fv.get(*id) as f64)
            .sum();
        acc.max(0.0).round() as u64
    }

    /// Axes that a real execution never leaves at zero alongside the traffic this batch
    /// claims — i.e. axes whose PRODUCER looks unwired, rather than unused.
    ///
    /// Every other trust signal keys on `count > 0`, so an axis a producer never fills is
    /// indistinguishable from an axis the batch never used, and a mis-mapped feature is
    /// therefore invisible: it reads as a batch that did none of that work. The schema
    /// this crate ships makes that a live risk rather than a theoretical one, because it
    /// splits era's single `RichAddressingOp` bucket into five measured cost classes
    /// (`crates/cycle_tracer/src/tracer.rs` for the vm2 mapping; era's legacy-VM producer
    /// in `core/lib/multivm/src/tracers/cycle_estimator/vm_latest/mod.rs` has to be
    /// re-mapped to match). Renaming that one arm and leaving it lumped compiles, prices
    /// every division at `arith_cheap_op`'s 145, and scores a batch that the correct
    /// mapping puts at 1.06x of the ceiling (1.37x conservative) at 0.028x instead —
    /// 37x under, silently, with every other signal green.
    ///
    /// So this signal exists to make that particular absence loud. It is not a general
    /// plausibility check on batch shapes: see `PRODUCER_COVERAGE` for the one group it
    /// covers, the organic evidence behind its threshold, and why `decommit_repeat` — the
    /// axis where a lost producer costs the most — cannot be covered this way.
    ///
    /// A false positive here costs a conservative seal, which is the cheap direction.
    pub fn producer_gap(fv: &FeatureVector) -> Vec<FeatureId> {
        PRODUCER_COVERAGE
            .iter()
            .filter(|(heavy, _, floor)| fv.get(*heavy) >= *floor)
            .filter(|(_, siblings, _)| siblings.iter().all(|id| fv.get(*id) == 0))
            .flat_map(|(_, siblings, _)| siblings.iter().copied())
            .collect()
    }

    /// Predicted RAW main-trace cycles, excluding delegation-circuit cost.
    ///
    /// Not a gate quantity — the ceiling applies to `predict`. This exists so a consumer
    /// can compare a prediction against something the prover measures directly and feed
    /// the error back, which is the only route by which this table gets corrected in
    /// production rather than by another offline campaign.
    pub fn predict_raw(&self, fv: &FeatureVector) -> u64 {
        let total = self.base.raw_cycles
            + self
                .ops
                .iter()
                .map(|(id, e)| e.raw_cycles_per_unit * fv.get(*id) as f64)
                .sum::<f64>();
        total.max(0.0) as u64
    }

    /// Operations the batch uses that the table cannot price: no entry, and not on the
    /// deliberately-[`unpriced`](Self::unpriced) list. Both `Measured` and `Bounded` are
    /// trustworthy — a bound cannot cause an under-estimate.
    ///
    /// Covers every variant via `FeatureId::iter()`, and both halves of that matter.
    /// Restricting it to the crypto axes assumed an unpriced axis is only dangerous when
    /// cryptographic, which the table disproves. And enumerating `VM_TRACE_FEATURES` plus
    /// `SAFETY_CRITICAL_FEATURES` instead — which this did first — silently missed the five
    /// batch-level features in neither list.
    ///
    /// While any axis lacks a rate, batches using it are declined. Measure the axis; never
    /// narrow this check.
    pub fn untrusted_pricing(&self, fv: &FeatureVector) -> Vec<FeatureId> {
        FeatureId::iter()
            .filter(|id| fv.get(*id) > 0)
            .filter(|id| !self.ops.contains_key(id) && !self.unpriced.contains(id))
            .collect()
    }

    /// Operations whose count is beyond the range their rate was calibrated over.
    ///
    /// One check replaces what used to be two envelopes — an arithmetic-share cap
    /// and a per-feature volume cap — because both asked the same question: is this
    /// batch outside the data the number came from? Per-entry domains answer it
    /// uniformly, and also cover input-range extrapolation, which a
    /// share-of-prediction test could not express.
    pub fn extrapolating(&self, fv: &FeatureVector) -> Vec<FeatureId> {
        self.ops
            .iter()
            .filter(|(id, e)| e.extrapolates(fv.get(**id)))
            .map(|(id, _)| *id)
            .collect()
    }

    /// True when the batch claims work yet its VM trace is empty — no tracer ran, so
    /// the estimate degenerates to the base plus whatever batch scalars the caller
    /// passed. Impossible for a real execution, and indistinguishable from a small
    /// batch to every other signal, so a consumer that forgets to wire a tracer
    /// would otherwise get a small trustworthy-looking number.
    pub fn trace_missing(fv: &FeatureVector) -> bool {
        let claims_work = [
            FeatureId::TransactionCount,
            FeatureId::MerkleLeafCount,
            FeatureId::PubdataBytes,
            FeatureId::StateDiffCount,
        ]
        .iter()
        .any(|id| fv.get(*id) > 0);
        let traced: u64 = VM_TRACE_FEATURES.iter().map(|id| fv.get(*id)).sum();
        claims_work && traced == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_parses_and_is_stamped() {
        let t = CostTable::embedded();
        assert!(!t.ops.is_empty());
        assert!(t.margin >= 1.0, "margin must not shrink an estimate");
        assert!(
            t.provenance.is_stamped(),
            "the committed table carries no complete provenance stamp — nothing \
             downstream can tell whether it still describes the guest it gates"
        );
    }

    /// How many schema features still have no rate. **May only ever be lowered**, and it
    /// is now zero: every feature is measured, bounded, or deliberately unpriced.
    ///
    /// Failing when the count goes *down* is deliberate — closing a gap without lowering
    /// this leaves headroom for a later regression to slip into, which is how the previous
    /// exception list went quiet. Kept at zero because that is precisely the assertion that
    /// no axis ever silently loses its rate.
    const UNMEASURED_AXES: usize = 0;

    #[test]
    fn unpriced_axis_count_only_ratchets_down() {
        let t = CostTable::embedded();
        let missing: Vec<_> = FeatureId::iter()
            .filter(|id| !t.ops.contains_key(id) && !t.unpriced.contains(id))
            .collect();
        // At a ratchet of zero the two directions collapse into one equality: any axis
        // without a rate is a regression, and there is no headroom left to lower.
        assert_eq!(
            missing.len(),
            UNMEASURED_AXES,
            "{missing:?} have no rate. Every axis in the schema is supposed to be \
             measured on an isolated family, bounded, or on the deliberately-unpriced \
             list — measure the new one or bound it. Do NOT price it by regressing \
             whole batches: that is what this design removed, and it produced six axes \
             priced at exactly zero."
        );
    }

    /// A missing rate must be REPORTED, not silently priced at zero.
    ///
    /// Exercised against a table with an axis deliberately removed, because the embedded
    /// table has no holes — so a test that only looks at the embedded table cannot
    /// distinguish "reports holes correctly" from "has no holes", and the previous version
    /// of this test could not fail for any input.
    #[test]
    fn a_missing_rate_is_reported_not_silently_zero() {
        let mut t = CostTable::from_json(EMBEDDED_COST_TABLE).expect("parse");
        assert!(
            t.ops.remove(&FeatureId::FarCall).is_some(),
            "far_call must be priced for this test to exercise a real hole"
        );
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::FarCall, 1);
        assert_eq!(
            t.untrusted_pricing(&fv),
            vec![FeatureId::FarCall],
            "an axis with no rate and no deliberate-unpriced entry must be reported"
        );
        assert!(
            t.predict(&fv) < CostTable::embedded().predict(&fv),
            "and it must actually cost nothing once removed — otherwise the test is not \
             exercising a real hole"
        );
        // A deliberately-unpriced axis is the opposite case and must stay quiet.
        let mut fv2 = FeatureVector::default();
        fv2.add(FeatureId::Decommit, 1);
        assert!(
            CostTable::embedded().untrusted_pricing(&fv2).is_empty(),
            "`decommit` is unpriced on purpose (both halves are charged separately)"
        );
    }

    /// The exported ceiling must equal airbender's own constant, and the whole table must
    /// fit under it with room — a table whose base alone approached the ceiling would be
    /// describing a guest that cannot prove an empty batch.
    #[test]
    fn the_ceiling_is_airbenders_and_the_base_fits_far_inside_it() {
        assert_eq!(PROVING_CYCLE_CEILING, 68_719_476_736, "2^36, per airbender");
        let t = CostTable::embedded();
        let frac = t.base.cycles / PROVING_CYCLE_CEILING as f64;
        assert!(
            frac < 0.05,
            "the per-batch base is {:.1}% of the ceiling; above a few percent it would \
             dominate every prediction and the per-axis rates would stop mattering",
            frac * 100.0
        );
    }

    /// `marginal` is `total` minus the base, exactly — this is the property a per-tx
    /// screen depends on, and getting it wrong re-introduces the double-counting.
    #[test]
    fn marginal_is_total_without_the_per_batch_base() {
        let t = CostTable::embedded();
        let mut fv = FeatureVector::default();
        fv.add(FeatureId::FarCall, 500);
        fv.add(FeatureId::ArithCheapOp, 1_000_000);
        let est = t.estimate(&fv);
        assert_eq!(est.total - est.marginal, t.base.cycles.round() as u64);
        assert!(
            est.marginal > 0,
            "a vector with real work must have non-zero marginal cost"
        );
        // And an empty batch is ALL base: nothing marginal to charge.
        assert_eq!(t.estimate(&FeatureVector::default()).marginal, 0);
    }

    #[test]
    fn measured_entries_declare_a_domain() {
        // An entry with no domain claims coverage it has not got. Bounded entries
        // are exempt: a bound holds outside the range it was taken over, which is
        // the whole point of it being a bound.
        for (id, e) in &CostTable::embedded().ops {
            if e.kind == Provenance::Measured {
                assert!(
                    e.domain_max.is_some(),
                    "{id:?} is Measured but declares no domain, so extrapolation \
                     beyond its calibration range cannot be detected"
                );
            }
        }
    }

    #[test]
    fn a_flood_beyond_its_domain_is_flagged() {
        let t = CostTable::embedded();
        let (id, entry) = t
            .ops
            .iter()
            .find(|(_, e)| e.domain_max.is_some_and(|m| m > 0))
            .expect("some entry must carry a domain");
        let mut fv = FeatureVector::default();
        fv.add(*id, entry.domain_max.unwrap() * 100);
        assert!(t.extrapolating(&fv).contains(id));
    }
}
