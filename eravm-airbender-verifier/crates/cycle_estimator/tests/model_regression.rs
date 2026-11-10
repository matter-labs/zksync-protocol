//! CI guard: **the table did not change unexpectedly** — not "the model is accurate".
//!
//! Both sides of the comparison are frozen committed data — the embedded table and a
//! fixture with measured `effective_cycles` baked in — so this catches an accidental
//! or accuracy-worsening edit to the table or the prediction code, and nothing else.
//! It **cannot see guest drift**: the fixture ages with the table. A predecessor
//! reached 2.05× over-prediction with this test green throughout. That job belongs to
//! `.github/workflows/cycle-model-drift.yaml`, which re-measures against the guest
//! built from HEAD.
//!
//! The fixture is the whole reproducible corpus, so it is IN-SAMPLE by construction —
//! a tripwire, not a validation.
//!
//! ## What "safe" means here now
//!
//! Every rate in the table is measured on an isolated family or is a deliberate bound;
//! nothing is fitted. The worst under-prediction across 215 measured batches is 8.07%
//! (deploy batch 900204) and on organic traffic 0.01%, which is what sets the margin at
//! 1.15 — calibrated, not picked round.
//!
//! One warning for whoever next sees a large residual here. An earlier version of this
//! table under-predicted organic traffic by 8.8%, and single-feature regression said the
//! shortfall was unattributable — every feature correlates ~0.85 with it, because
//! organic features all move together. It looked like irreducible model fidelity. It was
//! one axis priced at zero (`arith_ptr_op`), and it was found by testing synthetic
//! families for outlier ratios, not by staring at organic correlations. Check the
//! isolation corpus before concluding the model is at its limit.
//!
//! That is a better structure than the predecessor's, which reached a flattering 1.26%
//! MAPE by fitting eleven axes over these same batches — six of them to exactly zero.
//! It was accurate in total and wrong on every axis an attacker can isolate, which is
//! the only kind of accuracy a seal gate needs. `MAX_UNDER_PCT` is therefore a real
//! tolerance, and it is meaningful because it stays well inside the margin it sits in.
use serde::Deserialize;
use zksync_era_airbender_cycles_estimator::{CostTable, FeatureVector};

const FIXTURE: &str = include_str!("fixtures/measured_corpus.json");

/// Bounds on the committed table's error over its own corpus. Set with headroom over
/// the measured values so an ordinary re-measurement does not trip them, and tight
/// enough that a real regression does.
/// Loose because the deliberate bounds dominate it, and one of them is large on purpose:
/// `arith_div_op` is bounded at 15,474 — the worst of five measured divisor shapes — and
/// costs a mean 8% of the predicted total on real traffic. The previous 7,711 gave a
/// prettier MAPE and under-predicted the worst shape by 67%. Do not tighten this by
/// loosening a bound.
const MAX_MAPE_PCT: f64 = 9.0;
/// Over-prediction is safe but it is throughput given away. Loose on purpose: the
/// deliberate bounds dominate it, `arith_div_op` and `decommit_repeat` most of all. The
/// build prints each bound's cost on real traffic; tighten a bound there, never this.
const MAX_OVER_PCT: f64 = 15.0;
/// The one that matters: under-prediction is the only unsafe direction. It must stay
/// far inside the table's own margin — that gap is the safety claim.
const MAX_UNDER_PCT: f64 = 3.0;

#[derive(Deserialize)]
struct Row {
    batch_number: u64,
    effective_cycles: u64,
    raw_cycles: u64,
    features: FeatureVector,
}

#[test]
fn embedded_table_does_not_regress_on_measured_corpus() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    assert_eq!(
        rows.len(),
        52,
        "fixture size changed unexpectedly — it is a BUILD PRODUCT of the organic \
         corpus (build_fixtures.py), so a size change means a batch was added or \
         failed to measure"
    );
    let table = CostTable::embedded();

    let mut sum_ape = 0.0;
    let mut worst_over = (0u64, 0.0_f64);
    let mut worst_under = (0u64, 0.0_f64);
    for r in &rows {
        let actual = r.effective_cycles as f64;
        let pred = table.predict(&r.features) as f64;
        sum_ape += 100.0 * (pred - actual).abs() / actual;
        let signed = 100.0 * (pred - actual) / actual;
        if signed > worst_over.1 {
            worst_over = (r.batch_number, signed);
        }
        if -signed > worst_under.1 {
            worst_under = (r.batch_number, -signed);
        }
    }
    let mape = sum_ape / rows.len() as f64;
    println!(
        "measured corpus: MAPE={mape:.3}%  worst over=batch {} at {:.3}%  \
         worst under=batch {} at {:.3}%",
        worst_over.0, worst_over.1, worst_under.0, worst_under.1
    );

    assert!(
        worst_under.1 <= MAX_UNDER_PCT,
        "batch {} is UNDER-predicted by {:.3}% (limit {MAX_UNDER_PCT}%). Under-prediction \
         is the unsafe direction: such a batch can seal and then be unprovable. The \
         table's margin is {:.2}, so this must stay well inside it.",
        worst_under.0,
        worst_under.1,
        table.margin
    );
    assert!(
        worst_under.1 * 1.5 < (table.margin - 1.0) * 100.0,
        "the worst under-prediction ({:.2}%) has eaten most of the margin ({:.2}%). \
         Either the rates have drifted or the margin needs raising — do not just \
         loosen MAX_UNDER_PCT.",
        worst_under.1,
        (table.margin - 1.0) * 100.0
    );
    assert!(
        mape <= MAX_MAPE_PCT,
        "MAPE {mape:.3}% regressed past {MAX_MAPE_PCT}%"
    );
    assert!(
        worst_over.1 <= MAX_OVER_PCT,
        "batch {} over-predicted {:.3}%, past {MAX_OVER_PCT}% — over-prediction is safe \
         but it is throughput, and a jump here usually means a rate became a bound",
        worst_over.0,
        worst_over.1
    );
}

/// Every batch of real traffic must sit inside the calibrated domains.
///
/// The domain check fails *closed* — an out-of-domain batch is declined, never
/// silently trusted — so a domain that is too TIGHT costs throughput on ordinary
/// batches rather than admitting an attack. That failure mode is invisible in the
/// accuracy numbers, so pin it here: it is what notices if a rebuild narrows a domain
/// because it was rebuilt from a smaller corpus.
#[test]
fn real_traffic_is_inside_every_calibrated_domain() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    let table = CostTable::embedded();
    for r in &rows {
        let est = table.estimate(&r.features);
        assert!(
            est.is_within_calibration(),
            "corpus batch {} is outside the domain of {:?} — the domain is tighter than \
             real traffic",
            r.batch_number,
            est.extrapolating
        );
        assert!(
            !est.trace_missing,
            "corpus batch {} has a full trace; the missing-trace signal must stay quiet",
            r.batch_number
        );
    }
}

/// Tolerance on the RAW prediction. Deliberately looser than `MAX_UNDER_PCT` and for a
/// different reason: `MAX_UNDER_PCT` is a safety bound on the quantity the gate compares
/// against the proving ceiling, whereas raw is a diagnostic the gate never reads. An
/// under-prediction here costs credibility in the feedback channel, not provability.
///
/// Worth noting which way the two differ. Raw is the *more* accurate target — MAPE 1.87%
/// against 4.38% — because the effective table carries the deliberate bounds and their
/// over-charge, while its worst under-prediction is larger (3.31% against 0.01%) for the
/// same reason: that over-charge is what pushes effective to the safe side.
const MAX_RAW_UNDER_PCT: f64 = 5.0;

/// The RAW prediction must be accurate too, and must never exceed the effective one.
///
/// This is the number the consumer can actually check — `effective` folds in delegation
/// weights that have no authoritative source in this tree, so an operator comparing
/// predicted against actual has to use `raw` for the comparison to mean anything. If it
/// were left unvalidated, the feedback channel would report the model's error and the
/// weights' error mixed together, and the first production correction would chase the
/// wrong one.
#[test]
fn raw_prediction_is_accurate_and_never_exceeds_effective() {
    let rows: Vec<Row> = serde_json::from_str(FIXTURE).expect("parse fixture");
    let table = CostTable::embedded();

    let mut sum_ape = 0.0;
    let mut worst_under = (0u64, 0.0_f64);
    for r in &rows {
        let raw = table.predict_raw(&r.features);
        let eff = table.predict(&r.features);
        assert!(
            raw <= eff,
            "batch {}: predicted raw {raw} exceeds predicted effective {eff}. \
             effective = raw + weighted delegations and every weight is positive, so \
             this is arithmetically impossible — a rate table has raw and effective \
             swapped, or a raw rate is missing and defaulted to zero.",
            r.batch_number
        );
        let actual = r.raw_cycles as f64;
        let signed = 100.0 * (raw as f64 - actual) / actual;
        sum_ape += signed.abs();
        if -signed > worst_under.1 {
            worst_under = (r.batch_number, -signed);
        }
    }
    let mape = sum_ape / rows.len() as f64;
    println!(
        "raw prediction: MAPE={mape:.3}%  worst under=batch {} at {:.3}%",
        worst_under.0, worst_under.1
    );
    assert!(
        mape <= MAX_MAPE_PCT,
        "raw MAPE {mape:.3}% regressed past {MAX_MAPE_PCT}%"
    );
    assert!(
        worst_under.1 <= MAX_RAW_UNDER_PCT,
        "batch {} has its RAW cycles under-predicted by {:.3}% (limit \
         {MAX_RAW_UNDER_PCT}%). \
         The gate does not read this field, so this is not itself an under-estimation \
         vector — but it is the signal the operator uses to trust the table, and a biased \
         one teaches them to distrust a correct gate.",
        worst_under.0,
        worst_under.1
    );
}
