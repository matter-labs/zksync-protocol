//! Which axes can actually move a consumer's decision, and on what evidence.
//!
//! `model_regression.rs` asks whether the table is accurate and `adversarial_safety.rs`
//! whether it ever under-predicts a batch it trusts. Neither asks the question this file
//! does: **of the two things a consumer does with an estimate — seal a batch, or refuse a
//! transaction — which axes can trigger which?** That turns out to be decided almost
//! entirely by the domain check rather than by any rate, and the shape of it is not
//! obvious from either the table or the estimator:
//!
//! * A `Measured` axis carries a domain, and its domain trips long before its cost
//!   reaches the budget. Driving **every** domain-carrying axis at once to the largest
//!   count it is trusted at reaches 0.61 of the ceiling. So a measured axis answers a
//!   flood with *distrust*, never with magnitude — and the deployed consumer answers
//!   distrust by sealing.
//! * A `Bounded` axis carries no domain by construction (a bound holds outside the range
//!   it was taken over), so it never trips. Those are the only axes that can carry a
//!   trusted estimate up to the budget, which makes them the only route to the reject
//!   branch.
//!
//! Both halves are load-bearing and neither was checked anywhere. The consequence worth
//! stating plainly: **the domain guard is the effective seal condition, and the configured
//! cycle budget only ever fires through a bound.** That is a deliberate trade — see
//! `CostEntry::extrapolates` — and these tests exist so that a rate change which alters
//! it fails here instead of changing the gate's character silently.
//!
//! The budget is taken to BE the proving ceiling. era's `max_cycles_per_batch` defaults to
//! 14,552x it, at which nothing fires at all; `PROVING_CYCLE_CEILING` is exported so the
//! consumer's budget can be derived from the ceiling instead.

use zksync_era_airbender_cycles_estimator::{
    CostTable, FeatureId, FeatureVector, Provenance, DOMAIN_SLACK, PROVING_CYCLE_CEILING,
};

use serde::Deserialize;

/// era's `close_block_at_cycles_percentage` / `reject_tx_at_cycles_percentage`, both
/// defaulting to 0.95 in `core/lib/config/src/configs/chain.rs`. The two bounds coincide
/// at the default, so one constant covers both branches.
const TRIP_FRACTION: f64 = 0.95;

const ORGANIC: &str = include_str!("fixtures/measured_corpus.json");
const ADVERSARIAL: &str = include_str!("fixtures/adversarial.json");

#[derive(Deserialize)]
struct OrganicRow {
    features: FeatureVector,
}

#[derive(Deserialize)]
struct AdversarialRow {
    label: String,
    effective_cycles: u64,
    features: FeatureVector,
}

/// Cycles a single axis has to carry, on its own, for a consumer to reject or close.
fn trip_cycles(table: &CostTable) -> f64 {
    TRIP_FRACTION * PROVING_CYCLE_CEILING as f64 / table.margin.max(1.0)
}

/// The count of `id` at which that axis alone reaches the trip point, base included.
fn trip_count(table: &CostTable, id: FeatureId) -> f64 {
    let rate = table.ops[&id].cycles_per_unit;
    (trip_cycles(table) - table.base.cycles) / rate
}

/// Largest count of each axis in the 52 batches of real traffic.
fn organic_max(id: FeatureId) -> u64 {
    serde_json::from_str::<Vec<OrganicRow>>(ORGANIC)
        .expect("parse organic fixture")
        .iter()
        .map(|r| r.features.get(id))
        .max()
        .unwrap_or(0)
}

/// No domain-carrying axis, and no combination of them, can reach a consumer's trip
/// point while still being trusted — so the magnitude branches are unreachable through
/// measured evidence, and the domain check is what actually seals.
///
/// This is the assertion behind the claim in `CostEntry::extrapolates`. It is stated as
/// the SUM over every domain-carrying axis, not per axis, because that is the strong form:
/// even an attacker who maximises all of them simultaneously — which no single erg budget
/// buys — stays under the bound.
///
/// If this ever fails it is not necessarily a regression: a measured axis gaining enough
/// reach to close a batch on its own is an *improvement* (a seal decision resting on a
/// measurement rather than on a bound). But it changes what the gate is, so it must be
/// re-read and re-documented rather than silently absorbed.
#[test]
fn the_magnitude_branch_is_unreachable_through_domain_carrying_axes() {
    let table = CostTable::embedded();
    let mut total = table.base.cycles;
    let mut per_axis: Vec<(f64, FeatureId, u64)> = Vec::new();
    for (id, e) in &table.ops {
        if let Some(dom) = e.domain_max {
            let admitted = (dom as f64 * DOMAIN_SLACK).floor();
            let cycles = e.cycles_per_unit * admitted;
            total += cycles;
            per_axis.push((cycles / PROVING_CYCLE_CEILING as f64, *id, admitted as u64));
        }
    }
    per_axis.sort_by(|a, b| b.0.total_cmp(&a.0));
    println!(
        "every domain-carrying axis at its admitted maximum (domain x {DOMAIN_SLACK}): \
         {:.4}x of the ceiling, {:.4}x after the {:.2} margin",
        total / PROVING_CYCLE_CEILING as f64,
        total * table.margin / PROVING_CYCLE_CEILING as f64,
        table.margin
    );
    for (frac, id, admitted) in per_axis.iter().take(5) {
        println!("    {id:?} admits {admitted} = {frac:.4}x");
    }

    let reached = total * table.margin.max(1.0);
    let bound = TRIP_FRACTION * PROVING_CYCLE_CEILING as f64;
    assert!(
        reached < bound,
        "the domain-carrying axes now reach {:.3}x the trip point together. A measured \
         axis can close a batch on its own, which changes the gate's character: re-read \
         the trade recorded in CostEntry::extrapolates before adjusting this test.",
        reached / bound
    );
}

/// Axes where one unit of the feature costs one `precompile_call`, so `precompile_call`'s
/// own domain trips before the axis can reach a trip point.
///
/// Not an assumption about vm2 — measured, in the committed adversarial fixture: the
/// isolation batches report `mod_exp_cycles` 12,000 against 12,027 calls, `ec_mul_cycles`
/// 8,000/8,027, `ec_add_cycles` 60,000/60,027, `ec_recover_cycles` 8,001/8,027,
/// `secp256r1_verify_cycles` 5,000/5,027 (the 27 being the harness's own). The payload for
/// these five is a flat 1 per call, which is *why* they are bounded rather than measured,
/// and it is also what gates them.
const ONE_CALL_PER_UNIT: &[FeatureId] = &[
    FeatureId::ModExpCycles,
    FeatureId::EcMulCycles,
    FeatureId::EcAddCycles,
    FeatureId::EcRecoverCycles,
    FeatureId::Secp256r1VerifyCycles,
];

/// The bounds that can refuse a transaction are exactly two, and this test names them.
///
/// A refusal driven by a bound is a refusal at the worst operand shape an attacker could
/// have chosen, so it over-refuses whenever the true shape was cheaper. Knowing *which*
/// axes can do that is the whole content of the trade, so it is pinned as an equality: a
/// rate change that adds a third ungated route fails here.
///
/// The five crypto bounds are gated by `precompile_call`, which is `Measured` and carries a
/// domain: one unit of each costs one call, so reaching any of those bounds needs more
/// calls than `precompile_call` is trusted for, and distrust (i.e. seal) fires first.
/// `arith_div_op` and `decommit_repeat` have no such companion — `decommit` is deliberately
/// unpriced and so has no domain, and a division needs nothing but ergs.
#[test]
fn only_two_bounds_can_reach_the_reject_branch_ungated() {
    let table = CostTable::embedded();
    let call_gate = (table.ops[&FeatureId::PrecompileCall]
        .domain_max
        .expect("precompile_call is measured and must carry a domain") as f64
        * DOMAIN_SLACK)
        .floor();

    let mut ungated = Vec::new();
    for (id, e) in &table.ops {
        if e.kind != Provenance::Bounded {
            continue;
        }
        let trip = trip_count(table, *id);
        let gated = ONE_CALL_PER_UNIT.contains(id) && trip > call_gate;
        println!(
            "{id:?}: alone reaches the {:.0}% bound at {:.0} units; {}",
            TRIP_FRACTION * 100.0,
            trip,
            if gated {
                format!("gated — that needs >{call_gate:.0} precompile calls, past their domain")
            } else {
                "UNGATED — this axis can refuse a transaction on its own".to_string()
            }
        );
        if !gated {
            ungated.push(*id);
        }
    }

    ungated.sort();
    assert_eq!(
        ungated,
        vec![FeatureId::ArithDivOp, FeatureId::DecommitRepeat],
        "the set of bounds that can refuse a transaction has changed. Each one is an \
         axis where an honest transaction can be refused at up to the bound's \
         over-charge, so a new entry needs the same treatment the two known ones got: \
         a fixture at the cheap shape, and the over-refusal factor recorded."
    );
}

/// Every bound sits far above anything real traffic does, so the over-refusal is a
/// property of extreme batches only.
///
/// Worth pinning separately from accuracy: a bound could be raised for good safety
/// reasons (both of these were, by 1.9x and 9.8x, when the input sweeps landed) and the
/// first thing that would break is not accuracy but ordinary transactions. This is the
/// test that notices.
#[test]
fn no_organic_batch_comes_near_a_bound_driven_refusal() {
    let table = CostTable::embedded();
    /// Real traffic must stay this far below every trip point. Not tuned: the tightest
    /// axis is at 34x, so anything up to ~30 is headroom the corpus already has.
    const MIN_HEADROOM: f64 = 25.0;

    for (id, e) in &table.ops {
        if e.kind != Provenance::Bounded {
            continue;
        }
        let seen = organic_max(*id);
        let trip = trip_count(table, *id);
        if seen == 0 {
            println!("{id:?}: absent from real traffic — no organic exposure to its bound");
            continue;
        }
        let headroom = trip / seen as f64;
        println!("{id:?}: organic max {seen}, trips at {trip:.0} — {headroom:.1}x headroom");
        assert!(
            headroom >= MIN_HEADROOM,
            "{id:?} is priced by a BOUND and real traffic is within {headroom:.1}x of the \
             count at which that bound alone refuses a transaction. A bound over-refuses \
             by however far the true cost sits below it, so this is the axis where a \
             raised bound starts costing honest transactions."
        );
    }
}

/// What the `arith_div_op` bound costs, measured, and why it is still the right choice.
///
/// The axis is priced at the worst of five measured divisor shapes because the operands
/// are gone by the time a count is recorded. The committed fixture holds both ends of the
/// range, so the over-charge can be derived here rather than asserted from a comment: a
/// division costs 1,162 cycles at the cheapest measured shape and 14,307 at the dearest,
/// and every one of them is charged at 15,474.
///
/// The consequence is a real liveness cost, and it belongs in a test rather than in prose:
/// a transaction of ~3.2M cheap divisions is refused while truly costing ~7% of the
/// ceiling. The alternative — giving the axis a domain so the flood lands on the distrust
/// branch instead — is worse, because the deployed consumer answers distrust with
/// `IncludeAndSeal`: the *worst*-shape flood, which genuinely exceeds 2^36, would then be
/// admitted and sealed into an unprovable batch. Refusing an honest transaction costs its
/// sender; admitting that one costs the chain a batch. The gap closes for real only when
/// the operand shape becomes observable, which needs a vm2 change — a `Tracer` cannot see
/// an instruction's operands.
#[test]
fn the_div_bound_over_refuses_a_cheap_shape_by_a_measured_factor() {
    let table = CostTable::embedded();
    let rows: Vec<AdversarialRow> =
        serde_json::from_str(ADVERSARIAL).expect("parse adversarial fixture");
    let rate = table.ops[&FeatureId::ArithDivOp].cycles_per_unit;

    // Residualise each division fixture: everything the table charges except divisions,
    // subtracted from what the batch actually cost, is what a division actually cost.
    let per_div = |row: &AdversarialRow| {
        let divs = row.features.get(FeatureId::ArithDivOp) as f64;
        let mut others = table.base.cycles;
        for (id, e) in &table.ops {
            if *id != FeatureId::ArithDivOp {
                others += e.cycles_per_unit * row.features.get(*id) as f64;
            }
        }
        (row.effective_cycles as f64 - others) / divs
    };
    let find = |label: &str| {
        rows.iter()
            .find(|r| r.label == label)
            .unwrap_or_else(|| panic!("{label} is the fixture this test is about"))
    };

    let cheapest = per_div(find("div_fast_flood"));
    let dearest = per_div(find("div_lead3_2limb_t3"));
    println!(
        "divisions cost {cheapest:.0} at the cheapest measured shape and {dearest:.0} at \
         the dearest; all are charged {rate:.0}"
    );

    assert!(
        rate >= dearest,
        "the bound ({rate:.0}) no longer covers the dearest measured shape \
         ({dearest:.0}) — it has stopped being a bound, which is an under-estimation \
         vector rather than a throughput one"
    );
    let over_refusal = rate / cheapest;
    assert!(
        (11.0..15.0).contains(&over_refusal),
        "the bound over-charges the cheapest measured division by {over_refusal:.1}x, \
         outside the 11-15x this trade was accepted at. A move here changes how many \
         honest transactions are refused, so it is a decision and not a tolerance."
    );

    // And the liveness cost that follows from it, in the units it is paid in.
    let refused_at = trip_count(table, FeatureId::ArithDivOp);
    let mut cheap_flood = FeatureVector::default();
    cheap_flood.add(FeatureId::ArithDivOp, refused_at as u64);
    let true_cost = (table.base.cycles + cheapest * refused_at) / PROVING_CYCLE_CEILING as f64;
    println!(
        "a transaction is refused at {refused_at:.0} divisions, where the cheapest shape \
         truly costs {:.1}% of the ceiling",
        true_cost * 100.0
    );
    assert!(
        true_cost < 0.2,
        "the refusal point is no longer deep inside the provable range ({:.1}% of the \
         ceiling at the cheap shape), so the over-refusal has stopped being the cost of \
         a bound and started being a correct refusal — re-derive the trade",
        true_cost * 100.0
    );
    // The signal a consumer needs to see this for what it is.
    let est = table.estimate(&cheap_flood);
    assert!(
        est.bounded_share() > 0.9,
        "a refusal this shape must report itself as bound-driven, or nothing downstream \
         can tell it apart from a measured one: bounded_share={:.3}",
        est.bounded_share()
    );
}
