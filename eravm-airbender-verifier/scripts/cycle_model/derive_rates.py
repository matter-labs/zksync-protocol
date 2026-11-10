TARGET_FN = None

#!/usr/bin/env python3
"""Turn measured isolation families into per-axis rates. This is where every number in
`build_cost_table.py`'s MEASURED and BOUNDED tables comes from.

## Why a plain slope is the wrong answer

An isolation family runs its target operation in a loop, and the loop does other work:
the keccak family retires 49 cheap arithmetic ops, 6 shifts, a far call and a near call
per keccak call. So the raw regression slope is

    gross = marginal_cost(axis) + SUM over companions of ( count_per_unit x cost )

and every one of those companions is ALSO counted in the feature vector and charged
again by its own rate. Pricing the axis at `gross` therefore double-charges. Measured
directly: `far_call` gross 18,167 against a true marginal of 15,373, and `event` gross
22,618 against 3,180 -- a 7.1x over-charge hiding inside a number that looks measured.

So each family's rate is its slope MINUS the companions at their own rates. That makes
the system mutually recursive, and it is solved by iterating to a fixed point (converges
in under ten passes; the coupling is weak because companions appear with small weights).

## Attribution rates are not prediction rates

Subtracting a companion needs the cost it *actually incurred in that loop*, which is not
always the rate the table ships. `arith_div_op` ships as a worst-case BOUND of 7,322
because operand-dependent cost is unobservable, but a helper loop divides on the
small-divisor fast path at 1,165. Subtracting the bound over-subtracts by ~6,200 per
call, which is what drove `precompile_call` to a nonsensical -5,686 before this
distinction existed. ATTRIB_OVERRIDE holds the as-incurred values.

## Where a family shares an axis, the dearest member wins

`add`, `sub`, `bitwise` and `jump` all price `arith_cheap_op`. An attacker picks the
shape, so the rate is the maximum across the class -- `sub` at 145 over `jump` at 102.
A feature is only legitimately one feature if that spread is bounded, which is a thing
this script prints so it can be checked rather than assumed.

Usage:
    python scripts/cycle_model/derive_rates.py \\
        --datasets artifacts/iso/dataset.json artifacts/iso2/dataset.json \\
        --corpus testdata/cycle_model/isolation_corpus.csv \\
        --organic testdata/cycle_model/dataset.json
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measurement import (  # noqa: E402
    delegation_counts,
    effective_cycles,
    feature_counts,
    raw_cycles,
)

# Selectable prediction target. `effective` is what the gate compares against the 2^36
# ceiling; `raw` is what the prover reports directly, and predicting it too gives the
# operator something checkable. A delegation id selects that channel's count, which is
# what makes the weights auditable rather than load-bearing.
CEILING = 2**36  # MAX_NUMBER_OF_CYCLES
BATCH_ERG_BUDGET = 200_000_000  # stock max_gas_per_batch

TARGETS = {
    "effective": effective_cycles,
    "raw": raw_cycles,
    "blake2": lambda r: float(delegation_counts(r).get("1991", 0)),
    "bigint": lambda r: float(delegation_counts(r).get("1994", 0)),
    "keccak": lambda r: float(delegation_counts(r).get("1995", 0)),
}

# Families from the second campaign, which are not in the original corpus CSV.
# Each is (batch list in volume order, intended axis).
EXTRA_FAMILIES = {
    "keccak_rounds": ([900323, 900324, 900325, 900326], "keccak256_cycles"),
    "sha256_rounds": ([900331, 900332, 900333, 900334], "sha256_cycles"),
    "keccak_calls": ([900319, 900320, 900321, 900322], "precompile_call"),
    "read_warm": ([900367, 900368], "storage_read"),
    "read_cold": ([900364, 900365, 900366], "storage_application"),
    "write_same": ([900356, 900345], "storage_write"),
    "write_dist": ([900369, 900370, 900371], "state_diff_count"),
    "pubdata": ([900348, 900349, 900350, 900351], "pubdata_bytes"),
    "txcount": ([900352, 900353, 900354, 900355], "transaction_count"),
    "ptr": ([900357, 900358, 900359, 900360], "arith_ptr_op"),
    # Divisor-shape families. Cost tracks quotient digits (dividend limbs - divisor limbs
    # + 1), so a SMALL divisor against a full-width dividend is near the worst, not the
    # fast path. All five share `arith_div_op`, and it is a BOUND, so the class maximum is
    # what ships -- see BOUND_FAMILIES.
    "div_lead1_2limb": ([900390, 900391, 900392], "arith_div_op"),
    "div_lead3_2limb": ([900393, 900394, 900395], "arith_div_op"),
    "div_lead1_3limb": ([900396, 900397, 900398], "arith_div_op"),
    "div_lead1_4limb": ([900399, 900400, 900401], "arith_div_op"),
    "div_small_1limb": ([900402, 900403, 900404], "arith_div_op"),
    # Bytecode volume reached through the FAR-CALL decommit path, with the contract count
    # pinned so only `decommit_cycles` moves. The other producer of that feature.
    "bytecode_size": ([900385, 900386, 900387, 900388], "decommit_cycles"),
    "ecpairing_pairs": ([900372, 900373, 900374, 900375], "ec_pairing_cycles"),
}

# Cost as INCURRED in a helper loop, for subtraction only -- never for prediction.
#
# The asymmetry is deliberate and it is a safety property, not a convenience. For
# PREDICTION a cost class takes its dearest member, because an attacker picks the shape.
# For ATTRIBUTION it must take its CHEAPEST member, because over-subtracting a companion
# under-prices the axis being measured -- and under-pricing is the unsafe direction.
#
# Getting this backwards is what drove `arith_ptr_op` to a measured zero. The slicing
# loop retires nine cheap arithmetic ops per pointer op; subtracting them at `sub` (145,
# the class max) instead of `jump` (102, the class min) over-subtracts 387 per pointer
# op, which was enough to take the whole rate negative. A zero `arith_ptr_op` then
# under-predicted contract deployment -- which copies bytecode through fat pointers -- by
# **23.5%**, past the margin, on a batch no adversarial fixture covered.
ATTRIB_OVERRIDE = {
    "arith_cheap_op": 102,             # `jump`, the cheapest member of the class
    "arith_shift_op": 70,              # `shift`
    "arith_div_op": 1_165,             # small-divisor fast path, not the worst-case bound
    "mod_exp_cycles": 24_003,          # 32-bit exponent, as the hammer used
    "ec_mul_cycles": 269_997,          # scalar 7
    "ec_add_cycles": 53_560,
    "ec_recover_cycles": 463_227,
    "secp256r1_verify_cycles": 726_926,
}

# Families whose answer is a BOUND rather than a typical cost: the dearest operand
# regime, kept out of the shared-axis maximum so a cheap sibling cannot lower it.
# Families whose answer is a BOUND: the dearest regime, kept out of the shared-axis
# maximum so a cheaper sibling cannot lower it. All the div shapes qualify -- the axis is
# operand-dependent and the operands are invisible to the tracer, so only the worst is
# deployable.
BOUND_FAMILIES = {"div_worst2", "div_lead1_2limb", "div_lead3_2limb", "div_lead1_3limb",
                  "div_lead1_4limb", "div_small_1limb"}

# Axes forced to their GROSS slope, with the counter-example that forced it. This is a
# judgement call driven by measurement, not a formula, so each entry has to cite the
# batch that disproves the netted value.
#
# A netted rate is only transferable if the target batch's companion mix resembles the
# family's. When it does not, netting under-charges -- and there is no way to detect that
# from the family alone, which is why these need a named counter-example rather than a
# threshold.
FORCE_GROSS = {
    "arith_ptr_op":
        "The slicing family retires 9 cheap arithmetic ops per pointer op; contract "
        "deployment (batches 900201-900205), which copies bytecode through fat pointers, "
        "retires 4.3. The netted 287 under-predicts batch 900204 by 19.9% and a zero rate "
        "by 23.5% -- both past any sane margin. The gross 1,680 brings it to 8.2%. Since "
        "every companion cost is non-negative, gross >= the true marginal, always.",
}


def ols(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None, None, None
    m = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    b = my - m * mx
    ssr = sum((y - (m * x + b)) ** 2 for x, y in zip(xs, ys))
    sst = sum((y - my) ** 2 for y in ys)
    return m, b, (1 - ssr / sst if sst else 1.0)


def load_families(corpus, rows):
    fams = {}
    tiers = defaultdict(list)
    for m in csv.DictReader(Path(corpus).open()):
        # `ctrl` rows are matched controls with a deliberately different shape, NOT
        # points on the volume ramp. Including one corrupts the slope -- the `evt`
        # control sits above its own t3 on the axis.
        if m["status"].startswith("DEAD") or m["tier"] == "ctrl":
            continue
        b = int(m["fixture"])
        if b in rows:
            tiers[m["family"]].append((int(m["axis_count"]), b, m["intended_axis"]))
    for fam, ents in tiers.items():
        ents.sort()
        fams[fam] = ([b for _, b, _ in ents], ents[0][2])
    for fam, (bs, ax) in EXTRA_FAMILIES.items():
        bs = [b for b in bs if b in rows]
        if len(bs) >= 2:
            fams[fam] = (bs, ax)
    return fams


def family_rate(fams, fam, rows, pred, attrib):
    """Slope of cycles against the axis, minus every co-moving priced axis.

    Each companion's own slope against the axis comes from the same regression, rather
    than from two endpoints, so a family with a noisy middle tier does not skew the
    subtraction.
    """
    bs, ax = fams[fam]
    xs = [feature_counts(rows[b]).get(ax, 0) for b in bs]
    ys = [TARGET_FN(rows[b]) for b in bs]
    slope, _, r2 = ols(xs, ys)
    if slope is None:
        return ax, None, None, None
    keys = set()
    for b in bs:
        keys |= set(feature_counts(rows[b]))
    known = 0.0
    for k in keys - {ax}:
        r = attrib.get(k, pred.get(k))
        if r is None:
            continue
        zs = [feature_counts(rows[b]).get(k, 0) for b in bs]
        per, _, _ = ols(xs, zs)
        if per:
            known += r * per
    return ax, slope, slope - known, r2


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", nargs="+", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--organic", help="if given, reports out-of-sample error and the "
                                      "margin the model needs")
    ap.add_argument("--seed", help="a cost_table.json to seed the iteration from")
    ap.add_argument("--emit", help="write the derived rates as JSON, for "
                                   "build_cost_table.py to check its literals against")
    ap.add_argument("--target", default="effective", choices=sorted(TARGETS),
                    help="quantity to derive rates for (default: effective)")
    args = ap.parse_args()

    global TARGET_FN
    TARGET_FN = TARGETS[args.target]
    rows = {}
    for d in args.datasets:
        for r in json.loads(Path(d).read_text()):
            rows[r["batch_number"]] = r
    fams = load_families(args.corpus, rows)

    # Gross slopes, kept per axis so a non-positive net can fall back to one.
    gross_slope = defaultdict(list)
    for fam in fams:
        bs, ax = fams[fam]
        xs = [feature_counts(rows[b]).get(ax, 0) for b in bs]
        ys = [TARGET_FN(rows[b]) for b in bs]
        m, _, _ = ols(xs, ys)
        if m is not None:
            gross_slope[ax].append(m)

    cur = {}
    if args.seed:
        cur = {k: e["cycles_per_unit"]
               for k, e in json.loads(Path(args.seed).read_text())["ops"].items()}

    for it in range(80):
        attrib = {**cur, **ATTRIB_OVERRIDE}
        prop = defaultdict(list)
        for fam in fams:
            ax, _, net, _ = family_rate(fams, fam, rows, cur, attrib)
            if net is not None:
                prop[ax].append((max(net, 0.0), fam))
        new = dict(cur)
        for ax, v in prop.items():
            bound = [x for x, f in v if f in BOUND_FAMILIES]
            new[ax] = max(bound) if bound else max(x for x, _ in v)
        # GROSS FALLBACK. A net that comes out non-positive does not mean the operation
        # is free -- it means the attribution could not resolve it, because the
        # companions it always appears with account for the whole slope at their own
        # rates. Pricing it at zero then loses real cost the moment a batch pairs that
        # operation with a DIFFERENT companion mix, which is exactly what contract
        # deployment does: the slicing family retires 9 cheap ops per pointer op,
        # deployment only 4.3, so a zero `arith_ptr_op` under-predicted deployment by
        # 23.5% -- past the margin, on a shape no adversarial fixture covered.
        #
        # The gross slope is the safe answer for such an axis: since every companion
        # cost is non-negative, gross >= the true marginal, always. It over-charges
        # batches shaped like the family, which is the safe direction.
        for ax, v in prop.items():
            if new[ax] <= 0.0 or ax in FORCE_GROSS:
                new[ax] = max(gross_slope[ax])
        if all(abs(new.get(k, 0) - cur.get(k, 0)) < 0.5 for k in set(new) | set(cur)):
            cur = new
            break
        cur = new
    print(f"fixed point after {it + 1} iterations\n")

    attrib = {**cur, **ATTRIB_OVERRIDE}
    # Convexity is reported per family, because a through-range slope under-prices the
    # top of the range for a convex axis -- and the fixtures still look over-predicted
    # there, so it does not announce itself in the error numbers.
    print(f"{'family':<16}{'axis':<24}{'gross':>13}{'NET':>13}{'R2':>10}  double-charge")
    print("-" * 90)
    for fam in sorted(fams):
        ax, g, net, r2 = family_rate(fams, fam, rows, cur, attrib)
        if net is None:
            print(f"{fam:<16}{ax:<24}  AXIS DOES NOT VARY")
            continue
        ratio = f"{g / net:.2f}x" if net > 0 else "net <= 0"
        star = "  <- class max" if abs(cur[ax] - max(net, 0.0)) < 0.5 else ""
        print(f"{fam:<16}{ax:<24}{g:>13,.0f}{net:>13,.0f}{r2:>10.6f}  {ratio:<10}{star}")

    # Two believability checks, folded in from a separate script. They belong next to the
    # numbers they qualify: a slope with a drifting intercept is not measuring one axis,
    # and a slope whose axis cannot be bought in quantity does not need to be exact.
    #
    #   intercept drift -- fitted intercept against the empty-batch control. A family
    #     whose intercept drifts has a second axis scaling with its own; this is how a
    #     sha256 family's size/arithmetic collinearity announced itself (2.27e9 against a
    #     9.4e8 baseline). For a FIXED-COUNT size sweep the expected intercept is
    #     control + per-call x count, not the control alone, so read those rows with that
    #     in mind rather than as drift.
    #   ergs per unit -- what one batch's erg budget buys, as a fraction of the 2^36
    #     ceiling. An axis that cannot approach it does not need a tight rate.
    ergs = {}
    try:
        for m in csv.DictReader(Path(args.corpus).open()):
            if not m["status"].startswith("DEAD"):
                ergs[int(m["fixture"])] = float(m["ergs_used"])
    except (OSError, KeyError):
        pass
    control = min((TARGET_FN(r) for r in rows.values()), default=0.0)
    print(f"\n{'family':<16}{'intercept':>16}{'vs control':>12}{'ergs/unit':>13}"
          f"{'x ceiling':>11}")
    for fam in sorted(fams):
        bs, ax = fams[fam]
        xs = [feature_counts(rows[b]).get(ax, 0) for b in bs]
        slope, icept, _ = ols(xs, [TARGET_FN(rows[b]) for b in bs])
        if slope is None:
            continue
        drift = icept / control if control else float("nan")
        e = [ergs.get(b) for b in bs]
        if all(v is not None for v in e) and xs[-1] != xs[0]:
            epu = (e[-1] - e[0]) / (xs[-1] - xs[0])
            reach = (BATCH_ERG_BUDGET * cur.get(ax, 0) / epu / CEILING
                     if epu else float("nan"))
        else:
            epu = reach = float("nan")
        flag = "" if 0.9 <= drift <= 1.1 else "  <-- INTERCEPT DRIFT"
        print(f"{fam:<16}{icept:>16,.0f}{drift:>11.2f}x{epu:>13,.1f}{reach:>10.2f}x{flag}")
    fell_back = [a for a in gross_slope
                 if abs(cur.get(a, 0) - max(gross_slope[a])) < 0.5
                 and any(n <= 0 for n in [family_rate(fams, f, rows, cur,
                                                      {**cur, **ATTRIB_OVERRIDE})[2]
                                          for f in fams if fams[f][1] == a]
                         if n is not None)]
    if fell_back:
        print(f"\n⚠️  netted to <= 0, so priced at the GROSS slope instead: {fell_back}")
        print("    The companions these ops always appear with account for the whole\n"
              "    slope at their own rates, so attribution cannot resolve them. Gross\n"
              "    is provably >= the true marginal, and pricing them at zero instead\n"
              "    under-predicted contract deployment by 23.5%.")

    print("\nrates:")
    for ax in sorted(cur):
        print(f"  {ax:<28}{cur[ax]:>16,.1f}")

    if args.emit:
        # Only axes an actual family derived. `--seed` pre-loads the whole table so the
        # fixed point has somewhere to start, but an axis with no family here keeps its
        # seeded value untouched -- and the seed is a table of EFFECTIVE rates. Emitting
        # those under a `--target raw` or `--target keccak` heading would hand the reader
        # an effective rate labelled as a delegation count, which is how a reconstruction
        # check first produced nonsense (bounded axes came out 25x too large).
        derived_axes = {ax for _, ax in fams.values()}
        Path(args.emit).write_text(json.dumps(
            {"target": args.target,
             "rates": {k: round(v, 1) for k, v in sorted(cur.items()) if k in derived_axes},
             "not_derived": sorted(set(cur) - derived_axes)},
            indent=1) + "\n")
        print(f"\nwrote derived rates to {args.emit}")

    if args.organic:
        org = json.loads(Path(args.organic).read_text())
        b0 = min(org, key=TARGET_FN)
        base = TARGET_FN(b0) - sum(
            cur.get(k, 0) * v for k, v in feature_counts(b0).items())
        errs = sorted(
            100 * ((base + sum(cur.get(k, 0) * v for k, v in feature_counts(r).items()))
                   - TARGET_FN(r)) / TARGET_FN(r) for r in org)
        print(f"\nbase {base:,.0f} (smallest batch minus its own priced ops)")
        print(f"OUT-OF-SAMPLE on {len(org)} organic batches -- none of them was used "
              f"above:")
        print(f"  MAPE {sum(abs(x) for x in errs) / len(errs):.2f}%   "
              f"min {errs[0]:+.2f}%   max {errs[-1]:+.2f}%   "
              f"under {sum(1 for x in errs if x < 0)}/{len(errs)}")
        need = 1 / (1 + errs[0] / 100)
        print(f"\n  Worst under-prediction {errs[0]:+.2f}% => margin must exceed "
              f"{need:.4f}.")
        print("\n  Do NOT reach for 'model fidelity' if this number is large. Every "
              "feature in\n  organic traffic correlates ~0.85 with the residual, so a "
              "single-feature\n  regression cannot attribute it and the shortfall LOOKS "
              "irreducible. It was\n  not: an 8.8% version of this residual turned out "
              "to be one axis priced at\n  zero (`arith_ptr_op`), found by testing "
              "synthetic families rather than by\n  staring at organic correlations. "
              "Check the isolation corpus for a shape whose\n  ratio is an outlier "
              "before concluding the model is at its limit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
