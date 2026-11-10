#!/usr/bin/env python3
"""Host-side per-family report: axis linearity, collinear partners, ergs/unit,
and the erg-intercept drift against the empty-batch control (900356).

The CYCLE-side equivalents (cycles/unit slope, R^2, and the cycle-intercept
drift the coordinator asked for) need the guest; fit_input_slopes.py does that
once a cycle_bench dataset.json exists. Everything here is host-side only.
"""
import csv, json, os, sys
from statistics import mean

REPO = os.environ.get("REPO") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
D = os.path.dirname(os.path.abspath(__file__))
man = list(csv.DictReader(open(REPO + "/testdata/cycle_model/isolation_input_corpus.csv")))
feat = json.load(open(os.path.join(D, "all_features.json")))
base = next((r for r in man if r["family"] == "baseline"), None)
base_ergs = int(base["ergs_used"]) if base else None

def ols(xs, ys):
    mx, my = mean(xs), mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0: return None
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    sst = sum((y - my) ** 2 for y in ys)
    ssr = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return b, a, (1 - ssr / sst if sst else float("nan"))

# group by (family, swept_unit) so a count sweep and a size sweep stay separate
groups = {}
for r in man:
    if r["family"] == "baseline": continue
    key = (r["family"], "count" if r["tier"].startswith("calls@") or r["swept_unit"] == "unit_count"
           else r["swept_unit"])
    groups.setdefault(key, []).append(r)

for (fam, unit), rows in sorted(groups.items()):
    print(f"\n=== {fam}  [swept: {unit}]  {len(rows)} fixtures")
    xs, ys = [], []
    for r in sorted(rows, key=lambda r: int(r["swept_value"] or 0)):
        # x = total units of the axis actually traced
        x = int(r["axis_count"]) if int(r["axis_count"]) else int(r["unit_count"])
        xs.append(x); ys.append(int(r["ergs_used"]))
        print(f"  {r['fixture']}  {r['input_param']:28s} axis={int(r['axis_count']):>9,}"
              f"  ergs={int(r['ergs_used']):>12,}  pubdata={int(r['pubdata']):>7,}"
              f"  ntx={r['n_txs']}  [{r['status']}]")
    if len(set(xs)) > 1:
        b, a, r2 = ols(xs, ys)
        print(f"  ergs vs axis units: {b:,.2f} ergs/unit  intercept {a:,.0f}  R^2 {r2:.5f}")
        if base_ergs:
            print(f"  erg-intercept drift vs empty-batch control ({base_ergs:,}): "
                  f"{a/base_ergs:.2f}x")
    # which other features move across the group
    keys = sorted({k for r in rows for k in feat[r["fixture"]]})
    movers = []
    for k in keys:
        v = [feat[r["fixture"]].get(k, 0) for r in rows]
        lo, hi = min(v), max(v)
        if hi != lo:
            movers.append((k, lo, hi, (hi - lo) / max(lo, 1)))
    movers.sort(key=lambda t: -t[3])
    print(f"  features that MOVE ({len(movers)} of {len(keys)}):")
    for k, lo, hi, rel in movers:
        print(f"    {k:26s} {lo:>12,} .. {hi:>12,}   x{hi/max(lo,1):.1f}")
    if not movers:
        print("    NONE -- the whole host-side feature vector is invariant")
