#!/usr/bin/env python3
"""Per-family cycle-rate fit for the whole isolation campaign.

Run AFTER measuring 900301-900356 with the guest:

  cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
      --batch-files $(ls testdata/era_mainnet_batches/binary/9003*.bin.gz | paste -sd,) \
      --app-bin-dir guest/dist/app --jobs 8 --out artifacts/isolation_input_sweep

  python3 fit_slopes.py testdata/cycle_model/isolation_input_corpus.csv \
      artifacts/isolation_input_sweep/dataset.json

Per family it reports the slope of effective cycles against the swept quantity,
R^2, and the INTERCEPT DRIFT: the fitted intercept over the expected intercept.

  * volume sweep (units vary from ~0): expected intercept = the 900356
    empty-batch control's cycles. Drift far from 1.0 means a second axis is
    scaling with yours.
  * fixed-count size sweep: expected intercept = control + (that family's
    per-call cost from its OWN count sweep) x the fixed call count. This
    cross-validates the two sweeps of one family against each other.
"""
import csv, json, sys
from statistics import mean

DELEG_WEIGHT = 4  # effective = raw + weight * sum(delegations); match the schema

man = list(csv.DictReader(open(sys.argv[1])))
ds = json.load(open(sys.argv[2]))
if isinstance(ds, dict):
    ds = ds.get("rows", ds.get("dataset", []))
meas = {}
for row in ds:
    raw = row.get("raw_cycles") or row.get("cycles")
    d = sum((row.get("delegations") or {}).values())
    meas[str(row.get("batch_number"))] = raw + DELEG_WEIGHT * d

def ols(xs, ys):
    mx, my = mean(xs), mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0: return None
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    sst = sum((y - my) ** 2 for y in ys)
    ssr = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return b, a, (1 - ssr / sst if sst else float("nan"))

ctrl = next((r for r in man if r["family"] == "baseline"), None)
base = meas.get(ctrl["fixture"]) if ctrl else None
if base: print(f"empty-batch control {ctrl['fixture']}: {base:,} effective cycles")

groups = {}
for r in man:
    if r["family"] == "baseline": continue
    groups.setdefault((r["family"], r["swept_unit"]), []).append(r)

per_call = {}   # family -> cycles/call from its count sweep, for the size-sweep check
for (fam, unit), rows in sorted(groups.items()):
    rows = [r for r in rows if r["fixture"] in meas]
    if not rows: continue
    print(f"\n=== {fam}  [swept: {unit}]")
    xs, ys = [], []
    for r in sorted(rows, key=lambda r: float(r["swept_value"] or 0)):
        x = int(r["axis_count"]) or int(r["unit_count"])
        y = meas[r["fixture"]]
        xs.append(x); ys.append(y)
        print(f"  {r['fixture']} {r['input_param']:28s} axis={x:>10,} eff={y:>16,}"
              f"  per_unit={y/max(x,1):>12,.0f}")
    if len(set(xs)) < 2:
        continue
    b, a, r2 = ols(xs, ys)
    print(f"  slope = {b:,.1f} cycles/unit   intercept = {a:,.0f}   R^2 = {r2:.5f}")
    if unit in ("count", "slots", "tx_count") and fam not in per_call:
        per_call[fam] = b
    exp = base
    if unit == "rounds_per_call" and fam in per_call:
        calls = int(rows[0]["unit_count"])
        exp = (base or 0) + per_call[fam] * calls
        print(f"  expected intercept = control + {per_call[fam]:,.0f}/call x {calls:,} calls"
              f" = {exp:,.0f}")
    if exp:
        print(f"  INTERCEPT DRIFT = {a/exp:.2f}x  "
              f"({'clean' if 0.8 <= a/exp <= 1.25 else 'A SECOND AXIS IS SCALING WITH THIS ONE'})")
