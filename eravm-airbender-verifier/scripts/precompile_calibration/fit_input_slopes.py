#!/usr/bin/env python3
"""Per-family OLS of guest cycles against the swept input variable.

Run AFTER measuring the 9003xx fixtures with the guest, e.g.

  cargo run --release -p zksync_cycle_model --bin cycle_bench -- \
      --batch-files $(ls testdata/era_mainnet_batches/binary/9003*.bin.gz | paste -sd,) \
      --app-bin-dir guest/dist/app --jobs 8 --out artifacts/prec_input_sweep

  python3 fit_input_slopes.py testdata/cycle_model/precompile_input_corpus.csv \
      artifacts/prec_input_sweep/dataset.json

Reports, per family: slope of effective cycles per call against the input
variable (exponent bits / scalar bits), the intercept (input-independent part),
R^2, and for the fixed-cost families the spread across input classes.
"""
import csv, json, sys
from statistics import mean

DELEG_WEIGHT = 4  # effective = raw + sum(delegations) * weight; adjust to the schema

man = {r["fixture"]: r for r in csv.DictReader(open(sys.argv[1]))}
ds = json.load(open(sys.argv[2]))
if isinstance(ds, dict):
    ds = ds.get("rows", ds.get("dataset", []))
meas = {}
for row in ds:
    b = str(row.get("batch_number"))
    raw = row.get("raw_cycles") or row.get("cycles")
    deleg = sum(row.get("delegations", {}).values())
    meas[b] = dict(raw=raw, effective=raw + DELEG_WEIGHT * deleg)

def ols(xs, ys):
    n = len(xs); mx, my = mean(xs), mean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0: return None
    b = sxy / sxx; a = my - b * mx
    ss_t = sum((y - my) ** 2 for y in ys)
    ss_r = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    return b, a, (1 - ss_r / ss_t if ss_t else float("nan"))

fams = {}
for fx, r in man.items():
    if fx not in meas: continue
    fams.setdefault(r["family"], []).append((r, meas[fx]))

for fam, rows in sorted(fams.items()):
    print(f"\n=== {fam} ({len(rows)} fixtures)")
    per_call = []
    for r, m in sorted(rows, key=lambda t: int(t[0]["input_bits"])):
        pc = m["effective"] / int(r["call_count"])
        per_call.append((int(r["input_bits"]), pc, r))
        print(f"  {r['fixture']}  {r['input_param']:24s} bits={r['input_bits']:>4}"
              f"  calls={r['call_count']:>6}  eff={m['effective']:>15,}  per_call={pc:>12,.0f}")
    bits = [b for b, _, _ in per_call]
    if len(set(bits)) > 1:
        b, a, r2 = ols(bits, [p for _, p, _ in per_call])
        print(f"  slope = {b:,.1f} cycles/call/bit   intercept = {a:,.0f} cycles/call   R^2 = {r2:.5f}")
    else:
        vals = [p for _, p, _ in per_call]
        lo, hi = min(vals), max(vals)
        print(f"  input classes: per-call {lo:,.0f} .. {hi:,.0f}  spread = {100*(hi-lo)/lo:.2f}%"
              f"  -> {'INPUT-INDEPENDENT' if (hi-lo)/lo < 0.02 else 'INPUT-DEPENDENT'}")
