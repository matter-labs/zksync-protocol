#!/usr/bin/env python3
"""Compare the shipped cost table against a FRESHLY measured dataset.

This is the one check `cargo test` cannot do. `model_regression.rs` compares the
committed table against a committed fixture — both frozen — so it catches an
accuracy-worsening edit and nothing else. It cannot see the guest moving underneath
them: a predecessor of this table reached 2.05x over-prediction with that test green
throughout. Only re-measuring against a guest built from HEAD detects that, which is why
this runs nightly rather than in the test suite.

Replaces `eval_holdout.py`, which belonged to the deleted fitted pipeline (it reported
leave-one-out CV and an asymmetric-loss objective that no longer exist) and had been left
wired into the workflow after its script was removed, so the comparison step failed
outright.

Usage:
    python scripts/cycle_model/check_drift.py \\
        --cost-table crates/cycle_estimator/model/cost_table.json \\
        --dataset artifacts/drift/dataset.json \\
        --max-under-pct 3 --max-over-pct 20
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measurement import effective_cycles, feature_counts, raw_cycles  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cost-table", required=True)
    ap.add_argument("--dataset", required=True, help="freshly measured dataset.json")
    ap.add_argument("--max-under-pct", type=float, default=3.0,
                    help="the safety bound: under-prediction means a batch can seal and "
                         "then be unprovable")
    ap.add_argument("--max-over-pct", type=float, default=20.0,
                    help="over-prediction is safe but it is throughput; a jump usually "
                         "means the guest got faster and the table is now stale")
    args = ap.parse_args()

    table = json.loads(Path(args.cost_table).read_text())
    base, ops = table["base"], table["ops"]
    rows = json.loads(Path(args.dataset).read_text())
    if not rows:
        raise SystemExit("ERROR: dataset is empty; the measurement step produced nothing")

    def predict(feats, key, base_key):
        return base[base_key] + sum(e[key] * feats.get(k, 0) for k, e in ops.items())

    worst_under = worst_over = (None, 0.0)
    print(f"{'batch':>10}{'actual':>16}{'predicted':>16}{'error':>9}{'raw error':>11}")
    for r in sorted(rows, key=lambda r: r["batch_number"]):
        f = feature_counts(r)
        actual, pred = effective_cycles(r), predict(f, "cycles_per_unit", "cycles")
        raw_err = 100 * (predict(f, "raw_cycles_per_unit", "raw_cycles")
                         - raw_cycles(r)) / raw_cycles(r)
        err = 100 * (pred - actual) / actual
        print(f"{r['batch_number']:>10}{actual:>16,.0f}{pred:>16,.0f}"
              f"{err:>+8.2f}%{raw_err:>+10.2f}%")
        if -err > worst_under[1]:
            worst_under = (r["batch_number"], -err)
        if err > worst_over[1]:
            worst_over = (r["batch_number"], err)

    print(f"\nprovenance of the table under test: {table['provenance']}")
    print(f"worst under-prediction: batch {worst_under[0]} at {worst_under[1]:.2f}%")
    print(f"worst over-prediction:  batch {worst_over[0]} at {worst_over[1]:.2f}%")

    failed = False
    if worst_under[1] > args.max_under_pct:
        print(f"\nFAIL: batch {worst_under[0]} is under-predicted by {worst_under[1]:.2f}%, "
              f"past {args.max_under_pct}%. This is the unsafe direction: such a batch "
              f"seals and is then unprovable. The guest has moved; re-measure and refit.")
        failed = True
    if worst_over[1] > args.max_over_pct:
        print(f"\nFAIL: batch {worst_over[0]} is over-predicted by {worst_over[1]:.2f}%, "
              f"past {args.max_over_pct}%. Safe, but it is throughput given away and "
              f"usually means the guest got faster than the table.")
        failed = True
    if not failed:
        print("\nOK: the shipped table still describes the current guest.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
