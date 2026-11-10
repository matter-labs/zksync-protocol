#!/usr/bin/env python3
"""Build both Rust test fixtures from measured datasets.

Why one script for both. `fixtures/adversarial.json` became a build product of the
isolation corpus for a good reason -- its predecessor was nine hand-maintained rows
whose batch inputs were never committed, so eight went stale on the pre-delegation
guest and could not be refreshed. `fixtures/measured_corpus.json` had exactly the
same problem and nobody noticed, because it is the *regression* fixture rather than
the safety one: it had no generator at all. A fixture you cannot regenerate is a
fixture that silently ages away from the guest it claims to describe, and which of
the two tests it feeds does not change that.

So both are emitted here, from `cycle_bench` output, and neither is edited by hand.

Rows carry their `delegations` counts so that a revision of `DELEGATION_WEIGHTS` can
RE-SCALE these actuals instead of invalidating them. The fixture this replaced stored
only `effective_cycles`, which is why a delegation-weight sensitivity sweep once
compared a re-weighted model against a w=16 actual and produced margins that did not
mean what they appeared to.

Usage:
    python scripts/cycle_model/build_fixtures.py \\
        --organic artifacts/redesign/organic.json \\
        --isolation artifacts/redesign/isolation.json \\
        --manifest testdata/cycle_model/isolation_manifest.json \\
        --guest "delegation guest, app.bin sha256 8b9436a8..., measured 2026-08-21" \\
        --out-dir crates/cycle_estimator/tests/fixtures
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measurement import DELEGATION_WEIGHTS, effective_cycles, feature_counts  # noqa: E402


def row(r, guest, label=None):
    out = {"batch_number": r["batch_number"]}
    if label:
        out["label"] = label
    out["raw_cycles"] = int(r["raw_cycles"])
    # Precomputed so the Rust tests need not know the delegation weights -- but see
    # `delegations` below, which is what makes a weight revision recoverable.
    out["effective_cycles"] = int(effective_cycles(r))
    out["guest"] = guest
    out["delegations"] = {str(k): int(v) for k, v in (r.get("delegations") or {}).items()}
    out["delegation_weights"] = dict(DELEGATION_WEIGHTS)
    out["features"] = {"counts": feature_counts(r)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--organic", required=True, help="measured organic dataset.json")
    ap.add_argument("--isolation", required=True,
                    help="measured dataset.json covering the isolation batches")
    ap.add_argument("--manifest", required=True,
                    help="isolation manifest (batch -> label/family/adversarial)")
    ap.add_argument("--guest", required=True,
                    help="human identity of the guest these were measured on; recorded "
                         "per row so a mixed-vintage fixture is visible")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)

    organic = json.loads(Path(args.organic).read_text())
    corpus = [row(r, args.guest) for r in sorted(organic, key=lambda r: r["batch_number"])]
    (out_dir / "measured_corpus.json").write_text(json.dumps(corpus, indent=1) + "\n")
    print(f"Wrote measured_corpus.json: {len(corpus)} organic batches")

    iso = {r["batch_number"]: r for r in json.loads(Path(args.isolation).read_text())}
    manifest = json.loads(Path(args.manifest).read_text())
    adv, missing = [], []
    for entry in manifest:
        if not entry.get("adversarial"):
            continue
        b = entry["batch_number"]
        if b not in iso:
            missing.append((b, entry["label"]))
            continue
        adv.append(row(iso[b], args.guest, entry["label"]))

    if missing:
        # Not a warning. A fixture missing a family silently retires that family's
        # invariant, and the test still passes -- which is the worst possible
        # combination for a safety fixture.
        raise SystemExit(
            "ERROR: the manifest marks these adversarial but the dataset has no "
            "measurement for them:\n"
            + "\n".join(f"  {b}  {lbl}" for b, lbl in missing)
            + "\nMeasure the whole isolation corpus before rebuilding, or drop the rows "
              "from the manifest deliberately -- do not let a family vanish quietly."
        )
    if not adv:
        raise SystemExit("ERROR: manifest marked no rows adversarial; nothing to build.")

    (out_dir / "adversarial.json").write_text(json.dumps(adv, indent=1) + "\n")
    print(f"Wrote adversarial.json: {len(adv)} rows")
    for r in adv:
        print(f"  {r['label']:<26} batch {r['batch_number']:<8} "
              f"effective {r['effective_cycles']:>16,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
