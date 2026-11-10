"""Shared helpers for reading a measured dataset and applying a cost table.

Everything here is about *measurement*: turning `cycle_bench` output into the
quantities the cost table is built from and checked against. There is deliberately
no fitting machinery — see `build_cost_table.py` for why the per-operation rates are
measured rather than inferred.
"""
import json
from pathlib import Path

# Native-computational weight per delegation, keyed by the airbender delegation CSR
# id recorded in the guest's `delegation_counter` (NON_DETERMINISM_CSR 0x7c0 = 1984
# plus an offset):
#   1991  Blake2 round function
#   1994  U256/bigint
#   1995  Keccak special5
#
# ⚠️ These weights have NO authoritative source in this tree. They are zksync-os
# values, and `native_cost_conversion.md` implies a delegation may cost ~40 cycles
# rather than 4–16, which is 2.5–10x away. The uncertainty matters: a third of an
# `ec_recover` is delegation cost, so a revision moves that entry by ~1.5x.
#
# It also matters that this collapses four resources into one scalar. Raw main-trace
# rows and the three delegation channels each have their own hard limit, they are
# maximised by three *different* batches in the corpus, and their ratios to raw
# cycles span up to 10^8 — so a weighted sum cannot rank batches by proximity to a
# limit. Predicting a resource vector instead would remove these weights entirely.
# Any id absent from this map raises, rather than being silently dropped.
DELEGATION_WEIGHTS = {"1991": 16, "1994": 4, "1995": 4}


def effective_cycles(row) -> float:
    """The target: main RISC-V cycles plus the weighted delegation-circuit cost the
    main trace does not account for. Fixture rows may carry it precomputed."""
    if "effective_cycles" in row:
        return float(row["effective_cycles"])
    total = 0
    for did, count in (row.get("delegations") or {}).items():
        if did not in DELEGATION_WEIGHTS:
            raise ValueError(
                f"batch {row['batch_number']}: unknown delegation id {did!r}. Add its "
                f"weight to DELEGATION_WEIGHTS — silently dropping it would under-count."
            )
        total += DELEGATION_WEIGHTS[did] * count
    return float(row["raw_cycles"] + total)


def raw_cycles(row) -> float:
    """Main-trace RISC-V cycles only, with no delegation weighting.

    Reported alongside `effective_cycles` so a consumer can compare the prediction
    against something the prover measures directly, rather than against a quantity that
    depends on DELEGATION_WEIGHTS — whose values have no authoritative source in this
    tree. A prediction the operator cannot check is a prediction nobody will trust.
    """
    return float(row["raw_cycles"])


def delegation_counts(row) -> dict:
    """Per-channel delegation counts, unweighted."""
    return {k: int(v) for k, v in (row.get("delegations") or {}).items()}


def feature_counts(row) -> dict:
    """The feature-count map of a dataset or fixture row (both layouts)."""
    f = row["features"]
    return f["counts"] if "counts" in f else f
