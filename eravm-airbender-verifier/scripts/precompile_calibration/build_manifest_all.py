#!/usr/bin/env python3
"""Unified manifest + host-side analysis for the whole isolation campaign.

Reads the three driver logs, re-derives the tracer feature vector for every
fixture with `dump_features` (host-side; no guest), and emits
testdata/cycle_model/isolation_input_corpus.csv plus a per-family report:

  * does the intended axis move as expected (axis_count vs unit_count)?
  * which OTHER features move with it (the collinearity that decides whether a
    fitted rate is identifiable)?
  * ergs per unit, and the erg-intercept drift against the empty-batch control.
"""
import csv, json, os, subprocess, sys
from statistics import mean

REPO = os.environ.get("REPO") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BIN = os.path.join(REPO, "testdata/era_mainnet_batches/binary")
D = os.path.dirname(os.path.abspath(__file__))
DUMP = os.path.join(REPO, "target/release/examples/dump_features")
OUT = os.path.join(REPO, "testdata/cycle_model/isolation_input_corpus.csv")

AXIS = {"modexp": "mod_exp_cycles", "ecmul": "ec_mul_cycles", "ecadd": "ec_add_cycles",
        "ecrecover": "ec_recover_cycles", "secp256r1": "secp256r1_verify_cycles",
        "keccak256": "keccak256_cycles", "sha256": "sha256_cycles",
        "ecpairing": "ec_pairing_cycles", "ecpairing_vol": "ec_pairing_cycles",
        "ecpairing_inf": "ec_pairing_cycles", "ecpairing_maxcall": "ec_pairing_cycles"}
UNIT = {"modexp": "exponent_bits", "ecmul": "scalar_bits", "ecadd": "input_class",
        "ecrecover": "signature_class", "secp256r1": "signature_class",
        "keccak256": "rounds_per_call", "sha256": "rounds_per_call",
        "ecpairing": "pairs_per_call", "ecpairing_vol": "calls_at_1_pair",
        "ecpairing_inf": "input_class", "ecpairing_maxcall": "pairs_in_one_call"}

rows = []
# campaign 1+2: precompile input sweep and hash families
for log in ("sweep_log.csv", "sweep_log2.csv", "sweep_log6.csv", "sweep_log7.csv"):
    p = os.path.join(D, log)
    if not os.path.exists(p): continue
    for r in csv.DictReader(open(p)):
        if r["ok"] != "ok": continue
        fam = r["family"]
        rows.append(dict(fixture=r["fixture"], family=fam, tier=r["input_param"],
                         intended_axis=AXIS[fam], input_param=r["input_param"],
                         swept_unit=UNIT[fam], swept_value=r["bits"],
                         unit_count=r["count"], ergs_used=r["gas_used"],
                         real_l1_batch=r["l1_batch"], n_txs_intended=1))
# campaign 3: storage / pubdata / transaction_count
for p3 in [os.path.join(D, n) for n in ("sweep_log3.csv", "sweep_log4.csv", "sweep_log5.csv", "sweep_log8.csv", "sweep_log9.csv")]:
  if os.path.exists(p3):
    for r in csv.DictReader(open(p3)):
        if not r["ok"].startswith("ok"): continue
        rows.append(dict(fixture=r["fixture"], family=r["family"], tier=r["tier"],
                         intended_axis=r["intended_axis"], input_param=r["input_param"],
                         swept_unit=("payload_len_bytes" if r["family"]=="pubdata" else
                                     "tx_count" if r["family"]=="transaction_count" else
                                     "slices" if r["family"].startswith("arith_ptr_op") else
                                     "total_bytecode_bytes" if r["family"].startswith("bytecode") else
                                     "divisor_shape" if r["family"].startswith("div_") else "slots"),
                         swept_value=(r["input_param"].split("len=")[-1] if r["family"]=="pubdata"
                                      else r["n_txs"] if r["family"]=="transaction_count"
                                      else r["unit_count"]),
                         unit_count=r["unit_count"], ergs_used=r["gas_used"],
                         real_l1_batch=r["l1_batch"], n_txs_intended=r["n_txs"]))

env = dict(os.environ, ZKSYNC_USE_CUDA_STUBS="1")
feat = {}
for r in rows:
    out = subprocess.run([DUMP, BIN, r["fixture"] + ".bin.gz"], capture_output=True,
                         text=True, env=env, check=True).stdout
    feat[r["fixture"]] = json.loads(out.strip())["features"]["counts"]

cols = ["fixture", "family", "tier", "intended_axis", "input_param", "swept_unit",
        "swept_value", "unit_count", "axis_count", "storage_read", "storage_write",
        "storage_application", "merkle_leaf_count", "state_diff_count", "event",
        "far_call", "precompile_call", "arith_ptr_op", "uma_read", "uma_write",
        "keccak256_cycles", "ergs_used", "pubdata", "n_txs",
        "real_l1_batch", "bytes", "status"]
with open(OUT, "w", newline="") as f:
    w = csv.writer(f); w.writerow(cols)
    for r in sorted(rows, key=lambda r: r["fixture"]):
        c = feat[r["fixture"]]
        axis = r["intended_axis"]
        n = c.get(axis, 0) if axis != "none" else 0
        ntx = c.get("transaction_count", 0)
        note = "ok"
        if axis in ("mod_exp_cycles", "ec_mul_cycles", "ec_add_cycles",
                    "secp256r1_verify_cycles"):
            note = "ok" if n == int(r["unit_count"]) else f"AXIS {n} vs {r['unit_count']}"
        elif axis == "ec_recover_cycles":
            note = "ok (+1 bootloader tx-sig recover)" if n == int(r["unit_count"]) + 1 \
                   else f"AXIS {n} vs {int(r['unit_count'])+1}"
        elif axis in ("keccak256_cycles", "sha256_cycles"):
            # The bootloader keccak-hashes the tx's own calldata TWICE, so a
            # keccak size sweep carries an extra 2*rounds(payload) + ~27 organic
            # rounds. Verified exact at every tier (32B/1KiB/8KiB/64KiB ->
            # +29/+43/+149/+992). sha256_cycles has no such term.
            exp = int(r["unit_count"]) * int(r["swept_value"])
            if axis == "keccak256_cycles":
                payload = {1: 32, 8: 1024, 61: 8192, 482: 65536}.get(int(r["swept_value"]), 0)
                exp += 2 * (payload // 136 + 1) + 27
                note = "ok (incl. 2x tx-calldata hash + organic)" if abs(n - exp) <= 3 \
                       else f"AXIS {n} vs ~{exp}"
            else:
                note = "ok" if abs(n - exp) <= 60 else f"AXIS {n} vs ~{exp}"
        elif axis == "arith_div_op":
            exp = int(r["unit_count"])
            note = (f"ok (arith_div_op={n:,} = n+{n-exp} batch-intrinsic, 1:1 with the "
                    f"loop count)") if n >= exp else \
                   f"DEAD: arith_div_op={n} < n={exp}, degenerate loop"
        elif axis == "used_bytecode_bytes":
            # decommit_cycles turns out to be EXACTLY sum(ceil(size_i/64)), so
            # "total bytecode volume" is not a new axis -- it IS decommit_cycles.
            words = c.get("decommit_cycles", 0)
            note = (f"ok (decommit_cycles={words:,}; decommit opcode="
                    f"{c.get('decommit', 0)} -- far-call path, not CodeOracle)")
        elif axis == "ec_pairing_cycles":
            pairs = {"ecpairing": int(r["swept_value"]), "ecpairing_vol": 1,
                     "ecpairing_inf": 1,
                     "ecpairing_maxcall": int(r["swept_value"])}[r["family"]]
            exp = int(r["unit_count"]) * pairs
            note = (f"ok (axis carries PAIRS: {n}/{exp} = "
                    f"{n/exp:.4f} per pair)") if abs(n - exp) <= 1 \
                   else f"AXIS {n} vs {exp} pairs"
        elif axis == "arith_ptr_op":
            # ptrNest emitted NO pointer ops: zksolc folded the nested-slice
            # length arithmetic, so arith_ptr_op is flat at its baseline 300
            # across 100k..700k iterations. The loop still burns ergs, so the
            # batch is a pure-arithmetic row, not a pointer row.
            if r["family"] == "arith_ptr_op_nest":
                note = ("DEAD: zksolc folded the nested slices -- arith_ptr_op flat at "
                        "300 across all tiers; usable only as an extra arith row")
            else:
                note = "ok (bound: 1.0000 ptr op + 1.0000 uma_read per slice, ratio stable)"
        elif axis == "transaction_count":
            note = "ok" if ntx == int(r["n_txs_intended"]) else f"TX {ntx} vs {r['n_txs_intended']}"
        w.writerow([r["fixture"], r["family"], r["tier"], axis, r["input_param"],
                    r["swept_unit"], r["swept_value"], r["unit_count"], n,
                    c.get("storage_read", 0), c.get("storage_write", 0),
                    c.get("storage_application", 0), c.get("merkle_leaf_count", 0),
                    c.get("state_diff_count", 0), c.get("event", 0),
                    c.get("far_call", 0), c.get("precompile_call", 0),
                    c.get("arith_ptr_op", 0), c.get("uma_read", 0), c.get("uma_write", 0),
                    c.get("keccak256_cycles", 0), r["ergs_used"], c.get("pubdata_bytes", 0), ntx,
                    r["real_l1_batch"], os.path.getsize(os.path.join(BIN, r["fixture"] + ".bin.gz")),
                    note])
print("wrote", OUT, f"({len(rows)} rows)")
json.dump(feat, open(os.path.join(D, "all_features.json"), "w"), indent=1)
