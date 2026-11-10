#!/usr/bin/env python3
"""Build the input-sweep manifest CSV from the driver log + host-side tracer features.

Shape follows testdata/cycle_model/decommit_corpus.csv, plus `input_param`
(the swept quantity) and `input_bits` (its bit length).
"""
import csv, json, os, subprocess, sys

REPO = os.environ.get("REPO") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BIN = os.path.join(REPO, "testdata/era_mainnet_batches/binary")
D = os.path.dirname(os.path.abspath(__file__))
AXIS = {"modexp": "mod_exp_cycles", "ecmul": "ec_mul_cycles", "ecadd": "ec_add_cycles",
        "ecrecover": "ec_recover_cycles", "secp256r1": "secp256r1_verify_cycles"}
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    REPO, "testdata/cycle_model/precompile_input_corpus.csv")

rows = list(csv.DictReader(open(os.path.join(D, "sweep_log.csv"))))
rows = [r for r in rows if r["ok"] == "ok"]
fixtures = [r["fixture"] for r in rows]
env = dict(os.environ, ZKSYNC_USE_CUDA_STUBS="1")
feat = {}
for fx in fixtures:
    p = subprocess.run([os.path.join(REPO, "target/release/examples/dump_features"), BIN,
                        f"{fx}.bin.gz"], capture_output=True, text=True, env=env, check=True)
    feat[fx] = json.loads(p.stdout.strip())["features"]["counts"]

cols = ["fixture", "family", "tier", "intended_axis", "input_param", "input_bits",
        "call_count", "axis_count", "far_call", "precompile_call", "ergs_used",
        "pubdata", "n_txs", "real_l1_batch", "bytes", "status"]
with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(cols)
    for r in rows:
        fx, fam = r["fixture"], r["family"]
        c = feat[fx]
        axis = AXIS[fam]
        n = c.get(axis, 0)
        # ecrecover: +1 per tx from the bootloader's own signature validation
        organic = 1 if fam == "ecrecover" else 0
        want = int(r["count"]) + organic
        status = ("ok" if organic == 0 else "ok (+1 bootloader tx-sig recover)") \
            if n == want else f"AXIS MISMATCH: {axis}={n} vs expected {want}"
        w.writerow([fx, fam, r["vector"], axis, r["input_param"], r["bits"],
                    r["count"], n, c.get("far_call", 0), c.get("precompile_call", 0),
                    r["gas_used"], c.get("pubdata_bytes", 0), c.get("transaction_count", 0),
                    r["l1_batch"], os.path.getsize(os.path.join(BIN, fx + ".bin.gz")), status])
print("wrote", OUT)
for line in open(OUT):
    print(line.rstrip())
