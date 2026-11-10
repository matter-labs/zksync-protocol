#!/usr/bin/env bash
# Drive the local era node to produce precompile-calibration batches, export each
# sealed batch's airbender proof input, and convert it to a .bin.gz fixture.
#
# Two families:
#   - ISOLATED (one precompile per batch, varying load) -> fit coefficients
#   - COMBINED (mixed precompiles per batch)            -> held-out estimator test
#
# Representative (non-tiny) batches come from a BURST of txs fired into one
# ~15s state-keeper window (per-tx caps at ~10k modexp calls / ~77M gas).
#
# Prereqs: era node up (:3050 RPC, :4320 airbender handler) with a loosened
# block_commit_deadline_ms (~15s) and raised gas/circuit caps; PrecompileHammer
# deployed; a funded L2 account. See README.md.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
RPC="${RPC:-http://localhost:3050}"
HANDLER="${HANDLER:-http://localhost:4320}"
# Default: the era-test-node standard rich-wallet dev key — publicly documented,
# local-only funds. Override KEY for any other setup.
KEY="${KEY:-0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110}"
HAMMER="${HAMMER:?set HAMMER to the deployed PrecompileHammer address}"
OUT="${OUT:-$DIR/fixtures}"; mkdir -p "$OUT"
GASLIM="${GASLIM:-120000000}"      # per-tx gas limit passed to cast (the node's own execution caps bind first)
SEAL_WAIT="${SEAL_WAIT:-22}"       # > block_commit_deadline_ms so the burst's batch seals
CONVERT=(cargo run --release -q --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p zksync_cycle_model --example encode_batch --)
export PATH="$HOME/.foundry/bin:$PATH"

# Read a gen_inputs.py vector, failing fast if it is missing (an empty input
# would make the precompile trivially succeed and calibrate the wrong thing).
hexfile() {
  local f="$DIR/$1.hex"
  [[ -s "$f" ]] || { echo "missing $f — run gen_inputs.py first" >&2; exit 1; }
  cat "$f"
}

SENDER="${SENDER_ADDR:-0x36615Cf349d7F6344891B1e7CA7C72883F5dc049}"
# Monotonic local nonce so a burst of `--async` txs all land (fetching the nonce
# per-tx collides since none have confirmed yet). Fetched once, incremented per send.
NONCE=$(cast nonce "$SENDER" --rpc-url "$RPC" 2>/dev/null)
[[ -n "$NONCE" ]] || { echo "failed to fetch nonce for $SENDER — node down / cast missing?" >&2; exit 1; }
# snd <sig> [args...] — one async tx with the next sequential nonce. A failed
# send aborts the run: it would desync every later nonce and silently produce
# nothing.
snd() {
  cast send "$HAMMER" "$@" --private-key "$KEY" --rpc-url "$RPC" \
    --gas-limit "$GASLIM" --nonce "$NONCE" --async >/dev/null \
    || { echo "cast send failed (fn=$1 nonce=$NONCE) — aborting" >&2; exit 1; }
  NONCE=$((NONCE + 1))
}

manifest="$OUT/batches_manifest.csv"
echo "label,precompile,kind,l1_batch,fixture" > "$manifest"

# after a burst, wait for seal and export every newly-sealed batch in (b0, b1]
export_new() {  # b0 label kind precompile
  local b0="$1" label="$2" kind="$3" pc="$4"
  sleep "$SEAL_WAIT"
  local b1; b1=$(cast rpc zks_L1BatchNumber --rpc-url "$RPC" 2>/dev/null | tr -d '"')
  b1=$((b1)); local n
  for ((n=b0+1; n<=b1; n++)); do
    local json="$OUT/${label}_${n}.json" fix="$OUT/${n}.bin.gz"  # numeric name for resolve_batch_inputs
    if curl -sf "$HANDLER/airbender/proof_inputs_no_lock/$n" -o "$json" 2>/dev/null; then
      if "${CONVERT[@]}" "$json" "$fix" >/dev/null 2>&1; then
        echo "$label,$pc,$kind,$n,$(basename "$fix")" >> "$manifest"
        echo "  [$label] batch $n -> $(basename "$fix")"
        rm -f "$json"
      else echo "  [$label] batch $n: convert failed" >&2; fi
    else echo "  [$label] batch $n: export failed (not ready?)" >&2; fi
  done
}

cur() { local b; b=$(cast rpc zks_L1BatchNumber --rpc-url "$RPC" 2>/dev/null | tr -d '"'); echo $((b)); }

# fire n_txs async txs calling hammer.<fn>(args...), then export the batch(es)
isolated() {  # label precompile n_txs fn [fn-args...]
  local label="$1" pc="$2" n="$3" fn="$4"; shift 4
  echo "ISOLATED $label (fn=$fn txs=$n)"
  local b0 i; b0=$(cur)
  for ((i=0; i<n; i++)); do snd "$fn" "$@"; done
  export_new "$b0" "$label" isolated "$pc"
}

# ---- ISOLATED calibration batches (fit): wide range via count x input-size ----
# tiers ~ increasing total precompile load (n_txs x count), staying provable.
# modexp circuit supports <=32B operands only (>32B burnGas -> 0 cycles) and costs
# a FLAT 1 cycle/call, so range the feature via CALL COUNT with the light (<=32B) input.
LIGHT_MODEXP=$(hexfile modexp_light)
isolated modexp_s  modexp 1 'modexp(uint256,bytes)' 4000 "0x$LIGHT_MODEXP"   # ~4k calls
isolated modexp_m  modexp 3 'modexp(uint256,bytes)' 8000 "0x$LIGHT_MODEXP"   # ~24k
isolated modexp_l  modexp 8 'modexp(uint256,bytes)' 8000 "0x$LIGHT_MODEXP"   # ~64k
# deliberate replicate of modexp_l: a second ~64k point stabilizes the fit's top end
isolated modexp_xl modexp 8 'modexp(uint256,bytes)' 8000 "0x$LIGHT_MODEXP"   # ~64k

for tier in light medium heavy; do
  h=$(hexfile "sha256_${tier}")
  isolated "sha256_${tier}" sha256 6 'sha256_(uint256,bytes)' 5000 "0x$h"
done
# ec_pairing is ~6.6e7 cyc/pair, so the provable ceiling is only ~1000 pairs
# (2^36). Keep the sweep well under it — larger batches are unprovable AND far too
# slow to simulate. Use k=1 (light, 192B) and vary the pair count 100..900.
PAIR1=$(hexfile ecpairing_light)
isolated ecpairing_100 ecpairing 1 'ecPairing(uint256,bytes)' 100 "0x$PAIR1"  # ~100 pairs
isolated ecpairing_300 ecpairing 1 'ecPairing(uint256,bytes)' 300 "0x$PAIR1"  # ~300
isolated ecpairing_500 ecpairing 2 'ecPairing(uint256,bytes)' 250 "0x$PAIR1"  # ~500
isolated ecpairing_900 ecpairing 3 'ecPairing(uint256,bytes)' 300 "0x$PAIR1"  # ~900 (near ceiling)
ECADD=$(hexfile ecadd_fixed); ECMUL=$(hexfile ecmul_fixed); P256=$(hexfile secp256r1_fixed)
ECREC=$(hexfile ecrecover_fixed)
isolated ecadd_s ecadd 3 'ecAdd(uint256,bytes)' 4000 "0x$ECADD"
isolated ecadd_l ecadd 8 'ecAdd(uint256,bytes)' 8000 "0x$ECADD"
# ecrecover: organic batches carry ~one recover per tx (a near-constant column the
# organic fit cannot identify — see PrecompileHammer.ecRecover), so sweep it here
# over ~3 orders of magnitude. `ec_recover_cycles` is in PRECOMPILE_FEATURES and
# the fit ABORTS while this family is missing from the synthetic set.
isolated ecrecover_s ecrecover 1 'ecRecover(uint256,bytes)'  500 "0x$ECREC"   # ~500
isolated ecrecover_m ecrecover 3 'ecRecover(uint256,bytes)' 2000 "0x$ECREC"   # ~6k
isolated ecrecover_l ecrecover 8 'ecRecover(uint256,bytes)' 8000 "0x$ECREC"   # ~64k
isolated ecmul_s ecmul 3 'ecMul(uint256,bytes)' 4000 "0x$ECMUL"
isolated ecmul_l ecmul 8 'ecMul(uint256,bytes)' 8000 "0x$ECMUL"
# secp256r1 goes through the generic hammer(address,...) with the 0x100 precompile addr
P256_ADDR=0x0000000000000000000000000000000000000100
isolated p256_s secp256r1 2 'hammer(address,uint256,bytes)' "$P256_ADDR" 4000 "0x$P256"
isolated p256_l secp256r1 8 'hammer(address,uint256,bytes)' "$P256_ADDR" 8000 "0x$P256"

# ---- COMBINED batches (held-out estimator test): mixed precompiles per batch ----
combined() {  # label
  echo "COMBINED $1"
  local b0; b0=$(cur)
  # fire a mix of all precompiles into one window (sequential nonces => all land)
  snd 'modexp(uint256,bytes)'    6000 "0x$LIGHT_MODEXP"
  snd 'sha256_(uint256,bytes)'   6000 "0x$(hexfile sha256_medium)"
  snd 'ecPairing(uint256,bytes)'  400 "0x$PAIR1"
  snd 'ecAdd(uint256,bytes)'     6000 "0x$ECADD"
  snd 'ecMul(uint256,bytes)'     6000 "0x$ECMUL"
  snd 'ecRecover(uint256,bytes)' 6000 "0x$ECREC"
  snd 'hammer(address,uint256,bytes)' "$P256_ADDR" 6000 "0x$P256"
  export_new "$b0" "$1" combined mixed
}
combined combined_1
combined combined_2

echo "=== done; manifest: $manifest ==="; cat "$manifest"
