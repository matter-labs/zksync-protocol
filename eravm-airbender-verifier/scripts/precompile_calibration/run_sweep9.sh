#!/usr/bin/env bash
# storage_read / storage_write / pubdata_bytes / transaction_count families,
# plus the decoupling probes and a matched empty-batch control.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
RPC=${RPC:-http://localhost:3050}
HANDLER=${HANDLER:-http://localhost:4320}
S=${DIVH:-0xB5D57Fbb2F9128dC2874763d5fD6686Bc1A0ea5a}
# Default: the era-test-node standard rich-wallet dev key -- publicly documented,
# local-only funds. Override KEY for any other setup.
KEY="${KEY:-0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110}"
SENDER=${SENDER:-0x97d2a9f132bd5d74c11c2f12e6c9cfa43febc379}
D="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$D/../.." && pwd)}"
BIN="$REPO/testdata/era_mainnet_batches/binary"
LOG="$D/sweep_log9.csv"
ONLY="${ONLY:-}"
PUBDATA_ABORT=${PUBDATA_ABORT:-330000}
[[ -f "$LOG" ]] || echo "fixture,family,tier,intended_axis,input_param,unit_count,n_txs,l1_batch,gas_used,pubdata,ok" > "$LOG"
CONVERT=("$REPO/target/release/examples/encode_batch")
DUMP="$REPO/target/release/examples/dump_features"

# export + convert batch $1 into fixture $2; echoes pubdata_bytes
finish() { # bn fixture
  local bn=$1 fx=$2 json="$D/pi9_$1.json" i cur ok=no
  for ((i=0;i<90;i++)); do
    cur=$(cast rpc zks_L1BatchNumber --rpc-url "$RPC" 2>/dev/null | tr -d '"'); cur=$((cur))
    [[ $cur -ge $bn ]] && break
    sleep 2
  done
  for ((i=0;i<40;i++)); do
    curl -sf "$HANDLER/airbender/proof_inputs_no_lock/$bn" -o "$json" && { ok=yes; break; }
    sleep 3
  done
  [[ $ok == yes ]] || { echo "EXPORT_FAIL"; return 1; }
  "${CONVERT[@]}" "$json" "$BIN/$fx.bin.gz" >/dev/null 2>&1 || { echo "CONVERT_FAIL"; return 1; }
  rm -f "$json"
  ZKSYNC_USE_CUDA_STUBS=1 "$DUMP" "$BIN" "$fx.bin.gz" | python3 -c "
import sys,json; print(json.loads(sys.stdin.read())['features']['counts'].get('pubdata_bytes',0))"
}

# one <fixture> <family> <tier> <axis> <input_param> <unit_count> <sig> [args...]
one() {
  local fx=$1 fam=$2 tier=$3 axis=$4 ip=$5 units=$6 sig=$7; shift 7
  if [[ -n "$ONLY" && "$ONLY" != *"$fx"* ]]; then return 0; fi
  grep -q "^$fx," "$LOG" && { echo "[$fx] done, skip"; return 0; }
  echo "=== [$fx] $fam $tier  $sig $*"
  local o hash
  o=$(cast send "$S" "$sig" "$@" --private-key "$KEY" --rpc-url "$RPC" --gas-limit 120000000 --json 2>&1)
  hash=$(echo "$o" | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('transactionHash') or '')
except Exception: print('')")
  [[ -n "$hash" ]] || { echo "  SEND_FAIL $(echo "$o"|tail -2)"; echo "$fx,$fam,$tier,$axis,$ip,$units,,,,,SEND_FAIL" >> "$LOG"; return 1; }
  local batch gas status i j
  for ((i=0;i<90;i++)); do
    j=$(cast rpc eth_getTransactionReceipt "$hash" --rpc-url "$RPC" 2>/dev/null)
    read -r batch gas status <<<"$(echo "$j" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin) or {}; b=d.get('l1BatchNumber')
  print(int(b,16) if b else '-', int(d.get('gasUsed','0x0'),16), d.get('status',''))
except Exception: print('-','0','')")"
    [[ "$batch" != "-" ]] && break
    sleep 2
  done
  [[ "$batch" != "-" ]] || { echo "  NO_BATCH"; echo "$fx,$fam,$tier,$axis,$ip,$units,,,,,NO_BATCH" >> "$LOG"; return 1; }
  echo "  batch=$batch gas=$gas status=$status"
  [[ "$status" == "0x1" ]] || { echo "  REVERTED"; echo "$fx,$fam,$tier,$axis,$ip,$units,1,$batch,$gas,,REVERTED" >> "$LOG"; return 1; }
  local pd; pd=$(finish "$batch" "$fx") || { echo "$fx,$fam,$tier,$axis,$ip,$units,1,$batch,$gas,,$pd" >> "$LOG"; return 1; }
  echo "  -> $fx.bin.gz pubdata=$pd"
  echo "$fx,$fam,$tier,$axis,$ip,$units,1,$batch,$gas,$pd,ok" >> "$LOG"
  if [[ "$pd" =~ ^[0-9]+$ && $pd -gt $PUBDATA_ABORT ]]; then
    echo "!!! pubdata $pd > $PUBDATA_ABORT — ABORTING the run to protect the state keeper" >&2; exit 9
  fi
}

# burst <fixture> <family> <tier> <axis> <input_param> <units> <ntx> <sig> <arg>
# k async txs with sequential nonces so they land in ONE batch.
burst() {
  local fx=$1 fam=$2 tier=$3 axis=$4 ip=$5 units=$6 ntx=$7 sig=$8 arg=$9
  if [[ -n "$ONLY" && "$ONLY" != *"$fx"* ]]; then return 0; fi
  grep -q "^$fx," "$LOG" && { echo "[$fx] done, skip"; return 0; }
  echo "=== [$fx] $fam $tier  ${ntx}x $sig $arg"
  local n0 i last=""
  n0=$(cast nonce "$SENDER" --rpc-url "$RPC")
  for ((i=0;i<ntx;i++)); do
    last=$(cast send "$S" "$sig" "$arg" --private-key "$KEY" --rpc-url "$RPC" \
           --gas-limit 20000000 --nonce $((n0+i)) --async 2>&1 | tail -1)
  done
  local batch gas status j
  for ((i=0;i<90;i++)); do
    j=$(cast rpc eth_getTransactionReceipt "$last" --rpc-url "$RPC" 2>/dev/null)
    read -r batch gas status <<<"$(echo "$j" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin) or {}; b=d.get('l1BatchNumber')
  print(int(b,16) if b else '-', int(d.get('gasUsed','0x0'),16), d.get('status',''))
except Exception: print('-','0','')")"
    [[ "$batch" != "-" ]] && break
    sleep 2
  done
  [[ "$batch" != "-" ]] || { echo "  NO_BATCH"; echo "$fx,$fam,$tier,$axis,$ip,$units,$ntx,,,,NO_BATCH" >> "$LOG"; return 1; }
  echo "  batch=$batch (last tx) status=$status"
  local pd; pd=$(finish "$batch" "$fx") || { echo "$fx,$fam,$tier,$axis,$ip,$units,$ntx,$batch,,,$pd" >> "$LOG"; return 1; }
  local ntx_real; ntx_real=$(ZKSYNC_USE_CUDA_STUBS=1 "$DUMP" "$BIN" "$fx.bin.gz" | python3 -c "
import sys,json; print(json.loads(sys.stdin.read())['features']['counts'].get('transaction_count',0))")
  echo "  -> $fx.bin.gz pubdata=$pd transaction_count=$ntx_real (intended $ntx)"
  echo "$fx,$fam,$tier,$axis,$ip,$units,$ntx_real,$batch,,$pd,$([[ $ntx_real == $ntx ]] && echo ok || echo "TX_SPLIT: got $ntx_real of $ntx")" >> "$LOG"
}

# ---- storage_read: COLD, distinct unseeded slots -----------------------------
arr() { python3 -c "
import json;print('['+','.join(json.load(open('$D/targets.json'))['sets']['$1']['addrs'])+']')"; }
NUM0=$(python3 -c "print(((1<<256)-1) & ~0xffffffff)")
den() { python3 -c "
import sys
s={'lead1_2limb':(1<<64)|1,'lead3_2limb':(3<<64)|((1<<64)-1),
   'lead1_3limb':(1<<128)|1,'lead1_4limb':(1<<192)|1,'small_1limb':3}
print(s['$1'])"; }

# HARD AXIS GUARD: the family this replaces looked healthy on ergs while
# arith_div_op sat flat. Verify the tracer axis equals the loop count for every
# fixture and abort the run otherwise, rather than reporting a slope from a
# degenerate loop. Also verify the contract's own in-loop nonzero counter.
divcheck() { # fixture n
  local fx=$1 n=$2 ax nz
  ax=$(ZKSYNC_USE_CUDA_STUBS=1 "$DUMP" "$BIN" "$fx.bin.gz" | python3 -c "
import sys,json; print(json.loads(sys.stdin.read())['features']['counts'].get('arith_div_op',0))")
  nz=$(cast call "$S" 'nonzero()' --rpc-url "$RPC" | python3 -c "import sys;print(int(sys.stdin.read().strip(),16))")
  echo "    arith_div_op=$ax (loop n=$n, +35 batch-intrinsic expected)  in-loop nonzero=$nz"
  if [[ $ax -lt $n ]]; then
    echo "!!! [$fx] AXIS DID NOT SCALE: arith_div_op=$ax < n=$n -- DEGENERATE LOOP, aborting" >&2; exit 8
  fi
  if [[ $nz -ne $n ]]; then
    echo "!!! [$fx] SELF-CHECK FAILED: nonzero=$nz != n=$n -- operands degenerated, aborting" >&2; exit 8
  fi
}

divtier() { # fixture shape n
  local fx=$1 shape=$2 n=$3 d
  if [[ -n "$ONLY" && "$ONLY" != *"$fx"* ]]; then return 0; fi
  grep -q "^$fx," "$LOG" && { echo "[$fx] done, skip"; return 0; }
  d=$(den "$shape")
  one "$fx" "div_$shape" "n$n" arith_div_op "shape=${shape}_n=${n}" "$n" \
      'divLoop(uint256,uint256,uint256)' "$NUM0" "$d" "$n" || return 1
  divcheck "$fx" "$n"
}

# 4-limb dividend throughout (NUM0 has its top 224 bits set, low 32 varied by the
# loop counter). 53.93 ergs/iter measured, so 1.3M is the largest tier that fits
# under the ~77.5M single-tx ceiling.
divtier 900390 lead1_2limb 300000
divtier 900391 lead1_2limb 700000
divtier 900392 lead1_2limb 1300000
divtier 900393 lead3_2limb 300000
divtier 900394 lead3_2limb 700000
divtier 900395 lead3_2limb 1300000
divtier 900396 lead1_3limb 300000
divtier 900397 lead1_3limb 700000
divtier 900398 lead1_3limb 1300000
divtier 900399 lead1_4limb 300000
divtier 900400 lead1_4limb 700000
divtier 900401 lead1_4limb 1300000
divtier 900402 small_1limb 300000
divtier 900403 small_1limb 700000
divtier 900404 small_1limb 1300000
# matched control: identical tx shape, zero divisions
one 900405 div_ctrl n0 arith_div_op "shape=none_n=0" 0 'divLoop(uint256,uint256,uint256)' "$NUM0" 3 0
echo "=== log ==="; cat "$LOG"
