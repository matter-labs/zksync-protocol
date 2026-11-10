#!/usr/bin/env bash
# storage_read / storage_write / pubdata_bytes / transaction_count families,
# plus the decoupling probes and a matched empty-batch control.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
RPC=${RPC:-http://localhost:3050}
HANDLER=${HANDLER:-http://localhost:4320}
S=${STORE:-0x41a58A7e84eF7D5D4b3e2368119f146bF4FA3CB3}
# Default: the era-test-node standard rich-wallet dev key -- publicly documented,
# local-only funds. Override KEY for any other setup.
KEY="${KEY:-0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110}"
SENDER=${SENDER:-0x97d2a9f132bd5d74c11c2f12e6c9cfa43febc379}
D="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$D/../.." && pwd)}"
BIN="$REPO/testdata/era_mainnet_batches/binary"
LOG="$D/sweep_log3.csv"
ONLY="${ONLY:-}"
PUBDATA_ABORT=${PUBDATA_ABORT:-330000}
[[ -f "$LOG" ]] || echo "fixture,family,tier,intended_axis,input_param,unit_count,n_txs,l1_batch,gas_used,pubdata,ok" > "$LOG"
CONVERT=(cargo run --release -q --manifest-path "$REPO/Cargo.toml" -p zksync_cycle_model --example encode_batch --)
DUMP="$REPO/target/release/examples/dump_features"

# export + convert batch $1 into fixture $2; echoes pubdata_bytes
finish() { # bn fixture
  local bn=$1 fx=$2 json="$D/pi3_$1.json" i cur ok=no
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
one 900335 storage_read cold_5k    storage_read "cold_distinct_slots=5000"  5000  'coldRead(uint256,uint256)' 10000000 5000
one 900336 storage_read cold_12k   storage_read "cold_distinct_slots=12000" 12000 'coldRead(uint256,uint256)' 11000000 12000
one 900337 storage_read cold_20k   storage_read "cold_distinct_slots=20000" 20000 'coldRead(uint256,uint256)' 12000000 20000
one 900338 storage_read cold_28k   storage_read "cold_distinct_slots=28000" 28000 'coldRead(uint256,uint256)' 13000000 28000
# ---- storage_read: WARM, one slot (decoupling probe) -------------------------
one 900339 storage_read_warm warm_20k storage_read "warm_same_slot=20000" 20000 'warmRead(uint256,uint256)' 5000000 20000
one 900340 storage_read_warm warm_60k storage_read "warm_same_slot=60000" 60000 'warmRead(uint256,uint256)' 5000000 60000
# ---- storage_write: distinct slots (ascending; pubdata-guarded) --------------
one 900341 storage_write w_500  storage_write "distinct_slots=500"  500  'write(uint256,uint256)' 20000000 500
one 900342 storage_write w_1500 storage_write "distinct_slots=1500" 1500 'write(uint256,uint256)' 21000000 1500
one 900343 storage_write w_3500 storage_write "distinct_slots=3500" 3500 'write(uint256,uint256)' 22000000 3500
one 900344 storage_write w_6000 storage_write "distinct_slots=6000" 6000 'write(uint256,uint256)' 23000000 6000
# ---- storage_write: one slot (decoupling probe) ------------------------------
one 900345 storage_write_same same_20k storage_write "same_slot=20000" 20000 'writeSame(uint256,uint256)' 6000000 20000
# ---- storage_read: COLD reads of NON-ZERO slots (written by 900344) ----------
one 900346 storage_read_seeded seeded_6k storage_read "cold_nonzero_slots=6000" 6000 'coldRead(uint256,uint256)' 23000000 6000
one 900347 storage_read empty_6k        storage_read "cold_empty_slots=6000"   6000 'coldRead(uint256,uint256)' 14000000 6000
# ---- pubdata_bytes WITHOUT storage writes: 20 L2->L1 messages, length swept --
# event/L2ToL1Message opcode count is held at 20 for all four, so pubdata moves
# alone (modulo the L1Messenger's own keccak over the payload -- reported).
for spec in "900348 32 payload_32" "900349 1024 payload_1024" "900350 6144 payload_6144" "900351 12288 payload_12288"; do
  read -r fx len vec <<<"$spec"
  one $fx pubdata "msg20_${len}B" pubdata_bytes "msgs=20,len=$len" $len \
      'msgFlood(uint256,bytes)' 20 "0x$(cat "$D/$vec.hex")"
done
# ---- transaction_count: 120,000 work iterations split over 1/3/6/12 txs ------
one   900352 transaction_count tx1  transaction_count "txs=1,iters_each=120000" 120000 'work(uint256)' 120000
burst 900353 transaction_count tx3  transaction_count "txs=3,iters_each=40000"  120000 3  'work(uint256)' 40000
burst 900354 transaction_count tx6  transaction_count "txs=6,iters_each=20000"  120000 6  'work(uint256)' 20000
burst 900355 transaction_count tx12 transaction_count "txs=12,iters_each=10000" 120000 12 'work(uint256)' 10000
# ---- matched empty-batch control --------------------------------------------
one 900356 baseline ctrl none "single_touch_tx" 1 'touch()'
echo "=== log ==="; cat "$LOG"
