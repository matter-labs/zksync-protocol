#!/usr/bin/env bash
# storage_read / storage_write / pubdata_bytes / transaction_count families,
# plus the decoupling probes and a matched empty-batch control.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
RPC=${RPC:-http://localhost:3050}
HANDLER=${HANDLER:-http://localhost:4320}
S=${SLOT:-0x77F2cA1A8Aa7bfc91Da579ECAE653dFDEbC278AA}
# Default: the era-test-node standard rich-wallet dev key -- publicly documented,
# local-only funds. Override KEY for any other setup.
KEY="${KEY:-0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110}"
SENDER=${SENDER:-0x97d2a9f132bd5d74c11c2f12e6c9cfa43febc379}
D="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$D/../.." && pwd)}"
BIN="$REPO/testdata/era_mainnet_batches/binary"
LOG="$D/sweep_log5.csv"
ONLY="${ONLY:-}"
PUBDATA_ABORT=${PUBDATA_ABORT:-330000}
[[ -f "$LOG" ]] || echo "fixture,family,tier,intended_axis,input_param,unit_count,n_txs,l1_batch,gas_used,pubdata,ok" > "$LOG"
CONVERT=("$REPO/target/release/examples/encode_batch")
DUMP="$REPO/target/release/examples/dump_features"

# export + convert batch $1 into fixture $2; echoes pubdata_bytes
finish() { # bn fixture
  local bn=$1 fx=$2 json="$D/pi5_$1.json" i cur ok=no
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


# ---- keccak-free storage: breaks storage_read <-> precompile_call -----------
one 900364 storage_read_raw raw_cold_8k  storage_read "raw_cold_distinct_slots=8000"  8000  'rawCold(uint256,uint256)' 30000000 8000
one 900365 storage_read_raw raw_cold_18k storage_read "raw_cold_distinct_slots=18000" 18000 'rawCold(uint256,uint256)' 31000000 18000
one 900366 storage_read_raw raw_cold_28k storage_read "raw_cold_distinct_slots=28000" 28000 'rawCold(uint256,uint256)' 32000000 28000
one 900367 storage_read_raw_warm raw_warm_60k  storage_read "raw_warm_same_slot=60000"  60000  'rawWarm(uint256,uint256)' 9000000 60000
one 900368 storage_read_raw_warm raw_warm_200k storage_read "raw_warm_same_slot=200000" 200000 'rawWarm(uint256,uint256)' 9000000 200000
one 900369 storage_write_raw raw_w_500  storage_write "raw_distinct_slots=500"  500  'rawWrite(uint256,uint256)' 40000000 500
one 900370 storage_write_raw raw_w_2000 storage_write "raw_distinct_slots=2000" 2000 'rawWrite(uint256,uint256)' 41000000 2000
one 900371 storage_write_raw raw_w_4000 storage_write "raw_distinct_slots=4000" 4000 'rawWrite(uint256,uint256)' 42000000 4000
echo "=== log ==="; cat "$LOG"
