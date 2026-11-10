#!/usr/bin/env bash
# Drive the input-dimension sweep: one tx per batch, one input vector per batch,
# call count FIXED within each family so the per-call cost delta is attributable
# to the input alone.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
RPC=${RPC:-http://localhost:3050}
HANDLER=${HANDLER:-http://localhost:4320}
H=${HAMMER:-0x79d87985e7E80d26d7E96a8Fad30578078dDD603}
# Default: the era-test-node standard rich-wallet dev key -- publicly documented,
# local-only funds. Override KEY for any other setup.
KEY="${KEY:-0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110}"
D="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$(cd "$D/../.." && pwd)}"
BIN="$REPO/testdata/era_mainnet_batches/binary"
LOG="$D/sweep_log2.csv"
ONLY="${ONLY:-}"
[[ -f "$LOG" ]] || echo "fixture,family,vector,input_param,bits,count,addr,tx,l1_batch,gas_used,ok" > "$LOG"

CONVERT=(cargo run --release -q --manifest-path "$REPO/Cargo.toml" -p zksync_cycle_model --example encode_batch --)

one() { # fixture family vector input_param bits count addr gaslimit
  local fx=$1 fam=$2 vec=$3 ip=$4 bits=$5 cnt=$6 addr=$7 gl=$8
  if [[ -n "$ONLY" && "$ONLY" != *"$fx"* ]]; then return 0; fi
  if grep -q "^$fx," "$LOG"; then echo "[$fx] already done, skip"; return 0; fi
  local inp="0x$(cat "$D/$vec.hex")"
  echo "=== [$fx] $fam $vec count=$cnt gaslimit=$gl"
  local out tx
  out=$(cast send "$H" 'hammer(address,uint256,bytes)' "$addr" "$cnt" "$inp" \
        --private-key "$KEY" --rpc-url "$RPC" --gas-limit "$gl" --json 2>&1)
  local hash; hash=$(echo "$out" | python3 -c "import sys,json
try: print(json.load(sys.stdin).get('transactionHash') or '')
except Exception: print('')")
  if [[ -z "$hash" ]]; then
    echo "  send failed: $(echo "$out" | tail -3)"; echo "$fx,$fam,$vec,$ip,$bits,$cnt,$addr,,,,SEND_FAIL" >> "$LOG"; return 1
  fi
  # l1BatchNumber is null in the immediate receipt: poll until assigned
  local batch="" gas="" status="" j k
  for ((k=0;k<90;k++)); do
    j=$(cast rpc eth_getTransactionReceipt "$hash" --rpc-url "$RPC" 2>/dev/null)
    read -r batch gas status <<<"$(echo "$j" | python3 -c "import sys,json
try:
  d=json.load(sys.stdin) or {}
  b=d.get('l1BatchNumber'); print(int(b,16) if b else '-', int(d.get('gasUsed','0x0'),16), d.get('status',''))
except Exception: print('-','0','')")"
    [[ "$batch" != "-" ]] && break
    sleep 2
  done
  if [[ "$batch" == "-" || -z "$batch" ]]; then
    echo "  no l1BatchNumber"; echo "$fx,$fam,$vec,$ip,$bits,$cnt,$addr,$hash,,,NO_BATCH" >> "$LOG"; return 1
  fi
  local bn=$batch
  echo "  tx=$hash batch=$bn gas=$gas status=$status"
  if [[ "$status" != "0x1" && "$status" != "1" ]]; then
    echo "  TX REVERTED"; echo "$fx,$fam,$vec,$ip,$bits,$cnt,$addr,$hash,$bn,$gas,REVERTED" >> "$LOG"; return 1
  fi
  # wait until batch bn is sealed
  local i cur
  for ((i=0;i<60;i++)); do
    cur=$(cast rpc zks_L1BatchNumber --rpc-url "$RPC" 2>/dev/null | tr -d '"'); cur=$((cur))
    [[ $cur -ge $bn ]] && break
    sleep 2
  done
  # export proof inputs (retry: needs bn-1 commitment)
  local json="$D/pi_$bn.json" ok=no
  for ((i=0;i<40;i++)); do
    if curl -sf "$HANDLER/airbender/proof_inputs_no_lock/$bn" -o "$json"; then ok=yes; break; fi
    sleep 3
  done
  if [[ $ok != yes ]]; then echo "  export failed"; echo "$fx,$fam,$vec,$ip,$bits,$cnt,$addr,$hash,$bn,$gas,EXPORT_FAIL" >> "$LOG"; return 1; fi
  if ! "${CONVERT[@]}" "$json" "$BIN/$fx.bin.gz" >/dev/null 2>&1; then
    echo "  convert failed"; echo "$fx,$fam,$vec,$ip,$bits,$cnt,$addr,$hash,$bn,$gas,CONVERT_FAIL" >> "$LOG"; return 1
  fi
  rm -f "$json"
  echo "  -> $fx.bin.gz ($(wc -c < "$BIN/$fx.bin.gz" | tr -d " ") B)"
  echo "$fx,$fam,$vec,$ip,$bits,$cnt,$addr,$hash,$bn,$gas,ok" >> "$LOG"
}

A_KECCAK=0x0000000000000000000000000000000000008010
A_SHA256=0x0000000000000000000000000000000000000002

# ---- keccak256: CALL-COUNT sweep at a fixed 32 B input (1 round/call) --------
one 900319 keccak256 hashin_32 "calls@32B=8000"   1 8000   $A_KECCAK 120000000
one 900320 keccak256 hashin_32 "calls@32B=30000"  1 30000  $A_KECCAK 120000000
one 900321 keccak256 hashin_32 "calls@32B=60000"  1 60000  $A_KECCAK 120000000
one 900322 keccak256 hashin_32 "calls@32B=95000"  1 95000  $A_KECCAK 120000000
# ---- keccak256: INPUT-SIZE sweep at a fixed 3200 calls (rounds = len/136+1) --
one 900323 keccak256 hashin_32    "input_bytes=32"    1   3200 $A_KECCAK 120000000
one 900324 keccak256 hashin_1024  "input_bytes=1024"  8   3200 $A_KECCAK 120000000
one 900325 keccak256 hashin_8192  "input_bytes=8192"  61  3200 $A_KECCAK 120000000
one 900326 keccak256 hashin_65536 "input_bytes=65536" 482 3200 $A_KECCAK 120000000
# ---- sha256: CALL-COUNT sweep at a fixed 32 B input (1 round/call) -----------
one 900327 sha256 hashin_32 "calls@32B=8000"   1 8000   $A_SHA256 120000000
one 900328 sha256 hashin_32 "calls@32B=30000"  1 30000  $A_SHA256 120000000
one 900329 sha256 hashin_32 "calls@32B=60000"  1 60000  $A_SHA256 120000000
one 900330 sha256 hashin_32 "calls@32B=88000"  1 88000  $A_SHA256 120000000
# ---- sha256: INPUT-SIZE sweep at a fixed 900 calls (rounds = pad64(len+8)/64) -
one 900331 sha256 hashin_32    "input_bytes=32"    1    900 $A_SHA256 120000000
one 900332 sha256 hashin_1024  "input_bytes=1024"  17   900 $A_SHA256 120000000
one 900333 sha256 hashin_8192  "input_bytes=8192"  129  900 $A_SHA256 120000000
one 900334 sha256 hashin_65536 "input_bytes=65536" 1025 900 $A_SHA256 120000000
echo "=== log ==="; cat "$LOG"
