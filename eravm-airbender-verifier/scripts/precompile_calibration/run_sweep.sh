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
LOG="$D/sweep_log.csv"
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

A_MODEXP=0x0000000000000000000000000000000000000005
A_ECADD=0x0000000000000000000000000000000000000006
A_ECMUL=0x0000000000000000000000000000000000000007
A_ECREC=0x0000000000000000000000000000000000000001
A_P256=0x0000000000000000000000000000000000000100

# modexp: count fixed at 30000, exponent length swept 1..32 B (dense 0xff) + the
# shipped 0x03x4 control.
one 900301 modexp modexp_exp1b       "exp_bytes=1"      8   12000 $A_MODEXP 120000000
one 900302 modexp modexp_exp4b       "exp_bytes=4"      32  12000 $A_MODEXP 120000000
one 900303 modexp modexp_exp8b       "exp_bytes=8"      64  12000 $A_MODEXP 120000000
one 900304 modexp modexp_exp16b      "exp_bytes=16"     128 12000 $A_MODEXP 120000000
one 900305 modexp modexp_exp32b      "exp_bytes=32"     256 12000 $A_MODEXP 120000000
one 900306 modexp modexp_old_0x03x4  "exp_bytes=4_0x03" 26  12000 $A_MODEXP 120000000
# ecmul: count fixed at 8000, scalar bit length swept 3..254
one 900307 ecmul  ecmul_s3    "scalar_bits=3"   3   8000 $A_ECMUL 120000000
one 900308 ecmul  ecmul_s32   "scalar_bits=32"  32  8000 $A_ECMUL 120000000
one 900309 ecmul  ecmul_s64   "scalar_bits=64"  64  8000 $A_ECMUL 120000000
one 900310 ecmul  ecmul_s128  "scalar_bits=128" 128 8000 $A_ECMUL 120000000
one 900311 ecmul  ecmul_smax  "scalar_bits=254" 254 8000 $A_ECMUL 120000000
# ecadd: count fixed at 40000, three input classes
one 900312 ecadd  ecadd_gg        "class=G+G_double"    0 60000 $A_ECADD 120000000
one 900313 ecadd  ecadd_distinct  "class=2G+3G_generic" 0 60000 $A_ECADD 120000000
one 900314 ecadd  ecadd_identity  "class=2G+O_identity" 0 60000 $A_ECADD 120000000
# ecrecover: count fixed at 8000, two signature shapes
one 900315 ecrecover ecrecover_a "class=v27_r254bit"       254 8000 $A_ECREC 120000000
one 900316 ecrecover ecrecover_b "class=v28_r248bit_zeroL" 248 8000 $A_ECREC 120000000
# secp256r1: count fixed at 8000, two signature shapes
one 900317 secp256r1 secp256r1_a "class=r255bit"       255 5000 $A_P256 120000000
one 900318 secp256r1 secp256r1_b "class=r248bit_zeroL" 248 5000 $A_P256 120000000
echo "=== log ==="; cat "$LOG"
