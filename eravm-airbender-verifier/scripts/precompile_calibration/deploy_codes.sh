#!/usr/bin/env bash
# Deploy the Invoker + 174 distinct target bytecodes. Every target is deployed
# here so that the fixture batches later only INVOKE them: publication cost and
# the deploy's own decommit stay out of the measured batches entirely.
set -uo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
D="$(cd "$(dirname "$0")" && pwd)"
# forge runs from this directory (foundry.toml + src/ live here).
T="$D"
RPC="${RPC:-http://localhost:3050}"
# Default: the era-test-node standard rich-wallet dev key -- publicly documented,
# local-only funds. Override KEY for any other setup.
KEY="${KEY:-0x7726827caac94a7f9e1b160f7ea819f172f7b6f9d2a97f992c38edeab82d4110}"
OUT="$D/deployed.txt"; touch "$OUT"
dep() { # file:Contract label
  grep -q "^$2 " "$OUT" && return 0
  local a
  a=$(cd "$T" && forge create --broadcast --zksync "$1" --rpc-url "$RPC" --private-key "$KEY" 2>&1 \
      | grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | grep -oE '0x[0-9a-fA-F]{40}')
  if [[ -n "$a" ]]; then echo "$2 $a" >> "$OUT"; else echo "FAIL $2" >&2; return 1; fi
}
dep src/Invoker.sol:Invoker Invoker
for i in $(seq 0 149);    do dep "src/SmallCode.sol:S$i" "S$i" || exit 1; done
for i in $(seq 1000 1007); do dep "src/Mid8K.sol:M$i"   "M$i" || exit 1; done
for i in $(seq 2000 2007); do dep "src/Mid24K.sol:N$i"  "N$i" || exit 1; done
for i in $(seq 3000 3007); do dep "src/Big48K.sol:B$i"  "B$i" || exit 1; done
echo "DEPLOY_DONE $(wc -l < "$OUT") contracts"
