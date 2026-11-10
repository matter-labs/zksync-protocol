# Pricing precompiles from zksync-os native costs

zksync-os (`basic_system/src/cost_constants.rs`, branch `draft-0.4.0`) gives each
precompile as `native_with_delegations!(raw, bigint, blake)` — i.e. its **raw
RISC-V cycles** plus its **delegation counts** (bigint / blake), measured via
cycle markers. That decomposition is exactly what we need.

## Why the delegation counts transfer exactly

Our verifier's vm2 runs precompiles with `airbender-precompile-delegations`
enabled (zksync-protocol `popzxc-airbender-precompiles`, PR #209), so they use
the **same `airbender-crypto` delegations** zksync-os prices (keccak via
`sha3/delegated`, bn254/modexp via `bigint_delegation`). So for any precompile
the *number* of delegations it issues is identical in both worlds — zksync-os's
`bigint`/`blake` args give us those counts directly, with no calibration.

## The conversion

    our_cost(op) ≈ raw(op) + delegations(op) · d      [+ precompile_call per invocation]

- `raw(op)`, `delegations(op)` — from zksync-os's constant (transfer directly).
- `d` — our guest's raw-cycles **per delegation dispatch**. This is the only
  thing to calibrate, and it's a property of the machine, not the op.

### Calibrating d

The corpus can't isolate `d` by regression — `raw_cycles` is dominated by
non-delegation work (setup, merkle, non-crypto vm), so `raw_cycles ~ delegations`
fits a nonsensical negative base, and the delegations/keccak-round ratio (≈704 +
≈253 for ids 1991/1995) exceeds zksync-os's 649 because the guest also hashes
outside the VM (merkle/commitment). The clean anchor is keccak per round:

    d = (our_keccak_per_round − zksync_os_keccak_raw_per_round) / keccak_delegations_per_round
      = (26,951 − 1,250) / 649 ≈ 40 raw-cycles / delegation

**A controlled microbench should confirm `d`** (vary one precompile, measure
Δraw_cycles vs Δdelegations) — corpus data alone is too confounded. Treat d ≈ 40
as provisional.

## Per-op decomposition and provisional cost (our raw_cycles units, d ≈ 40)

| precompile | raw | delegations | ≈ our cost |
|---|---:|---:|---:|
| ec_recover / call | 240,000 | 32,000 | 1,520,000 |
| p256 / call | 500,000 | 71,000 | 3,340,000 |
| bn254 ec_add / call | 51,400 | 1,650 | 117,400 |
| bn254 ec_mul / call | 647,000 | 41,000 | 2,287,000 |
| bn254 pairing (base) | 6,244,000 | 0 | 6,244,000 |
| bn254 pairing / pair | 5,572,000 | 334,000 | 18,932,000 |
| modexp | given as total native units (no delegation split): 20,000 base + 340·digit² + 400·op — measure directly | | |

The delegation counts are firm; the ≈-column moves with the calibrated `d` and
each invocation also carries the fixed `precompile_call` fast-VM overhead.

## Caveat

- `d` is provisional (keccak-anchored, corpus can't isolate it) — pin it with a
  microbench before trusting the ≈-column.
- These move the five unpriced precompiles from **0** (silent under-estimate) to
  grounded, size-parameterized values; conservative to round up.
- keccak/sha256/ecrecover are already priced from the fit — don't replace them
  with lower values (under-pricing is unsafe); refine via the same microbench.

## Applying it

EC/modexp are per-call / per-pair / per-digit², which the current `<op>_cycles`
(CycleStats) features don't express. Pinning them needs a featurization upgrade:
have the tracer count invocations (+ pairs / operand size) so cost applies as
`base + per_pair·pairs`, then write the coefficients into `cost_table.json` (they
have no dataset column to fit). Until then the coverage guard rejects any batch
using an unpriced precompile.
