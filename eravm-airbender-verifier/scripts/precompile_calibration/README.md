# Precompile calibration batches

Generate **synthetic, precompile-dominated batches** from a local zksync-era node
to calibrate the cycle-cost model's precompile features. Targets the 5 unpriced
features (`modexp`, `ec_pairing`, `ec_add`, `ec_mul`, `secp256r1_verify`) plus
`sha256` (currently coeff 0.00) and `ec_recover` (see below). See the top-level
cycle-model docs for the fit.

> **`ec_recover` needs this set too — and the committed one does not have it.**
> Organic batches are full of ecrecovers, but at a near-CONSTANT volume (~one
> signature per tx, 293–760 per batch), and a near-constant column is collinear
> with the intercept: NNLS cannot identify a per-recover cost from it. Measured
> consequence — the committed table says 11.47M cyc/recover, a refit on the same
> corpus says 119k, and both predict organic batches equally well; an
> ecrecover-flood batch is priced by whichever value the fit happened to park.
> So `ec_recover_cycles` is in `PRECOMPILE_FEATURES` (residual-fit from *this*
> set), the hammer has an `ecRecover` family, and `gen_inputs.py` emits
> `ecrecover_fixed.hex`. The committed `synthetic_dataset.json` predates all
> three (`ec_recover_cycles` ranges 1–8 there), so **`build_cost_table.py` aborts
> against it** with an identifiability error rather than replacing a real
> coefficient with residual noise (~0 — which would be worse than the artifact).
> Regenerating this set on a node is what clears it; see
> `scripts/cycle_model/REFIT-RUNBOOK.md`.

## Adversarial hardening

A throwaway `CycleHammer` contract (transient-storage / context-op / memory /
pure-arithmetic loops, plus a modexp `burnGas` edge) driven against the local node
produced *adversarial* batches that probe under-estimation / DoS vectors — each
maximizes one vm2 feature the fitted model under-prices. Measured with
`cycle_bench`, the worst under-predicted **~9×** (transient storage & context ops,
priced at **0**) and **~3×** (pure arithmetic, `rich_addressing_op` priced ~3×
low). The contract itself is a dev artifact (not committed); the reproducible
outputs are the measured batches, committed as
`crates/cycle_estimator/tests/fixtures/adversarial.json` and enforced by
`crates/cycle_estimator/tests/adversarial_safety.rs`. Fixes: post-fit
`OPCODE_FLOORS` (transient/context) + a calibration-envelope guard for the compute
vector (`CostModel::extrapolated_features`, which makes `CycleEstimate::fits` fail
safe on compute-dominated batches). A dispatch-decomposition refit that would have
superseded both was evaluated and rejected — it creates a new storage-dominated
under-estimation vector; see the `BOUNDED` notes in `build_cost_table.py`.

## Why isolation

The NNLS fit only recovers a clean per-precompile coefficient if each batch is
**dominated by one precompile** (collinearity otherwise smears cost across
features). So each batch is a burst of transactions to a *single*
`PrecompileHammer` function; families are driven sequentially so each lands in
its own batch. Tiers sweep the feature ~2–3 orders of magnitude:

- input-dependent (`sha256`, `ecpairing`): tier by **input size** (light/medium/heavy)
- fixed-cost (`modexp` — the circuit only takes ≤32B operands — `ecadd`, `ecmul`,
  `secp256r1`, `ecrecover`): tier by **call count** (one input, driver sweeps
  `count`)

## Pieces

| file | role |
| --- | --- |
| `PrecompileHammer.sol` | loops `count` staticcalls to one precompile per tx (minimal contamination) |
| `gen_inputs.py` | emits `<precompile>_<tier>.hex` valid input vectors |
| `run_calibration.sh` | drive tx bursts against a pre-deployed hammer, export + convert each batch |

## Prerequisites

1. Local era node up with the airbender components (see `docs/.../launch.md`):
   ```sh
   ( cd <era> && zkstack containers && zkstack ecosystem init --dev )
   ( cd <era> && zkstack server --components \
       api,tree,eth,state_keeper,commitment_generator,vm_runner_bwip,airbender_proof_data_handler )
   ```
   L2 RPC on `:3050`, airbender proof-input handler on `:4320`.
2. Input vectors generated: `python3 gen_inputs.py` (needs `cryptography` for the
   secp256r1 vector — use a venv).
3. The JSON→`.bin` converter (already in-repo):
   `cargo run -p zksync_cycle_model --example encode_batch -- <json> <n>.bin.gz`.

## Flow (per batch)

```
tx burst to hammer.fn(count, input)   →  batch N seals (one precompile-dominant)
curl :4320/airbender/proof_inputs_no_lock/N  >  proof_inputs_N.json
encode_batch proof_inputs_N.json  N.bin.gz    (verifier fixture)
cycle_bench --batch-files N.bin.gz            (ground-truth guest cycles + features)
```

Append the measured `(features, cycles)` rows to the training set and refit
`scripts/cycle_model/build_cost_table.py`; the isolated batches give each target
precompile a well-conditioned coefficient.

## To confirm on the live node (curve inputs)

Curve/sig vectors are valid by construction but **verify before mass runs** — a
bad point makes the precompile fail and cost nothing:
```sh
cast call 0x0000000000000000000000000000000000000001 0x$(cat ecrecover_fixed.hex) # ecrecover → nonzero addr
cast call 0x0000000000000000000000000000000000000006 0x$(cat ecadd_fixed.hex)   # ecadd → ok, 64B
cast call 0x0000000000000000000000000000000000000008 0x$(cat ecpairing_light.hex) # ecpairing → ok, 32B
# secp256r1 address is chain-specific (0x100 on RIP-7212); confirm era's address + that it returns 1
```

## Fitting the precompile coefficients (residual method — important)

Do **not** naively merge these synthetic rows into the 506xxx corpus and re-run a
joint NNLS — the precompile-dominated batches have large generic-opcode counts
(`far_call`/`rich_addressing_op`/`precompile_call`, which scale with precompile
calls), and a joint fit lets those absorb precompile cost, inflating their
coefficients and **wrecking organic predictions** (513xxx hold-out MAPE went
0.45% → 37%).

Instead, **freeze the organic model and fit only the precompile coefficients on
the residual**: for each isolated synthetic batch, `residual = effective_cycles −
organic_model.predict(features)` (the organic table has 0 for precompile
features), then NNLS `residual ≈ Σ coef·precompile_feature`, and add those
coefficients to the `total` table. This leaves organic accuracy untouched
(513xxx hold-out stays 0.443%) and validates on the combined batches (+0.05%).

Measured coefficients (guest effective cycles): modexp ~9.4e5/call,
sha256 ~1.5e3/round, ec_add ~1.7e5/call, ec_mul ~1.9e5/call,
ec_pairing ~6.6e7/pair, secp256r1 ~1.3e7/call. Note ec_pairing (~1,034 pairs)
and secp256r1 (~5,403 verifies) exceed the 2^36 Airbender cycle ceiling — the
dominant unprovability vectors.

Reproduce (residual mode is first-class in the fit script):
```sh
python3 scripts/cycle_model/build_cost_table.py \
    --dataset <506xxx organic corpus>/dataset.json \
    --precompile-dataset scripts/precompile_calibration/synthetic_dataset.json \
    --tau 0.9 \
    --out artifacts/cycle_model
```
It fits the organic model from `--dataset`, freezes it, and residual-fits the
precompile coeffs from `synthetic_dataset.json` into `total` and the
`vm_execution` phase. This is what the committed `cost_table.json` is generated
from.

`--tau 0.9` fits the organic total with an **asymmetric (expectile) loss** that
penalizes under-prediction ~9× over over-prediction, so the model leans
conservative — the right bias for a seal gate. On the 513xxx hold-out this drops
the under-prediction rate 88%→67%, halves the mean bias (−0.42%→−0.26%), and
improves both worst-case under (−1.82%→−1.36%) and MAPE (0.44%→0.34%) versus a
plain (τ=0.5) least-squares fit. See `fit_asymmetric()` in the fit script.
