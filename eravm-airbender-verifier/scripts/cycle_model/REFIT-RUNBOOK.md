# Refitting the cost table on the current guest — runbook

The committed `crates/cycle_estimator/model/cost_table.json` is calibrated against a
**pre-delegation guest** and says so in its own `provenance.stale_reason`. This is the
procedure that replaces it. Everything here is a *measurement* task: the code-side
work (envelope guard, provenance schema, fail-loud fit guards, the `ecRecover`
hammer family) is already in the tree, and each of those guards will **abort** a
refit that skips a step below — that is deliberate.

## What you need that a sandbox does not have

| requirement | why | check |
|---|---|---|
| **Git-LFS credentials** for this repo | the 122-batch training corpus (`testdata/era_mainnet_batches/binary/5060*.bin.gz`) is LFS-tracked; an unauthenticated `git lfs pull` **no-ops silently** (`git lfs env` shows `auth=none`, files stay 133-byte pointers) | `git lfs pull --include='testdata/era_mainnet_batches/binary/506077.bin.gz' && ls -l` → ~MB, not 133 B |
| **A local zksync-era node** with the airbender components | the precompile + adversarial synthetic batches can only be produced by executing transactions and exporting proof inputs | `zkstack server --components api,tree,eth,state_keeper,commitment_generator,vm_runner_bwip,airbender_proof_data_handler` up on :3050/:4320 |
| **The airbender guest toolchain** | ground truth = guest cycles | `cargo airbender build --project guest -- --features cycle-markers` |
| ~10 GiB free disk, a few hours | 141 batch measurements + two builds | |

The era-node half is the **safe-ship gate**; the LFS half only improves fit
robustness. Ranked that way because without current-guest adversarial actuals the
safety invariant cannot be *evaluated at all*, whereas without the 122-batch
training set you can still fit (on a smaller corpus) — you just lose the
independent hold-out.

## Steps

### 1. Corpus (LFS)

```sh
git lfs pull --include='testdata/era_mainnet_batches/binary/*'
cargo run --release -p zksync_cycle_model --features cycle-markers --bin cycle_bench -- \
    --all-batches --check-only
```

Build `--check-only` with the same `--features cycle-markers` as the measurement run:
it runs in either flavour but its **criterion differs** — calibration accepts any minor
it can name (the point: the corpus is v29), production only labels at or above
`PINNED_PROTOCOL_VERSION`, which rejects the whole train split. It applies the same gate
`load_batch` does, so a batch it passes is one the run can load.

> **The 506xxx/513xxx corpus does not decode against the current wire** — it is in the
> pre-#76 merkle layout, so step 1 reports `invalid utf-8 sequence` for every batch, in
> **both** flavours. Stale corpus, not a flavour mismatch; no feature flag fixes it.
> Only 84730–84732 and 900065 decode today (all `Version31`; see
> `cycle-model-drift.yaml`'s `DRIFT_BATCHES`). **Re-export or transcode the corpus
> first** — everything below assumes decodable inputs.

Keep the split the committed table used: **train** on 506077–506204 (122 measured of
127 present at the time — five did not decode; `--check-only` shows which), **hold
out** 513601–513649 (49). Do not fit on the hold-out: an earlier reference refit had
to, because the training set was unfetchable without LFS credentials, and that alone
is why its output is reference-only rather than shippable.

### 2. Guest + organic measurement

```sh
cargo airbender build --project guest -- --features cycle-markers   # NEVER ship this guest
cargo run --release -p zksync_cycle_model --features cycle-markers --bin cycle_bench -- \
    --all-batches --batches-dir <train-dir> --app-bin-dir guest/dist/app \
    --jobs 8 --out artifacts/cycle_model/train
```

`cycle_bench` now writes `provenance.json` next to `dataset.json` (guest `app.bin`
sha256, verifier commit, locked `zksync_vm2` rev, protocol version, corpus range).
Pass it to the fit — the fit refuses to emit an unstamped table.

Two toolchain traps that have produced wrong numbers before:

- **Build the bench from the same tree as the guest.** An `airbender-host`
  simulator from a different release measuring a guest built by another is not a
  matched pair. (Cross-checked once and found benign — max |Δ| 0.000%, because
  cycles are retired RISC-V instructions of a fixed ELF — but do not rely on that.)
- **Isolate `CARGO_TARGET_DIR` per arm** if you measure two variants; a shared
  target dir can hand you a stale unsuffixed binary and you silently measure the
  wrong build.

### 3. Isolation corpus, on the era node

This is where the rates actually come from, so it is the step that decides whether the
table means anything. The organic corpus cannot identify a per-operation rate — see the
README — so a family here is not a supplement to the fit, it *replaces* it for that
axis.

```sh
cd scripts/precompile_calibration
python3 gen_input_sweep.py            # needs `cryptography` for the P-256 + ecrecover vectors
# confirm each vector on the live node BEFORE mass runs, with a negative control:
#   corrupt one byte and check the call returns 0x. Without the control you cannot tell
#   "verified" from "silently returned empty" — a transposed digit in a P-256 Gx was
#   caught exactly this way.
HAMMER=<deployed PrecompileHammer> bash run_sweep.sh
```

Then measure the produced fixtures with the same `cycle_bench`.

**Sweep the cost-determining INPUT, not just the call volume.** This is the trap that
cost the previous campaign its credibility: it swept volume with one fixed input each —
`modexp` with a 4-byte exponent, `ecmul` with the scalar 7 (three bits of a possible
256) — and produced numbers that looked like bounds and were not. Re-measured against
an input sweep, `mod_exp_cycles` was **9.77× under** the worst case and `ec_mul_cycles`
**2.49× under**. Both are flat 1-per-call in `CycleStats` and flat-priced in ergs, so
nothing observable distinguishes the cheap input from the dear one.

What each family must report, because these are the checks that make a slope
believable:

1. **Three or more volume tiers**, so the answer is a slope and per-batch fixed cost
   cancels.
2. **Intercept against a matched empty-batch control.** A family whose intercept drifts
   from the baseline has a second axis scaling with its own — this is how a sha256
   family's size/arithmetic collinearity announced itself (intercept 2.27e9 against a
   9.4e8 baseline). Report the drift ratio, not just R².
3. **Ergs per unit**, so `derive_rates.py` can say what the batch erg budget buys in
   units of the `2^36` ceiling. That decides whether the axis needs pricing at all.
4. **Whether the tracer's feature vector moves with the swept input.** If it does not,
   the axis cannot have a measured rate at any level of effort and must be bounded.

Two traps worth knowing about before you spend a night on them: gas-vs-`n` linearity is
necessary but *not sufficient* — a 256-bit seed once made `div(K, v)` return 0, so
`arith_div_op` sat flat at 35 while the ergs looked healthy. And zksolc closed-forms
chained `add`/`sub` loops, so a Solidity flood may not emit the opcodes you think.

Watch for **delegation ids outside `{1991, 1994, 1995}`** in the new measurements:
`effective_cycles()` fails closed on an unknown id, and a new one needs its native
weight added to `DELEGATION_WEIGHTS`.

### 4. Reduce, then build

```sh
python scripts/cycle_model/derive_rates.py \
    --datasets testdata/cycle_model/isolation_dataset.json \
    --corpus testdata/cycle_model/isolation_corpus.csv \
    --organic testdata/cycle_model/dataset.json \
    --seed crates/cycle_estimator/model/cost_table.json
```

Transcribe the slopes into `MEASURED` / `BOUNDED` in `build_cost_table.py`, each with
its family and R². They are literals on purpose: a rate change is then a reviewable
diff rather than a side effect of re-running a script.

Where a feature covers several opcodes, take the **worst** member — an attacker picks
the shape. `arith_cheap_op` takes `sub` (145) over `add` (137) / bitwise (119) / jump
(102). Confirm the class is homogeneous first: a feature is only one feature if its
internal cost spread is bounded, and that is testable.

```sh
# Emit the reducer's rates for all four targets, so the build can check its literals
# against them AND cross-check that effective = raw + weighted delegations per axis.
for t in effective raw blake2 bigint keccak; do
  python scripts/cycle_model/derive_rates.py --target $t \
      --datasets testdata/cycle_model/isolation_dataset.json \
      --corpus testdata/cycle_model/isolation_corpus.csv \
      --seed crates/cycle_estimator/model/cost_table.json \
      --emit artifacts/derived-$t.json
done

python scripts/cycle_model/build_cost_table.py \
    --check-rates artifacts/derived-effective.json \
    --check-reconstruction artifacts/derived-raw.json artifacts/derived-blake2.json \
                           artifacts/derived-bigint.json artifacts/derived-keccak.json \
    --organic artifacts/cycle_model/train/organic.json \
    --out crates/cycle_estimator/model/cost_table.json \
    --guest-sha256 ... --verifier-commit ... --vm2-rev ... --measured-on YYYY-MM-DD
```

The build **refuses** to emit a table that is unstamped, or in which an axis has a rate
while also being listed as unmeasured or deliberately unpriced. There are no flags to
pass — a fired guard means a measurement step is incomplete.

Note that step 4 is `derive_rates.py`, not a fit. Nothing in this pipeline regresses
whole batches any more; the organic corpus is used only to derive the base and to
*check* the result, which is what makes the reported error out-of-sample.

### 5. Validate before swapping anything in

```sh
python scripts/cycle_model/build_fixtures.py \
    --organic artifacts/cycle_model/train/organic.json \
    --isolation artifacts/cycle_model/isolation/dataset.json \
    --manifest testdata/cycle_model/isolation_manifest.json \
    --guest "<human description>" --out-dir crates/cycle_estimator/tests/fixtures
cargo test -p zksync-era-airbender-cycles-estimator
```

Ship only if **no adversarial batch is under-predicted** — that is the safety criterion,
and `adversarial_safety.rs` checks it independently of whether the gate would trust the
batch, so it cannot pass vacuously.

There is no separate pre-commit evaluator, deliberately. `EMBEDDED_COST_TABLE` is an
`include_str!` of `model/cost_table.json`, so `cargo test` on the working tree already
tests the freshly built candidate table against the freshly built fixtures. A Python
mirror of the same check existed and was deleted: it duplicated `CostEntry::extrapolates`
in a second language, drifted from it twice, and the second drift made the whole check
pass vacuously. Do **not** gate on a small MAPE: over-prediction is the safe direction
and bounds deliberately buy it. `build_cost_table.py` prints what each bound costs on
real traffic; that is the number to argue about, not the MAPE.

Two things that must be true and are easy to get wrong:

- **Both fixtures are build products.** Neither `adversarial.json` nor
  `measured_corpus.json` is hand-edited. The predecessor of the first was nine rows
  whose batch inputs were never committed, so eight went stale on the pre-delegation
  guest and could not be refreshed; the second had no generator at all and aged the
  same way unnoticed.
- **`model_regression.rs` cannot see guest drift.** Both sides of its comparison are
  frozen committed data, so it catches an accuracy-worsening edit and nothing else. A
  predecessor reached 2.05× over-prediction with it green throughout. Guest drift is
  `.github/workflows/cycle-model-drift.yaml`'s job, which re-measures against the guest
  built from HEAD.
