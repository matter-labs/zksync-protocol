# Airbender cycle-cost model

Predicts the **effective guest cycles** a batch will retire, so a sequencer can refuse
to seal a batch that would be unprovable. Airbender's `MAX_NUMBER_OF_CYCLES` is
`2^36 ≈ 68.7e9`; a batch past it cannot be proved, and by then it is already sealed.

The target is `raw_cycles + 16·blake2 + 4·bigint + 4·keccak` — main-trace RISC-V cycles
plus the weighted delegation-circuit cost the main trace does not account for. See the
warning on `DELEGATION_WEIGHTS` in `measurement.py`: those weights have **no
authoritative source in this tree**, and collapsing four independently-limited
resources into one scalar is a known modelling compromise, not a settled choice.

## The shape of the model, and why it is not a regression

The prediction is `base + Σ rate × count`. Nothing more — no interaction terms, no
non-linear features, no per-phase decomposition.

What changed in the 2026-08-21 redesign is not the shape but **where the numbers come
from**. The previous version inferred ~30 per-operation rates by regressing 53 whole
batches. That cannot work, and it is worth being precise about why: in real traffic
every feature moves with every other, so the design matrix is near-singular
(`far_call` had multiple R² = 0.999988 against the rest) and the fit is free to move
cost between collinear partners. Several axes came out at exactly zero — not because
those operations are free, but because a partner absorbed them. The result was a table
that was accurate in total and wrong on every axis an attacker can isolate, which is
the only kind of accuracy that matters for a gate.

No amount of additional organic data fixes this. Collinearity is a property of the
traffic, not of the sample size.

So every rate now carries its provenance, and the provenance is what the trust signals
key on:

| | meaning | trustworthy for a gate? |
|---|---|---|
| **Measured** | a slope from isolated single-axis batches, three or more volume tiers, priced in a unit the cost is linear in | yes |
| **Bounded** | a deliberate upper bound, where the cost-determining input is not observable to the tracer or varies with operands | yes — it over-predicts by construction |

There is no third category. **Every axis in the schema is now measured or bounded**, and
two are deliberately unpriced because another entry already charges their work. An axis
with no rate would be *absent*, and `untrusted_pricing` declines any batch that uses
one — an absence is detectable, a plausible placeholder is not.

There used to be a `Fitted` provenance for rates inferred by regressing whole batches.
It is gone, along with the NNLS solver and every list that tracked it, because a number
a regression invents for an axis it cannot identify is not a weaker measurement but a
fabrication with a plausible magnitude — and it failed in both directions. The last
fitted table had six axes at exactly **0** (a collinear partner absorbed the cost) and
`sha256_cycles` at **114,364 cycles per round**, implausible by orders of magnitude. All
of them predicted the 52-batch corpus well.

### A family's slope is not its rate

An isolation family runs its operation in a loop, and the loop does other work: the
keccak family retires 49 cheap arithmetic ops, 6 shifts, a far call and a near call per
keccak call. So the raw regression slope is

    gross = marginal_cost(axis) + SUM over companions of ( count_per_unit x cost )

and every companion is *also* in the feature vector and charged again by its own rate.
Pricing the axis at `gross` double-charges. The correction is large enough to matter:
`far_call` gross 18,167 against a true marginal of 15,373, and `event` gross 22,618
against 3,180 — a **7.1x over-charge** sitting inside a number that looked measured.

Subtracting companions makes the system mutually recursive, so `derive_rates.py` solves
it by iterating to a fixed point (under ten passes; the coupling is weak). Two details
are load-bearing:

- **Attribution rates are not prediction rates.** Subtracting a companion needs the cost
  it actually incurred, not the rate the table ships. `arith_div_op` ships as a
  worst-case bound of 7,322, but a helper loop divides on the fast path at 1,165;
  subtracting the bound over-subtracts ~6,200 per call, which drove `precompile_call` to
  a nonsensical −5,686 before this distinction existed.
- **`ctrl` rows are not tier rows.** The matched controls have a deliberately different
  shape and are not points on the volume ramp — the `evt` control sits *above* its own
  t3 on the axis. Including them corrupts the slope.

### The base is measured too

The base is what the smallest batch in the corpus costs once its own priced operations
are subtracted — not a fitted intercept. A fitted intercept absorbs whatever the rates
got wrong, which is how a large constant ends up flattering an R².

## Why a bound is sometimes the *right* answer

Two situations make an exact rate undeployable at any level of modelling effort:

1. **The cost-determining input never reaches the feature vector.** vm2 reports
   `CycleStats::ModExp(cycles)` and `CycleStats::EcMul(cycles)` with `cycles` flat at 1
   per call, so a 256-bit exponent and an 8-bit one are indistinguishable downstream.
   The erg price is flat too — the `precompileCall` constants in the system contracts
   are literals derived from an assumption of fixed circuit cycles per call — so an
   attacker buys the expensive input at the cheap input's price and nothing observable
   tells them apart.
2. **Cost varies with operands inside one opcode.** `div` runs 1,186 cyc/op on a
   small-divisor fast path and 7,711 sustaining the expensive branch of Knuth D, a
   6.6× spread, and the operands are gone by the time a count is recorded.

A bound costs throughput, never safety, and `build_cost_table.py` prints what each one
costs on real traffic so the price is visible rather than looking like ordinary error:

```
arith_div_op     mean  5.03%  max 10.77%
decommit_repeat  mean  3.16%  max  7.76%
```

A bound must be `>=` the true worst case, not merely large. With bound `B` and true
cost `T`, `M` operations predict `M·B` and cost `M·T`, so any `B < T` opens a window
`ceiling/T < M < ceiling/B` in which the gate accepts an unprovable batch.

## What replaced the ad-hoc guards

Every entry declares `domain_max`, the largest count it was calibrated over, and a
batch beyond `domain_max × 1.8` is declined. One rule, applied per axis.

This replaced two heuristics — a cap on the arithmetic *share* of a batch (trip point
0.315) and a per-feature volume cap. The share guard fired on every pure-arithmetic
batch including ones the model priced to within 7%, and its own comment conceded that
the thing it actually protected (frame churn / pooled-stack clearing, then 36.5×
under-predicted per iteration) was covered only *incidentally*, via the cheap
arithmetic that attack happens to run. The domain check covers it directly: reaching
the ceiling at ~41k cycles per churn iteration takes ~1.68M iterations, and
`near_call_count` leaves its domain at ~314k — declined with 5.3× to spare.

`Bounded` entries carry no domain and never extrapolate. That is the point of a bound,
and getting it wrong fails *closed*: an early version treated a missing domain as "no
coverage" for every entry, which declared `arith_div_op` out-of-domain on the smallest
batch in the corpus and would have made the gate decline everything.

## Which axes need a rate at all

Every axis draws from the same per-batch erg budget, so moving ergs from a dear axis
into a cheap one strictly lowers the true total: **an axis that cannot reach the
ceiling alone cannot be combined with another to exceed what that other reaches
alone.** `derive_rates.py` reports each family's cycles-per-erg and what the stock
budget buys in units of the ceiling. Price what can reach it; leaving the rest to the
fit costs organic accuracy for nothing.

### What that reachability looks like today

At a 200M-erg batch budget, with the input-swept worst-case rates:

| axis | ergs/call | cyc/call | cyc/erg | × ceiling | × ceiling at the OLD rate |
|---|---:|---:|---:|---:|---:|
| `arith_div_op` | — | 7,711 | — | **3.73×** | 4.44× |
| `ec_mul_cycles` | 6,158 | 683,591 | 111.0 | 0.323× | 0.130× |
| `ec_recover_cycles` | 7,816 | 466,954 | 59.7 | 0.174× | 0.174× |
| `secp256r1_verify_cycles` | 12,870 | 738,043 | 57.3 | 0.167× | 0.169× |
| `ec_add_cycles` | 949 | 53,560 | 56.4 | 0.164× | 0.159× |
| `mod_exp_cycles` | 5,794 | 228,241 | 39.4 | 0.115× | 0.012× |

This is the honest severity of the modexp/ecmul correction, and it is worth not
overstating: **no precompile axis reaches the ceiling alone**, before or after. The
dearest is `ec_mul` at 0.32×, and because every axis competes for the same erg budget,
combining them cannot exceed what the dearest reaches alone. `arith_div_op` is the only axis that
reaches the ceiling on arithmetic alone, and it is bounded at its family's GROSS slope
for that reason — see the note on it in `build_cost_table.py`, including why its true
worst-case regime is still unmeasured.

So the 9.77× and 2.49× shortfalls were a **mis-pricing, not an exploitable provability
break** at this budget. What they did threaten is the total on a *mixed* batch — a
div-heavy batch that also runs modexp had the modexp portion counted at a tenth of its
cost — and the ranking the gate uses to decide anything at all. Note also that the
reachability column scales with the erg budget: at a 10× larger budget `ec_mul` alone
crosses the ceiling, so this table is a conclusion about the current configuration, not
a property of the precompiles.

## Rebuilding

```sh
# 1. Guest + measurement (see REFIT-RUNBOOK.md for the full sequence)
cargo airbender build --project guest -- --features cycle-markers   # NEVER ship this guest
cargo run --release -p zksync_cycle_model --features cycle-markers --bin cycle_bench -- \
    --all-batches --batches-dir <dir> --app-bin-dir guest/dist/app \
    --jobs 8 --out artifacts/<run>

# 2. Reduce isolation families to per-axis rates, with the falsification checks
python scripts/cycle_model/derive_rates.py \
    --datasets testdata/cycle_model/isolation_dataset.json \
    --corpus testdata/cycle_model/isolation_corpus.csv \
    --organic testdata/cycle_model/dataset.json \
    --seed crates/cycle_estimator/model/cost_table.json

# 3. Emit the table (provenance stamp is mandatory — the build refuses without it)
python scripts/cycle_model/build_cost_table.py \
    --organic testdata/cycle_model/dataset.json \
    --isolation testdata/cycle_model/isolation_dataset.json \
    --out crates/cycle_estimator/model/cost_table.json \
    --guest-sha256 ... --verifier-commit ... --vm2-rev ... --measured-on YYYY-MM-DD
# --isolation is NOT optional in practice: without it `ec_pairing_cycles` gets no domain,
# and a Measured entry with no domain extrapolates on any use — a table that declines
# every pairing batch, with the test suite still green.

# 4. Rebuild both Rust fixtures — neither is hand-edited
python scripts/cycle_model/build_fixtures.py \
    --organic artifacts/<run>/organic.json --isolation artifacts/<run>/isolation.json \
    --manifest testdata/cycle_model/isolation_manifest.json \
    --guest "<human description>" --out-dir crates/cycle_estimator/tests/fixtures

# 5. Check the safety invariant, then the Rust suite
cargo test -p zksync-era-airbender-cycles-estimator
```

Measured rates live as literals in `build_cost_table.py`, each with the family it came
from and its R². They are *inputs* to the build, not outputs of it — editing one is a
deliberate act that shows up in review, which is the intent.

## Files

| | |
|---|---|
| `measurement.py` | reading a dataset, applying a table, delegation weights |
| `build_cost_table.py` | the measured/bounded literals → `cost_table.json` |
| `derive_rates.py` | isolation families → per-axis rates (netting companions), plus intercept-drift and ceiling-reachability checks |
| `build_fixtures.py` | both Rust test fixtures, from measured datasets |

`fit_cost_model.py` (899 lines), `cross_validate.py`, `test_fit_smoke.py`,
`eval_holdout.py` (now `check_drift.py`) and `eval_adversarial.py` were deleted: they existed to make a batch-level
fit trustworthy, which is not achievable. The NNLS solver that briefly replaced them is
gone too — with every rate measured there is nothing left to solve, so the pipeline has
**no numerical dependencies at all**: it reads literals, subtracts, and writes JSON.

## Accuracy, and where the safety comes from

52 organic batches (84730–84732 v31, 513601–513649 v29 mainnet), guest `8b9436a8…`,
vm2 `be1e50b`. **None of them was used to derive any rate**, so this is genuinely
out-of-sample:

```
organic (52):     MAPE 4.37%   worst under -0.01%   worst over +12.31%   under 2/52
isolation (163):  worst under +8.07% (deploy batch 900204)
```

## Choosing the margin

The margin is estimated on the **held-out set**: the 40 synthetic batches that
contributed no rate. That is the only population that answers the question that matters —
how wrong is the model on a shape it was *not* calibrated on. Mean ratio 0.9657, sample
sd 0.0869, worst 1.0807 (the deploy family, +8.07%), 5 of 40 under-predicted.

| method | bound |
|---|---|
| observed maximum | 1.0807 — covers 90% of shapes at 99% confidence, but 99% of them at only **33%** confidence |
| upper-tail fit, 99.9% coverage / 95% confidence | **1.0955** |
| upper-tail fit, 99.99% / 95% | 1.1159 |
| symmetric normal fit, 99.9% / 95% | 1.3006 |

The maximum of 40 samples is not a high-confidence bound on a high quantile — that is
what the first row says, and it is why "the worst we saw was 8%" is not an argument. The
symmetric fit is pessimistic in the other direction, because the sd is inflated by the
over-prediction side that the deliberate bounds create by design. The upper-tail fit is
the defensible statistic.

**Shipped: 1.30**, the pessimistic bound, chosen because the margin is nearly free. Real
batches run at a median **9.8%** and a maximum **13.0%** of the 2^36 ceiling, so any
margin below **7.4x** refuses nothing on traffic like this; it binds only on batches
already within 14% of the ceiling, which is to say on an attack. Where it does bind it
costs 23% of the cycle budget.

**What no multiplier can cover.** A margin covers model error on a *priced* axis. It does
nothing about an axis whose rate is simply wrong: `ec_pairing_cycles` is exercised by zero
batches in either corpus, so if it is off by 10x then a pairing-heavy batch is unprovable
at any margin. Guest drift is the same class of problem — that is
`cycle-model-drift.yaml`'s job. Treat the margin as protection against the model, never as
a substitute for a measurement.

This is a better structure than the predecessor's flattering 1.26% MAPE, which was
reached by fitting eleven axes over these same batches — six of them to exactly zero. It
was accurate in total and wrong on every axis an attacker can isolate.

On the adversarial side all **30/30** batches are covered, and 16 of them sit inside
every calibrated domain (the other 14 are declined as out-of-domain, which is the
protection working). Ratios are 1.00–1.20x where the un-netted table had `evt_flood` at 1.84x.

## Completeness audit

The test for a complete model is not its error but whether the **leftover is constant**:
if `actual − Σ rate×count` varies from batch to batch, something that scales is
unmodelled. Running that test is what found the largest defect in this table, and what
bounds what is still missing.

**What it found.** The leftover varied by 743M cycles — 64% of the base. Single-feature
regression said the shortfall was unattributable: every feature correlates ~0.85 with it,
because organic features all move together, so it read as irreducible model fidelity. It
was not. It was **`arith_ptr_op` priced at zero**, and it was found by scanning the
synthetic families for an outlier ratio, not by staring at organic correlations. Contract
deployment copies bytecode through fat pointers, and batch 900204 was **under-predicted
by 23.5%** — past any sane margin, on a shape no adversarial fixture covered. That batch
is now in the fixture.

The cause was an attribution error, not a measurement error, and it generalises: a netted
rate only transfers if the target's companion mix resembles the family's. The slicing
family retires 9 cheap arithmetic ops per pointer op; deployment retires 4.3. Subtracting
companions at a cost class's *dearest* member compounds it — see the attribution
asymmetry in `derive_rates.py`.

**What is still unexplained.** After the fix, and after relaxing the deliberate bounds so
their over-charge is not counted (they explain 33% of what remains, mostly
`decommit_repeat`), the leftover on v29 traffic is `1.338e9 ± 146e6` — **±10.9% of the
constant still scales with something unmodelled.**

Most of that turned out to be a **per-version constant**, not a missing feature. v31's
bootloader does per-batch work v29's does not — saving interop roots among others — and
being per-batch it lands in the base rather than on any feature:

```
v31 organic base   1,154,309,398
v29 organic base     852,674,893
difference           301,634,505    = 26.1% of the base, 4.51% of an average batch
```

That matches the 4.4% mean over-prediction observed on v29 almost exactly. Give each
version its own base and v29 comes out centred at 1.0015 with a CV of 0.022 — so what is
genuinely unexplained is **±5%**, not ±10.9%.

For the deployed gate the v31-derived base is the CORRECT one: the estimator runs on v31,
and the v29 over-charge is a corpus artifact rather than a production error. But it means
the headline organic error is measured mostly against the wrong protocol version, which is
the sharpest gap in this whole setup:

> **Every rate is calibrated on v31 and almost all validation traffic is v29.** The
> isolation fixtures come from a local v31 node; 49 of the 52 organic batches are v29
> mainnet. The three v31 organic batches are *the same CI batch replayed* — identical tx
> count, `arith_cheap_op` and `far_call` — and one of them is the batch the base is
> derived from. So there is effectively **one v31 organic shape**, and it is fitted to
> itself: its 1.0001 ratio is not evidence of anything.

v29 is over-predicted (mean ratio 0.956, so ~4.4% conservative), which is the safe
direction, but it means the deployed accuracy on v31 traffic is genuinely unmeasured.
Getting real v31 organic batches is the highest-value next measurement.

**Two smaller findings.** The phase markers account for only 88% of `raw_cycles` (mean
11.9% unphased, ranging 6.2–13.9%), so the phase breakdown is usable for attribution
hints but not for accounting. And the delegation channels are all covered — blake2
r=0.998 with `merkle_leaf_count`, bigint r=1.000 with `ec_recover_cycles`, keccak r=0.990
with `event` — so no delegation cost is missing from the target.

## Bootloader audit

Every per-batch and per-tx thing the bootloader does, and where its cost lands. The
unpriced quantities were extracted with `examples/dump_batch_shape.rs` and each tested
against the model residual, so "not priced" below is a measurement, not an assumption.

| bootloader work | priced by | evidence |
|---|---|---|
| per-batch constant | `base` = 1,154,243,294 | the dedicated empty-batch control (900356) predicts to 1.0124 |
| per-tx overhead | `transaction_count` 641,470 | family 900352–355: identical work over 1/3/6/12 txs, R² = 0.99996 |
| interop-root *processing* | traced opcodes | runs as bootloader code, so `uma_write`/`storage_write` count it |
| state-diff publishing | `state_diff_count` 90,208 + `pubdata_bytes` 622 | write families, R² ≥ 0.9998 |
| Merkle witness | `storage_application` 183,168 | `merkle_verification` phase is r = 0.998 with it |
| bytecode loading | `decommit_cycles` 7,123 | `setup` phase is r = 1.000 with it |

**Not priced, and measured not to matter.** Each was regressed against the residual:

| quantity | r | residual sd reduction |
|---|---:|---:|
| `pubdata_costs` length | −0.279 | 4.0% |
| `storage_refunds` length | −0.228 | 2.6% |
| `initial_heap_slots` | −0.156 | 1.2% |
| `l2_blocks` | −0.104 | 0.5% |
| `used_bytecode_words` | +0.054 | 0.1% |
| `used_bytecodes` | +0.020 | 0.0% |

None of them is a missing feature. Note especially **per-L2-block work**: mainnet batches
run ~298 L2 blocks against 8 in the CI batches, so it looked like a strong candidate for
the version offset, and it is not — its cost is absorbed by `transaction_count` and the
base. It is also **not attacker-controlled**: the sequencer decides how many L2 blocks a
batch has, so it cannot be used to inflate a batch past the ceiling.

**The one untested axis is interop roots.** `INTEROP_ROOT_SLOTS_SIZE = 5` slots per root
are reserved in bootloader memory, and v31 processes them per L2 block — but **all 68
measured batches have zero interop roots** (v29 mainnet predates them; the v31 CI batches
have none). Their *processing* is opcode-traced and therefore priced; what is not traced
is the host-built initial heap they occupy. `initial_heap_slots` shows no residual signal,
which is weak evidence that this is cheap, but it is evidence from batches containing no
interop roots at all. A v31 batch with interop roots is needed before claiming this axis
is covered.

## What the residual actually is

Total v29 leftover spread is ±2.08% of a batch. Removing the *deliberate* over-charges
one at a time:

```
as shipped                                  sd 139,260,758   2.08% of a batch
relax the decommit_repeat bound             sd 106,567,180   1.59%   (-23%)
  + relax the arith_ptr_op gross fallback   sd  97,918,572   1.47%   (-30%)
```

So **±1.47% of a batch is genuinely unexplained** — no axis, priced or unpriced, accounts
for it, and it is the fidelity floor of this feature schema.

Two details worth keeping. Relaxing `arith_div_op`'s bound *raises* the sd (98M → 216M),
because the bound absorbs the fast/slow operand mix in real traffic — the bound is
reducing variance, not adding it. And `transaction_count` shows a residual slope of
+745,929, 116% of its rate, which looks like per-tx work being under-priced; but doubling
the rate recovers only 15% of the residual while costing 13% over-prediction, so it is
organic correlation rather than an identified per-tx cost. It stays at its measured value.

## `ec_pairing` — the axis that turned out to be measurable

It had no fixture at all and was the only rate in the table with zero validation. Nine
fixtures (900372–900380) settle it, and the answer is better than expected:
`CycleStats::EcPairing` **carries the pair count exactly** (1.0000 per pair across an 8x
sweep), unlike modexp and ecmul whose payload is a flat 1 per call. So it is a **measured
per-pair rate, not a bound**.

Two orthogonal sweeps agree to 0.014% — 12,452,078/pair with the call count pinned at 127,
and 12,453,809 with calls moving 127→907, both R² = 1.000000. Their difference, 1,732, is
the per-call overhead and independently reproduces `precompile_call`. The previously
shipped 12,448,624 was right to **0.03%**, which was luck rather than evidence, and is
exactly why an unvalidated rate needed a fixture.

The degenerate case (G1 = point at infinity) is 19% cheaper and *still increments the
counter*, so it is over-charged — the opposite of `ecadd`, where the identity case is 12x
cheaper and charged per call. Miller-loop cost is a fixed iteration count per pair
regardless of the points, so there is no dearer input to bound against.

**This is the second axis that can reach the proving ceiling.** At 80,201 ergs/pair a
500 M-erg batch buys 6,234 pairs, and the ceiling needs 5,519 — so a maximally
pairing-loaded batch sits at **1.13x of 2^36**, with the gas limit capping a single call at
~951 pairs. The domain check declines above 1,620 pairs, leaving 3.4x headroom, which is
what actually protects it.

## Known gaps

Read these before quoting a number.

- **`arith_ptr_op` and `near_call_count` measure to zero marginal cost.** That is a
  result, not a hole: neither ever occurs without companions this table charges
  separately, and once those are charged there is nothing left to attribute. Their gross
  slopes are 1,680 and 926. Any residual is inside the margin.
- **`pubdata_bytes` could not be decoupled from `event`.** `L1Messenger.sendToL1` emits
  one `L2ToL1Message` per 32-byte chunk, so the two are locked at ~1 event per 64
  pubdata bytes on that route. Treat them as a bounded pair; a genuinely event-free
  pubdata source would need a different mechanism.
- **`modexp` and `ecmul` can only ever be bounds.** `modexp_function`/`ecmul_function`
  in zk_evm return a flat cycle count of 1, which vm2 forwards as
  `CycleStats::ModExp(cycles)`, so no tracer-side work recovers the exponent bits. The
  cost is real: bounding modexp at its 256-bit worst case charges a typical 1-byte
  exponent **90x** its true cost. The fix belongs upstream, in the same shape as
  vm2#130.
- **`decommit_cycles` has two producers and one rate.** The DECOMMIT opcode marginal is
  7,066 and the far-call (`pay_for_decommit`) marginal is 11,124 — a 1.56x spread — and
  the shipped 7,123 prices both at the cheaper end, because raising it lowers the base and
  makes both populations worse. The domain does not bound this away: `decommit_cycles`
  admits 303,627 units (168,682 observed x the 1.8 slack), and a batch whose decommit work
  is entirely far-call driven is under-charged by up to 303,627 x (11,124 - 7,123) =
  **1.21e9 cycles** there — 1.8% of the 2^36 ceiling, well inside the headroom, but real
  and invisible to `is_reliable`/`is_within_calibration`, which both still say true. What
  holds it is the adversarial fixture `bytecode_size_26208b` (batch 900388), the only row
  whose axis count comes entirely from the far-call producer. The fix is to split the
  feature; the tracer can attribute the stat to the instruction that produced it.
- **Three retired rows are uncovered coverage,** not cleanup — see
  `testdata/cycle_model/RETIRED_FIXTURES.md`.
- **A bound refuses transactions it cannot price, and only bounds can refuse at all.**
  `Bounded` entries carry no domain, so they never extrapolate, so they are the only axes
  that can carry a *trusted* estimate as far as a consumer's budget: every measured axis
  trips its domain first — all of them at once at 1.8x domain reach 0.61 of the ceiling,
  0.79 after the margin, against the 0.95 at which era closes a batch. Two bounds are
  reachable in practice (`arith_div_op` at ~3.17M divisions, `decommit_repeat` at ~24.4k
  repeats); the five crypto bounds are gated by `precompile_call`'s own domain, since their
  payload is one unit per call. The price is over-refusal: divisions cost 1,162 cycles at
  the cheapest measured shape and 14,307 at the dearest, all charged at 15,474, so a
  transaction of ~3.2M cheap divisions is refused while truly costing **7.0%** of the
  ceiling. Attaching a domain to the axis is not the fix — distrust means `IncludeAndSeal`
  downstream, so the worst-shape flood would then be admitted and sealed unprovable. It
  closes when the operand shape becomes observable (cost tracks quotient digits), which
  needs a vm2 change: a `Tracer` cannot see an instruction's operands.
  `crates/cycle_estimator/tests/gate_reachability.rs` asserts every number in this
  paragraph.
- **Nothing in a feature vector reveals a producer that never filled an axis.** Every trust
  signal keys on `count > 0`, so a mis-mapped feature reads exactly like work the batch did
  not do. This schema makes that live: it splits era's single `RichAddressingOp` bucket
  into five measured classes, and the mechanical port of that arm
  (`core/lib/multivm/src/tracers/cycle_estimator/vm_latest/mod.rs`) prices every division
  at `arith_cheap_op`'s 145 — a 4.6M-division batch the correct mapping puts at 1.06x of
  the ceiling scores 0.028x, 37x under, trusted, with no signal raised.
  `CostTable::producer_gap` catches the one
  detectable signature (≥1M cheap ops with all four dearer arithmetic axes at zero, a shape
  no organic batch has: all 52 run 64–179 cheap ops per division). The general case is not
  detectable — `decommit_repeat`, where a lost producer costs the most, cannot be covered
  this way, because a batch whose every DECOMMIT is fresh is a legitimate shape
  (`decommit_fresh_4blobs` is one). Re-measure one batch through both producers after
  touching either.
