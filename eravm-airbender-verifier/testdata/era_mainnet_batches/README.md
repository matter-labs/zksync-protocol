# Era Mainnet Batch Corpus

This directory is the workspace-owned home for reproducible Era mainnet batch inputs.
Each batch is stored as its own `*.bin.gz` Git LFS object so we can keep the full corpus in the repository without forcing every clone or CI run to download gigabytes of data up front.

## Layout

- `binary/<batch>.bin.gz`: compressed batch payloads, one LFS object per batch.
- CI hardcodes a small curated subset via the `CI_BATCHES` environment variable in `../../../.github/workflows/ci.yaml`.

## Why These Files Are Not Pulled By Default

The repository ships [`.lfsconfig`](../../../.lfsconfig) with
`lfs.fetchexclude = eravm-airbender-verifier/testdata/era_mainnet_batches/binary/**`, and points
`lfs.url` at the upstream repository's object store, where these objects live.
That keeps normal clones lightweight: Git checks out only pointer files until you explicitly request the batches you need.

If `git lfs` is missing, install it first:

Ubuntu:

```sh
sudo apt-get update
sudo apt-get install git-lfs
git lfs install
```

macOS:

```sh
brew install git-lfs
git lfs install
```

Fetch one batch:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz
```

Fetch the curated CI subset:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz,84731.bin.gz,84732.bin.gz
```

Fetch everything tracked in this directory:

```sh
./scripts/fetch_lfs_batches.sh --all
```

## Importing Existing Local Data

If you already have raw `*.bin` files outside the repository, compress and stage them into LFS with:

```sh
./scripts/import_mainnet_batches.sh \
  --source-dir /home/popzxc/workspace/airbender/storage/era_mainnet_batches/binary \
  --all
```

The import script intentionally stages only the batch payloads. It does not auto-commit, because you may want to review the resulting pointer changes before creating a commit.

## Storage-Soundness Regressions (no synthetic fixture needed)

`crates/airbender_verifier/tests/fail_closed.rs` guards the verifier's storage-view
soundness against the ordinary `84730` corpus. All three regressions tamper `84730`
directly and need no special fixture; none is ignored.

`omitted_merkle_path_read_cannot_inject_prestate` originally relied on an honest gap
batch (a fully rolled-back write, mainnet batch 506155, pre-v31). We could not
regenerate that batch on v31 — the batches we produced don't reproduce the gap — so
the test synthesizes the gap adversarially instead.

## Synthetic Read-Heavy Batch (`900065`)

`900065.bin.gz` is **not** a mainnet batch. It is a synthetic v31 batch generated
from a local Era node with 140,059 unique cold storage reads (the `9000xx` prefix
marks it synthetic; `65` is its source batch number). It is the regression fixture
for the streaming Merkle-proof verification (the RAM-exhaustion DoS fix): the
pre-fix path expanded every storage proof to full depth at once (~1.15 GiB here).

`host/tests/integration_test.rs::host_runs_read_heavy_batch_without_guest_oom`
runs it through the transpiler (the actual compiled guest under its bounded memory
model, CPU only — no GPU). The 4022 MiB guest heap holds ~1.15 GiB, so this is a
functional check of the streaming path; a regression to eager expansion does not
OOM the guest.
Fetch it and run explicitly:

```sh
./scripts/fetch_lfs_batches.sh 900065.bin.gz
cargo airbender build --project guest
cargo test -p eravm-prover-host --test integration_test \
  -- --ignored --nocapture host_runs_read_heavy_batch_without_guest_oom
```

## Running Tools Against This Corpus

Both the VM compare tool and the host runner accept this directory directly.
They read plain `*.bin` files for backwards compatibility, but the CLI expects one or more concrete filenames via `--batch-files`, such as `84730.bin` or `84730.bin.gz`. The repo-first workflow is the compressed one.
The default `--batches-dir` assumes you run `cargo run -p ...` from this workspace's root (`eravm-airbender-verifier/`); otherwise, pass `--batches-dir` explicitly.

Compare one batch:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- --batch-files 84730.bin.gz
```

Run the guest-host simulation for one batch:

```sh
cargo airbender build --project guest
cargo run --release -p eravm-prover-host -- --action run --batch-files 84730.bin.gz
```

Replay every fetched batch in compare mode:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- --all-batches
```

Process every fetched batch in host prove mode:

```sh
cargo run --release -p eravm-prover-host -- --action prove --all-batches
```

## The Isolation Corpus (`900101`–`900177`)

Single-axis synthetic batches, generated on a local Era node, whose job is to set
**per-op rates** — something organic traffic cannot do. In a real batch every
feature moves with every other, so the design matrix is near-singular (`far_call`
had multiple R² = 0.999988 against the rest) and no quantity of additional organic
data fixes that. These are designed experiments instead: one family per cost driver,
three to four volume tiers per family, so the answer is a slope and per-batch fixed
cost cancels.

Reduce them with `scripts/cycle_model/derive_rates.py`, which reports each
family's slope, R², cycles per erg, and — the number that actually decides whether
an axis needs pricing at all — what the stock per-batch erg budget buys in units of
the 2^36 proving ceiling. `scripts/cycle_model/build_fixtures.py` then
turns the same measurement into `crates/cycle_estimator/tests/fixtures/adversarial.json`.

Families: the five arithmetic cost classes (`add`, `sub`, `bitwise`, `jump` →
`arith_cheap_op`; `shift`, `shift_m`, `rotate` → `arith_shift_op`; `mul`; and both
`div` operand regimes, `div_fast` and `div_worst2`), plus `context` (`average_op`),
`farcall`, `nearcall`, `twrite`, `tread`, `evt`, `umaread`, `umawrite`. The manifest
at [`../cycle_model/isolation_corpus.csv`](../cycle_model/isolation_corpus.csv)
carries family, tier, intended axis, tracer count, ergs consumed and status.

**Committed as inputs, deliberately.** The fixture they build used to be
hand-maintained rows whose batches were never committed, so when the guest changed
they could not be re-measured — eight went stale for six weeks and then became
unusable outright at a feature-schema change. Inputs in the repo make
re-measurement a CI job.

**Six fixtures were generated and then dropped as dead**, and the reasons are worth
knowing because each would have shipped a wrong number silently:

- `900104` / `900108` — a single chained `add`/`sub` is an affine induction
  variable, and the optimizer closed-formed the loop away (132k ergs for 500k
  iterations).
- `900162`–`900165` — `arith_div_op` flat at 35 across all tiers. A 256-bit seed
  made the first `div(K, v)` return 0, `v` collapsed to 0, and zksolc's
  divide-by-zero guard then short-circuited the division forever. **The ergs looked
  perfectly healthy and scaled with `n`** — only the tracer count exposed it, which
  is why checking gas-versus-`n` is necessary but not sufficient, and why the
  intercept-versus-baseline check in `derive_rates.py` is a standing rule.

Two axes still have no family. `arith_ptr_op` needs a real fat pointer, which
Solidity cannot isolate (calldata slicing yields 2–3 pointer ops mixed with UMA) —
raw zkasm via `zkevm-assembly` is the clean route. And `decommit_repeat` was
deliberately skipped: it is the only family that can trip `max_pubdata_per_batch`
and crash-loop the node into a full rebuild. That one matters, because by erg
arithmetic the `decommit` repeat path is the other axis besides `div` that can reach
the proving ceiling, and its 285,000 floor has never been measured.

## The Decommit Families (`900201`–`900221`)

The last axis that could reach the proving ceiling with an unmeasured price. Its
mechanism is unusual enough to be worth stating: on a **repeat** DECOMMIT of a hash
already decommitted in the same VM run, vm2 calls `world.decommit_code(hash)`
unconditionally — an O(len) `Vec<u8>` build — while `CycleStats::Decommit` fires
only when *fresh*, and the instruction handler **refunds the ergs**. So the work is
real, the price is not, and the only counter that moves is the opcode count.

Measured here, with two independent tier deltas agreeing to under 1%:

| path | cycles per repeat |
| --- | --- |
| cached (contract in `program_cache`, which one far-call arranges) | `83,659 + 2.340 × len` |
| raw | `83,659 + 0.557 × len` |

The 4.2× per-byte gap is exactly the code: the cached path re-encodes through
`code_page_bytes()`, a U256 `to_big_endian` per 32-byte word, while the raw path is a
`Vec<u8>` clone. And the price is **flat at 1,713.87 ergs per repeat** — identical
for a 14,240 B and a 329,760 B target, i.e. 23× the byte work for the same cost.

`dc_fresh` doubles as a check on the method: `decommit_cycles` came out at exactly
`ceil(len/64)` units per fresh decommit against every one of four sizes, and the
measured 111.3 cycles/byte confirms the existing coefficient (153.3) is 1.38× over —
so that axis is conservatively priced, settling an earlier suspicion that it was 14%
under.

### Two bounds worth having, both measured rather than assumed

**The largest bytecode that deploys is not the protocol maximum.** 329,760 B of
runtime published 199,367 B of pubdata — 40% of the 500 KB cap. Compression *improves*
with size for this pattern (1.23:1 at 14 KiB rising to 1.65:1 at 322 KiB), which puts
the cap-limited bound near 800 KiB. The protocol maximum, `(2^16−1)×32 = 2,097,120` B,
would publish ~1.27 MB and exceed the cap by 2.5× — **it is not deployable in a single
batch on this chain.** The worst-case repeat target is therefore pubdata-limited, not
protocol-limited.

**CodeOracle is at `0x8012`, not `0x8011`.** `Constants.sol` defines it as
`SYSTEM_CONTRACTS_OFFSET + 0x12`; era's own `system-contracts/contracts/test-contracts/CodeOracleTest.sol`
hardcodes `REAL_CODE_ORACLE_ADDR = 0x8011`, which is the address its mocked hardhat
environment uses. On a real chain 0x8011 holds a different contract that reverts with
empty data. Sixteen batches were generated against the wrong address and looked
entirely healthy — ergs scaled with call count at a plausible rate — while the
`decommit` count was **0** in every one. Only the tracer count exposed it. Those
batches were discarded; this is worth reporting upstream.
