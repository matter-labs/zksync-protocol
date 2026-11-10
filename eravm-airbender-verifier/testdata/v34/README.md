# Offline v34 fixtures

These batches execute in Era's `vm_latest` test harness. No deployed node,
database, or L1 connection is required.

- `normal`: deploy a counter, then execute two payable L1 increments.
- `mixed`: deploy the same counter, force-fail the first increment, then execute
  the second normally. The failed transaction includes a deposit and factory dependency.

Each gzip JSON contains the verifier input, fixed expected outputs, and provenance.
Era produces the transaction results, logs, state diffs, pubdata, bootloader heap,
KZG blob data, and Airbender commitment with its sanity checks enabled. A separate Python sparse Merkle tree builds
proofs and the resulting state root from Era's initial storage and final storage logs.
The initial state and previous commitment are synthetic; these are not settled batches.

The integration tests compare the native verifier against these recorded outputs.
They also check JSON → stored batch → guest-wire round trips and reject a witness
whose force-fail flag has been cleared. Tests do not regenerate expected outputs.

From `eravm-airbender-verifier`:

```bash
cargo test -p zksync_airbender_verifier --test v34_era
```

## Regenerate

Use a local Era repository containing commit
`dd9f819a46b807aa93884126f4a5ae3d0568283a`, and a clean contracts checkout at
`4ab4a0ef3366e5fea80345d4fd91d7b996099020` with compiled system contracts,
EVM emulator, proved bootloader, and L2 predeploys. Run `yarn build-all-contracts`
in that contracts checkout; the generator reads `system-contracts/zkout` and
`l1-contracts/zkout`. Era's Rust test-contract build also needs its Solidity compilers.

```bash
python3 scripts/v34_fixtures/generate.py \
  --era-repo /path/to/zksync-era \
  --contracts /path/to/compiled/era-contracts \
  --work-dir ../.context/v34-fixture-generator
```

The generator creates a detached Era worktree and installs its test exporter there.
It adds serialization to the in-memory test storage without changing VM behavior.
It only reuses work directories it marked as its own. `manifest.json` records source
revisions, generator and artifact fingerprints, fixture hashes, and bootloader hashes.
Review regenerated expected outputs before committing them.

## Stored format

`save_batch()` writes the existing length-prefixed, padded hex frame. Its payload is
`ABVINPUT`, version byte `1`, then bincode `(LabeledVerifierInput, Vec<(u32, u32)>)`.
The positions identify force-failed L1 transactions in ascending `(block, tx)` order.
The loader still accepts both older unversioned layouts. Unknown versions, invalid
positions, truncated data, and trailing payload bytes are rejected.
