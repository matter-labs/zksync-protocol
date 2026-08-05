# vk_regression_checker

`vk_regression_checker` is a small CLI for detecting unintended verification keys drift.

The goal is to run it against a previously-calculated set of keys, and check if the changes
in this repository (or `zksync-crypto`) has caused VKs to change, which always should be an
intentional action.

It can:
- generate a fresh set of base-layer, recursive-layer, compression-layer, and compression-wrapper verification keys and finalization hints;
- compare freshly generated artifacts against a reference key directory;
- write generated artifacts to disk so you can inspect mismatches manually.

The `reference/` folder is intentionally structured to mirror
`zksync-era/prover/data/keys`, so it follows the same naming/layout quirks.

`zksync-era` also contains a few artifacts that are currently not checked by this tool:
- `commitments.json`
- `compression_wrapper_setup_data.bin`
- `fflonk_verification_snark_key.json`
- `verification_snark_key.json`

## Build

```bash
cargo build -p vk_regression_checker --release
```

## Usage

Show help:

```bash
cargo run -p vk_regression_checker -- --help
```

Generate keys into a target directory:

```bash
cargo run -p vk_regression_checker -- generate --keys-dir <output-dir> --jobs 1
```

Compare generated keys to a reference directory (writes generated keys to `generated/` by default):

```bash
cargo run -p vk_regression_checker -- compare --keys-dir <reference-dir> --jobs 1
```

Use a custom directory for generated comparison output:

```bash
cargo run -p vk_regression_checker -- compare --keys-dir <reference-dir> --generated-dir <output-dir> --jobs 1
```

`compare` exits with a non-zero status if any key artifact differs.

## Updating the reference keys

The `VK divergence check` CI job runs `compare` on every PR and uploads the freshly generated
keys as the `generated-vks` artifact (regardless of the outcome). When a change intentionally
alters the keys, take them from that artifact instead of regenerating locally:

```bash
gh run download <run-id> -R matter-labs/zksync-protocol \
  -n generated-vks -D crates/vk_regression_checker/reference
```

The artifact contains exactly the same file set as `reference/`, so this overwrites the whole
reference set in place. Review the resulting diff before committing.
