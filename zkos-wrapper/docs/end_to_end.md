# Running end to end wrapper

## Prerequisites

You need up to three files depending on the command:

- **risc_proof.json** - the final program proof from airbender (`UnrolledProgramProof`), generated with `--until final-proof`
- **setup.key** - trusted setup (CRS) file for the final SNARK (see [CRS](./overview.md##Crs) section). Only needed for SNARK-related commands.
- **app.bin / app.text** *(optional)* - RISC-V binary and text sections. If omitted, the default unified recursion verifier binary is used.

## CLI overview

```
wrapper [OPTIONS] <COMMAND>

Commands:
  prove-all           Full pipeline: FRI proof -> SNARK proof (phases 1+2+3)
  prove-risc-wrapper  Phase 1: Wrap FRI proof into a boojum STARK proof
  prove-compression   Phase 2: Compress a STARK wrapper proof
  prove-snark         Phase 3: Wrap compressed STARK proof into a BN256 SNARK
  generate-vk         Generate verification keys without a proof
  vk-hash             Compute the Keccak256 hash of a SNARK verification key
  verify              Verify a proof at any pipeline stage

Options:
  --threads <N>       Number of worker threads (defaults to all available cores)
```

## Running the full pipeline

Generate a SNARK proof from an airbender FRI proof in one step:

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  prove-all \
  --proof path/to/risc_proof.json \
  --output-dir /tmp/snark_output \
  --trusted-setup path/to/setup.key
```

This runs all three phases sequentially (RISC wrapper, compression, SNARK wrapper) and outputs `snark_proof.json` and `snark_vk.json`.

Use `--save-intermediates` to also save the RISC wrapper and compression outputs.

Use `--use-zk` to enable zero-knowledge padding in the SNARK phase.

**Note:** if `--trusted-setup` is omitted, the wrapper uses a fake trusted setup (`crs_42`), which **must not** be used for production but can be used for local testing.

## Running individual phases

### Phase 1: RISC wrapper (FRI -> STARK)

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  prove-risc-wrapper \
  --proof path/to/risc_proof.json \
  --output-dir /tmp/phase1_output
```

Outputs `risc_wrapper_proof.json` and `risc_wrapper_vk.json`.

To use a custom binary instead of the default recursion verifier:

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  prove-risc-wrapper \
  --proof path/to/risc_proof.json \
  --bin path/to/app.bin \
  --text path/to/app.text \
  --output-dir /tmp/phase1_output
```

### Phase 2: Compression (STARK -> STARK)

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  prove-compression \
  --risc-wrapper-proof /tmp/phase1_output/risc_wrapper_proof.json \
  --risc-wrapper-vk /tmp/phase1_output/risc_wrapper_vk.json \
  --output-dir /tmp/phase2_output
```

Outputs `compression_proof.json` and `compression_vk.json`.

### Phase 3: SNARK wrapper (STARK -> BN256 SNARK)

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  prove-snark \
  --compression-proof /tmp/phase2_output/compression_proof.json \
  --compression-vk /tmp/phase2_output/compression_vk.json \
  --trusted-setup path/to/setup.key \
  --output-dir /tmp/phase3_output
```

Outputs `snark_proof.json` and `snark_vk.json`, and prints the VK hash.

## Generating verification keys

Generate all verification keys (RISC wrapper, compression, SNARK) without needing a proof:

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  generate-vk \
  --trusted-setup path/to/setup.key \
  --output-dir /tmp/vk_output
```

Outputs `risc_wrapper_vk.json`, `compression_vk.json`, and `snark_vk.json`.

To generate VKs for a custom binary:

```bash
RUST_MIN_STACK=67108864 cargo +nightly run --bin wrapper --release -- \
  generate-vk \
  --bin path/to/app.bin \
  --text path/to/app.text \
  --trusted-setup path/to/setup.key \
  --output-dir /tmp/vk_output
```

## Computing VK hash

Get the Keccak256 hash of a SNARK VK for use in Ethereum contracts:

```bash
cargo +nightly run --bin wrapper --release -- \
  vk-hash --vk path/to/snark_vk.json
```

## Verifying proofs

Verify a proof at any stage:

```bash
cargo +nightly run --bin wrapper --release -- \
  verify --stage risc-wrapper \
  --proof path/to/risc_wrapper_proof.json \
  --vk path/to/risc_wrapper_vk.json
```

Supported `--stage` values: `risc-wrapper`, `compression`, `snark`.

## Regenerating wrapper

If you need to regenerate the wrapper due to changes in the airbender recursion circuit:

```bash
cargo +nightly run --bin wrapper_generator --release
```

<!-- TODO: GPU section -->
