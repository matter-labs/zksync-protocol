# EraVM Airbender Verifier

This directory combines reduced EraVM verifier libraries with an Airbender guest and host proving app.
It is used to reproduce ZKsync Era mainnet batch verification, compare VM execution, generate Airbender
FRI proofs, and wrap those proofs into SNARK proofs.

The long-running prover service that drives this pipeline in production lives in `zksync-era`, not here.
This workspace is self-contained around the guest, the `eravm-prover-host` CLI/library, and the verifier
libraries; the service consumes `eravm-prover-host` as a dependency.

## Vendored from `matter-labs/eravm-airbender-verifier`

This directory is a copy of [matter-labs/eravm-airbender-verifier] at the tip of its `main`
branch. This copy is the source of truth from now on: changes are made here, not upstream.

It is a **separate cargo workspace**, so every `cargo` command below has to run from this
directory (or with `--manifest-path eravm-airbender-verifier/Cargo.toml`). Two things about it are
worth knowing, and the header comment in [`Cargo.toml`](./Cargo.toml) explains both: the protocol,
vm2 and wrapper dependencies are **path** dependencies on `../protocol/`, `../vm2/` and
`../zkos-wrapper/` rather than published git tags, and the only toolchain file here is
`guest/rust-toolchain.toml`, which governs the build of the guest binary -- a release artifact,
reproducible only for a fixed toolchain. Everything else defers to the repository-root
`rust-toolchain`.

CI for this workspace is the `verifier-*` job group in
[`../.github/workflows/ci.yaml`](../.github/workflows/ci.yaml); its releases and their assets are
described in [`../RELEASE.md`](../RELEASE.md).

[matter-labs/eravm-airbender-verifier]: https://github.com/matter-labs/eravm-airbender-verifier

## Layout

- `crates/`: reduced verifier libraries extracted from `zksync-era` (entrypoint crate: `zksync_airbender_verifier`).
- `guest/`: Airbender guest program that reads `AirbenderVerifierInput` and runs `verify()`.
- `host/`: host runner/prover app for batch execution and proof generation.
- `testdata/era_mainnet_batches/`: compressed mainnet batch corpus tracked via Git LFS.

## Quick Start

Build guest artifacts:

```sh
cargo airbender build --project guest
```

Install Git LFS if `git lfs` is not available yet:

Ubuntu:

```sh
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get update
sudo apt-get install git-lfs
git lfs install
```

macOS:

```sh
brew install git-lfs
git lfs install
```

Fetch one compressed mainnet batch from Git LFS:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz
```

Compare legacy and fast VM execution on that batch:

```sh
cargo run --release -p zksync_vm_compare --bin vm_compare -- --batch-files 84730.bin.gz
```

Run host execution:

```sh
cargo run --release -p eravm-prover-host -- --action run --batch-files 84730.bin.gz
```

Run host proving:

```sh
cargo run --release -p eravm-prover-host -- --action prove --batch-files <number>.bin.gz
```

Process all available batches:

```sh
cargo run --release -p eravm-prover-host -- --action prove --all-batches
```

## Mainnet Batch Corpus

The repository stores reproducible batch inputs in `testdata/era_mainnet_batches/binary/*.bin.gz`.
Those files are tracked via Git LFS and excluded by default via the repository-root [`.lfsconfig`](../.lfsconfig), so a normal clone keeps only small pointer files until you explicitly fetch the batches you want. That file also points Git LFS at the upstream repository's object store, which is where the corpus lives -- read it before adding LFS content anywhere in this repository.

If `git lfs` is missing, install it first:

Ubuntu:

```sh
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get update
sudo apt-get install git-lfs
git lfs install
```

macOS:

```sh
brew install git-lfs
git lfs install
```

Fetch the same curated batches that CI uses:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz,84731.bin.gz,84732.bin.gz
```

Fetch every tracked batch:

```sh
./scripts/fetch_lfs_batches.sh --all
```

The default `--batches-dir` assumes you run these `cargo run -p ...` commands from this workspace's root (`eravm-airbender-verifier/`). If you invoke the binaries from another directory, pass `--batches-dir` explicitly.

Import the existing local corpus into the repo as compressed Git LFS objects:

```sh
./scripts/import_mainnet_batches.sh \
  --source-dir /home/popzxc/workspace/airbender/storage/era_mainnet_batches/binary \
  --all
```

More detailed batch-data instructions live in [testdata/era_mainnet_batches/README.md](testdata/era_mainnet_batches/README.md).

## Full e2e proving flow

If you're going to use GPU proving for SNARK, you also need to set up bellman CUDA.

Important: right now, bellman-cuda supports ONLY CUDA 12, while airbender can work with both 12 and 13.
So if you have CUDA 13 installed, your options are either to rely on CPU proving if acceptable, or install CUDA 12 instead.

```bash
# `era-bellman-cuda` & SNARK wrapper use old code that doesn't always respect `CUDA_HOME` and instead
# on linux checks `/usr/local/cuda`
echo $CUDA_HOME
# If your output is not `/usr/local/cuda`, you might want to create a symlink, e.g. `sudo ln -s /opt/cuda /usr/local/cuda`.

if [ ! -d "era-bellman-cuda" ]; then
    git clone https://github.com/matter-labs/era-bellman-cuda.git
else
    echo "era-bellman-cuda repository already exists. Skipping clone."
fi
# Now cmake will find the CUDA compiler (nvcc) via the updated PATH
cmake -Bera-bellman-cuda/build -Sera-bellman-cuda/ -DCMAKE_BUILD_TYPE=Release
cmake --build era-bellman-cuda/build/ -j16

BELLMAN_CUDA_DIR="$(pwd)/era-bellman-cuda"

# === IMPORTANT ===
# Add BELLMAN_CUDA_DIR to your *rc file (e.g. `.bashrc` / `.zshrc`)!
```
Then you can use the following flow:

```bash
# Clone the repo and set up the branch (check out the required branch)
git clone https://github.com/matter-labs/zksync-protocol.git
cd zksync-protocol/eravm-airbender-verifier
git checkout <desired_branch> # e.g. popzxc-snark-integrated-properly at the time of writing

# Download artifacts for proving
git lfs install

# Set up CRS key and stack for SNARK proving. The trusted setup must already
# exist on disk before the prover starts — point at it via `--trusted-setup`
# or `SNARK_TRUSTED_SETUP_FILE` (mirrors era's `KZG_TRUSTED_SETUP_FILE`).
# IMPORTANT: CPU/GPU use different keys. The `download-trusted-setup`
# subcommand picks the right URL based on the build's `gpu_snark` feature.
cargo run --release -p eravm-prover-host -- download-trusted-setup --output setup.key &
cargo run --release -p eravm-prover-host --features gpu_snark -- download-trusted-setup --output setup_gpu.key

ulimit -s unlimited

# Generate FRI proof
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host --features gpu_snark -- prove-fri --batch-files 84730.bin.gz --output-dir ./artifacts/proofs

# Generate SNARK proof
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host --features gpu_snark -- prove-snark --proof-files ./artifacts/proofs/batch-84730/fri_proof.json  --output-dir ./artifacts/proofs --trusted-setup setup_gpu.key
```

If you need to save intermediate SNARK artifacts:

```bash
# On CPU
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host -- prove-snark --proof-files ./artifacts/proofs/batch-84730/fri_proof.json  --output-dir ./artifacts/proofs --trusted-setup setup.key --save-intermediates

# On GPU
RUST_BACKTRACE=1 RUST_LOG=info cargo run --release -p eravm-prover-host --features gpu_snark -- prove-snark --proof-files ./artifacts/proofs/batch-84730/fri_proof.json  --output-dir ./artifacts/proofs --trusted-setup setup_gpu.key --save-intermediates
```

Note: `--features gpu_snark` is not technically required, it enables GPU SNARK proving, without it FRI proving will still be done on GPU, but SNARK wrapping will be done on CPU. If you use CPU, don't forget to use the correct CRS key.

### Verification keys

The canonical FRI and SNARK verification keys are published as GitHub **release assets** (`fri_vk.bin`, `snark_vk.json`), alongside the guest binary (`app.bin`, `app.text`) and a `checksums.txt`. They are built from the released commit by [`../.github/workflows/release-artifacts.yaml`](../.github/workflows/release-artifacts.yaml) — not committed to the repo — so they always match the source they were derived from. The server loads them from disk rather than deriving them on the fly; download them from a release or point the server at a local copy via `--fri-vk` (`FRI_VK`). See [`vks/README.md`](vks/README.md).

VK generation is costly (GPU + trusted setup). CI regenerates the keys from the PR's freshly-built guest to run the proving test (the `verifier-host-integration-run` job, only when guest/VK-relevant code changes), and the release build regenerates them to publish the assets — but you don't normally need keys locally. Regenerate them locally only when proving against a locally-changed guest:

```bash
cargo run --release -p eravm-prover-host --features gpu_snark -- gen-vks \
    --output-dir vks \
    --trusted-setup setup_gpu.key
```

### Guest memory (heap arena)

The guest runs on a fixed heap of **4022 MiB**, pinned by a `-C link-arg=--defsym=_heap_size=...` link-arg in [`guest/.cargo/config.toml`](guest/.cargo/config.toml) — that file carries the exact byte count, deliberately not duplicated here; without it the arena would be the 768 MiB default that the pinned `riscv_common` `link.x` provides. The host runs the machine with a 4 GiB RAM image (`RamSize::FourGb` on every runner and prover). Host memory per simulator instance: the interpreter reserves 16 GiB of virtual memory and commits only what the guest touches; the JIT allocates and zeroes 12 GiB per run; the GPU prover page-locks two 12 GiB images (24 GiB) when it is built. The guest links against its own [`guest/eravm_memory.x`](guest/eravm_memory.x) in place of `riscv_common`'s 1 GiB `memory.x`: ROM 4 MiB + RAM 4090 MiB, stopping 2 MiB short of 2^32 so `_eheap` stays a 32-bit address. `.heap` starts at the 2 MiB-aligned end of `.bss` (70 MiB today) — so **4024 MiB is the hard maximum** and 4022 leaves one alignment slot of cushion for static growth.

Two consequences worth knowing:

- **The arena size is VK-relevant.** It is baked into `app.bin` (the `lui` immediate that materializes `_eheap`), so changing it changes the guest sha and therefore both verification keys: it ships as a patch upgrade like any other guest change, never as a runtime knob. [`scripts/check_guest_memory_layout.sh`](scripts/check_guest_memory_layout.sh) asserts the linked arena on every CI guest build, so a guest built without the flag — a rustflags list re-authored without it (the `cargo airbender new` scaffold is exactly that shape), an upstream `PROVIDE` change, a toolchain precedence change — fails the build instead of shipping as a binary no registered VK accepts.
- **Overshooting fails loudly.** A value larger than the RAM region can hold is a link error (`section '.heap' will not fit in region 'RAM'`), never a silent overrun into memory the prover does not have.
- **The allocator splits the arena.** airbender-rt's talc allocator claims the arena as heaps of at most `isize::MAX` bytes: talc's gap arithmetic is undefined behaviour on a single gap past 2 GiB. CI runs a batch on a guest built with Rust's UB precondition checks ([`scripts/guest_ub_checks.toml`](scripts/guest_ub_checks.toml)), which panics on the first allocation if the split regresses, including through an airbender bump.
### CUDA-free builds

The FRI prover always runs on GPU (Airbender's CUDA `gpu_prover`), so the default build links CUDA. The default-on `gpu_fri` cargo feature gates that dependency, so a `--no-default-features` build of `eravm-prover-host` is completely CUDA-free — it can verify FRI proofs and wrap them into SNARKs on CPU, but cannot generate FRI proofs:

```bash
cargo build --release --no-default-features -p eravm-prover-host
```

### Integration tests

`host/tests/integration_test.rs` drives the proving pipeline in-process (no server). The tests are `#[ignore]` because they need the LFS batch corpus — and, for proving, a GPU, the guest binary, and the SNARK trusted setup. CI runs the end-to-end proving test in the `verifier-host-integration-run` job whenever guest/VK-relevant code changes, deriving the VKs from the PR's freshly-built guest. Run it locally with:

```bash
# CPU-only: native verification vs. transpiler execution
cargo test -p eravm-prover-host --test integration_test \
    -- --ignored --nocapture host_runs_batch_native_and_transpiler

# GPU: FRI proving followed by SNARK wrapping, end to end
cargo test -p eravm-prover-host --features gpu_snark --test integration_test \
    -- --ignored --nocapture host_proves_fri_then_snark
```

## Policies

- [Security policy](SECURITY.md)
- [Contribution policy](CONTRIBUTING.md)

## License

Licensed under either of:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Official Links

- [Website](https://zksync.io/)
- [GitHub](https://github.com/matter-labs)
- [ZK Credo](https://github.com/zksync/credo)
- [Twitter](https://twitter.com/zksync)
- [Twitter for Developers](https://twitter.com/zkSyncDevs)
- [Discord](https://join.zksync.dev/)
- [Mirror](https://zksync.mirror.xyz/)
- [Youtube](https://www.youtube.com/@zkSync-era)

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
