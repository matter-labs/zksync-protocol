# ZKsync Protocol Libraries

This repository contains the protocol libraries for ZKsync project,
including the implementation of out-of-circuit and in-circuit VM,
as well as utilities required for witness generation and CPU proving.

## Workspaces

The code is split across several **cargo workspaces**. Each one is
self-contained -- its own version line, its own `Cargo.lock` and its own lint
policy -- and there is deliberately no workspace at the repository root, so no
workspace has to `exclude` (or even know the layout of) the others. Cargo
commands have to be run from inside a workspace directory, or with an explicit
`--manifest-path`.

| Directory | Version line | What it is |
| --- | --- | --- |
| [`protocol/`](./protocol) | `0.153.x` | The protocol crates: in-circuit and out-of-circuit VM, witness generation, CPU proving. See [`protocol/README.md`](./protocol/README.md) for the crate list. |
| [`crypto/`](./crypto) | `0.32.x` | The cryptography libraries (`boojum`, `bellman`, `franklin-crypto`, `pairing`, ...), vendored. Formats at 200 columns. |
| [`vm2/`](./vm2) | `0.7.x` | The high-performance out-of-circuit EraVM rewrite, vendored from `matter-labs/vm2`. Its own lint policy (`missing_docs`, `clippy::pedantic`). |
| [`crypto-gpu/`](./crypto-gpu) | `0.156.x` | The CUDA provers (`shivini`, `boojum-cuda`, `gpu-prover`, ...), vendored. Building it needs a CUDA toolkit, so only its own jobs do. |
| [`eravm-airbender-verifier/`](./eravm-airbender-verifier) | `31.x` | The EraVM verifier libraries, the Airbender guest that runs them and the `eravm-prover-host` CLI, vendored from `matter-labs/eravm-airbender-verifier`. Its releases carry the guest binary and the verification keys as assets. |
| [`zkos-wrapper/`](./zkos-wrapper) | `0.1.x` | The wrapper that turns an Airbender proof into a SNARK, vendored. |

They are not independent of one another, which is the point of keeping them in
one repository: a change and the changes it forces elsewhere land in one commit,
and CI builds each workspace against the working tree rather than the last
published tag. `protocol/` depends on five `crypto/` crates by path; `vm2/`
depends on three `protocol/` crates by path; `crypto-gpu/` depends on two
`protocol/` crates and five `crypto/` ones; `eravm-airbender-verifier/` depends
on two `protocol/` crates and on `vm2/` and `zkos-wrapper/`; `zkos-wrapper/`
depends on four `crypto/` crates and, under its `gpu` feature, on three in
`crypto-gpu/`. Only its airbender dependencies come from outside the repository,
there being no airbender workspace here.

A PR runs the checks for every workspace its diff can reach, following those
edges (see [`.github/workflows/ci.yaml`](./.github/workflows/ci.yaml)). Two sets
of jobs sit outside that: the crypto-gpu tests in
[`.github/workflows/test-gpu.yaml`](./.github/workflows/test-gpu.yaml), which
need a GPU runner, and the verifier's end-to-end proving run, which is in
`ci.yaml` but only fires when the diff can reach the guest binary or a
verification key.

What they share is what sits at the root: the [`rust-toolchain`](./rust-toolchain)
pin, [`.cargo/config.toml`](./.cargo/config.toml) and the
[`deny.toml`](./deny.toml) advisory/licence policy. There is one copy of each and
no copies inside the workspaces: rustup, cargo and cargo-deny all find these by
walking up from the working directory, so there is nothing to keep in sync. The
one exception is `eravm-airbender-verifier/guest/rust-toolchain.toml`, which
shadows the root pin for the guest directory and nothing else, because it governs
the build that produces the reproducible release artifact.

Git LFS is used by one thing only -- the mainnet batch corpus under
`eravm-airbender-verifier/testdata/` -- and the root [`.lfsconfig`](./.lfsconfig)
keeps those objects out of a normal clone. Read that file before adding LFS
content of your own: it points every LFS operation in this repository at the
upstream verifier repository's store, which is where the corpus lives.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
