# High-Performance ZKsync Era VM (EraVM)

A high-performance rewrite of the out-of-circuit VM for ZKsync Era (aka EraVM).

See [Era docs](https://github.com/matter-labs/zksync-era/tree/main/docs/specs/zk_evm) for the VM overview and formal specification.

## Vendored from `matter-labs/vm2`

This directory is a copy of [matter-labs/vm2] at commit
[`12acc209`][upstream-commit] (tag `v0.7.0`, 2026-08-25). This copy is the
source of truth from now on: changes are made here, not upstream.

It is a **separate cargo workspace** and keeps its own version line (`0.7.0`),
its own `Cargo.lock` and its own lint policy (`missing_docs`,
`clippy::pedantic`). Build and test it from this directory:

```bash
cd vm2
cargo test -p zksync_vm2_interface -p zksync_vm2 --all-targets
```

What changed relative to upstream, and why:

- `zkevm_opcode_defs`, `zk_evm_abstractions` and `zk_evm` are **path
  dependencies** on `../protocol/crates/...` instead of a `zksync-protocol` git
  tag. That is the point of vendoring: a protocol change and the vm2 change it
  forces land in one commit, and CI builds vm2 against the working tree rather
  than the last published tag.
- `rust-toolchain.toml` is gone; the root `rust-toolchain` governs this
  directory too, so the two workspaces cannot pin different nightlies.
- `deny.toml` lives only at the repository root, so both workspaces are held to a
  single advisory/licence policy with nothing to drift (see
  `.github/workflows/deny.yaml`).
- CI lives in the repo-wide workflows: the `vm2-build-and-test` and `vm2-fuzz`
  jobs in `.github/workflows/ci.yaml` are the port of upstream's `ci.yml`, and
  they gate the mandatory `Github Status Check`. Upstream's `gh-pages` docs
  deploy was dropped (this repository publishes no docs site);
  the rustdoc build it guarded is kept as a CI step. Release automation is
  **not** wired up -- vm2 is not part of this repository's release-please
  configuration, and it is not published to crates.io.
- Repository-level GitHub metadata that the host repository already provides
  (`CODEOWNERS`, `SECURITY.md`, `CONTRIBUTING.md`, issue and PR templates,
  the secret scanner and PR-title workflows) was not copied.

[matter-labs/vm2]: https://github.com/matter-labs/vm2
[upstream-commit]: https://github.com/matter-labs/vm2/commit/12acc209b1ecdfe707d6b3582c8315ad31896fb8

## Overview

This workspace contains the following crates:

- [`zksync_vm2_interface`](crates/vm2-interface): stable VM interface for tracers
- [`zksync_vm2`](crates/vm2): VM implementation itself
- [`zksync_vm2_afl_fuzz`](tests/afl-fuzz): [AFL](https://crates.io/crates/afl)-based fuzzing for the VM.

## License

ZKsync Era VM is distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.
