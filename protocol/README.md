# ZKsync Protocol Libraries

This directory contains the protocol libraries for ZKsync project,
including the implementation of out-of-circuit and in-circuit VM,
as well as utilities required for witness generation and CPU proving.

It is a cargo workspace of its own, so cargo commands need to run from here (or
with `--manifest-path protocol/Cargo.toml`):

```bash
cd protocol
cargo build
cargo nextest run --release --manifest-path crates/zkevm_test_harness/Cargo.toml
```

The toolchain, the cargo config and the `cargo deny` policy come from the
repository root, which is the only copy of each.

## Crates

The project contains the following crates:

- [zk_evm_abstractions](./crates/zk_evm_abstractions/)
- [zkevm_opcode_defs](./crates/zkevm_opcode_defs/)
- [zkevm-assembly](./crates/zkEVM-assembly)
- [zkevm_circuits](./crates/zkevm_circuits/)
- [zk_evm](./crates/zk_evm/)
- [circuit_defintions](./crates/circuit_definitions/)
- [circuit_encodings](./crates/circuit_encodings/)
- [kzg](./crates/kzg/)
- [zkevm_test_harness](./crates/zkevm_test_harness/)

## Cross-directory dependencies

- The crates here depend on five crates in [`../crypto/`](../crypto) by path, so
  `cargo build` here does build them -- it just never runs their tests or format
  checks.
- The dependency runs the other way for [`../vm2/`](../vm2): it depends on
  `zk_evm`, `zk_evm_abstractions` and `zkevm_opcode_defs` by path, and nothing
  here refers to it, so `cargo build` here never compiles it.
