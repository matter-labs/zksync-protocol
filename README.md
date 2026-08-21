# ZKsync Protocol Libraries

This repository contains the protocol libraries for ZKsync project,
including the implementation of out-of-circuit and in-circuit VM,
as well as utilities required for witness generation and CPU proving.

## Toolchain

This repository pins a specific Rust nightly in `rust-toolchain`; `rustup` will
pick it up automatically. The pinned toolchain is currently
**`nightly-2026-08-09`**.

A pinned nightly is required rather than stable: several crates rely on
`generic_const_exprs`, `allocator_api` and `portable_simd`. The pin is exact
because these features change shape between nightlies.

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
