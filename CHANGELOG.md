# Changelog

## [0.150.19](https://github.com/matter-labs/zksync-protocol/compare/v0.150.18...v0.150.19) - 2024-12-20

### Other

- update Cargo.toml dependencies

## [0.150.18](https://github.com/matter-labs/zksync-protocol/compare/v0.150.17...v0.150.18) - 2024-12-18

### Other

- update Cargo.toml dependencies

## [0.150.17](https://github.com/matter-labs/zksync-protocol/compare/v0.150.16...v0.150.17) (2024-12-04)


### Bug Fixes

* **zkevm_circuits:** make zkevm_circuits compile with newest nightly rust ([#77](https://github.com/matter-labs/zksync-protocol/issues/77)) ([1aebbbe](https://github.com/matter-labs/zksync-protocol/commit/1aebbbe9e4b186b0539280c5923314f1d6b9973e))

## [0.150.16](https://github.com/matter-labs/zksync-protocol/compare/v0.150.15...v0.150.16) (2024-11-21)


### Features

* Support stable compiler for circuit_sequencer_api ([#58](https://github.com/matter-labs/zksync-protocol/issues/58)) ([f318e65](https://github.com/matter-labs/zksync-protocol/commit/f318e6537a20ef12244fb611a03778b203f986d0))

## [0.150.15](https://github.com/matter-labs/zksync-protocol/compare/v0.150.14...v0.150.15) (2024-11-20)


### Performance Improvements

* **circuit_definitions:** adjust proof configs for compression circuits ([#68](https://github.com/matter-labs/zksync-protocol/issues/68)) ([a411952](https://github.com/matter-labs/zksync-protocol/commit/a411952734f7dcac304b387c17a55e9ff1a9556c))

## [0.150.14](https://github.com/matter-labs/zksync-protocol/compare/v0.150.13...v0.150.14) (2024-11-19)


### Miscellaneous Chores

* bump crypto crates to 0.30.8 ([#69](https://github.com/matter-labs/zksync-protocol/issues/69)) ([9cd0b54](https://github.com/matter-labs/zksync-protocol/commit/9cd0b543a6619f94c50b0869a82b57288dc92264))

## [0.150.13](https://github.com/matter-labs/zksync-protocol/compare/v0.150.12...v0.150.13) (2024-11-18)


### Miscellaneous Chores

* bump crypto crates to 0.30.7 ([#66](https://github.com/matter-labs/zksync-protocol/issues/66)) ([e7f89fb](https://github.com/matter-labs/zksync-protocol/commit/e7f89fb306d12758ce60da16f3f1f921b7af3b55))

## [0.150.12](https://github.com/matter-labs/zksync-protocol/compare/v0.150.11...v0.150.12) (2024-11-06)


### Bug Fixes

* Compression setup generation ([#63](https://github.com/matter-labs/zksync-protocol/issues/63)) ([a17c0c0](https://github.com/matter-labs/zksync-protocol/commit/a17c0c0425e3c3c13f7c546d7c3f58ef264a502a))

## [0.150.11](https://github.com/matter-labs/zksync-protocol/compare/v0.150.10...v0.150.11) (2024-10-31)


### Features

* Generate light setup keys ([#56](https://github.com/matter-labs/zksync-protocol/issues/56)) ([587aaa1](https://github.com/matter-labs/zksync-protocol/commit/587aaa1530e0f44300530865a01777c42a3b1d85))

## [0.150.10](https://github.com/matter-labs/zksync-protocol/compare/v0.150.9...v0.150.10) (2024-10-31)


### Miscellaneous Chores

* bump crypto deps ([#59](https://github.com/matter-labs/zksync-protocol/issues/59)) ([e4d42e2](https://github.com/matter-labs/zksync-protocol/commit/e4d42e2ab1ff9c3f7767a1515f8407bb651c106f))

## [0.150.9](https://github.com/matter-labs/zksync-protocol/compare/v0.150.8...v0.150.9) (2024-10-29)


### Features

* **circuit_definitions:** naive snark-wrapper circuit for fflonk ([#50](https://github.com/matter-labs/zksync-protocol/issues/50)) ([53481d1](https://github.com/matter-labs/zksync-protocol/commit/53481d18eee028a72979ef32f930d40d1bfa0133))

## [0.150.8](https://github.com/matter-labs/zksync-protocol/compare/v0.150.7...v0.150.8) (2024-10-29)


### Miscellaneous Chores

* release 0.150.8 ([#54](https://github.com/matter-labs/zksync-protocol/issues/54)) ([fb1f3e2](https://github.com/matter-labs/zksync-protocol/commit/fb1f3e2f9cee1d352ca384e5869a771112ecc351))

## [0.150.7](https://github.com/matter-labs/zksync-protocol/compare/v0.150.6...v0.150.7) (2024-10-25)


### Bug Fixes

* remove the need for the `regex` crate's `pattern` feature ([#51](https://github.com/matter-labs/zksync-protocol/issues/51)) ([042ed7c](https://github.com/matter-labs/zksync-protocol/commit/042ed7c1d141f9da0ce54eb680bc42dc706371b2))

## [0.150.6](https://github.com/matter-labs/zksync-protocol/compare/v0.150.5...v0.150.6) (2024-10-07)


### Features

* Remove unneeded data and calculations from simulators in witgen ([#18](https://github.com/matter-labs/zksync-protocol/issues/18)) ([7316caf](https://github.com/matter-labs/zksync-protocol/commit/7316caf3428414c9cf8a1b9c4a7846bd813e4050))
* Reorganize witgen ([#49](https://github.com/matter-labs/zksync-protocol/issues/49)) ([9bf5cf8](https://github.com/matter-labs/zksync-protocol/commit/9bf5cf839f76a19f7c21981d8c56a7f8bbe03d7e))
* Use zeroes instead of simulator states as unused part of RAM permutation witness ([#47](https://github.com/matter-labs/zksync-protocol/issues/47)) ([a336980](https://github.com/matter-labs/zksync-protocol/commit/a3369809a760c448542d6e6877b95bbabac25d14))


### Bug Fixes

* Simplify closed_form_witness_from_full_form ([#38](https://github.com/matter-labs/zksync-protocol/issues/38)) ([af3d4c4](https://github.com/matter-labs/zksync-protocol/commit/af3d4c4995abf843c79813115716556b4216df53))
* **zkevm_test_harness:** Reduce ExtendedLogQuery RAM usage ([#44](https://github.com/matter-labs/zksync-protocol/issues/44)) ([eecf79a](https://github.com/matter-labs/zksync-protocol/commit/eecf79acebb15db168cf66534f7e1bb644526e72))

## [0.150.5](https://github.com/matter-labs/zksync-protocol/compare/v0.150.4...v0.150.5) (2024-09-06)


### Features

* Bump crypto dependencies ([#40](https://github.com/matter-labs/zksync-protocol/issues/40)) ([407645f](https://github.com/matter-labs/zksync-protocol/commit/407645f349052b47f224fc24febdf8f1618341a7))
* **ci:** Automatic releases on crates.io ([#24](https://github.com/matter-labs/zksync-protocol/issues/24)) ([24ff829](https://github.com/matter-labs/zksync-protocol/commit/24ff829f365b04948e349f9c5ad160d6e2eeae69))
* Introduce release-please ([#12](https://github.com/matter-labs/zksync-protocol/issues/12)) ([4bb5cca](https://github.com/matter-labs/zksync-protocol/commit/4bb5cca0b113f06185201d10db31a73f0f56ea1e))


### Bug Fixes

* Fix hard static analysis errors ([#14](https://github.com/matter-labs/zksync-protocol/issues/14)) ([ce50752](https://github.com/matter-labs/zksync-protocol/commit/ce50752e8c277537c40e3e16cfd6bc6f7ab8e700))
