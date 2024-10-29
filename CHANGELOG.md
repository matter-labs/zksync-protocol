# Changelog

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
