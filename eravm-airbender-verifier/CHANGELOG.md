# Changelog

## [31.5.0](https://github.com/matter-labs/zksync-protocol/compare/a2bba259e5610dd89273021145489c030e8742ca...d8ed68225c81474dfd144441e43c41bbe0ebe325) (2026-10-19)


### Features

* **verifier:** support protocol v34 ([18649a7](https://github.com/matter-labs/zksync-protocol/commit/18649a737953fe87d4e8b0582c6e86e8eab11839))

## [31.4.1](https://github.com/matter-labs/zksync-protocol/compare/940093d08e5abcdcd70f28dd32eeaef28b452d7e...a2bba259e5610dd89273021145489c030e8742ca) (2026-10-13)


### Bug Fixes

* **verifier:** treat the bootloader as decommitted at batch start ([ace5359](https://github.com/matter-labs/zksync-protocol/commit/ace5359826ae5eae38cb9a9a483b9f74908553b5))

## [31.4.0](https://github.com/matter-labs/zksync-protocol/compare/2b8c077cb96f5845e0c3da0e3c37d4b7e7b9fb68...940093d08e5abcdcd70f28dd32eeaef28b452d7e) (2026-10-01)


### Features

* **verifier:** run the guest on a 4 GiB RAM image ([012ded2](https://github.com/matter-labs/zksync-protocol/commit/012ded2f68f05e56871d9e1f44d8abf22d435532))


### Bug Fixes

* **verifier:** serve only proven pre-batch slots, using read proofs ([3893f99](https://github.com/matter-labs/zksync-protocol/commit/3893f99c16fc3d35677adc60c92de87008a78252))

## [31.3.1](https://github.com/matter-labs/zksync-protocol/compare/c9d7964082a748224f6c332dd1a6c460eafa249b...2b8c077cb96f5845e0c3da0e3c37d4b7e7b9fb68) (2026-09-03)


### Bug Fixes

* **crypto:** v33 VK parity for the vendored zkos-wrapper + the wrapper optimization PRs ([892cd63](https://github.com/matter-labs/zksync-protocol/commit/892cd63e85aa7c37929b8ed50970601b8fe60d9f))

## [31.3.0](https://github.com/matter-labs/zksync-protocol/compare/6b3de1ba0c35ddbd33b4f2666719ef6743b76707...c9d7964082a748224f6c332dd1a6c460eafa249b) (2026-09-02)


### Features

* **verifier:** pin protocol-version semantics in-guest, accept newer minors on the wire ([f2e213e](https://github.com/matter-labs/zksync-protocol/commit/f2e213ebb416cca97f5febbc72b32a9d37ef7e64))

## [31.2.0](https://github.com/matter-labs/zksync-protocol/compare/698c5a98dde73edfe75930c001d2ce02fdd6d4fb...6b3de1ba0c35ddbd33b4f2666719ef6743b76707) (2026-09-02)


### Features

* **eravm-airbender-verifier:** share the repository nightly ([faad39f](https://github.com/matter-labs/zksync-protocol/commit/faad39fb2b355241e1bb8087552c580082947bea))

## [29.9.0](https://github.com/matter-labs/eravm-airbender-verifier/compare/v29.8.0...v29.9.0) (2026-07-06)


### Features

* **v31:** wire-format compatibility with zksync-era v31 ([#76](https://github.com/matter-labs/eravm-airbender-verifier/issues/76)) ([be8e91e](https://github.com/matter-labs/eravm-airbender-verifier/commit/be8e91ecf307b7868869de0d433a95455c86935e))


### Bug Fixes

* **types:** reject &gt;u16::MAX initial writes in compress_state_diffs ([#69](https://github.com/matter-labs/eravm-airbender-verifier/issues/69)) ([15b87f6](https://github.com/matter-labs/eravm-airbender-verifier/commit/15b87f623f4eb2db338373c7c6d96b90f904919a))
* **verifier:** bind committed storage reads to merkle_paths ([#57](https://github.com/matter-labs/eravm-airbender-verifier/issues/57)) ([91e3618](https://github.com/matter-labs/eravm-airbender-verifier/commit/91e3618ae5abf3a9c8414d299099026e364a0971))
* **verifier:** commit zero EVM-emulator hash for emulator-disabled chains ([#65](https://github.com/matter-labs/eravm-airbender-verifier/issues/65)) ([4c1e53e](https://github.com/matter-labs/eravm-airbender-verifier/commit/4c1e53e3d206618c3714d1efbf16ba3bd8661e79))
* **verifier:** pin default_validation_computational_gas_limit ([#63](https://github.com/matter-labs/eravm-airbender-verifier/issues/63)) ([d6ff5a7](https://github.com/matter-labs/eravm-airbender-verifier/commit/d6ff5a7730907b87eb42591f7285d04f47a43d6b))
* **verifier:** pin system_env.execution_mode to VerifyExecute ([#62](https://github.com/matter-labs/eravm-airbender-verifier/issues/62)) ([5e1d6e8](https://github.com/matter-labs/eravm-airbender-verifier/commit/5e1d6e88b20d2fa8e44f7337d646ba81a74ef57a))
* **verifier:** reject batches/txs whose execution Halted ([#68](https://github.com/matter-labs/eravm-airbender-verifier/issues/68)) ([8fffbd9](https://github.com/matter-labs/eravm-airbender-verifier/commit/8fffbd97464898c7b630754af6cecd76b9830e95))
* **vm_interface:** reject oversized revert-reason words instead of panicking ([#64](https://github.com/matter-labs/eravm-airbender-verifier/issues/64)) ([e3ca953](https://github.com/matter-labs/eravm-airbender-verifier/commit/e3ca9537ee118d3d8a4ae96a1eba17f57bd2ecbb))


### Performance Improvements

* **guest:** compile out the circuit tracer in proving mode ([#72](https://github.com/matter-labs/eravm-airbender-verifier/issues/72)) ([42b8bb0](https://github.com/matter-labs/eravm-airbender-verifier/commit/42b8bb0d9a02d7d3b2870a110ad35d7729fc119a))

## [29.8.0](https://github.com/matter-labs/eravm-airbender-verifier/compare/v29.7.1...v29.8.0) (2026-06-19)


### Features

* CPU-only SNARK prover via optional gpu_fri feature ([#55](https://github.com/matter-labs/eravm-airbender-verifier/issues/55)) ([c09bf3d](https://github.com/matter-labs/eravm-airbender-verifier/commit/c09bf3ddcd12de0f8fa2d998ad5d1d0cb2b00602))
* Implement public output ([#4](https://github.com/matter-labs/eravm-airbender-verifier/issues/4)) ([bda698c](https://github.com/matter-labs/eravm-airbender-verifier/commit/bda698caec22f6614bac8b1588922f7d62b8253d))
* Initial implementation ([#2](https://github.com/matter-labs/eravm-airbender-verifier/issues/2)) ([dcb0b56](https://github.com/matter-labs/eravm-airbender-verifier/commit/dcb0b560b5c1924aa39c850d6a272ee5e168453e))
* Integrate updated wrapper ([#7](https://github.com/matter-labs/eravm-airbender-verifier/issues/7)) ([b58bd77](https://github.com/matter-labs/eravm-airbender-verifier/commit/b58bd7781a3bb54695188c204f9631bd5407fd05))
* **server:** bump airbender to v0.2.3, wire GpuProverConfig ([#54](https://github.com/matter-labs/eravm-airbender-verifier/issues/54)) ([18e6607](https://github.com/matter-labs/eravm-airbender-verifier/commit/18e6607107da1377ed9f928ca2619396e28fcb51))
* **server:** load FRI and SNARK VKs from disk, add vks/ + CI guards ([#22](https://github.com/matter-labs/eravm-airbender-verifier/issues/22)) ([f67b533](https://github.com/matter-labs/eravm-airbender-verifier/commit/f67b53370be3f69d5deb7928f677ccce72439b6f))
* **server:** report errors and panics to Sentry ([#46](https://github.com/matter-labs/eravm-airbender-verifier/issues/46)) ([0d3cf76](https://github.com/matter-labs/eravm-airbender-verifier/commit/0d3cf76ab151136b293256232ff870c6f657bebd))
* **server:** Use prover as a server ([#3](https://github.com/matter-labs/eravm-airbender-verifier/issues/3)) ([0e57505](https://github.com/matter-labs/eravm-airbender-verifier/commit/0e575052bafe898b2ba264e6e253e03eedbb19e3))


### Bug Fixes

* **ci:** grant update-vks dispatcher pull-requests: write ([#24](https://github.com/matter-labs/eravm-airbender-verifier/issues/24)) ([ccb2b4e](https://github.com/matter-labs/eravm-airbender-verifier/commit/ccb2b4e072aef6046e51cf9f1e9094b8b132b411))
* **ci:** set GH_REPO so update-vks gh calls work without a checkout ([#25](https://github.com/matter-labs/eravm-airbender-verifier/issues/25)) ([9a7582e](https://github.com/matter-labs/eravm-airbender-verifier/commit/9a7582e425f6e26a07b4a934e965f1225387c87a))
* harden verifier witness validation and VM rollback ([#45](https://github.com/matter-labs/eravm-airbender-verifier/issues/45)) ([9881acb](https://github.com/matter-labs/eravm-airbender-verifier/commit/9881acbdcd19ddbc881524d08a218f523994abaf))
* **host:** wire security level into the GPU prover ([#13](https://github.com/matter-labs/eravm-airbender-verifier/issues/13)) ([75e3051](https://github.com/matter-labs/eravm-airbender-verifier/commit/75e30513778546675d773e66ac92e2011a92090a))
* **server:** catch prover panics and report them as failed proofs ([#56](https://github.com/matter-labs/eravm-airbender-verifier/issues/56)) ([063da52](https://github.com/matter-labs/eravm-airbender-verifier/commit/063da529d57a9e3ae793e19eb571b418eedbf4d1))
* **server:** deserialize FRI input as flat struct from zksync-era ([#30](https://github.com/matter-labs/eravm-airbender-verifier/issues/30)) ([6f2d8bc](https://github.com/matter-labs/eravm-airbender-verifier/commit/6f2d8bca06da853de219618de8e36b9a70496f47))
