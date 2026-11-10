# ZKOS Wrapper - Overview

## Why do we need this wrapper?

In [airbender](https://github.com/matter-labs/zksync-airbender/tree/main) we can prove an arbitrary number of RISC-V cycles with multiple proofs and compress them into a single proof via recursion. But verifying such a proof directly on L1 would be expensive. Our purpose is to wrap the final airbender proof into a SNARK verifiable on Ethereum.

We already use [Snark wrapper](https://github.com/matter-labs/zksync-crypto/tree/main/crates/snark-wrapper) to wrap boojum STARK proofs into SNARKs. So we only need to implement an airbender → boojum wrapper. The full wrapping pipeline looks like this:

![diagram](../diagram.svg)

**Note:** we also use a `Compression` step (boojum → boojum re-proof) to make the proof small enough to fit into the `SnarkWrapper`. It also re-hashes the Merkle tree commitments from Goldilocks Poseidon2 to Bn256-compatible Poseidon2 for the SNARK wrapper.

## Wrapping pipeline

| Phase | Name | From | To |
|-------|------|------|----|
| 1 | RISC Wrapper | Airbender FRI proof (Blake2s Merkle trees) | Boojum STARK proof (Goldilocks Poseidon2) |
| 2 | Compression | Boojum STARK proof (Goldilocks Poseidon2) | Boojum STARK proof (Bn256-compatible Poseidon2) |
| 3 | SNARK Wrapper | Boojum STARK proof (Bn256-compatible Poseidon2) | BN256 SNARK proof |

## Repository components

- [wrapper](../wrapper/) — the main crate containing the wrapping pipeline
    - [inner_verifiers](../wrapper/src/inner_verifiers/) — verification logic for the two airbender proofs that the wrapper consumes:
        - `unified_reduced` — verifier for the main unified reduced machine proof
        - `blake_delegation` — verifier for the Blake2s delegation proof
        - `shared` — common skeleton structures and verification logic shared between the two verifiers
    - [wrapper_utils](../wrapper/src/wrapper_utils/) — circuit representation of airbender structs and traits used for verification
    - [transcript](../wrapper/src/transcript/) — Blake2s hash (for Merkle trees and transcript) and transcript (for random challenges)
    - [circuits](../wrapper/src/circuits/) — circuit definitions for all three pipeline phases: `risc_wrapper`, `compression`, and `snark_wrapper`
- [wrapper_generator](../wrapper_generator/) — generates code used in the inner verification functions
- [circuit_mersenne_field](../circuit_mersenne_field/) — circuit representation of the Mersenne31 field used in the wrapper

## What does the RISC wrapper verify?

The RISC wrapper circuit (Phase 1) verifies **two** airbender proofs simultaneously:
1. A **unified reduced machine** proof — the main execution proof from the final recursion layer
2. A **Blake2s delegation** proof — the proof for Blake2s precompile calls delegated during execution

Both proofs are provided together in the `UnrolledProgramProof` from airbender and extracted into `RiscWrapperWitness` for the wrapper circuit.

The circuit's public inputs are a Keccak256 hash of RISC-V registers 10–25:
- **registers 10–17** — output of the base program
- **registers 18–25** — auxiliary registers storing the execution trace hash and the chain of executed programs

These public inputs propagate through compression and the SNARK all the way to L1 verification.

## Why do we need `wrapper_generator`?

Usually, a verification function takes a VK (verification key) as an argument to specify what exact circuit to verify. However, in our case we hardcode all the inner airbender circuit parameters into the wrapper itself for optimization. The `wrapper_generator` generates four files — two per inner verifier:

- [unified_reduced/imports/](../wrapper/src/inner_verifiers/unified_reduced/imports/):
    - `circuit_layout.rs` — constants specifying the geometry of the unified reduced machine circuit
    - `circuit_quotient.rs` — the quotient part of verification
- [blake_delegation/imports/](../wrapper/src/inner_verifiers/blake_delegation/imports/):
    - `circuit_layout.rs` — constants specifying the geometry of the Blake2s delegation circuit
    - `circuit_quotient.rs` — the quotient part of verification

Both imports directories also contain a `circuit_layout.json` — the serialized `CompiledCircuitArtifact` loaded at runtime for proof deserialization. These are not produced by the generator and must be updated separately when the airbender circuits change.

We also need to verify that the correct code was executed. This is handled by `BinaryCommitment` (defined in `circuits/risc_wrapper.rs`), which computes a commitment (`end_params`) from the RISC-V binary — identifying which program was run on the last airbender circuit.

By default, the wrapper uses the built-in unified recursion verifier binary. Custom binaries can be provided via the `--bin` and `--text` CLI flags.

## CRS

CRS (common reference string) is a trusted setup required for the final SNARK (inner KZG commitment). You can download it with:

```bash
curl https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_2\^24.key --output setup.key
```

If `--trusted-setup` is omitted from CLI commands, the wrapper uses a fake trusted setup (`crs_42`), which **must not** be used for production but is fine for local testing.

## Testing

The main integration tests live in [wrapper/src/tests/](../wrapper/src/tests/). The `all_layers_full_test` test runs the full pipeline (all three phases) using a Fibonacci program as input.

**Note:** running the full test requires ~150GB RAM and a large stack (`RUST_MIN_STACK=67108864`).

## Running the wrapper

See [Running end to end](./end_to_end.md) for full CLI documentation covering all commands (`prove-all`, `prove-risc-wrapper`, `prove-compression`, `prove-snark`, `generate-vk`, `vk-hash`, `verify`).

## Regenerating wrapper

If the airbender recursion circuit changes, regenerate the inner verifier code:

```bash
cargo +nightly run --bin wrapper_generator --release
```
