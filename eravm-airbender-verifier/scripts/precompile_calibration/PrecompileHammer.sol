// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Generates precompile-dominated batches for calibrating the Airbender
/// cycle-cost model. Each call loops `count` staticcalls to a single precompile
/// with a fixed `input`, so a batch full of one function's transactions is
/// dominated by exactly one precompile's `*_cycles` feature — the isolation the
/// NNLS fit needs to attribute a clean coefficient.
///
/// Deliberately minimal contamination: the only state change is one `calls`
/// increment per transaction (so it is unambiguously a state-changing tx that
/// seals into a batch); there is no per-iteration hashing or storage, which
/// would inject keccak256/storage features and blur the isolation.
contract PrecompileHammer {
    /// Bumped once per transaction so the tx is state-changing (negligible vs.
    /// the millions of precompile cycles it drives).
    uint256 public calls;

    /// Loop `count` staticcalls to `precompile` with `input`. `require(ok)`
    /// guarantees the precompile actually did the work (invalid curve inputs
    /// fail early and would otherwise silently cost nothing).
    function _hammer(address precompile, uint256 count, bytes memory input) internal {
        for (uint256 i = 0; i < count; ) {
            (bool ok, ) = precompile.staticcall(input);
            require(ok, "precompile call failed");
            unchecked {
                ++i;
            }
        }
        unchecked {
            ++calls;
        }
    }

    /// Generic entry: target any precompile address (e.g. secp256r1 at 0x100,
    /// whose address is chain-specific) without redeploying.
    function hammer(address precompile, uint256 count, bytes calldata input) external {
        _hammer(precompile, count, input);
    }

    // Convenience entries for the standard EVM precompile addresses.

    /// ecrecover (fixed cost/call). Needed even though organic batches are full
    /// of ecrecovers: organic volume is near-CONSTANT (~one signature per tx,
    /// 293-760 per batch), and a near-constant column is collinear with the
    /// intercept, so the organic fit cannot identify a per-recover cost — the
    /// committed table has 11.47M and a refit on the same corpus 119k, a 100x
    /// swing that predicts organic batches equally well and mis-prices an
    /// ecrecover flood by that factor. Only a swept synthetic column determines
    /// it, which is why `ec_recover_cycles` is in PRECOMPILE_FEATURES and the fit
    /// aborts while this family is missing from the synthetic set.
    function ecRecover(uint256 count, bytes calldata input) external {
        _hammer(address(0x01), count, input); // ecrecover (fixed cost/call)
    }

    function sha256_(uint256 count, bytes calldata input) external {
        _hammer(address(0x02), count, input); // SHA-256 (input-dependent)
    }

    function modexp(uint256 count, bytes calldata input) external {
        _hammer(address(0x05), count, input); // MODEXP (input-dependent)
    }

    function ecAdd(uint256 count, bytes calldata input) external {
        _hammer(address(0x06), count, input); // bn254 G1 add (fixed cost/call)
    }

    function ecMul(uint256 count, bytes calldata input) external {
        _hammer(address(0x07), count, input); // bn254 G1 scalar-mul (fixed cost/call)
    }

    function ecPairing(uint256 count, bytes calldata input) external {
        _hammer(address(0x08), count, input); // bn254 pairing (input-dependent: k pairs)
    }
}
