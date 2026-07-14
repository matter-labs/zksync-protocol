use std::str::FromStr;

use super::*;

/// Externally computed vectors (Python `pow(b, e, m)`), covering full-width
/// operands, even moduli, power-of-two moduli, `b >= m`, exponents with
/// leading zeros and boundary values.
pub(crate) const MODEXP_VECTORS: &[(&str, &str, &str, &str)] = &[
    (
        "0x23b8c1e9392456de3eb13b9046685257bdd640fb06671ad11c80317fa3b1799d",
        "0x972a846916419f828b9d2434e465e150bd9c66b3ad3c2d6d1a3d1fa7bc8960a9",
        "0x9a1de644815ef6d13b8faa1837f8a88b17fc695a07a0ca6e0822e8f36c031199",
        "0x5ac2ad92075b85f4bd4f394b7eeafd348a335b282952b7968d649a462ce9697a",
    ),
    (
        "0x6b65a6a48b8148f6b38a088ca65ed389b74d0fb132e706298fadc1a606cb0fb3",
        "0xc241330b01a9e71fde8a774bcf36d58b4737819096da1dac72ff5d2a386ecbe0",
        "0x371ecd7b27cd813047229389571aa8766c307511b2b9437a28df6ec4ce4a2bbd",
        "0x29316b6d767c123a8065349e26b4e2b6bcb133d7822367de2bbb5b2d19c0d7c5",
    ),
    (
        "0x5be6128e18c267976142ea7d17be31111a2a73ed562b0f79c37459eef50bea63",
        "0x759cde66bacfb3d00b1f9163ce9ff57f43b7a3a69a8dca03580d7b71d8f56413",
        "0x4b0dbb418d5288f1142c3fe860e7a113ec1b8ca1f91e1d4c1ff49b7889463e85",
        "0x07665281e2969a9eb02df6d62c934bf5ec476d7f30da160d2764f1a3d5b2ea2b",
    ),
    (
        "0x3139d32c93cd59bf5c941cf0dc98d2c1e2acf72f9e574f7aa0ee89aed453dd32",
        "0xfc377a4c4a15544dc5e7ce8a3a578a8ea9488d990bbb259911ce5dd2b45ed1f0",
        "0x7412b29347294739614ff3d719db3ad0ddd1dfb23b982ef8daf61a26146d3f31",
        "0x265521d90ddbf01a1cf0b00afee75a1ab916d82ec811412b3be4d0acadf25a56",
    ),
    (
        "0xab9099a435a240ae5af305535ec42e0829a3b2e95d65a441d58842dea2bc372f",
        "0xa28defe39bf0027312476f57a5e5a5abaefcfad8efc89849b3aa7efe4458a885",
        "0x451b4cf36123fdf77656af7229d4beef3eabedcbbaa80dd488bd64072bcfbe01",
        "0x37d9123e0cccdc32cc3d36075639bc25cf35b2bd9284a2463d11a67147ca7c68",
    ),
    (
        "0x5304317faf42e12f3838b3268e944239b02b61c4a3d70628ece66fa2fd5166e6",
        "0xce177b4e0837b8a3d261a7ab3aa2e4f90e51f30dc6a7ee39c4b032ccd7c524a5",
        "0x9132b63ef16287e4e9c349e03602f8ac10f1bc81448aaa9e66b2bc5b50c187fc",
        "0x64bc331427a6f2506f030880ccc63193b0424c4073b4dc5c7e18d532b8dba90c",
    ),
    // Small exponent with leading zeros (e = 65537), Mersenne-like odd modulus.
    (
        "0x00000000000000000000000000000000000000000000000000000000deadbeef",
        "0x0000000000000000000000000000000000000000000000000000000000010001",
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        "0x194f3aafbdd3b89366b97896d401589337afa81c33f13cb1edf34d87f6180549",
    ),
    // Tiny operands.
    (
        "0x0000000000000000000000000000000000000000000000000000000000000003",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x000000000000000000000000000000000000000000000000000000000000000a",
        "0x0000000000000000000000000000000000000000000000000000000000000009",
    ),
    // All operands at U256::MAX (b == m so the result is 0).
    (
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
    ),
    // Base larger than the modulus.
    (
        "0x8000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000005",
        "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1",
        "0x0000000000000000000000000000000000000000000000000000000001b4d89f",
    ),
    // Power-of-two modulus (2^64).
    (
        "0x0000000000000000000000000000000000000000000000000000000000003039",
        "0x000000000000000000000000000000000000000000000000000000000000ffff",
        "0x0000000000000000000000000000000000000000000000010000000000000000",
        "0x000000000000000000000000000000000000000000000000fe76c99806acbe09",
    ),
    // Modulus 2 with a huge exponent (top bit set).
    (
        "0x0000000000000000000000000000000000000000000000000abcdef123456789",
        "0x8000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000001",
    ),
    // Largest power-of-two modulus (2^255).
    (
        "0x0000000000000000000000000000000000000000000000000000000000000007",
        "0x0000000000000000000000000000000000000000000000000000000000000064",
        "0x8000000000000000000000000000000000000000000000000000000000000000",
        "0x5319d5e494c9a977611d99b7b5cb34b967d4a2c6aecef68933be1fc93d3a1a61",
    ),
    // RSA-style: odd modulus, e = 65537.
    (
        "0xe27a984d654821d07fcd9eb1a7cad415366eb16f508ebad7b7c93acfe059a0ef",
        "0x0000000000000000000000000000000000000000000000000000000000010001",
        "0xbeb799193f22faf823bed01d43cf2fde24933b83757750a9a491f0b2ea1fca65",
        "0x6a8fa889c57def31a6995d058294303c719d78737819b92f16c526ccddf74ba3",
    ),
    // Even (non-power-of-two) modulus, e = 2.
    (
        "0x956269f0e5d7b8756dadd6c795a76d79bf3c4c06434308bc89fa6a688fb5d27b",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x7e570ddf04e0a15046d36b09febd3fe1fea17bc8704acf70b957992ecc7e392e",
        "0x4819c73eb18d760452a89c658bf62af5f4ab2d2ba57eead9d0e7b50174bd94e1",
    ),
    // Exponent with many leading zero bytes; sparse odd modulus.
    (
        "0x0000000000000000000000000000000000000000000000000000000000000005",
        "0x00000000000000000000000000000000000000000000000000000000000000ff",
        "0x0000000000000001000000000000000000000000000000010000000000000007",
        "0x000000000000000079f0c044150ce85613f2e5c522fbae58be6e3e74e9eed371",
    ),
];

fn u256(s: &str) -> U256 {
    U256::from_str(s).unwrap()
}

/// Edge cases mandated by EIP-198 semantics, in (b, e, m, expected) form.
pub(crate) fn edge_cases() -> Vec<(U256, U256, U256, U256)> {
    let max = U256::MAX;
    vec![
        // m == 0 => 0, regardless of anything else.
        (u256("0x5"), u256("0x5"), U256::zero(), U256::zero()),
        (max, max, U256::zero(), U256::zero()),
        // e == 0 => 1, except m == 1 => 0.
        (u256("0x5"), U256::zero(), U256::one(), U256::zero()),
        (u256("0x5"), U256::zero(), u256("0x7"), U256::one()),
        (U256::zero(), U256::zero(), u256("0x7"), U256::one()),
        // e == 1 => b % m, including b >= m.
        (u256("0x5"), U256::one(), u256("0x7"), u256("0x5")),
        (u256("0x9"), U256::one(), u256("0x7"), u256("0x2")),
        (max, U256::one(), u256("0x2"), U256::one()),
        // b == 0 => 0 (for e > 0).
        (U256::zero(), u256("0x5"), u256("0x7"), U256::zero()),
        (U256::zero(), max, max, U256::zero()),
        // b == 1 => 1, except m == 1 => 0.
        (U256::one(), max, u256("0x7"), U256::one()),
        (U256::one(), max, U256::one(), U256::zero()),
        // b == m => 0 for e >= 2.
        (u256("0x7"), u256("0x2"), u256("0x7"), U256::zero()),
        // m == 2 with even/odd bases.
        (u256("0x6"), u256("0x3"), u256("0x2"), U256::zero()),
        (u256("0x7"), u256("0x3"), u256("0x2"), U256::one()),
        // m == 3 (smallest modulus taking the generic path).
        (u256("0x5"), u256("0x4"), u256("0x3"), U256::one()),
        // e == 2 (smallest exponent taking the generic path).
        (max, u256("0x2"), max - U256::one(), U256::one()),
    ]
}

#[test]
fn modexp_inner_matches_external_vectors() {
    for (b, e, m, expected) in MODEXP_VECTORS {
        let result = modexp_inner(u256(b), u256(e), u256(m));
        assert_eq!(result, u256(expected), "modexp({b}, {e}, {m})");
    }
}

#[test]
fn modexp_inner_handles_edge_cases() {
    for (b, e, m, expected) in edge_cases() {
        let result = modexp_inner(b, e, m);
        assert_eq!(result, expected, "modexp({b}, {e}, {m})");
    }
}

/// Tests the correctness of the `modexp_inner` function for a specified
/// set of inputs from https://www.evm.codes/precompiled#0x05.
#[test]
fn test_modexp_inner_correctness_evm_codes() {
    let b = u256("0x8");
    let e = u256("0x9");
    let m = u256("0xa");

    let result = modexp_inner(b, e, m);

    assert_eq!(result, u256("0x8"));
}

/// Tests the correctness of the `modexp_inner` function for randomly
/// generated U256 integers.
#[test]
fn test_modexp_inner_correctness_big_ints() {
    let b = u256("0x7f333213268023a7d3d40ea760d0e1c00d5fe99710e379193fc5973e7ad09370");
    let e = u256("0x39d71831130091794534336679323390f4408be38cb89963ec41f4a90d6bf63");
    let m = u256("0xec6f05ec20e4c25420f9d6bc6800f9544ecabf5dbea80d11e0fb12c7f0517f5b");

    let result = modexp_inner(b, e, m);

    assert_eq!(
        result,
        u256("0x2779a7e4d2b26461c6557a12eb86285eeeb9cf5a40155305177854b15b4ed3df")
    );
}

#[test]
fn test_modexp_inner_trivial_exponent_and_modulus() {
    let b = u256("0x05");
    let e = u256("0x00");
    let m = u256("0x01");

    let result = modexp_inner(b, e, m);
    assert_eq!(result, U256::zero());
}

#[cfg(feature = "airbender-precompile-delegations")]
mod delegated {
    use super::super::airbender_backend::modexp_delegated;
    use super::*;

    #[test]
    fn delegated_modexp_matches_external_vectors() {
        for (b, e, m, expected) in MODEXP_VECTORS {
            let result = modexp_delegated(u256(b), u256(e), u256(m));
            assert_eq!(result, u256(expected), "modexp({b}, {e}, {m})");
        }
    }

    #[test]
    fn delegated_modexp_handles_edge_cases() {
        for (b, e, m, expected) in edge_cases() {
            let result = modexp_delegated(b, e, m);
            assert_eq!(result, expected, "modexp({b}, {e}, {m})");
        }
    }

    /// xorshift64* PRNG; deterministic, no external dependencies.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545F4914F6CDD1D)
        }

        fn next_u256(&mut self) -> U256 {
            let limbs = [
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
            ];
            let mut bytes = [0u8; 32];
            for (chunk, limb) in bytes.chunks_mut(8).zip(limbs) {
                chunk.copy_from_slice(&limb.to_le_bytes());
            }
            U256::from_little_endian(&bytes)
        }

        /// Random value with a random bit width, so small and large operands
        /// (and everything in between) are all exercised.
        fn next_sized(&mut self) -> U256 {
            let bits = (self.next_u64() % 257) as usize;
            if bits == 0 {
                return U256::zero();
            }
            let mask = if bits == 256 {
                U256::MAX
            } else {
                (U256::one() << bits) - U256::one()
            };
            self.next_u256() & mask
        }
    }

    #[test]
    fn delegated_modexp_matches_reference_randomized() {
        let mut rng = Rng(0x243F6A8885A308D3);
        for case in 0..5_000 {
            let b = rng.next_sized();
            let e = rng.next_sized();
            let mut m = rng.next_sized();
            // Force interesting modulus shapes on a rotating basis:
            // odd, even non-power-of-two, power of two, tiny.
            match case % 4 {
                0 => m |= U256::one(),
                1 => m &= !U256::one(),
                2 => m = U256::one() << (rng.next_u64() % 256) as usize,
                _ => m = U256::from(rng.next_u64() % 16),
            }

            let expected = modexp_inner(b, e, m);
            let actual = modexp_delegated(b, e, m);
            assert_eq!(actual, expected, "case {case}: modexp({b}, {e}, {m})");
        }
    }
}
