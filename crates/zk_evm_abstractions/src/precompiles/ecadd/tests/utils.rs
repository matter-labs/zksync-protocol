use anyhow::Result;
use cfg_if::cfg_if;
use zkevm_opcode_defs::ethereum_types::U256;

use crate::utils::bn254::ECPointCoordinates;

use super::super::ECAddBackend;

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use zkevm_opcode_defs::bn254::bn256::{Fr, G1Affine};
        use zkevm_opcode_defs::bn254::ff::PrimeField;
        use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};

        use crate::utils::bn254::point_to_u256_tuple;

        pub(super) const QUICKCHECK_NUM_CASES: u64 = 256;
    }
}

pub(super) struct DeterministicECAddCase {
    name: &'static str,
    point_1: ECPointCoordinates,
    point_2: ECPointCoordinates,
    expected: Result<ECPointCoordinates, ()>,
}

pub(super) fn deterministic_ecadd_cases() -> Vec<DeterministicECAddCase> {
    vec![
        DeterministicECAddCase {
            name: "custom-valid-point",
            point_1: (
                u256_from_hex("1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad"),
                u256_from_hex("0bac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d"),
            ),
            point_2: (
                u256_from_hex("251edb9081aba0cb29a45e4565ab2a2136750be5c893000e35e031ee123889e8"),
                u256_from_hex("24a972b009ad5986a7e14781d4e0c2d11aff281004712470811ec9b4fcb7c569"),
            ),
            expected: Ok((
                u256_from_dec(
                    "16722044054529980026630802318818607593549086552476606668453035265973506741708",
                ),
                u256_from_dec(
                    "5777135421494458653665242593020841953920930780504228016288089286576416057645",
                ),
            )),
        },
        DeterministicECAddCase {
            name: "evm-codes-generator-doubling",
            point_1: (u256_from_dec("1"), u256_from_dec("2")),
            point_2: (u256_from_dec("1"), u256_from_dec("2")),
            expected: Ok((
                u256_from_dec(
                    "1368015179489954701390400359078579693043519447331113978918064868415326638035",
                ),
                u256_from_dec(
                    "9918110051302171585080402603319702774565515993150576347155970296011118125764",
                ),
            )),
        },
        DeterministicECAddCase {
            name: "opposite-points-cancel",
            point_1: (
                u256_from_hex("1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad"),
                u256_from_hex("0bac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d"),
            ),
            point_2: (
                u256_from_hex("1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad"),
                u256_from_hex("24b83e5b5404c77f1d054cb33b65b94730bf50c369bf0f2f2f48beb251d9d2da"),
            ),
            expected: Ok((U256::zero(), U256::zero())),
        },
        DeterministicECAddCase {
            name: "infinity-plus-infinity",
            point_1: (U256::zero(), U256::zero()),
            point_2: (U256::zero(), U256::zero()),
            expected: Ok((U256::zero(), U256::zero())),
        },
        DeterministicECAddCase {
            name: "infinity-plus-generator",
            point_1: (U256::zero(), U256::zero()),
            point_2: (u256_from_dec("1"), u256_from_dec("2")),
            expected: Ok((u256_from_dec("1"), u256_from_dec("2"))),
        },
        DeterministicECAddCase {
            name: "invalid-first-point",
            point_1: (u256_from_dec("1"), u256_from_dec("3")),
            point_2: (
                u256_from_hex("251edb9081aba0cb29a45e4565ab2a2136750be5c893000e35e031ee123889e8"),
                u256_from_hex("24a972b009ad5986a7e14781d4e0c2d11aff281004712470811ec9b4fcb7c569"),
            ),
            expected: Err(()),
        },
        DeterministicECAddCase {
            name: "invalid-second-point",
            point_1: (
                u256_from_hex("1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad"),
                u256_from_hex("0bac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d"),
            ),
            point_2: (u256_from_dec("1"), u256_from_dec("16")),
            expected: Err(()),
        },
    ]
}

pub(super) fn assert_backend_matches_case<Backend: ECAddBackend>(case: &DeterministicECAddCase) {
    let actual = Backend::add(case.point_1, case.point_2);

    match (&case.expected, actual) {
        (Ok(expected), Ok(actual)) => assert_eq!(
            actual, *expected,
            "backend must match static vector '{}'",
            case.name,
        ),
        (Err(_), Err(_)) => {}
        (Ok(_), Err(error)) => panic!(
            "backend unexpectedly failed for vector '{}': {error}",
            case.name,
        ),
        (Err(_), Ok(actual)) => panic!(
            "backend unexpectedly succeeded for vector '{}': {actual:?}",
            case.name,
        ),
    }
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        pub(super) fn legacy_and_delegated_match_for_scalars<Legacy, Delegated>(
            left_scalar: u64,
            right_scalar: u64,
        ) -> bool
        where
            Legacy: ECAddBackend,
            Delegated: ECAddBackend,
        {
            let point_1 = point_from_scalar(left_scalar);
            let point_2 = point_from_scalar(right_scalar);

            backend_results_match::<Legacy, Delegated>(point_1, point_2)
        }

        fn backend_results_match<Left, Right>(
            point_1: ECPointCoordinates,
            point_2: ECPointCoordinates,
        ) -> bool
        where
            Left: ECAddBackend,
            Right: ECAddBackend,
        {
            let left = Left::add(point_1, point_2);
            let right = Right::add(point_1, point_2);

            match (left, right) {
                (Ok(left), Ok(right)) => left == right,
                (Err(_), Err(_)) => true,
                _ => false,
            }
        }

        fn point_from_scalar(scalar: u64) -> ECPointCoordinates {
            let scalar = Fr::from_str(scalar.to_string().as_str())
                .expect("u64 scalar must map into the BN254 scalar field");
            let point = G1Affine::one().mul(scalar).into_affine();
            point_to_u256_tuple(point)
        }
    }
}

fn u256_from_hex(hex: &str) -> U256 {
    U256::from_str_radix(hex, 16).expect("hex vector must parse as U256")
}

fn u256_from_dec(dec: &str) -> U256 {
    U256::from_str_radix(dec, 10).expect("decimal vector must parse as U256")
}
