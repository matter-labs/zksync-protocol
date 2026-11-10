use cfg_if::cfg_if;
use zkevm_opcode_defs::ethereum_types::U256;

use crate::utils::bn254::ECPointCoordinates;

use super::super::{ECMulBackend, EC_GROUP_ORDER};

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use zkevm_opcode_defs::bn254::bn256::{Fr, G1Affine};
        use zkevm_opcode_defs::bn254::ff::PrimeField;
        use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};

        use crate::utils::bn254::point_to_u256_tuple;

        pub(super) const QUICKCHECK_NUM_CASES: u64 = 256;
    }
}

pub(super) struct DeterministicECMulCase {
    name: &'static str,
    point: ECPointCoordinates,
    scalar: U256,
    expected: Result<ECPointCoordinates, ()>,
}

pub(super) fn deterministic_ecmul_cases() -> Vec<DeterministicECMulCase> {
    vec![
        DeterministicECMulCase {
            name: "custom-valid-point",
            point: (
                u256_from_hex("1148f79e53544582d22e5071480ae679d0b9df89d69e881f611e8381384ed1ad"),
                u256_from_hex("0bac10178d2cd8aa9b4af903461b9f1666c219cdfeb2bb5e0cd7cd6486a32a6d"),
            ),
            scalar: u256_from_hex(
                "15f0e77d431a6c4d21df6a71cdcb0b2eeba21fc1192bd9801b8cd8b7c763e115",
            ),
            expected: Ok((
                u256_from_dec(
                    "9941674825074992183128808489717167636392653540258056893654639521381088261704",
                ),
                u256_from_dec(
                    "8986289197266457569457494475222656986225227492679168701241837087965910154278",
                ),
            )),
        },
        DeterministicECMulCase {
            name: "evm-codes-generator-double",
            point: (u256_from_dec("1"), u256_from_dec("2")),
            scalar: u256_from_dec("2"),
            expected: Ok((
                u256_from_dec(
                    "1368015179489954701390400359078579693043519447331113978918064868415326638035",
                ),
                u256_from_dec(
                    "9918110051302171585080402603319702774565515993150576347155970296011118125764",
                ),
            )),
        },
        DeterministicECMulCase {
            name: "group-order-wraps-to-infinity",
            point: (u256_from_dec("1"), u256_from_dec("2")),
            scalar: u256_from_hex(EC_GROUP_ORDER.trim_start_matches("0x")),
            expected: Ok((U256::zero(), U256::zero())),
        },
        DeterministicECMulCase {
            name: "three-group-orders-wrap-to-infinity",
            point: (u256_from_dec("1"), u256_from_dec("2")),
            scalar: u256_from_hex(
                "912ceb58a394e07d28f0d12384840917789bb8d96d2c51b3cba5e0bbd0000003",
            ),
            expected: Ok((U256::zero(), U256::zero())),
        },
        DeterministicECMulCase {
            name: "five-group-orders-plus-one-reproduces-input",
            point: (u256_from_dec("1"), u256_from_dec("2")),
            scalar: u256_from_hex(
                "f1f5883e65f820d099915c908786b9d1c903896a609f32d65369cbe3b0000006",
            ),
            expected: Ok((u256_from_dec("1"), u256_from_dec("2"))),
        },
        DeterministicECMulCase {
            name: "invalid-point",
            point: (u256_from_dec("1"), u256_from_dec("10")),
            scalar: u256_from_hex(
                "15f0e77d431a6c4d21df6a71cdcb0b2eeba21fc1192bd9801b8cd8b7c763e115",
            ),
            expected: Err(()),
        },
    ]
}

pub(super) fn assert_backend_matches_case<Backend: ECMulBackend>(case: &DeterministicECMulCase) {
    let actual = Backend::mul(case.point, case.scalar);

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
            point_scalar: u64,
            multiplier_scalar: u64,
        ) -> bool
        where
            Legacy: ECMulBackend,
            Delegated: ECMulBackend,
        {
            let point = point_from_scalar(point_scalar);
            let scalar = U256::from(multiplier_scalar);

            backend_results_match::<Legacy, Delegated>(point, scalar)
        }

        fn backend_results_match<Left, Right>(point: ECPointCoordinates, scalar: U256) -> bool
        where
            Left: ECMulBackend,
            Right: ECMulBackend,
        {
            let left = Left::mul(point, scalar);
            let right = Right::mul(point, scalar);

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
