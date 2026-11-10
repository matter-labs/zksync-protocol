use cfg_if::cfg_if;
use quickcheck::QuickCheck;

use super::{check_if_in_subgroup, ecpairing_function, legacy_backend::LegacyECPairingBackend};

mod utils;

use self::utils::{
    assert_backend_matches_case, deterministic_ecpairing_cases, empty_input_query,
    legacy_backend_matches_inverse_pairing_case, point_at_infinity_ecpairing_cases,
    TestPrecompileMemory, QUICKCHECK_NUM_CASES,
};

#[test]
fn legacy_backend_matches_static_vectors() {
    for case in deterministic_ecpairing_cases() {
        assert_backend_matches_case::<LegacyECPairingBackend>(&case);
    }
}

#[test]
fn legacy_subgroup_check_accepts_infinity() {
    use zkevm_opcode_defs::bn254::bn256::G2Affine;
    use zkevm_opcode_defs::bn254::CurveAffine;

    assert!(check_if_in_subgroup(G2Affine::zero()));
}

#[test]
fn legacy_backend_matches_point_at_infinity_vectors() {
    for case in point_at_infinity_ecpairing_cases() {
        assert_backend_matches_case::<LegacyECPairingBackend>(&case);
    }
}

#[test]
fn empty_input_still_emits_a_final_witness_row() {
    let mut memory = TestPrecompileMemory::default();
    let (num_rounds, witness) =
        ecpairing_function::<TestPrecompileMemory, true>(0, empty_input_query(), &mut memory);

    assert_eq!(num_rounds, 0);

    let (_, write_history, rounds) = witness.expect("witnessed execution must produce a witness");
    assert_eq!(write_history.len(), 2);
    assert_eq!(rounds.len(), 1);
    assert!(rounds[0].new_request.is_none());
    assert!(rounds[0].writes.is_some());
    assert_eq!(
        rounds[0].writes.unwrap(),
        [write_history[0], write_history[1]]
    );
}

#[test]
fn legacy_backend_matches_inverse_pairing_quickcheck() {
    fn property(g1_scalar: u64, g2_scalar: u64) -> bool {
        legacy_backend_matches_inverse_pairing_case::<LegacyECPairingBackend>(g1_scalar, g2_scalar)
    }

    QuickCheck::new()
        .tests(QUICKCHECK_NUM_CASES)
        .quickcheck(property as fn(u64, u64) -> bool);
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use super::airbender_backend::DelegatedECPairingBackend;
        use self::utils::delegated_backend_matches_inverse_pairing_case;

        #[test]
        fn delegated_backend_matches_static_vectors() {
            for case in deterministic_ecpairing_cases() {
                assert_backend_matches_case::<DelegatedECPairingBackend>(&case);
            }
        }

        #[test]
        fn delegated_backend_matches_point_at_infinity_vectors() {
            for case in point_at_infinity_ecpairing_cases() {
                assert_backend_matches_case::<DelegatedECPairingBackend>(&case);
            }
        }

        #[test]
        fn delegated_backend_matches_legacy_quickcheck() {
            fn property(g1_scalar: u64, g2_scalar: u64) -> bool {
                legacy_backend_matches_inverse_pairing_case::<LegacyECPairingBackend>(g1_scalar, g2_scalar)
                    && delegated_backend_matches_inverse_pairing_case::<DelegatedECPairingBackend>(g1_scalar, g2_scalar)
            }

            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES)
                .quickcheck(property as fn(u64, u64) -> bool);
        }
    }
}
