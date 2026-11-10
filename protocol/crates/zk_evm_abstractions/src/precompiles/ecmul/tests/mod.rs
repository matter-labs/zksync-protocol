use cfg_if::cfg_if;

use super::legacy_backend::LegacyECMulBackend;

mod utils;

use self::utils::{assert_backend_matches_case, deterministic_ecmul_cases};

#[test]
fn legacy_backend_matches_static_vectors() {
    for case in deterministic_ecmul_cases() {
        assert_backend_matches_case::<LegacyECMulBackend>(&case);
    }
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use quickcheck::QuickCheck;
        use super::airbender_backend::DelegatedECMulBackend;
        use self::utils::{legacy_and_delegated_match_for_scalars, QUICKCHECK_NUM_CASES};

        #[test]
        fn delegated_backend_matches_static_vectors() {
            for case in deterministic_ecmul_cases() {
                assert_backend_matches_case::<DelegatedECMulBackend>(&case);
            }
        }

        #[test]
        fn delegated_backend_matches_legacy_quickcheck() {
            fn property(point_scalar: u64, multiplier_scalar: u64) -> bool {
                legacy_and_delegated_match_for_scalars::<
                    LegacyECMulBackend,
                    DelegatedECMulBackend,
                >(point_scalar, multiplier_scalar)
            }

            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES)
                .quickcheck(property as fn(u64, u64) -> bool);
        }
    }
}
