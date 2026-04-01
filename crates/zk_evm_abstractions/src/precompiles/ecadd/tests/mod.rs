use cfg_if::cfg_if;

use super::legacy_backend::LegacyECAddBackend;

mod utils;

use self::utils::{assert_backend_matches_case, deterministic_ecadd_cases};

#[test]
fn legacy_backend_matches_static_vectors() {
    for case in deterministic_ecadd_cases() {
        assert_backend_matches_case::<LegacyECAddBackend>(&case);
    }
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use super::airbender_backend::DelegatedECAddBackend;
        use quickcheck::QuickCheck;
        use self::utils::{legacy_and_delegated_match_for_scalars, QUICKCHECK_NUM_CASES};

        #[test]
        fn delegated_backend_matches_static_vectors() {
            for case in deterministic_ecadd_cases() {
                assert_backend_matches_case::<DelegatedECAddBackend>(&case);
            }
        }

        #[test]
        fn delegated_backend_matches_legacy_quickcheck() {
            fn property(left_scalar: u64, right_scalar: u64) -> bool {
                legacy_and_delegated_match_for_scalars::<
                    LegacyECAddBackend,
                    DelegatedECAddBackend,
                >(left_scalar, right_scalar)
            }

            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES)
                .quickcheck(property as fn(u64, u64) -> bool);
        }
    }
}
