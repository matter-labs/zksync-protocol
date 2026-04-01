use cfg_if::cfg_if;
use quickcheck::QuickCheck;

use super::legacy_backend::LegacyECRecoverBackend;

mod utils;

use self::utils::{
    assert_backend_matches_case, deterministic_ecrecover_cases, high_s_ecrecover_cases,
    legacy_backend_matches_signed_message, QUICKCHECK_MAX_MESSAGE_BYTES, QUICKCHECK_NUM_CASES,
};

#[test]
fn legacy_backend_matches_static_vectors() {
    for case in deterministic_ecrecover_cases() {
        assert_backend_matches_case::<LegacyECRecoverBackend>(&case);
    }
}

#[test]
fn legacy_backend_accepts_high_s_signature_vectors() {
    for case in high_s_ecrecover_cases() {
        assert_backend_matches_case::<LegacyECRecoverBackend>(&case);
    }
}

#[test]
fn legacy_backend_matches_signing_reference_quickcheck() {
    fn property(mut message: Vec<u8>) -> bool {
        message.truncate(QUICKCHECK_MAX_MESSAGE_BYTES);
        legacy_backend_matches_signed_message::<LegacyECRecoverBackend>(&message)
    }

    QuickCheck::new()
        .tests(QUICKCHECK_NUM_CASES)
        .quickcheck(property as fn(Vec<u8>) -> bool);
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use super::airbender_backend::DelegatedECRecoverBackend;
        use self::utils::{
            delegated_backend_matches_signed_message, invalid_recovery_id_panics_like_legacy,
        };

        #[test]
        fn delegated_backend_matches_static_vectors() {
            for case in deterministic_ecrecover_cases() {
                assert_backend_matches_case::<DelegatedECRecoverBackend>(&case);
            }
        }

        #[test]
        fn delegated_backend_accepts_high_s_signature_vectors() {
            for case in high_s_ecrecover_cases() {
                assert_backend_matches_case::<DelegatedECRecoverBackend>(&case);
            }
        }

        #[test]
        fn delegated_backend_matches_legacy_quickcheck() {
            fn property(mut message: Vec<u8>) -> bool {
                message.truncate(QUICKCHECK_MAX_MESSAGE_BYTES);
                legacy_backend_matches_signed_message::<LegacyECRecoverBackend>(&message)
                    && delegated_backend_matches_signed_message::<DelegatedECRecoverBackend>(&message)
            }

            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES)
                .quickcheck(property as fn(Vec<u8>) -> bool);
        }

        #[test]
        fn invalid_recovery_id_matches_legacy_panics() {
            assert!(invalid_recovery_id_panics_like_legacy::<
                LegacyECRecoverBackend,
                DelegatedECRecoverBackend,
            >());
        }
    }
}
