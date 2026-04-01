use cfg_if::cfg_if;
use quickcheck::QuickCheck;

use super::legacy_backend::LegacySecp256r1Backend;

mod utils;

use self::utils::{
    assert_backend_matches_case, deterministic_secp256r1_cases,
    legacy_backend_matches_signed_message, QUICKCHECK_MAX_MESSAGE_BYTES, QUICKCHECK_NUM_CASES,
};

#[test]
fn legacy_backend_matches_static_vectors() {
    for case in deterministic_secp256r1_cases() {
        assert_backend_matches_case::<LegacySecp256r1Backend>(&case);
    }
}

#[test]
fn legacy_backend_matches_signing_reference_quickcheck() {
    fn property(mut message: Vec<u8>) -> bool {
        message.truncate(QUICKCHECK_MAX_MESSAGE_BYTES);
        legacy_backend_matches_signed_message::<LegacySecp256r1Backend>(&message)
    }

    QuickCheck::new()
        .tests(QUICKCHECK_NUM_CASES)
        .quickcheck(property as fn(Vec<u8>) -> bool);
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use super::airbender_backend::DelegatedSecp256r1Backend;
        use self::utils::delegated_backend_matches_signed_message;

        #[test]
        fn delegated_backend_matches_static_vectors() {
            for case in deterministic_secp256r1_cases() {
                assert_backend_matches_case::<DelegatedSecp256r1Backend>(&case);
            }
        }

        #[test]
        fn delegated_backend_matches_legacy_quickcheck() {
            fn property(mut message: Vec<u8>) -> bool {
                message.truncate(QUICKCHECK_MAX_MESSAGE_BYTES);
                legacy_backend_matches_signed_message::<LegacySecp256r1Backend>(&message)
                    && delegated_backend_matches_signed_message::<DelegatedSecp256r1Backend>(&message)
            }

            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES)
                .quickcheck(property as fn(Vec<u8>) -> bool);
        }
    }
}
