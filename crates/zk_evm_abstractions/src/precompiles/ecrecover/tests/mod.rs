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
            delegated_backend_matches_signed_message, delegated_matches_legacy_on_raw,
            invalid_recovery_id_panics_like_legacy,
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
        fn delegated_backend_matches_legacy_on_arbitrary_inputs_quickcheck() {
            // Full-entropy 32-byte inputs (quickcheck 1.1 implements `Arbitrary`
            // for `[u8; 32]`), avoiding the most-significant-end bias a
            // `Vec<u8>` + left-pad would introduce. The r/s == 0 and >= n reject
            // boundary is reached by random inputs only with probability ~2^-128,
            // so it is covered explicitly by
            // `delegated_matches_legacy_on_boundary_scalars`.
            fn property(digest: [u8; 32], r: [u8; 32], s: [u8; 32], rec_id_odd: bool) -> bool {
                delegated_matches_legacy_on_raw::<LegacyECRecoverBackend, DelegatedECRecoverBackend>(
                    digest, r, s, rec_id_odd,
                )
            }

            // This property is cheap (no signing), so run well above the default.
            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES * 16)
                .quickcheck(property as fn([u8; 32], [u8; 32], [u8; 32], bool) -> bool);
        }

        /// Both backends must agree on the accept/reject decision at the scalar
        /// boundaries `Signature::from_scalars` cares about — `0`, `1`, `n - 1`,
        /// `n`, `n + 1`, and `2^256 - 1` — which the random quickcheck above
        /// effectively never reaches. `n` and above (and `0`) must be rejected
        /// by both; in-range values must recover identically.
        #[test]
        fn delegated_matches_legacy_on_boundary_scalars() {
            // secp256k1 group order n, big-endian.
            const N: [u8; 32] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
                0xd0, 0x36, 0x41, 0x41,
            ];
            let with_last = |delta: i16| {
                let mut v = N;
                v[31] = (v[31] as i16 + delta) as u8;
                v
            };
            let zero = [0u8; 32];
            let one = with_last_byte(1);
            let max = [0xffu8; 32];
            let valid = [0x42u8; 32]; // nonzero and < n
            let scalars = [zero, one, with_last(-1), N, with_last(1), max, valid];

            let digest = [0x11u8; 32];
            for r in scalars {
                for s in scalars {
                    for rec_id_odd in [false, true] {
                        assert!(
                            delegated_matches_legacy_on_raw::<
                                LegacyECRecoverBackend,
                                DelegatedECRecoverBackend,
                            >(digest, r, s, rec_id_odd),
                            "backends disagree at r={r:02x?} s={s:02x?} rec_id_odd={rec_id_odd}"
                        );
                    }
                }
            }
        }

        fn with_last_byte(v: u8) -> [u8; 32] {
            let mut out = [0u8; 32];
            out[31] = v;
            out
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
