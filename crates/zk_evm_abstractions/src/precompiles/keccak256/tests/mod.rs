use super::{legacy_backend::LegacyKeccakBackend, transmute_state, Keccak256};
use cfg_if::cfg_if;
use quickcheck::QuickCheck;
use zkevm_opcode_defs::sha2::Digest;

mod utils;

use self::utils::{
    assert_backend_matches_reference, execution_output_bytes, reference_keccak256,
    run_keccak_precompile_test_backend, DETERMINISTIC_KECCAK_CASES, QUICKCHECK_MAX_INPUT_BYTES,
    QUICKCHECK_NUM_CASES,
};

#[test]
fn test_empty_string() {
    let mut hasher = Keccak256::new();
    hasher.update(&[]);
    let result = hasher.finalize();
    println!("Empty string hash = {}", hex::encode(result.as_slice()));

    let mut our_hasher = Keccak256::default();
    let mut block = [0u8; 136];
    block[0] = 0x01;
    block[135] = 0x80;
    our_hasher.update(&block);
    let state_inner = transmute_state(our_hasher);
    for (idx, el) in state_inner.iter().enumerate() {
        println!("Element {} = 0x{:016x}", idx, el);
    }
}

#[test]
fn legacy_backend_matches_tiny_keccak_boundary_vectors() {
    for case in DETERMINISTIC_KECCAK_CASES {
        assert_backend_matches_reference::<LegacyKeccakBackend>(*case);
    }
}

#[test]
fn legacy_backend_matches_tiny_keccak_quickcheck() {
    fn property(mut input: Vec<u8>, input_offset: u8) -> bool {
        input.truncate(QUICKCHECK_MAX_INPUT_BYTES);

        let input_offset = (input_offset % 32) as u32;
        let actual = execution_output_bytes(&run_keccak_precompile_test_backend::<
            LegacyKeccakBackend,
        >(input_offset, &input));
        let reference = reference_keccak256(&input);

        actual == reference
    }

    QuickCheck::new()
        .tests(QUICKCHECK_NUM_CASES)
        .quickcheck(property as fn(Vec<u8>, u8) -> bool);
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use super::airbender_backend::DelegatedKeccakBackend;

        #[test]
        fn delegated_backend_matches_tiny_keccak_boundary_vectors() {
            for case in DETERMINISTIC_KECCAK_CASES {
                assert_backend_matches_reference::<DelegatedKeccakBackend>(*case);
            }
        }

        #[test]
        fn legacy_and_delegated_backends_match_tiny_keccak_quickcheck() {
            fn property(mut input: Vec<u8>, input_offset: u8) -> bool {
                input.truncate(QUICKCHECK_MAX_INPUT_BYTES);

                let input_offset = (input_offset % 32) as u32;
                let reference = reference_keccak256(&input);
                let legacy = execution_output_bytes(
                    &run_keccak_precompile_test_backend::<LegacyKeccakBackend>(input_offset, &input),
                );
                let delegated = execution_output_bytes(
                    &run_keccak_precompile_test_backend::<DelegatedKeccakBackend>(input_offset, &input),
                );

                legacy == reference && delegated == reference
            }

            QuickCheck::new()
                .tests(QUICKCHECK_NUM_CASES)
                .quickcheck(property as fn(Vec<u8>, u8) -> bool);
        }
    }
}
