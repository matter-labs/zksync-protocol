use cfg_if::cfg_if;
use zkevm_opcode_defs::ethereum_types::U256;
use zkevm_opcode_defs::k256::ecdsa::SigningKey;
use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;
use zkevm_opcode_defs::sha2::Digest;
use zkevm_opcode_defs::sha3;

use super::super::ECRecoverBackend;

pub(super) const QUICKCHECK_NUM_CASES: u64 = 256;
pub(super) const QUICKCHECK_MAX_MESSAGE_BYTES: usize = 256;

pub(super) struct DeterministicECRecoverCase {
    name: &'static str,
    digest: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    rec_id: u8,
    expected: Result<[u8; 65], ()>,
}

pub(super) fn deterministic_ecrecover_cases() -> Vec<DeterministicECRecoverCase> {
    let valid_cases = [
        (
            "empty-message-fixed-key",
            hex_to_32("06f9f7f6f4c5f70b2bcf0fdb5f8f4672d8cc9b2f4fbed4352f0f0d0c0b0a0908"),
            b"".as_slice(),
        ),
        (
            "airbender-message-fixed-key",
            hex_to_32("49a3f7e1d4c6b8a2908172635445362718190a0b0c0d0e0f1021324354657687"),
            b"airbender".as_slice(),
        ),
        (
            "protocol-message-fixed-key",
            hex_to_32("8854b52e0d56cb713f1189b15fd3684670e8c89ce11b7bcff37204d894f2519a"),
            b"zksync-protocol ecrecover differential test".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, private_key, message)| signed_case(name, private_key, message));

    let invalid_cases = [
        DeterministicECRecoverCase {
            name: "all-zero-inputs",
            digest: hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
            r: hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
            s: hex_to_32("0000000000000000000000000000000000000000000000000000000000000000"),
            rec_id: 0,
            expected: Err(()),
        },
        DeterministicECRecoverCase {
            name: "all-ones-inputs",
            digest: hex_to_32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            r: hex_to_32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            s: hex_to_32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            rec_id: 1,
            expected: Err(()),
        },
    ];

    valid_cases.chain(invalid_cases).collect()
}

pub(super) fn high_s_ecrecover_cases() -> Vec<DeterministicECRecoverCase> {
    [
        (
            "empty-message-high-s",
            hex_to_32("06f9f7f6f4c5f70b2bcf0fdb5f8f4672d8cc9b2f4fbed4352f0f0d0c0b0a0908"),
            b"".as_slice(),
        ),
        (
            "airbender-message-high-s",
            hex_to_32("49a3f7e1d4c6b8a2908172635445362718190a0b0c0d0e0f1021324354657687"),
            b"airbender".as_slice(),
        ),
        (
            "protocol-message-high-s",
            hex_to_32("8854b52e0d56cb713f1189b15fd3684670e8c89ce11b7bcff37204d894f2519a"),
            b"zksync-protocol ecrecover differential test".as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, private_key, message)| high_s_signed_case(name, private_key, message))
    .collect()
}

pub(super) fn assert_backend_matches_case<Backend: ECRecoverBackend>(
    case: &DeterministicECRecoverCase,
) {
    let actual = Backend::recover(&case.digest, &case.r, &case.s, case.rec_id);

    match (&case.expected, actual) {
        (Ok(expected), Ok(actual)) => assert_eq!(
            verifying_key_bytes(&actual),
            *expected,
            "backend must match static vector '{}'",
            case.name,
        ),
        (Err(_), Err(_)) => {}
        (Ok(_), Err(_)) => panic!("backend unexpectedly failed for vector '{}'", case.name),
        (Err(_), Ok(actual)) => panic!(
            "backend unexpectedly succeeded for vector '{}': {:?}",
            case.name,
            verifying_key_bytes(&actual),
        ),
    }
}

pub(super) fn legacy_backend_matches_signed_message<Backend: ECRecoverBackend>(
    message: &[u8],
) -> bool {
    let case = signed_case(
        "quickcheck-message",
        hex_to_32("06f9f7f6f4c5f70b2bcf0fdb5f8f4672d8cc9b2f4fbed4352f0f0d0c0b0a0908"),
        message,
    );
    backend_matches_case::<Backend>(&case)
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        pub(super) fn delegated_backend_matches_signed_message<Backend: ECRecoverBackend>(
            message: &[u8],
        ) -> bool {
            let case = signed_case(
                "quickcheck-message",
                hex_to_32("49a3f7e1d4c6b8a2908172635445362718190a0b0c0d0e0f1021324354657687"),
                message,
            );
            backend_matches_case::<Backend>(&case)
        }

        pub(super) fn invalid_recovery_id_panics_like_legacy<Legacy, Delegated>() -> bool
        where
            Legacy: ECRecoverBackend,
            Delegated: ECRecoverBackend,
        {
            let digest = hex_to_32("0101010101010101010101010101010101010101010101010101010101010101");
            let r = hex_to_32("0202020202020202020202020202020202020202020202020202020202020202");
            let s = hex_to_32("0303030303030303030303030303030303030303030303030303030303030303");

            let legacy = std::panic::catch_unwind(|| Legacy::recover(&digest, &r, &s, 2));
            let delegated = std::panic::catch_unwind(|| Delegated::recover(&digest, &r, &s, 2));

            legacy.is_err() == delegated.is_err()
        }
    }
}

fn backend_matches_case<Backend: ECRecoverBackend>(case: &DeterministicECRecoverCase) -> bool {
    match (
        &case.expected,
        Backend::recover(&case.digest, &case.r, &case.s, case.rec_id),
    ) {
        (Ok(expected), Ok(actual)) => verifying_key_bytes(&actual) == *expected,
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

fn signed_case(
    name: &'static str,
    private_key: [u8; 32],
    message: &[u8],
) -> DeterministicECRecoverCase {
    let signing_key =
        SigningKey::from_bytes((&private_key).into()).expect("private key vector must be valid");
    let digest = sha3::Keccak256::digest(message);

    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(digest.as_slice());

    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&digest_bytes)
        .expect("prehash signing must succeed");

    let signature_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&signature_bytes[..32]);
    s.copy_from_slice(&signature_bytes[32..]);

    DeterministicECRecoverCase {
        name,
        digest: digest_bytes,
        r,
        s,
        rec_id: recovery_id.to_byte(),
        expected: Ok(verifying_key_bytes(signing_key.verifying_key())),
    }
}

fn high_s_signed_case(
    name: &'static str,
    private_key: [u8; 32],
    message: &[u8],
) -> DeterministicECRecoverCase {
    use zkevm_opcode_defs::k256::ecdsa::{RecoveryId, Signature};

    let signing_key =
        SigningKey::from_bytes((&private_key).into()).expect("private key vector must be valid");
    let digest = sha3::Keccak256::digest(message);

    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(digest.as_slice());

    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&digest_bytes)
        .expect("prehash signing must succeed");

    let (r_bytes, s_bytes) = signature.split_bytes();
    let r: [u8; 32] = r_bytes.into();
    let low_s: [u8; 32] = s_bytes.into();
    let high_s = to_high_s_bytes(low_s);

    let high_s_signature =
        Signature::from_scalars(r, high_s).expect("constructed high-s signature must be valid");
    let normalized_signature = high_s_signature
        .normalize_s()
        .expect("constructed signature must normalize back to low-s form");
    assert_eq!(
        normalized_signature.to_bytes().as_slice(),
        signature.to_bytes().as_slice(),
        "high-s test vector must be the malleable counterpart of the original signature",
    );

    let high_s_recovery_id = RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced());

    DeterministicECRecoverCase {
        name,
        digest: digest_bytes,
        r,
        s: high_s,
        rec_id: high_s_recovery_id.to_byte(),
        expected: Ok(verifying_key_bytes(signing_key.verifying_key())),
    }
}

fn to_high_s_bytes(low_s: [u8; 32]) -> [u8; 32] {
    let curve_order = U256::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .expect("secp256k1 group order constant must parse");
    let low_s = U256::from_big_endian(&low_s);
    let high_s = curve_order - low_s;

    let mut bytes = [0u8; 32];
    high_s.to_big_endian(&mut bytes);
    bytes
}

fn verifying_key_bytes(verifying_key: &VerifyingKey) -> [u8; 65] {
    let encoded = verifying_key.to_encoded_point(false);
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(encoded.as_bytes());
    bytes
}

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("hex decode should succeed");
    bytes
        .as_slice()
        .try_into()
        .expect("hex string must be 32 bytes")
}
