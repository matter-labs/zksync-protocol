use cfg_if::cfg_if;
use zkevm_opcode_defs::p256;
use zkevm_opcode_defs::sha2::Digest;
use zkevm_opcode_defs::sha3;

use super::super::Secp256r1Backend;

pub(super) const QUICKCHECK_NUM_CASES: u64 = 256;
pub(super) const QUICKCHECK_MAX_MESSAGE_BYTES: usize = 256;

#[derive(Clone, Copy)]
pub(super) struct DeterministicSecp256r1Case {
    name: &'static str,
    digest: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    x: [u8; 32],
    y: [u8; 32],
    expected: Result<bool, ()>,
}

pub(super) fn deterministic_secp256r1_cases() -> Vec<DeterministicSecp256r1Case> {
    let valid_case = signed_case(
        "valid-signature",
        hex_to_32("8854b52e0d56cb713f1189b15fd3684670e8c89ce11b7bcff37204d894f2519a"),
        hex_to_32("0101010101010101010101010101010101010101010101010101010101010101"),
    );

    let mut bad_digest = valid_case.digest;
    bad_digest[0] ^= 1;
    let mut bad_r = valid_case.r;
    bad_r[31] ^= 1;

    vec![
        valid_case,
        DeterministicSecp256r1Case {
            name: "tampered-digest",
            digest: bad_digest,
            r: valid_case.r,
            s: valid_case.s,
            x: valid_case.x,
            y: valid_case.y,
            expected: Ok(false),
        },
        DeterministicSecp256r1Case {
            name: "tampered-signature",
            digest: valid_case.digest,
            r: bad_r,
            s: valid_case.s,
            x: valid_case.x,
            y: valid_case.y,
            expected: Ok(false),
        },
        DeterministicSecp256r1Case {
            name: "invalid-zero-coordinates",
            digest: hex_to_32("0000000000000000000000000000000000000000000000000000000000000001"),
            r: hex_to_32("0000000000000000000000000000000000000000000000000000000000000001"),
            s: hex_to_32("0000000000000000000000000000000000000000000000000000000000000001"),
            x: [0u8; 32],
            y: [0u8; 32],
            expected: Err(()),
        },
    ]
}

pub(super) fn assert_backend_matches_case<Backend: Secp256r1Backend>(
    case: &DeterministicSecp256r1Case,
) {
    let actual = Backend::verify(&case.digest, &case.r, &case.s, &case.x, &case.y);
    match (&case.expected, actual) {
        (Ok(expected), Ok(actual)) => assert_eq!(
            actual, *expected,
            "backend must match static vector '{}'",
            case.name,
        ),
        (Err(_), Err(_)) => {}
        (Ok(_), Err(_)) => panic!("backend unexpectedly failed for vector '{}'", case.name),
        (Err(_), Ok(actual)) => panic!(
            "backend unexpectedly succeeded for vector '{}': {actual}",
            case.name,
        ),
    }
}

pub(super) fn legacy_backend_matches_signed_message<Backend: Secp256r1Backend>(
    message: &[u8],
) -> bool {
    let digest = sha3::Keccak256::digest(message);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(digest.as_slice());
    backend_matches_case::<Backend>(&signed_case(
        "quickcheck-message",
        hex_to_32("49a3f7e1d4c6b8a2908172635445362718190a0b0c0d0e0f1021324354657687"),
        digest_bytes,
    ))
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        pub(super) fn delegated_backend_matches_signed_message<Backend: Secp256r1Backend>(
            message: &[u8],
        ) -> bool {
            let digest = sha3::Keccak256::digest(message);
            let mut digest_bytes = [0u8; 32];
            digest_bytes.copy_from_slice(digest.as_slice());
            backend_matches_case::<Backend>(&signed_case(
                "quickcheck-message",
                hex_to_32("8854b52e0d56cb713f1189b15fd3684670e8c89ce11b7bcff37204d894f2519a"),
                digest_bytes,
            ))
        }
    }
}

fn backend_matches_case<Backend: Secp256r1Backend>(case: &DeterministicSecp256r1Case) -> bool {
    match (
        &case.expected,
        Backend::verify(&case.digest, &case.r, &case.s, &case.x, &case.y),
    ) {
        (Ok(expected), Ok(actual)) => *expected == actual,
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

fn signed_case(
    name: &'static str,
    private_key: [u8; 32],
    digest: [u8; 32],
) -> DeterministicSecp256r1Case {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};

    let signing_key =
        SigningKey::from_bytes((&private_key).into()).expect("private key vector must be valid");
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let (x, y) = match encoded.coordinates() {
        p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => (*x, *y),
        _ => panic!("signing key must produce uncompressed coordinates"),
    };
    let x: [u8; 32] = x.into();
    let y: [u8; 32] = y.into();

    let signature: Signature = signing_key
        .sign_prehash(&digest)
        .expect("prehash signing must succeed");

    DeterministicSecp256r1Case {
        name,
        digest,
        r: signature.r().to_bytes().into(),
        s: signature.s().to_bytes().into(),
        x,
        y,
        expected: Ok(true),
    }
}

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("hex decode should succeed");
    bytes
        .as_slice()
        .try_into()
        .expect("hex string must be 32 bytes")
}
