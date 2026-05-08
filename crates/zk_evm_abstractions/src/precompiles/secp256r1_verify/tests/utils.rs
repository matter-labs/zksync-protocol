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

// These vectors are structurally valid secp256r1 inputs where verification
// reaches an exceptional elliptic-curve state. The precompile contract
// distinguishes malformed inputs (`Err(())`) from well-formed signatures that
// simply do not verify (`Ok(false)`), so these must stay on the latter path.
//
// Attribution: These test cases are taken from the wycheproof project, licensed
// under Apache 2.0 license.
// Project repository: https://github.com/C2SP/wycheproof/
pub(super) fn wycheproof_edge_case_divergences() -> Vec<DeterministicSecp256r1Case> {
    vec![
        DeterministicSecp256r1Case {
            name: "wycheproof-169-point-at-infinity-during-verify",
            digest: hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"),
            r: hex_to_32("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"),
            s: hex_to_32("555555550000000055555555555555553ef7a8e48d07df81a693439654210c70"),
            x: hex_to_32("b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f287"),
            y: hex_to_32("1b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47"),
            expected: Ok(false),
        },
        DeterministicSecp256r1Case {
            name: "wycheproof-205-duplication-bug",
            digest: hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"),
            r: hex_to_32("6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569"),
            s: hex_to_32("bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b"),
            x: hex_to_32("5b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963"),
            y: hex_to_32("7c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db616"),
            expected: Ok(false),
        },
        DeterministicSecp256r1Case {
            name: "wycheproof-208-comparison-with-point-at-infinity",
            digest: hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"),
            r: hex_to_32("555555550000000055555555555555553ef7a8e48d07df81a693439654210c70"),
            s: hex_to_32("3333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9"),
            x: hex_to_32("dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d250"),
            y: hex_to_32("45d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7"),
            expected: Ok(false),
        },
        DeterministicSecp256r1Case {
            name: "wycheproof-222-public-key-shares-generator-x-low-y",
            digest: hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"),
            r: hex_to_32("44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e"),
            s: hex_to_32("249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2"),
            x: hex_to_32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            y: hex_to_32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            expected: Ok(false),
        },
        DeterministicSecp256r1Case {
            name: "wycheproof-223-public-key-shares-generator-x-high-y",
            digest: hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"),
            r: hex_to_32("bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"),
            s: hex_to_32("249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2"),
            x: hex_to_32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            y: hex_to_32("b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"),
            expected: Ok(false),
        },
    ]
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
