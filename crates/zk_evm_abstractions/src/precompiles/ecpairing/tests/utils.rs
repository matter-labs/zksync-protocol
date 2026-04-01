use cfg_if::cfg_if;
use std::str::FromStr;

use zkevm_opcode_defs::bn254::bn256::{Fq, Fr, G1Affine, G2Affine};
use zkevm_opcode_defs::bn254::ff::PrimeField;
use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};
use zkevm_opcode_defs::ethereum_types::{Address, U256};
use zkevm_opcode_defs::PrecompileCallABI;

use super::super::{ECPairingBackend, EcPairingInputTuple};
use crate::aux::Timestamp;
use crate::queries::{LogQuery, MemoryQuery};
use crate::vm::Memory;

pub(super) const QUICKCHECK_NUM_CASES: u64 = 256;

pub(super) enum PairingExpectation {
    Ok(bool),
    AnyErr,
    ErrMessage(&'static str),
}

pub(super) struct DeterministicECPairingCase {
    name: &'static str,
    inputs: Vec<EcPairingInputTuple>,
    expected: PairingExpectation,
}

pub(super) fn deterministic_ecpairing_cases() -> Vec<DeterministicECPairingCase> {
    let mut cases = vec![
        DeterministicECPairingCase {
            name: "empty-input",
            inputs: vec![],
            expected: PairingExpectation::Ok(true),
        },
        DeterministicECPairingCase {
            name: "evm-codes-true-case",
            inputs: valid_true_case(),
            expected: PairingExpectation::Ok(true),
        },
        DeterministicECPairingCase {
            name: "evm-codes-true-case-with-zeros",
            inputs: {
                let mut inputs = valid_true_case();
                inputs.extend([[U256::zero(); 6]; 4]);
                inputs
            },
            expected: PairingExpectation::Ok(true),
        },
        DeterministicECPairingCase {
            name: "subgroup-invalid-case",
            inputs: subgroup_invalid_case(),
            expected: PairingExpectation::ErrMessage("G2 not on the subgroup"),
        },
        DeterministicECPairingCase {
            name: "invalid-first-point",
            inputs: invalid_point_case(),
            expected: PairingExpectation::AnyErr,
        },
    ];
    cases.extend(point_at_infinity_ecpairing_cases());
    cases
}

pub(super) fn point_at_infinity_ecpairing_cases() -> Vec<DeterministicECPairingCase> {
    vec![
        DeterministicECPairingCase {
            name: "g1-infinity-with-g2-generator",
            inputs: vec![pairing_tuple(G1Affine::zero(), G2Affine::one())],
            expected: PairingExpectation::Ok(true),
        },
        DeterministicECPairingCase {
            name: "g2-infinity-with-g1-generator",
            inputs: vec![pairing_tuple(G1Affine::one(), G2Affine::zero())],
            expected: PairingExpectation::Ok(true),
        },
        DeterministicECPairingCase {
            name: "both-points-infinity",
            inputs: vec![pairing_tuple(G1Affine::zero(), G2Affine::zero())],
            expected: PairingExpectation::Ok(true),
        },
    ]
}

pub(super) fn assert_backend_matches_case<Backend: ECPairingBackend>(
    case: &DeterministicECPairingCase,
) {
    match (&case.expected, Backend::pairing(case.inputs.clone())) {
        (PairingExpectation::Ok(expected), Ok(actual)) => assert_eq!(
            actual, *expected,
            "backend must match static vector '{}'",
            case.name,
        ),
        (PairingExpectation::AnyErr, Err(_)) => {}
        (PairingExpectation::ErrMessage(expected), Err(actual)) => assert_eq!(
            actual.to_string(),
            *expected,
            "backend must match static vector '{}'",
            case.name,
        ),
        (PairingExpectation::Ok(_), Err(error)) => panic!(
            "backend unexpectedly failed for vector '{}': {error}",
            case.name,
        ),
        (PairingExpectation::AnyErr, Ok(actual)) => panic!(
            "backend unexpectedly succeeded for vector '{}': {actual}",
            case.name,
        ),
        (PairingExpectation::ErrMessage(expected), Ok(actual)) => panic!(
            "backend unexpectedly succeeded for vector '{}' expected error '{}', got {actual}",
            case.name, expected,
        ),
    }
}

pub(super) fn legacy_backend_matches_inverse_pairing_case<Backend: ECPairingBackend>(
    g1_scalar: u64,
    g2_scalar: u64,
) -> bool {
    backend_matches_expected::<Backend>(inverse_pairing_case(g1_scalar, g2_scalar), true)
}

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
pub(super) fn delegated_backend_matches_inverse_pairing_case<Backend: ECPairingBackend>(
            g1_scalar: u64,
            g2_scalar: u64,
        ) -> bool {
            backend_matches_expected::<Backend>(inverse_pairing_case(g1_scalar, g2_scalar), true)
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct TestPrecompileMemory;

impl Memory for TestPrecompileMemory {
    fn execute_partial_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        query: MemoryQuery,
    ) -> MemoryQuery {
        query
    }

    fn specialized_code_query(
        &mut self,
        _monotonic_cycle_counter: u32,
        _query: MemoryQuery,
    ) -> MemoryQuery {
        unreachable!("ecpairing precompile does not issue code queries")
    }

    fn read_code_query(&self, _monotonic_cycle_counter: u32, _query: MemoryQuery) -> MemoryQuery {
        unreachable!("ecpairing precompile does not issue code queries")
    }
}

pub(super) fn empty_input_query() -> LogQuery {
    let abi = PrecompileCallABI {
        input_memory_offset: 0,
        input_memory_length: 0,
        output_memory_offset: 0,
        output_memory_length: 2,
        memory_page_to_read: 1,
        memory_page_to_write: 2,
        precompile_interpreted_data: 0,
    };

    LogQuery {
        timestamp: Timestamp(1),
        tx_number_in_block: 0,
        aux_byte: 0,
        shard_id: 0,
        address: Address::zero(),
        key: abi.to_u256(),
        read_value: U256::zero(),
        written_value: U256::zero(),
        rw_flag: false,
        rollback: false,
        is_service: false,
    }
}

fn backend_matches_expected<Backend: ECPairingBackend>(
    inputs: Vec<EcPairingInputTuple>,
    expected: bool,
) -> bool {
    matches!(Backend::pairing(inputs), Ok(actual) if actual == expected)
}

fn inverse_pairing_case(g1_scalar: u64, g2_scalar: u64) -> Vec<EcPairingInputTuple> {
    let g1_scalar = scalar_from_u64(g1_scalar.saturating_add(1));
    let g2_scalar = scalar_from_u64(g2_scalar.saturating_add(1));

    let point_1 = G1Affine::one().mul(g1_scalar).into_affine();
    let point_2 = G2Affine::one().mul(g2_scalar).into_affine();
    let mut negative_point_1 = point_1.into_projective();
    negative_point_1.negate();

    vec![
        pairing_tuple(point_1, point_2),
        pairing_tuple(negative_point_1.into_affine(), point_2),
    ]
}

fn pairing_tuple(point_1: G1Affine, point_2: G2Affine) -> EcPairingInputTuple {
    let (x1, y1) = g1_to_tuple(point_1);
    let [x2, y2, x3, y3] = g2_to_tuple(point_2);
    [x1, y1, x2, y2, x3, y3]
}

fn g1_to_tuple(point: G1Affine) -> (U256, U256) {
    if point.is_zero() {
        return (U256::zero(), U256::zero());
    }

    let (x, y) = point.into_xy_unchecked();
    (fq_to_u256(x), fq_to_u256(y))
}

fn g2_to_tuple(point: G2Affine) -> [U256; 4] {
    if point.is_zero() {
        return [U256::zero(); 4];
    }

    let (x, y) = point.into_xy_unchecked();
    [
        fq_to_u256(x.c1),
        fq_to_u256(x.c0),
        fq_to_u256(y.c1),
        fq_to_u256(y.c0),
    ]
}

fn fq_to_u256(value: Fq) -> U256 {
    U256::from_str(format!("{}", value.into_repr()).as_str())
        .expect("BN254 field element must format as a decimal U256")
}

fn scalar_from_u64(value: u64) -> Fr {
    Fr::from_str(value.to_string().as_str()).expect("u64 scalar must fit into BN254 scalar field")
}

fn subgroup_invalid_case() -> Vec<EcPairingInputTuple> {
    vec![[
        u256_from_hex("0412aa5b0805215b55a5e2dbf0662031aad0f5ef13f28b25df20b8670d1c59a6"),
        u256_from_hex("16fb4b64ccff216fa5272e1e987c0616d60d8883d5834229c685949047e9411d"),
        u256_from_hex("2d81dbc969f72bc0454ff8b04735b717b725fee98a2fcbcdcf6c5b51b1dff33f"),
        u256_from_hex("075239888fc8448ab781e2a8bb85eb556469474cd707d4b913bee28679920eb6"),
        u256_from_hex("1ef1c268b7c4c78959f099a043ecd5e537fe3069ac9197235f16162372848cba"),
        u256_from_hex("209cfadc22f7e80d399d1886f1c53898521a34c62918ed802305f32b4070a3c4"),
    ]]
}

fn valid_true_case() -> Vec<EcPairingInputTuple> {
    vec![
        [
            u256_from_hex("2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"),
            u256_from_hex("2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"),
            u256_from_hex("1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"),
            u256_from_hex("22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"),
            u256_from_hex("2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"),
            u256_from_hex("2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"),
        ],
        [
            u256_from_hex("0000000000000000000000000000000000000000000000000000000000000001"),
            u256_from_hex("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"),
            u256_from_hex("1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"),
            u256_from_hex("091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"),
            u256_from_hex("2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"),
            u256_from_hex("23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"),
        ],
    ]
}

fn invalid_point_case() -> Vec<EcPairingInputTuple> {
    vec![[
        U256::from(5u64),
        U256::from(10u64),
        u256_from_hex("16342ef5343ae56e96dafd3fc43aaf6a715642f376327cf2bdb813cf41a0b55b"),
        u256_from_hex("237e8c97323c9032ce9e05af4b1597881131d137b5313182c9ef1b2576c9f3f1"),
        u256_from_hex("09c316c01492b5d4e2521d897b66de1e47438adf83a320054f8fc763935dc754"),
        u256_from_hex("0e1bf45145e9ee5372a81f2ad50b81830e3bb26400a5a72999fac2f73d768089"),
    ]]
}

fn u256_from_hex(hex: &str) -> U256 {
    U256::from_str_radix(hex, 16).expect("hex vector must parse as U256")
}
