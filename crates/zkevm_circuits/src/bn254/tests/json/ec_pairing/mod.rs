use crate::bn254::tests::json::types::{RawFq12, RawG1Point, RawG2Point};
use serde::{Deserialize, Serialize};

/// Test cases for G2 Curve
const G2_CURVE_TEST_CASES: &str = include_str!("g2_tests.json");
/// Test cases for easy exponentiation
const FINAL_EXP_TEST_CASES: &str = include_str!("final_exp_tests.json");
/// Test cases for pairing evaluation
const PAIRING_TEST_CASES: &str = include_str!("pairing_tests.json");
/// Ttest cases for invalid subgroup checks
const INVALID_SUBGROUP_CHECKS: &str = include_str!("pairing_invalid_subgroup_tests.json");

// --- G2 Tests ---
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct G2TestCase {
    pub point_1: RawG2Point,
    pub point_2: RawG2Point,
    pub expected: G2ExpectedValue,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct G2ExpectedValue {
    pub sum: RawG2Point,
    pub point_1_double: RawG2Point,
    pub point_2_double: RawG2Point,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct G2TestCases {
    pub tests: Vec<G2TestCase>,
}

/// Load [`G2TestCases`] from the local `.json` file
pub(in super::super) fn load_g2_curve_test_cases() -> G2TestCases {
    serde_json::from_str(&G2_CURVE_TEST_CASES).expect("Failed to deserialize")
}

// --- Final exponentiation tests ---

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalExpTestCase {
    pub scalar: RawFq12,
    pub expected: RawFq12,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalExpTestCases {
    pub tests: Vec<FinalExpTestCase>,
}

/// Load [`FinalExpTestCases`] from the local `.json` file
pub(in super::super) fn load_final_exp_test_cases() -> FinalExpTestCases {
    serde_json::from_str(&FINAL_EXP_TEST_CASES).expect("Failed to deserialize")
}

// --- Pairing tests ---
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PairingTestCase {
    pub g1_point: RawG1Point,
    pub g2_point: RawG2Point,
    pub miller_loop: RawFq12,
    pub pairing: RawFq12,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PairingTestCases {
    pub tests: Vec<PairingTestCase>,
}

/// Load [`PairingTestCases`] test cases from the local `.json` file
pub(in super::super) fn load_pairing_test_cases() -> PairingTestCases {
    serde_json::from_str(&PAIRING_TEST_CASES).expect("Failed to deserialize")
}

// --- Invalid subgroup tests ---
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PairingInvalidSubgroupTestCase {
    pub g1_point: RawG1Point,
    pub g2_point: RawG2Point,
    pub g1_point_doubled: RawG1Point,
    pub g2_point_doubled: RawG2Point,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PairingInvalidSubgroupTestCases {
    pub tests: Vec<PairingInvalidSubgroupTestCase>,
}

/// Load [`PairingInvalidSubgroupTestCases`] from the local `.json` file
pub(in super::super) fn load_pairing_invalid_subgroup_test_cases() -> PairingInvalidSubgroupTestCases
{
    serde_json::from_str(&INVALID_SUBGROUP_CHECKS).expect("Failed to deserialize")
}
