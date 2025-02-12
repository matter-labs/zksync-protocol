use ec_pairing::PairingInvalidSubgroupTestCases;
use lazy_static::lazy_static;

use self::{
    ec_add::ECAddTestCases,
    ec_mul::{DecompositionTestCases, MultiplicationTestCases},
    ec_pairing::{FinalExpTestCases, PairingTestCases},
};

pub mod ec_add;
pub mod ec_mul;
pub mod ec_pairing;
pub mod types;

// All tests gathered in one place
lazy_static! {
    /// Test cases for EC addition
    pub static ref EC_ADD_TEST_CASES: ECAddTestCases = ec_add::load_ec_add_test_cases();
    /// Test cases for scalar decomposition
    pub static ref DECOMPOSITION_TEST_CASES: DecompositionTestCases = ec_mul::load_decomposition_test_cases();
    /// Test cases for scalar multiplication
    pub static ref EC_MUL_TEST_CASES: MultiplicationTestCases = ec_mul::load_multiplication_test_cases();
    /// Test cases for easy exponentiation
    pub static ref FINAL_EXP_TEST_CASES: FinalExpTestCases = ec_pairing::load_final_exp_test_cases();
    /// Test cases for pairing bilinearity
    pub static ref PAIRING_TEST_CASES: PairingTestCases = ec_pairing::load_pairing_test_cases();
    /// Test cases for pairing invalid subgroup checks
    pub static ref INVALID_SUBGROUP_TEST_CASES: PairingInvalidSubgroupTestCases = ec_pairing::load_pairing_invalid_subgroup_test_cases();
}
