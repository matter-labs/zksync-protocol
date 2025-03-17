#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use revm::precompile::bn128;
use zkevm_test_harness::ethereum_types::U256;
use zkevm_test_harness::tests::complex_tests::precompiles::test_ecpairing_using_tuples_fuzz;

#[derive(Debug, Arbitrary)]
struct Input {
    x1: [u8; 32],
    y1: [u8; 32],
    x2: [u8; 32],
    y2: [u8; 32],
    x3: [u8; 32],
    y3: [u8; 32],
}

impl Input {
    pub fn to_tuple(&self) -> Vec<[[u8; 32]; 6]> {
        vec![[self.x1, self.y1, self.x2, self.y2, self.x3, self.y3]; 6]
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        result.extend_from_slice(&self.x1);
        result.extend_from_slice(&self.y1);
        result.extend_from_slice(&self.x2);
        result.extend_from_slice(&self.y2);
        result.extend_from_slice(&self.x3);
        result.extend_from_slice(&self.y3);

        result
    }
}

fuzz_target!(|data: Input| {
    let tuple = data.to_tuple();
    let (success, result) = test_ecpairing_using_tuples_fuzz(tuple);
    let expected_res = bn128::run_pair(data.to_bytes().as_slice(), 0, 0, 1 << 27);

    match expected_res {
        Ok(expected) => {
            let expected_result = U256::from_big_endian(&expected.bytes.to_vec().as_slice()[0..32]);

            assert_eq!(success, U256::one());
            assert_eq!(result, expected_result);
        }
        Err(_) => assert_eq!(success, U256::zero()),
    }
});
