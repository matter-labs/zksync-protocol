#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use revm::precompile::modexp;
use zkevm_test_harness::ethereum_types::U256;
use zkevm_test_harness::tests::complex_tests::precompiles::test_modexp_using_tuple_fuzz;

#[derive(Debug, Arbitrary)]
struct Input {
    b: [u8; 32],
    e: [u8; 32],
    m: [u8; 32],
}

impl Input {
    pub fn to_tuple(&self) -> Vec<[[u8; 32]; 3]> {
        vec![[self.b, self.e, self.m]]
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let hex_str_32 =
            &*hex::decode("0000000000000000000000000000000000000000000000000000000000000020")
                .unwrap();
        let mut result = Vec::new();

        result.extend_from_slice(hex_str_32);
        result.extend_from_slice(hex_str_32);
        result.extend_from_slice(hex_str_32);

        result.extend_from_slice(&self.b);
        result.extend_from_slice(&self.e);
        result.extend_from_slice(&self.m);

        result
    }
}

fuzz_target!(|data: Input| {
    let tuple = data.to_tuple();
    let zksync_res = test_modexp_using_tuple_fuzz(tuple);
    let bytes: alloy::primitives::Bytes = data.to_bytes().into();
    let expected_res = modexp::berlin_run(&bytes, 1 << 27);

    match expected_res {
        Ok(expected) => {
            let expected_x = U256::from_big_endian(&expected.bytes.to_vec().as_slice()[0..32]);
            assert_eq!(expected_x, zksync_res);
        }

        Err(_) => assert_eq!(zksync_res, U256::zero()),
    }
});
