#![no_main]
#[macro_use] extern crate libfuzzer_sys;

use libfuzzer_sys::fuzz_target;
//use zkevm_test_harness::tests::complex_tests::precompiles::test_ecadd_from_hex;

fuzz_target!(|data: &[u8]| {
     //test_ecadd_from_hex(&*hex::encode(data));
});
