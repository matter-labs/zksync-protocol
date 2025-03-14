#![no_main]
#[macro_use] extern crate libfuzzer_sys;

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use zkevm_test_harness::tests::complex_tests::precompiles::test_ecadd_using_tuple;

#[derive(Debug, Arbitrary)]
struct Input {
     x1: [u8; 32],
     y1: [u8; 32],
     x2: [u8; 32],
     y2: [u8; 32],
}
fuzz_target!(|data: Input| {
     dbg!(1);
     let tuple = vec![[data.x1, data.y1], [data.x2, data.y2]];
     let _ = test_ecadd_using_tuple(tuple);
});
