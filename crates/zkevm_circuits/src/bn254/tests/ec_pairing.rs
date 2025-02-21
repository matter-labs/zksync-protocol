pub mod test {

    use crate::bn254::ec_pairing::alternative_precompile_naive::compute_pair;
    use crate::bn254::ec_pairing::final_exp::{
        CompressionMethod, FinalExpEvaluation, HardExpMethod,
    };

    use crate::bn254::tests::json::{
        FINAL_EXP_TEST_CASES, INVALID_SUBGROUP_TEST_CASES, PAIRING_TEST_CASES,
    };
    use crate::bn254::tests::utils::assert::assert_equal_fq12;
    use crate::bn254::tests::utils::cs::create_test_cs;
    use boojum::field::goldilocks::GoldilocksField;

    use boojum::gadgets::traits::witnessable::WitnessHookable;

    type F = GoldilocksField;
    type P = GoldilocksField;

    /// Tests the final exponentiation step used in the pairing computation.
    ///
    /// At the beginning of the test, one can specify the hard exponentiation method to use
    /// and whether to debug the number of rows in the constraint system.
    ///
    /// The test cases are loaded from the [`FINAL_EXP_TEST_CASES`] constant.
    #[test]
    fn test_final_exponentiation() {
        const HARD_EXP_METHOD: HardExpMethod = HardExpMethod::Naive;
        const COMPRESSION_METHOD: CompressionMethod = CompressionMethod::None;
        const DEBUG_PERFORMANCE: bool = false;

        // Running tests from file
        for (i, test) in FINAL_EXP_TEST_CASES.tests.iter().enumerate() {
            // Preparing the constraint system and parameters
            let mut owned_cs = create_test_cs(1 << 19);
            let cs = &mut owned_cs;

            // Expected:
            let expected_f_final = test.expected.to_fq12(cs);

            // Actual:
            let mut f = test.scalar.to_fq12(cs);
            let f_final =
                FinalExpEvaluation::evaluate(cs, &mut f, HARD_EXP_METHOD, COMPRESSION_METHOD);
            let f_final = f_final.get();

            // Asserting:
            assert_equal_fq12(cs, &f_final, &expected_f_final);

            use boojum::worker::Worker;
            use std::alloc::Global;

            // Printing the number of constraints if needed
            if DEBUG_PERFORMANCE {
                let worker = Worker::new_with_num_threads(8);

                //drop(cs1);
                owned_cs.pad_and_shrink();
                let mut owned_cs = owned_cs.into_assembly::<Global>();
                assert!(owned_cs.check_if_satisfied(&worker));

                owned_cs.print_gate_stats();
            }

            println!("Final exponentiation test {} has passed!", i);
        }
    }

    /// Tests the EC pairing as a whole by comparing output with the one retrieved from the Sage implementation.
    ///
    /// At the beginning of the test, one can specify the hard exponentiation method to use
    /// and whether to debug the number of rows in the constraint system.
    ///
    /// The test cases are loaded from the [`PAIRING_TEST_CASES`] constant.
    #[test]
    fn test_ec_pairing_inner() {
        const HARD_EXP_METHOD: HardExpMethod = HardExpMethod::Naive;
        const COMPRESSION_METHOD: CompressionMethod = CompressionMethod::AlgebraicTorus;
        const DEBUG_PERFORMANCE: bool = true;

        // Running tests from file
        for (i, test) in PAIRING_TEST_CASES.tests.iter().enumerate() {
            // Preparing the constraint system and parameters
            let mut owned_cs = create_test_cs(1 << 20);
            let cs = &mut owned_cs;

            // Expected:
            let mut expected_pairing = test.pairing.to_fq12(cs);

            // Input:

            let g1_point = test.g1_point.to_affine(cs);
            let g2_point = test.g2_point.to_affine(cs);
            // Actual:
            let (_, mut pairing) = compute_pair(cs, g1_point, g2_point);

            // Asserting:
            assert_equal_fq12(cs, &mut pairing, &mut expected_pairing);

            if DEBUG_PERFORMANCE {
                let cs = owned_cs.into_assembly::<std::alloc::Global>();
                cs.print_gate_stats();
            }
            println!("EC pairing test {} has passed!", i);
        }
    }

    /// Tests the unsatisfiability of the EC pairing when the points are not in the correct subgroup,
    /// so in other words when, for example, `P` and `Q` are not in the r-torsion subgroup.
    ///
    /// The test takes invalid `Q` G2 point from the [`INVALID_SUBGROUP_TEST_CASES`] constant and tries to compute the pairing
    /// of `e([2]P,Q)` and `e(P,[2]Q)`. The values should not be equal.
    #[test]
    fn test_ec_pairing_non_subgroup_unsatisfiability() {
        const HARD_EXP_METHOD: HardExpMethod = HardExpMethod::Naive;
        const COMPRESSION_METHOD: CompressionMethod = CompressionMethod::None;
        const DEBUG_PERFORMANCE: bool = true;

        // Running tests from file
        for (i, test) in INVALID_SUBGROUP_TEST_CASES.tests.iter().enumerate() {
            // Preparing the constraint system and parameters
            let mut owned_cs = create_test_cs(1 << 20);
            let cs = &mut owned_cs;

            let g1_point = test.g1_point.to_affine(cs);
            let g2_point = test.g2_point.to_affine(cs);

            let (result, _) = compute_pair(cs, g1_point, g2_point);

            assert_eq!(Some(false), result.witness_hook(cs)());

            if DEBUG_PERFORMANCE {
                let cs = owned_cs.into_assembly::<std::alloc::Global>();
                cs.print_gate_stats();
            }
            println!("EC pairing invalid subgroup test {} has passed!", i);
        }
    }
}
