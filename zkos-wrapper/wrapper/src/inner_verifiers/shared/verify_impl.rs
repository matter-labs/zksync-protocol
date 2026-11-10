pub fn verify<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    skeleton: WrappedProofSkeletonInstance<F>,
    queries: [WrappedQueryValuesInstance<F>; NUM_QUERIES],
) -> (
    WrappedProofOutput<
        F,
        TREE_CAP_SIZE,
        NUM_COSETS,
        NUM_DELEGATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
    >,
    WrappedProofPublicInputs<F, NUM_STATE_ELEMENTS>,
) {
    // now drive the transcript and continue
    let mut transcript_hasher = Blake2sStateGate::<F>::new(cs);
    let input = skeleton.transcript_elements_before_stage2(cs);
    let mut seed = Blake2sWrappedTranscript::commit_initial_using_hasher(
        cs,
        &mut transcript_hasher,
        &input,
    );

    if SECURITY_CONFIG.lookup_pow_bits > 0 {
        Blake2sWrappedTranscript::verify_pow_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            skeleton.pow_challenges.lookup_pow_challenge,
            SECURITY_CONFIG.lookup_pow_bits
        );
    }

    // draw local lookup argument challenges
    const NUM_LOOKUP_CHALLENGES: usize = transcript_challenge_array_size(
        NUM_STAGE_2_CHALLENGES * 4,
        SECURITY_CONFIG.lookup_pow_bits as usize,
    );
    let mut transcript_challenges = [UInt32::zero(cs); NUM_LOOKUP_CHALLENGES];
    Blake2sWrappedTranscript::draw_randomness_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &mut transcript_challenges,
    );

    let mut it =  if SECURITY_CONFIG.lookup_pow_bits > 0 {
        // skip 1 word used for PoW
        transcript_challenges[1..].as_chunks::<4>().0.iter()
    } else {
        transcript_challenges.as_chunks::<4>().0.iter()
    };

    let lookup_argument_linearization_challenges: [MersenneQuartic<F>;
        NUM_LOOKUP_ARGUMENT_LINEARIZATION_CHALLENGES] = core::array::from_fn(|_| {
        MersenneQuartic::from_coeffs(
            it.next()
                .unwrap()
                .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
        )
    });
    let lookup_argument_gamma = MersenneQuartic::from_coeffs(
        it.next()
            .unwrap()
            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
    );

    let (decoder_lookup_linearization_challenges, decoder_lookup_gamma) =
        if imports::VERIFIER_COMPILED_LAYOUT
            .witness_layout
            .multiplicities_columns_for_decoder_in_executor_families
            .num_elements()
            > 0
        {
            let linearization_challenges: [MersenneQuartic<F>;
                EXECUTOR_FAMILY_CIRCUIT_DECODER_TABLE_LINEARIZATION_CHALLENGES] =
                core::array::from_fn(|_| {
                    MersenneQuartic::from_coeffs(
                        it.next()
                            .unwrap()
                            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
                    )
                });
            let additive_part = MersenneQuartic::from_coeffs(
                it.next()
                    .unwrap()
                    .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
            );

            (linearization_challenges, additive_part)
        } else {
            (
                [MersenneQuartic::zero(cs);
                    EXECUTOR_FAMILY_CIRCUIT_DECODER_TABLE_LINEARIZATION_CHALLENGES],
                MersenneQuartic::zero(cs),
            )
        };

    // commit stage 2 artifacts - tree and memory grand product / delegation set accumulator
    let input = skeleton.transcript_elements_stage2_to_stage3(cs);
    Blake2sWrappedTranscript::commit_with_seed_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &input,
    );

    if SECURITY_CONFIG.quotient_alpha_pow_bits > 0 {
        Blake2sWrappedTranscript::verify_pow_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            skeleton.pow_challenges.quotient_alpha_pow_challenge,
            SECURITY_CONFIG.quotient_alpha_pow_bits
        );
    }

    // draw quotient linearization challenges
    let mut transcript_challenges =
        [UInt32::zero(cs); transcript_challenge_array_size(
            2usize * 4,
            SECURITY_CONFIG.quotient_alpha_pow_bits as usize,
        )];
    Blake2sWrappedTranscript::draw_randomness_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &mut transcript_challenges,
    );

    let mut it =  if SECURITY_CONFIG.quotient_alpha_pow_bits > 0 {
        // skip 1 word used for PoW
        transcript_challenges[1..].as_chunks::<4>().0.iter()
    } else {
        transcript_challenges.as_chunks::<4>().0.iter()
    };

    let quotient_alpha = MersenneQuartic::from_coeffs(
        it.next()
            .unwrap()
            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
    );

    let quotient_beta = MersenneQuartic::from_coeffs(
        it.next()
            .unwrap()
            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
    );

    // commit quotient tree
    Blake2sWrappedTranscript::commit_with_seed_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &skeleton.transcript_elements_stage3_to_stage4(),
    );

    if SECURITY_CONFIG.quotient_z_pow_bits > 0 {
        Blake2sWrappedTranscript::verify_pow_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            skeleton.pow_challenges.quotient_z_pow_challenge,
            SECURITY_CONFIG.quotient_z_pow_bits
        );
    }

    // draw DEEP poly linearization challenge
    let mut transcript_challenges =
        [UInt32::zero(cs); transcript_challenge_array_size(
            1usize * 4,
            SECURITY_CONFIG.quotient_z_pow_bits as usize,
        )];
    Blake2sWrappedTranscript::draw_randomness_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &mut transcript_challenges,
    );

    let mut it =  if SECURITY_CONFIG.quotient_z_pow_bits > 0 {
        // skip 1 word used for PoW
        transcript_challenges[1..].as_chunks::<4>().0.iter()
    } else {
        transcript_challenges.as_chunks::<4>().0.iter()
    };

    let z = MersenneQuartic::from_coeffs(
        it.next()
            .unwrap()
            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
    );

    // commit evaluations
    let input = skeleton.transcript_elements_evaluations_at_z(cs);
    Blake2sWrappedTranscript::commit_with_seed_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &input,
    );

    if SECURITY_CONFIG.deep_poly_alpha_pow_bits > 0 {
        Blake2sWrappedTranscript::verify_pow_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            skeleton.pow_challenges.deep_poly_alpha_pow_challenge,
            SECURITY_CONFIG.deep_poly_alpha_pow_bits
        );
    }

    // draw initial challenges for DEEP-poly:
    // alpha to batch the DEEP terms, and beta for the (1 + beta * x) degree lift
    let mut transcript_challenges =
        [UInt32::zero(cs); transcript_challenge_array_size(
            2usize * 4,
            SECURITY_CONFIG.deep_poly_alpha_pow_bits as usize,
        )];
    Blake2sWrappedTranscript::draw_randomness_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &mut transcript_challenges,
    );

    let mut it =  if SECURITY_CONFIG.deep_poly_alpha_pow_bits > 0 {
        // skip 1 word used for PoW
        transcript_challenges[1..].as_chunks::<4>().0.iter()
    } else {
        transcript_challenges.as_chunks::<4>().0.iter()
    };

    let deep_poly_alpha = MersenneQuartic::from_coeffs(
        it.next()
            .unwrap()
            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
    );
    // prover multiplies the DEEP poly by (1 + beta * x) before committing,
    // to make it of full degree
    let deep_poly_beta = MersenneQuartic::from_coeffs(
        it.next()
            .unwrap()
            .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
    );

    // now we should draw challenges and commit FRI oracles
    let mut fri_folding_challenges = [MersenneQuartic::<F>::zero(cs); NUM_FRI_STEPS];

    for (((caps, challenge), pow_challenge), pow_bits) in skeleton
        .transcript_elements_fri_intermediate_oracles()
        .into_iter()
        .zip(fri_folding_challenges.iter_mut())
        .zip(skeleton.pow_challenges.foldings_pow_challenges)
        .zip(SECURITY_CONFIG.foldings_pow_bits)
    {
        Blake2sWrappedTranscript::commit_with_seed_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            &caps,
        );

        if pow_bits > 0 {
            Blake2sWrappedTranscript::verify_pow_using_hasher(
                cs,
                &mut transcript_hasher,
                &mut seed,
                pow_challenge,
                pow_bits
            );
        }

        let mut transcript_challenges =
            vec![UInt32::zero(cs); transcript_challenge_array_size(
                1usize * 4,
                pow_bits as usize,
            )];

        Blake2sWrappedTranscript::draw_randomness_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            &mut transcript_challenges,
        );

        let mut it =  if pow_bits > 0 {
            // skip 1 word used for PoW
            transcript_challenges[1..].as_chunks::<4>().0.iter()
        } else {
            transcript_challenges.as_chunks::<4>().0.iter()
        };

        *challenge = MersenneQuartic::from_coeffs(
            it.next()
                .unwrap()
                .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
        );
    }

    if LAST_FRI_STEP_EXPOSE_LEAFS {
        let dst = &mut fri_folding_challenges[NUM_FRI_STEPS - 1];
        let input = skeleton.transcript_elements_last_fri_step_leaf_values(cs);
        Blake2sWrappedTranscript::commit_with_seed_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            &input,
        );

        if SECURITY_CONFIG.foldings_pow_bits[NUM_FRI_STEPS - 1] > 0 {
            Blake2sWrappedTranscript::verify_pow_using_hasher(
                cs,
                &mut transcript_hasher,
                &mut seed,
                skeleton.pow_challenges.foldings_pow_challenges[NUM_FRI_STEPS - 1],
                SECURITY_CONFIG.foldings_pow_bits[NUM_FRI_STEPS - 1]
            );
        }

        let mut transcript_challenges =
            vec![UInt32::zero(cs); transcript_challenge_array_size(
                1usize * 4,
                SECURITY_CONFIG.foldings_pow_bits[NUM_FRI_STEPS - 1] as usize,
            )];
        Blake2sWrappedTranscript::draw_randomness_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            &mut transcript_challenges,
        );

        let mut it =  if SECURITY_CONFIG.foldings_pow_bits[NUM_FRI_STEPS - 1] > 0 {
            // skip 1 word used for PoW
            transcript_challenges[1..].as_chunks::<4>().0.iter()
        } else {
            transcript_challenges.as_chunks::<4>().0.iter()
        };

        *dst = MersenneQuartic::from_coeffs(
            it.next()
                .unwrap()
                .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
        );
    }

    // commit monomial coefficients before drawing queries
    let input = skeleton.transcript_elements_monomial_coefficients(cs);
    Blake2sWrappedTranscript::commit_with_seed_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &input,
    );

    // now we can verify PoW
    Blake2sWrappedTranscript::verify_pow_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        skeleton.pow_challenges.fri_queries_pow_challenge,
        SECURITY_CONFIG.fri_queries_pow_bits
    );

    // now we need to draw enough bits to form query indexes
    let mut indexes_bits = [UInt32::<F>::zero(cs); NUM_REQUIRED_WORDS_FOR_QUERY_INDEXES];
    Blake2sWrappedTranscript::draw_randomness_using_hasher(
        cs,
        &mut transcript_hasher,
        &mut seed,
        &mut indexes_bits,
    );

    // NOTE: when we will use queries below, we MUST check that query set's index is exactly the index we draw from transcript.
    // Indexes in `queries` are already checked to be included in merkle tree caps declared in `skeleton`

    // And NOW we can check algebraic properties of the proof:
    // - quotient evaluation at z
    // - consistency check for DEEP poly
    // - correct folding in FRI

    // quotient evaluation at z

    let omega = MersenneComplex::allocate_constant(
        cs,
        Mersenne31Complex::TWO_ADICITY_GENERATORS[TRACE_LEN_LOG2],
    );
    let omega_inv = MersenneComplex::allocate_constant(
        cs,
        Mersenne31Complex::TWO_ADICITY_GENERATORS_INVERSED[TRACE_LEN_LOG2],
    );

    let z_omega = z.mul_by_base(cs, &omega);

    {
        // setup, then witness, then memory, then stage 2 base, then stage 2 ext, then quotient
        let (setup, rest) = skeleton.openings_at_z.split_at(NUM_SETUP_OPENINGS);
        let (witness, rest) = rest.split_at(NUM_WITNESS_OPENINGS);
        let (memory, rest) = rest.split_at(NUM_MEMORY_OPENINGS);
        let (stage_2, rest) = rest.split_at(NUM_STAGE2_OPENINGS);
        assert_eq!(rest.len(), 1);
        let quotient_opening = rest[0];

        let mut witness_next_row = [MersenneQuartic::zero(cs); NUM_WITNESS_OPENINGS];
        let mut memory_next_row = [MersenneQuartic::zero(cs); NUM_MEMORY_OPENINGS];
        let mut stage_2_next_row = [MersenneQuartic::zero(cs); NUM_STAGE2_OPENINGS];

        // we only need to update very few places here, so we will overwrite them below

        let lookup_argument_two_gamma = lookup_argument_gamma.double(cs);

        let (witness_next_row_set, rest) = skeleton
            .openings_at_z_omega
            .split_at(NUM_WITNESS_OPENING_NEXT_ROW);
        let (memory_next_row_set, rest) = rest.split_at(NUM_MEMORY_OPENING_NEXT_ROW);
        assert_eq!(rest.len(), 1);
        let stage_2_next_row_set = rest;

        debug_assert_eq!(
            witness_next_row_set.len(),
            WITNESS_NEXT_ROW_OPENING_INDEXES.len()
        );
        debug_assert_eq!(
            memory_next_row_set.len(),
            MEMORY_NEXT_ROW_OPENING_INDEXES.len()
        );

        for (index, element) in WITNESS_NEXT_ROW_OPENING_INDEXES
            .iter()
            .zip(witness_next_row_set.iter())
        {
            witness_next_row[*index] = *element;
        }
        for (index, element) in MEMORY_NEXT_ROW_OPENING_INDEXES
            .iter()
            .zip(memory_next_row_set.iter())
        {
            memory_next_row[*index] = *element;
        }

        stage_2_next_row[MEMORY_GRAND_PRODUCT_ACCUMULATOR_POLY_INDEX] = stage_2_next_row_set[0];

        let one_base = MersenneField::one(cs);

        let mut vanishing = z.exp_power_of_2(cs, TRACE_LEN_LOG2);
        vanishing = vanishing.sub_base(cs, &one_base);

        let omega_inv_squared = MersenneComplex::allocate_constant(
            cs,
            Mersenne31Complex::TWO_ADICITY_GENERATORS_INVERSED[TRACE_LEN_LOG2 - 1],
        );

        let mut z_minus_omega_inv = z;
        z_minus_omega_inv = z_minus_omega_inv.sub_base(cs, &omega_inv);

        let mut z_minus_omega_inv_squared = z;
        z_minus_omega_inv_squared = z_minus_omega_inv_squared.sub_base(cs, &omega_inv_squared);

        // now we should assemble candidates for batch inversion

        // first row is 1 / (x - omega^0)
        let mut first_row_to_inverse = z;
        first_row_to_inverse = first_row_to_inverse.sub_base(cs, &one_base);

        // one before last row is 1/(x - omega^-2)
        let mut one_before_last_row_to_inverse = z;
        one_before_last_row_to_inverse =
            one_before_last_row_to_inverse.sub_base(cs, &omega_inv_squared);

        // last row is 1/(x - omega^-1)
        let mut last_row_to_inverse = z;
        last_row_to_inverse = last_row_to_inverse.sub_base(cs, &omega_inv);

        let mut to_batch_inverse = [
            z,
            vanishing,
            first_row_to_inverse,
            one_before_last_row_to_inverse,
            last_row_to_inverse,
        ];

        for el in to_batch_inverse.iter_mut() {
            // TODO: can be optimized
            *el = el.inverse_or_zero(cs);

            // low probability here
            let boolean_false = Boolean::allocated_constant(cs, false);
            let is_zero = el.is_zero(cs);
            Boolean::enforce_equal(cs, &is_zero, &boolean_false);
        }

        let [
            z_inv,
            vanishing_inv,
            first_row,
            one_before_last_row,
            last_row,
        ] = to_batch_inverse;

        // everywhere except last row (x - omega^-1) / (x^n - 1)
        let everywhere_except_last = z_minus_omega_inv.mul(cs, &vanishing_inv);

        // everywhere except last two rows
        let everywhere_except_last_two_rows =
            everywhere_except_last.mul(cs, &z_minus_omega_inv_squared);

        let last_row_and_zero = last_row.mul(cs, &z_inv);

        let divisors = [
            everywhere_except_last,
            everywhere_except_last_two_rows,
            first_row,
            one_before_last_row,
            last_row,
            last_row_and_zero,
        ];

        let delegation_argument_accumulator_sum =
            if NUM_DELEGATION_CHALLENGES > 0 {
                skeleton.delegation_argument_accumulator[0]
            } else {
                // will be unused, but we do not want to deal with Option
                MersenneQuartic::zero(cs)
            };

        let aux_proof_values = WrappedProofAuxValues {
            grand_product_accumulator_final_value: skeleton.grand_product_accumulator,
            delegation_argument_accumulator_sum,
        };

        let machine_state_permutation_challenges =
            if NUM_MACHINE_STATE_PERMUTATION_CHALLENGES > 0 {
                skeleton
                    .machine_state_permutation_challenges[0]
            } else {
                WrappedExternalMachineStateArgumentChallenges{
                    linearization_challenges: [MersenneQuartic::zero(cs);
                        NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES],
                    additive_term: MersenneQuartic::zero(cs),
                }
            };

        let delegation_argument_linearization_challenges =
            if NUM_DELEGATION_CHALLENGES > 0 {
                skeleton.delegation_argument_challenges[0]
            } else {
                WrappedExternalDelegationArgumentChallenges {
                    delegation_argument_linearization_challenges: [MersenneQuartic::zero(cs);
                        NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES],
                    delegation_argument_gamma: MersenneQuartic::zero(cs),
                }
            };

        let shift = UInt32::allocate_constant(cs, 1 << CIRCUIT_SEQUENCE_BITS_SHIFT as u32);
        let memory_timestamp_high_from_circuit_sequence =
            skeleton.circuit_sequence_idx.non_widening_mul(cs, &shift);
        let memory_timestamp_high_from_circuit_sequence = MersenneField::from_uint32_with_reduction(
            cs,
            memory_timestamp_high_from_circuit_sequence,
        );

        let delegation_type = MersenneField::from_variable_checked(
            cs,
            skeleton.delegation_type.get_variable(),
            false,
        );

        // we need to show the sum of the values everywhere except the last row,
        // so we show that intermediate poly - interpolant((0, 0), (omega^-1, `value``)) is divisible
        // by our selected divisor, where "value" == negate(our sum over all other domain), and we also require that sum over
        // all the domain is 0

        // interpolant is literaly 1/omega^-1 * value * X (as one can see it's 0 at 0 and `value` at omega^-1)
        let mut delegation_argument_interpolant_linear_coeff =
            delegation_argument_accumulator_sum.mul_by_base(cs, &omega);
        delegation_argument_interpolant_linear_coeff =
            delegation_argument_interpolant_linear_coeff.negated(cs);

        use imports::evaluate_quotient;
        let quotient_recomputed_value = unsafe {
            evaluate_quotient(
                cs,
                z,
                witness,
                memory,
                setup,
                stage_2,
                &witness_next_row,
                &memory_next_row,
                &stage_2_next_row,
                quotient_alpha,
                quotient_beta,
                &divisors,
                &lookup_argument_linearization_challenges,
                lookup_argument_gamma,
                lookup_argument_two_gamma,
                &skeleton
                    .memory_argument_challenges
                    .memory_argument_linearization_challenges,
                skeleton.memory_argument_challenges.memory_argument_gamma,
                &delegation_argument_linearization_challenges
                    .delegation_argument_linearization_challenges,
                delegation_argument_linearization_challenges.delegation_argument_gamma,
                &decoder_lookup_linearization_challenges,
                decoder_lookup_gamma,
                &machine_state_permutation_challenges.linearization_challenges,
                machine_state_permutation_challenges.additive_term,
                &skeleton.public_inputs,
                &aux_proof_values,
                &skeleton.aux_boundary_values,
                memory_timestamp_high_from_circuit_sequence,
                delegation_type,
                delegation_argument_interpolant_linear_coeff,
            )
        };

        quotient_recomputed_value.enforce_equal(cs, &quotient_opening);
    }

    {
        // For the purposes of FRI below we consider query index as indexing into coset (highest bits) and domain (lowest bits).
        // Both indexes are bitreversed. When we will perform FRI folding we will need to perform an operation like (a - b)/eval_point(a).
        // Since our lowest bits are bitreversed, it means that lowest 3 bits correspond to element arising from 8th root of unity, and at
        // the end of the day we would to precompute 4 elements - 0..=3 powers of 8th root, and every time when our evaluation point is mapped
        // as x -> x^2, we only start to ignore

        assert_eq!(FRI_FACTOR_LOG2, 1);

        // below we will use consistency checks for oracles, where we compute just \sum alpha^i (f(z) - f(x))/(z - x) for few values of x.
        // So we can precompute \sum_i alpha^i f(z) that doesn't change

        let mut extra_factor_for_accumulation_at_z_omega = MersenneQuartic::zero(cs);

        let (precompute_with_evals_at_z, precompute_with_evals_at_z_omega) =
            precompute_for_consistency_checks(
                cs,
                &skeleton,
                &deep_poly_alpha,
                &mut extra_factor_for_accumulation_at_z_omega,
            );

        let omega = MersenneComplex::allocate_constant(
            cs,
            Mersenne31Complex::TWO_ADICITY_GENERATORS[TRACE_LEN_LOG2],
        );
        let tau = MersenneComplex::allocate_constant(
            cs,
            Mersenne31Complex::TWO_ADICITY_GENERATORS[TRACE_LEN_LOG2 + FRI_FACTOR_LOG2],
        );
        let tau_inv = MersenneComplex::allocate_constant(
            cs,
            Mersenne31Complex::TWO_ADICITY_GENERATORS_INVERSED[TRACE_LEN_LOG2 + FRI_FACTOR_LOG2],
        );

        let mut taus = [MersenneComplex::zero(cs); 1 << FRI_FACTOR_LOG2];
        taus[0] = MersenneComplex::one(cs);
        taus[1] = tau;

        let mut taus_inversed = [MersenneComplex::zero(cs); 1 << FRI_FACTOR_LOG2];
        taus_inversed[0] = MersenneComplex::one(cs);
        taus_inversed[1] = tau_inv;

        let mut taus_in_domain_by_half = [MersenneComplex::zero(cs); 1 << FRI_FACTOR_LOG2];
        taus_in_domain_by_half[0] = MersenneComplex::one(cs);
        taus_in_domain_by_half[1] = MersenneComplex::allocate_constant(
            cs,
            Mersenne31Complex::TWO_ADICITY_GENERATORS
                [TRACE_LEN_LOG2 + FRI_FACTOR_LOG2 - (TRACE_LEN_LOG2 - 1)],
        );

        let mut taus_in_domain_by_half_inversed = [MersenneComplex::zero(cs); 1 << FRI_FACTOR_LOG2];
        taus_in_domain_by_half_inversed[0] = MersenneComplex::one(cs);
        taus_in_domain_by_half_inversed[1] = MersenneComplex::allocate_constant(
            cs,
            Mersenne31Complex::TWO_ADICITY_GENERATORS_INVERSED
                [TRACE_LEN_LOG2 + FRI_FACTOR_LOG2 - (TRACE_LEN_LOG2 - 1)],
        );

        // here we will precompute max powers even needed
        let fri_folding_challenges_powers = fri_folding_challenges.map(|el| {
            let squared = el.square(cs);
            let quad = squared.square(cs);
            let eigths = quad.square(cs);
            let sixteens = eigths.square(cs);

            [el, squared, quad, eigths, sixteens]
        });

        // NOTE: here we skip 1 word because PoW is checked over it
        let mut bit_iterator = WrappedBitSource::new(cs, &indexes_bits[1..]);
        for query_round in 0..NUM_QUERIES {
            let query = &queries[query_round];
            let query_index_bits = bit_iterator.get_next_bits(cs, BITS_FOR_QUERY_INDEX);

            // assert that our query is at the proper index
            let mut powers = [F::ZERO; BITS_FOR_QUERY_INDEX];
            powers.copy_from_slice(&F::SHIFTS[..BITS_FOR_QUERY_INDEX]);
            boojum::gadgets::impls::lc::linear_combination_collapse(
                cs,
                &mut query_index_bits
                    .iter()
                    .map(|bit| bit.get_variable())
                    .zip(powers),
                Some(query.query_index.get_variable()),
            );

            let mut tree_index_bits = query_index_bits[0..TRACE_LEN_LOG2].to_vec();
            let mut domain_index_bits = tree_index_bits.clone();
            domain_index_bits.reverse();
            let coset_index_bits = query_index_bits[TRACE_LEN_LOG2..].to_vec();

            let mut evaluation_point = omega.pow(cs, &domain_index_bits);

            assert!(coset_index_bits.len() == 1);
            let tau_power =
                MersenneComplex::conditionally_select(cs, coset_index_bits[0], &taus[1], &taus[0]);

            evaluation_point = evaluation_point.mul(cs, &tau_power);

            let mut to_inverse = [z, z_omega];

            for el in to_inverse.iter_mut() {
                *el = el.sub_base(cs, &evaluation_point);

                // TODO: can be optimized
                *el = el.inverse_or_zero(cs);

                // low probability here
                let boolean_false = Boolean::allocated_constant(cs, false);
                let is_zero = el.is_zero(cs);
                Boolean::enforce_equal(cs, &is_zero, &boolean_false);
            }

            let [divisor_for_z, divisor_for_z_omega] = to_inverse;

            // and can verify FRI. Note that FRI oracle initial leaf is true RS code word, without any adjustments by tau^H/2,
            // and so all next intermediate oracles

            let taus_in_domain_by_half_power = MersenneComplex::conditionally_select(
                cs,
                coset_index_bits[0],
                &taus_in_domain_by_half[1],
                &taus_in_domain_by_half[0],
            );
            let tau_in_domain_by_half_inversed_power = MersenneComplex::conditionally_select(
                cs,
                coset_index_bits[0],
                &taus_in_domain_by_half_inversed[1],
                &taus_in_domain_by_half_inversed[0],
            );

            let mut expected_value = accumulate_over_row_for_consistency_check(
                cs,
                precompute_with_evals_at_z,
                precompute_with_evals_at_z_omega,
                &query,
                deep_poly_alpha,
                extra_factor_for_accumulation_at_z_omega,
                divisor_for_z,
                divisor_for_z_omega,
                taus_in_domain_by_half_power,
                tau_in_domain_by_half_inversed_power,
            );

            let mut domain_size_log_2 = TRACE_LEN_LOG2;
            // let mut domain_index = domain_index as usize;
            // let mut tree_index = tree_index as usize;
            let mut offset_inv = MersenneComplex::conditionally_select(
                cs,
                coset_index_bits[0],
                &taus_inversed[1],
                &taus_inversed[0],
            );
            let mut leaf_src: &[MersenneField<F>] = &query.fri_oracles_leafs;

            // committed FRI poly is the DEEP quotient additionally multiplied by (1 + beta * x),
            // so we adjust the value reconstructed from the oracle leafs before comparing
            // against the FRI oracle leaf
            let mut linear_factor = deep_poly_beta.mul_by_base(cs, &evaluation_point);
            let one = MersenneField::one(cs);
            linear_factor = linear_factor.add_base(cs, &one);
            expected_value = expected_value.mul(cs, &linear_factor);

            expected_value = expected_value.mul_by_base(cs, &tau_in_domain_by_half_inversed_power);
            for (step, folding_degree_log_2) in FRI_FOLDING_SCHEDULE.iter().enumerate() {
                let leaf_size = (1 << *folding_degree_log_2) * 4;
                let leaf_size_log = folding_degree_log_2 + 2;

                let leaf_projection = if LAST_FRI_STEP_EXPOSE_LEAFS && (step == NUM_FRI_STEPS - 1) {
                    let leaf_size_in_ext4_elements = leaf_size / 4;
                    let leaf_size_in_ext4_elements_log = leaf_size_log - 2;
                    // we should peek into the skeleton for all leaf values
                    let all_leaf_values_in_coset = <[MersenneQuartic<F>;
                        LAST_FRI_STEP_LEAFS_TOTAL_SIZE_PER_COSET]>::conditionally_select(
                        cs,
                        coset_index_bits[0],
                        &skeleton.fri_final_step_leafs[1],
                        &skeleton.fri_final_step_leafs[0],
                    );

                    let leaf_index_bits = &tree_index_bits[leaf_size_in_ext4_elements_log..];

                    let num_non_zero_bits = (all_leaf_values_in_coset.len()
                        / leaf_size_in_ext4_elements)
                        .trailing_zeros() as usize;
                    let leaf_projection = get_chunk_with_index_bits(
                        cs,
                        &all_leaf_values_in_coset,
                        &leaf_index_bits[..num_non_zero_bits],
                    );
                    for bit in leaf_index_bits[num_non_zero_bits..].iter() {
                        let boolean_false = Boolean::allocated_constant(cs, false);
                        Boolean::enforce_equal(cs, bit, &boolean_false);
                    }

                    assert_eq!(leaf_projection.len(), leaf_size_in_ext4_elements);

                    let leaf_projection: Vec<_> = leaf_projection
                        .into_iter()
                        .flat_map(|el| el.into_coeffs())
                        .collect();

                    leaf_projection
                } else {
                    let leaf_projection = leaf_src[..leaf_size].to_vec();
                    leaf_src = &leaf_src[leaf_size..];
                    leaf_projection
                };
                assert!(leaf_projection.len() == leaf_size);

                let challenges = fri_folding_challenges_powers[step];

                // NOTE: routine below will check that our expected value is indeed in the leaf at the expected position

                match *folding_degree_log_2 {
                    1 => {
                        fri_fold_by_log_n::<_, _, 1>(
                            cs,
                            &mut expected_value,
                            &mut evaluation_point,
                            &mut domain_size_log_2,
                            &mut domain_index_bits,
                            &mut tree_index_bits,
                            &mut offset_inv,
                            &leaf_projection,
                            &challenges,
                            &SHARED_FACTORS_FOR_FOLDING,
                        );
                    }
                    2 => {
                        fri_fold_by_log_n::<_, _, 2>(
                            cs,
                            &mut expected_value,
                            &mut evaluation_point,
                            &mut domain_size_log_2,
                            &mut domain_index_bits,
                            &mut tree_index_bits,
                            &mut offset_inv,
                            &leaf_projection,
                            &challenges,
                            &SHARED_FACTORS_FOR_FOLDING,
                        );
                    }
                    3 => {
                        fri_fold_by_log_n::<_, _, 3>(
                            cs,
                            &mut expected_value,
                            &mut evaluation_point,
                            &mut domain_size_log_2,
                            &mut domain_index_bits,
                            &mut tree_index_bits,
                            &mut offset_inv,
                            &leaf_projection,
                            &challenges,
                            &SHARED_FACTORS_FOR_FOLDING,
                        );
                    }
                    4 => {
                        fri_fold_by_log_n::<_, _, 4>(
                            cs,
                            &mut expected_value,
                            &mut evaluation_point,
                            &mut domain_size_log_2,
                            &mut domain_index_bits,
                            &mut tree_index_bits,
                            &mut offset_inv,
                            &leaf_projection,
                            &challenges,
                            &SHARED_FACTORS_FOR_FOLDING,
                        );
                    }
                    5 => {
                        fri_fold_by_log_n::<_, _, 5>(
                            cs,
                            &mut expected_value,
                            &mut evaluation_point,
                            &mut domain_size_log_2,
                            &mut domain_index_bits,
                            &mut tree_index_bits,
                            &mut offset_inv,
                            &leaf_projection,
                            &challenges,
                            &SHARED_FACTORS_FOR_FOLDING,
                        );
                    }
                    _ => {
                        unreachable!("too high folding degree");
                    }
                }
            }

            let value_from_monomial_form =
                evaluate_monomial_form(cs, &skeleton.monomial_coeffs, &evaluation_point);

            expected_value = expected_value.mul_by_base(cs, &taus_in_domain_by_half_power);

            value_from_monomial_form.enforce_equal(cs, &expected_value);
        }
    }

    // NOTE: we will NOT perform any logic about comparison here, and instead we will just write the result back to callee

    let proof_state_dst = WrappedProofOutput {
        setup_caps: skeleton.setup_caps,
        memory_caps: skeleton.memory_caps,
        memory_challenges: skeleton.memory_argument_challenges,
        delegation_challenges: skeleton.delegation_argument_challenges,
        lazy_init_boundary_values: skeleton.aux_boundary_values,
        machine_state_permutation_challenges: skeleton.machine_state_permutation_challenges,
        grand_product_accumulator: skeleton.grand_product_accumulator,
        delegation_argument_accumulator: skeleton.delegation_argument_accumulator,
        circuit_sequence: skeleton.circuit_sequence_idx,
        delegation_type: skeleton.delegation_type,
    };

    let proof_input_dst = if NUM_STATE_ELEMENTS > 0 {
        let mut it = skeleton
            .public_inputs
            .as_chunks::<NUM_STATE_ELEMENTS>()
            .0
            .iter();
        let input_state_variables = *it.next().unwrap();
        let output_state_variables = *it.next().unwrap();
        WrappedProofPublicInputs {
            input_state_variables,
            output_state_variables,
        }
    } else {
        WrappedProofPublicInputs {
            input_state_variables: [MersenneField::zero(cs); 0],
            output_state_variables: [MersenneField::zero(cs); 0],
        }
    };

    (proof_state_dst, proof_input_dst)
}

fn precompute_for_consistency_checks<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    skeleton: &WrappedProofSkeletonInstance<F>,
    deep_poly_alpha: &MersenneQuartic<F>,
    extra_factor_for_accumulation_at_z_omega: &mut MersenneQuartic<F>,
) -> (MersenneQuartic<F>, MersenneQuartic<F>) {
    // here we should inverse the Horner rule (walk backwards)
    let num_evals_at_z = skeleton.openings_at_z.len();

    let mut i = num_evals_at_z - 1;
    let mut precompute_with_evals_at_z = skeleton.openings_at_z[i];
    while i > 0 {
        i -= 1;
        precompute_with_evals_at_z = deep_poly_alpha.mul_and_add(
            cs,
            &precompute_with_evals_at_z,
            &skeleton.openings_at_z[i],
        );
    }

    let mut i = skeleton.openings_at_z_omega.len() - 1;
    let mut precompute_with_evals_at_z_omega = skeleton.openings_at_z_omega[i];
    while i > 0 {
        i -= 1;
        precompute_with_evals_at_z_omega = deep_poly_alpha.mul_and_add(
            cs,
            &precompute_with_evals_at_z_omega,
            &skeleton.openings_at_z_omega[i],
        );
    }

    // multiply by extra power
    *extra_factor_for_accumulation_at_z_omega = deep_poly_alpha.pow_const(cs, num_evals_at_z);
    precompute_with_evals_at_z_omega =
        precompute_with_evals_at_z_omega.mul(cs, extra_factor_for_accumulation_at_z_omega);

    (precompute_with_evals_at_z, precompute_with_evals_at_z_omega)
}

fn accumulate_over_row_for_consistency_check<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    precompute_with_evals_at_z: MersenneQuartic<F>,
    precompute_with_evals_at_z_omega: MersenneQuartic<F>,
    query: &WrappedQueryValuesInstance<F>,
    deep_poly_alpha: MersenneQuartic<F>,
    extra_factor_for_accumulation_at_z_omega: MersenneQuartic<F>,
    divisor_for_z: MersenneQuartic<F>,
    divisor_for_z_omega: MersenneQuartic<F>,
    tau_in_domain_by_half: MersenneComplex<F>,
    tau_in_domain_by_half_inversed: MersenneComplex<F>,
) -> MersenneQuartic<F> {
    use imports::VERIFIER_COMPILED_LAYOUT;

    // now we can do consistency check
    // quotient is just a single value
    let mut accumulated_at_z = {
        let leaf_el = MersenneQuartic::from_coeffs(query.quotient_leaf);
        // NOTE: we compute quotient at non-main domain first, and then LDE, so we do NOT have adjustment
        // there, and we should cancel one below
        leaf_el.mul_by_base(cs, &tau_in_domain_by_half_inversed)
    };

    for leaf_el in query.stage_2_leaf[VERIFIER_COMPILED_LAYOUT.stage_2_layout.ext4_polys_offset..]
        .as_chunks::<4>()
        .0
        .iter()
        .rev()
    {
        let leaf_el = MersenneQuartic::from_coeffs(*leaf_el);
        accumulated_at_z = accumulated_at_z.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }

    for leaf_el in query.stage_2_leaf[..VERIFIER_COMPILED_LAYOUT
        .stage_2_layout
        .num_base_field_polys()]
        .iter()
        .rev()
    {
        let leaf_el = MersenneQuartic::from_base(cs, *leaf_el);
        accumulated_at_z = accumulated_at_z.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }

    for leaf_el in query.memory_leaf.iter().rev() {
        let leaf_el = MersenneQuartic::from_base(cs, *leaf_el);
        accumulated_at_z = accumulated_at_z.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }

    for leaf_el in query.witness_leaf.iter().rev() {
        let leaf_el = MersenneQuartic::from_base(cs, *leaf_el);
        accumulated_at_z = accumulated_at_z.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }

    // setup, then witness, then memory, then stage 2 base, then stage 2 ext, then quotient
    for leaf_el in query.setup_leaf.iter().rev() {
        let leaf_el = MersenneQuartic::from_base(cs, *leaf_el);
        accumulated_at_z = accumulated_at_z.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }

    // all terms are linear over leaf values, so it's enough to scale once
    accumulated_at_z = accumulated_at_z.mul_by_base(cs, &tau_in_domain_by_half);

    let mut simulated_from_z = precompute_with_evals_at_z.sub(cs, &accumulated_at_z);
    simulated_from_z = simulated_from_z.mul(cs, &divisor_for_z);

    // single element for stage 2
    let mut accumulated_at_z_omega = {
        let leaf_el =
            query.stage_2_leaf[VERIFIER_COMPILED_LAYOUT.stage_2_layout.ext4_polys_offset
                + (MEMORY_GRAND_PRODUCT_ACCUMULATOR_POLY_INDEX
                    - VERIFIER_COMPILED_LAYOUT
                        .stage_2_layout
                        .num_base_field_polys())
                    * 4..]
                .as_chunks::<4>()
                .0
                .iter()
                .next()
                .unwrap();
        let leaf_el = MersenneQuartic::from_coeffs(*leaf_el);
        leaf_el
    };

    for index in MEMORY_NEXT_ROW_OPENING_INDEXES.iter().rev() {
        let leaf_el = MersenneQuartic::from_base(cs, query.memory_leaf[*index]);
        accumulated_at_z_omega = accumulated_at_z_omega.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }
    for index in WITNESS_NEXT_ROW_OPENING_INDEXES.iter().rev() {
        let leaf_el = MersenneQuartic::from_base(cs, query.witness_leaf[*index]);
        accumulated_at_z_omega = accumulated_at_z_omega.mul_and_add(cs, &deep_poly_alpha, &leaf_el);
    }

    accumulated_at_z_omega =
        accumulated_at_z_omega.mul(cs, &extra_factor_for_accumulation_at_z_omega);

    // all terms are linear over leaf values, so it's enough to scale once
    accumulated_at_z_omega = accumulated_at_z_omega.mul_by_base(cs, &tau_in_domain_by_half);

    let mut simulated_from_z_omega =
        precompute_with_evals_at_z_omega.sub(cs, &accumulated_at_z_omega);
    simulated_from_z_omega = simulated_from_z_omega.mul(cs, &divisor_for_z_omega);

    simulated_from_z.add(cs, &simulated_from_z_omega)
}

fn evaluate_monomial_form<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    monomial_coeffs: &[MersenneQuartic<F>; FRI_FINAL_DEGREE],
    evaluation_point: &MersenneComplex<F>,
) -> MersenneQuartic<F> {
    // now we have our evaluation point, and we can evaluate a result from the monomial form
    // here Horner rule is a little more involved
    // we want to multiply previous by evaluation point, and add to the new one
    let bound = monomial_coeffs.len();
    let mut i = bound - 1;
    let mut value_from_monomial_form = monomial_coeffs[i];
    let evaluation_point = MersenneQuartic::from_complex(cs, *evaluation_point);
    while i > 0 {
        i -= 1;
        value_from_monomial_form =
            value_from_monomial_form.mul_and_add(cs, &evaluation_point, &monomial_coeffs[i]);
    }

    value_from_monomial_form
}

fn get_chunk_with_index_bits<F: SmallField, CS: ConstraintSystem<F>, T: Selectable<F> + Clone>(
    cs: &mut CS,
    src: &[T],
    index_bits: &[Boolean<F>],
) -> Vec<T> {
    assert!(
        src.len() % (1 << index_bits.len()) == 0,
        "src should contain 2^index_bits.len() equal chunks"
    );

    let mut result = src.to_vec();

    for bit in index_bits.iter().rev() {
        let current_length = result.len() / 2;
        let mut current = Vec::with_capacity(current_length);

        for idx in 0..current_length {
            current.push(T::conditionally_select(
                cs,
                bit.clone(),
                &result[idx + current_length],
                &result[idx],
            ));
        }

        result = current;
    }

    result
}

pub fn fri_fold_by_log_n<
    F: SmallField,
    CS: ConstraintSystem<F>,
    const FOLDING_DEGREE_LOG2: usize,
>(
    cs: &mut CS,
    expected_value: &mut MersenneQuartic<F>,
    evaluation_point: &mut MersenneComplex<F>,
    domain_size_log_2: &mut usize,
    domain_index_bits: &mut [Boolean<F>],
    tree_index_bits: &mut [Boolean<F>],
    offset_inv: &mut MersenneComplex<F>,
    leaf: &[MersenneField<F>],
    fri_folding_challenges_powers: &[MersenneQuartic<F>],
    shared_factors_for_folding: &[Mersenne31Complex],
) {
    const MAX_SIZE_FOR_LEAF: usize = 32;
    const MAX_SIZE_FOR_ROOTS: usize = 16;

    assert!(FOLDING_DEGREE_LOG2 > 0);
    assert!(FOLDING_DEGREE_LOG2 <= 5);
    debug_assert_eq!(leaf.len(), (1 << FOLDING_DEGREE_LOG2) * 4);

    let eval_points_num_bits = *domain_size_log_2 - FOLDING_DEGREE_LOG2;
    let generator_inv = MersenneComplex::allocate_constant(
        cs,
        Mersenne31Complex::TWO_ADICITY_GENERATORS_INVERSED[*domain_size_log_2],
    );

    *domain_size_log_2 -= FOLDING_DEGREE_LOG2;

    // here we use worst-case sizes
    let mut leaf_parsed = [MersenneQuartic::zero(cs); MAX_SIZE_FOR_LEAF];
    let mut it = leaf.as_chunks::<4>().0.iter();
    for i in 0..(1 << FOLDING_DEGREE_LOG2) {
        // NOTE: field elements are reduced in the query already!
        leaf_parsed[i] = MersenneQuartic::from_coeffs(*it.next().unwrap());
    }

    let expected_index_in_rs_code_word_leaf_bits = tree_index_bits[..FOLDING_DEGREE_LOG2].to_vec();
    let value_at_expected_index =
        get_chunk_with_index_bits(cs, &leaf, &expected_index_in_rs_code_word_leaf_bits);
    assert_eq!(value_at_expected_index.len(), 4);

    let value_at_expected_index =
        MersenneQuartic::from_coeffs(value_at_expected_index.try_into().unwrap());
    // check that our simulated value is actually in the leaf

    expected_value.enforce_equal(cs, &value_at_expected_index);

    // note that our evaluation points share highest N-3 bits, so we can just precompute additional multiplication
    // factors for lower bits. We only need elements that are not negations of each other

    let shared_bits_in_folding = domain_index_bits[..eval_points_num_bits].to_vec();
    let mut evaluation_point_shared_factor = generator_inv.pow(cs, &shared_bits_in_folding);
    evaluation_point_shared_factor = evaluation_point_shared_factor.mul(cs, offset_inv);
    // again - worst case size
    let mut folding_evals_points_inversed = [MersenneComplex::zero(cs); MAX_SIZE_FOR_ROOTS];
    for i in 0..(1 << (FOLDING_DEGREE_LOG2 - 1)) {
        let t = MersenneComplex::allocate_constant(cs, shared_factors_for_folding[i]);
        folding_evals_points_inversed[i] = t.mul(cs, &evaluation_point_shared_factor);
    }

    let mut buffer_0 = [MersenneQuartic::zero(cs); MAX_SIZE_FOR_LEAF];
    let mut buffer_1 = [MersenneQuartic::zero(cs); MAX_SIZE_FOR_LEAF];

    for round in 0..FOLDING_DEGREE_LOG2 {
        let roots_stride = 1 << round;
        if round > 0 {
            // we should remap evaluation points
            for i in 0..1 << (FOLDING_DEGREE_LOG2 - round - 1) {
                folding_evals_points_inversed[i * roots_stride] =
                    folding_evals_points_inversed[i * roots_stride].square(cs);
            }
        }
        let (input_buffer, output_buffer) = if round % 2 == 0 {
            (&mut buffer_0, &mut buffer_1)
        } else {
            (&mut buffer_1, &mut buffer_0)
        };
        let challenge = fri_folding_challenges_powers[round];

        for i in 0..1 << (FOLDING_DEGREE_LOG2 - round - 1) {
            let root = folding_evals_points_inversed[i * roots_stride];
            let (a, b) = if round == 0 {
                (leaf_parsed[2 * i], leaf_parsed[2 * i + 1])
            } else {
                (input_buffer[2 * i], input_buffer[2 * i + 1])
            };

            let mut t = a.sub(cs, &b);
            t = t.mul_by_base(cs, &root);
            let folder = t.mul_and_add(cs, &challenge, &a);

            output_buffer[i] = folder.add(cs, &b);
        }
    }

    *expected_value = if FOLDING_DEGREE_LOG2 % 2 == 0 {
        buffer_0[0]
    } else {
        buffer_1[0]
    };

    for _ in 0..FOLDING_DEGREE_LOG2 {
        *evaluation_point = evaluation_point.square(cs);
        *offset_inv = offset_inv.square(cs);
    }

    let remaining_len = tree_index_bits.len() - FOLDING_DEGREE_LOG2;
    for i in 0..remaining_len {
        tree_index_bits[i] = tree_index_bits[i + FOLDING_DEGREE_LOG2].clone();
    }
    for bit in tree_index_bits[remaining_len..].iter_mut() {
        *bit = Boolean::allocated_constant(cs, false);
    }
    for bit in domain_index_bits[*domain_size_log_2..].iter_mut() {
        *bit = Boolean::allocated_constant(cs, false);
    }
}
