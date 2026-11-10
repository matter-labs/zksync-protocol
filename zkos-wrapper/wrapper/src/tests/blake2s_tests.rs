use super::*;

// #[test]
// fn test_transcript_circuit() {
//     let input_len = 64;
//     let mut input_u32: Vec<u32> = vec![];
//     for i in 0..input_len {
//         input_u32.push(i as u32);
//     }

// }

// #[test]
// fn test_single_round_exact() {
//     test_blake2s(64);
// }

#[test]
fn test_blake2s_round_function() {
    let len = 16;
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let mut input = vec![];
    for _ in 0..len {
        let byte: u32 = rng.r#gen();
        input.push(byte);
    }

    let mut hasher = risc_verifier::blake2s_u32::Blake2sState::new();
    hasher
        .input_buffer
        .iter_mut()
        .enumerate()
        .for_each(|(i, x)| {
            *x = input[i];
        });
    unsafe {
        hasher.run_round_function::<true>(len, true);
    }
    let reference_output = hasher.read_state_for_output();

    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 20,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 4,
    };

    use boojum::config::DevCSConfig;
    use boojum::cs::cs_builder_reference::*;
    let builder_impl =
        CsReferenceImplementationBuilder::<F, F, DevCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            1 << 17,
        );
    use boojum::cs::cs_builder::new_builder;
    let builder = new_builder::<_, F>(builder_impl);

    let builder = builder.allow_lookup(
        boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions: 5,
            share_table_id: true,
        },
    );
    let builder = ConstantsAllocatorGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = U32TriAddCarryAsChunkGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 4>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );

    // let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 20));
    let mut owned_cs = builder.build(1 << 20);

    // add tables
    let table = create_xor8_table();
    owned_cs.add_lookup_table::<Xor8Table, 3>(table);

    let table = create_byte_split_table::<F, 4>();
    owned_cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

    let table = create_byte_split_table::<F, 7>();
    owned_cs.add_lookup_table::<ByteSplitTable<7>, 3>(table);

    let table = create_byte_split_table::<F, 1>();
    owned_cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);

    // let table = create_byte_split_table::<F, 2>();
    // owned_cs.add_lookup_table::<ByteSplitTable<2>, 3>(table);

    // let table = create_byte_split_table::<F, 3>();
    // owned_cs.add_lookup_table::<ByteSplitTable<3>, 3>(table);

    let mut circuit_input = vec![];

    let cs = &mut owned_cs;

    for val in input.iter() {
        let val = UInt32::allocate_checked(cs, *val);
        circuit_input.push(val);
    }

    let mut hasher = Blake2sStateGate::new(cs);
    hasher
        .input_buffer
        .iter_mut()
        .enumerate()
        .for_each(|(i, x)| {
            *x = Word {
                inner: circuit_input[i].to_le_bytes(cs),
            };
        });
    hasher.run_round_function::<_, true>(cs, len, true);

    let output = hasher
        .read_state_for_output()
        .map(|el| UInt32::from_le_bytes(cs, el.inner));

    let output = output.witness_hook(cs)().unwrap();
    let reference_output = reference_output.as_slice();
    assert_eq!(output, reference_output);

    let _ = cs;
    let _owned_cs = owned_cs.into_assembly::<Global>();
}

// #[test]
// fn test_transcript_circuit_initial() {
//     test_transcript_circuit(200);
// }

// fn test_transcript_circuit(len: usize) {
//     // use rand::{Rng, SeedableRng};
//     // let mut rng = rand::rngs::StdRng::seed_from_u64(42);

//     let mut input = vec![];
//     for i in 0..len {
//         let byte: u32 = i as u32; // rng.r#gen();
//         input.push(byte);
//     }

//     const POW_BITS: usize = 28;

//     let mut transcript_hasher = risc_verifier::blake2s_u32::Blake2sState::new();
//     let mut seed = risc_verifier::transcript::Blake2sTranscript::commit_initial_using_hasher(
//         &mut transcript_hasher,
//         &input[..],
//     );
//     risc_verifier::transcript::Blake2sTranscript::commit_with_seed_using_hasher(
//         &mut transcript_hasher,
//         &mut seed,
//         &input,
//     );
//     let mut transcript_challenges = unsafe {
//         MaybeUninit::<
//             [u32; (1usize * 4)
//                 .next_multiple_of(risc_verifier::blake2s_u32::BLAKE2S_DIGEST_SIZE_U32_WORDS)],
//         >::uninit()
//         .assume_init()
//     };
//     risc_verifier::transcript::Blake2sTranscript::draw_randomness_using_hasher(
//         &mut transcript_hasher,
//         &mut seed,
//         &mut transcript_challenges,
//     );

//     // let worker = zkos_verifier_worker::Worker::new_with_num_threads(4);
//     // let (mut _seed, pow_nonce) = zkos_verifier::transcript::Blake2sTranscript::search_pow(&seed, POW_BITS, &worker);
//     let pow_nonce: u64 = 280946043;
//     tracing::info!("pow_nonce: {}", pow_nonce);
//     // let mut transcript_hasher = zkos_verifier::blake2s_u32::Blake2sState::new();
//     risc_verifier::transcript::Blake2sTranscript::verify_pow_using_hasher(
//         &mut transcript_hasher,
//         &mut seed,
//         pow_nonce as u64,
//         POW_BITS as u32,
//     );

//     let reference_output = transcript_challenges; // seed.0;

//     let geometry = CSGeometry {
//         num_columns_under_copy_permutation: 20,
//         num_witness_columns: 0,
//         num_constant_columns: 4,
//         max_allowed_constraint_degree: 4,
//     };

//     use boojum::config::DevCSConfig;
//     use boojum::cs::cs_builder_reference::*;
//     let builder_impl =
//         CsReferenceImplementationBuilder::<F, F, DevCSConfig, StCircuitResolver>::new(geometry, 1 << 17);
//     use boojum::cs::cs_builder::new_builder;
//     let builder = new_builder::<_, F>(builder_impl);

//     let builder = builder.allow_lookup(
//         boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
//             width: 3,
//             num_repetitions: 5,
//             share_table_id: true,
//         },
//     );
//     let builder = ConstantsAllocatorGate::configure_builder(
//         builder,
//         GatePlacementStrategy::UseGeneralPurposeColumns,
//     );
//     let builder = U32TriAddCarryAsChunkGate::configure_builder(
//         builder,
//         GatePlacementStrategy::UseGeneralPurposeColumns,
//     );
//     let builder = ReductionGate::<F, 4>::configure_builder(
//         builder,
//         GatePlacementStrategy::UseGeneralPurposeColumns,
//     );
//     let builder = UIntXAddGate::<16>::configure_builder(
//         builder,
//         GatePlacementStrategy::UseGeneralPurposeColumns,
//     );
//     let builder = UIntXAddGate::<8>::configure_builder(
//         builder,
//         GatePlacementStrategy::UseGeneralPurposeColumns,
//     );
//     let builder =
//         NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

//     let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 20));

//     // add tables
//     let table = create_xor8_table();
//     owned_cs.add_lookup_table::<Xor8Table, 3>(table);

//     let table = create_byte_split_table::<F, 4>();
//     owned_cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

//     let table = create_byte_split_table::<F, 7>();
//     owned_cs.add_lookup_table::<ByteSplitTable<7>, 3>(table);

//     let table = create_byte_split_table::<F, 1>();
//     owned_cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);

//     // let table = create_byte_split_table::<F, 2>();
//     // owned_cs.add_lookup_table::<ByteSplitTable<2>, 3>(table);

//     // let table = create_byte_split_table::<F, 3>();
//     // owned_cs.add_lookup_table::<ByteSplitTable<3>, 3>(table);

//     let mut circuit_input = vec![];

//     let cs = &mut owned_cs;

//     for pair in input.iter() {
//         let pair = UInt32::<F>::allocate_checked(cs, *pair);
//         circuit_input.push(pair);
//     }

//     let pow_nonce = [
//         UInt32::allocate_checked(cs, pow_nonce as u32),
//         UInt32::allocate_checked(cs, (pow_nonce >> 32) as u32),
//     ];

//     // let output = blake2s(cs, &circuit_input);
//     let mut transcript_hasher = Blake2sStateGate::new(cs);
//     let mut seed = Blake2sWrappedTranscript::commit_initial_using_hasher(
//         cs,
//         &mut transcript_hasher,
//         &circuit_input,
//     );
//     Blake2sWrappedTranscript::commit_with_seed_using_hasher(
//         cs,
//         &mut transcript_hasher,
//         &mut seed,
//         &circuit_input,
//     );
//     let mut transcript_challenges = [UInt32::zero(cs);
//         (1usize * 4).next_multiple_of(risc_verifier::blake2s_u32::BLAKE2S_DIGEST_SIZE_U32_WORDS)];
//     Blake2sWrappedTranscript::draw_randomness_using_hasher(
//         cs,
//         &mut transcript_hasher,
//         &mut seed,
//         &mut transcript_challenges,
//     );

//     Blake2sWrappedTranscript::verify_pow_using_hasher::<_, _, POW_BITS>(
//         cs,
//         &mut transcript_hasher,
//         &mut seed,
//         pow_nonce,
//         // POW_BITS as u32,
//     );
//     let output = transcript_challenges; // seed.0.map(|el| UInt32::from_le_bytes(cs, el.inner));

//     let output = output.witness_hook(cs)().unwrap();
//     let reference_output = reference_output.as_slice();
//     assert_eq!(output, reference_output);

//     let _ = cs;
//     let worker = boojum::worker::Worker::new_with_num_threads(4);

//     owned_cs.pad_and_shrink();
//     let mut owned_cs = owned_cs.into_assembly::<Global>();
//     assert!(owned_cs.check_if_satisfied(&worker));
// }

#[test]
fn test_leaf_inclusion() {
    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 80,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 4,
    };

    use boojum::config::DevCSConfig;
    use boojum::cs::cs_builder_reference::*;
    let builder_impl =
        CsReferenceImplementationBuilder::<F, F, DevCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            1 << 20,
        );
    use boojum::cs::cs_builder::new_builder;
    let builder = new_builder::<_, F>(builder_impl);

    let builder = builder.allow_lookup(
        boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions: 20,
            share_table_id: true,
        },
    );
    let builder = ConstantsAllocatorGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    // let builder = ZeroCheckGate::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    //     false,
    // );
    let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = U32TriAddCarryAsChunkGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 4>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 2>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = UIntXAddGate::<16>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = UIntXAddGate::<8>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

    // let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 26));
    let mut owned_cs = builder.build(1 << 26);

    // add tables
    let table = create_range_check_16_bits_table::<3, F>();
    owned_cs.add_lookup_table::<RangeCheck16BitsTable<3>, 3>(table);

    let table = create_range_check_15_bits_table::<3, F>();
    owned_cs.add_lookup_table::<RangeCheck15BitsTable<3>, 3>(table);

    let table = create_xor8_table();
    owned_cs.add_lookup_table::<Xor8Table, 3>(table);

    let table = create_byte_split_table::<F, 4>();
    owned_cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

    let table = create_byte_split_table::<F, 7>();
    owned_cs.add_lookup_table::<ByteSplitTable<7>, 3>(table);

    let table = create_byte_split_table::<F, 1>();
    owned_cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);

    let cs = &mut owned_cs;

    // read proof and set iterator
    let risc_proof = deserialize_from_bin_file(RISC_PROOF_PATH).unwrap();
    let shuffle_ram_inits_and_teardowns_len =
        crate::inner_verifiers::unified_reduced::imports::VERIFIER_COMPILED_LAYOUT
            .memory_layout
            .shuffle_ram_inits_and_teardowns
            .len();
    crate::set_iterator_from_proof(&risc_proof, shuffle_ram_inits_and_teardowns_len);

    let mut leaf_inclusion_verifier = CircuitBlake2sForEverythingVerifier::new(cs);
    let skeleton = unsafe {
        WrappedProofSkeletonInstance::from_non_determinism_source::<_, DefaultNonDeterminismSource>(
            cs,
        )
    };

    let _queries: [_; NUM_QUERIES] = std::array::from_fn(|_idx| unsafe {
        WrappedQueryValuesInstance::from_non_determinism_source::<_, DefaultNonDeterminismSource, _>(
            cs,
            &skeleton,
            &mut leaf_inclusion_verifier,
        )
    });

    let _ = cs;
    let worker = boojum::worker::Worker::new_with_num_threads(4);

    owned_cs.pad_and_shrink();
    let mut owned_cs = owned_cs.into_assembly::<Global>();
    assert!(owned_cs.check_if_satisfied(&worker));
}

#[test]
fn test_buffering_transcript() {
    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 80,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 4,
    };

    use boojum::config::DevCSConfig;
    use boojum::cs::cs_builder_reference::*;
    let builder_impl =
        CsReferenceImplementationBuilder::<F, F, DevCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            1 << 20,
        );
    use boojum::cs::cs_builder::new_builder;
    let builder = new_builder::<_, F>(builder_impl);

    let builder = builder.allow_lookup(
        boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions: 20,
            share_table_id: true,
        },
    );
    let builder = ConstantsAllocatorGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    // let builder = ZeroCheckGate::configure_builder(
    //     builder,
    //     GatePlacementStrategy::UseGeneralPurposeColumns,
    //     false,
    // );
    let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = U32TriAddCarryAsChunkGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 4>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 2>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = UIntXAddGate::<16>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = UIntXAddGate::<8>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

    // let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 25));
    let mut owned_cs = builder.build(1 << 25);

    let table = create_xor8_table();
    owned_cs.add_lookup_table::<Xor8Table, 3>(table);

    let table = create_byte_split_table::<F, 4>();
    owned_cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

    let table = create_byte_split_table::<F, 7>();
    owned_cs.add_lookup_table::<ByteSplitTable<7>, 3>(table);

    let table = create_byte_split_table::<F, 1>();
    owned_cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);

    let cs = &mut owned_cs;

    let witness: Vec<u32> = (1..40).collect();
    let vars = witness
        .iter()
        .map(|x| UInt32::allocate_checked(cs, *x))
        .collect::<Vec<_>>();

    use risc_verifier::prover::transcript::Blake2sBufferingTranscript;

    let mut transcript = Blake2sBufferingTranscript::new();
    let mut transcript_2 = Blake2sBufferingTranscript::new();
    let mut circuit_transcript = Blake2sWrappedBufferingTranscript::new(cs);
    let mut circuit_transcript_2 = Blake2sWrappedBufferingTranscript::new(cs);

    transcript.absorb(&witness);
    for w in witness.iter() {
        transcript_2.absorb(&[*w]);
    }
    dbg!("1");
    circuit_transcript.absorb(cs, &vars);
    dbg!("2");
    for v in vars.iter() {
        dbg!("2.1");
        circuit_transcript_2.absorb(cs, &[*v]);
    }

    let witness_result = transcript.finalize_reset();
    let witness_result_2 = transcript_2.finalize_reset();
    let circuit_result = circuit_transcript.finalize_reset(cs);
    let circuit_result_2 = circuit_transcript_2.finalize_reset(cs);

    for (a, b) in witness_result.0.iter().zip(witness_result_2.0.iter()) {
        assert_eq!(a, b);
    }

    for (a, b) in witness_result.0.iter().zip(circuit_result.0.iter()) {
        assert_eq!(a.to_le_bytes(), b.inner.witness_hook(cs)().unwrap());
    }

    for (a, b) in witness_result.0.iter().zip(circuit_result_2.0.iter()) {
        assert_eq!(a.to_le_bytes(), b.inner.witness_hook(cs)().unwrap());
    }

    let _ = cs;
    let worker = boojum::worker::Worker::new_with_num_threads(4);

    owned_cs.pad_and_shrink();
    let mut owned_cs = owned_cs.into_assembly::<Global>();
    assert!(owned_cs.check_if_satisfied(&worker));
}

#[test]
fn test_decompose() {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let input: u32 = rng.r#gen();

    let reference_output = input;

    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 20,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 4,
    };

    use boojum::config::DevCSConfig;
    use boojum::cs::cs_builder_reference::*;
    let builder_impl =
        CsReferenceImplementationBuilder::<F, F, DevCSConfig, StCircuitResolver<_, _>>::new(
            geometry,
            1 << 17,
        );
    use boojum::cs::cs_builder::new_builder;
    let builder = new_builder::<_, F>(builder_impl);

    let builder = builder.allow_lookup(
        boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions: 5,
            share_table_id: true,
        },
    );
    let builder = ConstantsAllocatorGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = U32TriAddCarryAsChunkGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = ReductionGate::<F, 4>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

    // let mut owned_cs = builder.build(CircuitResolverOpts::new(1 << 20));
    let mut owned_cs = builder.build(1 << 20);

    // add tables
    let table = create_xor8_table();
    owned_cs.add_lookup_table::<Xor8Table, 3>(table);

    let cs = &mut owned_cs;

    let circuit_input = UInt32::<F>::allocate_checked(cs, input);

    let output = circuit_input.to_le_bytes(cs);
    let output = UInt32::from_le_bytes(cs, output);

    let output = output.witness_hook(cs)().unwrap();
    let reference_output = reference_output; //.as_slice();
    assert_eq!(output, reference_output);

    let _ = cs;
    let worker = boojum::worker::Worker::new_with_num_threads(4);

    owned_cs.pad_and_shrink();
    let mut owned_cs = owned_cs.into_assembly::<Global>();
    assert!(owned_cs.check_if_satisfied(&worker));
}
