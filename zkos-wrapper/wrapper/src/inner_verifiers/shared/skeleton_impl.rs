pub(crate) type WrappedProofSkeletonInstance<F> = WrappedProofSkeleton<
    F,
    TREE_CAP_SIZE,
    NUM_COSETS,
    NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS,
    NUM_DELEGATION_CHALLENGES,
    NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
    NUM_AUX_BOUNDARY_VALUES,
    NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS,
    NUM_OPENINGS_AT_Z,
    NUM_OPENINGS_AT_Z_OMEGA,
    NUM_FRI_STEPS,
    NUM_FRI_STEPS_WITH_ORACLES,
    LAST_FRI_STEP_LEAFS_TOTAL_SIZE_PER_COSET,
    FRI_FINAL_DEGREE,
>;

pub struct WrappedProofSkeleton<
    F: SmallField,
    const CAP_SIZE: usize,
    const NUM_COSETS: usize,
    const NUM_PUBLIC_INPUTS: usize,
    const NUM_DELEGATION_CHALLENGES: usize,
    const NUM_MACHINE_STATE_PERMUTATION_CHALLENGES: usize,
    const NUM_AUX_BOUNDARY_VALUES: usize,
    const NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS: usize,
    const NUM_OPENINGS_AT_Z: usize,
    const NUM_OPENINGS_AT_Z_OMEGA: usize,
    const NUM_FRI_STEPS: usize,
    const NUM_FRI_STEPS_WITH_ORACLES: usize,
    const FINAL_FRI_STEP_LEAF_SIZE_PER_COSET: usize,
    const FRI_FINAL_DEGREE: usize,
> {
    pub(crate) circuit_sequence_idx: UInt32<F>,
    pub(crate) delegation_type: UInt32<F>,
    pub(crate) public_inputs: [MersenneField<F>; NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS],
    pub(crate) setup_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub(crate) memory_argument_challenges: WrappedExternalMemoryArgumentChallenges<F>,
    pub(crate) delegation_argument_challenges:
        [WrappedExternalDelegationArgumentChallenges<F>; NUM_DELEGATION_CHALLENGES],
    pub(crate) machine_state_permutation_challenges:
        [WrappedExternalMachineStateArgumentChallenges<F>; NUM_MACHINE_STATE_PERMUTATION_CHALLENGES],
    pub(crate) aux_boundary_values: [WrappedAuxArgumentsBoundaryValues<F>; NUM_AUX_BOUNDARY_VALUES],
    pub(crate) witness_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub(crate) memory_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub(crate) stage_2_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub(crate) grand_product_accumulator: MersenneQuartic<F>,
    pub(crate) delegation_argument_accumulator: [MersenneQuartic<F>; NUM_DELEGATION_CHALLENGES],
    pub(crate) quotient_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub(crate) openings_at_z: [MersenneQuartic<F>; NUM_OPENINGS_AT_Z],
    pub(crate) openings_at_z_omega: [MersenneQuartic<F>; NUM_OPENINGS_AT_Z_OMEGA],
    pub(crate) fri_intermediate_oracles:
        [[WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS]; NUM_FRI_STEPS_WITH_ORACLES],
    pub(crate) fri_final_step_leafs:
        [[MersenneQuartic<F>; FINAL_FRI_STEP_LEAF_SIZE_PER_COSET]; NUM_COSETS],
    pub(crate) monomial_coeffs: [MersenneQuartic<F>; FRI_FINAL_DEGREE],
    pub(crate) pow_challenges: WrappedSizedProofPowChallenges<F, NUM_FRI_STEPS>,
}

impl<
    F: SmallField,
    const CAP_SIZE: usize,
    const NUM_COSETS: usize,
    const NUM_PUBLIC_INPUTS: usize,
    const NUM_DELEGATION_CHALLENGES: usize,
    const NUM_MACHINE_STATE_PERMUTATION_CHALLENGES: usize,
    const NUM_AUX_BOUNDARY_VALUES: usize,
    const NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS: usize,
    const NUM_OPENINGS_AT_Z: usize,
    const NUM_OPENINGS_AT_Z_OMEGA: usize,
    const NUM_FRI_STEPS: usize,
    const NUM_FRI_STEPS_WITH_ORACLES: usize,
    const FINAL_FRI_STEP_LEAF_SIZE_PER_COSET: usize,
    const FRI_FINAL_DEGREE: usize,
> CSAllocatable<F>
    for WrappedProofSkeleton<
        F,
        CAP_SIZE,
        NUM_COSETS,
        NUM_PUBLIC_INPUTS,
        NUM_DELEGATION_CHALLENGES,
        NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS,
        NUM_OPENINGS_AT_Z,
        NUM_OPENINGS_AT_Z_OMEGA,
        NUM_FRI_STEPS,
        NUM_FRI_STEPS_WITH_ORACLES,
        FINAL_FRI_STEP_LEAF_SIZE_PER_COSET,
        FRI_FINAL_DEGREE,
    >
{
    type Witness = ProofSkeleton<
        SKELETON_PADDING,
        CAP_SIZE,
        NUM_COSETS,
        NUM_PUBLIC_INPUTS,
        NUM_DELEGATION_CHALLENGES,
        NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS,
        NUM_OPENINGS_AT_Z,
        NUM_OPENINGS_AT_Z_OMEGA,
        NUM_FRI_STEPS,
        NUM_FRI_STEPS_WITH_ORACLES,
        FINAL_FRI_STEP_LEAF_SIZE_PER_COSET,
        FRI_FINAL_DEGREE,
    >;

    fn placeholder_witness() -> Self::Witness {
        ProofSkeleton {
            _padding: [MaybeUninit::<u32>::uninit(); SKELETON_PADDING],
            circuit_sequence_idx: UInt32::<F>::placeholder_witness(),
            delegation_type: UInt32::<F>::placeholder_witness(),
            public_inputs: [MersenneField::<F>::placeholder_witness();
                NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS],
            setup_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            memory_argument_challenges:
                WrappedExternalMemoryArgumentChallenges::<F>::placeholder_witness(),
            delegation_argument_challenges:
                [WrappedExternalDelegationArgumentChallenges::<F>::placeholder_witness();
                    NUM_DELEGATION_CHALLENGES],
            machine_state_permutation_challenges:
                [WrappedExternalMachineStateArgumentChallenges::<F>::placeholder_witness();
                    NUM_MACHINE_STATE_PERMUTATION_CHALLENGES],
            aux_boundary_values: [WrappedAuxArgumentsBoundaryValues::<F>::placeholder_witness();
                NUM_AUX_BOUNDARY_VALUES],
            witness_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            memory_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            stage_2_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            grand_product_accumulator: MersenneQuartic::<F>::placeholder_witness(),
            delegation_argument_accumulator: [MersenneQuartic::<F>::placeholder_witness();
                NUM_DELEGATION_CHALLENGES],
            quotient_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            openings_at_z: [MersenneQuartic::<F>::placeholder_witness(); NUM_OPENINGS_AT_Z],
            openings_at_z_omega: [MersenneQuartic::<F>::placeholder_witness();
                NUM_OPENINGS_AT_Z_OMEGA],
            fri_intermediate_oracles: [[WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness();
                NUM_COSETS]; NUM_FRI_STEPS_WITH_ORACLES],
            fri_final_step_leafs: [[MersenneQuartic::<F>::placeholder_witness();
                FINAL_FRI_STEP_LEAF_SIZE_PER_COSET]; NUM_COSETS],
            monomial_coeffs: [MersenneQuartic::<F>::placeholder_witness(); FRI_FINAL_DEGREE],
            pow_challenges: WrappedSizedProofPowChallenges::<F, NUM_FRI_STEPS>::placeholder_witness(),
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            circuit_sequence_idx: UInt32::allocate_without_value(cs),
            delegation_type: UInt32::allocate_without_value(cs),
            public_inputs: [(); NUM_PUBLIC_INPUTS_FROM_STATE_ELEMENTS]
                .map(|_| MersenneField::allocate_without_value(cs)),
            setup_caps: [(); NUM_COSETS].map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            memory_argument_challenges:
                WrappedExternalMemoryArgumentChallenges::allocate_without_value(cs),
            delegation_argument_challenges: [(); NUM_DELEGATION_CHALLENGES]
                .map(|_| WrappedExternalDelegationArgumentChallenges::allocate_without_value(cs)),
            machine_state_permutation_challenges: [(); NUM_MACHINE_STATE_PERMUTATION_CHALLENGES]
                .map(|_| WrappedExternalMachineStateArgumentChallenges::allocate_without_value(cs)),
            aux_boundary_values: [(); NUM_AUX_BOUNDARY_VALUES]
                .map(|_| WrappedAuxArgumentsBoundaryValues::allocate_without_value(cs)),
            witness_caps: [(); NUM_COSETS]
                .map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            memory_caps: [(); NUM_COSETS].map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            stage_2_caps: [(); NUM_COSETS]
                .map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            grand_product_accumulator: MersenneQuartic::allocate_without_value(cs),
            delegation_argument_accumulator: [(); NUM_DELEGATION_CHALLENGES]
                .map(|_| MersenneQuartic::allocate_without_value(cs)),
            quotient_caps: [(); NUM_COSETS]
                .map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            openings_at_z: [(); NUM_OPENINGS_AT_Z]
                .map(|_| MersenneQuartic::allocate_without_value(cs)),
            openings_at_z_omega: [(); NUM_OPENINGS_AT_Z_OMEGA]
                .map(|_| MersenneQuartic::allocate_without_value(cs)),
            fri_intermediate_oracles: [[(); NUM_COSETS]; NUM_FRI_STEPS_WITH_ORACLES]
                .map(|x| x.map(|_| WrappedMerkleTreeCap::allocate_without_value(cs))),
            fri_final_step_leafs: [[(); FINAL_FRI_STEP_LEAF_SIZE_PER_COSET]; NUM_COSETS]
                .map(|x| x.map(|_| MersenneQuartic::allocate_without_value(cs))),
            monomial_coeffs: [(); FRI_FINAL_DEGREE]
                .map(|_| MersenneQuartic::allocate_without_value(cs)),
            pow_challenges: WrappedSizedProofPowChallenges::allocate_without_value(cs),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            circuit_sequence_idx: UInt32::allocate(cs, witness.circuit_sequence_idx),
            delegation_type: UInt32::allocate(cs, witness.delegation_type),
            public_inputs: witness
                .public_inputs
                .map(|x| MersenneField::allocate(cs, x)),
            setup_caps: witness
                .setup_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            memory_argument_challenges: WrappedExternalMemoryArgumentChallenges::allocate(
                cs,
                witness.memory_argument_challenges,
            ),
            delegation_argument_challenges: witness
                .delegation_argument_challenges
                .map(|x| WrappedExternalDelegationArgumentChallenges::allocate(cs, x)),
            machine_state_permutation_challenges: witness
                .machine_state_permutation_challenges
                .map(|x| WrappedExternalMachineStateArgumentChallenges::allocate(cs, x)),
            aux_boundary_values: witness
                .aux_boundary_values
                .map(|x| WrappedAuxArgumentsBoundaryValues::allocate(cs, x)),
            witness_caps: witness
                .witness_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            memory_caps: witness
                .memory_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            stage_2_caps: witness
                .stage_2_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            grand_product_accumulator: MersenneQuartic::allocate(
                cs,
                witness.grand_product_accumulator,
            ),
            delegation_argument_accumulator: witness
                .delegation_argument_accumulator
                .map(|x| MersenneQuartic::allocate(cs, x)),
            quotient_caps: witness
                .quotient_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            openings_at_z: witness
                .openings_at_z
                .map(|x| MersenneQuartic::allocate(cs, x)),
            openings_at_z_omega: witness
                .openings_at_z_omega
                .map(|x| MersenneQuartic::allocate(cs, x)),
            fri_intermediate_oracles: witness
                .fri_intermediate_oracles
                .map(|x| x.map(|y| WrappedMerkleTreeCap::allocate(cs, y))),
            fri_final_step_leafs: witness
                .fri_final_step_leafs
                .map(|x| x.map(|y| MersenneQuartic::allocate(cs, y))),
            monomial_coeffs: witness
                .monomial_coeffs
                .map(|x| MersenneQuartic::allocate(cs, x)),
            pow_challenges: WrappedSizedProofPowChallenges::allocate(cs, witness.pow_challenges),
        }
    }
}

impl<F: SmallField> WrappedProofSkeletonInstance<F> {
    pub(crate) unsafe fn from_non_determinism_source<
        CS: ConstraintSystem<F>,
        I: NonDeterminismSource,
    >(
        cs: &mut CS,
    ) -> Self {
        let witness = unsafe {
            let mut skeleton = MaybeUninit::<AirbenderProofSkeletonInstance>::uninit();
            <AirbenderProofSkeletonInstance as ProofSkeletonInstanceExt<ActiveSecurity>>::fill::<I>(
                skeleton.as_mut_ptr(),
            );
            skeleton.assume_init()
        };

        Self::allocate(cs, witness)
    }

    pub(crate) fn transcript_elements_before_stage2<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = vec![];

        result.push(self.circuit_sequence_idx.clone());
        result.push(self.delegation_type.clone());
        result.extend_from_slice(&self.public_inputs.map(|x| x.into_uint32(cs)));
        for cap in &self.setup_caps {
            result.extend_from_slice(&cap.to_slice());
        }
        result.extend_from_slice(&self.memory_argument_challenges.to_uint32_vec(cs));
        for challenge in &self.delegation_argument_challenges {
            result.extend_from_slice(&challenge.to_uint32_vec(cs));
        }
        for challenge in &self.machine_state_permutation_challenges {
            result.extend_from_slice(&challenge.to_uint32_vec(cs));
        }
        for boundary_values in &self.aux_boundary_values {
            result.extend_from_slice(&boundary_values.to_uint32_vec(cs));
        }
        for cap in &self.witness_caps {
            result.extend_from_slice(&cap.to_slice());
        }
        for cap in &self.memory_caps {
            result.extend_from_slice(&cap.to_slice());
        }

        result
    }

    pub fn transcript_elements_stage2_to_stage3<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = vec![];
        for cap in &self.stage_2_caps {
            result.extend_from_slice(&cap.to_slice());
        }
        result.extend_from_slice(&self.grand_product_accumulator.into_uint32s(cs));
        for acc in &self.delegation_argument_accumulator {
            result.extend_from_slice(&acc.into_uint32s(cs));
        }

        result
    }

    pub fn transcript_elements_stage3_to_stage4(&self) -> Vec<UInt32<F>> {
        let mut result = vec![];

        for cap in &self.quotient_caps {
            result.extend_from_slice(&cap.to_slice());
        }

        result
    }

    pub fn transcript_elements_evaluations_at_z<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = vec![];

        for opening in &self.openings_at_z {
            result.extend_from_slice(&opening.into_uint32s(cs));
        }
        for opening in &self.openings_at_z_omega {
            result.extend_from_slice(&opening.into_uint32s(cs));
        }

        result
    }

    pub fn transcript_elements_fri_intermediate_oracles(
        &self,
    ) -> [Vec<UInt32<F>>; NUM_FRI_STEPS_WITH_ORACLES] {
        self.fri_intermediate_oracles
            .each_ref()
            .map(|current_step| {
                let mut result = vec![];
                for coset in current_step {
                    result.extend_from_slice(&coset.to_slice());
                }
                result
            })
    }

    pub fn transcript_elements_last_fri_step_leaf_values<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = vec![];

        for coset in &self.fri_final_step_leafs {
            for leaf in coset {
                result.extend_from_slice(&leaf.into_uint32s(cs));
            }
        }

        result
    }

    pub fn transcript_elements_monomial_coefficients<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = vec![];

        for coeff in &self.monomial_coeffs {
            result.extend_from_slice(&coeff.into_uint32s(cs));
        }

        result
    }
}

pub struct WrappedSizedProofPowChallenges<
    F: SmallField,
    const NUM_FOLDINGS: usize
> {
    pub lookup_pow_challenge: [UInt32<F>; 2],
    pub quotient_alpha_pow_challenge: [UInt32<F>; 2],
    pub quotient_z_pow_challenge: [UInt32<F>; 2],
    pub deep_poly_alpha_pow_challenge: [UInt32<F>; 2],
    pub foldings_pow_challenges: [[UInt32<F>; 2]; NUM_FOLDINGS],
    pub fri_queries_pow_challenge: [UInt32<F>; 2],
}

impl<F: SmallField, const NUM_FOLDINGS: usize> CSAllocatable<F>
    for WrappedSizedProofPowChallenges<F, NUM_FOLDINGS> {
    type Witness = SizedProofPowChallenges<NUM_FOLDINGS>;

    fn placeholder_witness() -> Self::Witness {
        SizedProofPowChallenges {
            lookup_pow_challenge: 0u64,
            quotient_alpha_pow_challenge: 0u64,
            quotient_z_pow_challenge: 0u64,
            deep_poly_alpha_pow_challenge: 0u64,
            foldings_pow_challenges: [0u64; NUM_FOLDINGS],
            fri_queries_pow_challenge: 0u64,
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            lookup_pow_challenge: [
                UInt32::allocate_without_value(cs),
                UInt32::allocate_without_value(cs),
            ],
            quotient_alpha_pow_challenge: [
                UInt32::allocate_without_value(cs),
                UInt32::allocate_without_value(cs),
            ],
            quotient_z_pow_challenge: [
                UInt32::allocate_without_value(cs),
                UInt32::allocate_without_value(cs),
            ],
            deep_poly_alpha_pow_challenge: [
                UInt32::allocate_without_value(cs),
                UInt32::allocate_without_value(cs),
            ],
            foldings_pow_challenges: [(); NUM_FOLDINGS].map(|_| [
                UInt32::allocate_without_value(cs),
                UInt32::allocate_without_value(cs),
            ]),
            fri_queries_pow_challenge: [
                UInt32::allocate_without_value(cs),
                UInt32::allocate_without_value(cs),
            ],
        }
    }

    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            lookup_pow_challenge: [
                UInt32::allocate(cs, (witness.lookup_pow_challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (witness.lookup_pow_challenge >> 32) as u32),
            ],
            quotient_alpha_pow_challenge: [
                UInt32::allocate(cs, (witness.quotient_alpha_pow_challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (witness.quotient_alpha_pow_challenge >> 32) as u32),
            ],
            quotient_z_pow_challenge: [
                UInt32::allocate(cs, (witness.quotient_z_pow_challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (witness.quotient_z_pow_challenge >> 32) as u32),
            ],
            deep_poly_alpha_pow_challenge: [
                UInt32::allocate(cs, (witness.deep_poly_alpha_pow_challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (witness.deep_poly_alpha_pow_challenge >> 32) as u32),
            ],
            foldings_pow_challenges: witness.foldings_pow_challenges.map(|challenge| [
                UInt32::allocate(cs, (challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (challenge >> 32) as u32),
            ]),
            fri_queries_pow_challenge: [
                UInt32::allocate(cs, (witness.fri_queries_pow_challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (witness.fri_queries_pow_challenge >> 32) as u32),
            ],
        }
    }
}

pub(crate) type WrappedQueryValuesInstance<F> = WrappedQueryValues<
    F,
    BITS_FOR_QUERY_INDEX,
    DEFAULT_MERKLE_PATH_LENGTH,
    TOTAL_FRI_ORACLES_PATHS_LENGTH,
    LEAF_SIZE_SETUP,
    LEAF_SIZE_WITNESS_TREE,
    LEAF_SIZE_MEMORY_TREE,
    LEAF_SIZE_STAGE_2,
    LEAF_SIZE_QUOTIENT,
    TOTAL_FRI_LEAFS_SIZES,
    NUM_FRI_STEPS,
>;

pub(crate) struct WrappedQueryValues<
    F: SmallField,
    const BITS_FOR_QUERY_INDEX: usize,
    const DEFAULT_MERKLE_PATH_LENGTH: usize,
    const TOTAL_FRI_ORACLES_PATHS_LENGTH: usize,
    const LEAF_SIZE_SETUP: usize,
    const LEAF_SIZE_WITNESS_TREE: usize,
    const LEAF_SIZE_MEMORY_TREE: usize,
    const LEAF_SIZE_STAGE_2: usize,
    const LEAF_SIZE_QUOTIENT: usize,
    const TOTAL_FRI_LEAFS_SIZES: usize,
    const NUM_FRI_STEPS: usize, // we will still bind it here
> {
    pub(crate) query_index: UInt32<F>,
    pub(crate) setup_leaf: [MersenneField<F>; LEAF_SIZE_SETUP],
    pub(crate) witness_leaf: [MersenneField<F>; LEAF_SIZE_WITNESS_TREE],
    pub(crate) memory_leaf: [MersenneField<F>; LEAF_SIZE_MEMORY_TREE],
    pub(crate) stage_2_leaf: [MersenneField<F>; LEAF_SIZE_STAGE_2],
    pub(crate) quotient_leaf: [MersenneField<F>; LEAF_SIZE_QUOTIENT],
    pub(crate) fri_oracles_leafs: [MersenneField<F>; TOTAL_FRI_LEAFS_SIZES],
}

impl<
    F: SmallField,
    const BITS_FOR_QUERY_INDEX: usize,
    const DEFAULT_MERKLE_PATH_LENGTH: usize,
    const TOTAL_FRI_ORACLES_PATHS_LENGTH: usize,
    const LEAF_SIZE_SETUP: usize,
    const LEAF_SIZE_WITNESS_TREE: usize,
    const LEAF_SIZE_MEMORY_TREE: usize,
    const LEAF_SIZE_STAGE_2: usize,
    const LEAF_SIZE_QUOTIENT: usize,
    const TOTAL_FRI_LEAFS_SIZES: usize,
    const NUM_FRI_STEPS: usize,
> CSAllocatable<F>
    for WrappedQueryValues<
        F,
        BITS_FOR_QUERY_INDEX,
        DEFAULT_MERKLE_PATH_LENGTH,
        TOTAL_FRI_ORACLES_PATHS_LENGTH,
        LEAF_SIZE_SETUP,
        LEAF_SIZE_WITNESS_TREE,
        LEAF_SIZE_MEMORY_TREE,
        LEAF_SIZE_STAGE_2,
        LEAF_SIZE_QUOTIENT,
        TOTAL_FRI_LEAFS_SIZES,
        NUM_FRI_STEPS,
    >
{
    type Witness = QueryValues<
        BITS_FOR_QUERY_INDEX,
        DEFAULT_MERKLE_PATH_LENGTH,
        TOTAL_FRI_ORACLES_PATHS_LENGTH,
        LEAF_SIZE_SETUP,
        LEAF_SIZE_WITNESS_TREE,
        LEAF_SIZE_MEMORY_TREE,
        LEAF_SIZE_STAGE_2,
        LEAF_SIZE_QUOTIENT,
        TOTAL_FRI_LEAFS_SIZES,
        NUM_FRI_STEPS,
    >;

    fn placeholder_witness() -> Self::Witness {
        QueryValues {
            query_index: UInt32::<F>::placeholder_witness(),
            setup_leaf: AlignedArray64::from_value(MersenneField::<F>::placeholder_witness()),
            witness_leaf: AlignedArray64::from_value(MersenneField::<F>::placeholder_witness()),
            memory_leaf: AlignedArray64::from_value(MersenneField::<F>::placeholder_witness()),
            stage_2_leaf: AlignedArray64::from_value(MersenneField::<F>::placeholder_witness()),
            quotient_leaf: AlignedArray64::from_value(MersenneField::<F>::placeholder_witness()),
            fri_oracles_leafs: AlignedArray64::from_value(MersenneField::<F>::placeholder_witness()),
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            query_index: UInt32::allocate_without_value(cs),
            setup_leaf: [(); LEAF_SIZE_SETUP].map(|_| MersenneField::allocate_without_value(cs)),
            witness_leaf: [(); LEAF_SIZE_WITNESS_TREE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            memory_leaf: [(); LEAF_SIZE_MEMORY_TREE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            stage_2_leaf: [(); LEAF_SIZE_STAGE_2]
                .map(|_| MersenneField::allocate_without_value(cs)),
            quotient_leaf: [(); LEAF_SIZE_QUOTIENT]
                .map(|_| MersenneField::allocate_without_value(cs)),
            fri_oracles_leafs: [(); TOTAL_FRI_LEAFS_SIZES]
                .map(|_| MersenneField::allocate_without_value(cs)),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            query_index: UInt32::allocate(cs, witness.query_index),
            setup_leaf: witness.setup_leaf.map(|x| MersenneField::allocate(cs, x)),
            witness_leaf: witness.witness_leaf.map(|x| MersenneField::allocate(cs, x)),
            memory_leaf: witness.memory_leaf.map(|x| MersenneField::allocate(cs, x)),
            stage_2_leaf: witness.stage_2_leaf.map(|x| MersenneField::allocate(cs, x)),
            quotient_leaf: witness
                .quotient_leaf
                .map(|x| MersenneField::allocate(cs, x)),
            fri_oracles_leafs: witness
                .fri_oracles_leafs
                .map(|x| MersenneField::allocate(cs, x)),
        }
    }
}

impl<F: SmallField> WrappedQueryValuesInstance<F> {
    pub unsafe fn from_non_determinism_source<
        CS: ConstraintSystem<F>,
        I: NonDeterminismSource,
        V: CircuitLeafInclusionVerifier<F>,
    >(
        cs: &mut CS,
        proof_skeleton: &WrappedProofSkeletonInstance<F>,
        hasher: &mut V,
    ) -> Self {
        let mut source = MaybeUninit::<AirbenderQueryValuesInstance>::uninit();
        let dst = source.as_mut_ptr().cast::<u32>();
        let modulus = Mersenne31Field::CHARACTERISTICS as u32;
        // query index
        let query_index = I::read_word();
        assert!(
            query_index < (1u32 << BITS_FOR_QUERY_INDEX),
            "query index 0x{:08x} must be smaller than 0x{:08x}",
            query_index,
            1u32 << BITS_FOR_QUERY_INDEX
        );
        unsafe { dst.write(query_index) };

        let query_value_offsets = <AirbenderQueryValuesInstance as QueryValuesInstanceExt<
            ActiveSecurity,
        >>::BASE_CIRCUIT_QUERY_VALUES_OFFSETS;
        let mut i = 0;
        // leaf values are field elements
        while i < NUM_QUERY_VALUES {
            dst.add(query_value_offsets[i])
                .write(I::read_reduced_field_element(modulus));
            i += 1;
        }
        let source = unsafe { source.assume_init() };
        let query = Self::allocate(cs, source.clone());

        // for all except FRI the following is valid
        let tree_index = UInt32::allocate_checked(cs, source.query_index & TREE_INDEX_MASK);
        let coset_index = UInt32::allocate_checked(cs, source.query_index >> TRACE_LEN_LOG2);

        let chunks = [
            (tree_index.get_variable(), F::ONE),
            (
                coset_index.get_variable(),
                F::from_u64(1 << TRACE_LEN_LOG2).unwrap(),
            ),
        ];
        use boojum::gadgets::impls::lc::linear_combination_collapse;
        linear_combination_collapse(
            cs,
            &mut chunks.into_iter(),
            Some(query.query_index.get_variable()),
        );

        let coset_index = coset_index
            .into_num()
            .spread_into_bits::<CS, FRI_FACTOR_LOG2>(cs);
        let mut tree_index = tree_index
            .into_num()
            .spread_into_bits::<CS, TRACE_LEN_LOG2>(cs);

        // and now we should optimistically verify each leaf over the corresponding merkle cap
        hasher.verify_leaf_inclusion::<CS, I, TREE_CAP_SIZE, NUM_COSETS>(
            cs,
            &coset_index,
            &tree_index,
            DEFAULT_MERKLE_PATH_LENGTH,
            &query.setup_leaf,
            &proof_skeleton.setup_caps,
        );

        hasher.verify_leaf_inclusion::<CS, I, TREE_CAP_SIZE, NUM_COSETS>(
            cs,
            &coset_index,
            &tree_index,
            DEFAULT_MERKLE_PATH_LENGTH,
            &query.witness_leaf,
            &proof_skeleton.witness_caps,
        );

        hasher.verify_leaf_inclusion::<CS, I, TREE_CAP_SIZE, NUM_COSETS>(
            cs,
            &coset_index,
            &tree_index,
            DEFAULT_MERKLE_PATH_LENGTH,
            &query.memory_leaf,
            &proof_skeleton.memory_caps,
        );

        hasher.verify_leaf_inclusion::<CS, I, TREE_CAP_SIZE, NUM_COSETS>(
            cs,
            &coset_index,
            &tree_index,
            DEFAULT_MERKLE_PATH_LENGTH,
            &query.stage_2_leaf,
            &proof_skeleton.stage_2_caps,
        );

        hasher.verify_leaf_inclusion::<CS, I, TREE_CAP_SIZE, NUM_COSETS>(
            cs,
            &coset_index,
            &tree_index,
            DEFAULT_MERKLE_PATH_LENGTH,
            &query.quotient_leaf,
            &proof_skeleton.quotient_caps,
        );

        let mut fri_tree_index = &mut tree_index[..];
        let mut fri_path_length = DEFAULT_MERKLE_PATH_LENGTH;
        let mut fri_leaf_start = query.fri_oracles_leafs.as_ptr();
        for fri_step in 0..NUM_FRI_STEPS_WITH_ORACLES {
            let caps = &proof_skeleton.fri_intermediate_oracles[fri_step];
            fri_tree_index = &mut fri_tree_index[FRI_FOLDING_SCHEDULE[fri_step]..];
            fri_path_length -= FRI_FOLDING_SCHEDULE[fri_step];
            let leaf_size = 4 * (1 << FRI_FOLDING_SCHEDULE[fri_step]);
            let fri_leaf_slice = unsafe { core::slice::from_raw_parts(fri_leaf_start, leaf_size) };
            hasher.verify_leaf_inclusion::<CS, I, TREE_CAP_SIZE, NUM_COSETS>(
                cs,
                &coset_index,
                &fri_tree_index,
                fri_path_length,
                fri_leaf_slice,
                caps,
            );
            fri_leaf_start = unsafe { fri_leaf_start.add(leaf_size) };
        }

        query
    }
}
