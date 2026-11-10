use super::*;

pub struct WrappedProofPublicInputs<F: SmallField, const NUM_STATE_ELEMENTS: usize> {
    pub input_state_variables: [MersenneField<F>; NUM_STATE_ELEMENTS],
    pub output_state_variables: [MersenneField<F>; NUM_STATE_ELEMENTS],
}

impl<F: SmallField, const NUM_STATE_ELEMENTS: usize> CSAllocatable<F>
    for WrappedProofPublicInputs<F, NUM_STATE_ELEMENTS>
{
    type Witness = ProofPublicInputs<NUM_STATE_ELEMENTS>;

    fn placeholder_witness() -> Self::Witness {
        ProofPublicInputs {
            input_state_variables: [Mersenne31Field::ZERO; NUM_STATE_ELEMENTS],
            output_state_variables: [Mersenne31Field::ZERO; NUM_STATE_ELEMENTS],
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            input_state_variables: [(); NUM_STATE_ELEMENTS]
                .map(|_| MersenneField::allocate_without_value(cs)),
            output_state_variables: [(); NUM_STATE_ELEMENTS]
                .map(|_| MersenneField::allocate_without_value(cs)),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            input_state_variables: witness
                .input_state_variables
                .map(|x| MersenneField::allocate(cs, x)),
            output_state_variables: witness
                .output_state_variables
                .map(|x| MersenneField::allocate(cs, x)),
        }
    }
}

pub struct WrappedMerkleTreeCap<F: SmallField, const N: usize> {
    pub cap: [[UInt32<F>; DIGEST_SIZE_U32_WORDS]; N],
}

impl<F: SmallField, const N: usize> WrappedMerkleTreeCap<F, N> {
    pub(crate) fn to_slice(&self) -> &[UInt32<F>] {
        let (head, middle, tail) = unsafe { self.cap.align_to::<UInt32<F>>() };
        assert!(head.is_empty() && tail.is_empty());
        middle
    }

    pub(crate) fn enforce_equal<CS: ConstraintSystem<F>>(&self, cs: &mut CS, other: &Self) {
        for i in 0..N {
            for j in 0..DIGEST_SIZE_U32_WORDS {
                Num::enforce_equal(cs, &self.cap[i][j].into_num(), &other.cap[i][j].into_num());
            }
        }
    }
}

impl<F: SmallField, const N: usize> CSAllocatable<F> for WrappedMerkleTreeCap<F, N> {
    type Witness = MerkleTreeCap<N>;

    fn placeholder_witness() -> Self::Witness {
        MerkleTreeCap {
            cap: [[0u32; DIGEST_SIZE_U32_WORDS]; N],
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let mut cap = [[UInt32::zero(cs); DIGEST_SIZE_U32_WORDS]; N];
        for i in 0..N {
            for j in 0..DIGEST_SIZE_U32_WORDS {
                cap[i][j] = UInt32::allocate_without_value(cs);
            }
        }

        Self { cap }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        let cap = witness.cap.map(|row| row.map(|x| UInt32::allocate(cs, x)));
        Self { cap }
    }
    fn allocate_constant<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        let cap = witness
            .cap
            .map(|row| row.map(|x| UInt32::allocate_constant(cs, x)));
        Self { cap }
    }
}

pub struct WrappedExternalMemoryArgumentChallenges<F: SmallField> {
    pub memory_argument_linearization_challenges:
        [MersenneQuartic<F>; NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES],
    pub memory_argument_gamma: MersenneQuartic<F>,
}

impl<F: SmallField> WrappedExternalMemoryArgumentChallenges<F> {
    pub(crate) fn to_uint32_vec<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = Vec::with_capacity(NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES * 4 + 4);
        for i in 0..NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES {
            result.extend_from_slice(
                &self.memory_argument_linearization_challenges[i].into_uint32s(cs),
            );
        }
        result.extend_from_slice(&self.memory_argument_gamma.into_uint32s(cs));
        result
    }

    pub(crate) fn enforce_equal<CS: ConstraintSystem<F>>(&self, cs: &mut CS, other: &Self) {
        for i in 0..NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES {
            self.memory_argument_linearization_challenges[i]
                .enforce_equal(cs, &other.memory_argument_linearization_challenges[i]);
        }
        self.memory_argument_gamma
            .enforce_equal(cs, &other.memory_argument_gamma)
    }
}

impl<F: SmallField> CSAllocatable<F> for WrappedExternalMemoryArgumentChallenges<F> {
    type Witness = ExternalMemoryArgumentChallenges;

    fn placeholder_witness() -> Self::Witness {
        ExternalMemoryArgumentChallenges {
            memory_argument_linearization_challenges: [Mersenne31Quartic::ZERO;
                NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES],
            memory_argument_gamma: Mersenne31Quartic::ZERO,
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let memory_argument_linearization_challenges = [();
            NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES]
            .map(|_| MersenneQuartic::allocate_without_value(cs));

        Self {
            memory_argument_linearization_challenges,
            memory_argument_gamma: MersenneQuartic::allocate_without_value(cs),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        let memory_argument_linearization_challenges = witness
            .memory_argument_linearization_challenges
            .map(|x| MersenneQuartic::allocate(cs, x));
        let memory_argument_gamma = MersenneQuartic::allocate(cs, witness.memory_argument_gamma);
        Self {
            memory_argument_linearization_challenges,
            memory_argument_gamma,
        }
    }
}

#[derive(Clone, Copy)]
pub struct WrappedExternalDelegationArgumentChallenges<F: SmallField> {
    pub delegation_argument_linearization_challenges:
        [MersenneQuartic<F>; NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES],
    pub delegation_argument_gamma: MersenneQuartic<F>,
}

impl<F: SmallField> WrappedExternalDelegationArgumentChallenges<F> {
    pub(crate) fn to_uint32_vec<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result =
            Vec::with_capacity(NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES * 4 + 4);
        for i in 0..NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES {
            result.extend_from_slice(
                &self.delegation_argument_linearization_challenges[i].into_uint32s(cs),
            );
        }
        result.extend_from_slice(&self.delegation_argument_gamma.into_uint32s(cs));
        result
    }

    pub(crate) fn enforce_equal<CS: ConstraintSystem<F>>(&self, cs: &mut CS, other: &Self) {
        for i in 0..NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES {
            self.delegation_argument_linearization_challenges[i]
                .enforce_equal(cs, &other.delegation_argument_linearization_challenges[i]);
        }
        self.delegation_argument_gamma
            .enforce_equal(cs, &other.delegation_argument_gamma)
    }
}

impl<F: SmallField> CSAllocatable<F> for WrappedExternalDelegationArgumentChallenges<F> {
    type Witness = ExternalDelegationArgumentChallenges;

    fn placeholder_witness() -> Self::Witness {
        ExternalDelegationArgumentChallenges {
            delegation_argument_linearization_challenges: [Mersenne31Quartic::ZERO;
                NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES],
            delegation_argument_gamma: Mersenne31Quartic::ZERO,
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let delegation_argument_linearization_challenges = [();
            NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES]
            .map(|_| MersenneQuartic::allocate_without_value(cs));

        Self {
            delegation_argument_linearization_challenges,
            delegation_argument_gamma: MersenneQuartic::allocate_without_value(cs),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        let delegation_argument_linearization_challenges = witness
            .delegation_argument_linearization_challenges
            .map(|x| MersenneQuartic::allocate(cs, x));
        let delegation_argument_gamma =
            MersenneQuartic::allocate(cs, witness.delegation_argument_gamma);
        Self {
            delegation_argument_linearization_challenges,
            delegation_argument_gamma,
        }
    }
}

#[derive(Clone, Copy)]
pub struct WrappedExternalMachineStateArgumentChallenges<F: SmallField> {
    pub linearization_challenges: [MersenneQuartic<F>; NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES],
    pub additive_term: MersenneQuartic<F>,
}

impl<F: SmallField> WrappedExternalMachineStateArgumentChallenges<F> {
    pub(crate) fn to_uint32_vec<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = Vec::with_capacity(NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES * 4 + 4);
        for i in 0..NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES {
            result.extend_from_slice(&self.linearization_challenges[i].into_uint32s(cs));
        }
        result.extend_from_slice(&self.additive_term.into_uint32s(cs));
        result
    }

    pub(crate) fn enforce_equal<CS: ConstraintSystem<F>>(&self, cs: &mut CS, other: &Self) {
        for i in 0..NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES {
            self.linearization_challenges[i].enforce_equal(cs, &other.linearization_challenges[i]);
        }
        self.additive_term.enforce_equal(cs, &other.additive_term)
    }
}

impl<F: SmallField> CSAllocatable<F> for WrappedExternalMachineStateArgumentChallenges<F> {
    type Witness = ExternalMachineStateArgumentChallenges;

    fn placeholder_witness() -> Self::Witness {
        ExternalMachineStateArgumentChallenges {
            linearization_challenges: [MersenneQuartic::<F>::placeholder_witness();
                NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES],
            additive_term: MersenneQuartic::<F>::placeholder_witness(),
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            linearization_challenges: [(); NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES]
                .map(|_| MersenneQuartic::allocate_without_value(cs)),
            additive_term: MersenneQuartic::allocate_without_value(cs),
        }
    }

    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            linearization_challenges: witness
                .linearization_challenges
                .map(|x| MersenneQuartic::allocate(cs, x)),
            additive_term: MersenneQuartic::allocate(cs, witness.additive_term),
        }
    }
}

#[derive(Clone, Copy)]
pub struct WrappedAuxArgumentsBoundaryValues<F: SmallField> {
    pub lazy_init_first_row: [MersenneField<F>; REGISTER_SIZE],
    pub teardown_value_first_row: [MersenneField<F>; REGISTER_SIZE],
    pub teardown_timestamp_first_row: [MersenneField<F>; REGISTER_SIZE],
    pub lazy_init_one_before_last_row: [MersenneField<F>; REGISTER_SIZE],
    pub teardown_value_one_before_last_row: [MersenneField<F>; REGISTER_SIZE],
    pub teardown_timestamp_one_before_last_row: [MersenneField<F>; REGISTER_SIZE],
}

impl<F: SmallField> WrappedAuxArgumentsBoundaryValues<F> {
    pub(crate) fn to_uint32_vec<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Vec<UInt32<F>> {
        let mut result = Vec::with_capacity(REGISTER_SIZE * 2);
        result.extend_from_slice(&self.lazy_init_first_row.map(|x| x.into_uint32(cs)));
        result.extend_from_slice(&self.teardown_value_first_row.map(|x| x.into_uint32(cs)));
        result.extend_from_slice(&self.teardown_timestamp_first_row.map(|x| x.into_uint32(cs)));
        result.extend_from_slice(
            &self
                .lazy_init_one_before_last_row
                .map(|x| x.into_uint32(cs)),
        );
        result.extend_from_slice(
            &self
                .teardown_value_one_before_last_row
                .map(|x| x.into_uint32(cs)),
        );
        result.extend_from_slice(
            &self
                .teardown_timestamp_one_before_last_row
                .map(|x| x.into_uint32(cs)),
        );
        result
    }

    pub(crate) fn zero<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            lazy_init_first_row: [MersenneField::zero(cs); REGISTER_SIZE],
            teardown_value_first_row: [MersenneField::zero(cs); REGISTER_SIZE],
            teardown_timestamp_first_row: [MersenneField::zero(cs); REGISTER_SIZE],
            lazy_init_one_before_last_row: [MersenneField::zero(cs); REGISTER_SIZE],
            teardown_value_one_before_last_row: [MersenneField::zero(cs); REGISTER_SIZE],
            teardown_timestamp_one_before_last_row: [MersenneField::zero(cs); REGISTER_SIZE],
        }
    }
}

impl<F: SmallField> CSAllocatable<F> for WrappedAuxArgumentsBoundaryValues<F> {
    type Witness = AuxArgumentsBoundaryValues;

    fn placeholder_witness() -> Self::Witness {
        AuxArgumentsBoundaryValues {
            lazy_init_first_row: [Mersenne31Field::ZERO; REGISTER_SIZE],
            teardown_value_first_row: [Mersenne31Field::ZERO; REGISTER_SIZE],
            teardown_timestamp_first_row: [Mersenne31Field::ZERO; REGISTER_SIZE],
            lazy_init_one_before_last_row: [Mersenne31Field::ZERO; REGISTER_SIZE],
            teardown_value_one_before_last_row: [Mersenne31Field::ZERO; REGISTER_SIZE],
            teardown_timestamp_one_before_last_row: [Mersenne31Field::ZERO; REGISTER_SIZE],
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            lazy_init_first_row: [(); REGISTER_SIZE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            teardown_value_first_row: [(); REGISTER_SIZE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            teardown_timestamp_first_row: [(); REGISTER_SIZE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            lazy_init_one_before_last_row: [(); REGISTER_SIZE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            teardown_value_one_before_last_row: [(); REGISTER_SIZE]
                .map(|_| MersenneField::allocate_without_value(cs)),
            teardown_timestamp_one_before_last_row: [(); REGISTER_SIZE]
                .map(|_| MersenneField::allocate_without_value(cs)),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            lazy_init_first_row: witness
                .lazy_init_first_row
                .map(|x| MersenneField::allocate(cs, x)),
            teardown_value_first_row: witness
                .teardown_value_first_row
                .map(|x| MersenneField::allocate(cs, x)),
            teardown_timestamp_first_row: witness
                .teardown_timestamp_first_row
                .map(|x| MersenneField::allocate(cs, x)),
            lazy_init_one_before_last_row: witness
                .lazy_init_one_before_last_row
                .map(|x| MersenneField::allocate(cs, x)),
            teardown_value_one_before_last_row: witness
                .teardown_value_one_before_last_row
                .map(|x| MersenneField::allocate(cs, x)),
            teardown_timestamp_one_before_last_row: witness
                .teardown_timestamp_one_before_last_row
                .map(|x| MersenneField::allocate(cs, x)),
        }
    }
}

pub struct WrappedProofOutput<
    F: SmallField,
    const CAP_SIZE: usize,
    const NUM_COSETS: usize,
    const NUM_DELEGATION_CHALLENGES: usize,
    const NUM_AUX_BOUNDARY_VALUES: usize,
    const NUM_MACHINE_STATE_CHALLENGES: usize = 0,
> {
    pub setup_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub memory_caps: [WrappedMerkleTreeCap<F, CAP_SIZE>; NUM_COSETS],
    pub memory_challenges: WrappedExternalMemoryArgumentChallenges<F>,
    pub delegation_challenges:
        [WrappedExternalDelegationArgumentChallenges<F>; NUM_DELEGATION_CHALLENGES],
    pub lazy_init_boundary_values: [WrappedAuxArgumentsBoundaryValues<F>; NUM_AUX_BOUNDARY_VALUES],
    pub machine_state_permutation_challenges:
        [WrappedExternalMachineStateArgumentChallenges<F>; NUM_MACHINE_STATE_CHALLENGES],
    pub grand_product_accumulator: MersenneQuartic<F>,
    pub delegation_argument_accumulator: [MersenneQuartic<F>; NUM_DELEGATION_CHALLENGES],
    pub circuit_sequence: UInt32<F>,
    pub delegation_type: UInt32<F>,
}

impl<
    F: SmallField,
    const CAP_SIZE: usize,
    const NUM_COSETS: usize,
    const NUM_DELEGATION_CHALLENGES: usize,
    const NUM_AUX_BOUNDARY_VALUES: usize,
    const NUM_MACHINE_STATE_CHALLENGES: usize,
> CSAllocatable<F>
    for WrappedProofOutput<
        F,
        CAP_SIZE,
        NUM_COSETS,
        NUM_DELEGATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_MACHINE_STATE_CHALLENGES,
    >
{
    type Witness = ProofOutput<
        CAP_SIZE,
        NUM_COSETS,
        NUM_DELEGATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_MACHINE_STATE_CHALLENGES,
    >;

    fn placeholder_witness() -> Self::Witness {
        ProofOutput {
            setup_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            memory_caps: [WrappedMerkleTreeCap::<F, CAP_SIZE>::placeholder_witness(); NUM_COSETS],
            memory_challenges: WrappedExternalMemoryArgumentChallenges::<F>::placeholder_witness(),
            delegation_challenges:
                [WrappedExternalDelegationArgumentChallenges::<F>::placeholder_witness();
                    NUM_DELEGATION_CHALLENGES],
            lazy_init_boundary_values: [WrappedAuxArgumentsBoundaryValues::<F>::placeholder_witness(
            ); NUM_AUX_BOUNDARY_VALUES],
            machine_state_permutation_challenges:
                [WrappedExternalMachineStateArgumentChallenges::<F>::placeholder_witness();
                    NUM_MACHINE_STATE_CHALLENGES],
            grand_product_accumulator: Mersenne31Quartic::ZERO,
            delegation_argument_accumulator: [Mersenne31Quartic::ZERO; NUM_DELEGATION_CHALLENGES],
            circuit_sequence: 0u32,
            delegation_type: 0u32,
        }
    }
    fn allocate_without_value<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        Self {
            setup_caps: [(); NUM_COSETS].map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            memory_caps: [(); NUM_COSETS].map(|_| WrappedMerkleTreeCap::allocate_without_value(cs)),
            memory_challenges: WrappedExternalMemoryArgumentChallenges::allocate_without_value(cs),
            delegation_challenges: [(); NUM_DELEGATION_CHALLENGES]
                .map(|_| WrappedExternalDelegationArgumentChallenges::allocate_without_value(cs)),
            lazy_init_boundary_values: [(); NUM_AUX_BOUNDARY_VALUES]
                .map(|_| WrappedAuxArgumentsBoundaryValues::allocate_without_value(cs)),
            machine_state_permutation_challenges: [(); NUM_MACHINE_STATE_CHALLENGES]
                .map(|_| WrappedExternalMachineStateArgumentChallenges::allocate_without_value(cs)),
            grand_product_accumulator: MersenneQuartic::allocate_without_value(cs),
            delegation_argument_accumulator: [(); NUM_DELEGATION_CHALLENGES]
                .map(|_| MersenneQuartic::allocate_without_value(cs)),
            circuit_sequence: UInt32::allocate_without_value(cs),
            delegation_type: UInt32::allocate_without_value(cs),
        }
    }
    fn allocate<CS: ConstraintSystem<F>>(cs: &mut CS, witness: Self::Witness) -> Self {
        Self {
            setup_caps: witness
                .setup_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            memory_caps: witness
                .memory_caps
                .map(|x| WrappedMerkleTreeCap::allocate(cs, x)),
            memory_challenges: WrappedExternalMemoryArgumentChallenges::allocate(
                cs,
                witness.memory_challenges,
            ),
            delegation_challenges: witness
                .delegation_challenges
                .map(|x| WrappedExternalDelegationArgumentChallenges::allocate(cs, x)),
            machine_state_permutation_challenges: witness
                .machine_state_permutation_challenges
                .map(|x| WrappedExternalMachineStateArgumentChallenges::allocate(cs, x)),
            lazy_init_boundary_values: witness
                .lazy_init_boundary_values
                .map(|x| WrappedAuxArgumentsBoundaryValues::allocate(cs, x)),
            grand_product_accumulator: MersenneQuartic::allocate(
                cs,
                witness.grand_product_accumulator,
            ),
            delegation_argument_accumulator: witness
                .delegation_argument_accumulator
                .map(|x| MersenneQuartic::allocate(cs, x)),
            circuit_sequence: UInt32::allocate(cs, witness.circuit_sequence),
            delegation_type: UInt32::allocate(cs, witness.delegation_type),
        }
    }
}

pub struct WrappedProofAuxValues<F: SmallField> {
    pub grand_product_accumulator_final_value: MersenneQuartic<F>,
    pub delegation_argument_accumulator_sum: MersenneQuartic<F>,
}

pub struct WrappedBitSource<F: SmallField> {
    bytes: Vec<UInt8<F>>,
    rest: Vec<Boolean<F>>,
}

impl<F: SmallField> WrappedBitSource<F> {
    pub fn new<CS: ConstraintSystem<F>>(cs: &mut CS, uint32_values: &[UInt32<F>]) -> Self {
        let bytes = uint32_values
            .iter()
            .flat_map(|value| value.decompose_into_bytes(cs))
            .rev() // we are going to take from the top
            .collect();

        Self {
            bytes,
            rest: vec![],
        }
    }

    pub fn get_next_bit<CS: ConstraintSystem<F>>(&mut self, cs: &mut CS) -> Boolean<F> {
        if let Some(bit) = self.rest.pop() {
            return bit;
        }

        let next_byte = self.bytes.pop().expect("Must have enough bits");

        self.rest = next_byte
            .into_num()
            .spread_into_bits::<CS, 8>(cs)
            .into_iter()
            .rev()
            .collect();

        self.rest.pop().unwrap()
    }

    pub fn get_next_bits<CS: ConstraintSystem<F>>(
        &mut self,
        cs: &mut CS,
        num_bits: usize,
    ) -> Vec<Boolean<F>> {
        let mut result = Vec::with_capacity(num_bits);
        for _ in 0..num_bits {
            result.push(self.get_next_bit(cs));
        }
        result
    }
}
