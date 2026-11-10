use boojum::{
    cs::{
        CSGeometry, GateConfigurationHolder, LookupParameters, StaticToolboxHolder,
        cs_builder::{CsBuilder, CsBuilderImpl},
        gates::{
            BooleanConstraintGate, ConditionalSwapGate, ConstantsAllocatorGate,
            FmaGateInBaseFieldWithoutConstant, FmaGateInExtensionWithoutConstant, NopGate,
            ParallelSelectionGate, PublicInputGate, ReductionGate, SelectionGate, ZeroCheckGate,
        },
        implementations::prover::ProofConfig,
        traits::{circuit::CircuitBuilder, cs::ConstraintSystem, gate::GatePlacementStrategy},
    },
    gadgets::{
        boolean::Boolean,
        recursion::{allocated_proof::AllocatedProof, allocated_vk::AllocatedVerificationKey},
        traits::{allocatable::CSAllocatable, round_function::BuildableCircuitRoundFunction},
    },
    implementations::poseidon2::Poseidon2Goldilocks,
};

use crate::*;

pub struct CompressionCircuit {
    pub witness: Option<RiscWrapperProof>,
    pub vk: RiscWrapperVK,
}

impl CircuitBuilder<GL> for CompressionCircuit {
    fn geometry() -> CSGeometry {
        // With a low-degree extension factor of 4 in the RISC wrapper, this
        // geometry fits a 2^16 trace. A factor of 32 here keeps the downstream
        // PLONK circuit within a 2^22 domain.
        CSGeometry {
            num_columns_under_copy_permutation: 56,
            num_witness_columns: 74,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::NoLookup
    }

    fn configure_builder<
        T: CsBuilderImpl<GL, T>,
        GC: GateConfigurationHolder<GL>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, GL, GC, TB>,
    ) -> CsBuilder<T, GL, impl GateConfigurationHolder<GL>, impl StaticToolboxHolder> {
        let builder = ConstantsAllocatorGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = BooleanConstraintGate::configure_builder(
            builder,
            GatePlacementStrategy::UseSpecializedColumns {
                num_repetitions: 1,
                share_constants: false,
            },
        );
        let builder = Poseidon2Goldilocks::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            true,
        );
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = FmaGateInExtensionWithoutConstant::<GL, GLExt2>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ParallelSelectionGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ConditionalSwapGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = PublicInputGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<_, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }
}

impl CompressionCircuit {
    pub fn new(
        risc_wrapper_proof: Option<RiscWrapperProof>,
        risc_wrapper_vk: RiscWrapperVK,
    ) -> Self {
        Self {
            witness: risc_wrapper_proof,
            vk: risc_wrapper_vk,
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        let trace_len = 1 << 16;
        let max_variables = 1 << 24;
        (Some(trace_len), Some(max_variables))
    }

    pub fn get_proof_config() -> ProofConfig {
        ProofConfig {
            fri_lde_factor: 32,
            merkle_tree_cap_size: 16,
            fri_folding_schedule: None,
            #[cfg(feature = "security_80")]
            security_level: 80,
            #[cfg(feature = "security_100")]
            security_level: 100,
            pow_bits: 0,
            extra_fri_queries: true,
        }
    }

    pub fn synthesize_into_cs<CS: ConstraintSystem<GL> + 'static>(self, cs: &mut CS) {
        let Self { witness, vk } = self;

        let verifier_builder =
            RiscWrapperCircuitBuilder::dyn_recursive_verifier_builder::<GLExt2, CS>();

        // use this and deal with borrow checker
        let r = cs as *mut CS;

        assert_eq!(vk.fixed_parameters.parameters, verifier_builder.geometry());

        let fixed_parameters = vk.fixed_parameters.clone();

        let verifier = verifier_builder.create_recursive_verifier(cs);

        let cs = unsafe { &mut *r };

        let vk = AllocatedVerificationKey::allocate_constant(cs, vk);

        let proof_config = RiscWrapper::get_proof_config();

        let proof = AllocatedProof::allocate_from_witness(
            cs,
            witness,
            &verifier,
            &fixed_parameters,
            &proof_config,
        );

        // verify the proof
        let (is_valid, public_inputs) = verifier.verify::<
            CircuitRiscWrapperTreeHasher,
            RiscWrapperTranscript,
            CircuitRiscWrapperTranscript,
            NoPow
        >(
            cs,
            (),
            &proof,
            &fixed_parameters,
            &proof_config,
            &vk,
        );

        let boolean_true = Boolean::allocated_constant(cs, true);
        Boolean::enforce_equal(cs, &is_valid, &boolean_true);

        assert_eq!(public_inputs.len(), fixed_parameters.num_public_inputs());

        for el in public_inputs.into_iter() {
            use boojum::cs::gates::PublicInputGate;
            let gate = PublicInputGate::new(el.get_variable());
            gate.add_to_cs(cs);
        }
    }
}
