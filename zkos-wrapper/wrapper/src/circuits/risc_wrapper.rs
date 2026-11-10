use boojum::{
    cs::{
        CSGeometry, GateConfigurationHolder, LookupParameters, StaticToolboxHolder,
        cs_builder::{CsBuilder, CsBuilderImpl},
        gates::{
            ConstantsAllocatorGate, FmaGateInBaseFieldWithoutConstant, NopGate, PublicInputGate,
            ReductionGate, SelectionGate, U32TriAddCarryAsChunkGate, UIntXAddGate, ZeroCheckGate,
        },
        implementations::prover::ProofConfig,
        traits::{circuit::CircuitBuilder, cs::ConstraintSystem, gate::GatePlacementStrategy},
    },
    field::SmallField,
    gadgets::{
        num::Num,
        tables::{
            and8::{And8Table, create_and8_table},
            byte_split::{ByteSplitTable, create_byte_split_table},
            xor8::{Xor8Table, create_xor8_table},
        },
        traits::allocatable::CSAllocatable,
        u16::UInt16,
        u32::UInt32,
    },
};
use circuit_mersenne_field::{
    MersenneField, MersenneQuartic, extension_trait::CircuitFieldExpression,
};
use std::mem::MaybeUninit;
use std::sync::OnceLock;

use crate::inner_verifiers::unified_reduced::skeleton::{
    WrappedProofSkeletonInstance, WrappedQueryValuesInstance,
};
use crate::inner_verifiers::unified_reduced::*;
use crate::wrapper_utils::prover_structs::*;
use crate::wrapper_utils::verifier_traits::{CircuitLeafInclusionVerifier, PlaceholderSource};
use crate::{inner_verifiers::unified_reduced, risc_verifier};
use risc_verifier::blake2s_u32::*;
use risc_verifier::concrete::size_constants::*;
use risc_verifier::prover::definitions::LeafInclusionVerifier;
use risc_verifier::prover::field::Mersenne31Field;
use risc_verifier::prover::riscv_transpiler::cycle::state::NUM_REGISTERS;

use risc_verifier::prover::cs::definitions::*;

use risc_verifier::verifier_common::{
    DefaultNonDeterminismSource, ProofOutput, ProofPublicInputs,
    cs::one_row_compiler::CompiledCircuitArtifact,
};

use boojum::gadgets::tables::RangeCheck15BitsTable;
use boojum::gadgets::tables::RangeCheck16BitsTable;
use boojum::gadgets::tables::create_range_check_15_bits_table;
use boojum::gadgets::tables::create_range_check_16_bits_table;
use risc_verifier::prover::prover_stages::Proof as RiscProof;
use risc_verifier::prover::prover_stages::unrolled_prover::UnrolledModeProof as RiscUnrolledProof;

use execution_utils::{RecursionArtifact, RecursionLayer, unrolled::UnrolledProgramProof};

const NUM_RISC_WRAPPER_PUBLIC_INPUTS: usize = 4;

#[cfg(feature = "security_80")]
const NUM_UNIFIED_PROOFS: usize = 1;
#[cfg(feature = "security_100")]
const NUM_UNIFIED_PROOFS: usize = 2;

pub struct RiscWrapperWitness {
    pub final_pc: u32,
    pub final_timestamp: [u32; 2],
    pub final_registers_state: [u32; NUM_REGISTERS * 3],
    pub unified_proofs: [RiscUnrolledProof; NUM_UNIFIED_PROOFS],
    pub blake_proof: RiscProof,
    pub pow_challenge: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct BinaryCommitment {
    pub end_params: [u32; 8],
    pub aux_params: [u32; 8],
}

impl BinaryCommitment {
    /// Build from all three layer binaries explicitly:
    /// 1. the base program (e.g. zksync_os app),
    /// 2. the unrolled-recursion verifier,
    /// 3. the unified-recursion verifier.
    ///
    /// `aux_params` is the Blake2s recursion-chain hash folded over the layer
    /// `end_params` in order (base -> unrolled). The top unified verifier does
    /// not fold its own `end_params` into the chain it exposes, so `aux_params`
    /// stops at the unrolled layer. This is the binary chain commitment the top
    /// verifier exposes in its final registers 18..=25.
    pub fn from_binaries(
        base_bin: &[u8],
        base_text: &[u8],
        unrolled_bin: &[u8],
        unrolled_text: &[u8],
        unified_bin: &[u8],
        unified_text: &[u8],
    ) -> Self {
        use execution_utils::unified_circuit::compute_unified_setup_for_machine_configuration;
        use execution_utils::unrolled::{
            UnrolledProgramSetup, compute_setup_for_machine_configuration,
        };
        use risc_verifier::prover::riscv_transpiler::cycle::{
            IMStandardIsaConfigWithUnsignedMulDiv, IWithoutByteAccessIsaConfigWithDelegation,
        };

        fn padded(bytes: &[u8]) -> Vec<u8> {
            let mut v = bytes.to_vec();
            setups::pad_bytecode_bytes_for_proving(&mut v);
            v
        }

        let padded_base_bin = padded(base_bin);
        let padded_base_text = padded(base_text);
        let padded_unrolled_bin = padded(unrolled_bin);
        let padded_unrolled_text = padded(unrolled_text);
        let padded_unified_bin = padded(unified_bin);
        let padded_unified_text = padded(unified_text);

        let base_setup = compute_setup_for_machine_configuration::<
            IMStandardIsaConfigWithUnsignedMulDiv,
        >(&padded_base_bin, &padded_base_text);
        let unrolled_setup = compute_setup_for_machine_configuration::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded_unrolled_bin, &padded_unrolled_text);
        let unified_setup = compute_unified_setup_for_machine_configuration::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded_unified_bin, &padded_unified_text);

        // The chain the top verifier exposes in registers 18..=25: base -> unrolled -> unified.
        // Measured against real airbender v0.6.0-rc.1 proofs, those registers hold the full
        // chain (same value as registers 8..=15), so stopping at `unrolled` rejects every
        // real proof. `RiscWrapperWitness::from_full_proof` checks this against the proof.
        let (h1, p1) = UnrolledProgramSetup::begin_recursion_chain(&base_setup.end_params);
        let (h2, p2) =
            UnrolledProgramSetup::continue_recursion_chain(&unrolled_setup.end_params, &h1, &p1);
        let (aux_params, _) =
            UnrolledProgramSetup::continue_recursion_chain(&unified_setup.end_params, &h2, &p2);

        Self {
            end_params: unified_setup.end_params,
            aux_params,
        }
    }

    /// Build from the base program only; pulls the unrolled / unified
    /// verifier binaries from `execution_utils::verifier_binaries`.
    pub fn from_base_binary(base_bin: &[u8], base_text: &[u8]) -> Self {
        let security = crate::active_security::ACTIVE_SECURITY_MODEL;
        let load = |layer, artifact| {
            execution_utils::verifier_binaries::recursion_artifact(security, layer, artifact)
        };
        Self::from_binaries(
            base_bin,
            base_text,
            load(RecursionLayer::Unrolled, RecursionArtifact::Bin),
            load(RecursionLayer::Unrolled, RecursionArtifact::Txt),
            load(RecursionLayer::Unified, RecursionArtifact::Bin),
            load(RecursionLayer::Unified, RecursionArtifact::Txt),
        )
    }
}

impl Default for BinaryCommitment {
    /// `end_params` from the default unified-recursion verifier binary, with a
    /// zero `aux_params`. Use when `check_aux_params` is disabled — the base
    /// program bin/text is then unnecessary (`aux_params` is never consumed).
    fn default() -> Self {
        use execution_utils::unified_circuit::compute_unified_setup_for_machine_configuration;
        use risc_verifier::prover::riscv_transpiler::cycle::IWithoutByteAccessIsaConfigWithDelegation;

        let security = crate::active_security::ACTIVE_SECURITY_MODEL;
        let load = |artifact| {
            execution_utils::verifier_binaries::recursion_artifact(
                security,
                RecursionLayer::Unified,
                artifact,
            )
        };

        let mut unified_bin = load(RecursionArtifact::Bin).to_vec();
        setups::pad_bytecode_bytes_for_proving(&mut unified_bin);
        let mut unified_text = load(RecursionArtifact::Txt).to_vec();
        setups::pad_bytecode_bytes_for_proving(&mut unified_text);

        let unified_setup = compute_unified_setup_for_machine_configuration::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&unified_bin, &unified_text);

        Self {
            end_params: unified_setup.end_params,
            aux_params: [0u32; 8],
        }
    }
}

impl RiscWrapperWitness {
    pub fn from_full_proof(
        full_proof: UnrolledProgramProof,
        binary_commitment: &BinaryCommitment,
        check_aux_params: bool,
    ) -> anyhow::Result<Self> {
        let UnrolledProgramProof {
            final_pc,
            final_timestamp,
            circuit_families_proofs,
            inits_and_teardowns_proofs,
            delegation_proofs,
            register_final_values,
            recursion_chain_preimage: _,
            recursion_chain_hash: _,
            pow_challenge,
        } = full_proof;

        // TODO: check final_pc

        if check_aux_params {
            // Off-circuit mirror of the in-circuit aux_params constraint (see
            // `prepare_and_allocate_public_inputs`, which enforces registers
            // 18..=25 == aux_params). Checking it here rejects a mismatched binary
            // commitment up front with a clear error instead of producing an
            // unsatisfiable circuit at proving time.
            //
            // The program exposes the binary chain commitment in its final registers
            // 18..=25, which is the source of truth here. Note this is NOT the proof's
            // `recursion_chain_hash`: that field is the prover's internal
            // recursion-layer chain, whose value depends on how many unified-recursion
            // iterations ran, so comparing against it would reject valid proofs.
            for i in 0..8 {
                let actual = register_final_values[18 + i].value;
                let expected = binary_commitment.aux_params[i];
                anyhow::ensure!(
                    actual == expected,
                    "register {} (0x{:08x}) does not match binary commitment aux_params[{}] (0x{:08x})",
                    18 + i,
                    actual,
                    i,
                    expected,
                );
            }
        }

        let (final_timestamp_low, final_timestamp_high) =
            risc_verifier::prover::cs::definitions::split_timestamp(final_timestamp);

        let final_registers_state: Vec<_> = register_final_values
            .into_iter()
            .flat_map(|final_values| {
                let (low, high) = risc_verifier::prover::cs::definitions::split_timestamp(
                    final_values.last_access_timestamp,
                );
                [final_values.value, low, high]
            })
            .collect();

        let mut cf_iter = circuit_families_proofs.into_iter();
        let unified_proofs = {
            let unified_proofs = cf_iter.next().unwrap();
            assert!(
                unified_proofs.0 == REDUCED_MACHINE_CIRCUIT_FAMILY_IDX,
                "Expected unified reduced circuit family"
            );
            assert!(
                unified_proofs.1.len() == NUM_UNIFIED_PROOFS,
                "Expected exact number of unified proofs"
            );
            unified_proofs.1.try_into().unwrap()
        };
        assert!(cf_iter.next().is_none(), "Too many circuit family proofs");

        assert!(
            inits_and_teardowns_proofs.is_empty(),
            "Expected no inits and teardowns proofs"
        );

        let mut dp_iter = delegation_proofs.into_iter();
        let blake_proof = {
            let blake_proofs = dp_iter.next().unwrap();
            assert!(
                blake_proofs.0 == BLAKE2S_DELEGATION_CSR_REGISTER,
                "Expected blake delegation proof"
            );
            assert!(blake_proofs.1.len() == 1, "Expected only one blake proof");
            blake_proofs.1.into_iter().next().unwrap()
        };
        assert!(dp_iter.next().is_none(), "Too many delegation proofs");

        Ok(Self {
            final_pc,
            final_timestamp: [final_timestamp_low, final_timestamp_high],
            final_registers_state: final_registers_state.try_into().unwrap(),
            unified_proofs,
            blake_proof,
            pow_challenge,
        })
    }
}

pub struct RiscWrapperCircuit<F: SmallField, V: CircuitLeafInclusionVerifier<F>> {
    pub witness: Option<RiscWrapperWitness>,
    pub binary_commitment: BinaryCommitment,
    pub check_aux_params: bool,
    _phantom: std::marker::PhantomData<(F, V)>,
}

impl<F: SmallField, V: CircuitLeafInclusionVerifier<F>> CircuitBuilder<F>
    for RiscWrapperCircuit<F, V>
{
    fn geometry() -> CSGeometry {
        if cfg!(feature = "security_80") {
            CSGeometry {
                num_columns_under_copy_permutation: 136,
                num_witness_columns: 0,
                num_constant_columns: 4,
                max_allowed_constraint_degree: 4,
            }
        } else if cfg!(feature = "security_100") {
            CSGeometry {
                num_columns_under_copy_permutation: 255,
                num_witness_columns: 0,
                num_constant_columns: 4,
                max_allowed_constraint_degree: 4,
            }
        } else {
            panic!("Security level not supported");
        }
    }

    fn lookup_parameters() -> LookupParameters {
        if cfg!(feature = "security_80") {
            LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                width: 3,
                num_repetitions: 56,
                share_table_id: true,
            }
        } else if cfg!(feature = "security_100") {
            LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
                width: 3,
                num_repetitions: 101,
                share_table_id: true,
            }
        } else {
            panic!("Security level not supported");
        }
    }

    fn configure_builder<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = builder.allow_lookup(Self::lookup_parameters());

        let builder = ConstantsAllocatorGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<F, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
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

        // This gate is not supported by GPU. If we added support for it, then we should also set the limbs2 in range_check_32_bits in field.rs
        /*let builder = ReductionGate::<F, 2>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );*/
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );
        let builder = PublicInputGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = U32TriAddCarryAsChunkGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        // This gate is not supported by GPU.
        /*let builder = U32AddCarryAsChunkGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );*/

        builder
    }
}

impl<F: SmallField, V: CircuitLeafInclusionVerifier<F>> RiscWrapperCircuit<F, V> {
    pub fn new(
        witness: Option<RiscWrapperWitness>,
        verify_inner_proof: bool,
        binary_commitment: BinaryCommitment,
        check_aux_params: bool,
    ) -> Self {
        if verify_inner_proof {
            if let Some(witness) = &witness {
                for proof in witness.unified_proofs.iter() {
                    verify_risc_proof::<V::OutOfCircuitImpl>(proof);
                }
                crate::inner_verifiers::blake_delegation::verify_blake_proof::<V::OutOfCircuitImpl>(
                    &witness.blake_proof,
                );
            } else {
                panic!("Proof is required for verification");
            }
        }

        Self {
            witness,
            binary_commitment,
            check_aux_params,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        let trace_len = 1 << 20;
        let max_variables = 1 << 28;
        (Some(trace_len), Some(max_variables))
    }

    pub fn add_tables<CS: ConstraintSystem<F>>(&self, cs: &mut CS) {
        let table = create_range_check_16_bits_table::<3, F>();
        cs.add_lookup_table::<RangeCheck16BitsTable<3>, 3>(table);

        let table = create_range_check_15_bits_table::<3, F>();
        cs.add_lookup_table::<RangeCheck15BitsTable<3>, 3>(table);

        let table = create_xor8_table();
        cs.add_lookup_table::<Xor8Table, 3>(table);

        let table = create_and8_table();
        cs.add_lookup_table::<And8Table, 3>(table);

        let table = create_byte_split_table::<F, 1>();
        cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);

        let table = create_byte_split_table::<F, 2>();
        cs.add_lookup_table::<ByteSplitTable<2>, 3>(table);

        let table = create_byte_split_table::<F, 3>();
        cs.add_lookup_table::<ByteSplitTable<3>, 3>(table);

        let table = create_byte_split_table::<F, 4>();
        cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);

        let table = create_byte_split_table::<F, 7>();
        cs.add_lookup_table::<ByteSplitTable<7>, 3>(table);
    }

    pub fn get_proof_config() -> ProofConfig {
        ProofConfig {
            fri_lde_factor: 4,
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

    pub fn synthesize_into_cs<CS: ConstraintSystem<F>>(&self, cs: &mut CS) {
        let final_pc_witness = if let Some(witness) = &self.witness {
            witness.final_pc
        } else {
            0u32
        };

        let final_pc = UInt32::allocate(cs, final_pc_witness);

        let final_timestamp_witness = if let Some(witness) = &self.witness {
            witness.final_timestamp
        } else {
            [0u32; 2]
        };

        let final_timestamp = [
            UInt32::allocate(cs, final_timestamp_witness[0]),
            UInt32::allocate(cs, final_timestamp_witness[1]),
        ];

        let final_registers_state_witness = if let Some(witness) = &self.witness {
            witness.final_registers_state
        } else {
            [0u32; NUM_REGISTERS * 3]
        };

        let final_registers_state =
            <[UInt32<F>; NUM_REGISTERS * 3]>::allocate(cs, final_registers_state_witness);

        let unified_proof_parts = if let Some(witness) = &self.witness {
            witness
                .unified_proofs
                .each_ref()
                .map(|proof| prepare_unrolled_proof_for_wrapper::<_, _, V>(cs, proof))
        } else {
            [(); NUM_UNIFIED_PROOFS].map(|_| {
                // allocate from placeholder
                let skeleton_witness = WrappedProofSkeletonInstance::<F>::placeholder_witness();
                let skeleton = WrappedProofSkeletonInstance::allocate(cs, skeleton_witness);

                let mut leaf_inclusion_verifier = V::new(cs);

                let queries: [_; NUM_QUERIES] = std::array::from_fn(|_idx| unsafe {
                    WrappedQueryValuesInstance::from_non_determinism_source::<_, PlaceholderSource, _>(
                        cs,
                        &skeleton,
                        &mut leaf_inclusion_verifier,
                    )
                });

                (skeleton, queries)
            })
        };

        let unified_proofs_states = unified_proof_parts.map(|(skeleton, queries)| {
            crate::inner_verifiers::unified_reduced::verify(cs, skeleton, queries).0
        });

        let (skeleton, queries) = if let Some(witness) = &self.witness {
            crate::inner_verifiers::blake_delegation::prepare_blake_proof_for_wrapper::<_, _, V>(
                cs,
                &witness.blake_proof,
            )
        } else {
            crate::inner_verifiers::blake_delegation::placeholders::<_, _, V>(cs)
        };

        let (blake_state, _) =
            crate::inner_verifiers::blake_delegation::verify(cs, skeleton, queries);

        let pow_challenge = if let Some(witness) = &self.witness {
            [
                UInt32::allocate(cs, (witness.pow_challenge & 0xffffffff) as u32),
                UInt32::allocate(cs, (witness.pow_challenge >> 32) as u32),
            ]
        } else {
            [UInt32::allocate(cs, 0), UInt32::allocate(cs, 0)]
        };

        check_proof_state(
            cs,
            final_pc,
            final_timestamp,
            final_registers_state,
            &unified_proofs_states,
            &blake_state,
            pow_challenge,
            &self.binary_commitment,
        );

        prepare_and_allocate_public_inputs(
            cs,
            final_registers_state,
            self.check_aux_params,
            &self.binary_commitment,
        );
    }
}

pub(crate) fn prepare_unrolled_proof_for_wrapper<
    F: SmallField,
    CS: ConstraintSystem<F>,
    V: CircuitLeafInclusionVerifier<F>,
>(
    cs: &mut CS,
    proof: &RiscUnrolledProof,
) -> (
    WrappedProofSkeletonInstance<F>,
    [WrappedQueryValuesInstance<F>; NUM_QUERIES],
) {
    set_iterator_from_unrolled_proof(proof, unified_reduced_compiled_circuit());

    let skeleton = unsafe {
        WrappedProofSkeletonInstance::from_non_determinism_source::<_, DefaultNonDeterminismSource>(
            cs,
        )
    };

    let mut leaf_inclusion_verifier = V::new(cs);

    let queries: [_; NUM_QUERIES] = std::array::from_fn(|_idx| unsafe {
        WrappedQueryValuesInstance::from_non_determinism_source::<_, DefaultNonDeterminismSource, _>(
            cs,
            &skeleton,
            &mut leaf_inclusion_verifier,
        )
    });

    (skeleton, queries)
}

// Kept for ad-hoc debugging of the delegated proof shape, even though the main
// wrapping path currently feeds the unrolled proof variant directly.
#[allow(dead_code)]
pub(crate) fn prepare_proof_for_wrapper<
    F: SmallField,
    CS: ConstraintSystem<F>,
    V: CircuitLeafInclusionVerifier<F>,
>(
    cs: &mut CS,
    proof: &RiscProof,
) -> (
    WrappedProofSkeletonInstance<F>,
    [WrappedQueryValuesInstance<F>; NUM_QUERIES],
) {
    let shuffle_ram_inits_and_teardowns_len = unified_reduced::imports::VERIFIER_COMPILED_LAYOUT
        .memory_layout
        .shuffle_ram_inits_and_teardowns
        .len();

    set_iterator_from_proof(proof, shuffle_ram_inits_and_teardowns_len);

    let skeleton = unsafe {
        WrappedProofSkeletonInstance::from_non_determinism_source::<_, DefaultNonDeterminismSource>(
            cs,
        )
    };

    let mut leaf_inclusion_verifier = V::new(cs);

    let queries: [_; NUM_QUERIES] = std::array::from_fn(|_idx| unsafe {
        WrappedQueryValuesInstance::from_non_determinism_source::<_, DefaultNonDeterminismSource, _>(
            cs,
            &skeleton,
            &mut leaf_inclusion_verifier,
        )
    });

    (skeleton, queries)
}

#[allow(invalid_value)]
// Kept for ad-hoc debugging of the inner verifier outside the main proving
// pipeline, which now relies on explicit top-level verification methods.
#[allow(dead_code)]
pub(crate) fn verify_risc_proof<V: LeafInclusionVerifier>(
    proof: &RiscUnrolledProof,
) -> (
    ProofOutput<
        TREE_CAP_SIZE,
        NUM_COSETS,
        NUM_DELEGATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
    >,
    ProofPublicInputs<NUM_STATE_ELEMENTS>,
) {
    set_iterator_from_unrolled_proof(proof, unified_reduced_compiled_circuit());

    let mut proof_state_dst = unsafe {
        MaybeUninit::<
            ProofOutput<
                TREE_CAP_SIZE,
                NUM_COSETS,
                NUM_DELEGATION_CHALLENGES,
                NUM_AUX_BOUNDARY_VALUES,
                NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
            >,
        >::uninit()
        .assume_init()
    };
    let mut proof_input_dst =
        unsafe { MaybeUninit::<ProofPublicInputs<NUM_STATE_ELEMENTS>>::uninit().assume_init() };

    unsafe {
        risc_verifier::verify_with_configuration::<
            crate::active_security::ActiveSecurity,
            DefaultNonDeterminismSource,
            V,
        >(&mut proof_state_dst, &mut proof_input_dst);
    }

    (proof_state_dst, proof_input_dst)
}

pub(crate) fn set_iterator_from_unrolled_proof(
    proof: &RiscUnrolledProof,
    compiled_circuit: &CompiledCircuitArtifact<Mersenne31Field>,
) {
    let oracle_data = risc_verifier::verifier_common::proof_flattener::flatten_full_unrolled_proof(
        &proof,
        compiled_circuit,
    );

    let it = oracle_data.into_iter();

    risc_verifier::prover::nd_source_std::set_iterator(it.clone());
}

// The compiled layout is immutable generated data, so parsing it once per
// process is enough for every proof we wrap.
fn unified_reduced_compiled_circuit() -> &'static CompiledCircuitArtifact<Mersenne31Field> {
    static COMPILED_CIRCUIT: OnceLock<CompiledCircuitArtifact<Mersenne31Field>> = OnceLock::new();

    COMPILED_CIRCUIT.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../inner_verifiers/unified_reduced/imports/circuit_layout.json"
        ))
        .unwrap()
    })
}

pub(crate) fn set_iterator_from_proof(
    proof: &RiscProof,
    shuffle_ram_inits_and_teardowns_len: usize,
) {
    let mut oracle_data = vec![];

    oracle_data.extend(
        risc_verifier::verifier_common::proof_flattener::flatten_proof_for_skeleton(
            &proof,
            shuffle_ram_inits_and_teardowns_len,
        ),
    );
    for query in proof.queries.iter() {
        oracle_data.extend(risc_verifier::verifier_common::proof_flattener::flatten_query(query));
    }

    let it = oracle_data.into_iter();

    risc_verifier::prover::nd_source_std::set_iterator(it.clone());
}

use crate::inner_verifiers::blake_delegation::WrappedBlakeProofOutput;
pub(crate) fn check_proof_state<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    final_pc: UInt32<F>,
    final_timestamp: [UInt32<F>; 2],
    final_registers_state: [UInt32<F>; NUM_REGISTERS * 3],
    unified_proofs_states: &[WrappedProofOutput<
        F,
        TREE_CAP_SIZE,
        NUM_COSETS,
        NUM_DELEGATION_CHALLENGES,
        NUM_AUX_BOUNDARY_VALUES,
        NUM_MACHINE_STATE_PERMUTATION_CHALLENGES,
    >; NUM_UNIFIED_PROOFS],
    blake_state: &WrappedBlakeProofOutput<F>,
    pow_challenge: [UInt32<F>; 2],
    binary_commitment: &BinaryCommitment,
) {
    let mut transcript = Blake2sWrappedBufferingTranscript::new(cs);

    // x0 is always 0, for sanity
    let zero = Num::zero(cs);
    Num::enforce_equal(cs, &final_registers_state[0].into_num(), &zero);

    transcript.absorb(cs, &final_registers_state);

    let mut final_pc_buffer = [UInt32::zero(cs); BLAKE2S_BLOCK_SIZE_U32_WORDS];

    final_pc_buffer[0] = final_pc;
    final_pc_buffer[1] = final_timestamp[0];
    final_pc_buffer[2] = final_timestamp[1];

    transcript.absorb(cs, &final_pc_buffer);

    let mut grand_product_accumulator = MersenneQuartic::one(cs);
    let mut delegation_set_accumulator = MersenneQuartic::zero(cs);

    let mut buffer = [UInt32::zero(cs); BLAKE2S_BLOCK_SIZE_U32_WORDS];
    buffer[0] = UInt32::allocated_constant(cs, REDUCED_MACHINE_CIRCUIT_FAMILY_IDX as u32);
    transcript.absorb(cs, &buffer);

    unified_proofs_states.iter().for_each(|proof_state| {
        Num::enforce_equal(cs, &proof_state.circuit_sequence.into_num(), &zero);
        Num::enforce_equal(cs, &proof_state.delegation_type.into_num(), &zero);

        for cap in proof_state.memory_caps.iter() {
            for chunk in cap.cap.iter() {
                transcript.absorb(cs, chunk);
            }
        }

        grand_product_accumulator =
            grand_product_accumulator.mul(cs, &proof_state.grand_product_accumulator);
        if NUM_DELEGATION_CHALLENGES > 0 {
            delegation_set_accumulator =
                delegation_set_accumulator.add(cs, &proof_state.delegation_argument_accumulator[0]);
        }
    });

    for (current, previous) in unified_proofs_states
        .iter()
        .skip(1)
        .zip(unified_proofs_states.iter())
    {
        for (l, r) in current.setup_caps.iter().zip(previous.setup_caps.iter()) {
            l.enforce_equal(cs, r);
        }

        current
            .memory_challenges
            .enforce_equal(cs, &previous.memory_challenges);
        for (l, r) in current
            .delegation_challenges
            .iter()
            .zip(previous.delegation_challenges.iter())
        {
            l.enforce_equal(cs, r);
        }
        for (l, r) in current
            .machine_state_permutation_challenges
            .iter()
            .zip(previous.machine_state_permutation_challenges.iter())
        {
            l.enforce_equal(cs, r);
        }

        // and we also check inits/teardowns
        // check lazy inits
        fn unit32_from_two_16_bit_mersenne<F: SmallField, CS: ConstraintSystem<F>>(
            cs: &mut CS,
            chunks: &[MersenneField<F>; 2],
        ) -> UInt32<F> {
            // Only for local usage
            // We know that lazy_init_boundary_values have 16 bits (checked in quotient)
            use boojum::cs::gates::ConstantAllocatableCS;
            use boojum::gadgets::impls::limbs_decompose::reduce_terms;

            if cs.gate_is_allowed::<ReductionGate<F, 2>>() {
                let terms = [chunks[0].get_variable(), chunks[1].get_variable()];
                unsafe { UInt32::from_variable_unchecked(reduce_terms(cs, F::SHIFTS[16], terms)) }
            } else if cs.gate_is_allowed::<ReductionGate<F, 4>>() {
                let zero_var = cs.allocate_constant(F::ZERO);
                let terms = [
                    chunks[0].get_variable(),
                    chunks[1].get_variable(),
                    zero_var,
                    zero_var,
                ];
                unsafe { UInt32::from_variable_unchecked(reduce_terms(cs, F::SHIFTS[16], terms)) }
            } else {
                unimplemented!();
            }
        }

        let last_previous = unit32_from_two_16_bit_mersenne(
            cs,
            &previous.lazy_init_boundary_values[0].lazy_init_one_before_last_row,
        );

        let first_current = unit32_from_two_16_bit_mersenne(
            cs,
            &current.lazy_init_boundary_values[0].lazy_init_first_row,
        );

        // it should be either
        // flag = first_current > last_previous
        fn greater<F: SmallField, CS: ConstraintSystem<F>>(
            cs: &mut CS,
            a: UInt32<F>,
            b: UInt32<F>,
        ) -> Boolean<F> {
            // res = a > b <=> b - a + 2^32 * res = diff is in [0, 2^32)

            let res = Boolean::allocate_without_value(cs);
            let diff = UInt32::allocate_without_value(cs);

            use boojum::{config::*, cs::*};
            if <CS::Config as CSConfig>::WitnessConfig::EVALUATE_WITNESS {
                let value_fn = move |inputs: [F; 2]| {
                    let a = inputs[0].as_u64_reduced();
                    let b = inputs[1].as_u64_reduced();
                    if a > b {
                        [
                            F::from_u64_with_reduction(1),
                            F::from_u64_with_reduction((1 << 32) + b - a),
                        ]
                    } else {
                        [
                            F::from_u64_with_reduction(0),
                            F::from_u64_with_reduction(b - a),
                        ]
                    }
                };

                cs.set_values_with_dependencies(
                    &[a.variable.into(), b.variable.into()],
                    &Place::from_variables([res.get_variable().into(), diff.variable.into()]),
                    value_fn,
                );
            }

            if <CS::Config as CSConfig>::SetupConfig::KEEP_SETUP == true {
                use boojum::cs::gates::ConstantAllocatableCS;

                let reduction_constants = [
                    F::MINUS_ONE,
                    F::ONE,
                    F::from_u64_unchecked(1 << 32),
                    F::ZERO,
                ];
                let output_variables = [
                    a.variable,
                    b.variable,
                    res.get_variable(),
                    cs.allocate_constant(F::ZERO),
                ];

                let gate = boojum::cs::gates::ReductionGate::<F, 4> {
                    params: boojum::cs::gates::ReductionGateParams {
                        reduction_constants,
                    },
                    terms: output_variables,
                    reduction_result: diff.variable,
                };
                gate.add_to_cs(cs);
            }

            res
        }

        let order_flag = greater(cs, first_current, last_previous);

        // or
        let mut other_flags = vec![];

        other_flags.push(last_previous.is_zero(cs));
        other_flags.push(
            previous.lazy_init_boundary_values[0].teardown_value_one_before_last_row[0]
                .clone()
                .is_zero(cs),
        );
        other_flags.push(
            previous.lazy_init_boundary_values[0].teardown_value_one_before_last_row[1]
                .clone()
                .is_zero(cs),
        );
        other_flags.push(
            previous.lazy_init_boundary_values[0].teardown_timestamp_one_before_last_row[0]
                .clone()
                .is_zero(cs),
        );
        other_flags.push(
            previous.lazy_init_boundary_values[0].teardown_timestamp_one_before_last_row[1]
                .clone()
                .is_zero(cs),
        );

        use boojum::gadgets::boolean::Boolean;
        let true_flag = Boolean::allocated_constant(cs, true);
        let final_flag = Boolean::multi_and(cs, &other_flags).or(cs, order_flag);
        Boolean::enforce_equal(cs, &final_flag, &true_flag);
    }

    // Now delegation circuit
    {
        let mut buffer = [UInt32::zero(cs); BLAKE2S_BLOCK_SIZE_U32_WORDS];
        buffer[0] = blake_state.delegation_type;
        transcript.absorb(cs, &buffer);

        Num::enforce_equal(cs, &blake_state.circuit_sequence.into_num(), &zero);
        let blake_delegation_type = UInt32::allocated_constant(cs, BLAKE2S_DELEGATION_CSR_REGISTER);
        Num::enforce_equal(
            cs,
            &blake_state.delegation_type.into_num(),
            &blake_delegation_type.into_num(),
        );

        let expected_setup_caps =
            <[WrappedMerkleTreeCap<F, TREE_CAP_SIZE>; NUM_COSETS]>::allocate_constant(
                cs,
                setups::all_parameters::ALL_DELEGATION_CIRCUITS_PARAMS[0].2,
            );

        for (cap, expected_cap) in blake_state
            .setup_caps
            .iter()
            .zip(expected_setup_caps.iter())
        {
            cap.enforce_equal(cs, expected_cap);
        }

        for cap in blake_state.memory_caps.iter() {
            for chunk in cap.cap.iter() {
                transcript.absorb(cs, chunk);
            }
        }

        blake_state
            .memory_challenges
            .enforce_equal(cs, &unified_proofs_states[0].memory_challenges);
        for (l, r) in blake_state
            .delegation_challenges
            .iter()
            .zip(unified_proofs_states[0].delegation_challenges.iter())
        {
            l.enforce_equal(cs, r);
        }

        grand_product_accumulator =
            grand_product_accumulator.mul(cs, &blake_state.grand_product_accumulator);
        delegation_set_accumulator =
            delegation_set_accumulator.sub(cs, &blake_state.delegation_argument_accumulator[0]);
    }

    let memory_seed = transcript.finalize_reset(cs);

    let (
        memory_argument_challenges,
        delegation_argument_challenges,
        machine_state_permutation_challenges,
    ) = draw_from_transcript_seed_with_state_permutation(
        cs,
        memory_seed,
        crate::active_security::ACTIVE_SECURITY_MODEL.memory_delegation_pow_bits() as u32,
        pow_challenge,
    );

    unified_proofs_states.iter().for_each(|proof_state| {
        memory_argument_challenges.enforce_equal(cs, &proof_state.memory_challenges);
        if NUM_DELEGATION_CHALLENGES > 0 {
            delegation_argument_challenges.enforce_equal(cs, &proof_state.delegation_challenges[0]);
        }
        machine_state_permutation_challenges
            .enforce_equal(cs, &proof_state.machine_state_permutation_challenges[0]);
    });

    // conclude that our memory argument is valid
    let register_contribution = produce_register_contribution_into_memory_accumulator_raw(
        cs,
        &final_registers_state,
        memory_argument_challenges.memory_argument_linearization_challenges,
        memory_argument_challenges.memory_argument_gamma,
    );
    let machine_state_contribution = produce_pc_into_permutation_accumulator_raw(
        cs,
        INITIAL_PC,
        split_timestamp(INITIAL_TIMESTAMP),
        final_pc,
        (final_timestamp[0], final_timestamp[1]),
        &machine_state_permutation_challenges.linearization_challenges,
        &machine_state_permutation_challenges.additive_term,
    );

    grand_product_accumulator = grand_product_accumulator.mul(cs, &register_contribution);
    grand_product_accumulator = grand_product_accumulator.mul(cs, &machine_state_contribution);

    let one_m4 = MersenneQuartic::one(cs);
    let zero_m4 = MersenneQuartic::zero(cs);
    grand_product_accumulator.enforce_equal(cs, &one_m4);
    delegation_set_accumulator.enforce_equal(cs, &zero_m4);

    // Now we only need to reason about "which program do we execute", and "did it finish succesfully or not".

    // the final piece is to make sure that we ended on the PC that is "expected" (basically - loops to itself, and at the right place),
    // so the program ended logical execution and we can conclude that the set of register values is meaningful

    let mut final_pc_buffer = [UInt32::zero(cs); BLAKE2S_BLOCK_SIZE_U32_WORDS];
    final_pc_buffer[0] = final_pc;

    let mut result_hasher = Blake2sWrappedBufferingTranscript::new(cs);
    result_hasher.absorb(cs, &final_pc_buffer);
    for cap in unified_proofs_states[0].setup_caps.iter() {
        for chunk in cap.cap.iter() {
            result_hasher.absorb(cs, chunk);
        }
    }
    let end_params_output = result_hasher.finalize_reset(cs);

    // We know exactly what program should be executed, so end_params_output should be constant
    for i in 0..8 {
        let end_params_word = UInt32::from_le_bytes(cs, end_params_output.0[i].inner);
        let expected_word = UInt32::allocate_constant(cs, binary_commitment.end_params[i]);
        Num::enforce_equal(cs, &expected_word.into_num(), &end_params_word.into_num());
    }
}

fn prepare_and_allocate_public_inputs<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    final_registers_state: [UInt32<F>; NUM_REGISTERS * 3],
    check_aux_params: bool,
    binary_commitment: &BinaryCommitment,
) {
    // We hash needed data for the L1 verifier
    // registers 10-17 - those are the output of the base program
    // registers 18-25 - those are the aux registers that we use to store
    // the hash of the execution trace, and the chain of executed programs
    let flattened_public_input: Vec<_> = final_registers_state
        .chunks(3)
        .skip(10)
        .take(16)
        .flat_map(|chunk| chunk[0].decompose_into_bytes(cs))
        .collect();

    use boojum::gadgets::keccak256;
    // Computed unconditionally: the hashed path below consumes it. In the
    // `check_aux_params` branch the result is discarded, but keccak is still run so
    // the keccak gates/tables stay present in both modes, keeping the circuit
    // skeleton uniform. Skipping it in check mode is a possible future optimization
    // (it would change the check-mode VK).
    let input_keccak_hash = keccak256::keccak256(cs, &flattened_public_input);

    let public_input_source: Vec<_> = if check_aux_params {
        // Pack registers 10..=16 (7 registers = 28 bytes) directly as the public
        // input, bypassing keccak. The loop below consumes exactly
        // NUM_RISC_WRAPPER_PUBLIC_INPUTS * take_by = 4 * 7 = 28 bytes, matching the
        // 28-byte truncation the hashed path applies to the 32-byte keccak digest.
        // We assume the base program has placed a keccak hash in these registers.
        final_registers_state
            .chunks(3)
            .skip(10)
            .take(7)
            .flat_map(|chunk| chunk[0].decompose_into_bytes(cs))
            .collect()
    } else {
        input_keccak_hash.to_vec()
    };

    let take_by = F::CAPACITY_BITS / 8;

    for chunk in public_input_source
        .chunks_exact(take_by)
        .take(NUM_RISC_WRAPPER_PUBLIC_INPUTS)
    {
        let mut lc = Vec::with_capacity(chunk.len());
        // treat as BE
        for (idx, el) in chunk.iter().rev().enumerate() {
            lc.push((el.get_variable(), F::SHIFTS[idx * 8]));
        }
        let as_num = Num::linear_combination(cs, &lc);
        use boojum::cs::gates::PublicInputGate;
        let gate = PublicInputGate::new(as_num.get_variable());
        gate.add_to_cs(cs);
    }

    if check_aux_params {
        // Constrain registers 18..26 (8 values) to equal the aux_params constant
        // baked into the binary commitment. Mirrors the end_params check above.
        for i in 0..8 {
            let expected = UInt32::allocate_constant(cs, binary_commitment.aux_params[i]);
            let actual = final_registers_state[(18 + i) * 3];
            Num::enforce_equal(cs, &expected.into_num(), &actual.into_num());
        }
    }
}

pub fn produce_register_contribution_into_memory_accumulator_raw<
    F: SmallField,
    CS: ConstraintSystem<F>,
>(
    cs: &mut CS,
    register_final_data: &[UInt32<F>; NUM_REGISTERS * 3],
    memory_argument_linearization_challenges: [MersenneQuartic<F>;
        NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES],
    memory_argument_gamma: MersenneQuartic<F>,
) -> MersenneQuartic<F> {
    let mut write_set_contribution = MersenneQuartic::one(cs);
    // all registers are write 0 at timestamp 0
    for reg_idx in 0..NUM_REGISTERS {
        let mut contribution = MersenneQuartic::one(cs); // is_register == 1, without challenge
        let mut t =
            memory_argument_linearization_challenges[MEM_ARGUMENT_CHALLENGE_POWERS_ADDRESS_LOW_IDX];
        let idx_allocated = MersenneField::allocate_constant(cs, Mersenne31Field(reg_idx as u32));
        t = t.mul_by_base(cs, &idx_allocated);
        contribution = contribution.add(cs, &t);
        contribution = contribution.add(cs, &memory_argument_gamma);
        write_set_contribution = write_set_contribution.mul(cs, &contribution);
    }

    let mut read_set_contribution = MersenneQuartic::one(cs);
    // all registers are write 0 at timestamp 0
    for (reg_idx, value_and_timestamp) in register_final_data.chunks(3).enumerate() {
        let [value_low, value_high] = split_uint32_into_pair_mersenne(cs, &value_and_timestamp[0]);
        let timestamp_low =
            MersenneField::from_variable_checked(cs, value_and_timestamp[1].get_variable(), true);
        let timestamp_high =
            MersenneField::from_variable_checked(cs, value_and_timestamp[2].get_variable(), true);

        let mut contribution = MersenneQuartic::one(cs); // is_register == 1, without challenge
        let mut t =
            memory_argument_linearization_challenges[MEM_ARGUMENT_CHALLENGE_POWERS_ADDRESS_LOW_IDX];
        let idx_allocated = MersenneField::allocate_constant(cs, Mersenne31Field(reg_idx as u32));
        t = t.mul_by_base(cs, &idx_allocated);
        contribution = contribution.add(cs, &t);

        let mut t = memory_argument_linearization_challenges
            [MEM_ARGUMENT_CHALLENGE_POWERS_TIMESTAMP_LOW_IDX];
        t = t.mul_by_base(cs, &timestamp_low);
        contribution = contribution.add(cs, &t);

        let mut t = memory_argument_linearization_challenges
            [MEM_ARGUMENT_CHALLENGE_POWERS_TIMESTAMP_HIGH_IDX];
        t = t.mul_by_base(cs, &timestamp_high);
        contribution = contribution.add(cs, &t);

        let mut t =
            memory_argument_linearization_challenges[MEM_ARGUMENT_CHALLENGE_POWERS_VALUE_LOW_IDX];
        t = t.mul_by_base(cs, &value_low);
        contribution = contribution.add(cs, &t);

        let mut t =
            memory_argument_linearization_challenges[MEM_ARGUMENT_CHALLENGE_POWERS_VALUE_HIGH_IDX];
        t = t.mul_by_base(cs, &value_high);
        contribution = contribution.add(cs, &t);

        contribution = contribution.add(cs, &memory_argument_gamma);
        read_set_contribution = read_set_contribution.mul(cs, &contribution);
    }

    let t = read_set_contribution.inverse_or_zero(cs);
    write_set_contribution.mul(cs, &t)
}

/// (PC, timestamp)
pub fn produce_pc_into_permutation_accumulator_raw<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    initial_pc: u32,
    initial_timestamp: (u32, u32),
    final_pc: UInt32<F>,
    final_timestamp: (UInt32<F>, UInt32<F>),
    state_permutation_argument_linearization_challenges: &[MersenneQuartic<F>;
        NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES],
    state_permutation_argument_gamma: &MersenneQuartic<F>,
) -> MersenneQuartic<F> {
    let mut write_set_contribution = MersenneQuartic::one(cs);
    let mut read_set_contribution = MersenneQuartic::one(cs);

    let initial_pc = UInt32::allocate_constant(cs, initial_pc);
    let initial_timestamp = (
        MersenneField::allocate_constant(cs, Mersenne31Field(initial_timestamp.0)),
        MersenneField::allocate_constant(cs, Mersenne31Field(initial_timestamp.1)),
    );

    // let final_pc = MersenneField::from_uint32_with_reduction(cs, final_pc);
    let final_timestamp = (
        MersenneField::from_uint32_with_reduction(cs, final_timestamp.0),
        MersenneField::from_uint32_with_reduction(cs, final_timestamp.1),
    );

    for (dst, (pc, (ts_low, ts_high))) in [&mut write_set_contribution, &mut read_set_contribution]
        .into_iter()
        .zip([(initial_pc, initial_timestamp), (final_pc, final_timestamp)].into_iter())
    {
        let [pc_low, pc_high] = split_uint32_into_pair_mersenne(cs, &pc);
        // PC low without challenge
        let mut contribution = MersenneQuartic::from_base(cs, pc_low);
        // PC high
        let mut t = state_permutation_argument_linearization_challenges
            [MACHINE_STATE_CHALLENGE_POWERS_PC_HIGH_IDX];
        t = t.mul_by_base(cs, &pc_high);
        contribution = contribution.add(cs, &t);
        // timestamp low
        let mut t = state_permutation_argument_linearization_challenges
            [MACHINE_STATE_CHALLENGE_POWERS_TIMESTAMP_LOW_IDX];
        t = t.mul_by_base(cs, &ts_low);
        contribution = contribution.add(cs, &t);
        // timestamp high
        let mut t = state_permutation_argument_linearization_challenges
            [MACHINE_STATE_CHALLENGE_POWERS_TIMESTAMP_HIGH_IDX];
        t = t.mul_by_base(cs, &ts_high);
        contribution = contribution.add(cs, &t);
        // additive term
        contribution = contribution.add(cs, state_permutation_argument_gamma);
        *dst = dst.mul(cs, &contribution);
    }

    let mut result = write_set_contribution;
    let t = read_set_contribution.inverse_or_zero(cs);
    result = result.mul(cs, &t);

    result
}

fn split_uint32_into_pair_mersenne<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    uint32_value: &UInt32<F>,
) -> [MersenneField<F>; 2] {
    let bytes = uint32_value.decompose_into_bytes(cs);
    let chunks = [
        UInt16::from_le_bytes(cs, [bytes[0], bytes[1]]),
        UInt16::from_le_bytes(cs, [bytes[2], bytes[3]]),
    ];

    chunks.map(|chunk| MersenneField::from_variable_checked(cs, chunk.get_variable(), true))
}

fn split_uint32_into_pair_uint16<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    uint32_value: UInt32<F>,
) -> (UInt16<F>, UInt16<F>) {
    let bytes = uint32_value.decompose_into_bytes(cs);
    (
        UInt16::from_le_bytes(cs, [bytes[0], bytes[1]]),
        UInt16::from_le_bytes(cs, [bytes[2], bytes[3]]),
    )
}

pub fn draw_from_transcript_seed_with_state_permutation<F: SmallField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    mut seed: SeedWrapped<F>,
    pow_bits: u32,
    pow_challenge: [UInt32<F>; 2],
) -> (
    WrappedExternalMemoryArgumentChallenges<F>,
    WrappedExternalDelegationArgumentChallenges<F>,
    WrappedExternalMachineStateArgumentChallenges<F>,
) {
    if pow_bits > 0 {
        let mut transcript_hasher = Blake2sStateGate::<F>::new(cs);

        Blake2sWrappedTranscript::verify_pow_using_hasher(
            cs,
            &mut transcript_hasher,
            &mut seed,
            pow_challenge,
            pow_bits,
        );
    }

    unsafe {
        const TOTAL_CHALLENGES: usize = (NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES
            + 1
            + NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES
            + 1
            + NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES
            + 1)
            * 4;

        let mut transcript_challenges = vec![];

        let mut it = if pow_bits > 0 {
            transcript_challenges.resize(
                (TOTAL_CHALLENGES + 1).next_multiple_of(BLAKE2S_DIGEST_SIZE_U32_WORDS),
                UInt32::zero(cs),
            );
            Blake2sWrappedTranscript::draw_randomness(cs, &mut seed, &mut transcript_challenges);

            transcript_challenges[1..].as_chunks::<4>().0.iter()
        } else {
            transcript_challenges.resize(
                (TOTAL_CHALLENGES).next_multiple_of(BLAKE2S_DIGEST_SIZE_U32_WORDS),
                UInt32::zero(cs),
            );
            Blake2sWrappedTranscript::draw_randomness(cs, &mut seed, &mut transcript_challenges);

            transcript_challenges.as_chunks::<4>().0.iter()
        };

        let memory_argument_linearization_challenges: [MersenneQuartic<F>;
            NUM_MEM_ARGUMENT_LINEARIZATION_CHALLENGES] = core::array::from_fn(|_| {
            MersenneQuartic::from_coeffs(
                it.next()
                    .unwrap_unchecked()
                    .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
            )
        });
        let memory_argument_gamma = MersenneQuartic::from_coeffs(
            it.next()
                .unwrap_unchecked()
                .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
        );

        let delegation_argument_linearization_challenges: [MersenneQuartic<F>;
            NUM_DELEGATION_ARGUMENT_LINEARIZATION_CHALLENGES] = core::array::from_fn(|_| {
            MersenneQuartic::from_coeffs(
                it.next()
                    .unwrap_unchecked()
                    .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
            )
        });
        let delegation_argument_gamma = MersenneQuartic::from_coeffs(
            it.next()
                .unwrap_unchecked()
                .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
        );

        let machine_state_permutation_argument_linearization_challenges: [MersenneQuartic<F>;
            NUM_MACHINE_STATE_LINEARIZATION_CHALLENGES] = core::array::from_fn(|_| {
            MersenneQuartic::from_coeffs(
                it.next()
                    .unwrap_unchecked()
                    .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
            )
        });

        let machine_state_permutation_argument_additive_term = MersenneQuartic::from_coeffs(
            it.next()
                .unwrap_unchecked()
                .map(|el| MersenneField::from_uint32_with_reduction(cs, el)),
        );

        let memory_argument = WrappedExternalMemoryArgumentChallenges {
            memory_argument_linearization_challenges,
            memory_argument_gamma,
        };

        let delegation_argument = WrappedExternalDelegationArgumentChallenges {
            delegation_argument_linearization_challenges,
            delegation_argument_gamma,
        };

        let machine_state_permutation_argument = WrappedExternalMachineStateArgumentChallenges {
            linearization_challenges: machine_state_permutation_argument_linearization_challenges,
            additive_term: machine_state_permutation_argument_additive_term,
        };

        (
            memory_argument,
            delegation_argument,
            machine_state_permutation_argument,
        )
    }
}
