use std::mem::MaybeUninit;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::u32::UInt32;
use circuit_mersenne_field::extension_trait::CircuitFieldExpression;
use circuit_mersenne_field::{MersenneComplex, MersenneField, MersenneQuartic};

use crate::risc_verifier;
use risc_verifier::blake2s_u32::*;
use risc_verifier::concrete::size_constants::*;
// use risc_verifier::concrete::skeleton_instance::BASE_CIRCUIT_QUERY_VALUES_NO_PADDING_U32_WORDS;
use risc_verifier::concrete::skeleton_instance::ProofSkeletonInstance;
use risc_verifier::concrete::skeleton_instance::QueryValuesInstance;
use risc_verifier::field::*;
use risc_verifier::prover::cs::definitions::*;
use risc_verifier::skeleton::{ProofSkeleton, QueryValues};
use risc_verifier::verifier_common;
use risc_verifier::verifier_common::non_determinism_source::NonDeterminismSource;
use risc_verifier::verifier_common::{
    SizedProofPowChallenges, SizedProofSecurityConfig, transcript_challenge_array_size,
};

use crate::active_security::ActiveSecurity;
use crate::wrapper_utils::prover_structs::*;

pub(crate) mod imports;
pub mod skeleton;

pub use crate::transcript::*;
use crate::wrapper_utils::verifier_traits::*;
use skeleton::*;

// Airbender now exposes verifier geometry through a security marker. The wrapper
// still compiles one security model at a time, so the shared verifier code can
// keep using concrete constants selected by the active Cargo feature.
type AirbenderProofSkeletonInstance = ProofSkeletonInstance<ActiveSecurity>;
type AirbenderQueryValuesInstance = QueryValuesInstance<ActiveSecurity>;
type ActiveGeometry = Geometry<ActiveSecurity>;

const SECURITY_CONFIG: SizedProofSecurityConfig<NUM_FRI_STEPS> = ActiveGeometry::SECURITY_CONFIG;
pub(crate) const NUM_QUERIES: usize = ActiveGeometry::NUM_QUERIES;
const NUM_QUERY_VALUES: usize = ActiveGeometry::NUM_QUERY_VALUES;
const NUM_REQUIRED_WORDS_FOR_QUERY_INDEXES: usize =
    ActiveGeometry::NUM_REQUIRED_WORDS_FOR_QUERY_INDEXES;
const LAST_FRI_STEP_EXPOSE_LEAFS: bool = ActiveGeometry::LAST_FRI_STEP_EXPOSE_LEAFS;
const LAST_FRI_STEP_LEAFS_TOTAL_SIZE_PER_COSET: usize =
    ActiveGeometry::LAST_FRI_STEP_LEAFS_TOTAL_SIZE_PER_COSET;
const NUM_FRI_STEPS_WITH_ORACLES: usize = ActiveGeometry::NUM_FRI_STEPS_WITH_ORACLES;
const TOTAL_FRI_ORACLES_PATHS_LENGTH: usize = ActiveGeometry::TOTAL_FRI_ORACLES_PATHS_LENGTH;
const TOTAL_FRI_LEAFS_SIZES: usize = ActiveGeometry::TOTAL_FRI_LEAFS_SIZES;

include!("../shared/verify_impl.rs");
