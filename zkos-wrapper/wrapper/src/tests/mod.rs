use crate::inner_verifiers::unified_reduced::NUM_QUERIES;
use crate::inner_verifiers::unified_reduced::skeleton::*;
use crate::risc_verifier;
use crate::transcript::*;
use crate::wrapper_utils::verifier_traits::CircuitBlake2sForEverythingVerifier;
use crate::wrapper_utils::verifier_traits::CircuitLeafInclusionVerifier;
use anyhow::Context as _;
use boojum::cs::LookupParameters;
use boojum::cs::gates::FmaGateInBaseFieldWithoutConstant;
use boojum::cs::gates::NopGate;
use boojum::cs::gates::SelectionGate;
use boojum::cs::gates::ZeroCheckGate;
use boojum::gadgets::tables::RangeCheck15BitsTable;
use boojum::gadgets::tables::RangeCheck16BitsTable;
use boojum::gadgets::tables::create_range_check_15_bits_table;
use boojum::gadgets::tables::create_range_check_16_bits_table;
use boojum::{
    cs::{
        CSGeometry,
        gates::{ConstantsAllocatorGate, ReductionGate, U32TriAddCarryAsChunkGate, UIntXAddGate},
        traits::{cs::ConstraintSystem, gate::GatePlacementStrategy},
    },
    dag::{CircuitResolverOpts, StCircuitResolver},
    gadgets::blake2s::mixing_function::Word,
    gadgets::{
        tables::{
            byte_split::{ByteSplitTable, create_byte_split_table},
            xor8::{Xor8Table, create_xor8_table},
        },
        traits::witnessable::WitnessHookable,
        u32::UInt32,
    },
};
use risc_verifier::prover::prover_stages::Proof as RiscProof;
use risc_verifier::prover::prover_stages::unrolled_prover::UnrolledModeProof as RiscUnrolledProof;
use std::alloc::Global;

use risc_verifier::concrete::size_constants::*;
use risc_verifier::prover::definitions::Blake2sForEverythingVerifier;
use risc_verifier::verifier_common::{DefaultNonDeterminismSource, ProofOutput, ProofPublicInputs};

type F = boojum::field::goldilocks::GoldilocksField;

mod blake2s_tests;
mod compression_tests;
mod risc_wrapper_tests;
mod size_estimator;
mod snark_wrapper_tests;

#[test]
fn all_layers_full_test() {
    tracing::info!("Testing Risc wrapper");
    risc_wrapper_tests::risc_wrapper_full_test();
    // These tests may use a lot of memory, so we can try to free up some space afterwards.
    // It is especially important on CI machines.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }

    tracing::info!("Testing compression");
    compression_tests::compression_full_test();
    tracing::info!("Testing Snark wrapper");
    snark_wrapper_tests::snark_wrapper_full_test();
}

#[test]
fn all_layers_setup_test() {
    risc_wrapper_tests::risc_wrapper_setup_test();
    compression_tests::compression_setup_test();
    snark_wrapper_tests::snark_wrapper_setup_test();
}

pub(crate) const RISC_PROGRAM_BIN_PATH: &str = "testing_data/risc_app.bin";
pub(crate) const RISC_PROGRAM_TEXT_PATH: &str = "testing_data/risc_app.text";

#[cfg(feature = "security_80")]
pub(crate) mod path_constants {
    pub(crate) const RISC_PROOF_PATH: &str = "testing_data/risc_proof_80sb";
    pub(crate) const RISC_WRAPPER_PROOF_PATH: &str = "testing_data/risc_wrapper_proof_80sb";
    pub(crate) const RISC_WRAPPER_VK_PATH: &str = "testing_data/risc_wrapper_vk_80sb";
    pub(crate) const COMPRESSION_PROOF_PATH: &str = "testing_data/compression_proof_80sb";
    pub(crate) const COMPRESSION_VK_PATH: &str = "testing_data/compression_vk_80sb";
    pub(crate) const SNARK_WRAPPER_PROOF_PATH: &str = "testing_data/snark_wrapper_proof_80sb";
    pub(crate) const SNARK_WRAPPER_VK_PATH: &str = "testing_data/snark_wrapper_vk_80sb";
}

#[cfg(feature = "security_100")]
pub(crate) mod path_constants {
    pub(crate) const RISC_PROOF_PATH: &str = "testing_data/risc_proof_100sb";
    pub(crate) const RISC_WRAPPER_PROOF_PATH: &str = "testing_data/risc_wrapper_proof_100sb";
    pub(crate) const RISC_WRAPPER_VK_PATH: &str = "testing_data/risc_wrapper_vk_100sb";
    pub(crate) const COMPRESSION_PROOF_PATH: &str = "testing_data/compression_proof_100sb";
    pub(crate) const COMPRESSION_VK_PATH: &str = "testing_data/compression_vk_100sb";
    pub(crate) const SNARK_WRAPPER_PROOF_PATH: &str = "testing_data/snark_wrapper_proof_100sb";
    pub(crate) const SNARK_WRAPPER_VK_PATH: &str = "testing_data/snark_wrapper_vk_100sb";
}

use path_constants::*;

pub(crate) fn serialize_to_bin_file<T: serde::ser::Serialize>(
    content: &T,
    filename: &str,
) -> anyhow::Result<()> {
    let file =
        std::fs::File::create(filename).with_context(|| format!("Can't create file {filename}"))?;
    let mut writer = std::io::BufWriter::new(file);
    bincode::serde::encode_into_std_write(content, &mut writer, bincode::config::standard())
        .with_context(|| format!("Can't bincode-serialize {filename}"))?;
    Ok(())
}

pub(crate) fn deserialize_from_bin_file<T: serde::de::DeserializeOwned>(
    filename: &str,
) -> anyhow::Result<T> {
    let file =
        std::fs::File::open(filename).with_context(|| format!("Can't open file {filename}"))?;
    let mut reader = std::io::BufReader::new(file);
    bincode::serde::decode_from_std_read(&mut reader, bincode::config::standard())
        .with_context(|| format!("Can't bincode-deserialize the contents of file {filename}"))
}

/// Test for updating testing_data/risc_proof_{80,100}sb from JSON to bincode in place.
///
/// Run via:
///   RUST_MIN_STACK=16777216 cargo test convert_risc_proof_from_json -- --ignored --nocapture
///   RUST_MIN_STACK=16777216 cargo test convert_risc_proof_from_json --no-default-features --features security_100 -- --ignored --nocapture
#[test]
#[ignore]
fn convert_risc_proof_from_json() {
    use execution_utils::unrolled::UnrolledProgramProof;

    let path = RISC_PROOF_PATH;
    let before = std::fs::metadata(path).unwrap().len();
    let value: UnrolledProgramProof = {
        let f = std::fs::File::open(path).unwrap();
        serde_json::from_reader(std::io::BufReader::new(f)).unwrap()
    };
    let tmp = format!("{path}.tmp");
    serialize_to_bin_file(&value, &tmp).unwrap();
    std::fs::rename(&tmp, path).unwrap();
    let after = std::fs::metadata(path).unwrap().len();
    println!("{path}: {before} -> {after} bytes");
}
