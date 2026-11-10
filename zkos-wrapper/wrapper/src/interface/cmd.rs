use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context as _;
use serde::de::DeserializeOwned;

use crate::{
    SnarkWrapper, SnarkWrapperConfig, calculate_verification_key_hash, deserialize_from_file,
    serialize_to_file,
};

use super::utils::{ensure_output_dir, load_proof, output_path};

#[derive(Clone)]
pub enum VerifyStage {
    RiscWrapper,
    Compression,
    Snark,
}

// ==============================================================================
// Public Command Entry Points
// ==============================================================================
//
// The stateful SnarkWrapper is the main library API now. Even mid-pipeline
// resume commands flow through it, with optional VK artifacts seeding the
// reusable setup chain when the caller already has them on disk.

fn load_json_artifact<T: DeserializeOwned>(path: &Path, label: &str) -> anyhow::Result<T> {
    tracing::info!("Loading {label} from {}", path.display());
    deserialize_from_file(&path.to_string_lossy())
        .with_context(|| format!("while attempting to load {label}"))
}

fn load_optional_json_artifact<T: DeserializeOwned>(
    path: &Option<PathBuf>,
    label: &str,
) -> anyhow::Result<Option<T>> {
    path.as_ref()
        .map(|path| load_json_artifact(path, label))
        .transpose()
}

pub fn cmd_prove_all(
    proof: PathBuf,
    bin: Option<PathBuf>,
    text: Option<PathBuf>,
    output_dir: PathBuf,
    trusted_setup: Option<PathBuf>,
    use_zk: bool,
    save_intermediates: bool,
    check_aux_params: bool,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    ensure_output_dir(&output_dir)?;
    let total_start = Instant::now();
    let program_proof = load_proof(&proof).context("Can't load the proof")?;
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin,
        text,
        trusted_setup,
        threads,
        check_aux_params,
        risc_wrapper_vk: None,
        compression_vk: None,
        snark_vk: None,
        binary_commitment: None,
    })?;

    let risc_wrapper_proof = wrapper.prove_risc_wrapper(program_proof)?;

    if save_intermediates {
        serialize_to_file(
            &risc_wrapper_proof,
            &output_path(&output_dir, "risc_wrapper_proof.json"),
        )?;
        serialize_to_file(
            wrapper.risc_wrapper_vk()?,
            &output_path(&output_dir, "risc_wrapper_vk.json"),
        )?;
        tracing::info!("Saved intermediate Phase 1 outputs");
    }

    let compression_proof = wrapper.prove_compression(risc_wrapper_proof)?;

    if save_intermediates {
        serialize_to_file(
            &compression_proof,
            &output_path(&output_dir, "compression_proof.json"),
        )?;
        serialize_to_file(
            wrapper.compression_vk()?,
            &output_path(&output_dir, "compression_vk.json"),
        )?;
        tracing::info!("Saved intermediate Phase 2 outputs");
    }

    let snark_proof = wrapper.prove_snark(compression_proof, use_zk)?;

    serialize_to_file(&snark_proof, &output_path(&output_dir, "snark_proof.json"))?;
    serialize_to_file(
        wrapper.snark_vk()?,
        &output_path(&output_dir, "snark_vk.json"),
    )?;

    let vk_hash = calculate_verification_key_hash(wrapper.snark_vk()?.clone());
    tracing::info!("SNARK VK hash: {vk_hash:?}");
    tracing::info!(
        "=== Total pipeline time: {:.1}s",
        total_start.elapsed().as_secs_f64()
    );

    Ok(())
}

pub fn cmd_prove_risc_wrapper(
    proof: PathBuf,
    bin: Option<PathBuf>,
    text: Option<PathBuf>,
    output_dir: PathBuf,
    check_aux_params: bool,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    ensure_output_dir(&output_dir)?;
    let program_proof = load_proof(&proof).context("Can't load the proof")?;
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin,
        text,
        trusted_setup: None,
        threads,
        check_aux_params,
        risc_wrapper_vk: None,
        compression_vk: None,
        snark_vk: None,
        binary_commitment: None,
    })?;

    let risc_wrapper_proof = wrapper.prove_risc_wrapper(program_proof)?;

    serialize_to_file(
        &risc_wrapper_proof,
        &output_path(&output_dir, "risc_wrapper_proof.json"),
    )?;
    serialize_to_file(
        wrapper.risc_wrapper_vk()?,
        &output_path(&output_dir, "risc_wrapper_vk.json"),
    )?;

    Ok(())
}

pub fn cmd_prove_compression(
    risc_wrapper_proof_path: PathBuf,
    risc_wrapper_vk_path: Option<PathBuf>,
    bin: Option<PathBuf>,
    text: Option<PathBuf>,
    output_dir: PathBuf,
    check_aux_params: bool,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    ensure_output_dir(&output_dir)?;
    let risc_wrapper_proof = load_json_artifact(&risc_wrapper_proof_path, "RISC wrapper proof")?;
    let risc_wrapper_vk = load_optional_json_artifact::<crate::RiscWrapperVK>(
        &risc_wrapper_vk_path,
        "RISC wrapper VK",
    )?;
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin,
        text,
        trusted_setup: None,
        threads,
        check_aux_params,
        risc_wrapper_vk,
        compression_vk: None,
        snark_vk: None,
        binary_commitment: None,
    })?;

    let compression_proof = wrapper.prove_compression(risc_wrapper_proof)?;

    serialize_to_file(
        &compression_proof,
        &output_path(&output_dir, "compression_proof.json"),
    )?;
    serialize_to_file(
        wrapper.compression_vk()?,
        &output_path(&output_dir, "compression_vk.json"),
    )?;

    Ok(())
}

pub fn cmd_prove_snark(
    compression_proof_path: PathBuf,
    compression_vk_path: Option<PathBuf>,
    bin: Option<PathBuf>,
    text: Option<PathBuf>,
    output_dir: PathBuf,
    trusted_setup: Option<PathBuf>,
    use_zk: bool,
    check_aux_params: bool,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    ensure_output_dir(&output_dir)?;
    let compression_proof = load_json_artifact(&compression_proof_path, "compression proof")?;
    let compression_vk = load_optional_json_artifact::<crate::CompressionVK>(
        &compression_vk_path,
        "compression VK",
    )?;
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin,
        text,
        trusted_setup,
        threads,
        check_aux_params,
        risc_wrapper_vk: None,
        compression_vk,
        snark_vk: None,
        binary_commitment: None,
    })?;

    let snark_proof = wrapper.prove_snark(compression_proof, use_zk)?;

    serialize_to_file(&snark_proof, &output_path(&output_dir, "snark_proof.json"))?;
    serialize_to_file(
        wrapper.snark_vk()?,
        &output_path(&output_dir, "snark_vk.json"),
    )?;

    let vk_hash = calculate_verification_key_hash(wrapper.snark_vk()?.clone());
    tracing::info!("SNARK VK hash: {vk_hash:?}");

    Ok(())
}

pub fn cmd_generate_vk(
    output_dir: PathBuf,
    bin: Option<PathBuf>,
    text: Option<PathBuf>,
    trusted_setup: Option<PathBuf>,
    check_aux_params: bool,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    ensure_output_dir(&output_dir)?;
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin,
        text,
        trusted_setup,
        threads,
        check_aux_params,
        risc_wrapper_vk: None,
        compression_vk: None,
        snark_vk: None,
        binary_commitment: None,
    })?;

    serialize_to_file(
        wrapper.risc_wrapper_vk()?,
        &output_path(&output_dir, "risc_wrapper_vk.json"),
    )?;
    tracing::info!("Saved risc_wrapper_vk.json");

    serialize_to_file(
        wrapper.compression_vk()?,
        &output_path(&output_dir, "compression_vk.json"),
    )?;
    tracing::info!("Saved compression_vk.json");

    serialize_to_file(
        wrapper.snark_vk()?,
        &output_path(&output_dir, "snark_vk.json"),
    )?;
    tracing::info!("Saved snark_vk.json");

    let vk_hash = calculate_verification_key_hash(wrapper.snark_vk()?.clone());
    tracing::info!("SNARK VK hash: {vk_hash:?}");

    Ok(())
}

pub fn cmd_compute_aux_params(
    bin: PathBuf,
    text: PathBuf,
    output: Option<PathBuf>,
) -> anyhow::Result<()> {
    let binary = std::fs::read(&bin)
        .with_context(|| format!("while reading the binary at {}", bin.display()))?;
    let text_data = std::fs::read(&text)
        .with_context(|| format!("while reading the text section at {}", text.display()))?;

    let commitment = crate::circuits::BinaryCommitment::from_base_binary(&binary, &text_data);
    tracing::info!("aux_params: {:?}", commitment.aux_params);

    if let Some(out) = output {
        serialize_to_file(&commitment.aux_params, &out.to_string_lossy())?;
        tracing::info!("Wrote aux_params to {}", out.display());
    }

    Ok(())
}

pub fn cmd_vk_hash(vk_path: PathBuf) -> anyhow::Result<()> {
    tracing::info!("Loading VK from {}", vk_path.display());
    let vk = deserialize_from_file(vk_path.to_str().unwrap())?;
    let vk_hash = calculate_verification_key_hash(vk);
    tracing::info!("SNARK VK hash: {vk_hash:?}");
    Ok(())
}

pub fn cmd_verify(stage: VerifyStage, proof_path: PathBuf, vk_path: PathBuf) -> anyhow::Result<()> {
    let proof_str = proof_path.to_str().unwrap();
    let vk_str = vk_path.to_str().unwrap();

    let is_valid = match stage {
        VerifyStage::RiscWrapper => {
            tracing::info!("Verifying RISC wrapper proof...");
            let proof = deserialize_from_file(proof_str).context("proof")?;
            let vk = deserialize_from_file(vk_str).context("vk")?;
            crate::verify_risc_wrapper_proof(&proof, &vk)
        }
        VerifyStage::Compression => {
            tracing::info!("Verifying compression proof...");
            let proof = deserialize_from_file(proof_str).context("proof")?;
            let vk = deserialize_from_file(vk_str).context("vk")?;
            crate::verify_compression_proof(&proof, &vk)
        }
        VerifyStage::Snark => {
            tracing::info!("Verifying SNARK proof...");
            let proof = deserialize_from_file(proof_str).context("proof")?;
            let vk = deserialize_from_file(vk_str).context("vk")?;
            crate::verify_snark_wrapper_proof(&proof, &vk)
        }
    };

    if is_valid {
        tracing::info!("Proof is VALID");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Proof verification FAILED"))
    }
}
