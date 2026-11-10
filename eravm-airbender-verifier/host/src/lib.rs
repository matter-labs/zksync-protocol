mod chain;
mod fri;
mod setup_download;
mod snark;

// The GPU FRI prover and its CUDA dependency are confined to these two modules,
// compiled only under the `gpu_fri` feature. The CUDA-free build omits them and
// uses the `build_fri_prover` / `prove_batches_fri` stubs defined below.
#[cfg(feature = "gpu_fri")]
mod gpu_fri;
#[cfg(feature = "gpu_fri")]
mod statistics;

use airbender_host::SecurityLevel;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zksync_cli_utils::BatchInputFile;

pub use crate::fri::{
    app_bin_path, app_text_path, default_fri_vk_path, dist_dir, load_vk_from_disk, FriProver,
    FriProverConfig, FriVerifier, ProveOutput, RawFriProof,
};
pub use crate::setup_download::{
    default_trusted_setup_download_url, default_trusted_setup_path,
    download_trusted_setup_if_not_present,
};
pub use crate::snark::{SnarkOptions, SnarkPipeline};
pub use zkos_wrapper::{deserialize_from_file, SnarkWrapperProof, SnarkWrapperVK};

// `build_fri_prover` and `prove_batches_fri` are always part of the public API.
// The GPU build re-exports the real implementations; the CUDA-free build uses
// the stubs below, so callers (server, host CLI) never need a `#[cfg]`.
#[cfg(feature = "gpu_fri")]
pub use crate::gpu_fri::{build_fri_prover, prove_batches_fri};

use crate::fri::{build_runner, load_raw_proof, run_batch, NativeVerify, FRI_PROOF_FILE_NAME};

/// CUDA-free stub: building a FRI prover requires the `gpu_fri` feature.
#[cfg(not(feature = "gpu_fri"))]
pub fn build_fri_prover(
    _dist_dir: &Path,
    _vk_path: &Path,
    _security: SecurityLevel,
    _config: FriProverConfig,
) -> Result<Box<dyn FriProver>> {
    anyhow::bail!(
        "FRI proving requires the `gpu_fri` feature; this is a CUDA-free build \
         (only `--mode snark-only` is supported)"
    )
}

/// CUDA-free stub: FRI proving requires the `gpu_fri` feature.
#[cfg(not(feature = "gpu_fri"))]
pub fn prove_batches_fri(
    _batch_inputs: &[BatchInputFile],
    _worker_threads: Option<usize>,
    _output_root: &Path,
    _vk_path: &Path,
    _security: SecurityLevel,
) -> Result<()> {
    anyhow::bail!("FRI proving requires the `gpu_fri` feature; this is a CUDA-free build")
}

// ==============================================================================
// Host Orchestration
// ==============================================================================
//
// The library entrypoints below keep the command behavior intentionally direct.
// Each top-level mode maps to a small loop that resolves inputs, delegates the
// actual proving work to either `fri` or `snark`, and applies the agreed output
// directory conventions.

pub fn run_batches(batch_inputs: &[BatchInputFile], jit: bool) -> Result<()> {
    use zksync_airbender_verifier::Verify;
    run_batches_with(batch_inputs, jit, Verify::verify)
}

/// [`run_batches`] with unproven slots served empty, for fixtures without read
/// proofs. Needs a guest built with `--features legacy-unproven-gaps`.
#[cfg(feature = "legacy-unproven-gaps")]
pub fn run_batches_legacy_unproven_gaps(batch_inputs: &[BatchInputFile], jit: bool) -> Result<()> {
    run_batches_with(
        batch_inputs,
        jit,
        zksync_airbender_verifier::verify_legacy_unproven_gaps,
    )
}

fn run_batches_with(
    batch_inputs: &[BatchInputFile],
    jit: bool,
    native_verify: NativeVerify,
) -> Result<()> {
    let runner = build_runner(&dist_dir(), jit)?;

    for batch_input in batch_inputs {
        run_batch(
            &runner,
            batch_input.number,
            &batch_input.path,
            native_verify,
        )
        .with_context(|| {
            format!(
                "while attempting to run batch {} from {} in transpiler",
                batch_input.number,
                batch_input.path.display()
            )
        })?;
    }

    Ok(())
}

/// Generates the FRI verification key for the current guest binary and
/// writes it to `output_path`, overwriting any previous file. Used by the
/// `gen-vks` host subcommand and the release-artifacts VK build.
pub fn generate_fri_vk(output_path: &Path, security: SecurityLevel) -> Result<()> {
    if output_path.exists() {
        std::fs::remove_file(output_path).with_context(|| {
            format!(
                "while attempting to remove stale VK at {}",
                output_path.display()
            )
        })?;
    }
    // `FriVerifier::load_or_generate` writes the VK to disk as a side effect
    // when the file is missing; that is exactly the behavior we want here.
    let _ = FriVerifier::load_or_generate(&dist_dir(), output_path, security)?;
    info!(path = %output_path.display(), "Wrote FRI verification key");
    Ok(())
}

/// Derives the SNARK wrapper VK from the trusted setup chain and writes it
/// to `output_path` as JSON. Used by the `gen-vks` host subcommand.
pub fn generate_snark_vk(output_path: &Path, snark_options: &SnarkOptions) -> Result<()> {
    use crate::snark::derive_snark_vk;
    let vk = derive_snark_vk(snark_options).context("while deriving SNARK VK")?;
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("while attempting to create {}", parent.display()))?;
        }
    }
    let path_string = output_path.to_string_lossy().into_owned();
    zkos_wrapper::serialize_to_file(&vk, &path_string)
        .with_context(|| format!("while attempting to write {}", output_path.display()))?;
    info!(path = %output_path.display(), "Wrote SNARK verification key");
    Ok(())
}

pub fn wrap_to_snark(
    proof_files: &[PathBuf],
    output_root: &Path,
    snark_options: &SnarkOptions,
    snark_vk: Option<SnarkWrapperVK>,
) -> Result<()> {
    let mut pipeline = SnarkPipeline::new(snark_options, snark_vk)?;

    for (index, proof_file) in proof_files.iter().enumerate() {
        let raw_proof = load_raw_proof(proof_file)
            .with_context(|| format!("while attempting to load {}", proof_file.display()))?;
        let output_dir = proof_file_output_dir(output_root, proof_file)?;
        pipeline
            .prove_and_save_outcome(raw_proof, &output_dir)
            .with_context(|| {
                format!(
                    "while attempting to wrap raw proof {} into a SNARK",
                    proof_file.display()
                )
            })?;

        info!(
            proof_file = %proof_file.display(),
            output_dir = %output_dir.display(),
            completed_proofs = index + 1,
            total_proofs = proof_files.len(),
            "Successfully generated SNARK proof"
        );
    }

    Ok(())
}

pub(crate) fn batch_output_dir(output_root: &Path, batch_number: u64) -> PathBuf {
    output_root.join(format!("batch-{batch_number}"))
}

fn proof_file_output_dir(output_root: &Path, proof_file: &Path) -> Result<PathBuf> {
    // Standard host-exported FRI proofs live under `batch-<n>/fri_proof.json`.
    // Preserve that batch-oriented layout when we wrap those artifacts into
    // SNARKs, so `prove-fri` and `prove-snark` agree on the same output root.
    if let Some(batch_number) = batch_number_from_exported_fri_proof_path(proof_file) {
        return Ok(batch_output_dir(output_root, batch_number));
    }

    let stem = proof_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context(
            "while attempting to derive an output directory name from the raw proof filename",
        )?;

    Ok(output_root.join(stem))
}

fn batch_number_from_exported_fri_proof_path(proof_file: &Path) -> Option<u64> {
    if proof_file.file_name()? != FRI_PROOF_FILE_NAME {
        return None;
    }

    let parent_name = proof_file.parent()?.file_name()?.to_str()?;
    let batch_number = parent_name.strip_prefix("batch-")?;
    batch_number.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{
        batch_number_from_exported_fri_proof_path, batch_output_dir, proof_file_output_dir,
    };
    use std::path::Path;

    #[test]
    fn batch_output_dir_uses_batch_prefix() {
        let output_dir = batch_output_dir(Path::new("/tmp/output"), 42);
        assert_eq!(output_dir, Path::new("/tmp/output/batch-42"));
    }

    #[test]
    fn proof_file_output_dir_uses_proof_stem() {
        let output_dir = proof_file_output_dir(
            Path::new("/tmp/output"),
            Path::new("/tmp/input/fri-proof.json"),
        )
        .expect("proof stem should be available");
        assert_eq!(output_dir, Path::new("/tmp/output/fri-proof"));
    }

    #[test]
    fn proof_file_output_dir_reuses_batch_directory_for_exported_fri_proof() {
        let output_dir = proof_file_output_dir(
            Path::new("/tmp/output"),
            Path::new("/tmp/input/batch-42/fri_proof.json"),
        )
        .expect("batch directory name should be available");
        assert_eq!(output_dir, Path::new("/tmp/output/batch-42"));
    }

    #[test]
    fn batch_number_from_exported_fri_proof_path_reads_standard_layout() {
        let batch_number = batch_number_from_exported_fri_proof_path(Path::new(
            "/tmp/input/batch-42/fri_proof.json",
        ));
        assert_eq!(batch_number, Some(42));
    }

    #[test]
    fn batch_number_from_exported_fri_proof_path_ignores_nonstandard_layout() {
        let batch_number =
            batch_number_from_exported_fri_proof_path(Path::new("/tmp/input/fri_proof.json"));
        assert_eq!(batch_number, None);
    }
}
