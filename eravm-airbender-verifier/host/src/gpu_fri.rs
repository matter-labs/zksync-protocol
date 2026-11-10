//! GPU FRI prover — the entire CUDA dependency lives in this one module.
//!
//! The module is compiled only under the `gpu_fri` feature (see the `mod`
//! declaration in `lib.rs`), so nothing inside needs per-item `#[cfg]`
//! attributes. A CUDA-free build omits the file wholesale and relies on the
//! stub [`build_fri_prover`](crate::build_fri_prover) /
//! [`prove_batches_fri`](crate::prove_batches_fri) in `lib.rs`.

use airbender_host::{
    GpuProver, GpuProverBuilder, GpuProverConfig, Inputs, Proof, Prover, ProverLevel, SecurityLevel,
};
use anyhow::{Context, Result};
use std::io::BufWriter;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::info;
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::BatchInputFile;

use crate::fri::{
    app_bin_path, load_verifier_input, FriProver, FriProverConfig, FriVerifier, ProveOutput,
    RawFriProof, FRI_PROOF_FILE_NAME, GUEST_RAM_SIZE,
};
use crate::statistics::StatisticsCollector;

/// Serializes a raw FRI proof to `path` as pretty JSON, creating parent dirs.
/// Lives here because the GPU `prove-fri` flow is now its only caller.
fn save_raw_proof(proof: &RawFriProof, path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("while attempting to derive the parent directory for the raw FRI proof file")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("while attempting to create {}", parent.display()))?;

    let file = std::fs::File::create(path)
        .with_context(|| format!("while attempting to create {}", path.display()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, proof)
        .with_context(|| format!("while attempting to serialize {}", path.display()))
}

struct FriProofArtifact {
    proof: RawFriProof,
    proving_time: Duration,
    cycles: u64,
}

/// GPU-backed FRI prover: a CUDA `GpuProver` plus the verifier that checks the
/// proofs it produces. Constructed via [`build_fri_prover`] (server path) or
/// [`FriPipeline::new_with_generated_vk`] (dev CLI path).
pub struct FriPipeline {
    prover: GpuProver,
    verifier: FriVerifier,
}

impl FriPipeline {
    /// Strict constructor: hard-fails if `vk_path` is missing. Used by the
    /// server, where a stale or absent VK must never silently regenerate.
    pub fn new(
        dist_dir: &Path,
        vk_path: &Path,
        security: SecurityLevel,
        config: GpuProverConfig,
    ) -> Result<Self> {
        Self::with_verifier(
            dist_dir,
            FriVerifier::load(dist_dir, vk_path, security)?,
            security,
            config,
        )
    }

    /// Lenient constructor: generates the VK at `vk_path` if it doesn't
    /// exist yet. Used by the host `prove-fri` CLI so a dev can FRI-prove
    /// against a fresh guest without first running `gen-vks` (which also
    /// requires the SNARK trusted setup). The server never calls this.
    pub fn new_with_generated_vk(
        dist_dir: &Path,
        vk_path: &Path,
        worker_threads: Option<usize>,
        security: SecurityLevel,
    ) -> Result<Self> {
        Self::with_verifier(
            dist_dir,
            FriVerifier::load_or_generate(dist_dir, vk_path, security)?,
            security,
            // Dev CLI only sets worker threads; it never runs the SNARK wrapper
            // in-process, so it has no reason to cap VRAM or tune the host pool.
            GpuProverConfig::default().maybe_worker_threads(worker_threads),
        )
    }

    fn with_verifier(
        dist_dir: &Path,
        verifier: FriVerifier,
        security: SecurityLevel,
        config: GpuProverConfig,
    ) -> Result<Self> {
        let prover = GpuProverBuilder::new(app_bin_path(dist_dir))
            .with_level(ProverLevel::RecursionUnified)
            .with_security(security)
            .with_config(config.with_ram_size(GUEST_RAM_SIZE))
            .build()
            .context("while attempting to build GPU prover")?;

        Ok(Self { prover, verifier })
    }

    /// Proves an `AirbenderVerifierInput` by encoding it to the prover word
    /// stream first, then delegating to [`FriProver::prove_input`].
    fn prove_verifier_input(
        &self,
        batch_number: u64,
        input: &AirbenderVerifierInput,
    ) -> Result<ProveOutput> {
        let mut prover_input = Inputs::new();
        prover_input
            .push(input)
            .context("failed to encode AirbenderVerifierInput")?;
        self.prove_input(batch_number, prover_input.words())
    }

    fn prove_batch(&self, batch_number: u64, batch_path: &Path) -> Result<FriProofArtifact> {
        let input = load_verifier_input(batch_path).with_context(|| {
            format!(
                "failed to load batch {batch_number} from {}",
                batch_path.display()
            )
        })?;
        let ProveOutput {
            proof,
            cycles,
            proving_time,
            ..
        } = self.prove_verifier_input(batch_number, &input)?;

        let proof = match proof {
            Proof::Real(proof) => proof.into_inner(),
            Proof::Dev(_) => {
                anyhow::bail!("GPU prover returned a development proof unexpectedly")
            }
        };

        Ok(FriProofArtifact {
            proof,
            proving_time,
            cycles,
        })
    }
}

impl FriProver for FriPipeline {
    fn prove_input(&self, batch_number: u64, input_words: &[u32]) -> Result<ProveOutput> {
        let proving_started_at = Instant::now();
        let prove_result = self.prover.prove(input_words).with_context(|| {
            format!("while attempting to generate proof for batch {batch_number}")
        })?;
        let proving_time = proving_started_at.elapsed();
        let cycles = prove_result.cycles;
        let output = prove_result.receipt.output;

        info!(
            batch_number,
            cycles,
            proving_time_secs = proving_time.as_secs_f64(),
            ?output,
            "Finished FRI proof generation"
        );

        self.verifier
            .verify(batch_number, &prove_result.proof, output)?;

        info!(batch_number, "Finished FRI proof verification");

        Ok(ProveOutput {
            proof: prove_result.proof,
            cycles,
            proving_time,
            output,
        })
    }
}

/// Builds a GPU FRI prover behind the backend-agnostic [`FriProver`] trait
/// object the server consumes. The CUDA-free build provides a stub of the same
/// name (see `lib.rs`) that returns an error instead.
pub fn build_fri_prover(
    dist_dir: &Path,
    vk_path: &Path,
    security: SecurityLevel,
    config: FriProverConfig,
) -> Result<Box<dyn FriProver>> {
    let mut gpu_config = GpuProverConfig::default().maybe_worker_threads(config.worker_threads);
    // Treat a 0 buffer count as "keep the backend default" rather than forcing
    // zero pinned host↔device transfer buffers, which starves the prover's copy
    // pool and stalls proving. This keeps `FriProverConfig::default()` usable.
    if config.host_buffers_per_job > 0 {
        gpu_config = gpu_config.with_host_allocators_per_job(config.host_buffers_per_job);
    }
    if config.host_buffers_per_device > 0 {
        gpu_config = gpu_config.with_host_allocators_per_device(config.host_buffers_per_device);
    }
    if let Some(gb) = config.max_device_memory_gb {
        gpu_config = gpu_config.with_max_device_memory_bytes((gb * (1u64 << 30) as f64) as usize);
    }

    let pipeline = FriPipeline::new(dist_dir, vk_path, security, gpu_config)?;
    Ok(Box::new(pipeline))
}

/// Proves a set of batches end-to-end with the GPU FRI prover and writes the
/// raw proofs to disk. Backs the host `prove-fri` subcommand; the CUDA-free
/// build provides a stub of the same name (see `lib.rs`).
pub fn prove_batches_fri(
    batch_inputs: &[BatchInputFile],
    worker_threads: Option<usize>,
    output_root: &Path,
    vk_path: &Path,
    security: SecurityLevel,
) -> Result<()> {
    // Host CLI is a dev/debug entry point — generate the FRI VK on the fly
    // if it isn't checked in yet, so a fresh-guest workflow doesn't require
    // the SNARK trusted setup just to FRI-prove a batch.
    let pipeline =
        FriPipeline::new_with_generated_vk(&crate::dist_dir(), vk_path, worker_threads, security)?;
    let mut statistics = StatisticsCollector::default();

    for (index, batch_input) in batch_inputs.iter().enumerate() {
        let proof_artifact = pipeline
            .prove_batch(batch_input.number, &batch_input.path)
            .with_context(|| {
                format!(
                    "while attempting to prove batch {} from {}",
                    batch_input.number,
                    batch_input.path.display()
                )
            })?;

        let output_dir = crate::batch_output_dir(output_root, batch_input.number);
        let proof_path = output_dir.join(FRI_PROOF_FILE_NAME);
        save_raw_proof(&proof_artifact.proof, &proof_path)?;

        statistics.add_sample(proof_artifact.proving_time, proof_artifact.cycles);
        info!(
            batch_number = batch_input.number,
            batch_file = %batch_input.path.display(),
            proof_path = %proof_path.display(),
            completed_batches = index + 1,
            total_batches = batch_inputs.len(),
            "Successfully wrote raw FRI proof"
        );
        statistics.print_stats();
    }

    Ok(())
}
