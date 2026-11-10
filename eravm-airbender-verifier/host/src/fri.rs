use airbender_host::{
    Inputs, Proof, ProverLevel, RamSize, RealVerifier, RealVerifierBuilder, Runner, SecurityLevel,
    TranspilerRunner, TranspilerRunnerBuilder, VerificationKey, VerificationRequest, Verifier,
};
use anyhow::{Context, Result};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;
use zksync_airbender_verifier::types::AirbenderVerifierInput;

/// The machine address space the guest is linked for (`guest/eravm_memory.x`).
/// Every runner and prover must use it. The guest's allocator writes a tag at the
/// top of its heap (near 4 GiB) when it initializes, and the simulator indexes RAM
/// unchecked (bounds are only debug-asserted), so on a smaller image every run
/// starts with an out-of-bounds host access: undefined behaviour, not a clean
/// error.
pub(crate) const GUEST_RAM_SIZE: RamSize = RamSize::FourGb;

/// Resolves the guest binary inside a dist dir. We build the verifier/prover/
/// transpiler directly from `app.bin` rather than via `Program::load` (which
/// also requires the unused `app.elf` / `manifest.toml`). The transpiler
/// additionally reads the sibling `app.text`. `app.bin` and `app.text` are not
/// committed: they are built reproducibly and published as GitHub release assets
/// (`cargo airbender build` writes them under `guest/dist/app/` locally).
pub fn app_bin_path(dist_dir: &Path) -> PathBuf {
    dist_dir.join("app.bin")
}

pub fn app_text_path(dist_dir: &Path) -> PathBuf {
    dist_dir.join("app.text")
}

/// The guest returns `[u32; 8]` — the proof public input hash.
/// We no longer check against a fixed expected output; any non-zero output
/// indicates successful execution + commitment computation.
/// The actual value is batch-specific and verified by L1 against stored commitments.
pub(crate) const FRI_PROOF_FILE_NAME: &str = "fri_proof.json";

pub type RawFriProof = airbender_host::raw::UnrolledProgramProof;

/// Result of running the FRI prover on an encoded input.
///
/// `proof` is the full `Proof` envelope (real or dev variant) so callers can
/// either serialize it directly (server flow) or strip it to the raw inner
/// proof for on-disk storage (host flow).
pub struct ProveOutput {
    pub proof: Proof,
    pub cycles: u64,
    pub proving_time: Duration,
    pub output: [u32; 8],
}

/// Backend-agnostic FRI prover. The only implementor today is the GPU
/// [`FriPipeline`](crate::gpu_fri::FriPipeline), compiled in under the
/// `gpu_fri` feature; the server holds a `Box<dyn FriProver>` so nothing on
/// the proving path is aware of the GPU backend. `Send` is required because the
/// server runs the prover on a dedicated thread.
pub trait FriProver: Send {
    /// Proves a pre-encoded input word stream, checks the output is non-zero,
    /// and verifies the proof against the cached VK.
    fn prove_input(&self, batch_number: u64, input_words: &[u32]) -> Result<ProveOutput>;
}

/// Plain (backend-agnostic) tuning knobs for the FRI prover. Mapped onto
/// Airbender's `GpuProverConfig` inside the `gpu_fri` module; ignored by the
/// CUDA-free build. Keeping it free of GPU types lets the server assemble it
/// without depending on `airbender-host`'s GPU API.
#[derive(Clone, Debug, Default)]
pub struct FriProverConfig {
    /// Worker threads for the prover (None = backend default).
    pub worker_threads: Option<usize>,
    /// Cap (GiB) on device memory the allocator claims (None = all free VRAM).
    pub max_device_memory_gb: Option<f64>,
    /// Pinned host transfer buffers pre-allocated per concurrent job
    /// (0 = backend default).
    pub host_buffers_per_job: usize,
    /// Pinned host transfer buffers pre-allocated per device
    /// (0 = backend default).
    pub host_buffers_per_device: usize,
}

// ==============================================================================
// FRI Verifier
// ==============================================================================
//
// This module keeps all Airbender-specific behavior in one place so the rest of
// the host can talk in terms of "run batch", "prove batch", and "load/save raw
// proof" without needing to know how the guest program, GPU prover, or VK cache
// are assembled. The GPU prover itself lives in the `gpu_fri` module so the
// CUDA dependency is confined to a single conditionally-compiled file.

/// Verifier-only counterpart to the GPU FRI pipeline. Holds the real verifier
/// and a
/// cached/generated verification key, but no GPU prover — built when callers
/// (like the `snark-only` server mode) need to validate incoming FRI proofs
/// without proving anything themselves.
pub struct FriVerifier {
    verifier: RealVerifier,
    vk: VerificationKey,
}

impl FriVerifier {
    /// Builds a verifier with a pre-generated VK loaded from `vk_path`. Hard-
    /// fails if the file is missing or its contents don't match `security` —
    /// the server path uses this so a stale or absent VK never silently
    /// triggers an on-the-fly regeneration.
    pub fn load(dist_dir: &Path, vk_path: &Path, security: SecurityLevel) -> Result<Self> {
        let verifier =
            RealVerifierBuilder::new(app_bin_path(dist_dir), ProverLevel::RecursionUnified)
                .build()
                .context("while attempting to build real verifier")?;

        let vk = load_vk_from_disk(vk_path, security)?;

        Ok(Self { verifier, vk })
    }

    /// Builds a verifier, generating the VK on the fly if `vk_path` does not
    /// exist yet and caching the result to disk. Used by host-side tooling
    /// (the `gen-vks` subcommand, dev workflows) that needs to produce a VK
    /// in the first place — the server never calls this.
    pub fn load_or_generate(
        dist_dir: &Path,
        vk_path: &Path,
        security: SecurityLevel,
    ) -> Result<Self> {
        let verifier =
            RealVerifierBuilder::new(app_bin_path(dist_dir), ProverLevel::RecursionUnified)
                .build()
                .context("while attempting to build real verifier")?;

        let vk = load_or_generate_vk(&verifier, vk_path, security).with_context(|| {
            format!(
                "while attempting to prepare verification key cache {}",
                vk_path.display()
            )
        })?;

        Ok(Self { verifier, vk })
    }

    pub fn vk(&self) -> &VerificationKey {
        &self.vk
    }

    /// Verifies a FRI proof envelope against the cached VK, binding it to a
    /// specific guest output. The output must be non-zero — a zero output
    /// signals the guest's own verification + commitment step failed.
    pub fn verify(&self, batch_number: u64, proof: &Proof, output: [u32; 8]) -> Result<()> {
        if output == [0u32; 8] {
            anyhow::bail!(
                "batch {batch_number} proof returned zero output — verification or commitment failed"
            );
        }
        self.verifier
            .verify(proof, &self.vk, VerificationRequest::real(&output))
            .with_context(|| format!("while attempting to verify proof for batch {batch_number}"))
    }

    /// Verifies a FRI proof envelope against the cached VK without binding to
    /// a specific guest output — only structural / cryptographic validity is
    /// checked. Used by the SNARK-only server mode, which receives proofs from
    /// the job server and does not have the original receipt at hand.
    pub fn verify_envelope(&self, batch_number: u64, proof: &Proof) -> Result<()> {
        self.verifier
            .verify(proof, &self.vk, VerificationRequest::empty())
            .with_context(|| format!("while attempting to verify proof for batch {batch_number}"))
    }
}

pub(crate) fn build_runner(dist_dir: &Path, jit: bool) -> Result<TranspilerRunner> {
    let mut runner_builder = TranspilerRunnerBuilder::new(app_bin_path(dist_dir))
        .with_cycles(usize::MAX)
        .with_ram_size(GUEST_RAM_SIZE);

    if jit {
        runner_builder = runner_builder.with_jit();
    }

    runner_builder
        .build()
        .context("while attempting to build transpiler runner")
}

/// The native pre-check [`run_batch`] compares the guest against.
pub(crate) type NativeVerify =
    fn(AirbenderVerifierInput) -> Result<zksync_airbender_verifier::VerificationResult>;

pub(crate) fn run_batch(
    runner: &TranspilerRunner,
    batch_number: u64,
    batch_path: &Path,
    native_verify: NativeVerify,
) -> Result<()> {
    let input = load_verifier_input(batch_path).with_context(|| {
        format!(
            "failed to load batch {batch_number} from {}",
            batch_path.display()
        )
    })?;

    let native_result = native_verify(input.clone()).context("native verification failed")?;

    info!(
        batch_number,
        ?native_result.commitment,
        ?native_result.proof_public_input,
        "Native verification + commitment succeeded"
    );

    // Re-run on the transpiler with the same input; the public input must match.
    let mut transpiler_input = Inputs::new();
    transpiler_input
        .push(&input)
        .context("failed to encode AirbenderVerifierInput")?;

    let execution = runner
        .run(transpiler_input.words())
        .with_context(|| format!("while attempting to execute batch {batch_number}"))?;
    let output = execution.receipt.output;

    info!(
        batch_number,
        cycles = execution.cycles_executed,
        reached_end = execution.reached_end,
        ?output,
        "Finished transpiler run"
    );

    // Verify transpiler output matches native verification.
    anyhow::ensure!(
        output == native_result.proof_public_input,
        "batch {batch_number}: transpiler output {output:?} doesn't match native {0:?}",
        native_result.proof_public_input
    );

    info!(
        batch_number,
        "Transpiler output matches native verification"
    );

    Ok(())
}

/// Load and deserialize an `AirbenderVerifierInput` from a batch file. The
/// corpus ships with `commitment_input` baked in, so callers can `verify()`
/// directly — no runtime synthesis step.
pub(crate) fn load_verifier_input(batch_path: &Path) -> Result<AirbenderVerifierInput> {
    let parent_dir = batch_path.parent().with_context(|| {
        format!(
            "batch path {} has no parent directory",
            batch_path.display()
        )
    })?;
    let batch_input = zksync_cli_utils::resolve_batch_inputs(
        parent_dir,
        Some(&[batch_path.to_path_buf()]),
        false,
    )?
    .into_iter()
    .next()
    .context("resolve_batch_inputs returned no entries")?;
    zksync_cli_utils::load_batch(&batch_input)
}

pub(crate) fn load_raw_proof(path: &Path) -> Result<RawFriProof> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("while attempting to open {}", path.display()))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .with_context(|| format!("while attempting to deserialize {}", path.display()))
}

/// Loads a bincode-encoded `VerificationKey` from `path`, refusing to fall
/// back to generation if the file is missing or its security level doesn't
/// match `expected_security`. The server uses this so an absent VK never
/// silently regenerates at startup.
pub fn load_vk_from_disk(path: &Path, expected_security: SecurityLevel) -> Result<VerificationKey> {
    if !path.exists() {
        anyhow::bail!(
            "FRI verification key file does not exist: {}. \
             Download it from a GitHub release (asset `fri_vk.bin`) or regenerate \
             it with `cargo run -p eravm-prover-host -- gen-vks`.",
            path.display()
        );
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("while attempting to read {}", path.display()))?;
    let (vk, decoded_len): (VerificationKey, usize) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
            .with_context(|| format!("while attempting to decode {}", path.display()))?;
    if decoded_len != bytes.len() {
        anyhow::bail!(
            "verification key file {} has trailing bytes",
            path.display()
        );
    }
    if vk.security() != expected_security {
        anyhow::bail!(
            "verification key file {} was built for {} but the server is configured for {}",
            path.display(),
            vk.security(),
            expected_security
        );
    }

    info!(path = %path.display(), "Loaded verification key from disk");
    Ok(vk)
}

fn load_or_generate_vk(
    verifier: &RealVerifier,
    cache_path: &Path,
    security: SecurityLevel,
) -> Result<VerificationKey> {
    if cache_path.exists() {
        return load_vk_from_disk(cache_path, security);
    }

    let vk = verifier
        .generate_vk(security)
        .context("while attempting to generate verification key")?;
    let encoded = bincode::serde::encode_to_vec(&vk, bincode::config::standard())
        .context("while attempting to bincode-encode verification key cache payload")?;
    if let Some(parent) = cache_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("while attempting to create {}", parent.display()))?;
        }
    }
    std::fs::write(cache_path, encoded)
        .with_context(|| format!("while attempting to write {}", cache_path.display()))?;

    info!(path = %cache_path.display(), "Generated and cached verification key");
    Ok(vk)
}

/// Resolves the guest dist directory: `ERAVM_PROVER_HOST_GUEST_DIR` env var if
/// set, otherwise the workspace-relative path baked in at compile time. Lets a
/// binary built on one machine find the guest dist on another (e.g. the CI
/// prove-batch flow builds host on a CPU runner and runs it on the GPU runner).
pub fn dist_dir() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ERAVM_PROVER_HOST_GUEST_DIR") {
        return std::path::PathBuf::from(p);
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app")
}

/// Workspace-relative default location for the FRI verification key, baked in at
/// compile time. The key is not committed — it's a release asset downloaded into
/// place (or regenerated via `gen-vks`); deployments override the path via
/// `--fri-vk` / `FRI_VK`.
pub fn default_fri_vk_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vks/fri_vk.bin")
}
