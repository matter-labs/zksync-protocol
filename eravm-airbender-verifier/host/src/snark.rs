use crate::chain::ChainAdvancer;
use crate::fri::RawFriProof;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::info;
use zkos_wrapper::{
    serialize_to_file, SnarkWrapper, SnarkWrapperConfig, SnarkWrapperProof, SnarkWrapperVK,
};

// Mirror `zkos-wrapper`'s artifact names so operators can switch between the
// standalone wrapper CLI and the integrated host without translating outputs.
pub(crate) const RISC_WRAPPER_PROOF_FILE_NAME: &str = "risc_wrapper_proof.json";
pub(crate) const RISC_WRAPPER_VK_FILE_NAME: &str = "risc_wrapper_vk.json";
pub(crate) const COMPRESSION_PROOF_FILE_NAME: &str = "compression_proof.json";
pub(crate) const COMPRESSION_VK_FILE_NAME: &str = "compression_vk.json";
pub(crate) const SNARK_PROOF_FILE_NAME: &str = "snark_proof.json";
pub(crate) const SNARK_VK_FILE_NAME: &str = "snark_vk.json";

#[derive(Clone, Debug)]
pub struct SnarkOptions {
    pub worker_threads: Option<usize>,
    pub trusted_setup: Option<PathBuf>,
    pub use_zk: bool,
    pub save_intermediates: bool,
    pub bin: PathBuf,
    pub text: PathBuf,
}

// ==============================================================================
// SNARK Wrapper Pipeline
// ==============================================================================
//
// The host intentionally treats the wrapper as a separate module with a narrow
// API: give it raw Airbender proofs and output directories, and it produces the
// final SNARK artifacts. Owning the stateful wrapper here lets one `prove-snark`
// invocation reuse setup and VK caches across every proof file it wraps.

pub struct SnarkPipeline {
    wrapper: SnarkWrapper,
    advancer: ChainAdvancer,
    use_zk: bool,
    save_intermediates: bool,
}

impl SnarkPipeline {
    /// `snark_vk` is the pre-generated SNARK verifying key, loaded by the
    /// caller (entry point). When `Some`, it is reused as-is; when `None`, the
    /// VK is derived once from the setup chain at construction. Either way,
    /// the VK is resolved up-front and cached so per-proof wraps never touch
    /// it again.
    pub fn new(options: &SnarkOptions, snark_vk: Option<SnarkWrapperVK>) -> Result<Self> {
        let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
            bin: Some(options.bin.clone()),
            text: Some(options.text.clone()),
            trusted_setup: options.trusted_setup.clone(),
            threads: options.worker_threads,
            check_aux_params: true,
            risc_wrapper_vk: None,
            compression_vk: None,
            binary_commitment: None,
            snark_vk,
        })
        .context("while attempting to initialize the SNARK wrapper")?;

        wrapper
            .snark_vk()
            .context("while attempting to resolve SNARK VK at startup")?;

        Ok(Self {
            wrapper,
            advancer: ChainAdvancer::new(),
            use_zk: options.use_zk,
            save_intermediates: options.save_intermediates,
        })
    }

    /// Runs the three-phase wrapping pipeline (risc wrapper → compression →
    /// SNARK) on a raw FRI proof. The phase-1 step proves and then verifies
    /// the FRI proof inside the recursion circuit, so callers don't need a
    /// separate pre-flight verification step.
    pub fn prove(&mut self, raw_proof: RawFriProof) -> Result<SnarkWrapperProof> {
        self.run_phases(raw_proof, None)
    }

    pub(crate) fn prove_and_save_outcome(
        &mut self,
        raw_proof: RawFriProof,
        output_dir: &Path,
    ) -> Result<()> {
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("while attempting to create {}", output_dir.display()))?;

        info!(
            output_dir = %output_dir.display(),
            "Starting SNARK wrapper pipeline with the built-in recursion verifier binary"
        );

        let intermediates_dir = self.save_intermediates.then_some(output_dir);
        let snark_proof = self.run_phases(raw_proof, intermediates_dir)?;

        let proof_path = output_dir.join(SNARK_PROOF_FILE_NAME);
        save_wrapper_artifact(&snark_proof, &proof_path)?;

        let vk_path = output_dir.join(SNARK_VK_FILE_NAME);
        save_wrapper_artifact(
            self.wrapper
                .snark_vk()
                .context("while attempting to resolve wrapper phase 3 VK")?,
            &vk_path,
        )?;

        info!(
            proof_path = %proof_path.display(),
            vk_path = %vk_path.display(),
            "Finished SNARK wrapper pipeline"
        );

        Ok(())
    }

    fn run_phases(
        &mut self,
        raw_proof: RawFriProof,
        intermediates_dir: Option<&Path>,
    ) -> Result<SnarkWrapperProof> {
        // Phase 1 constrains registers 18..=25 to the unified-level chain, which a
        // proof that converged on its first pass does not carry. No-op when it does.
        let raw_proof = self.advancer.advance(raw_proof, 0)?;

        let risc_wrapper_proof = self
            .wrapper
            .prove_risc_wrapper(raw_proof)
            .context("while attempting to run wrapper phase 1")?;

        if let Some(dir) = intermediates_dir {
            let risc_wrapper_vk = self
                .wrapper
                .risc_wrapper_vk()
                .context("while attempting to resolve wrapper phase 1 VK")?;
            save_wrapper_artifact_pair(
                &risc_wrapper_proof,
                RISC_WRAPPER_PROOF_FILE_NAME,
                risc_wrapper_vk,
                RISC_WRAPPER_VK_FILE_NAME,
                dir,
                "phase 1",
            )
            .context("while attempting to save wrapper phase 1 intermediates")?;
        }

        let compression_proof = self
            .wrapper
            .prove_compression(risc_wrapper_proof)
            .context("while attempting to run wrapper phase 2")?;

        if let Some(dir) = intermediates_dir {
            let compression_vk = self
                .wrapper
                .compression_vk()
                .context("while attempting to resolve wrapper phase 2 VK")?;
            save_wrapper_artifact_pair(
                &compression_proof,
                COMPRESSION_PROOF_FILE_NAME,
                compression_vk,
                COMPRESSION_VK_FILE_NAME,
                dir,
                "phase 2",
            )
            .context("while attempting to save wrapper phase 2 intermediates")?;
        }

        self.wrapper
            .prove_snark(compression_proof, self.use_zk)
            .context("while attempting to run wrapper phase 3")
    }
}

/// Resolves the phase-3 wrapper VK from the trusted setup chain. Used by the
/// `gen-vks` host subcommand to commit a deterministic SNARK VK file into the
/// repo; the server then loads that file directly instead of re-deriving on
/// startup.
pub fn derive_snark_vk(options: &SnarkOptions) -> Result<SnarkWrapperVK> {
    let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
        bin: Some(options.bin.clone()),
        text: Some(options.text.clone()),
        trusted_setup: options.trusted_setup.clone(),
        threads: options.worker_threads,
        check_aux_params: true,
        risc_wrapper_vk: None,
        compression_vk: None,
        binary_commitment: None,
        snark_vk: None,
    })
    .context("while attempting to initialize the SNARK wrapper for VK derivation")?;

    let vk = wrapper
        .snark_vk()
        .context("while attempting to derive SNARK VK")?
        .clone();
    Ok(vk)
}

fn save_wrapper_artifact<T: serde::Serialize>(artifact: &T, path: &Path) -> Result<()> {
    let path_string = path.to_string_lossy().into_owned();
    serialize_to_file(artifact, &path_string)
        .with_context(|| format!("while attempting to serialize {}", path.display()))
}

fn save_wrapper_artifact_pair<TProof, TVk>(
    proof: &TProof,
    proof_file_name: &str,
    vk: &TVk,
    vk_file_name: &str,
    output_dir: &Path,
    phase_name: &str,
) -> Result<()>
where
    TProof: serde::Serialize,
    TVk: serde::Serialize,
{
    let proof_path = output_dir.join(proof_file_name);
    save_wrapper_artifact(proof, &proof_path)?;

    let vk_path = output_dir.join(vk_file_name);
    save_wrapper_artifact(vk, &vk_path)?;

    info!(
        phase = phase_name,
        proof_path = %proof_path.display(),
        vk_path = %vk_path.display(),
        "Saved SNARK wrapper intermediate artifacts"
    );

    Ok(())
}
