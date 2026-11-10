//! Advancing a proof's carried recursion chain to the unified level.
//!
//! A unified proof that converges on its first pass carries the *unrolled*-level
//! chain in its final registers `18..=25`; one that takes a further pass carries
//! the *unified*-level chain. Airbender's verifier accepts either, but the SNARK
//! wrapper runs with `check_aux_params` and constrains those registers to one
//! baked-in commitment -- the unified-level one -- so a first-pass proof has to be
//! advanced before wrapping or phase 1 rejects it.
//!
//! [`ChainAdvancer::advance`] runs the missing pass and returns the proof
//! unchanged when its chain is already unified-level.

use anyhow::{Context, Result};
use cli_lib::prover_utils::{
    CarriedChainCombiner, ProofArtifact, ProofCounts, ProofTarget, ProofTimingsMs, ProverBackend,
    SecurityLevel,
};

use crate::fri::RawFriProof;

const ARTIFACT_SCHEMA_VERSION: u32 = 1;

/// The wrapper is pinned to `security_100` in the workspace manifest, and
/// `airbender-host`'s `SecurityLevel` defaults to the same, so the chain the
/// combiner advances has to be built at that level too.
const SECURITY: SecurityLevel = SecurityLevel::Security100;

pub struct ChainAdvancer {
    combiner: CarriedChainCombiner,
}

impl ChainAdvancer {
    pub fn new() -> Self {
        #[cfg(feature = "gpu_fri")]
        let mut combiner =
            CarriedChainCombiner::new_gpu(SECURITY, cli_lib::prover_utils::GpuConfig::default());
        #[cfg(not(feature = "gpu_fri"))]
        let mut combiner =
            CarriedChainCombiner::new_cpu(SECURITY, cli_lib::prover_utils::CpuConfig::default());

        // `advance_carried_chain` warms up before its early return, so this costs
        // nothing extra and fails at startup rather than mid-wrap.
        combiner.warm_up();

        Self { combiner }
    }

    /// Advances `proof`'s carried chain to the unified level, or returns it
    /// unchanged when it is already there.
    ///
    /// `batch_id` only distinguishes the prover's per-pass ids.
    pub fn advance(&mut self, proof: RawFriProof, batch_id: u64) -> Result<RawFriProof> {
        let artifact = ProofArtifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            security_level: SECURITY,
            target: ProofTarget::RecursionUnified,
            backend: if cfg!(feature = "gpu_fri") {
                ProverBackend::Gpu
            } else {
                ProverBackend::Cpu
            },
            batch_id,
            cycles: 0,
            // Inert: `advance_carried_chain` forwards these as its own expected
            // keccaks, so they are compared against themselves and bind nothing.
            program_bin_keccak: [0u8; 32],
            program_text_keccak: [0u8; 32],
            timings_ms: ProofTimingsMs::default(),
            proof_counts: ProofCounts::default(),
            proof,
        };

        self.combiner
            .advance_carried_chain(&artifact)
            .map(|advanced| advanced.proof)
            .map_err(|err| anyhow::anyhow!(err))
            .context("while attempting to advance the carried recursion chain")
    }
}

impl Default for ChainAdvancer {
    fn default() -> Self {
        Self::new()
    }
}
