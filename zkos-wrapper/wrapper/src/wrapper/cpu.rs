use std::path::PathBuf;
use std::time::Instant;

use anyhow::Context as _;
use bellman::kate_commitment::{Crs, CrsForMonomialForm};
use bellman::worker::Worker as BellmanWorker;
use boojum::cs::implementations::hints::{DenseVariablesCopyHint, DenseWitnessCopyHint};
use boojum::cs::implementations::polynomial_storage::{SetupBaseStorage, SetupStorage};
use boojum::cs::implementations::setup::FinalizationHintsForProver;
use boojum::cs::oracle::merkle_tree::MerkleTreeWithCap;

use crate::circuits::{BinaryCommitment, RiscWrapperWitness};
use crate::{
    Bn256, BoojumWorker, CompressionProof, CompressionTreeHasher, CompressionVK, GL,
    L1_VERIFIER_DOMAIN_SIZE_LOG, RiscWrapperProof, RiscWrapperTreeHasher, RiscWrapperVK,
    SnarkWrapperProof, SnarkWrapperSetup, SnarkWrapperVK,
};

pub(crate) struct BackendState {
    risc_wrapper: Option<RiscWrapperSetupCache>,
    compression: Option<CompressionSetupCache>,
    snark: Option<SnarkSetupCache>,
}

struct RiscWrapperSetupCache {
    finalization_hint: FinalizationHintsForProver,
    setup_base: SetupBaseStorage<GL>,
    setup: SetupStorage<GL>,
    vk: RiscWrapperVK,
    setup_tree: MerkleTreeWithCap<GL, RiscWrapperTreeHasher>,
    vars_hint: DenseVariablesCopyHint,
    witness_hints: DenseWitnessCopyHint,
}

struct CompressionSetupCache {
    finalization_hint: FinalizationHintsForProver,
    setup_base: SetupBaseStorage<GL>,
    setup: SetupStorage<GL>,
    vk: CompressionVK,
    setup_tree: MerkleTreeWithCap<GL, CompressionTreeHasher>,
    vars_hint: DenseVariablesCopyHint,
    witness_hints: DenseWitnessCopyHint,
}

struct SnarkSetupCache {
    worker: BellmanWorker,
    crs_mons: Crs<Bn256, CrsForMonomialForm>,
    snark_setup: SnarkWrapperSetup,
    vk: SnarkWrapperVK,
}

impl BackendState {
    pub(crate) fn new() -> Self {
        Self {
            risc_wrapper: None,
            compression: None,
            snark: None,
        }
    }

    pub(crate) fn cached_risc_wrapper_vk(&self) -> Option<&RiscWrapperVK> {
        self.risc_wrapper.as_ref().map(|cache| &cache.vk)
    }

    pub(crate) fn cached_compression_vk(&self) -> Option<&CompressionVK> {
        self.compression.as_ref().map(|cache| &cache.vk)
    }

    pub(crate) fn cached_snark_vk(&self) -> Option<&SnarkWrapperVK> {
        self.snark.as_ref().map(|cache| &cache.vk)
    }

    pub(crate) fn prove_risc_wrapper(
        &mut self,
        witness: RiscWrapperWitness,
        binary_commitment: BinaryCommitment,
        check_aux_params: bool,
        worker: &BoojumWorker,
    ) -> anyhow::Result<RiscWrapperProof> {
        let start = Instant::now();
        let cache = self.ensure_risc_wrapper_setup(binary_commitment, check_aux_params, worker)?;
        tracing::info!(
            "Phase 1 setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let start = Instant::now();
        let proof = crate::prove_risc_wrapper(
            witness,
            &cache.finalization_hint,
            &cache.setup_base,
            &cache.setup,
            &cache.vk,
            &cache.setup_tree,
            &cache.vars_hint,
            &cache.witness_hints,
            worker,
            binary_commitment,
            check_aux_params,
        );
        tracing::info!("Phase 1 proving took {:.3}s", start.elapsed().as_secs_f64());

        Ok(proof)
    }

    pub(crate) fn risc_wrapper_vk(
        &mut self,
        binary_commitment: BinaryCommitment,
        check_aux_params: bool,
        worker: &BoojumWorker,
    ) -> anyhow::Result<&RiscWrapperVK> {
        let start = Instant::now();
        let cache = self.ensure_risc_wrapper_setup(binary_commitment, check_aux_params, worker)?;
        tracing::info!(
            "Phase 1 setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(&cache.vk)
    }

    pub(crate) fn prove_compression(
        &mut self,
        risc_wrapper_proof: RiscWrapperProof,
        risc_wrapper_vk: RiscWrapperVK,
        worker: &BoojumWorker,
    ) -> anyhow::Result<CompressionProof> {
        let start = Instant::now();
        let cache = self.ensure_compression_setup(risc_wrapper_vk.clone(), worker)?;
        tracing::info!(
            "Phase 2 setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let start = Instant::now();
        let proof = crate::prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk,
            &cache.finalization_hint,
            &cache.setup_base,
            &cache.setup,
            &cache.vk,
            &cache.setup_tree,
            &cache.vars_hint,
            &cache.witness_hints,
            worker,
        );
        tracing::info!("Phase 2 proving took {:.3}s", start.elapsed().as_secs_f64());

        Ok(proof)
    }

    pub(crate) fn compression_vk(
        &mut self,
        risc_wrapper_vk: RiscWrapperVK,
        worker: &BoojumWorker,
    ) -> anyhow::Result<&CompressionVK> {
        let start = Instant::now();
        let cache = self.ensure_compression_setup(risc_wrapper_vk, worker)?;
        tracing::info!(
            "Phase 2 setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(&cache.vk)
    }

    pub(crate) fn prove_snark(
        &mut self,
        compression_proof: CompressionProof,
        compression_vk: CompressionVK,
        trusted_setup: &Option<PathBuf>,
        provided_snark_vk: Option<&SnarkWrapperVK>,
        use_zk: bool,
    ) -> anyhow::Result<SnarkWrapperProof> {
        let start = Instant::now();
        let cache =
            self.ensure_snark_setup(trusted_setup, compression_vk.clone(), provided_snark_vk)?;
        tracing::info!(
            "Phase 3 setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let start = Instant::now();
        let proof = crate::prove_snark_wrapper(
            compression_proof,
            compression_vk,
            &cache.snark_setup,
            &cache.crs_mons,
            &cache.worker,
            use_zk,
        );
        tracing::info!("Phase 3 proving took {:.3}s", start.elapsed().as_secs_f64());

        Ok(proof)
    }

    pub(crate) fn snark_vk(
        &mut self,
        trusted_setup: &Option<PathBuf>,
        compression_vk: CompressionVK,
    ) -> anyhow::Result<&SnarkWrapperVK> {
        let start = Instant::now();
        let cache = self.ensure_snark_setup(trusted_setup, compression_vk, None)?;
        tracing::info!(
            "Phase 3 setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(&cache.vk)
    }

    fn ensure_risc_wrapper_setup(
        &mut self,
        binary_commitment: BinaryCommitment,
        check_aux_params: bool,
        worker: &BoojumWorker,
    ) -> anyhow::Result<&RiscWrapperSetupCache> {
        if self.risc_wrapper.is_none() {
            let (finalization_hint, setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
                crate::get_risc_wrapper_setup(worker, binary_commitment, check_aux_params);

            self.risc_wrapper = Some(RiscWrapperSetupCache {
                finalization_hint,
                setup_base,
                setup,
                vk,
                setup_tree,
                vars_hint,
                witness_hints,
            });
        }

        Ok(self.risc_wrapper.as_ref().expect("phase 1 cache exists"))
    }

    fn ensure_compression_setup(
        &mut self,
        risc_wrapper_vk: RiscWrapperVK,
        worker: &BoojumWorker,
    ) -> anyhow::Result<&CompressionSetupCache> {
        if self.compression.is_none() {
            let (finalization_hint, setup_base, setup, vk, setup_tree, vars_hint, witness_hints) =
                crate::get_compression_setup(risc_wrapper_vk, worker);

            self.compression = Some(CompressionSetupCache {
                finalization_hint,
                setup_base,
                setup,
                vk,
                setup_tree,
                vars_hint,
                witness_hints,
            });
        }

        Ok(self.compression.as_ref().expect("phase 2 cache exists"))
    }

    fn ensure_snark_setup(
        &mut self,
        trusted_setup: &Option<PathBuf>,
        compression_vk: CompressionVK,
        provided_snark_vk: Option<&SnarkWrapperVK>,
    ) -> anyhow::Result<&SnarkSetupCache> {
        if self.snark.is_none() {
            let crs_mons = load_crs(trusted_setup)?;
            let worker = BellmanWorker::new();
            let snark_setup = crate::create_snark_wrapper_setup(compression_vk, &worker);
            let vk = match provided_snark_vk {
                Some(vk) => vk.clone(),
                None => crate::derive_snark_wrapper_vk(&snark_setup, &crs_mons, &worker),
            };

            self.snark = Some(SnarkSetupCache {
                worker,
                crs_mons,
                snark_setup,
                vk,
            });
        }

        Ok(self.snark.as_ref().expect("phase 3 cache exists"))
    }

    /// No-op on the CPU backend: all cached state is host-resident by construction.
    pub(crate) fn release_device_state(&mut self) {}

    /// Setup snapshots are a GPU-build feature; the CPU backend never has a
    /// snapshot-able chain, so saves are declined before any file is touched.
    pub(crate) fn has_full_setup_chain(&self) -> bool {
        false
    }

    /// See [`Self::has_full_setup_chain`].
    pub(crate) fn setup_chain_vk_sha3(&self) -> anyhow::Result<[String; 3]> {
        anyhow::bail!("setup snapshots are only supported on gpu builds")
    }

    /// See [`Self::has_full_setup_chain`].
    pub(crate) fn save_setups_to_dir(
        &self,
        _dir: &std::path::Path,
    ) -> anyhow::Result<std::collections::BTreeMap<String, u64>> {
        anyhow::bail!("setup snapshots are only supported on gpu builds")
    }

    /// See [`Self::has_full_setup_chain`] ([`super::SnarkWrapperHostCache::load_from_dir`]
    /// skips GPU snapshots on CPU builds via the manifest's backend field first).
    pub(crate) fn load_setups_from_dir(
        _dir: &std::path::Path,
        _expected_lengths: &std::collections::BTreeMap<String, u64>,
    ) -> anyhow::Result<Self> {
        anyhow::bail!("setup snapshots are only supported on gpu builds")
    }
}

fn load_crs(trusted_setup: &Option<PathBuf>) -> anyhow::Result<Crs<Bn256, CrsForMonomialForm>> {
    match trusted_setup {
        Some(path) => crate::get_trusted_setup(&path.to_string_lossy().to_string())
            .context("while attempting to load the trusted setup"),
        None => Ok(Crs::<Bn256, CrsForMonomialForm>::crs_42(
            1 << L1_VERIFIER_DOMAIN_SIZE_LOG,
            &BellmanWorker::new(),
        )),
    }
}
