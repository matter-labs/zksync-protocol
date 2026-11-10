use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context as _;
use proof_compression::serialization::{
    GenericWrapper as _, PlonkSnarkVerifierCircuitDeviceSetupWrapper,
};
use shivini::cs::GpuSetup;
use shivini::{ProverContext, ProverContextConfig};
use zksync_gpu_prover::AsyncSetup;

use crate::circuits::{BinaryCommitment, RiscWrapperWitness};
use crate::{
    BoojumWorker, CompressionProof, CompressionTreeHasher, CompressionVK, RiscWrapperProof,
    RiscWrapperTreeHasher, RiscWrapperVK, SnarkWrapperProof, SnarkWrapperVK,
};

pub(crate) struct BackendState {
    risc_wrapper: Option<RiscWrapperSetupCache>,
    compression: Option<CompressionSetupCache>,
    snark: Option<SnarkSetupCache>,
    stark_context: Option<ProverContext>,
}

struct RiscWrapperSetupCache {
    finalization_hint: boojum::cs::implementations::setup::FinalizationHintsForProver,
    gpu_setup: GpuSetup<RiscWrapperTreeHasher>,
    vk: RiscWrapperVK,
}

struct CompressionSetupCache {
    finalization_hint: boojum::cs::implementations::setup::FinalizationHintsForProver,
    gpu_setup: GpuSetup<CompressionTreeHasher>,
    vk: CompressionVK,
}

struct SnarkSetupCache {
    /// Loaded lazily from the trusted-setup file; `None` when the phase-3 setup came
    /// from a disk snapshot and no proof has needed the CRS yet (the CRS is a file
    /// already, so snapshots never duplicate it).
    crs: Option<crate::gpu::snark::CompactRawCrs>,
    setup: Option<SnarkGeneratedSetupCache>,
}

struct SnarkGeneratedSetupCache {
    precomputation: PlonkSnarkVerifierCircuitDeviceSetupWrapper,
    vk: SnarkWrapperVK,
}

impl BackendState {
    pub(crate) fn new() -> Self {
        Self {
            risc_wrapper: None,
            compression: None,
            snark: None,
            stark_context: None,
        }
    }

    pub(crate) fn cached_risc_wrapper_vk(&self) -> Option<&RiscWrapperVK> {
        self.risc_wrapper.as_ref().map(|cache| &cache.vk)
    }

    pub(crate) fn cached_compression_vk(&self) -> Option<&CompressionVK> {
        self.compression.as_ref().map(|cache| &cache.vk)
    }

    pub(crate) fn cached_snark_vk(&self) -> Option<&SnarkWrapperVK> {
        self.snark
            .as_ref()
            .and_then(|cache| cache.setup.as_ref())
            .map(|setup| &setup.vk)
    }

    pub(crate) fn prove_risc_wrapper(
        &mut self,
        witness: RiscWrapperWitness,
        binary_commitment: BinaryCommitment,
        check_aux_params: bool,
        worker: &BoojumWorker,
    ) -> anyhow::Result<RiscWrapperProof> {
        let start = Instant::now();
        self.ensure_stark_context()
            .context("while attempting to prepare the STARK GPU context")?;
        let cache = self.ensure_risc_wrapper_setup(binary_commitment, check_aux_params, worker)?;
        tracing::info!(
            "Phase 1 GPU setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let start = Instant::now();
        let proof = crate::gpu::risc_wrapper::prove_risc_wrapper(
            witness,
            &cache.finalization_hint,
            &cache.gpu_setup,
            &cache.vk,
            worker,
            binary_commitment,
            check_aux_params,
        );
        tracing::info!(
            "Phase 1 GPU proving took {:.3}s",
            start.elapsed().as_secs_f64()
        );

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
            "Phase 1 GPU setup ready in {:.3}s",
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
        self.ensure_stark_context()
            .context("while attempting to prepare the STARK GPU context")?;
        let cache = self.ensure_compression_setup(risc_wrapper_vk.clone(), worker)?;
        tracing::info!(
            "Phase 2 GPU setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let start = Instant::now();
        let proof = crate::gpu::compression::prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk,
            &cache.finalization_hint,
            &cache.gpu_setup,
            &cache.vk,
            worker,
        );
        tracing::info!(
            "Phase 2 GPU proving took {:.3}s",
            start.elapsed().as_secs_f64()
        );

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
            "Phase 2 GPU setup ready in {:.3}s",
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
        self.release_stark_context();

        let start = Instant::now();
        let mut device_manager = {
            let crs = self.ensure_snark_crs(trusted_setup)?;
            crate::gpu::snark::gpu_create_snark_device_manager(crs)
                .context("while attempting to initialize the phase 3 GPU device manager")?
        };
        let cache = self.ensure_snark_setup(
            compression_vk.clone(),
            provided_snark_vk,
            &mut device_manager,
        )?;
        tracing::info!(
            "Phase 3 GPU setup ready in {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let start = Instant::now();
        let proof = crate::gpu::snark::gpu_snark_prove_with_manager(
            &cache.precomputation,
            &cache.vk,
            compression_proof,
            compression_vk,
            &mut device_manager,
            use_zk,
        )?;
        tracing::info!(
            "Phase 3 GPU proving took {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(proof)
    }

    pub(crate) fn snark_vk(
        &mut self,
        trusted_setup: &Option<PathBuf>,
        compression_vk: CompressionVK,
    ) -> anyhow::Result<&SnarkWrapperVK> {
        self.release_stark_context();
        let start = Instant::now();
        let cache = self.create_snark_setup(trusted_setup, compression_vk, None)?;
        tracing::info!(
            "Phase 3 GPU setup ready in {:.3}s",
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
            self.ensure_stark_context()
                .context("while attempting to initialize the phase 1 GPU prover context")?;
            let (gpu_setup, vk, finalization_hint) =
                crate::gpu::risc_wrapper::get_risc_wrapper_setup(
                    worker,
                    binary_commitment,
                    check_aux_params,
                );

            self.risc_wrapper = Some(RiscWrapperSetupCache {
                finalization_hint,
                gpu_setup,
                vk,
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
            self.ensure_stark_context()
                .context("while attempting to initialize the phase 2 GPU prover context")?;
            let (gpu_setup, vk, finalization_hint) =
                crate::gpu::compression::get_compression_setup(worker, risc_wrapper_vk);

            self.compression = Some(CompressionSetupCache {
                finalization_hint,
                gpu_setup,
                vk,
            });
        }

        Ok(self.compression.as_ref().expect("phase 2 cache exists"))
    }

    fn ensure_snark_crs(
        &mut self,
        trusted_setup: &Option<PathBuf>,
    ) -> anyhow::Result<&crate::gpu::snark::CompactRawCrs> {
        let needs_crs = self.snark.as_ref().is_none_or(|cache| cache.crs.is_none());
        if needs_crs {
            self.release_stark_context();
            let crs_file_path = trusted_setup
                .as_ref()
                .context("while attempting to prepare the phase 3 GPU setup")?;
            let crs_file = crs_file_path.to_string_lossy().to_string();
            let crs = crate::gpu::snark::gpu_load_compact_raw_crs(&crs_file)
                .context("while attempting to load the phase 3 compact CRS")?;

            match &mut self.snark {
                Some(cache) => cache.crs = Some(crs),
                None => {
                    self.snark = Some(SnarkSetupCache {
                        crs: Some(crs),
                        setup: None,
                    })
                }
            }
        }

        Ok(self
            .snark
            .as_ref()
            .and_then(|cache| cache.crs.as_ref())
            .expect("phase 3 CRS was just ensured"))
    }

    fn ensure_snark_setup(
        &mut self,
        compression_vk: CompressionVK,
        provided_snark_vk: Option<&SnarkWrapperVK>,
        device_manager: &mut crate::gpu::snark::PlonkDeviceManager,
    ) -> anyhow::Result<&SnarkGeneratedSetupCache> {
        let cache = self.snark.as_mut().expect("phase 3 CRS is loaded");
        if cache.setup.is_none() {
            let (precomputation, vk) = crate::gpu::snark::gpu_create_snark_setup_data_with_manager(
                &compression_vk,
                device_manager,
                provided_snark_vk,
            )
            .context("while attempting to create the phase 3 SNARK setup")?;

            cache.setup = Some(SnarkGeneratedSetupCache { precomputation, vk });
        }

        Ok(cache.setup.as_ref().expect("phase 3 setup exists"))
    }

    fn create_snark_setup(
        &mut self,
        trusted_setup: &Option<PathBuf>,
        compression_vk: CompressionVK,
        provided_snark_vk: Option<&SnarkWrapperVK>,
    ) -> anyhow::Result<&SnarkGeneratedSetupCache> {
        if self
            .snark
            .as_ref()
            .and_then(|cache| cache.setup.as_ref())
            .is_none()
        {
            let mut device_manager = {
                let crs = self.ensure_snark_crs(trusted_setup)?;
                crate::gpu::snark::gpu_create_snark_device_manager(crs)
                    .context("while attempting to initialize the phase 3 GPU device manager")?
            };

            self.ensure_snark_setup(compression_vk, provided_snark_vk, &mut device_manager)?;
        }

        Ok(self
            .snark
            .as_ref()
            .and_then(|cache| cache.setup.as_ref())
            .expect("phase 3 setup exists"))
    }

    fn ensure_stark_context(&mut self) -> anyhow::Result<()> {
        if self.stark_context.is_none() {
            // Both STARK phases use shivini's process-global context. Use the
            // smallest domain required by phase 2 so one context can serve phase
            // 1 and phase 2 for a single FRI -> SNARK pipeline iteration.
            let config =
                ProverContextConfig::default().with_smallest_supported_domain_size(1 << 15);
            self.stark_context = Some(
                ProverContext::create_with_config(config)
                    .context("while attempting to initialize the STARK GPU prover context")?,
            );
        }

        Ok(())
    }

    fn release_stark_context(&mut self) {
        self.stark_context = None;
    }

    /// Drop everything device-resident, leaving only the host-side setup caches.
    ///
    /// The setup caches themselves never hold device memory (shivini's `GpuSetup` is
    /// host-side data, the CRS and phase-3 setup are pinned host buffers); the STARK
    /// context is the only member that owns VRAM, and the phase-3 device manager is
    /// scoped to the proving calls.
    pub(crate) fn release_device_state(&mut self) {
        self.release_stark_context();
    }

    /// Write the derived setup caches as files under `dir` (see
    /// [`SnarkWrapperHostCache::save_to_dir`]). All-or-nothing: the full phase 1..3
    /// chain must be derived (a partial save over an older snapshot would otherwise
    /// mix setups from two derivations under one manifest), and the directory's
    /// previous phase files are removed first. The CRS is never written — it already
    /// lives in the trusted-setup file and is re-read on demand.
    /// Whether the full phase 1..3 setup chain is derived and snapshot-able.
    pub(crate) fn has_full_setup_chain(&self) -> bool {
        self.risc_wrapper.is_some()
            && self.compression.is_some()
            && self
                .snark
                .as_ref()
                .and_then(|cache| cache.setup.as_ref())
                .is_some()
    }

    /// SHA3-256 of each phase VK (bincode-encoded), phase order. Requires
    /// [`Self::has_full_setup_chain`].
    pub(crate) fn setup_chain_vk_sha3(&self) -> anyhow::Result<[String; 3]> {
        let (Some(risc_wrapper), Some(compression), Some(snark)) = (
            self.risc_wrapper.as_ref(),
            self.compression.as_ref(),
            self.snark.as_ref().and_then(|cache| cache.setup.as_ref()),
        ) else {
            anyhow::bail!("the phase 1..3 chain is not fully derived");
        };
        Ok([
            bincode_sha3(&risc_wrapper.vk)?,
            bincode_sha3(&compression.vk)?,
            bincode_sha3(&snark.vk)?,
        ])
    }

    pub(crate) fn save_setups_to_dir(
        &self,
        dir: &Path,
    ) -> anyhow::Result<std::collections::BTreeMap<String, u64>> {
        let (Some(risc_wrapper), Some(compression), Some(snark)) = (
            self.risc_wrapper.as_ref(),
            self.compression.as_ref(),
            self.snark.as_ref().and_then(|cache| cache.setup.as_ref()),
        ) else {
            anyhow::bail!(
                "refusing to save a partial setup snapshot: the phase 1..3 chain must be \
                 fully derived"
            );
        };

        for file in SETUP_CACHE_PHASE_FILES {
            let path = dir.join(file);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("while removing the stale {}", path.display()))?;
            }
        }

        write_bincode(
            &dir.join(PHASE1_SETUP_FILE),
            &(
                &risc_wrapper.finalization_hint,
                &risc_wrapper.gpu_setup,
                &risc_wrapper.vk,
            ),
        )?;
        write_bincode(
            &dir.join(PHASE2_SETUP_FILE),
            &(
                &compression.finalization_hint,
                &compression.gpu_setup,
                &compression.vk,
            ),
        )?;

        let path = dir.join(PHASE3_PRECOMPUTATION_FILE);
        let file = std::fs::File::create(&path)
            .with_context(|| format!("while creating {}", path.display()))?;
        let mut writer = std::io::BufWriter::new(file);
        snark
            .precomputation
            .into_inner_ref()
            .write(&mut writer)
            .map_err(|e| anyhow::anyhow!("while writing the phase 3 precomputation: {e:?}"))?;
        // BufWriter's Drop swallows flush errors, so an ENOSPC/short write would
        // otherwise report success and the manifest would bless a truncated file.
        writer
            .into_inner()
            .map_err(|e| anyhow::anyhow!("while flushing {}: {e}", path.display()))?
            .sync_all()
            .with_context(|| format!("while syncing {}", path.display()))?;
        write_bincode(&dir.join(PHASE3_VK_FILE), &snark.vk)?;

        let mut lengths = std::collections::BTreeMap::new();
        for file in SETUP_CACHE_PHASE_FILES {
            let path = dir.join(file);
            let len = std::fs::metadata(&path)
                .with_context(|| format!("while sizing {}", path.display()))?
                .len();
            lengths.insert(file.to_string(), len);
        }
        Ok(lengths)
    }

    /// Rebuild the setup caches from the files [`Self::save_setups_to_dir`] wrote.
    /// Requires the full phase 1..3 chain (saves are all-or-nothing, so anything else
    /// is a damaged snapshot); unreadable or mis-sized files are an error, so a
    /// corrupt snapshot is reported rather than silently recomputed around.
    pub(crate) fn load_setups_from_dir(
        dir: &Path,
        expected_lengths: &std::collections::BTreeMap<String, u64>,
    ) -> anyhow::Result<Self> {
        for file in SETUP_CACHE_PHASE_FILES {
            let path = dir.join(file);
            anyhow::ensure!(
                path.is_file(),
                "setup snapshot in {} is missing {file} (snapshots are written \
                 all-or-nothing, so this one is damaged)",
                dir.display(),
            );
            // Sizes are checked up front because a truncated stream would otherwise
            // abort inside gpu-prover's read_exact (an internal expect) instead of
            // erroring here.
            let len = std::fs::metadata(&path)
                .with_context(|| format!("while sizing {}", path.display()))?
                .len();
            let expected = expected_lengths.get(file).copied();
            anyhow::ensure!(
                expected == Some(len),
                "setup snapshot file {} is {len} bytes, but the manifest recorded \
                 {expected:?} — the snapshot is truncated or damaged",
                path.display(),
            );
        }

        let mut state = Self::new();

        let (finalization_hint, gpu_setup, vk) = read_bincode(&dir.join(PHASE1_SETUP_FILE))?;
        state.risc_wrapper = Some(RiscWrapperSetupCache {
            finalization_hint,
            gpu_setup,
            vk,
        });

        let (finalization_hint, gpu_setup, vk) = read_bincode(&dir.join(PHASE2_SETUP_FILE))?;
        state.compression = Some(CompressionSetupCache {
            finalization_hint,
            gpu_setup,
            vk,
        });

        // Read at this build's domain size. `MemcopySerializable::read_from_buffer` is
        // not usable here: it allocates at proof-compression's default 2^24 slot size,
        // and the length-header-free stream of a 2^25 (`security_100`) setup would
        // load into it silently mis-parsed.
        let precomputation_path = dir.join(PHASE3_PRECOMPUTATION_FILE);
        let file = std::fs::File::open(&precomputation_path)
            .with_context(|| format!("while opening {}", precomputation_path.display()))?;
        let mut inner = AsyncSetup::allocate(1 << crate::L1_VERIFIER_DOMAIN_SIZE_LOG);
        inner
            .read(std::io::BufReader::new(file))
            .map_err(|e| anyhow::anyhow!("while reading the phase 3 precomputation: {e:?}"))?;
        let precomputation = PlonkSnarkVerifierCircuitDeviceSetupWrapper::from_inner(inner);
        let vk = read_bincode(&dir.join(PHASE3_VK_FILE))?;
        state.snark = Some(SnarkSetupCache {
            crs: None,
            setup: Some(SnarkGeneratedSetupCache { precomputation, vk }),
        });

        Ok(state)
    }
}

const PHASE1_SETUP_FILE: &str = "phase1_risc_wrapper_setup.bin";
const PHASE2_SETUP_FILE: &str = "phase2_compression_setup.bin";
const PHASE3_PRECOMPUTATION_FILE: &str = "phase3_snark_precomputation.bin";
const PHASE3_VK_FILE: &str = "phase3_snark_vk.bin";
const SETUP_CACHE_PHASE_FILES: [&str; 4] = [
    PHASE1_SETUP_FILE,
    PHASE2_SETUP_FILE,
    PHASE3_PRECOMPUTATION_FILE,
    PHASE3_VK_FILE,
];

/// SHA3-256 (hex) of a value's bincode encoding — the integrity identity the
/// snapshot manifest records for each phase VK.
fn bincode_sha3<T: serde::Serialize>(value: &T) -> anyhow::Result<String> {
    use sha3::Digest as _;
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard())
        .context("while encoding a VK for hashing")?;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&bytes);
    Ok(super::hex_encode(&hasher.finalize()))
}

fn write_bincode<T: serde::Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("while creating {}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    bincode::serde::encode_into_std_write(value, &mut writer, bincode::config::standard())
        .with_context(|| format!("while writing {}", path.display()))?;
    // BufWriter's Drop swallows flush errors; surface short writes here instead.
    writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("while flushing {}: {e}", path.display()))?
        .sync_all()
        .with_context(|| format!("while syncing {}", path.display()))?;
    Ok(())
}

fn read_bincode<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let file =
        std::fs::File::open(path).with_context(|| format!("while opening {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    bincode::serde::decode_from_std_read(&mut reader, bincode::config::standard())
        .with_context(|| format!("while reading {}", path.display()))
}
