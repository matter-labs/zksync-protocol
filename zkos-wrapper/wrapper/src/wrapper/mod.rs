use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Context as _;
use execution_utils::unrolled::UnrolledProgramProof;

use crate::circuits::{BinaryCommitment, RiscWrapperWitness};
use crate::{
    BoojumWorker, CompressionProof, CompressionVK, RiscWrapperProof, RiscWrapperVK,
    SnarkWrapperProof, SnarkWrapperVK,
};

#[cfg(not(feature = "gpu"))]
mod cpu;
#[cfg(feature = "gpu")]
mod gpu;

#[cfg(not(feature = "gpu"))]
use self::cpu as backend;
#[cfg(feature = "gpu")]
use self::gpu as backend;

// ==============================================================================
// Public Wrapper Configuration
// ==============================================================================
//
// A wrapper instance represents one stable proving environment. We keep the
// configuration intentionally small for now so the public API tracks the
// concrete inputs that determine the reusable setup chain.

#[derive(Clone, Debug, Default)]
pub struct SnarkWrapperConfig {
    pub bin: Option<PathBuf>,
    pub text: Option<PathBuf>,
    pub trusted_setup: Option<PathBuf>,
    pub threads: Option<usize>,
    /// When enabled, the RISC wrapper circuit packs registers 10..=16 directly as
    /// public inputs (no keccak) and constrains registers 18..=25 to equal
    /// `BinaryCommitment::aux_params` instead of folding them into the digest.
    pub check_aux_params: bool,
    /// Trusted phase-1 VK to be reused instead of deriving it from the binary.
    pub risc_wrapper_vk: Option<RiscWrapperVK>,
    /// Trusted phase-2 VK to be reused instead of deriving it from the phase-1 VK.
    pub compression_vk: Option<CompressionVK>,
    /// Trusted phase-3 VK to be reused instead of deriving it from the SNARK setup.
    pub snark_vk: Option<SnarkWrapperVK>,
    /// Trusted binary commitment to be reused instead of deriving it from `bin`/`text`.
    ///
    /// Deriving recomputes the layer setups of the base program and both embedded
    /// recursion verifiers on the CPU (minutes for a production-sized base binary), yet
    /// the result is a pure function of those binaries: `aux_params` is the app-program
    /// chain commitment a caller like the prover service already knows (it is pinned per
    /// protocol version and checked against every FRI proof), and `end_params` comes from
    /// the embedded unified verifier alone ([`BinaryCommitment::default`]). When set,
    /// `bin`/`text` are not read.
    ///
    /// The commitment is baked into the phase-1 circuit and therefore the VK: a wrong
    /// value yields a *different* VK (proofs then fail against the registered VK hash
    /// downstream), never a VK that accepts wrong-program proofs — but supply a trusted
    /// value, or VK derivation is silently wrong.
    pub binary_commitment: Option<BinaryCommitment>,
}

// ==============================================================================
// Stateful Wrapper API
// ==============================================================================
//
// The wrapper owns only the stable session-level state that is worth caching:
// the binary commitment and the backend-specific setup chain. Proof artifacts
// stay outside so library callers remain free to serialize or route them as
// they see fit.

pub struct SnarkWrapper {
    config: SnarkWrapperConfig,
    binary_commitment: Option<BinaryCommitment>,
    worker: BoojumWorker,
    backend: backend::BackendState,
}

/// Host-resident setup caches (plus their configuration and the loaded binary
/// commitment) extracted from a [`SnarkWrapper`] session.
///
/// Deriving the setup chain from scratch costs minutes, while rebuilding a wrapper from
/// this cache via [`SnarkWrapper::from_host_cache`] is near-instant. The cache holds no
/// device memory, so callers that must leave the GPU completely free between jobs can
/// drop the `SnarkWrapper` after each job and keep only the cache.
pub struct SnarkWrapperHostCache {
    config: SnarkWrapperConfig,
    binary_commitment: Option<BinaryCommitment>,
    backend: backend::BackendState,
}

impl SnarkWrapper {
    pub fn new(config: SnarkWrapperConfig) -> anyhow::Result<Self> {
        if config.bin.is_some() != config.text.is_some() {
            anyhow::bail!("Both --bin and --text must be provided together");
        }
        validate_trusted_setup_file(&config.trusted_setup)?;

        let worker = create_boojum_worker(config.threads);

        // A configured commitment seeds the lazy cache, so `binary_commitment()` never
        // pays the multi-minute derivation from `bin`/`text`. Without
        // `check_aux_params` the derivation path deliberately normalizes to
        // `BinaryCommitment::default()` (aux params are never consumed); a provided
        // value must not bypass that, or the two paths would synthesize different VKs
        // for the same inputs.
        let binary_commitment = if config.check_aux_params {
            config.binary_commitment
        } else {
            if config.binary_commitment.is_some() {
                tracing::warn!(
                    "binary_commitment is ignored without check_aux_params: end_params \
                     always comes from the fixed unified verifier binary"
                );
            }
            None
        };

        Ok(Self {
            config,
            binary_commitment,
            worker,
            backend: backend::BackendState::new(),
        })
    }

    /// Build a wrapper that adopts the setup caches (and configuration) of a previous
    /// session. See [`SnarkWrapperHostCache`].
    pub fn from_host_cache(cache: SnarkWrapperHostCache) -> anyhow::Result<Self> {
        let mut wrapper = Self::new(cache.config)?;
        wrapper.binary_commitment = cache.binary_commitment;
        wrapper.backend = cache.backend;
        Ok(wrapper)
    }

    /// Consume the wrapper, keeping only its host-resident setup caches.
    ///
    /// Any device-resident state (the STARK prover context on GPU builds) is released
    /// here, so holding the returned cache keeps no GPU memory allocated.
    pub fn into_host_cache(mut self) -> SnarkWrapperHostCache {
        self.backend.release_device_state();
        SnarkWrapperHostCache {
            config: self.config,
            binary_commitment: self.binary_commitment,
            backend: self.backend,
        }
    }
}

/// Version stamp of the on-disk setup-snapshot format; bump on layout changes so old
/// snapshots are skipped instead of misread.
const SETUP_CACHE_FORMAT_VERSION: u32 = 3;
const SETUP_CACHE_MANIFEST_FILE: &str = "manifest.json";

/// Compatibility fingerprint stored next to a setup snapshot. Loading validates every
/// field, so a snapshot from a different build shape (backend, security level, L1
/// domain size, aux-params mode) or a different bound app binary is skipped, not
/// misused.
#[derive(serde::Serialize, serde::Deserialize)]
struct SetupCacheManifest {
    format_version: u32,
    /// Released wrapper version the snapshot was derived by. A released circuit
    /// change bumps it and invalidates old snapshots; in-tree changes between
    /// releases are not distinguished (the CI fixture tests are the guard there).
    wrapper_version: String,
    backend: String,
    security_model: String,
    l1_verifier_domain_size_log: usize,
    /// The phase-1 circuit bakes this flag in, so it moves the whole VK chain.
    check_aux_params: bool,
    /// SHA3-256 of the bound app binary's `bin`/`text` files at save time. Only
    /// recorded (and only required) when the commitment is derived from the files:
    /// with a pinned `binary_commitment` the commitments are compared instead, and
    /// without `check_aux_params` the VK does not bind an app binary at all.
    bin_sha3: Option<String>,
    text_sha3: Option<String>,
    /// The commitment memo at save time: `[end_params, aux_params]`, absent when the
    /// retired session never loaded one.
    binary_commitment: Option<[[u32; 8]; 2]>,
    /// Byte length of every phase file, checked before decoding (a truncated stream
    /// would otherwise abort inside gpu-prover's readers instead of erroring).
    file_lengths: std::collections::BTreeMap<String, u64>,
    /// SHA3-256 of each phase VK's bincode encoding, phase order; re-checked against
    /// the decoded VKs on load so swapped or mismatched files are rejected.
    vk_sha3: [String; 3],
}

/// The identity half of the manifest — everything derived from the build and the
/// config rather than from the snapshot's files.
fn manifest_identity(
    config: &SnarkWrapperConfig,
    binary_commitment: Option<BinaryCommitment>,
) -> anyhow::Result<SetupCacheManifest> {
    // With a pinned commitment the files are never read (and may be absent), so the
    // binary identity is the commitment itself; hash the files only when they are
    // what the commitment will be derived from.
    let hash_binaries = config.check_aux_params && config.binary_commitment.is_none();
    Ok(SetupCacheManifest {
        format_version: SETUP_CACHE_FORMAT_VERSION,
        wrapper_version: env!("CARGO_PKG_VERSION").to_string(),
        backend: if cfg!(feature = "gpu") { "gpu" } else { "cpu" }.to_string(),
        security_model: format!("{:?}", crate::active_security::ACTIVE_SECURITY_MODEL),
        l1_verifier_domain_size_log: crate::L1_VERIFIER_DOMAIN_SIZE_LOG,
        check_aux_params: config.check_aux_params,
        bin_sha3: if hash_binaries {
            config.bin.as_deref().map(file_sha3).transpose()?
        } else {
            None
        },
        text_sha3: if hash_binaries {
            config.text.as_deref().map(file_sha3).transpose()?
        } else {
            None
        },
        binary_commitment: binary_commitment.map(|bc| [bc.end_params, bc.aux_params]),
        file_lengths: Default::default(),
        vk_sha3: Default::default(),
    })
}

/// SHA3-256 of a file, hex-encoded. Reads the file once (~0.3s for a production app
/// binary) — paid on snapshot save and load only, never on the proving path.
fn file_sha3(path: &Path) -> anyhow::Result<String> {
    use sha3::Digest as _;
    let bytes = std::fs::read(path).with_context(|| format!("while reading {}", path.display()))?;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(&bytes);
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl SnarkWrapperHostCache {
    /// Whether `dir` holds a setup snapshot (compatible or not). NOTE: an
    /// *incompatible* snapshot also reports true, so gating "save once" on this alone
    /// leaves a stale snapshot in place forever; prefer saving whenever
    /// [`Self::load_from_dir`] returned `None` — saves remove the previous phase
    /// files, so overwriting a stale snapshot is safe.
    pub fn snapshot_exists(dir: &Path) -> bool {
        dir.join(SETUP_CACHE_MANIFEST_FILE).is_file()
    }

    /// Persist the host-resident setup caches as files under `dir` so a later process
    /// can skip the multi-minute setup-chain derivation entirely (measured ~14 minutes
    /// for phases 1+3 of a production configuration on an A100 host, vs seconds of
    /// file reads). All-or-nothing: the full phase 1..3 chain must be derived, any
    /// previous snapshot files in `dir` are replaced, and the manifest is written last
    /// (a save interrupted before it leaves no manifest, so the remnants read as "no
    /// snapshot"). The CRS is never written — it already lives in the trusted-setup
    /// file and is re-read on demand. GPU builds only.
    pub fn save_to_dir(&self, dir: &Path) -> anyhow::Result<()> {
        // Every reason to decline is checked before the existing snapshot is touched,
        // so a save that bails never destroys a previously valid one.
        anyhow::ensure!(
            self.backend.has_full_setup_chain(),
            "refusing to save a setup snapshot: the phase 1..3 chain is not fully \
             derived on this backend"
        );
        anyhow::ensure!(
            self.config.risc_wrapper_vk.is_none()
                && self.config.compression_vk.is_none()
                && self.config.snark_vk.is_none(),
            "refusing to save a setup snapshot from a session with pinned VKs: the \
             snapshot would present the override as a derived chain"
        );
        let mut manifest = manifest_identity(&self.config, self.binary_commitment)?;
        manifest.vk_sha3 = self.backend.setup_chain_vk_sha3()?;

        std::fs::create_dir_all(dir)
            .with_context(|| format!("while creating {}", dir.display()))?;
        let manifest_path = dir.join(SETUP_CACHE_MANIFEST_FILE);
        // Invalidate any previous snapshot before touching its files, so an
        // interrupted write can't leave a manifest attesting to a mixed chain.
        if manifest_path.exists() {
            std::fs::remove_file(&manifest_path)
                .with_context(|| format!("while removing the stale {}", manifest_path.display()))?;
        }
        manifest.file_lengths = self.backend.save_setups_to_dir(dir)?;
        let file = std::fs::File::create(&manifest_path)
            .with_context(|| format!("while creating {}", manifest_path.display()))?;
        serde_json::to_writer_pretty(&file, &manifest)
            .with_context(|| format!("while writing {}", manifest_path.display()))?;
        file.sync_all()
            .with_context(|| format!("while syncing {}", manifest_path.display()))?;
        Ok(())
    }

    /// Rebuild a host cache from a [`Self::save_to_dir`] snapshot, adopting `config`
    /// the way a fresh session would. Returns `Ok(None)` — derive from scratch — when
    /// no snapshot exists or its manifest doesn't match this build's backend, security
    /// level, L1 domain size, or `config.binary_commitment` (when both sides pin one);
    /// a snapshot that matches but fails to read is an error, so corruption is
    /// reported rather than silently recomputed around.
    pub fn load_from_dir(dir: &Path, config: SnarkWrapperConfig) -> anyhow::Result<Option<Self>> {
        let manifest_path = dir.join(SETUP_CACHE_MANIFEST_FILE);
        if !manifest_path.is_file() {
            return Ok(None);
        }
        let file = std::fs::File::open(&manifest_path)
            .with_context(|| format!("while opening {}", manifest_path.display()))?;
        let manifest: SetupCacheManifest = match serde_json::from_reader(file) {
            Ok(manifest) => manifest,
            Err(e) => {
                tracing::warn!("ignoring setup snapshot with unreadable manifest: {e}");
                return Ok(None);
            }
        };

        let expected = manifest_identity(&config, config.binary_commitment)?;
        // The bound binary matters exactly when `check_aux_params` is on (it is what
        // the phase-1 circuit bakes in); there it must be *verified* the same — a
        // pinned commitment matching the saved one, or bin/text hashing to what was
        // saved — never assumed. Without `check_aux_params` the VK binds no app
        // binary, so there is nothing to compare.
        let same_binary = if !expected.check_aux_params {
            true
        } else {
            match (manifest.binary_commitment, expected.binary_commitment) {
                (Some(saved), Some(configured)) => saved == configured,
                _ => {
                    manifest.bin_sha3.is_some()
                        && manifest.bin_sha3 == expected.bin_sha3
                        && manifest.text_sha3.is_some()
                        && manifest.text_sha3 == expected.text_sha3
                }
            }
        };
        let compatible = manifest.format_version == expected.format_version
            && manifest.wrapper_version == expected.wrapper_version
            && manifest.backend == expected.backend
            && manifest.security_model == expected.security_model
            && manifest.l1_verifier_domain_size_log == expected.l1_verifier_domain_size_log
            && manifest.check_aux_params == expected.check_aux_params
            && same_binary;
        if !compatible {
            tracing::warn!(
                "ignoring incompatible setup snapshot in {} (different wrapper build, \
                 build shape, aux-params mode, or bound app binary)",
                dir.display()
            );
            return Ok(None);
        }

        let backend = backend::BackendState::load_setups_from_dir(dir, &manifest.file_lengths)?;
        // The decoded VKs must be the ones the manifest attests, so swapped or
        // mismatched phase files are rejected even when they decode cleanly.
        let loaded_vk_sha3 = backend.setup_chain_vk_sha3()?;
        anyhow::ensure!(
            loaded_vk_sha3 == manifest.vk_sha3,
            "setup snapshot in {} decoded to different VKs than its manifest attests — \
             the snapshot is damaged or its files were replaced",
            dir.display()
        );
        let binary_commitment = manifest
            .binary_commitment
            .map(|[end_params, aux_params]| BinaryCommitment {
                end_params,
                aux_params,
            })
            .or(config.binary_commitment);
        Ok(Some(Self {
            config,
            binary_commitment,
            backend,
        }))
    }
}

impl SnarkWrapper {
    /// Proves phase 1 and verifies the generated RISC wrapper proof before returning it.
    pub fn prove_risc_wrapper(
        &mut self,
        program_proof: UnrolledProgramProof,
    ) -> anyhow::Result<RiscWrapperProof> {
        let binary_commitment = self.binary_commitment()?;
        let check_aux_params = self.config.check_aux_params;
        let start = Instant::now();
        let witness = RiscWrapperWitness::from_full_proof(
            program_proof,
            &binary_commitment,
            check_aux_params,
        )?;
        tracing::info!(
            "Phase 1 witness generation took {:.3}s",
            start.elapsed().as_secs_f64()
        );

        let proof = self.backend.prove_risc_wrapper(
            witness,
            binary_commitment,
            check_aux_params,
            &self.worker,
        )?;
        let start = Instant::now();
        if !self
            .verify_risc_wrapper(&proof)
            .context("while attempting to verify generated RISC wrapper proof")?
        {
            anyhow::bail!("RISC wrapper proof verification failed");
        }
        tracing::info!(
            "Phase 1 verification took {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(proof)
    }

    /// Verifies an existing phase-1 proof against this wrapper's resolved RISC wrapper VK.
    pub fn verify_risc_wrapper(&mut self, proof: &RiscWrapperProof) -> anyhow::Result<bool> {
        Ok(crate::verify_risc_wrapper_proof(
            proof,
            self.risc_wrapper_vk()?,
        ))
    }

    pub fn risc_wrapper_vk(&mut self) -> anyhow::Result<&RiscWrapperVK> {
        if self.config.risc_wrapper_vk.is_some() {
            return Ok(self
                .config
                .risc_wrapper_vk
                .as_ref()
                .expect("phase 1 config VK exists"));
        }

        if self.backend.cached_risc_wrapper_vk().is_some() {
            return Ok(self
                .backend
                .cached_risc_wrapper_vk()
                .expect("phase 1 cache VK exists"));
        }

        let binary_commitment = self.binary_commitment()?;
        let check_aux_params = self.config.check_aux_params;

        self.backend
            .risc_wrapper_vk(binary_commitment, check_aux_params, &self.worker)
    }

    /// Proves phase 2 and verifies the generated compression proof before returning it.
    pub fn prove_compression(
        &mut self,
        risc_wrapper_proof: RiscWrapperProof,
    ) -> anyhow::Result<CompressionProof> {
        let risc_wrapper_vk = self.risc_wrapper_vk()?.clone();

        let proof =
            self.backend
                .prove_compression(risc_wrapper_proof, risc_wrapper_vk, &self.worker)?;
        let start = Instant::now();
        if !self
            .verify_compression(&proof)
            .context("while attempting to verify generated compression proof")?
        {
            anyhow::bail!("Compression proof verification failed");
        }
        tracing::info!(
            "Phase 2 verification took {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(proof)
    }

    /// Verifies an existing phase-2 proof against this wrapper's resolved compression VK.
    pub fn verify_compression(&mut self, proof: &CompressionProof) -> anyhow::Result<bool> {
        Ok(crate::verify_compression_proof(
            proof,
            self.compression_vk()?,
        ))
    }

    pub fn compression_vk(&mut self) -> anyhow::Result<&CompressionVK> {
        if self.config.compression_vk.is_some() {
            return Ok(self
                .config
                .compression_vk
                .as_ref()
                .expect("phase 2 config VK exists"));
        }

        if self.backend.cached_compression_vk().is_some() {
            return Ok(self
                .backend
                .cached_compression_vk()
                .expect("phase 2 cache VK exists"));
        }

        let risc_wrapper_vk = self.risc_wrapper_vk()?.clone();

        self.backend.compression_vk(risc_wrapper_vk, &self.worker)
    }

    /// Proves phase 3 and verifies the generated SNARK proof before returning it.
    pub fn prove_snark(
        &mut self,
        compression_proof: CompressionProof,
        use_zk: bool,
    ) -> anyhow::Result<SnarkWrapperProof> {
        let compression_vk = self.compression_vk()?.clone();

        let proof = self.backend.prove_snark(
            compression_proof,
            compression_vk,
            &self.config.trusted_setup,
            self.config.snark_vk.as_ref(),
            use_zk,
        )?;
        let start = Instant::now();
        if !self
            .verify_snark(&proof)
            .context("while attempting to verify generated SNARK proof")?
        {
            anyhow::bail!("SNARK wrapper proof verification failed");
        }
        tracing::info!(
            "Phase 3 verification took {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(proof)
    }

    /// Runs the full FRI-to-SNARK pipeline and returns the verified SNARK proof.
    pub fn prove_all(
        &mut self,
        program_proof: UnrolledProgramProof,
        use_zk: bool,
    ) -> anyhow::Result<SnarkWrapperProof> {
        let start = Instant::now();
        let risc_wrapper_proof = self.prove_risc_wrapper(program_proof)?;
        let compression_proof = self.prove_compression(risc_wrapper_proof)?;
        let snark_proof = self.prove_snark(compression_proof, use_zk)?;
        tracing::info!(
            "Full FRI-to-SNARK pipeline took {:.3}s",
            start.elapsed().as_secs_f64()
        );

        Ok(snark_proof)
    }

    /// Verifies an existing phase-3 proof against this wrapper's resolved SNARK VK.
    pub fn verify_snark(&mut self, proof: &SnarkWrapperProof) -> anyhow::Result<bool> {
        Ok(crate::verify_snark_wrapper_proof(proof, self.snark_vk()?))
    }

    pub fn snark_vk(&mut self) -> anyhow::Result<&SnarkWrapperVK> {
        if self.config.snark_vk.is_some() {
            return Ok(self
                .config
                .snark_vk
                .as_ref()
                .expect("phase 3 config VK exists"));
        }

        if self.backend.cached_snark_vk().is_some() {
            return Ok(self
                .backend
                .cached_snark_vk()
                .expect("phase 3 cache VK exists"));
        }

        let compression_vk = self.compression_vk()?.clone();

        self.backend
            .snark_vk(&self.config.trusted_setup, compression_vk)
    }

    fn binary_commitment(&mut self) -> anyhow::Result<BinaryCommitment> {
        if let Some(binary_commitment) = self.binary_commitment {
            return Ok(binary_commitment);
        }

        let start = Instant::now();
        let binary_commitment = load_binary_commitment(
            &self.config.bin,
            &self.config.text,
            self.config.check_aux_params,
        )?;
        tracing::info!(
            "Binary commitment loading took {:.3}s",
            start.elapsed().as_secs_f64()
        );
        self.binary_commitment = Some(binary_commitment);

        Ok(binary_commitment)
    }
}

fn create_boojum_worker(threads: Option<usize>) -> BoojumWorker {
    match threads {
        Some(num_threads) => BoojumWorker::new_with_num_threads(num_threads),
        None => BoojumWorker::new(),
    }
}

fn validate_trusted_setup_file(trusted_setup: &Option<PathBuf>) -> anyhow::Result<()> {
    let Some(path) = trusted_setup else {
        return Ok(());
    };

    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "while attempting to read trusted setup metadata at {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "Trusted setup path must point to a file: {}",
            path.display()
        );
    }

    Ok(())
}

fn load_binary_commitment(
    bin: &Option<PathBuf>,
    text: &Option<PathBuf>,
    check_aux_params: bool,
) -> anyhow::Result<BinaryCommitment> {
    if !check_aux_params {
        if bin.is_some() || text.is_some() {
            tracing::warn!(
                "--bin/--text are ignored without --check-aux-params: end_params always comes \
                 from the fixed unified verifier binary, so the resulting VK does not depend on \
                 them. Pass --check-aux-params to bind the base program via aux_params."
            );
        }
        // `aux_params` is never consumed in this mode; `end_params` comes solely
        // from the fixed unified verifier binary, so the base program is not needed.
        return Ok(BinaryCommitment::default());
    }

    match (bin, text) {
        (Some(bin_path), Some(text_path)) => {
            let binary = std::fs::read(bin_path).with_context(|| {
                format!(
                    "while attempting to read the binary at {}",
                    bin_path.display()
                )
            })?;
            let text_data = std::fs::read(text_path).with_context(|| {
                format!(
                    "while attempting to read the text section at {}",
                    text_path.display()
                )
            })?;

            Ok(BinaryCommitment::from_base_binary(&binary, &text_data))
        }
        (None, None) => {
            anyhow::bail!(
                "--bin and --text are required when --check-aux-params is set (path to the base program)"
            )
        }
        _ => anyhow::bail!("Both --bin and --text must be provided together"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The small base program shipped with the repo's testing data. Loading its
    // commitment still computes the recursion-layer setups (minutes in debug,
    // ~3 min in release — same cost as the from_base_binary tests CI runs).
    const RISC_PROGRAM_BIN_PATH: &str = "testing_data/risc_app.bin";
    const RISC_PROGRAM_TEXT_PATH: &str = "testing_data/risc_app.text";

    fn config_with_base_program() -> SnarkWrapperConfig {
        SnarkWrapperConfig {
            bin: Some(PathBuf::from(RISC_PROGRAM_BIN_PATH)),
            text: Some(PathBuf::from(RISC_PROGRAM_TEXT_PATH)),
            check_aux_params: true,
            ..SnarkWrapperConfig::default()
        }
    }

    #[test]
    fn provided_binary_commitment_skips_derivation() {
        // Nonexistent paths prove the provided value short-circuits file loading
        // and the multi-minute layer-setup derivation.
        let provided = BinaryCommitment {
            end_params: [1; 8],
            aux_params: [2; 8],
        };
        let mut wrapper = SnarkWrapper::new(SnarkWrapperConfig {
            bin: Some(PathBuf::from("does/not/exist.bin")),
            text: Some(PathBuf::from("does/not/exist.text")),
            check_aux_params: true,
            binary_commitment: Some(provided),
            ..SnarkWrapperConfig::default()
        })
        .expect("wrapper is created");

        let commitment = wrapper
            .binary_commitment()
            .expect("provided commitment is returned without derivation");
        assert_eq!(commitment.end_params, provided.end_params);
        assert_eq!(commitment.aux_params, provided.aux_params);
    }

    #[test]
    fn host_cache_roundtrip_preserves_binary_commitment() {
        let mut wrapper =
            SnarkWrapper::new(config_with_base_program()).expect("wrapper is created");
        let commitment = wrapper
            .binary_commitment()
            .expect("binary commitment loads from testing data");

        let restored = SnarkWrapper::from_host_cache(wrapper.into_host_cache())
            .expect("wrapper restores from the host cache");

        let restored_commitment = restored
            .binary_commitment
            .expect("restoring must not lose the already-loaded binary commitment");
        assert_eq!(restored_commitment.end_params, commitment.end_params);
        assert_eq!(restored_commitment.aux_params, commitment.aux_params);
    }

    /// Full snapshot roundtrip on real setup data: derive the whole chain, save it,
    /// load it as a fresh session, require every phase's VK to survive unchanged, and
    /// prove from the loaded phase-3 setup (VKs alone cannot catch payload corruption).
    ///
    /// ```bash
    /// TRUSTED_SETUP_FILE=/path/to/setup_compact.key \
    ///   cargo test --release --features gpu -- --ignored setup_snapshot_roundtrip
    /// ```
    #[test]
    #[cfg(feature = "gpu")]
    #[ignore = "needs a GPU, the compact CRS (TRUSTED_SETUP_FILE) and ~30 minutes"]
    fn setup_snapshot_roundtrip_preserves_vks() {
        let trusted_setup =
            std::env::var("TRUSTED_SETUP_FILE").expect("set TRUSTED_SETUP_FILE to the compact CRS");
        let snapshot_dir = std::env::temp_dir().join(format!(
            "zkos-wrapper-setup-snapshot-test-{}",
            std::process::id()
        ));
        // Mirror the checked-in fixture lane: at security 100 it proves with
        // `check_aux_params = false` and `BinaryCommitment::default()` (see
        // `binary_commitment_for_testing`), so the fixture risc proof is provable
        // in-session and no binary identity is involved.
        let config = SnarkWrapperConfig {
            trusted_setup: Some(PathBuf::from(&trusted_setup)),
            ..SnarkWrapperConfig::default()
        };

        // Session 1: derive the full chain, produce a same-lane compression proof
        // from the checked-in risc proof, and snapshot the chain.
        let mut derived = SnarkWrapper::new(config.clone()).expect("wrapper is created");
        let derived_snark_vk =
            serde_json::to_string(&derived.snark_vk().expect("chain derives").clone()).unwrap();
        let risc_proof =
            crate::tests::deserialize_from_bin_file(crate::tests::path_constants::RISC_PROOF_PATH)
                .expect("risc proof fixture loads");
        let risc_wrapper_proof = derived
            .prove_risc_wrapper(risc_proof)
            .expect("phase 1 proves in the derive session");
        let compression_proof = derived
            .prove_compression(risc_wrapper_proof)
            .expect("phase 2 proves in the derive session");
        let derived_cache = derived.into_host_cache();
        let derived_risc_vk =
            serde_json::to_string(&derived_cache.backend.cached_risc_wrapper_vk()).unwrap();
        let derived_compression_vk =
            serde_json::to_string(&derived_cache.backend.cached_compression_vk()).unwrap();
        derived_cache
            .save_to_dir(&snapshot_dir)
            .expect("snapshot saves");

        // Session 2: load the snapshot cold and require the identical chain.
        let loaded_cache = SnarkWrapperHostCache::load_from_dir(&snapshot_dir, config)
            .expect("snapshot loads")
            .expect("snapshot is compatible");
        assert_eq!(
            serde_json::to_string(&loaded_cache.backend.cached_risc_wrapper_vk()).unwrap(),
            derived_risc_vk,
            "phase 1 VK changed across the snapshot roundtrip"
        );
        assert_eq!(
            serde_json::to_string(&loaded_cache.backend.cached_compression_vk()).unwrap(),
            derived_compression_vk,
            "phase 2 VK changed across the snapshot roundtrip"
        );
        let mut loaded = SnarkWrapper::from_host_cache(loaded_cache).expect("wrapper restores");
        let loaded_snark_vk =
            serde_json::to_string(&loaded.snark_vk().expect("cached VK returns").clone()).unwrap();
        assert_eq!(
            loaded_snark_vk, derived_snark_vk,
            "phase 3 VK changed across the snapshot roundtrip"
        );

        // VK equality alone cannot catch a corrupt setup payload (the VKs are decoded
        // independently of it), so prove through the loaded chain with the compression
        // proof the derive session produced: a mis-sized or damaged phase-3
        // precomputation fails proving or yields an invalid proof.
        let snark_proof = loaded
            .prove_snark(compression_proof, false)
            .expect("proving from the loaded phase-3 setup succeeds");
        assert!(
            crate::verify_snark_wrapper_proof(&snark_proof, loaded.snark_vk().unwrap()),
            "proof from the loaded setup does not verify — the snapshot payload is corrupt"
        );

        std::fs::remove_dir_all(&snapshot_dir).ok();
    }

    #[test]
    fn host_cache_roundtrip_preserves_config() {
        let sentinel_vk = RiscWrapperVK::default();
        let config = SnarkWrapperConfig {
            threads: Some(2),
            risc_wrapper_vk: Some(sentinel_vk.clone()),
            ..config_with_base_program()
        };

        let wrapper = SnarkWrapper::new(config).expect("wrapper is created");
        let restored = SnarkWrapper::from_host_cache(wrapper.into_host_cache())
            .expect("wrapper restores from the host cache");

        assert_eq!(
            restored.config.bin,
            Some(PathBuf::from(RISC_PROGRAM_BIN_PATH))
        );
        assert_eq!(
            restored.config.text,
            Some(PathBuf::from(RISC_PROGRAM_TEXT_PATH))
        );
        assert!(restored.config.check_aux_params);
        assert_eq!(restored.config.threads, Some(2));
        // A trusted VK provided via the config must survive the roundtrip, so the
        // restored session keeps resolving it without deriving the setup chain.
        assert_eq!(restored.config.risc_wrapper_vk, Some(sentinel_vk));
        // No commitment was loaded before caching, so none should appear after.
        assert!(restored.binary_commitment.is_none());
    }
}
