//! Host-based integration tests: drive the `eravm-prover-host` proving pipeline
//! in-process — no server, no HTTP. They replace the server-process harness the
//! prover service used before it moved to zksync-era, exercising the same host
//! library surface that service now consumes.
//!
//! All tests are `#[ignore]` because they need the LFS batch corpus (and, for
//! proving, a GPU + the guest binary + the SNARK trusted setup). Run one
//! explicitly, e.g.:
//!
//! ```sh
//! cargo test -p eravm-prover-host --features gpu_snark --test integration_test \
//!     -- --ignored --nocapture host_proves_fri_then_snark
//! ```
//!
//! Path/credential inputs are overridable via `IT_*` env vars so a binary built
//! on one machine (the CUDA build runner) can run on another (the GPU runner)
//! whose baked-in `CARGO_MANIFEST_DIR` points elsewhere.

use std::path::PathBuf;

use zksync_airbender_verifier::test_utils::read_proofs::old_root_read_proofs;
use zksync_cli_utils::{load_batch, save_batch, BatchInputFile};

// ---------------------------------------------------------------------------
// Path / env helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "gpu_fri")]
fn guest_dist_dir() -> PathBuf {
    std::env::var_os("IT_GUEST_DIST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../guest/dist/app"))
}

fn batch_file_path(filename: &str) -> PathBuf {
    std::env::var_os("IT_BATCHES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/era_mainnet_batches/binary")
        })
        .join(filename)
}

/// FRI verification key (a release asset; override with `IT_FRI_VK`).
/// `build_fri_prover` loads it strictly (never regenerates), so proving here
/// verifies against the same VK production uses.
#[cfg(feature = "gpu_fri")]
fn fri_vk_path() -> PathBuf {
    std::env::var_os("IT_FRI_VK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vks/fri_vk.bin"))
}

/// SNARK wrapper VK (a release asset; override with `IT_SNARK_VK`). Loaded when
/// present so the wrapper reuses it instead of re-deriving from the setup chain;
/// absent → derived on the fly.
#[cfg(feature = "gpu_fri")]
fn snark_vk_path() -> PathBuf {
    std::env::var_os("IT_SNARK_VK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vks/snark_vk.json"))
}

fn batch_number_from_filename(filename: &str) -> u64 {
    let raw = filename
        .strip_suffix(".bin.gz")
        .or_else(|| filename.strip_suffix(".bin"))
        .unwrap_or_else(|| panic!("batch filename must end in .bin or .bin.gz: {filename}"));
    raw.parse().unwrap_or_else(|_| {
        panic!("batch filename must start with a numeric batch number: {filename}")
    })
}

fn batch_input(filename: &str) -> BatchInputFile {
    BatchInputFile {
        number: batch_number_from_filename(filename),
        path: batch_file_path(filename),
    }
}

/// Default batch the proving/run tests use; override with `IT_BATCH_FILE`.
fn default_batch_file() -> String {
    std::env::var("IT_BATCH_FILE").unwrap_or_else(|_| "84730.bin.gz".to_owned())
}

// ---------------------------------------------------------------------------
// CPU-only: native verification vs. transpiler execution
// ---------------------------------------------------------------------------

/// Runs a batch through `run_batches`, which natively verifies it and re-runs
/// the same input on the transpiler, asserting the public inputs match. CPU
/// only — no GPU, no VK, no trusted setup — but still needs the LFS batch.
#[ignore = "requires the LFS batch corpus"]
#[test]
fn host_runs_batch_native_and_transpiler() {
    let batch = batch_input(&default_batch_file());
    println!("[test] run_batches on {}", batch.path.display());
    eravm_prover_host::run_batches(std::slice::from_ref(&batch), false)
        .expect("run_batches (native + transpiler) failed");
    println!("[test] native verification matched transpiler execution");
}

/// Regression guard for the streaming Merkle-proof verification (the
/// RAM-exhaustion DoS fix, PR #83). Batch `900065` is a synthetic v31 batch
/// (generated from a local Era node, not mainnet) with 140,059 unique storage
/// reads — the batch the fix was validated against.
///
/// The pre-fix path expanded every storage Merkle proof to full depth at once
/// (~1.15 GiB for this batch: 140_059 * 256 * 32 B). The transpiler runs the
/// actual compiled guest binary under the bounded guest heap, so this exercises
/// the streaming pass on CPU (no GPU needed). The 4022 MiB arena fits ~1.15 GiB,
/// so a regression to eager expansion no longer OOMs on this batch; it only
/// shows up as a larger peak.
#[ignore = "requires the LFS batch corpus and the built guest binary"]
#[test]
fn host_runs_read_heavy_batch_without_guest_oom() {
    let batch = batch_input("900065.bin.gz");
    println!(
        "[test] run_batches on read-heavy batch (140_059 unique reads): {}",
        batch.path.display()
    );
    eravm_prover_host::run_batches(std::slice::from_ref(&batch), false).expect(
        "run_batches failed — the guest may have OOMed on eager Merkle-proof expansion \
         (the RAM-exhaustion DoS may have regressed)",
    );
    println!("[test] read-heavy batch verified natively and on the transpiler without OOM");
}

/// Re-runs a batch with an old-root read proof for every `merkle_paths` entry.
/// Stored fixtures carry no read proofs, so this is the only guest run that
/// decodes a non-empty `prestate_read_proofs` and folds it on the transpiler.
#[ignore = "requires the LFS batch corpus and the built guest binary"]
#[test]
fn host_runs_batch_with_read_proofs() {
    let filename = default_batch_file();
    let mut input = load_batch(&batch_input(&filename)).expect("load batch");
    input.prestate_read_proofs =
        old_root_read_proofs(&input.merkle_paths).expect("build read proofs");
    assert!(!input.prestate_read_proofs.is_empty());

    let dir = std::env::temp_dir().join(format!("read-proofs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let batch = BatchInputFile {
        number: batch_number_from_filename(&filename),
        path: dir.join(&filename),
    };
    save_batch(&input, &batch.path).expect("save batch");
    let result = eravm_prover_host::run_batches(std::slice::from_ref(&batch), false);
    std::fs::remove_dir_all(&dir).ok();
    result.expect("run_batches with read proofs failed");
}

// ---------------------------------------------------------------------------
// GPU: FRI proving followed by SNARK wrapping, end-to-end in-process
// ---------------------------------------------------------------------------

/// End-to-end host proving path, mirroring what the service does per job but
/// without any network hop:
///   1. load the batch, natively verify it to get the expected public input;
///   2. build the GPU FRI prover against the release VK and prove the encoded
///      input — `prove_input` also verifies the proof against that VK;
///   3. cross-check the proven guest output equals the native public input;
///   4. strip the envelope to a raw FRI proof and wrap it into a SNARK;
///   5. round-trip the SNARK proof through `serde_json` as a shape check.
#[cfg(feature = "gpu_fri")]
#[ignore = "requires GPU, guest binary, LFS batch, and SNARK trusted setup"]
#[test]
fn host_proves_fri_then_snark() {
    use airbender_host::{Inputs, Proof, SecurityLevel};
    use eravm_prover_host::{
        app_bin_path, app_text_path, build_fri_prover, default_trusted_setup_download_url,
        default_trusted_setup_path, deserialize_from_file, download_trusted_setup_if_not_present,
        FriProverConfig, SnarkOptions, SnarkPipeline, SnarkWrapperProof, SnarkWrapperVK,
    };
    use zksync_airbender_verifier::Verify;
    use zksync_cli_utils::load_batch;

    let filename = default_batch_file();
    let batch = batch_input(&filename);
    let security = SecurityLevel::default();

    // 1. Load + native verify -> expected public input.
    println!("[test] Loading batch from {}", batch.path.display());
    let input = load_batch(&batch).expect("failed to load batch");
    let expected_public_input = input
        .clone()
        .verify()
        .expect("native verification failed")
        .proof_public_input;
    println!(
        "[test] Native public input for batch {}: {expected_public_input:?}",
        batch.number
    );

    // 2. Encode the verifier input to the guest word stream.
    let mut words = Inputs::new();
    words
        .push(&input)
        .expect("failed to encode AirbenderVerifierInput");

    // 3. Build the GPU FRI prover against the release VK and prove. The
    //    prover verifies the proof against that VK internally, and rejects a
    //    zero output (failed guest verification/commitment). The default config
    //    keeps the backend's own host-buffer pool sizing.
    println!("[test] Building GPU FRI prover against release VK...");
    let prover = build_fri_prover(
        &guest_dist_dir(),
        &fri_vk_path(),
        security,
        FriProverConfig::default(),
    )
    .expect("failed to build GPU FRI prover");
    println!("[test] Proving FRI for batch {}...", batch.number);
    let output = prover
        .prove_input(batch.number, words.words())
        .expect("FRI proving failed");

    // 4. The proven guest output must match the native public input.
    assert_eq!(
        output.output, expected_public_input,
        "proven guest output does not match native public input"
    );
    println!("[test] FRI proof verified; output matches native public input");

    // 5. Strip the envelope to a raw FRI proof for the SNARK wrapper.
    let raw_proof = match output.proof {
        Proof::Real(real) => real.into_inner(),
        Proof::Dev(_) => panic!("GPU prover unexpectedly returned a development proof"),
    };

    // Release the FRI prover's GPU memory before the SNARK wrapper allocates its
    // own device pool. Production runs FRI and SNARK in separate processes; here
    // they share one, so without this drop the wrapper's setup allocation OOMs
    // the device (shivini's static allocator) on top of the still-resident FRI
    // pool. `output` owns the proof data, so the prover is no longer needed.
    drop(prover);

    // 6. Provision the trusted setup (CRS). Cached in the system temp dir so
    //    the test stays self-contained; override via IT_SNARK_TRUSTED_SETUP.
    let trusted_setup = std::env::var_os("IT_SNARK_TRUSTED_SETUP")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut name = std::ffi::OsString::from("eravm-airbender-");
            name.push(default_trusted_setup_path().as_os_str());
            std::env::temp_dir().join(name)
        });
    download_trusted_setup_if_not_present(&trusted_setup, default_trusted_setup_download_url())
        .expect("failed to provision SNARK trusted setup");

    // Reuse the release SNARK VK when present; otherwise derive it.
    let snark_vk: Option<SnarkWrapperVK> = {
        let path = snark_vk_path();
        path.exists().then(|| {
            deserialize_from_file(&path.to_string_lossy()).expect("failed to load SNARK VK")
        })
    };

    // 7. Wrap the raw FRI proof into a SNARK.
    println!("[test] Wrapping FRI proof into a SNARK...");
    let snark_options = SnarkOptions {
        worker_threads: None,
        trusted_setup: Some(trusted_setup),
        use_zk: false,
        save_intermediates: false,
        bin: app_bin_path(&guest_dist_dir()),
        text: app_text_path(&guest_dist_dir()),
    };
    let mut pipeline =
        SnarkPipeline::new(&snark_options, snark_vk).expect("failed to build SNARK pipeline");
    let snark_proof = pipeline.prove(raw_proof).expect("SNARK wrapping failed");

    // 8. Shape check: the proof round-trips through serde_json.
    let json = serde_json::to_string(&snark_proof).expect("failed to serialize SNARK proof");
    let _back: SnarkWrapperProof =
        serde_json::from_str(&json).expect("SNARK proof did not round-trip through serde_json");
    println!("[test] SNARK proof produced and round-tripped successfully");
}
