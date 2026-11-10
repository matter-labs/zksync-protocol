use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn testing_data() -> PathBuf {
    manifest_dir().join("testing_data")
}

fn wrapper_bin() -> PathBuf {
    // The binary is built alongside the test; cargo puts it in the same target dir.
    let mut path = std::env::current_exe().expect("current_exe");
    // current_exe is something like target/release/deps/cli-<hash>
    // Go up to target/release/ and append the binary name.
    path.pop(); // remove test binary name
    path.pop(); // remove "deps"
    path.push("wrapper");
    path
}

/// Run the wrapper binary with the given arguments.
fn run(args: &[&str]) -> std::process::Output {
    Command::new(wrapper_bin())
        .args(args)
        .env("RUST_MIN_STACK", "67108864")
        .output()
        .expect("failed to execute wrapper binary")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn data(name: &str) -> String {
    testing_data().join(name).to_string_lossy().to_string()
}

// ---------------------------------------------------------------------------
// Lightweight tests (always run)
// ---------------------------------------------------------------------------

#[test]
fn verify_risc_wrapper() {
    let output = run(&[
        "verify",
        "--stage",
        "risc-wrapper",
        "--proof",
        &data("risc_wrapper_proof_80sb"),
        "--vk",
        &data("risc_wrapper_vk_80sb"),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "verify risc-wrapper failed: {out}{}",
        stderr(&output)
    );
    assert!(out.contains("VALID"), "expected VALID in output: {out}");
}

#[test]
fn verify_compression() {
    let output = run(&[
        "verify",
        "--stage",
        "compression",
        "--proof",
        &data("compression_proof_80sb"),
        "--vk",
        &data("compression_vk_80sb"),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "verify compression failed: {out}{}",
        stderr(&output)
    );
    assert!(out.contains("VALID"), "expected VALID in output: {out}");
}

#[test]
fn verify_snark() {
    let output = run(&[
        "verify",
        "--stage",
        "snark",
        "--proof",
        &data("snark_wrapper_proof_80sb"),
        "--vk",
        &data("snark_wrapper_vk_80sb"),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "verify snark failed: {out}{}",
        stderr(&output)
    );
    assert!(out.contains("VALID"), "expected VALID in output: {out}");
}

#[test]
fn vk_hash() {
    let output = run(&["vk-hash", "--vk", &data("snark_wrapper_vk_80sb")]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "vk-hash failed: {out}{}",
        stderr(&output)
    );
    assert!(
        out.contains("VK hash"),
        "expected 'VK hash' in output: {out}"
    );
}

#[test]
fn verify_mismatched_proof_and_vk() {
    // Use snark proof with compression VK — should fail verification.
    let output = run(&[
        "verify",
        "--stage",
        "snark",
        "--proof",
        &data("snark_wrapper_proof_80sb"),
        "--vk",
        &data("compression_vk_80sb"),
    ]);
    assert!(
        !output.status.success(),
        "expected failure for mismatched proof/VK"
    );
}

#[test]
fn verify_missing_file() {
    let output = run(&[
        "verify",
        "--stage",
        "snark",
        "--proof",
        "/nonexistent/proof.json",
        "--vk",
        &data("snark_wrapper_vk_80sb"),
    ]);
    assert!(
        !output.status.success(),
        "expected failure for missing file"
    );
}

#[test]
fn no_subcommand_shows_error() {
    let output = run(&[]);
    assert!(
        !output.status.success(),
        "expected non-zero exit with no subcommand"
    );
}

// ---------------------------------------------------------------------------
// Heavy prove tests (require ~150GB RAM, run with --ignored)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn prove_risc_wrapper() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run(&[
        "prove-risc-wrapper",
        "--proof",
        &data("risc_proof_80sb"),
        "--bin",
        &data("risc_app.bin"),
        "--text",
        &data("risc_app.text"),
        "-o",
        tmp.path().to_str().unwrap(),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "prove-risc-wrapper failed: {out}{}",
        stderr(&output)
    );
    assert!(
        tmp.path().join("risc_wrapper_proof.json").exists(),
        "missing risc_wrapper_proof.json"
    );
    assert!(
        tmp.path().join("risc_wrapper_vk.json").exists(),
        "missing risc_wrapper_vk.json"
    );
}

#[test]
#[ignore]
fn prove_compression() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run(&[
        "prove-compression",
        "--risc-wrapper-proof",
        &data("risc_wrapper_proof_80sb"),
        "--risc-wrapper-vk",
        &data("risc_wrapper_vk_80sb"),
        "-o",
        tmp.path().to_str().unwrap(),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "prove-compression failed: {out}{}",
        stderr(&output)
    );
    assert!(
        tmp.path().join("compression_proof.json").exists(),
        "missing compression_proof.json"
    );
    assert!(
        tmp.path().join("compression_vk.json").exists(),
        "missing compression_vk.json"
    );
}

#[test]
#[ignore]
fn prove_snark() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run(&[
        "prove-snark",
        "--compression-proof",
        &data("compression_proof_80sb"),
        "--compression-vk",
        &data("compression_vk_80sb"),
        "-o",
        tmp.path().to_str().unwrap(),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "prove-snark failed: {out}{}",
        stderr(&output)
    );
    assert!(
        tmp.path().join("snark_proof.json").exists(),
        "missing snark_proof.json"
    );
    assert!(
        tmp.path().join("snark_vk.json").exists(),
        "missing snark_vk.json"
    );
    assert!(out.contains("VK hash"), "expected VK hash in output: {out}");
}

#[test]
#[ignore]
fn prove_all_with_intermediates() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run(&[
        "prove-all",
        "--proof",
        &data("risc_proof_80sb"),
        "--bin",
        &data("risc_app.bin"),
        "--text",
        &data("risc_app.text"),
        "--save-intermediates",
        "-o",
        tmp.path().to_str().unwrap(),
    ]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "prove-all failed: {out}{}",
        stderr(&output)
    );
    // Final outputs
    assert!(
        tmp.path().join("snark_proof.json").exists(),
        "missing snark_proof.json"
    );
    assert!(
        tmp.path().join("snark_vk.json").exists(),
        "missing snark_vk.json"
    );
    // Intermediates
    assert!(
        tmp.path().join("risc_wrapper_proof.json").exists(),
        "missing risc_wrapper_proof.json"
    );
    assert!(
        tmp.path().join("risc_wrapper_vk.json").exists(),
        "missing risc_wrapper_vk.json"
    );
    assert!(
        tmp.path().join("compression_proof.json").exists(),
        "missing compression_proof.json"
    );
    assert!(
        tmp.path().join("compression_vk.json").exists(),
        "missing compression_vk.json"
    );
    assert!(out.contains("VK hash"), "expected VK hash in output: {out}");
}

#[test]
#[ignore]
fn generate_vk() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run(&["generate-vk", "-o", tmp.path().to_str().unwrap()]);
    let out = stdout(&output);
    assert!(
        output.status.success(),
        "generate-vk failed: {out}{}",
        stderr(&output)
    );
    assert!(
        tmp.path().join("risc_wrapper_vk.json").exists(),
        "missing risc_wrapper_vk.json"
    );
    assert!(
        tmp.path().join("compression_vk.json").exists(),
        "missing compression_vk.json"
    );
    assert!(
        tmp.path().join("snark_vk.json").exists(),
        "missing snark_vk.json"
    );
    assert!(out.contains("VK hash"), "expected VK hash in output: {out}");
}
