#![expect(warnings)]
#![feature(slice_from_ptr_range)]
#![feature(allocator_api)]

use clap::Parser;
use prover::{cs::one_row_compiler::CompiledCircuitArtifact, field::Mersenne31Field};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;
use zkos_verifier_generator::{generate_from_parts, generate_inlined_configured};

mod mersenne_wrapper;
use mersenne_wrapper::MersenneBoojumWrapper;

/// Returns formatted rust code with verifier and inline verifier files.
fn generate_verifier_files(circuit: &CompiledCircuitArtifact<Mersenne31Field>) -> (String, String) {
    let verifier = format_rust_code(&generate_from_parts(&circuit).to_string()).unwrap();

    let inlined_verifier = format_rust_code(
        &generate_inlined_configured::<MersenneBoojumWrapper>(circuit.clone()).to_string(),
    )
    .unwrap();

    (verifier, inlined_verifier)
}

/// Runs rustfmt to format the code.
fn format_rust_code(code: &str) -> Result<String, String> {
    // Spawn the `rustfmt` process
    let mut rustfmt = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn rustfmt: {}", e))?;

    // Write the Rust code to `rustfmt`'s stdin
    if let Some(mut stdin) = rustfmt.stdin.take() {
        stdin
            .write_all(code.as_bytes())
            .map_err(|e| format!("Failed to write to rustfmt stdin: {}", e))?;
    }

    // Wait for `rustfmt` to complete and collect the formatted code
    let output = rustfmt
        .wait_with_output()
        .map_err(|e| format!("Failed to read rustfmt output: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "rustfmt failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Convert the output to a String
    String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF-8 in rustfmt output: {}", e))
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(
        long,
        default_value = "wrapper/src/inner_verifiers/unified_reduced/imports"
    )]
    output_dir: String,
    #[arg(
        long,
        default_value = "wrapper/src/inner_verifiers/blake_delegation/imports"
    )]
    blake_output_dir: String,
}

fn main() {
    let cli = Cli::parse();
    let output_dir = cli.output_dir;
    let blake_output_dir = cli.blake_output_dir;

    let dummy_bytecode = vec![0u32; setups::unified_reduced_machine::MAX_ROM_SIZE / 4];
    let compiled_circuit = setups::unified_reduced_machine::get_circuit(&dummy_bytecode);

    let (verifier, inline_verifier) = generate_verifier_files(&compiled_circuit);
    std::fs::write(Path::new(&output_dir).join("circuit_layout.rs"), verifier)
        .expect(&format!("Failed to write to {}", output_dir));
    std::fs::write(
        Path::new(&output_dir).join("circuit_quotient.rs"),
        inline_verifier,
    )
    .expect(&format!("Failed to write to {}", output_dir));

    let blake_compiled_circuit =
        setups::blake2_with_compression::get_delegation_circuit().compiled_circuit;
    let (verifier, inline_verifier) = generate_verifier_files(&blake_compiled_circuit);
    std::fs::write(
        Path::new(&blake_output_dir).join("circuit_layout.rs"),
        verifier,
    )
    .expect(&format!("Failed to write to {}", blake_output_dir));
    std::fs::write(
        Path::new(&blake_output_dir).join("circuit_quotient.rs"),
        inline_verifier,
    )
    .expect(&format!("Failed to write to {}", blake_output_dir));
}
