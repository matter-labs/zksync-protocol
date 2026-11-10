use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use zkos_wrapper::interface;

#[derive(Parser)]
#[command(
    name = "wrapper",
    version,
    about = "Wrap FRI proofs from zksync-airbender into SNARKs verifiable on Ethereum"
)]
struct Cli {
    /// Number of worker threads (defaults to all available cores)
    #[arg(long, global = true)]
    threads: Option<usize>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Full pipeline: FRI proof -> SNARK proof (phases 1+2+3)
    ProveAll {
        /// Path to the FRI proof JSON (UnrolledProgramProof from airbender)
        #[arg(long)]
        proof: PathBuf,

        /// Path to the base program .bin file (required with --check-aux-params)
        #[arg(long, requires = "text", required_if_eq("check_aux_params", "true"))]
        bin: Option<PathBuf>,

        /// Path to the base program .text file (required with --check-aux-params)
        #[arg(long, requires = "bin", required_if_eq("check_aux_params", "true"))]
        text: Option<PathBuf>,

        /// Output directory for proof and VK files
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Path to trusted setup (CRS) file. If omitted, uses fake crs_42 for testing.
        #[arg(long)]
        trusted_setup: Option<PathBuf>,

        /// Enable zero-knowledge padding in SNARK proving phase
        #[arg(long)]
        use_zk: bool,

        /// Save intermediate proofs (risc wrapper, compression) alongside final SNARK
        #[arg(long)]
        save_intermediates: bool,

        /// Pack registers 10..=16 directly as public inputs and constrain
        /// registers 18..=25 to `BinaryCommitment::aux_params` (instead of
        /// hashing registers 10..=25 into the public input).
        #[arg(long)]
        check_aux_params: bool,
    },

    /// Phase 1: Wrap FRI proof into a boojum STARK proof
    ProveRiscWrapper {
        /// Path to the FRI proof JSON (UnrolledProgramProof)
        #[arg(long)]
        proof: PathBuf,

        /// Path to the base program .bin file (required with --check-aux-params)
        #[arg(long, requires = "text", required_if_eq("check_aux_params", "true"))]
        bin: Option<PathBuf>,

        /// Path to the base program .text file (required with --check-aux-params)
        #[arg(long, requires = "bin", required_if_eq("check_aux_params", "true"))]
        text: Option<PathBuf>,

        /// Output directory
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Pack registers 10..=16 directly as public inputs and constrain
        /// registers 18..=25 to `BinaryCommitment::aux_params` (instead of
        /// hashing registers 10..=25 into the public input).
        #[arg(long)]
        check_aux_params: bool,
    },

    /// Phase 2: Compress a STARK wrapper proof (Poseidon2-based re-hashing)
    ProveCompression {
        /// Path to risc_wrapper_proof.json
        #[arg(long)]
        risc_wrapper_proof: PathBuf,

        /// Optional path to risc_wrapper_vk.json to reuse a saved phase-1 VK
        #[arg(long)]
        risc_wrapper_vk: Option<PathBuf>,

        /// Path to the base program .bin file (needed with --check-aux-params
        /// unless a saved --risc-wrapper-vk is supplied)
        #[arg(long, requires = "text")]
        bin: Option<PathBuf>,

        /// Path to the base program .text file (needed with --check-aux-params
        /// unless a saved --risc-wrapper-vk is supplied)
        #[arg(long, requires = "bin")]
        text: Option<PathBuf>,

        /// Output directory
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Must match the value used to produce the phase-1 proof / VK chain.
        #[arg(long)]
        check_aux_params: bool,
    },

    /// Phase 3: Wrap compressed STARK proof into a BN256 SNARK
    ProveSnark {
        /// Path to compression_proof.json
        #[arg(long)]
        compression_proof: PathBuf,

        /// Optional path to compression_vk.json to reuse a saved phase-2 VK
        #[arg(long)]
        compression_vk: Option<PathBuf>,

        /// Path to the base program .bin file (needed with --check-aux-params
        /// unless a saved --compression-vk is supplied)
        #[arg(long, requires = "text")]
        bin: Option<PathBuf>,

        /// Path to the base program .text file (needed with --check-aux-params
        /// unless a saved --compression-vk is supplied)
        #[arg(long, requires = "bin")]
        text: Option<PathBuf>,

        /// Output directory
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Path to trusted setup (CRS) file. If omitted, uses fake crs_42 for testing.
        #[arg(long)]
        trusted_setup: Option<PathBuf>,

        /// Enable zero-knowledge padding in SNARK proving
        #[arg(long)]
        use_zk: bool,

        /// Must match the value used to produce the phase-1 proof / VK chain.
        #[arg(long)]
        check_aux_params: bool,
    },

    /// Generate verification keys without a proof (for deployment preparation)
    GenerateVk {
        /// Output directory for VK files
        #[arg(short, long)]
        output_dir: PathBuf,

        /// Path to the base program .bin file (required with --check-aux-params)
        #[arg(long, requires = "text", required_if_eq("check_aux_params", "true"))]
        bin: Option<PathBuf>,

        /// Path to the base program .text file (required with --check-aux-params)
        #[arg(long, requires = "bin", required_if_eq("check_aux_params", "true"))]
        text: Option<PathBuf>,

        /// Path to trusted setup (CRS) file. If omitted, uses fake crs_42.
        #[arg(long)]
        trusted_setup: Option<PathBuf>,

        /// Pack registers 10..=16 directly as public inputs and constrain
        /// registers 18..=25 to `BinaryCommitment::aux_params`.
        #[arg(long)]
        check_aux_params: bool,
    },

    /// Compute the recursion-chain hash (aux_params, folded base -> unrolled) for a base program
    ComputeAuxParams {
        /// Path to the base program .bin file
        #[arg(long, requires = "text")]
        bin: PathBuf,

        /// Path to the base program .text file
        #[arg(long, requires = "bin")]
        text: PathBuf,

        /// Optional path to write aux_params as a JSON [u32; 8] array
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Compute the Keccak256 hash of a SNARK verification key
    VkHash {
        /// Path to snark_vk.json
        #[arg(long)]
        vk: PathBuf,
    },

    /// Verify a proof at any pipeline stage
    Verify {
        /// Pipeline stage of the proof
        #[arg(long, value_enum)]
        stage: VerifyStage,

        /// Path to the proof JSON file
        #[arg(long)]
        proof: PathBuf,

        /// Path to the verification key JSON file
        #[arg(long)]
        vk: PathBuf,
    },
}

#[derive(Clone, ValueEnum)]
enum VerifyStage {
    RiscWrapper,
    Compression,
    Snark,
}

impl From<VerifyStage> for zkos_wrapper::interface::VerifyStage {
    fn from(this: VerifyStage) -> Self {
        match this {
            VerifyStage::RiscWrapper => Self::RiscWrapper,
            VerifyStage::Compression => Self::Compression,
            VerifyStage::Snark => Self::Snark,
        }
    }
}

// `INFO` logs are enabled by default, but `RUST_LOG` overrides are supported as well.
fn init_tracing() -> anyhow::Result<()> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("Failed to initialize tracing subscriber: {error}"))?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    init_tracing()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::ProveAll {
            proof,
            bin,
            text,
            output_dir,
            trusted_setup,
            use_zk,
            save_intermediates,
            check_aux_params,
        } => interface::cmd_prove_all(
            proof,
            bin,
            text,
            output_dir,
            trusted_setup,
            use_zk,
            save_intermediates,
            check_aux_params,
            cli.threads,
        ),

        Commands::ProveRiscWrapper {
            proof,
            bin,
            text,
            output_dir,
            check_aux_params,
        } => interface::cmd_prove_risc_wrapper(
            proof,
            bin,
            text,
            output_dir,
            check_aux_params,
            cli.threads,
        ),

        Commands::ProveCompression {
            risc_wrapper_proof,
            risc_wrapper_vk,
            bin,
            text,
            output_dir,
            check_aux_params,
        } => interface::cmd_prove_compression(
            risc_wrapper_proof,
            risc_wrapper_vk,
            bin,
            text,
            output_dir,
            check_aux_params,
            cli.threads,
        ),

        Commands::ProveSnark {
            compression_proof,
            compression_vk,
            bin,
            text,
            output_dir,
            trusted_setup,
            use_zk,
            check_aux_params,
        } => interface::cmd_prove_snark(
            compression_proof,
            compression_vk,
            bin,
            text,
            output_dir,
            trusted_setup,
            use_zk,
            check_aux_params,
            cli.threads,
        ),

        Commands::GenerateVk {
            output_dir,
            bin,
            text,
            trusted_setup,
            check_aux_params,
        } => interface::cmd_generate_vk(
            output_dir,
            bin,
            text,
            trusted_setup,
            check_aux_params,
            cli.threads,
        ),

        Commands::ComputeAuxParams { bin, text, output } => {
            interface::cmd_compute_aux_params(bin, text, output)
        }

        Commands::VkHash { vk } => interface::cmd_vk_hash(vk),

        Commands::Verify { stage, proof, vk } => interface::cmd_verify(stage.into(), proof, vk),
    }
}
