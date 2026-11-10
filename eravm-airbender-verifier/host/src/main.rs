use airbender_host::SecurityLevel;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use eravm_prover_host::{
    app_bin_path, app_text_path, default_fri_vk_path, default_trusted_setup_download_url,
    default_trusted_setup_path, deserialize_from_file, dist_dir,
    download_trusted_setup_if_not_present, generate_fri_vk, generate_snark_vk, prove_batches_fri,
    run_batches, wrap_to_snark, SnarkOptions, SnarkWrapperVK,
};
use std::path::PathBuf;
use zksync_cli_utils::{init_tracing, resolve_batch_inputs, BatchInputFile};

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityLevelArg {
    #[value(name = "80")]
    Bits80,
    #[value(name = "100")]
    Bits100,
}

impl From<SecurityLevelArg> for SecurityLevel {
    fn from(security: SecurityLevelArg) -> Self {
        match security {
            SecurityLevelArg::Bits80 => Self::Bits80,
            SecurityLevelArg::Bits100 => Self::Bits100,
        }
    }
}

impl From<SecurityLevel> for SecurityLevelArg {
    fn from(security: SecurityLevel) -> Self {
        match security {
            SecurityLevel::Bits80 => Self::Bits80,
            SecurityLevel::Bits100 => Self::Bits100,
        }
    }
}

impl Default for SecurityLevelArg {
    fn default() -> Self {
        SecurityLevel::default().into()
    }
}

impl std::fmt::Display for SecurityLevelArg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", SecurityLevel::from(*self))
    }
}

#[derive(Debug, Parser)]
#[command(version, about = "Run, prove, and wrap Era mainnet batches")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(RunArgs),
    ProveFri(ProveFriArgs),
    ProveSnark(ProveSnarkArgs),
    /// Download the bellman SNARK trusted setup (CRS) so it is on disk before
    /// running `prove-snark`. Skips the download if the file already exists.
    DownloadTrustedSetup(DownloadTrustedSetupArgs),
    /// Generate the FRI and SNARK verification keys into a directory. The
    /// server only loads VKs from disk; the release-artifacts workflow runs this
    /// to produce the `fri_vk.bin` / `snark_vk.json` assets attached to each
    /// GitHub release. Run it locally to regenerate them for development.
    #[command(name = "gen-vks")]
    GenerateVks(GenerateVksArgs),
}

#[derive(Debug, Args)]
struct BatchSelectionArgs {
    #[arg(long, value_delimiter = ',', conflicts_with = "all_batches")]
    batch_files: Option<Vec<PathBuf>>,

    #[arg(long, conflicts_with = "batch_files")]
    all_batches: bool,

    #[arg(long, default_value = "testdata/era_mainnet_batches/binary")]
    batches_dir: PathBuf,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    batch_selection: BatchSelectionArgs,

    #[arg(long)]
    jit: bool,

    /// Serve unproven slots as empty, for fixtures without read proofs. Needs
    /// the matching bench guest.
    #[cfg(feature = "legacy-unproven-gaps")]
    #[arg(long)]
    legacy_unproven_gaps: bool,
}

#[derive(Debug, Args)]
struct ProveFriArgs {
    #[command(flatten)]
    batch_selection: BatchSelectionArgs,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,

    #[arg(long, default_value_t = SecurityLevelArg::default())]
    security: SecurityLevelArg,

    /// Path to the committed FRI verification key. Reused if present;
    /// otherwise generated on the fly and written here.
    #[arg(long, default_value_os_t = default_fri_vk_path())]
    fri_vk: PathBuf,
}

#[derive(Debug, Args)]
struct GenerateVksArgs {
    /// Where to write the verification key files. Both `fri_vk.bin` and
    /// `snark_vk.json` are written under this directory.
    #[arg(long, default_value = "vks")]
    output_dir: PathBuf,

    #[arg(long, default_value_t = SecurityLevelArg::default())]
    security: SecurityLevelArg,

    /// SNARK trusted setup (CRS). Required to derive the SNARK wrapper VK.
    #[arg(long, env = "SNARK_TRUSTED_SETUP_FILE")]
    trusted_setup: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,
}

#[derive(Debug, Args)]
struct DownloadTrustedSetupArgs {
    /// Where to write the trusted setup file.
    #[arg(
        long,
        env = "SNARK_TRUSTED_SETUP_FILE",
        default_value_os_t = default_trusted_setup_path(),
    )]
    output: PathBuf,

    /// URL to download from. Defaults to the GCS bucket that matches the
    /// build's SNARK feature set (CPU vs `gpu_snark`).
    #[arg(long, default_value_t = default_trusted_setup_download_url().to_string())]
    url: String,
}

#[derive(Debug, Args)]
struct ProveSnarkArgs {
    #[arg(long, value_delimiter = ',')]
    proof_files: Vec<PathBuf>,

    #[arg(long)]
    output_dir: PathBuf,

    #[arg(long)]
    worker_threads: Option<usize>,

    #[arg(long, env = "SNARK_TRUSTED_SETUP_FILE")]
    trusted_setup: Option<PathBuf>,

    /// Optional path to a pre-generated SNARK VK JSON. When set, the VK is
    /// loaded once at startup and reused for every wrap; otherwise it is
    /// derived from the setup chain.
    #[arg(long)]
    snark_vk: Option<PathBuf>,

    #[arg(long)]
    use_zk: bool,

    #[arg(long)]
    save_intermediates: bool,
}

impl BatchSelectionArgs {
    fn resolve(&self) -> Result<Vec<BatchInputFile>> {
        let batches_dir = self.batches_dir.canonicalize().with_context(|| {
            format!(
                "while attempting to canonicalize batches directory path {}",
                self.batches_dir.display()
            )
        })?;
        resolve_batch_inputs(&batches_dir, self.batch_files.as_deref(), self.all_batches)
            .context("while attempting to resolve requested batches")
    }
}

fn main() -> Result<()> {
    init_tracing().context("while attempting to initialize tracing")?;

    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => {
            let batch_inputs = args.batch_selection.resolve()?;
            #[cfg(feature = "legacy-unproven-gaps")]
            if args.legacy_unproven_gaps {
                return eravm_prover_host::run_batches_legacy_unproven_gaps(
                    &batch_inputs,
                    args.jit,
                );
            }
            run_batches(&batch_inputs, args.jit)
        }
        Command::ProveFri(args) => {
            let batch_inputs = args.batch_selection.resolve()?;
            prove_batches_fri(
                &batch_inputs,
                args.worker_threads,
                &args.output_dir,
                &args.fri_vk,
                args.security.into(),
            )
        }
        Command::DownloadTrustedSetup(args) => {
            download_trusted_setup_if_not_present(&args.output, &args.url)
                .context("while attempting to download the SNARK trusted setup")
        }
        Command::ProveSnark(args) => {
            let dist_dir = dist_dir();
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: args.trusted_setup,
                use_zk: args.use_zk,
                save_intermediates: args.save_intermediates,
                bin: app_bin_path(&dist_dir),
                text: app_text_path(&dist_dir),
            };
            let snark_vk = load_snark_vk(args.snark_vk.as_deref())?;
            wrap_to_snark(
                &args.proof_files,
                &args.output_dir,
                &snark_options,
                snark_vk,
            )
        }
        Command::GenerateVks(args) => {
            std::fs::create_dir_all(&args.output_dir).with_context(|| {
                format!(
                    "while attempting to create VK output directory {}",
                    args.output_dir.display()
                )
            })?;

            let fri_vk_path = args.output_dir.join("fri_vk.bin");
            generate_fri_vk(&fri_vk_path, args.security.into())
                .context("while generating the FRI verification key")?;

            let snark_vk_path = args.output_dir.join("snark_vk.json");
            let dist_dir = dist_dir();
            let snark_options = SnarkOptions {
                worker_threads: args.worker_threads,
                trusted_setup: Some(args.trusted_setup),
                use_zk: false,
                save_intermediates: false,
                bin: app_bin_path(&dist_dir),
                text: app_text_path(&dist_dir),
            };
            generate_snark_vk(&snark_vk_path, &snark_options)
                .context("while generating the SNARK verification key")?;
            Ok(())
        }
    }
}

fn load_snark_vk(path: Option<&std::path::Path>) -> Result<Option<SnarkWrapperVK>> {
    let Some(path) = path else { return Ok(None) };
    let path_string = path.to_string_lossy().into_owned();
    let vk: SnarkWrapperVK = deserialize_from_file(&path_string)
        .with_context(|| format!("while loading SNARK VK from {}", path.display()))?;
    Ok(Some(vk))
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn prove_snark_parses_save_intermediates_flag() {
        let cli = Cli::try_parse_from([
            "eravm-prover-host",
            "prove-snark",
            "--proof-files",
            "./artifacts/proofs/batch-42/fri_proof.json",
            "--output-dir",
            "./artifacts/proofs",
            "--save-intermediates",
        ])
        .expect("prove-snark arguments should parse");

        match cli.command {
            Command::ProveSnark(args) => {
                assert!(args.save_intermediates);
                assert_eq!(
                    args.proof_files,
                    vec![PathBuf::from("./artifacts/proofs/batch-42/fri_proof.json")]
                );
                assert_eq!(args.output_dir, PathBuf::from("./artifacts/proofs"));
            }
            _ => panic!("expected prove-snark command"),
        }
    }
}
