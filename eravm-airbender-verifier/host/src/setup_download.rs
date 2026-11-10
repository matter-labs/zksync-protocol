use std::fs::{create_dir_all, File};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};

// Public GCS buckets that host the bellman SNARK trusted setup. Mirrors the
// URLs in the README and CI workflow.
const CPU_TRUSTED_SETUP_URL: &str =
    "https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_2^25.key";
const GPU_TRUSTED_SETUP_URL: &str =
    "https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/setup_compact.key";

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const DOWNLOAD_RETRIES: usize = 5;
const DOWNLOAD_BACKOFF: Duration = Duration::from_secs(5);

/// Default trusted-setup filename for the build's SNARK feature set.
pub fn default_trusted_setup_path() -> PathBuf {
    if cfg!(feature = "gpu_snark") {
        PathBuf::from("setup_gpu.key")
    } else {
        PathBuf::from("setup.key")
    }
}

/// Default download URL for the trusted-setup file matching the build's
/// SNARK feature set.
pub fn default_trusted_setup_download_url() -> &'static str {
    if cfg!(feature = "gpu_snark") {
        GPU_TRUSTED_SETUP_URL
    } else {
        CPU_TRUSTED_SETUP_URL
    }
}

/// Downloads the SNARK trusted setup to `path` if it isn't already present.
/// Intended to be invoked explicitly (e.g. via the `download-trusted-setup`
/// CLI subcommand or a deployment step) — never called from the prover hot
/// path, which expects the file to already exist.
pub fn download_trusted_setup_if_not_present(path: &Path, url: &str) -> Result<()> {
    if path.exists() {
        info!(
            path = %path.display(),
            "SNARK trusted setup already present, skipping download"
        );
        return Ok(());
    }

    info!(url, "Downloading SNARK trusted setup");
    let bytes = download_with_retries(url)
        .with_context(|| format!("while attempting to download trusted setup from {url}"))?;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_dir_all(parent).with_context(|| {
            format!(
                "while attempting to create trusted setup directory {}",
                parent.display()
            )
        })?;
    }

    let mut file = File::create(path).with_context(|| {
        format!(
            "while attempting to create trusted setup file at {}",
            path.display()
        )
    })?;
    std::io::copy(&mut Cursor::new(bytes), &mut file).with_context(|| {
        format!(
            "while attempting to write downloaded trusted setup to {}",
            path.display()
        )
    })?;

    info!(path = %path.display(), "Saved SNARK trusted setup");
    Ok(())
}

fn download_with_retries(url: &str) -> reqwest::Result<Vec<u8>> {
    // Named, not defaulted: `cli_lib` enables `reqwest`'s `default-tls` too.
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .timeout(DOWNLOAD_TIMEOUT)
        .build()?;

    let mut last_err = None;
    for attempt in 1..=DOWNLOAD_RETRIES {
        match fetch(&client, url) {
            Ok(bytes) => return Ok(bytes),
            Err(err) => {
                warn!(
                    attempt,
                    max_attempts = DOWNLOAD_RETRIES,
                    error = %err,
                    "Trusted setup download attempt failed, backing off"
                );
                last_err = Some(err);
                if attempt < DOWNLOAD_RETRIES {
                    std::thread::sleep(DOWNLOAD_BACKOFF);
                }
            }
        }
    }
    Err(last_err.expect("DOWNLOAD_RETRIES is non-zero so at least one error was recorded"))
}

fn fetch(client: &reqwest::blocking::Client, url: &str) -> reqwest::Result<Vec<u8>> {
    let response = client.get(url).send()?.error_for_status()?;
    Ok(response.bytes()?.to_vec())
}
