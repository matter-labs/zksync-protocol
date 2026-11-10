use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use tracing::{error, info};

use crate::artifacts::{planned_key_artifacts, FileKind};
use crate::file_io::read_json;
use crate::generation::{generate_data_source, validate_jobs, write_era_compatible_layout};

#[derive(Default, Debug)]
pub struct ComparisonSummary {
    pub checked: usize,
    pub different: usize,
}

pub fn run_compare(reference_keys_dir: &Path, generated_dir: &Path, jobs: usize) -> Result<()> {
    validate_jobs(jobs)?;

    info!("Generating keys for comparison");
    info!("jobs={jobs}");
    info!("reference={}", reference_keys_dir.display());
    info!("generated={}", generated_dir.display());

    let source = generate_data_source(jobs)?;
    write_era_compatible_layout(&source, generated_dir)?;

    let summary = compare_key_folders(reference_keys_dir, generated_dir)?;

    if summary.different > 0 {
        bail!(
            "{}/{} key files are different",
            summary.different,
            summary.checked
        );
    }

    info!("All {} key files match", summary.checked);
    Ok(())
}

pub fn compare_key_folders(
    reference_keys_dir: &Path,
    generated_dir: &Path,
) -> Result<ComparisonSummary> {
    let mut summary = ComparisonSummary::default();

    for artifact in planned_key_artifacts() {
        summary.checked += 1;

        let reference_path = reference_keys_dir.join(&artifact.file_name);
        let generated_path = generated_dir.join(&artifact.file_name);

        if !reference_path.exists() {
            summary.different += 1;
            error!("Key <{}> is different", artifact.file_name);
            error!("missing reference file {}", reference_path.display());
            continue;
        }

        if !generated_path.exists() {
            summary.different += 1;
            error!("Key <{}> is different", artifact.file_name);
            error!("missing generated file {}", generated_path.display());
            continue;
        }

        let is_same = match artifact.kind {
            FileKind::Json => {
                let reference = read_json(&reference_path).with_context(|| {
                    format!(
                        "while attempting to read reference JSON key {}",
                        reference_path.display()
                    )
                })?;
                let generated = read_json(&generated_path).with_context(|| {
                    format!(
                        "while attempting to read generated JSON key {}",
                        generated_path.display()
                    )
                })?;
                reference == generated
            }
            FileKind::Binary => {
                let reference = fs::read(&reference_path).with_context(|| {
                    format!(
                        "while attempting to read reference binary key {}",
                        reference_path.display()
                    )
                })?;
                let generated = fs::read(&generated_path).with_context(|| {
                    format!(
                        "while attempting to read generated binary key {}",
                        generated_path.display()
                    )
                })?;
                reference == generated
            }
        };

        if !is_same {
            summary.different += 1;
            error!("Key <{}> is different", artifact.file_name);
        }
    }

    Ok(summary)
}
