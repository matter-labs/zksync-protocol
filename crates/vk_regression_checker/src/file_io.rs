use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let payload = serde_json::to_string_pretty(value)
        .context("while attempting to serialize value as pretty JSON")?;
    fs::write(path, payload)
        .with_context(|| format!("while attempting to write JSON file {}", path.display()))?;

    Ok(())
}

pub fn write_bin(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let payload = bincode::serialize(value)
        .context("while attempting to serialize value into binary payload")?;
    fs::write(path, payload)
        .with_context(|| format!("while attempting to write binary file {}", path.display()))?;

    Ok(())
}

pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    let payload = fs::read(path)
        .with_context(|| format!("while attempting to read JSON file {}", path.display()))?;

    serde_json::from_slice(&payload)
        .with_context(|| format!("while attempting to parse JSON file {}", path.display()))
}
