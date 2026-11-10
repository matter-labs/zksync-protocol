//! Measurement identity for a calibration dataset.
//!
//! A cost table models one specific guest binary, and without recording which one
//! its staleness is undetectable: the fit's accuracy numbers and the CI fixture
//! both age *with* the table. That is how the pre-delegation table reached 2.05×
//! over-prediction with every in-repo check green, until it was re-measured by
//! hand and reweighted on 2026-08-19.
//!
//! So `cycle_bench` writes this manifest next to `dataset.json`, and
//! `build_cost_table.py` stamps it into `cost_table.json`,
//! where a unit test refuses an unstamped table. Fields this process cannot
//! establish stay `None` rather than guessed — a wrong stamp is worse than an
//! absent one, because it invites trust.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a dataset was measured against. Serialized as the JSON manifest
/// `build_cost_table.py` consumes; the key names match the
/// `Provenance` struct in the estimator crate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatasetProvenance {
    /// sha256 of the guest `app.bin` the ground truth was measured with.
    pub guest_sha256: Option<String>,
    /// Verifier commit (`git rev-parse HEAD`) the guest + tooling were built from.
    pub verifier_commit: Option<String>,
    /// `zksync_vm2` revision the native features were traced with, read from the
    /// workspace `Cargo.lock` (the features are only comparable across builds
    /// that agree on it).
    pub vm2_rev: Option<String>,
    /// Protocol version(s) the measured batches actually carry — read per batch
    /// from `system_env.version`, NOT the verifier's pin. A calibration guest is
    /// built with `--features cycle-markers`, which relaxes the version pin
    /// precisely so older batches decode, so the pin would be a false stamp: the
    /// committed table's corpus is entirely `Version29` while the pin is
    /// `Version34`. A mixed corpus is labelled `MIXED: ...`.
    pub protocol_version: Option<String>,
    /// Wall-clock of the measurement run, seconds since the UNIX epoch.
    pub measured_at_unix: Option<u64>,
    /// Free-text description of the corpus (batch ranges / counts).
    pub dataset: Option<String>,
}

impl DatasetProvenance {
    /// Collect everything this process can establish. Every field is
    /// best-effort: a missing git binary, a guest measured elsewhere, or a
    /// checkout without `Cargo.lock` yields `None`, which the fit then refuses to
    /// ship unstamped unless the operator supplies it explicitly.
    pub fn collect(app_bin_dir: Option<&Path>, protocol_version: String, dataset: String) -> Self {
        Self {
            guest_sha256: app_bin_dir.and_then(|d| sha256_file(&d.join("app.bin"))),
            verifier_commit: git_head(),
            vm2_rev: vm2_rev_from_lockfile(),
            protocol_version: Some(protocol_version),
            measured_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            dataset: Some(dataset),
        }
    }

    /// Write `provenance.json` next to the dataset.
    pub fn write(&self, out_dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(out_dir)?;
        std::fs::write(
            out_dir.join("provenance.json"),
            serde_json::to_string_pretty(self)?,
        )?;
        Ok(())
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn git(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The commit the measurement ran from, suffixed `-dirty` for an unclean tree.
///
/// A bare SHA over a dirty tree is a *false* stamp, and not hypothetically: the
/// committed table was measured with an uncommitted dependency overlay (a newer
/// vm2 than the commit pins), so the commit alone does not identify the build.
fn git_head() -> Option<String> {
    let head = git(&["rev-parse", "HEAD"])?;
    let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.trim().is_empty());
    Some(if dirty { format!("{head}-dirty") } else { head })
}

/// The `source` line of the locked `zksync_vm2` package — for a git dependency
/// this carries the exact revision, which is what makes two feature vectors
/// comparable. Read at run time from the workspace lockfile (this is an offline
/// dev tool that always runs from its checkout).
///
/// Two cases the obvious version of this gets wrong:
/// - A `[patch]` pointing vm2 at a local checkout produces a package entry with
///   **no `source` line** at all. That is a real workflow here (benchmarking an
///   unreleased vm2 branch), and it must still stamp *something* — the version
///   plus an explicit "no source" marker — rather than returning `None` and
///   letting the dataset ship unattributed.
/// - Any TOML table header ends the block, not just `[[package]]`. A lockfile
///   with `[[patch.unused]]` sections would otherwise leak the vm2 block state
///   into the next crate and report *its* revision as vm2's.
fn vm2_rev_from_lockfile() -> Option<String> {
    let lock = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .parent()?
            .join("Cargo.lock"),
    )
    .ok()?;
    parse_vm2_rev(&lock)
}

/// The lockfile-parsing half of [`vm2_rev_from_lockfile`], split out so the two
/// edge cases above are testable without a real workspace on disk.
fn parse_vm2_rev(lock: &str) -> Option<String> {
    let patched =
        |v: Option<String>| v.map(|v| format!("{v} (no source: patched to a local path)"));
    let mut in_pkg = false;
    let mut version = None;
    for line in lock.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if in_pkg {
                return patched(version); // block ended without a `source`
            }
            version = None;
        } else if line == "name = \"zksync_vm2\"" {
            in_pkg = true;
        } else if in_pkg {
            if let Some(v) = line.strip_prefix("version = ") {
                version = Some(v.trim_matches('"').to_string());
            }
            if let Some(src) = line.strip_prefix("source = ") {
                let src = src.trim_matches('"');
                return Some(match version {
                    Some(v) => format!("{v} ({src})"),
                    None => src.to_string(),
                });
            }
        }
    }
    if in_pkg {
        patched(version) // vm2 was the final block in the file
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_locked_vm2_revision() {
        // The lockfile is committed, so this must resolve in any checkout; a
        // silent None here would mean datasets get stamped without the one field
        // that says which VM produced the features. Accept either form: a git
        // `source` line, or the version + no-source marker a local `[patch]`
        // produces (this repo really is benchmarked that way).
        let rev = vm2_rev_from_lockfile().expect("zksync_vm2 must be in the workspace lockfile");
        assert!(
            rev.contains("vm2") || rev.contains("no source"),
            "unexpected vm2 source line: {rev}"
        );
    }

    #[test]
    fn patched_vm2_still_stamps_a_version() {
        // A `[patch]` to a local checkout emits no `source`, and `[[patch.unused]]`
        // is a table header that is not `[[package]]` — both used to break this.
        let lock = "\
[[package]]
name = \"zksync_vm2\"
version = \"0.6.3\"
dependencies = [
 \"enum_dispatch\",
]

[[patch.unused]]
name = \"other\"
version = \"9.9.9\"
source = \"git+https://example.invalid/other?tag=v9#deadbeef\"
";
        let rev = parse_vm2_rev(lock).expect("a patched vm2 must still stamp its version");
        assert!(rev.starts_with("0.6.3"), "{rev}");
        assert!(rev.contains("no source"), "{rev}");
        assert!(
            !rev.contains("deadbeef"),
            "leaked the next package's rev: {rev}"
        );
    }

    #[test]
    fn hashes_a_file_and_tolerates_a_missing_one() {
        let dir = std::env::temp_dir().join(format!(
            "cycle_model_provenance_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("app.bin");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            sha256_file(&f).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(sha256_file(&dir.join("nope.bin")).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
