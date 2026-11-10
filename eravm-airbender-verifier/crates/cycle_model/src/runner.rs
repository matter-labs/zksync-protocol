use std::collections::BTreeMap;
use std::path::Path;

use airbender_host::{CycleMarker, Inputs, RamSize, Runner, TranspilerRunnerBuilder};
use anyhow::Context;
use zksync_airbender_verifier::types::AirbenderVerifierInput;

/// The four phase regions between the verifier's five cycle markers, in order.
/// Must stay in lockstep with the `phase_marker()` call sequence in
/// `crates/airbender_verifier/src/lib.rs`.
pub const PHASE_LABELS: [&str; 4] = ["setup", "vm_execution", "merkle_verification", "commitment"];

/// Diff consecutive cumulative marks into per-label cycle counts. `markers`
/// holds one mark per emitted boundary in execution order; `labels[i]` names the
/// region between mark `i` and mark `i + 1`.
pub fn phases_from_markers(markers: &CycleMarker, labels: &[&str]) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for (i, label) in labels.iter().enumerate() {
        if let (Some(before), Some(after)) = (markers.markers.get(i), markers.markers.get(i + 1)) {
            out.insert(label.to_string(), after.diff(before).cycles);
        }
    }
    out
}

/// Ground-truth guest measurements for one batch.
#[derive(Debug, Clone)]
pub struct GuestMeasurement {
    pub raw_cycles: u64,
    pub phase_cycles: BTreeMap<String, u64>,
    pub delegations: BTreeMap<u32, u64>,
}

/// Run the (cycle-marker-instrumented) guest over `input` through the non-JIT
/// transpiler and extract total cycles, per-phase cycles, and delegation counts.
///
/// `app_bin_dir` must contain `app.bin` + `app.text` for a guest built with
/// `--features cycle-markers` (see the bench usage docs). The runner must not
/// use JIT — cycle markers are only collected on the interpreter path.
pub fn run_guest(
    app_bin_dir: &Path,
    input: &AirbenderVerifierInput,
) -> anyhow::Result<GuestMeasurement> {
    let runner = TranspilerRunnerBuilder::new(app_bin_dir.join("app.bin"))
        .with_cycles(usize::MAX)
        // The guest is linked for 4 GiB (`guest/eravm_memory.x`); must match
        // `GUEST_RAM_SIZE` in the host crate.
        .with_ram_size(RamSize::FourGb)
        .build()
        .context("building transpiler runner")?;

    let mut words = Inputs::new();
    words.push(input).context("encoding verifier input")?;
    let execution = runner.run(words.words()).context("guest run failed")?;

    // `run` returns `Ok` even when the guest trapped, so without this an
    // aborted guest is recorded as a valid, very cheap measurement.
    anyhow::ensure!(
        execution.reached_end,
        "the guest trapped or ran out of cycles, so this measurement is \
         meaningless. A decode failure here usually means host and guest were \
         built with different `cycle-markers` flavours; they must match."
    );

    // `None` only on the JIT path, which this runner never selects; a guest
    // built without the feature yields `Some(empty)` instead, so the contents
    // are what actually need checking.
    let markers = execution
        .cycle_markers
        .context("no cycle markers collected — the runner used JIT; ensure JIT is off")?;
    // Exactly one more mark than labels: a short or padded set would silently
    // yield a partial or misaligned phase map.
    anyhow::ensure!(
        markers.markers.len() == PHASE_LABELS.len() + 1,
        "expected {} cycle markers, got {} — build the guest with `--features cycle-markers`, \
         and build this bench with the matching flavour",
        PHASE_LABELS.len() + 1,
        markers.markers.len()
    );

    Ok(GuestMeasurement {
        raw_cycles: execution.cycles_executed as u64,
        phase_cycles: phases_from_markers(&markers, &PHASE_LABELS),
        // `delegation_counter` is a HashMap; collect into a BTreeMap for a
        // stable, deterministic column order in the dataset.
        delegations: markers
            .delegation_counter
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use airbender_host::Mark;

    fn mark(cycles: u64) -> Mark {
        Mark {
            cycles,
            delegations: Default::default(),
        }
    }

    #[test]
    fn phases_diff_consecutive_marks() {
        let markers = CycleMarker {
            markers: vec![mark(0), mark(100), mark(350), mark(400), mark(500)],
            delegation_counter: Default::default(),
        };
        let phases = phases_from_markers(&markers, &PHASE_LABELS);
        assert_eq!(phases["setup"], 100);
        assert_eq!(phases["vm_execution"], 250);
        assert_eq!(phases["merkle_verification"], 50);
        assert_eq!(phases["commitment"], 100);
    }
}
