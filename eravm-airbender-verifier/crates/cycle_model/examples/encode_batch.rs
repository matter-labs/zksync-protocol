//! Convert a batch into the verifier's on-disk fixture format (`.bin`/`.bin.gz`).
//!
//! The primary path turns a zksync-era airbender export — a `proof_inputs_*.json`
//! (a JSON-serialized verifier input, as served by the node's
//! `/airbender/proof_inputs_no_lock/{batch}` endpoint) — into a repo fixture:
//!
//!   cargo run --release -p zksync_cycle_model --example encode_batch -- \
//!       proof_inputs_<N>.json <N>.bin.gz
//!
//! With `--from-bin` the input is an existing `.bin`/`.bin.gz` fixture instead of
//! JSON — useful to re-encode or sanity-check the round-trip on a known batch:
//!
//!   cargo run ... --example encode_batch -- --from-bin <N>.bin.gz /tmp/rt.bin.gz
//!
//! After writing, it reloads the output via `load_batch` and asserts it equals
//! the input, so a successful run is a proof the encode/decode round-trips.
//!
//! Both inputs are decoded through the labeled form
//! (`zksync_cli_utils::labeled`), whose `into_verifier_input` gates the
//! era/stored protocol-version labels fail-fast — refuse below the pin, warn
//! above it. The guest types carry no version field, so no label survives into
//! the typed input: the fixture written here keeps both label SLOTS, but their
//! values are re-stamped (the pin, in a production build), which relabels an
//! above-pin source. That is reported on stderr when it happens.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use anyhow::{Context, Result};
use zksync_airbender_verifier::types::AirbenderVerifierInput;
use zksync_cli_utils::labeled::LabeledVerifierInput;
use zksync_cli_utils::{load_batch, load_labeled_batch, save_batch, BatchInputFile};

fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let from_bin = args.first().map(|a| a == "--from-bin").unwrap_or(false);
    if from_bin {
        args.remove(0);
    }
    if args.len() != 2 {
        anyhow::bail!(
            "usage: encode_batch [--from-bin] <input(.json|.bin[.gz])> <output.bin[.gz]>"
        );
    }
    let in_path = PathBuf::from(&args[0]);
    let out_path = PathBuf::from(&args[1]);

    // Both paths decode the labeled form, so the source labels can be reported
    // and compared against what gets written back.
    let labeled: LabeledVerifierInput = if from_bin {
        // Resolves the format (.bin / .bin.gz) itself; number is irrelevant
        // here, only the path is used.
        load_labeled_batch(&BatchInputFile {
            number: 0,
            path: in_path.clone(),
        })
        .with_context(|| format!("loading fixture {}", in_path.display()))?
    } else {
        serde_json::from_reader(BufReader::new(
            File::open(&in_path).with_context(|| format!("opening {}", in_path.display()))?,
        ))
        .with_context(|| {
            format!(
                "parsing {} as a labeled verifier-input JSON",
                in_path.display()
            )
        })?
    };

    let source_labels = labeled.labels();
    eprintln!(
        "source labels: system_env.version = {}, vm_run_data.protocol_version = {}",
        source_labels.system_env_version, source_labels.vm_run_data_protocol_version
    );

    let input: AirbenderVerifierInput = labeled.into_verifier_input().with_context(|| {
        format!(
            "checking the protocol-version labels of {}",
            in_path.display()
        )
    })?;

    save_batch(&input, &out_path).with_context(|| format!("writing {}", out_path.display()))?;

    // The typed input carries no label, so `save_batch` re-stamps both slots.
    // In production that is the pin, which silently RELABELS an above-pin
    // fixture — say so rather than letting the round-trip check below (which
    // compares the label-free typed form) imply nothing changed. Read from the
    // borrow — `from_verifier_input` would deep-copy the input a second time.
    let written = LabeledVerifierInput::stamped_labels(&input);
    if written != source_labels {
        eprintln!(
            "NOTE: labels re-stamped on write: system_env.version {} -> {}, \
             vm_run_data.protocol_version {} -> {}",
            source_labels.system_env_version,
            written.system_env_version,
            source_labels.vm_run_data_protocol_version,
            written.vm_run_data_protocol_version,
        );
    }

    // Self-check: reload the fixture we just wrote and confirm it matches.
    let reloaded = load_batch(&BatchInputFile {
        number: 0,
        path: out_path.clone(),
    })
    .with_context(|| format!("re-loading {} for round-trip check", out_path.display()))?;
    anyhow::ensure!(
        reloaded == input,
        "round-trip mismatch: reloaded {} does not equal the input",
        out_path.display()
    );

    let written = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "wrote {} ({written} bytes) and verified load_batch round-trip",
        out_path.display()
    );
    Ok(())
}
