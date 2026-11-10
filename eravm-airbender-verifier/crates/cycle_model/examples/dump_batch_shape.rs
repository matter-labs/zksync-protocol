//! Dump the batch-level quantities the feature schema does NOT price, so they can be
//! tested against the model's residual.
//!
//! Everything here is available to the sequencer at seal time (unlike `merkle_paths`,
//! which is a verifier input), so anything that turns out to explain residual variation
//! is a candidate feature rather than a dead end.
//!
//!   cargo run --release -p zksync_cycle_model --example dump_batch_shape -- <dir> [files...]
use anyhow::{Context, Result};
use std::path::PathBuf;
use zksync_cli_utils::{load_labeled_batch, resolve_batch_inputs};
use zksync_types::ExecuteTransactionCommon;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .context("usage: dump_batch_shape <dir> [files...]")?,
    )
    .canonicalize()
    .context("canonicalizing batches dir")?;
    let files: Vec<PathBuf> = args.map(PathBuf::from).collect();
    let (sel, all) = if files.is_empty() {
        (None, true)
    } else {
        (Some(files.as_slice()), false)
    };

    println!(
        "batch,protocol_version,l2_blocks,interop_roots,virtual_blocks,txs,\
         initial_heap_slots,used_bytecodes,used_bytecode_words,storage_refunds,pubdata_costs,\
         l1_txs,l2_txs,upgrade_txs,paymaster_txs,tx_calldata_bytes,signature_bytes,\
         factory_deps,tx_types"
    );
    for bi in resolve_batch_inputs(&dir, sel, all).context("resolving batches")? {
        // Read the stored form and stay in it: every quantity below is present
        // on the labeled shape, so `into_verifier_input`'s proving gate would
        // only make this analysis tool skip the below-pin corpus it exists to
        // analyse — silently, since a skipped row still exits 0.
        let input = match load_labeled_batch(&bi) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skip {}: {e}", bi.number);
                continue;
            }
        };
        // Rendered as `VersionNN` to keep the column stable now that the label
        // is a raw minor rather than a `ProtocolVersionId` (cf. `cycle_bench`).
        let protocol_version = format!("Version{}", input.labels().vm_run_data_protocol_version);
        let blocks = &input.l2_blocks_execution_data;
        let interop: usize = blocks.iter().map(|b| b.interop_roots.len()).sum();
        let virt: u32 = blocks.iter().map(|b| b.virtual_blocks).sum();
        let txs: usize = blocks.iter().map(|b| b.txs.len()).sum();
        let words: usize = input
            .vm_run_data
            .used_bytecodes
            .values()
            .map(|w| w.len())
            .sum();
        // Transaction shape. Split by the bootloader flows that differ: an L1 tx skips
        // signature validation and is paid on L1; a paymaster tx runs two extra far calls
        // (validateAndPayForPaymasterTransaction + postTransaction). Both are opcode-traced,
        // so this is about whether any per-tx cost escapes the opcode features.
        let mut l1 = 0usize;
        let mut l2 = 0usize;
        let mut upg = 0usize;
        let mut pay = 0usize;
        let mut sig_bytes = 0usize;
        let mut types = std::collections::BTreeSet::<u32>::new();
        let mut calldata = 0usize;
        let mut factory_deps = 0usize;
        for b in blocks {
            for t in &b.txs {
                calldata += t.execute.calldata.len();
                factory_deps += t.execute.factory_deps.len();
                match &t.common_data {
                    ExecuteTransactionCommon::L1(_) => l1 += 1,
                    ExecuteTransactionCommon::ProtocolUpgrade(_) => upg += 1,
                    ExecuteTransactionCommon::L2(d) => {
                        l2 += 1;
                        sig_bytes += d.signature.len();
                        types.insert(d.transaction_type as u32);
                        if d.paymaster_params.paymaster != Default::default() {
                            pay += 1;
                        }
                    }
                }
            }
        }
        let type_list: Vec<String> = types.iter().map(|t| t.to_string()).collect();
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            bi.number,
            protocol_version,
            blocks.len(),
            interop,
            virt,
            txs,
            input.vm_run_data.initial_heap_content.len(),
            input.vm_run_data.used_bytecodes.len(),
            words,
            input.vm_run_data.storage_refunds.len(),
            input.vm_run_data.pubdata_costs.len(),
            l1,
            l2,
            upg,
            pay,
            calldata,
            sig_bytes,
            factory_deps,
            type_list.join("|"),
        );
    }
    Ok(())
}
