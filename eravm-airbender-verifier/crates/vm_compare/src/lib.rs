mod fast;
mod legacy;
mod types;

use std::collections::BTreeSet;

use anyhow::{bail, Result};
use fast::FastTraceTracer;
use legacy::LegacyTraceTracer;
pub use types::{CompareOptions, ComparisonOutcome, ComparisonReport, Divergence, TxLocation};
// The harness must replay at exactly the version the verifier commits at, so it
// asks rather than re-deriving it.
use zksync_airbender_verifier::{stf_protocol_version, types::AirbenderVerifierInput};
use zksync_multivm::{
    interface::{
        storage::{StorageSnapshot, StorageView},
        FinishedL1Batch, L2BlockEnv, VmFactory, VmInterface, VmInterfaceHistoryEnabled,
    },
    pubdata_builders::pubdata_params_to_builder,
    tracers::TracerDispatcher,
    vm_fast::FastValidationTracer,
    vm_latest::HistoryEnabled,
    FastVmInstance, LegacyVmInstance, MultiVmTracer,
};
use zksync_types::{u256_to_h256, Transaction, H256};

use crate::types::TransactionTrace;

type CompareStorage = StorageSnapshot;
type CompareStorageView = StorageView<CompareStorage>;
type LegacyCompareVm = LegacyVmInstance<CompareStorage, HistoryEnabled>;
type FastCompareVm = FastVmInstance<CompareStorage, FastTraceTracer>;

#[derive(Debug)]
struct TxExecutionCapture {
    used_compression: bool,
    trace: TransactionTrace,
}

pub fn compare(input: AirbenderVerifierInput, options: CompareOptions) -> Result<ComparisonReport> {
    let protocol_version = stf_protocol_version(&input.system_env);
    let system_env = input.system_env.clone().into_system_env(protocol_version);
    let storage_snapshot = create_storage_snapshot(&input);
    let legacy_storage = StorageView::new(storage_snapshot.clone()).to_rc_ptr();
    let fast_storage = StorageView::new(storage_snapshot).to_rc_ptr();

    let mut legacy_vm = <LegacyCompareVm as VmFactory<CompareStorageView>>::new(
        input.l1_batch_env.clone(),
        system_env.clone(),
        legacy_storage,
    );
    let mut fast_vm = FastCompareVm::fast(input.l1_batch_env.clone(), system_env, fast_storage);

    let mut compared_transactions = 0usize;
    let compared_l2_blocks = input.l2_blocks_execution_data.len().saturating_sub(1);
    let mut last_location = None;
    let mut divergences = Vec::new();

    let next_l2_blocks = input.l2_blocks_execution_data.iter().skip(1);
    for (l2_block_data, next_l2_block_data) in
        input.l2_blocks_execution_data.iter().zip(next_l2_blocks)
    {
        for (tx_index, tx) in l2_block_data.txs.iter().enumerate() {
            let location = TxLocation {
                l2_block_number: l2_block_data.number.0,
                tx_index_in_block: tx_index,
                tx_hash: tx.hash(),
            };
            last_location = Some(location.clone());

            let legacy = execute_tx_legacy(tx, &mut legacy_vm, options)?;
            let fast = execute_tx_fast(tx, &mut fast_vm, options)?;
            compared_transactions += 1;

            if legacy.used_compression != fast.used_compression {
                divergences.push(Divergence {
                    location: location.clone(),
                    reason: format!(
                        "bytecode compression fallback mismatch (legacy used compression: {}, fast used compression: {})",
                        legacy.used_compression, fast.used_compression
                    ),
                    legacy: None,
                    fast: None,
                });
                if options.fail_fast {
                    return Ok(divergence_report(
                        compared_transactions,
                        compared_l2_blocks,
                        divergences,
                    ));
                }
            }

            if legacy.trace.execution_result != fast.trace.execution_result {
                divergences.push(Divergence {
                    location: location.clone(),
                    reason: format!(
                        "execution result mismatch: legacy={:?}, fast={:?}",
                        legacy.trace.execution_result, fast.trace.execution_result
                    ),
                    legacy: None,
                    fast: None,
                });
                if options.fail_fast {
                    return Ok(divergence_report(
                        compared_transactions,
                        compared_l2_blocks,
                        divergences,
                    ));
                }
            }

            if legacy.trace.total_steps != fast.trace.total_steps {
                divergences.push(Divergence {
                    location: location.clone(),
                    reason: format!(
                        "executed step count mismatch: legacy={}, fast={}",
                        legacy.trace.total_steps, fast.trace.total_steps
                    ),
                    legacy: None,
                    fast: None,
                });
                if options.fail_fast {
                    return Ok(divergence_report(
                        compared_transactions,
                        compared_l2_blocks,
                        divergences,
                    ));
                }
            }

            if let Some((legacy_step, fast_step)) = first_step_mismatch(&legacy.trace, &fast.trace)
            {
                divergences.push(Divergence {
                    location: location.clone(),
                    reason: format!(
                        "observation mismatch at legacy step {} vs fast step {}",
                        legacy_step.step, fast_step.step
                    ),
                    legacy: Some(legacy_step.clone()),
                    fast: Some(fast_step.clone()),
                });
                if options.fail_fast {
                    return Ok(divergence_report(
                        compared_transactions,
                        compared_l2_blocks,
                        divergences,
                    ));
                }
            }

            if legacy.trace.observations.len() != fast.trace.observations.len() {
                divergences.push(Divergence {
                    location: location.clone(),
                    reason: format!(
                        "observation count mismatch: legacy={}, fast={}",
                        legacy.trace.observations.len(),
                        fast.trace.observations.len()
                    ),
                    legacy: legacy
                        .trace
                        .observations
                        .get(fast.trace.observations.len())
                        .cloned(),
                    fast: fast
                        .trace
                        .observations
                        .get(legacy.trace.observations.len())
                        .cloned(),
                });
                if options.fail_fast {
                    return Ok(divergence_report(
                        compared_transactions,
                        compared_l2_blocks,
                        divergences,
                    ));
                }
            }
        }

        legacy_vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_l2_block_data));
        fast_vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_l2_block_data));
    }

    let legacy_batch = legacy_vm.finish_batch(pubdata_params_to_builder(
        input.pubdata_params,
        protocol_version,
    ));
    let fast_batch = fast_vm.finish_batch(pubdata_params_to_builder(
        input.pubdata_params,
        protocol_version,
    ));

    let final_location = last_location.unwrap_or_else(|| default_location(&input));
    for reason in compare_batch_outputs(&legacy_batch, &fast_batch) {
        divergences.push(Divergence {
            location: final_location.clone(),
            reason,
            legacy: None,
            fast: None,
        });
        if options.fail_fast {
            return Ok(divergence_report(
                compared_transactions,
                compared_l2_blocks,
                divergences,
            ));
        }
    }

    if divergences.is_empty() {
        return Ok(ComparisonReport {
            compared_transactions,
            compared_l2_blocks,
            outcome: ComparisonOutcome::Match,
        });
    }

    Ok(divergence_report(
        compared_transactions,
        compared_l2_blocks,
        divergences,
    ))
}

fn divergence_report(
    compared_transactions: usize,
    compared_l2_blocks: usize,
    divergences: Vec<Divergence>,
) -> ComparisonReport {
    ComparisonReport {
        compared_transactions,
        compared_l2_blocks,
        outcome: ComparisonOutcome::Diverged(divergences),
    }
}

fn default_location(input: &AirbenderVerifierInput) -> TxLocation {
    TxLocation {
        l2_block_number: input
            .l2_blocks_execution_data
            .first()
            .map(|block| block.number.0)
            .unwrap_or_default(),
        tx_index_in_block: 0,
        tx_hash: H256::zero(),
    }
}

/// Run the fast VM over an entire batch with a caller-supplied passive tracer,
/// returning the finished batch.
///
/// Mirrors the verifier's `execute_tx` compression dance (snapshot → try with
/// bytecode compression → on failure roll back and retry without), so the
/// executed instruction stream — and thus the features counted by `tracer` —
/// matches what the proved guest runs, INCLUDING transactions re-executed on
/// compression fallback (the guest pays those cycles too).
///
/// `tracer` is cloned into each execution attempt; if its clones share a
/// recorder (as `zksync_cycle_model`'s tracer does), all counts accumulate
/// there, and the caller reads them from its own handle after this returns.
/// Used by the cycle-cost calibration harness.
pub fn run_fast_vm_with_tracer<Tr>(
    input: &AirbenderVerifierInput,
    tracer: Tr,
) -> Result<FinishedL1Batch>
where
    Tr: zksync_vm2::interface::Tracer + Clone + Default + 'static,
{
    let protocol_version = stf_protocol_version(&input.system_env);
    let storage = StorageView::new(create_storage_snapshot(input)).to_rc_ptr();
    let mut vm = FastVmInstance::<CompareStorage, Tr>::fast(
        input.l1_batch_env.clone(),
        input.system_env.clone().into_system_env(protocol_version),
        storage,
    );

    let next_blocks = input.l2_blocks_execution_data.iter().skip(1);
    for (block, next_block) in input.l2_blocks_execution_data.iter().zip(next_blocks) {
        for tx in &block.txs {
            run_tx_fast_with_tracer(&mut vm, tx, &tracer)?;
        }
        vm.start_new_l2_block(L2BlockEnv::from_l2_block_data(next_block));
    }

    Ok(vm.finish_batch(pubdata_params_to_builder(
        input.pubdata_params,
        protocol_version,
    )))
}

/// One transaction through the fast VM with `tracer`, replicating the verifier's
/// bytecode-compression fallback so the observed instruction stream matches.
fn run_tx_fast_with_tracer<Tr>(
    vm: &mut FastVmInstance<CompareStorage, Tr>,
    tx: &Transaction,
    tracer: &Tr,
) -> Result<()>
where
    Tr: zksync_vm2::interface::Tracer + Clone + Default + 'static,
{
    vm.make_snapshot();
    let mut dispatcher = (tracer.clone(), FastValidationTracer::default());
    let (compression, _execution) =
        vm.inspect_transaction_with_bytecode_compression(&mut dispatcher, tx.clone(), true);
    if compression.is_ok() {
        vm.pop_snapshot_no_rollback();
        return Ok(());
    }

    vm.rollback_to_the_latest_snapshot();
    let mut dispatcher = (tracer.clone(), FastValidationTracer::default());
    let (compression, _execution) =
        vm.inspect_transaction_with_bytecode_compression(&mut dispatcher, tx.clone(), false);
    if compression.is_err() {
        bail!("compression can't fail if we don't apply it");
    }
    Ok(())
}

pub fn create_storage_snapshot(input: &AirbenderVerifierInput) -> StorageSnapshot {
    let storage = input
        .vm_run_data
        .witness_block_state
        .read_storage_key
        .iter()
        .enumerate()
        .map(|(i, (hash, bytes))| (hash.hashed_key(), Some((*bytes, i as u64 + 1u64))))
        .chain(
            input
                .vm_run_data
                .witness_block_state
                .is_write_initial
                .iter()
                .filter_map(|(key, initial_write)| {
                    initial_write.then_some((key.hashed_key(), None))
                }),
        )
        .collect();

    let factory_deps = input
        .vm_run_data
        .used_bytecodes
        .iter()
        .map(|(hash, bytes)| (u256_to_h256(*hash), bytes.clone().into_flattened()))
        .collect();

    StorageSnapshot::new(storage, factory_deps)
}

fn execute_tx_legacy(
    tx: &Transaction,
    vm: &mut LegacyCompareVm,
    options: CompareOptions,
) -> Result<TxExecutionCapture> {
    vm.make_snapshot();
    let (tracer, recorder) = LegacyTraceTracer::new(options);
    let mut dispatcher = TracerDispatcher::from(tracer.into_tracer_pointer());
    let (compression_result, execution) =
        vm.inspect_transaction_with_bytecode_compression(&mut dispatcher, tx.clone(), true);
    let compression_succeeded = compression_result.is_ok();
    drop(compression_result);

    if compression_succeeded {
        vm.pop_snapshot_no_rollback();
        return Ok(TxExecutionCapture {
            used_compression: true,
            trace: legacy::into_trace(recorder, execution.result),
        });
    }

    vm.rollback_to_the_latest_snapshot();

    let (tracer, recorder) = LegacyTraceTracer::new(options);
    let mut dispatcher = TracerDispatcher::from(tracer.into_tracer_pointer());
    let (compression_result, execution) =
        vm.inspect_transaction_with_bytecode_compression(&mut dispatcher, tx.clone(), false);
    if compression_result.is_err() {
        bail!("compression must succeed when disabled");
    }

    Ok(TxExecutionCapture {
        used_compression: false,
        trace: legacy::into_trace(recorder, execution.result),
    })
}

fn execute_tx_fast(
    tx: &Transaction,
    vm: &mut FastCompareVm,
    options: CompareOptions,
) -> Result<TxExecutionCapture> {
    vm.make_snapshot();
    let mut dispatcher = (
        FastTraceTracer::new(options),
        FastValidationTracer::default(),
    );
    let (compression_result, execution) =
        vm.inspect_transaction_with_bytecode_compression(&mut dispatcher, tx.clone(), true);
    let compression_succeeded = compression_result.is_ok();
    drop(compression_result);

    if compression_succeeded {
        vm.pop_snapshot_no_rollback();
        return Ok(TxExecutionCapture {
            used_compression: true,
            trace: dispatcher.0.into_trace(execution.result),
        });
    }

    vm.rollback_to_the_latest_snapshot();

    let mut dispatcher = (
        FastTraceTracer::new(options),
        FastValidationTracer::default(),
    );
    let (compression_result, execution) =
        vm.inspect_transaction_with_bytecode_compression(&mut dispatcher, tx.clone(), false);
    if compression_result.is_err() {
        bail!("compression must succeed when disabled");
    }

    Ok(TxExecutionCapture {
        used_compression: false,
        trace: dispatcher.0.into_trace(execution.result),
    })
}

fn first_step_mismatch<'a>(
    legacy: &'a TransactionTrace,
    fast: &'a TransactionTrace,
) -> Option<(
    &'a crate::types::ObservedStep,
    &'a crate::types::ObservedStep,
)> {
    legacy
        .observations
        .iter()
        .zip(&fast.observations)
        .find(|(legacy_step, fast_step)| legacy_step != fast_step)
}

fn compare_batch_outputs(legacy: &FinishedL1Batch, fast: &FinishedL1Batch) -> Vec<String> {
    let mut divergences = Vec::new();

    if legacy.block_tip_execution_result.result != fast.block_tip_execution_result.result {
        divergences.push(format!(
            "batch tip execution result mismatch: legacy={:?}, fast={:?}",
            legacy.block_tip_execution_result.result, fast.block_tip_execution_result.result
        ));
    }
    if legacy.final_execution_state.events != fast.final_execution_state.events {
        divergences.push("final events mismatch".to_owned());
    }
    if legacy.final_execution_state.deduplicated_storage_logs
        != fast.final_execution_state.deduplicated_storage_logs
    {
        divergences.push("final deduplicated storage logs mismatch".to_owned());
    }
    if legacy.final_execution_state.user_l2_to_l1_logs
        != fast.final_execution_state.user_l2_to_l1_logs
    {
        divergences.push("final user L2->L1 logs mismatch".to_owned());
    }
    if legacy.final_execution_state.system_logs != fast.final_execution_state.system_logs {
        divergences.push("final system logs mismatch".to_owned());
    }
    let legacy_contracts: BTreeSet<_> = legacy
        .final_execution_state
        .used_contract_hashes
        .iter()
        .copied()
        .collect();
    let fast_contracts: BTreeSet<_> = fast
        .final_execution_state
        .used_contract_hashes
        .iter()
        .copied()
        .collect();
    if legacy_contracts != fast_contracts {
        divergences.push("used contract hashes mismatch".to_owned());
    }
    if legacy.final_execution_state.storage_refunds != fast.final_execution_state.storage_refunds {
        divergences.push("storage refunds mismatch".to_owned());
    }
    if legacy.final_execution_state.pubdata_costs != fast.final_execution_state.pubdata_costs {
        divergences.push("pubdata costs mismatch".to_owned());
    }
    if legacy.final_bootloader_memory != fast.final_bootloader_memory {
        divergences.push("final bootloader memory mismatch".to_owned());
    }
    if legacy.pubdata_input != fast.pubdata_input {
        divergences.push("pubdata input mismatch".to_owned());
    }
    if legacy.state_diffs != fast.state_diffs {
        divergences.push("state diffs mismatch".to_owned());
    }

    divergences
}
