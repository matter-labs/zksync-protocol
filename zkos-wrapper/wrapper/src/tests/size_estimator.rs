use std::fs;
use std::io::Write as IoWrite;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use crate::circuits::BinaryCommitment;

use super::*;

const SIZE_ESTIMATOR_OUTPUT_DIR: &str = "testing_data/size_estimator_outputs";

/// Extract a human-readable message from a panic payload.
fn panic_payload_to_string(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = e.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic payload".to_string()
    }
}

/// Attempts to build a CS with the given geometry parameters and synthesize the
/// RiscWrapperCircuit into it. Returns `Ok(())` if synthesis and pad_and_shrink
/// both complete without panicking, `Err(message)` otherwise.
fn try_synthesize_wrapper_with_params(
    num_columns: usize,
    num_repetitions: usize,
) -> Result<(), String> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: num_columns,
            num_witness_columns: 0,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 4,
        };

        let lookup_params = LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions,
            share_table_id: true,
        };

        use boojum::config::SetupCSConfig;
        use boojum::cs::cs_builder::new_builder;
        use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
        use boojum::cs::gates::PublicInputGate;

        let builder_impl =
            CsReferenceImplementationBuilder::<F, F, SetupCSConfig, StCircuitResolver<_, _>>::new(
                geometry,
                1 << 20,
            );
        let builder = new_builder::<_, F>(builder_impl);

        // Manually replicate RiscWrapperCircuit::configure_builder,
        // but with our custom lookup parameters.
        let builder = builder.allow_lookup(lookup_params);
        let builder = ConstantsAllocatorGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<F, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<16>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<8>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );
        let builder = PublicInputGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = U32TriAddCarryAsChunkGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );

        let mut owned_cs = builder.build(1 << 27);

        use std::io::Read;
        let mut binary = vec![];
        let mut file = std::fs::File::open(crate::tests::RISC_PROGRAM_BIN_PATH).unwrap();
        file.read_to_end(&mut binary).unwrap();
        let mut text = vec![];
        let mut file = std::fs::File::open(crate::tests::RISC_PROGRAM_TEXT_PATH).unwrap();
        file.read_to_end(&mut text).unwrap();
        let binary_commitment = BinaryCommitment::from_base_binary(&binary, &text);
        use crate::RiscWrapper;
        let circuit = RiscWrapper::new(None, false, binary_commitment, false);
        circuit.add_tables(&mut owned_cs);
        circuit.synthesize_into_cs(&mut owned_cs);
        owned_cs.pad_and_shrink();
    }));

    result.map_err(|e| panic_payload_to_string(e))
}

#[test]
#[ignore]
fn find_minimum_cs_parameters_for_wrapper() {
    // Customizable starting values via environment variables.
    // NUM_REPETITIONS: used as the high bound when searching for min num_repetitions,
    //                  and as the fixed value when searching for min num_columns. Default: 100.
    // NUM_COLUMNS: used as the high bound when searching for min num_columns,
    //              and as the fixed value when searching for min num_repetitions. Default: 180.
    let num_repetitions: usize = std::env::var("NUM_REPETITIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let num_columns: usize = std::env::var("NUM_COLUMNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);

    println!(
        "Starting parameters: num_columns={}, num_repetitions={}",
        num_columns, num_repetitions
    );

    // Clear/create output directory
    let _ = fs::remove_dir_all(SIZE_ESTIMATOR_OUTPUT_DIR);
    fs::create_dir_all(SIZE_ESTIMATOR_OUTPUT_DIR).unwrap();

    // Panic hook that captures info to a shared buffer
    let default_hook = std::panic::take_hook();
    let panic_buf = Arc::new(Mutex::new(String::new()));
    let panic_buf_hook = Arc::clone(&panic_buf);
    std::panic::set_hook(Box::new(move |info| {
        let mut buf = panic_buf_hook.lock().unwrap();
        *buf = format!("{}", info);
    }));

    // Search 1: minimum num_columns_under_copy_permutation (with fixed num_repetitions)
    println!(
        "=== Searching for minimum num_columns_under_copy_permutation (num_repetitions={}) ===",
        num_repetitions
    );
    let mut low: usize = 10;
    let mut high: usize = num_columns;
    while low < high {
        let mid = (low + high) / 2;
        print!("  Trying num_columns={}... ", mid);
        match try_synthesize_wrapper_with_params(mid, num_repetitions) {
            Ok(()) => {
                println!("OK");
                high = mid;
            }
            Err(msg) => {
                println!("FAILED");
                let hook_info = panic_buf.lock().unwrap().clone();
                let filename = format!(
                    "{}/wrapper_cols{}_reps{}_FAILED.txt",
                    SIZE_ESTIMATOR_OUTPUT_DIR, mid, num_repetitions
                );
                let mut f = fs::File::create(&filename).unwrap();
                writeln!(
                    f,
                    "Parameters: num_columns={}, num_repetitions={}",
                    mid, num_repetitions
                )
                .unwrap();
                writeln!(f, "\nPanic message:\n{}", msg).unwrap();
                writeln!(f, "\nPanic hook info:\n{}", hook_info).unwrap();
                low = mid + 1;
            }
        }
    }
    println!("Minimum num_columns_under_copy_permutation: {}\n", low);

    // Search 2: minimum num_repetitions (with fixed num_columns)
    println!(
        "=== Searching for minimum num_repetitions (num_columns_under_copy_permutation={}) ===",
        num_columns
    );
    let mut low: usize = 1;
    let mut high: usize = num_repetitions;
    while low < high {
        let mid = (low + high) / 2;
        print!("  Trying num_repetitions={}... ", mid);
        match try_synthesize_wrapper_with_params(num_columns, mid) {
            Ok(()) => {
                println!("OK");
                high = mid;
            }
            Err(msg) => {
                println!("FAILED");
                let hook_info = panic_buf.lock().unwrap().clone();
                let filename = format!(
                    "{}/wrapper_cols{}_reps{}_FAILED.txt",
                    SIZE_ESTIMATOR_OUTPUT_DIR, num_columns, mid
                );
                let mut f = fs::File::create(&filename).unwrap();
                writeln!(
                    f,
                    "Parameters: num_columns={}, num_repetitions={}",
                    num_columns, mid
                )
                .unwrap();
                writeln!(f, "\nPanic message:\n{}", msg).unwrap();
                writeln!(f, "\nPanic hook info:\n{}", hook_info).unwrap();
                low = mid + 1;
            }
        }
    }
    println!("Minimum num_repetitions: {}", low);

    // Restore default panic hook
    std::panic::set_hook(default_hook);
}

/// Attempts to build a CS with the given geometry parameters and synthesize the
/// CompressionCircuit into it. Returns `Ok(())` if synthesis and pad_and_shrink
/// both complete without panicking, `Err(message)` otherwise.
fn try_synthesize_compression_with_params(
    num_columns: usize,
    num_witness_columns: usize,
    vk: &crate::RiscWrapperVK,
) -> Result<(), String> {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let geometry = CSGeometry {
            num_columns_under_copy_permutation: num_columns,
            num_witness_columns,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        };

        use boojum::config::SetupCSConfig;
        use boojum::cs::cs_builder::new_builder;
        use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
        use boojum::cs::traits::circuit::CircuitBuilder;

        let builder_impl =
            CsReferenceImplementationBuilder::<F, F, SetupCSConfig, StCircuitResolver<_, _>>::new(
                geometry,
                1 << 16,
            );
        let builder = new_builder::<_, F>(builder_impl);

        let builder = crate::circuits::CompressionCircuit::configure_builder(builder);

        let mut owned_cs = builder.build(1 << 24);

        let circuit = crate::circuits::CompressionCircuit::new(None, vk.clone());
        circuit.synthesize_into_cs(&mut owned_cs);
        owned_cs.pad_and_shrink();
    }));

    result.map_err(|e| panic_payload_to_string(e))
}

#[test]
#[ignore]
fn find_minimum_cs_parameters_for_compression() {
    let vk: crate::RiscWrapperVK = deserialize_from_bin_file(RISC_WRAPPER_VK_PATH).unwrap();

    // Clear/create output directory
    let _ = fs::remove_dir_all(SIZE_ESTIMATOR_OUTPUT_DIR);
    fs::create_dir_all(SIZE_ESTIMATOR_OUTPUT_DIR).unwrap();

    // Panic hook that captures info to a shared buffer
    let default_hook = std::panic::take_hook();
    let panic_buf = Arc::new(Mutex::new(String::new()));
    let panic_buf_hook = Arc::clone(&panic_buf);
    std::panic::set_hook(Box::new(move |info| {
        let mut buf = panic_buf_hook.lock().unwrap();
        *buf = format!("{}", info);
    }));

    for num_total_columns in [130, 150] {
        // Linear scan: for each possible num_columns_under_copy_permutation,
        // test with num_witness_columns = num_total_columns - copy_cols.
        // The working range may not be contiguous — it could be [x..y].
        println!(
            "=== Scanning all splits for num_total_columns={} ===",
            num_total_columns
        );

        let mut min_copy_cols = None;

        for copy_cols in 0..=num_total_columns {
            let witness_cols = num_total_columns - copy_cols;
            print!(
                "  copy_permutation={}, witness={}... ",
                copy_cols, witness_cols
            );
            match try_synthesize_compression_with_params(copy_cols, witness_cols, &vk) {
                Ok(()) => {
                    println!("OK");
                    min_copy_cols = Some(copy_cols);
                    break;
                }
                Err(msg) => {
                    println!("FAILED");
                    let hook_info = panic_buf.lock().unwrap().clone();
                    let filename = format!(
                        "{}/compression_cols{}_wcols{}_FAILED.txt",
                        SIZE_ESTIMATOR_OUTPUT_DIR, copy_cols, witness_cols
                    );
                    let mut f = fs::File::create(&filename).unwrap();
                    writeln!(
                        f,
                        "Parameters: num_columns_under_copy_permutation={}, num_witness_columns={}",
                        copy_cols, witness_cols
                    )
                    .unwrap();
                    writeln!(f, "\nPanic message:\n{}", msg).unwrap();
                    writeln!(f, "\nPanic hook info:\n{}", hook_info).unwrap();
                }
            }
        }

        println!(
            "\n=== Results for CompressionCircuit (num_total_columns={}) ===",
            num_total_columns
        );
        if let Some(copy_cols) = min_copy_cols {
            let witness_cols = num_total_columns - copy_cols;
            println!("  min num_columns_under_copy_permutation: {}", copy_cols);
            println!("  max num_witness_columns: {}", witness_cols);
            break;
        } else {
            println!("  No working configuration found, trying next total...");
        }
    }

    // Restore default panic hook
    std::panic::set_hook(default_hook);
}
