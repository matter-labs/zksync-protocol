use asm_tests::run_asm_based_test_with_evm_contracts;

use super::*;

#[test_log::test]
fn test_far_call_to_evm_contract() {
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/call_zkevm_to_evm",
        &[],
        &[65536], // evm contracts
        false,    // Don't use custom default AA
        Options {
            cycles_per_vm_snapshot: 1,
            ..Default::default()
        },
    );
}

#[test_log::test]
fn test_far_call_evm_to_zkvm_contract() {
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/call_evm_to_zkevm",
        &[65537], // zkvm contracts
        &[65536], // evm contracts
        false,    // Don't use custom default AA
        Options {
            cycles_per_vm_snapshot: 1,
            ..Default::default()
        },
    );
}

#[test_log::test]
fn test_static_call_to_evm_and_zkvm() {
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/static_call_to_evm_and_zkvm",
        &[65537], // zkvm contracts
        &[65536], // evm contracts
        false,    // Don't use custom default AA
        Options {
            cycles_per_vm_snapshot: 1,
            ..Default::default()
        },
    );
}

#[test_log::test]
fn test_static_call_to_zkevm_and_evm() {
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/static_call_to_zkvm_and_evm",
        &[65537], // zkvm contracts
        &[65536], // evm contracts
        false,    // Don't use custom default AA
        Options {
            cycles_per_vm_snapshot: 1,
            ..Default::default()
        },
    );
}

#[test_log::test]
fn test_delegate_call_to_evm() {
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/delegatecall_zkevm_to_evm",
        &[],      // zkvm contracts
        &[65536], // evm contracts
        false,    // Don't use custom default AA
        Options {
            cycles_per_vm_snapshot: 1,
            ..Default::default()
        },
    );
}

#[test_log::test]
fn test_decommit_evm() {
    // Decomit EVM bytecode with even length in versioned bytecode hash
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/decommit_evm",
        &[],      // zkvm contracts
        &[65536], // evm contracts
        false,    // Don't use custom default AA
        Options {
            cycles_per_vm_snapshot: 1,
            ..Default::default()
        },
    );
}

#[test_log::test]
fn test_far_call_blob_marker_mismatch_static_overconstraint() {
    run_asm_based_test_with_evm_contracts(
        "src/tests/simple_tests/testdata/evm_emulator/blob_marker_mismatch_static_overconstraint",
        &[65536, 32770],
        &[65537],
        true, // Use custom default AA
        Default::default(),
    );
}
