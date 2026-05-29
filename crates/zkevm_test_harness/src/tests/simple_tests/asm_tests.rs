use self::run_manually::{
    run_and_try_create_witness_for_extended_state, run_and_try_create_witness_inner, Options,
};
use super::*;
pub use crate::tests::utils::preprocess_asm::TemplateDictionary;
use crate::tests::utils::preprocess_asm::{asm_with_default_config, preprocess_asm};
use std::{fs, path::Path};
use zkevm_assembly::Assembly;

/// Runs the tests based on the ASM files from a given directory.
/// The main assembly should be in `entry.asm` file, while additional
/// contracts should be in `ADDRESS.asm` files, where `ADDRESS` is the numerical
/// address at which they should be deployed.
pub fn run_asm_based_test(
    test_dir: &str,
    additional_contracts_addresses: &[i32],
    options: Options,
) {
    let additional_contracts = additional_contracts_addresses
        .iter()
        .map(|address| (address.to_string(), *address))
        .collect();

    run_asm_based_test_template(test_dir, &additional_contracts, options, None);
}

pub fn run_asm_based_test_with_default_aa(
    test_dir: &str,
    additional_contracts_addresses: &[i32],
    mut options: Options,
) {
    let default_aa =
        compile_additional_contracts(test_dir, &vec![("default_aa".to_owned(), 0)], None)[0]
            .clone()
            .1;
    options.default_aa = Some(default_aa);

    let additional_contracts = additional_contracts_addresses
        .iter()
        .map(|address| (address.to_string(), *address))
        .collect();

    run_asm_based_test_template(test_dir, &additional_contracts, options, None);
}

pub fn run_asm_based_test_with_evm_contracts(
    test_dir: &str,
    additional_contracts_addresses: &[i32],
    additional_evm_contracts_addresses: &[i32],
    use_custom_default_aa: bool,
    mut options: Options,
) {
    let evm_emulator =
        compile_additional_contracts(test_dir, &vec![("evm_emulator".to_owned(), 0)], None)[0]
            .clone()
            .1;

    let default_aa = if use_custom_default_aa {
        Some(
            compile_additional_contracts(test_dir, &vec![("default_aa".to_owned(), 0)], None)[0]
                .clone()
                .1,
        )
    } else {
        None
    };

    let other_evm_contracts = additional_evm_contracts_addresses
        .iter()
        .map(|x| Address::from_low_u64_be(*x as u64))
        .collect();

    options.evm_emulator = Some(evm_emulator);
    options.default_aa = default_aa;
    options.other_evm_contracts = other_evm_contracts;

    let additional_contracts = additional_contracts_addresses
        .iter()
        .map(|address| (address.to_string(), *address))
        .collect();

    run_asm_based_test_template(test_dir, &additional_contracts, options, None);
}

pub fn run_asm_based_test_template(
    test_dir: &str,
    additional_contracts: &Vec<(String, i32)>,
    options: Options,
    dictionary: Option<&TemplateDictionary>,
) {
    let data_path = Path::new(test_dir);

    let contracts: Vec<(H160, Vec<[u8; 32]>)> =
        compile_additional_contracts(test_dir, additional_contracts, dictionary);

    let entry_bytecode = compile_asm_template(data_path, "entry", dictionary, Some(&contracts));

    let mut options = options.clone();
    options.other_contracts = contracts;
    run_with_options(entry_bytecode, options);
}

pub fn compile_additional_contracts(
    test_dir: &str,
    contracts: &Vec<(String, i32)>,
    dictionary: Option<&TemplateDictionary>,
) -> Vec<(H160, Vec<[u8; 32]>)> {
    let data_path = Path::new(test_dir);
    contracts
        .iter()
        .map(|(source_file, address)| {
            let bytecode = compile_asm_template(data_path, source_file, dictionary, None);
            (Address::from_low_u64_be(*address as u64), bytecode)
        })
        .collect()
}

fn compile_asm_template(
    data_path: &Path,
    filename: &str,
    dictionary: Option<&TemplateDictionary>,
    additional_contracts: Option<&Vec<(H160, Vec<[u8; 32]>)>>,
) -> Vec<[u8; 32]> {
    let file_path = data_path.join(format!("{filename}.asm"));
    let asm = fs::read_to_string(file_path.clone()).expect(&format!(
        "Should have been able to read the file {:?}",
        file_path
    ));
    let asm_preprocessed = preprocess_asm(asm, additional_contracts, dictionary);
    Assembly::try_from(asm_preprocessed.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .expect(&format!("Failed to compile {:?}", file_path))
}

#[ignore = "used for manual runs"]
#[test_log::test]
fn test_manual_asm() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/meta_opcode",
        &[],
        Default::default(),
    )
}
#[test_log::test]
fn test_noncanonical_dst1_on_add() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 42, r0, r1
        add r0, r0, r2
        add r1, r0, stack[0]
        ret.ok r0
    "#,
    );

    let mut assembly = Assembly::try_from(asm).unwrap();
    let mut bytecode = assembly.compile_to_bytecode().unwrap();
    assert_eq!(
        bytecode[0][12], 0x02,
        "Unexpected dst_regs byte for instruction 1; layout may have shifted"
    );

    // set dst1_reg_idx from 0 -> 1.
    bytecode[0][12] |= 0x10;

    // Expecting: r1 stays 42, stack[0] = 42

    run_and_try_create_witness_for_extended_state(bytecode, vec![], 50);
}

#[test_log::test]
fn test_canonical_dst1_on_mul() {
    let asm = asm_with_default_config(
        r#"
    __entry:
    .main:
        add 3, r0, r1
        add 5, r0, r2
        mul r1, r2, r3, r4
        add r3, r0, stack[0]
        add r4, r0, stack[1]
        ret.ok r0
    "#,
    );

    let mut assembly = Assembly::try_from(asm).unwrap();
    let bytecode = assembly.compile_to_bytecode().unwrap();

    run_and_try_create_witness_for_extended_state(bytecode, vec![], 50);
}
