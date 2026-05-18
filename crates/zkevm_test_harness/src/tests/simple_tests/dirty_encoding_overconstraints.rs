use super::*;
use crate::tests::simple_tests::asm_tests::run_asm_based_test;

use std::path::Path;
use zkevm_assembly::zkevm_opcode_defs::decoding::encoding_mode_production::EncodingModeProduction;
use zkevm_assembly::zkevm_opcode_defs::decoding::VmEncodingMode;

fn run_asm_based_test_with_bytecode_patch(
    test_dir: &str,
    options: run_manually::Options,
    patch: impl FnOnce(&mut Vec<[u8; 32]>),
) {
    use crate::tests::utils::preprocess_asm::preprocess_asm;
    use std::fs;
    use zkevm_assembly::Assembly;

    let data_path = Path::new(test_dir);
    let file_path = data_path.join("entry.asm");
    let asm = fs::read_to_string(&file_path)
        .unwrap_or_else(|_| panic!("Should have been able to read the file {:?}", file_path));
    let asm_preprocessed = preprocess_asm(asm, None, None);
    let mut entry_bytecode = Assembly::try_from(asm_preprocessed.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .unwrap_or_else(|_| panic!("Failed to compile {:?}", file_path));

    patch(&mut entry_bytecode);

    run_manually::run_with_options(entry_bytecode, options);
}

#[test_log::test]
fn test_dirty_dst1_encoding_on_add() {
    run_asm_based_test_with_bytecode_patch(
        "src/tests/simple_tests/testdata/dirty_encoding_overconstraints/dst1_dirty_add_overconstraint",
        Default::default(),
        |entry_bytecode| {
            // Instructions are packed as 8 bytes each inside 32-byte words.
            // The instruction encoding is a BE `u64` (`u64::to_be_bytes()`), where:
            // byte[4] holds `dst_regs_encoding` (low nibble = dst0, high nibble = dst1).
            //
            // We patch the 2nd instruction (pc = 1): byte offset = 8*1 + 4 = 12.
            // High nibble is `dst1_reg_idx`; set it to 2 (r2).
            assert!(!entry_bytecode.is_empty(), "empty entry bytecode");
            let word0 = &mut entry_bytecode[0];
            let idx = 8 * 1 + 4;
            assert!(idx < 32, "unexpected instruction packing");

            // Sanity check: decode the opcode before/after patch and assert `dst1_reg_idx` changed.
            {
                let instr_bytes: [u8; 8] = word0[8..16].try_into().expect("instr slice");
                let enc = u64::from_be_bytes(instr_bytes);
                let (decoded, _) =
                    EncodingModeProduction::parse_preliminary_variant_and_absolute_number(enc);
                assert_eq!(decoded.dst1_reg_idx, 0, "precondition: dst1 must be 0");
            }

            word0[idx] = (word0[idx] & 0x0f) | (2u8 << 4);

            {
                let instr_bytes: [u8; 8] = word0[8..16].try_into().expect("instr slice");
                let enc = u64::from_be_bytes(instr_bytes);
                let (decoded, _) =
                    EncodingModeProduction::parse_preliminary_variant_and_absolute_number(enc);
                assert_eq!(decoded.dst1_reg_idx, 2, "dst1 must be patched to r2");
            }
        },
    );
}
