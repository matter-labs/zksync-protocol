use zkevm_opcode_defs::decoding::EncodingModeProduction;

use crate::assembly::*;
use std::convert::TryFrom;

#[test]
fn test_memory_syntax() {
    let asm_text = r#"
    .data
        .globl    val                             ; @val
        .p2align    5
    val:
        .zero 64 ; 64 bytes
        .cell 123
    .text
    .globl  __entry
    __entry:
    .func_begin0:
        st.1 r5, r1
        ret.ok r0
    .rodata
    const_1:
        .cell 777 ; 2 bytes
    switch.table.fun_f:
        .cell 0
        .cell 1
        .cell 4
    "#;
    let mut asm = Assembly::try_from(asm_text.to_owned()).unwrap();
    let _bc = asm.compile_to_bytecode_for_mode::<8, EncodingModeProduction>().unwrap();
    let instructions = asm.opcodes::<8, EncodingModeProduction>();
    dbg!(&instructions);
}