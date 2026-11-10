use crate::assembly::instruction::jump::flag::Flag;
use crate::assembly::instruction::Instruction::NoOperation;
use crate::{Assembly, AssemblyParseError, DataOperation, FullOperand, Instruction, InstructionReadError, JumpInstruction, MemoryInstruction, MemoryOperand, MemoryType, RegisterOperand, ShuffleInstruction, FunctionJumpInstruction, FunctionJumpLocation, ContextInstruction, ContextField, StorageInstruction, BitwiseInstruction, BitwiseOpType, ShiftInstruction};
use std::convert::{TryFrom, TryInto};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::array::IntoIter;

#[test]
fn test_noop() {
    let asm_text = r#"
        .text
       nop
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![NoOperation],
            labels: HashMap::new(),
            pc_line_mapping: [(0, 3)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_invalid_layout() {
    let asm_text = r#"
        .text
       nop
        .data
       arr:
        .quad    1
        .data
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());
    assert_eq!(asm, Err(AssemblyParseError::AssemblerLayoutError))
}

#[test]
fn test_memory_syntax() {
    let asm_text = r#"
     .text
        mov 10, r2
        mov.p 10, r2
        mov.c r2, 10
        mov r1, arr+10
        mov 10(sp), r2
        mov arr(sp), r2
        mov arr(r3), r2
        mov arr+19(r4), r2
        mov arr+17(sp), r2
        mov arr+17(sp-r5), r2
     .data
     unused:
        .zero 1 ; 1 byte
     arr:
        .word 777 ; 2 bytes
    "#;
    let asm = Assembly::try_from(asm_text.to_owned());
    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![
                // HEAP SYMBOLS
                // `unused`
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(0),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 0,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // `arr`
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(777),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // PROGRAM CODE
                //  mov 10, r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 10,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                // mov.p 10, r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::SharedParent,
                        offset: 10,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                // mov.c r2, 10
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::SharedChild,
                        offset: 10,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(1)
                    },
                }),
                //  mov r1, arr+10
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1 + 10,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                //   mov 10(sp), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 10,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                //   mov arr(sp), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 1,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                //   mov arr(r3), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1,
                        register: RegisterOperand::Register(2),
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                //   mov arr+19(r4), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1 + 19,
                        register: RegisterOperand::Register(3),
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                //   mov arr+17(sp), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 1 + 17,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                //   mov arr+17(sp-r5), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 1 + 17,
                        register: RegisterOperand::Register(4),
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                })
            ],
            labels: HashMap::from_iter(IntoIter::new([("unused".to_owned(), 0), ("arr".to_owned(), 1)])),
            pc_line_mapping:
            [(4, 3), (5, 4), (6, 5), (7, 6), (8, 7), (9, 8), (10, 9), (11, 10), (12, 11), (13, 12)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_push_pop() {
    let asm_text = r#"
     .text
        pop #10, r2
        push #3, r1
    "#;
    let asm = Assembly::try_from(asm_text.to_owned());
    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![
                // PROGRAM CODE
                //  pop #10, r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: true },
                        offset: 10,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                //  push #3, r1
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: true },
                        offset: 3,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
            ],
            labels: HashMap::new(),
            pc_line_mapping:
            [(0, 3), (1, 4)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_memory_operand_syntax() {
    let asm_text = r#"
     .text
        sfll #arr, r0, r1
        sflh #arr+5, r0, r1
        sflh arr+5, r0, r1
        sflh r4, r0, r1
        sfll arr+17(r3), r5, r1
        sfll arr-17(r3), r5, r1
        sfll -42(r1), r5, r1
     .data
     unused:
        .zero 1 ; 1 byte
     arr:
        .word 777 ; 2 bytes
    "#;
    let asm = Assembly::try_from(asm_text.to_owned());
    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![
                // HEAP SYMBOLS
                // `unused`
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(0),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 0,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // `arr`
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(777),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // PROGRAM CODE
                //   sfll #arr, r0, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(1), // arr = 1
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                //   sflh #arr+5, r0, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(1 + 5), // arr = 1
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: false,
                }),
                //   sflh arr+5, r0, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Memory(MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 6,
                        register: RegisterOperand::Null,
                    }),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: false,
                }),
                //   sflh r4, r0, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Register(RegisterOperand::Register(3)),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: false,
                }),
                //   sfll arr+17(r3), r5, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Memory(MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 18,
                        register: RegisterOperand::Register(2),
                    }),
                    source_2: RegisterOperand::Register(4),
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                //   sfll arr-17(r3), r5, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Memory(MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1u16.wrapping_sub(17),
                        register: RegisterOperand::Register(2),
                    }),
                    source_2: RegisterOperand::Register(4),
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                // sfll -42(r1), r5, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Memory(MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 0u16.wrapping_sub(42),
                        register: RegisterOperand::Register(0),
                    }),
                    source_2: RegisterOperand::Register(4),
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
            ],
            labels: HashMap::from_iter(IntoIter::new([("unused".to_owned(), 0), ("arr".to_owned(), 1)])),
            pc_line_mapping:
            [(4, 3), (5, 4), (6, 5), (7, 6), (8, 7), (9, 8), (10, 9)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_label_parsing() {
    let asm_text = r#"
     .text
        round_up_to_mul_of_32:
        call round_up_to_mul_of_32
    "#;
    let asm = Assembly::try_from(asm_text.to_owned());
    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![
                Instruction::FunctionJump(FunctionJumpInstruction::Call {
                    location: FunctionJumpLocation::Local {
                        address: 0,
                        operand: FullOperand::Register(RegisterOperand::Null),
                    }
                })
            ],
            labels: HashMap::from_iter(IntoIter::new([("round_up_to_mul_of_32".to_owned(), 0)])),
            pc_line_mapping:
            [(0, 4)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_heap_allocation_multiple_symbols() {
    let asm_text = r#"
     .text
        j label, label
        mov arr1+1(sp-r3), r2
        mov r0, arr2(r3)
        sfll #arr3, r0, r1
     label:
        nop
     .data
     arr1:                ; will have heap offset 0
        .byte 255 ; 1 byte
        .word 12  ; 1 + 2  = 3 bytes
        .quad 8   ; 3 + 4  = 7 bytes
        .zero 1   ; 7 + 1  = 8 bytes
        .zero 26  ; 8 + 26 = 34 bytes in total - occupies two slots in heap
     arr2:                ; will have heap offset 2
        .byte 200 ; 1 byte
     arr3:                ; will have heap offset 3
        .zero 7   ; 7 bytes
        .byte 100 ; 7 + 1 = 8 bytes
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    let mut arr1_first_u128_bytes = vec![255u8, 12u8, 0u8, 8u8];
    arr1_first_u128_bytes.resize(16, 0);

    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![
                // arr1: first 256 bits
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(u128::from_le_bytes(
                        arr1_first_u128_bytes.try_into().unwrap()
                    )),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(0),
                    source_2: RegisterOperand::Register(0),
                    destination: RegisterOperand::Register(0),
                    load_in_low: false,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 0,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // arr1: second 256 bits
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(0),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 1,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // arr2
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(200u128),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 2,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // arr3
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(100u128 << (7 * 8)), // first 7 bytes are zero
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 3,
                        register: RegisterOperand::Null,
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Register(0)
                    },
                }),
                // program code
                Instruction::Jump(JumpInstruction {
                    source: FullOperand::Register(RegisterOperand::Null),
                    flags: vec![Flag::Unconditional],
                    destination_true: 13, // originally label points to `4`, but we prepend with 9 instructions
                    destination_false: 13,
                }),
                // move arr+1(sp-r3), r2
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 0 + 1, // arr + 1
                        register: RegisterOperand::Register(2),
                    },
                    operation: DataOperation::Read {
                        destination: RegisterOperand::Register(1)
                    },
                }),
                // mov r0, arr2(r3)
                Instruction::Memory(MemoryInstruction {
                    address: MemoryOperand {
                        r#type: MemoryType::Local,
                        offset: 2, // arr
                        register: RegisterOperand::Register(2),
                    },
                    operation: DataOperation::Write {
                        source: RegisterOperand::Null
                    },
                }),
                // sfll #arr3, r0, r1
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(3), //arr3 = 3
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::NoOperation
            ],
            labels: HashMap::from_iter(IntoIter::new([("arr3".to_owned(), 3), ("arr2".to_owned(), 2), ("arr1".to_owned(), 0), ("label".to_owned(), 13)])),
            pc_line_mapping: [(9, 3), (10, 4), (11, 5), (12, 6), (13, 8)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_context_mnemonics() {
    let asm_text = r#"
     .text
        ctx #3, r3
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(
        asm,
        Ok(Assembly {
            instructions: vec![
                // arr1: first 256 bits
                Instruction::Context(ContextInstruction {
                    destination: RegisterOperand::Register(2),
                    field: ContextField::GasLeft,
                })
            ],
            labels: HashMap::new(),
            pc_line_mapping: [(0, 3)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        })
    )
}

#[test]
fn test_invalid_number() {
    let asm_text = r#"
        .text
       nop
        .data
       arr:
        .quad    1q
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    if let Err(AssemblyParseError::LineReadError(errors)) = asm {
        assert!(matches!(
            errors.get(&6),
            Some(InstructionReadError::InvalidNumber(_, _))
        ));
    } else {
        panic!("unexpected result: {:?}", asm)
    }
}

#[test]
fn test_unknown_vars() {
    let asm_text = r#"
        .text
       nop
       mov arr, r0
         label:
       mov r1, arr2
       mov unk, r4
       j label, label
       j unko, unko2
        .data
       arr:
        .quad    1
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    if let Err(AssemblyParseError::LineReadError(errors)) = asm {
        assert_eq!(errors.len(), 3);
        assert!(matches!(
            errors.get(&6),
            Some(InstructionReadError::UnknownLabel(_))
        ));
        assert!(matches!(
            errors.get(&7),
            Some(InstructionReadError::UnknownLabel(_))
        ));
        assert!(matches!(
            errors.get(&9),
            Some(InstructionReadError::UnknownLabel(_))
        ));
    } else {
        panic!("unexpected result: {:?}", asm)
    }
}

#[test]
fn test_events() {
    let asm_text = r#"
        .text
       sfll #32, r0, r1
       evt.i #2, r1
       evt #777, r3
       evt #123, r0
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(Ok(
        Assembly {
            instructions: vec![
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(32),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Storage(StorageInstruction::LogInit {
                    packed_lengths: FullOperand::Immediate(2),
                    first_topic_or_chunk: RegisterOperand::Register(0),
                }),
                Instruction::Storage(StorageInstruction::Log(FullOperand::Immediate(777), RegisterOperand::Register(2))),
                Instruction::Storage(StorageInstruction::Log(FullOperand::Immediate(123), RegisterOperand::Null)),
            ],
            labels: Default::default(),
            pc_line_mapping: [(0, 3), (1, 4), (2, 5), (3, 6)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        }
    ), asm)
}

#[test]
fn test_storage() {
    let asm_text = r#"
        .text
       sfll #366, r0, r1
       st r1, #533
       ret
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(Ok(
        Assembly {
            instructions: vec![
                Instruction::Shuffle(ShuffleInstruction {
                    source_1: FullOperand::Immediate(366),
                    source_2: RegisterOperand::Null,
                    destination: RegisterOperand::Register(0),
                    load_in_low: true,
                }),
                Instruction::Storage(StorageInstruction::Storage {
                    storage_key: FullOperand::Immediate(533),
                    operation: DataOperation::Write { source: RegisterOperand::Register(0) },
                    is_external_storage_access: false,
                }),
                Instruction::FunctionJump(FunctionJumpInstruction::Return { error: false })
            ],
            labels: Default::default(),
            pc_line_mapping: [(0, 3), (1, 4), (2, 5)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        }
    ), asm)
}

#[test]
fn test_bitwise_xor() {
    let asm_text = r#"
        .text
       xor r1, r2, r3
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(Ok(
        Assembly {
            instructions: vec![
                Instruction::Bitwise(BitwiseInstruction {
                    source_1: FullOperand::Register(RegisterOperand::Register(0)),
                    source_2: RegisterOperand::Register(1),
                    destination: RegisterOperand::Register(2),
                    op_type: BitwiseOpType::Xor,
                }),
            ],
            labels: Default::default(),
            pc_line_mapping: [(0, 3)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        }
    ), asm)
}

#[test]
fn test_bitwise_shift() {
    let asm_text = r#"
        .text
       shl r2, r1, r3
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(Ok(
        Assembly {
            instructions: vec![
                Instruction::Shift(ShiftInstruction {
                    source_1: FullOperand::Register(RegisterOperand::Register(0)),
                    source_2: RegisterOperand::Register(1),
                    destination: RegisterOperand::Register(2),
                    is_cyclic: false,
                    is_right: false,
                }),
            ],
            labels: Default::default(),
            pc_line_mapping: [(0, 3)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        }
    ), asm)
}

#[test]
fn test_bitwise_cycle_right() {
    let asm_text = r#"
        .text
       ror r2, r1, r3
    "#;

    let asm = Assembly::try_from(asm_text.to_owned());

    assert_eq!(Ok(
        Assembly {
            instructions: vec![
                Instruction::Shift(ShiftInstruction {
                    source_1: FullOperand::Register(RegisterOperand::Register(0)),
                    source_2: RegisterOperand::Register(1),
                    destination: RegisterOperand::Register(2),
                    is_cyclic: true,
                    is_right: true,
                }),
            ],
            labels: Default::default(),
            pc_line_mapping: [(0, 3)]
                .iter()
                .cloned()
                .collect(),
            assembly_code: String::from(asm_text),
        }
    ), asm)
}
