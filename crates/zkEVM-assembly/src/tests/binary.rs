use crate::assembly::instruction::function_jump::location::Location;
use crate::assembly::instruction::jump::flag::Flag;
use crate::assembly::operand::RegisterOperand::Register;
use crate::error::BinaryParseError;
use crate::{AddInstruction, Assembly, DataOperation, DivInstruction, FullOperand, FunctionJumpInstruction, HashAbsorbInstruction, HashOutputInstruction, Instruction, JumpInstruction, MemoryInstruction, MemoryOperand, MemoryType, MulInstruction, RegisterOperand, SetExternalAddressInstruction, ShuffleInstruction, StorageInstruction, SubInstruction, ContextInstruction, ContextField, BitwiseInstruction, BitwiseOpType, ShiftInstruction};
use std::convert::{TryFrom, TryInto};
use std::collections::HashMap;

#[test]
fn test_noop() {
    let input: u64 = 0b10010;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::NoOperation],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    )
}

#[test]
fn test_shuffle() {
    //               0bmemf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u64 = 0b0000_0001_000001_100000_000000_000010_00001100;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Shuffle(ShuffleInstruction {
                source_1: FullOperand::Register(Register(1)),
                source_2: RegisterOperand::Null,
                destination: RegisterOperand::Register(5),
                load_in_low: true,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    )
}

#[test]
fn test_mul_memory() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b1111_1111_0000_000000_100000_100000_000100_00000110;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Mul(MulInstruction {
                source_1: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0b1111,
                    register: RegisterOperand::Register(2),
                }),
                source_2: RegisterOperand::Register(5),
                destination_1: RegisterOperand::Register(5),
                destination_2: RegisterOperand::Null,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_sum() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b0000_0000_0000_000000_001000_000000_000000_00000010;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Add(AddInstruction {
                source_1: FullOperand::Immediate(0),
                source_2: RegisterOperand::Null,
                destination: RegisterOperand::Register(3),
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_mul_memory_operand() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b1111_1111_0000_000000_100000_100000_000100_00000110;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Mul(MulInstruction {
                source_1: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::Stack { force: true },
                    offset: 0b1111,
                    register: RegisterOperand::Register(2),
                }),
                source_2: RegisterOperand::Register(5),
                destination_1: RegisterOperand::Register(5),
                destination_2: RegisterOperand::Null,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_mul_memory_invalid_stack_flag() {
    //               0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u64 = 0b1111_1100_0000_000000_100000_100000_000100_00000110;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(assembly, Err(BinaryParseError::UnexpectedForceStackFlag));
}

#[test]
fn test_sub_memory() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b1101_0011_0001_000000_100000_100000_000100_00000100;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Sub(SubInstruction {
                source_1: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 0b1101,
                    register: RegisterOperand::Register(2),
                }),
                source_2: RegisterOperand::Register(5),
                destination: RegisterOperand::Register(5),
                swap_operands: true,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_div() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b0000_0000_0000_001000_000100_000010_000001_00001000;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);
    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Div(DivInstruction {
                source_1: FullOperand::Register(RegisterOperand::Register(0)),
                source_2: RegisterOperand::Register(1),
                quotient_destination: RegisterOperand::Register(2),
                remainder_destination: RegisterOperand::Register(3),
                swap_operands: false,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_memory_read() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b1001_0010_0001_000000_100000_000000_000100_00001110;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::Local,
                    offset: 0b1001,
                    register: RegisterOperand::Register(2),
                },
                operation: DataOperation::Read {
                    destination: RegisterOperand::Register(5)
                },
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_memory_write() {
    //                0b imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b1001_0100_0000_000000_000000_000010_000100_00001110;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Memory(MemoryInstruction {
                address: MemoryOperand {
                    r#type: MemoryType::SharedChild,
                    offset: 0b1001,
                    register: RegisterOperand::Register(2),
                },
                operation: DataOperation::Write {
                    source: RegisterOperand::Register(1)
                },
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_jump_all_flags() {
    //                0b                          immediate_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 =
        0b00000000_00010110_00000010_00000000_0000_1110_000000_000000_000000_000000_00001010;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);

    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Jump(JumpInstruction {
                // note that the immediate must be ignored here. For any other instruction, this would result in FullOperand::Immediate
                source: FullOperand::Register(RegisterOperand::Null),
                flags: vec![Flag::LesserThan, Flag::Equals, Flag::GreaterThan],
                destination_true: 0b00000010_00000000,
                destination_false: 0b00000000_00010110,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_jump_unconditional_memory() {
    //                0b                          immediate_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 =
        0b00000000_00010110_00000010_00000000_0001_0001_000000_000000_000000_001000_00001010;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Jump(JumpInstruction {
                source: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::SharedParent,
                    offset: 0, // note that the immediate must be ignored here
                    register: RegisterOperand::Register(3),
                }),
                flags: vec![Flag::Unconditional],
                destination_true: 0b00000010_00000000,
                destination_false: 0b00000000_00010110,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_jump_all_flags_memory() {
    //                0b                          immediate_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 =
        0b00000000_00010110_00000010_00000000_0001_1111_000000_000000_000000_001000_00001010;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);

    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Jump(JumpInstruction {
                source: FullOperand::Memory(MemoryOperand {
                    r#type: MemoryType::SharedParent,
                    offset: 0, // note that the immediate must be ignored here
                    register: RegisterOperand::Register(3),
                }),
                flags: vec![
                    Flag::Unconditional,
                    Flag::LesserThan,
                    Flag::Equals,
                    Flag::GreaterThan
                ],
                destination_true: 0b00000010_00000000,
                destination_false: 0b00000000_00010110,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_function_jump_return_error() {
    //                0b    imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000000_0000_0100_000000_000000_000000_000000_00000111;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::FunctionJump(FunctionJumpInstruction::Return {
                error: true,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_function_jump_return_no_error() {
    //                0b    imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000000_0000_0000_000000_000000_000000_000000_00000111;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::FunctionJump(FunctionJumpInstruction::Return {
                error: false
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_function_jump_local_call() {
    //               0b                  imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b11_00001001_00001001_0000_0011_000000_000000_000000_000001_00000111;
    // `11` prefix will be ignored, becuase only the low 16 bits are used in instruction
    let expected: u128 = 0b00001001_00001001_0000_0011_000000_000000_000000_000001_00000111;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::FunctionJump(FunctionJumpInstruction::Call {
                // note that the bits higher than 16 are ignored when computing the destination address
                location: Location::Local {
                    address: 0b00001001_00001001,
                    operand: FullOperand::Register(RegisterOperand::Register(0)),
                },
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );
    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(expected, converted_back);
}

#[test]
fn test_function_jump_local_call_immediate() {
    //               0b                  imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b11_00001001_00001001_0000_0011_000000_000000_000000_000000_00000111;
    // `11` prefix is not ignored here, because the immediate is used as first operand.
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: Location::Local {
                    // note that the bits higher than 16 are ignored when computing the destination address
                    address: 0b00001001_00001001,
                    // here no bits are ignored
                    operand: FullOperand::Immediate(0b11_00001001_00001001),
                },
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );
    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_function_jump_external_call() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_011_0111_0001_000000_000000_000000_000001_00000111;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::FunctionJump(FunctionJumpInstruction::Call {
                location: Location::External {
                    operand: FullOperand::Memory(MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 0b011,
                        register: RegisterOperand::Register(0),
                    }),
                    is_delegate: false
                },
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_storage_read() {
    //                0b_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_0000_0101_000000_001000_000000_000100_00000101;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Storage(StorageInstruction::Storage {
                storage_key: FullOperand::Register(RegisterOperand::Register(2)),
                operation: DataOperation::Read {
                    destination: RegisterOperand::Register(3)
                },
                is_external_storage_access: true,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_storage_write() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_011_0000_0000_000000_000000_000001_000000_00000101;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Storage(StorageInstruction::Storage {
                storage_key: FullOperand::Immediate(0b011),
                operation: DataOperation::Write {
                    source: RegisterOperand::Register(0)
                },
                is_external_storage_access: false,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_log_init() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_011_0000_1010_000000_000000_000010_000000_00000101;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Storage(StorageInstruction::LogInit {
                packed_lengths: FullOperand::Immediate(0b011),
                first_topic_or_chunk: RegisterOperand::Register(1),
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_log() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000_0000_0010_000000_000000_000000_001000_00000101;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Storage(StorageInstruction::Log(
                FullOperand::Register(RegisterOperand::Register(3)),
                RegisterOperand::Null,
            ))],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_hash_absorb() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_011_0000_0001_000000_000000_000000_000000_00000011;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::HashAbsorb(HashAbsorbInstruction {
                source: FullOperand::Immediate(0b011),
                reset: true,
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_hash_output() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000_0000_0000_000000_000000_000000_000000_00001001;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::HashOutput(HashOutputInstruction {
                destination: RegisterOperand::Null
            })],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_invalid_register_selectors() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000_0000_0000_011000_001000_000000_000000_00010100;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(assembly, Err(BinaryParseError::InvalidRegisterSelector));
}

#[test]
fn test_set_external_address() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_001_0111_0000_000000_000000_000000_000000_00010110;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::SetExternalAddress(
                SetExternalAddressInstruction {
                    source: FullOperand::Memory(MemoryOperand {
                        r#type: MemoryType::Stack { force: false },
                        offset: 1,
                        register: RegisterOperand::Null,
                    })
                }
            )],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_context() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_101_0000_0000_000000_000010_000000_000000_00010100;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Context(
                ContextInstruction {
                    destination: RegisterOperand::Register(1),
                    field: ContextField::CurrentAddress,
                }
            )],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_bitwise_or() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000_0000_0100_000000_000100_000010_000001_00011010;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Bitwise(
                BitwiseInstruction {
                    source_1: FullOperand::Register(RegisterOperand::Register(0)),
                    source_2: RegisterOperand::Register(1),
                    destination: RegisterOperand::Register(2),
                    op_type: BitwiseOpType::Or,
                }
            )],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}

#[test]
fn test_bitwise_shift() {
    //                0b_imm_memf_flag_outrg2_outrg1_inreg2_inreg1_opcode
    let input: u128 = 0b_000_0000_0010_000000_000100_000010_000001_00011000;
    let mut bytecode = input.to_le_bytes().to_vec();
    bytecode.resize(32, 0);

    let assembly = Assembly::try_from(&bytecode);
    assert_eq!(
        assembly,
        Ok(Assembly {
            instructions: vec![Instruction::Shift(
                ShiftInstruction {
                    source_1: FullOperand::Register(RegisterOperand::Register(0)),
                    source_2: RegisterOperand::Register(1),
                    destination: RegisterOperand::Register(2),
                    is_cyclic: false,
                    is_right: true,
                }
            )],
            labels: HashMap::new(),
            assembly_code: String::new(),
            pc_line_mapping: HashMap::new(),
        })
    );

    let instruction = assembly.unwrap().instructions.pop().unwrap();
    let converted_back =
        u128::from_le_bytes(Vec::<u8>::from(instruction)[0..16].try_into().unwrap());
    assert_eq!(input, converted_back);
}
