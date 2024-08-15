//!
//! The instruction.
//!

use crate::{assembly::operand::*, AssemblyParseError};
// use crate::assembly::*;
use crate::assembly::parse::code_element::*;
use crate::error::InstructionReadError;
use zkevm_opcode_defs::decoding::VmEncodingMode;
use zkevm_opcode_defs::*;

use self::add::Add;
use self::bitwise::Bitwise;
use self::condition::ConditionCase;
use self::context::Context;
use self::div::Div;
use self::far_call::FarCall;
use self::invalid::Invalid;
use self::jump::Jump;
use self::log::Log;
use self::mul::Mul;
use self::near_call::NearCall;
use self::nop::Nop;
use self::ptr::Ptr;
use self::ret::Ret;
use self::set_flags::SetFlags;
use self::shift::Shift;
use self::sub::Sub;
use self::uma::UMA;

use self::utils::*;

use std::collections::{HashMap, HashSet};
use zkevm_opcode_defs::decoding::AllowedPcOrImm;

pub mod add;
pub mod bitwise;
pub mod condition;
pub mod context;
pub mod div;
pub mod far_call;
pub mod invalid;
pub mod jump;
pub mod log;
pub mod mul;
pub mod near_call;
pub mod nop;
pub mod ptr;
pub mod ret;
pub mod set_flags;
pub mod shift;
pub mod sub;
pub mod uma;
pub mod utils;

pub(crate) const ALL_CANONICAL_OPCODES: [&str; 16] = [
    "invalid",
    "nop",
    "add",
    "sub",
    "mul",
    "div",
    "jump",
    "ctx",
    "shift",
    "binop",
    "ptr",
    "log",
    "near_call",
    "far_call",
    "ret",
    "uma",
];

///
/// The instruction.
///
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    /// The `invalid` instruction.
    Invalid(Invalid),
    /// The `noop` instruction.
    Nop(Nop),
    /// The arithmetic addition instruction.
    Add(Add),
    /// The arithmetic subtraction instruction.
    Sub(Sub),
    /// The arithmetic multiplication instruction.
    Mul(Mul),
    /// The arithmetic division or remainder instruction.
    Div(Div),
    /// The jump control flow instruction.
    Jump(Jump),
    /// Read value from execution context.
    Context(Context),
    /// Bitwise shift operation (shl, shr, rol, ror).
    Shift(Shift),
    /// Bitwise operation: AND, OR or XOR.
    Bitwise(Bitwise),
    /// Pointer arithmetics
    Ptr(Ptr),
    /// Log opcode for all external accesses
    Log(Log),
    /// Call to the same code page
    NearCall(NearCall),
    /// Call to another contract
    FarCall(FarCall),
    /// Return
    Ret(Ret),
    /// Unaligned memory access
    UMA(UMA),
}

impl Instruction {
    #[track_caller]
    pub fn try_from_parts(
        opcode: &str,
        modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        match opcode {
            "invalid" => Ok(Instruction::Invalid(Invalid::build_from_parts(
                modifiers, operands,
            )?)),
            "nop" => Ok(Instruction::Nop(Nop::build_from_parts(
                modifiers, operands,
            )?)),
            "add" => Ok(Instruction::Add(Add::build_from_parts(
                modifiers, operands,
            )?)),
            "sub" => Ok(Instruction::Sub(Sub::build_from_parts(
                modifiers, operands,
            )?)),
            "mul" => Ok(Instruction::Mul(Mul::build_from_parts(
                modifiers, operands,
            )?)),
            "div" => Ok(Instruction::Div(Div::build_from_parts(
                modifiers, operands,
            )?)),
            "jump" => Ok(Instruction::Jump(Jump::build_from_parts(
                modifiers, operands,
            )?)),
            "context" => Ok(Instruction::Context(Context::build_from_parts(
                modifiers, operands,
            )?)),
            "shift" => Ok(Instruction::Shift(Shift::build_from_parts(
                modifiers, operands,
            )?)),
            "binop" => Ok(Instruction::Bitwise(Bitwise::build_from_parts(
                modifiers, operands,
            )?)),
            "ptr" => Ok(Instruction::Ptr(Ptr::build_from_parts(
                modifiers, operands,
            )?)),
            "log" => Ok(Instruction::Log(Log::build_from_parts(
                modifiers, operands,
            )?)),
            "near_call" => Ok(Instruction::NearCall(NearCall::build_from_parts(
                modifiers, operands,
            )?)),
            "far_call" => Ok(Instruction::FarCall(FarCall::build_from_parts(
                modifiers, operands,
            )?)),
            "ret" => Ok(Instruction::Ret(Ret::build_from_parts(
                modifiers, operands,
            )?)),
            "uma" => Ok(Instruction::UMA(UMA::build_from_parts(
                modifiers, operands,
            )?)),
            _ => Err(InstructionReadError::UnexpectedInstruction(
                opcode.to_owned(),
            )),
        }
    }

    pub(crate) fn link<const N: usize, E: VmEncodingMode<N>>(
        &mut self,
        function_labels_to_pc: &HashMap<String, usize>,
        constant_labels_to_offset: &HashMap<String, usize>,
        globals_to_offsets: &HashMap<String, usize>,
    ) -> Result<(), AssemblyParseError> {
        match self {
            Instruction::Invalid(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Nop(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Add(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Sub(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Mul(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Div(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Jump(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Context(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Shift(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Bitwise(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Ptr(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Log(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::NearCall(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::FarCall(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::Ret(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
            Instruction::UMA(instr) => instr.link::<N, E>(
                function_labels_to_pc,
                constant_labels_to_offset,
                globals_to_offsets,
            ),
        }
    }
}

pub(crate) fn link_operand<const N: usize, E: VmEncodingMode<N>>(
    operand: &mut FullOperand,
    function_labels_to_pc: &HashMap<String, usize>,
    constant_labels_to_offset: &HashMap<String, usize>,
    globals_to_offsets: &HashMap<String, usize>,
) -> Result<(), AssemblyParseError> {
    match operand.clone() {
        FullOperand::Constant(ConstantOperand {
            label,
            register,
            immediate,
        }) => {
            if let Some(pc) = function_labels_to_pc.get(&*label).copied() {
                assert_eq!(
                    immediate, 0,
                    "jumps can not have immediates in labels addressing"
                );
                assert!(
                    register.is_void(),
                    "jumps can not have registers in labels addressing"
                );
                if pc > (E::PcOrImm::max()).as_u64() as usize {
                    return Err(AssemblyParseError::CodeIsTooLong(
                        pc,
                        label,
                        (E::PcOrImm::max()).as_u64(),
                    ));
                }
                // assert!(pc <= Offset::MAX as usize, "pc overflow in linker");
                *operand = FullOperand::Full(GenericOperand {
                    r#type: ImmMemHandlerFlags::UseImm16Only,
                    register: RegisterOperand::Null,
                    immediate: pc as u64,
                });
            } else if let Some(offset) = constant_labels_to_offset.get(&*label).copied() {
                if offset > (E::PcOrImm::max()).as_u64() as usize {
                    return Err(AssemblyParseError::CodeIsTooLong(
                        offset,
                        label,
                        (E::PcOrImm::max()).as_u64(),
                    ));
                }
                // assert!(offset <= Offset::MAX as usize, "offset overflow in linker");
                let imm = E::PcOrImm::from_u64_clipped(immediate)
                    .wrapping_add(E::PcOrImm::from_u64_clipped(offset as u64))
                    .as_u64();

                *operand = FullOperand::Full(GenericOperand {
                    r#type: ImmMemHandlerFlags::UseCodePage,
                    register,
                    immediate: imm,
                });
            } else {
                return Err(AssemblyParseError::LabelNotFound(label.to_owned()));
            }
        }
        FullOperand::GlobalVariable(GlobalVariable {
            label,
            register,
            immediate,
        }) => {
            if let Some(offset) = globals_to_offsets.get(&*label).copied() {
                if offset > (E::PcOrImm::max()).as_u64() as usize {
                    return Err(AssemblyParseError::CodeIsTooLong(
                        offset,
                        label,
                        (E::PcOrImm::max()).as_u64(),
                    ));
                }
                // assert!(offset <= Offset::MAX as usize, "offset overflow in linker");
                let imm = E::PcOrImm::from_u64_clipped(immediate)
                    .wrapping_add(E::PcOrImm::from_u64_clipped(offset as u64))
                    .as_u64();

                *operand = FullOperand::Full(GenericOperand {
                    r#type: ImmMemHandlerFlags::UseAbsoluteOnStack,
                    register,
                    immediate: imm,
                });
            } else {
                return Err(AssemblyParseError::LabelNotFound(label.to_owned()));
            }
        }
        _ => {}
    }

    Ok(())
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Instruction> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Instruction) -> Result<Self, Self::Error> {
        match value {
            Instruction::Invalid(instr) => DecodedOpcode::try_from(instr),
            Instruction::Nop(instr) => DecodedOpcode::try_from(instr),
            Instruction::Add(instr) => DecodedOpcode::try_from(instr),
            Instruction::Sub(instr) => DecodedOpcode::try_from(instr),
            Instruction::Mul(instr) => DecodedOpcode::try_from(instr),
            Instruction::Div(instr) => DecodedOpcode::try_from(instr),
            Instruction::Jump(instr) => DecodedOpcode::try_from(instr),
            Instruction::Context(instr) => DecodedOpcode::try_from(instr),
            Instruction::Shift(instr) => DecodedOpcode::try_from(instr),
            Instruction::Bitwise(instr) => DecodedOpcode::try_from(instr),
            Instruction::Ptr(instr) => DecodedOpcode::try_from(instr),
            Instruction::Log(instr) => DecodedOpcode::try_from(instr),
            Instruction::NearCall(instr) => DecodedOpcode::try_from(instr),
            Instruction::FarCall(instr) => DecodedOpcode::try_from(instr),
            Instruction::Ret(instr) => DecodedOpcode::try_from(instr),
            Instruction::UMA(instr) => DecodedOpcode::try_from(instr),
        }
    }
}

pub fn set_src0_or_dst0_full_operand<const N: usize, E: VmEncodingMode<N>>(
    operand: &GenericOperand,
    into: &mut DecodedOpcode<N, E>,
    is_dst: bool,
) {
    let GenericOperand {
        r#type: imm_mem,
        immediate,
        register,
    } = operand;
    let idx = match register {
        &RegisterOperand::Null => 0,
        &RegisterOperand::Register(idx) => idx,
    };
    if is_dst {
        into.dst0_reg_idx = idx;
        into.variant.dst0_operand_type = Operand::Full(*imm_mem);
        into.imm_1 = E::PcOrImm::from_u64_clipped(*immediate);
    } else {
        into.src0_reg_idx = idx;
        into.variant.src0_operand_type = Operand::Full(*imm_mem);
        into.imm_0 = E::PcOrImm::from_u64_clipped(*immediate);
    }
}

pub fn set_src0_or_dst0_register_operand<const N: usize, E: VmEncodingMode<N>>(
    operand: &RegisterOperand,
    into: &mut DecodedOpcode<N, E>,
    is_dst: bool,
) {
    let idx = match operand {
        &RegisterOperand::Null => 0,
        &RegisterOperand::Register(idx) => idx,
    };
    if is_dst {
        into.dst0_reg_idx = idx;
        into.variant.dst0_operand_type = Operand::RegOnly;
        into.imm_1 = E::PcOrImm::from_u64_clipped(0);
    } else {
        into.src0_reg_idx = idx;
        into.variant.src0_operand_type = Operand::RegOnly;
        into.imm_0 = E::PcOrImm::from_u64_clipped(0);
    }
}

pub fn set_src_non_memory_operand<const N: usize, E: VmEncodingMode<N>>(
    operand: &NonMemoryOperand,
    into: &mut DecodedOpcode<N, E>,
) {
    let idx = match &operand.register {
        &RegisterOperand::Null => 0,
        &RegisterOperand::Register(idx) => idx,
    };

    match operand.r#type {
        RegOrImmFlags::UseRegOnly => {
            into.src0_reg_idx = idx;
            into.variant.src0_operand_type = Operand::RegOrImm(RegOrImmFlags::UseRegOnly);
            into.imm_0 = E::PcOrImm::from_u64_clipped(0);
        }
        RegOrImmFlags::UseImm16Only => {
            assert!(idx == 0);
            into.src0_reg_idx = 0;
            into.variant.src0_operand_type = Operand::RegOrImm(RegOrImmFlags::UseImm16Only);
            into.imm_0 = E::PcOrImm::from_u64_clipped(operand.immediate);
        }
    }
}

pub fn set_register_operand<const N: usize, E: VmEncodingMode<N>>(
    operand: &RegisterOperand,
    into: &mut DecodedOpcode<N, E>,
    is_dst: bool,
) {
    let idx = match operand {
        &RegisterOperand::Null => 0,
        &RegisterOperand::Register(idx) => idx,
    };
    if is_dst {
        into.dst1_reg_idx = idx;
    } else {
        into.src1_reg_idx = idx;
    }
}
