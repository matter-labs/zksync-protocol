//!
//! The zkEVM register.
//!
//!
use nom::{
    self,
    bytes::complete::{tag, take_until, take_while1, take_while_m_n},
    multi::many_m_n,
    AsChar,
};

use nom::error::{Error, ErrorKind};

use std::{convert::TryFrom, num::ParseIntError};

use crate::error::InstructionReadError;

use zkevm_opcode_defs::{ImmMemHandlerFlags, RegOrImmFlags};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FullOperand {
    /// Full including all memory modifiers
    Full(GenericOperand),
    /// Use value at register
    Register(RegisterOperand),
    /// Constant and potentially offset
    Constant(ConstantOperand),
    /// Global variable on the stack
    GlobalVariable(GlobalVariable),
}

///
/// Structure representing address of the constant.
///
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConstantOperand {
    /// Label of the constant
    pub label: String,
    /// Register to use it offset computation
    pub register: RegisterOperand,
    /// Offset to the constant label
    pub immediate: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalVariable {
    /// Label of the constant
    pub label: String,
    /// Register to use it offset computation
    pub register: RegisterOperand,
    /// Offset to the constant label
    pub immediate: u64,
}

///
/// Structure representing address in memory.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenericOperand {
    pub r#type: ImmMemHandlerFlags,
    /// Offset to apply to sp for Stack memory and memory address for other types of memory
    pub immediate: u64,
    /// Additional offset to apply
    pub register: RegisterOperand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterOperand {
    /// The special null/void register.
    Null,
    /// The general purpose register. 1-based.
    Register(u8),
}

///
/// Structure representing non-memory operand
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonMemoryOperand {
    pub r#type: RegOrImmFlags,
    /// Offset to apply to sp for Stack memory and memory address for other types of memory
    pub immediate: u64,
    /// Additional offset to apply
    pub register: RegisterOperand,
}

impl NonMemoryOperand {
    pub fn as_register_operand(
        self,
        index: usize,
    ) -> Result<RegisterOperand, InstructionReadError> {
        match self.r#type {
            RegOrImmFlags::UseRegOnly => Ok(self.register),
            RegOrImmFlags::UseImm16Only => {
                Err(InstructionReadError::InvalidRegImmInPlaceOfReg { index, found: self })
            }
        }
    }
}

fn is_imm(input: &str) -> (&str, bool) {
    let t = tag("#")(input);
    match t {
        Ok((input, _)) => (input, true),
        Err(nom::Err::Error(Error {
            input,
            code: ErrorKind::Tag,
        })) => (input, false),
        _ => {
            unreachable!()
        }
    }
}

fn is_register(input: &str) -> (&str, bool, &str) {
    let mut reg_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        tag("r"),
        take_while_m_n(1, 2, |el: char| el.is_ascii_digit()),
    ));

    match reg_parser(input) {
        Ok((rest, result)) => {
            let reg_raw = result.2;

            (rest, true, reg_raw)
        }
        _ => (input, false, ""),
    }
}

fn is_label(input: &str) -> (&str, bool, &str) {
    let label_name_parser =
        take_while1(|c: char| c.is_alphanum() || (c.is_ascii() && (c as u8) == b"_"[0]));
    let mut label_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        tag("."),
        label_name_parser,
    ));

    let label_name_parser =
        take_while1(|c: char| c.is_alphanum() || (c.is_ascii() && (c as u8) == b"_"[0]));
    let mut pseudo_label_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        tag("."),
        label_name_parser,
        nom::sequence::pair(tag("["), take_until("]")),
    ));

    // we need to parse .label, but not .label[] that will be handled by other cases

    match pseudo_label_parser(input) {
        Ok(_) => (input, false, ""),
        _ => match label_parser(input) {
            Ok((rest, result)) => {
                let label_raw = result.2;

                (rest, true, label_raw)
            }
            _ => (input, false, ""),
        },
    }
}

fn has_tag<'a>(input: &'a str, tag: &str) -> (bool, &'a str) {
    match nom::bytes::complete::tag::<_, _, nom::error::Error<_>>(tag)(input) {
        Ok((rest, _)) => (true, rest),
        Err(nom::Err::Error(Error {
            input,
            code: ErrorKind::Tag,
        })) => (false, input),
        _ => {
            unreachable!()
        }
    }
}

fn try_memory_offset<'a>(
    input: &'a str,
) -> Result<(&'a str, Vec<&'a str>, Vec<&'a str>, Vec<&'a str>), ()> {
    let reg_parser = nom::sequence::tuple::<_, _, nom::error::Error<_>, _>((
        nom::character::complete::space0,
        tag("r"),
        take_while_m_n(1, 2, |el: char| el.is_ascii_digit()),
    ));

    let sign_parser = nom::sequence::tuple((
        nom::character::complete::space0,
        many_m_n(0, 1, nom::branch::alt((tag("+"), tag("-")))),
        nom::character::complete::space0,
    ));

    let mut parser = nom::sequence::tuple((
        many_m_n(0, 1, reg_parser),
        nom::character::complete::space0,
        sign_parser,
    ));

    match parser(input) {
        Ok((rest, result)) => {
            let (reg_parsing, _, sign_parsing) = result;
            let reg_may_be: Vec<_> = reg_parsing.into_iter().map(|el| el.2).collect();
            let sign_may_be = sign_parsing.1;

            if rest.is_empty() {
                return Ok((rest, reg_may_be, sign_may_be, vec![]));
            }

            // otherwise try to parse imm
            match many_m_n::<_, _, nom::error::Error<_>, _>(
                0,
                1,
                nom::character::complete::alphanumeric0,
            )(rest)
            {
                Ok((rest, result)) => Ok((rest, reg_may_be, sign_may_be, result)),
                Err(nom::Err::Error(Error { input, code })) => {
                    dbg!(input);
                    dbg!(code);
                    Err(())
                }
                _ => Err(()),
            }
        }
        _ => Err(()),
    }
}

fn try_immediate<'a>(input: &'a str) -> Result<(&'a str, u64), ParseIntError> {
    let (has_prefix, input) = has_tag(input, "0x");
    if has_prefix {
        match u64::from_str_radix(input, 16) {
            Ok(imm) => Ok(("", imm)),
            Err(e) => Err(e),
        }
    } else {
        let (has_prefix, input) = has_tag(input, "0b");
        if has_prefix {
            match u64::from_str_radix(input, 2) {
                Ok(imm) => Ok(("", imm)),
                Err(e) => Err(e),
            }
        } else {
            match u64::from_str_radix(input, 10) {
                Ok(imm) => Ok(("", imm)),
                Err(e) => Err(e),
            }
        }
    }
}

impl FullOperand {
    pub fn as_register_operand(
        self,
        index: usize,
    ) -> Result<RegisterOperand, InstructionReadError> {
        match self {
            FullOperand::Register(reg) => Ok(reg),
            other => Err(InstructionReadError::InvalidOperandForRegLocation {
                index,
                found: other,
            }),
        }
    }

    pub fn as_non_memory_operand(
        self,
        index: usize,
    ) -> Result<NonMemoryOperand, InstructionReadError> {
        match self {
            FullOperand::Full(operand) => Ok(operand.as_non_memory_operand()),
            other => Err(InstructionReadError::InvalidOperandForRegImmLocation {
                index,
                found: other,
            }),
        }
    }

    pub fn as_generic_operand(self, index: usize) -> Result<GenericOperand, InstructionReadError> {
        match self {
            FullOperand::Full(operand) => Ok(operand),
            other => Err(InstructionReadError::InvalidOperandForGenericLocation {
                index,
                found: other,
            }),
        }
    }

    pub fn as_constant_operand(
        self,
        index: usize,
    ) -> Result<ConstantOperand, InstructionReadError> {
        match self {
            FullOperand::Constant(operand) => Ok(operand),
            other => Err(InstructionReadError::InvalidOperandForLabelLocation {
                index,
                found: other,
            }),
        }
    }

    pub fn as_global_variable(self, index: usize) -> Result<GlobalVariable, InstructionReadError> {
        match self {
            FullOperand::GlobalVariable(operand) => Ok(operand),
            other => Err(InstructionReadError::InvalidOperandForLabelLocation {
                index,
                found: other,
            }),
        }
    }

    pub fn as_immediate(self, index: usize) -> Result<u64, InstructionReadError> {
        match self {
            FullOperand::Full(GenericOperand {
                r#type: ImmMemHandlerFlags::UseImm16Only,
                immediate: imm,
                register: RegisterOperand::Null,
            }) => Ok(imm),
            other => Err(InstructionReadError::InvalidArgument {
                index,
                expected: "label or immediate",
                found: format!("{:?}", other),
            }),
        }
    }
}

impl GenericOperand {
    pub fn as_word_offset_into_code_page(self) -> u64 {
        let GenericOperand {
            r#type,
            immediate,
            register,
        } = self;
        match register {
            RegisterOperand::Null => {}
            _ => {
                panic!("Invalid linking result")
            }
        }
        match r#type {
            ImmMemHandlerFlags::UseCodePage => immediate,
            _ => {
                panic!("Invalid linking result")
            }
        }
    }

    pub fn as_pc_offset(self) -> u64 {
        let GenericOperand {
            r#type,
            immediate,
            register,
        } = self;
        match register {
            RegisterOperand::Null => {}
            _ => {
                panic!("Invalid linking result")
            }
        }
        match r#type {
            ImmMemHandlerFlags::UseImm16Only => immediate,
            _ => {
                panic!("Invalid linking result")
            }
        }
    }

    pub fn as_non_memory_operand(self) -> NonMemoryOperand {
        match self.r#type {
            ImmMemHandlerFlags::UseRegOnly => {
                assert!(self.immediate == 0);
                NonMemoryOperand {
                    register: self.register,
                    r#type: RegOrImmFlags::UseRegOnly,
                    immediate: 0,
                }
            }
            ImmMemHandlerFlags::UseImm16Only => {
                match self.register {
                    RegisterOperand::Null => {}
                    _ => {
                        panic!("Register must be zero")
                    }
                }
                NonMemoryOperand {
                    register: self.register,
                    r#type: RegOrImmFlags::UseImm16Only,
                    immediate: self.immediate,
                }
            }
            _ => {
                panic!("Invalid reg/imm operand")
            }
        }
    }
}

impl RegisterOperand {
    ///
    /// Whether the register is the null (`r0`) one.
    ///
    pub fn is_void(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl TryFrom<&str> for RegisterOperand {
    type Error = InstructionReadError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        let index: u8 = input
            .parse()
            .map_err(|e| InstructionReadError::InvalidNumber(input.to_owned(), e))?;
        if index == 0 {
            return Ok(Self::Null);
        }
        if index as usize > zkevm_opcode_defs::REGISTERS_COUNT {
            return Err(InstructionReadError::UnknownRegister(input.to_owned()));
        }

        Ok(Self::Register(index))
    }
}
