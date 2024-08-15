//!
//! The common error.
//!

use crate::assembly::operand::{FullOperand, NonMemoryOperand};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// The file opening error.
    #[error("file opening: {0}")]
    FileOpening(std::io::Error),
    /// The file metadata error.
    #[error("file metadata: {0}")]
    FileMetadata(std::io::Error),
    /// The file reading error.
    #[error("file reading: {0}")]
    FileReading(std::io::Error),
    #[error(transparent)]
    AssemblyParseError(#[from] AssemblyParseError),
}

#[derive(Debug, Error, PartialEq)]
pub enum AssemblyParseError {
    #[error("assembly code cannot be empty")]
    EmptyCode,
    #[error("assembly code cannot be larger than {0} instructions")]
    CodeTooLarge(usize),
    #[error("can not parse data section element: {0}")]
    DataSectionInvalid(SectionReadError),
    #[error("can not parse globals section element: {0}")]
    GlobalsSectionInvalid(SectionReadError),
    #[error("can not parse text section element: {0}")]
    TextSectionInvalid(SectionReadError),
    #[error("there is a duplicate label in a code: {0}")]
    DuplicateLabel(String),
    #[error("there is no label `{0}` in data section of functions")]
    LabelNotFound(String),
    #[error("failed to resolve relocation for label `{0}` in data section")]
    RelocationError(String),
    #[error("Label {1} was tried to be used for either PC or constant at offset {0} that is more than `{2}` addressable space")]
    CodeIsTooLong(usize, String, u64),
}

#[derive(Debug, Error, PartialEq)]
pub enum SectionReadError {
    #[error("cannot parse lines: {0:?}")]
    LineReadError(HashMap<usize, (String, InstructionReadError)>),
}

#[derive(Debug, Error, PartialEq)]
pub enum InstructionReadError {
    /// Failed to parse text assembly
    #[error("assembly parse error {0}")]
    AssemblyParseError(AssemblyParseError),
    /// The unknown register error.
    #[error("unknown register `{0}`")]
    UnknownRegister(String),
    /// The invalid number error.
    #[error("invalid number `{0}`: {1}")]
    InvalidNumber(String, std::num::ParseIntError),
    /// The invalid big number error.
    #[error("invalid big number `{0}`: {1}")]
    InvalidBigNumber(String, num_bigint::ParseBigIntError),
    /// The invalid instruction argument.
    #[error("failed to parse labeled constant value `{0}`")]
    InvalidLabeledConstant(String),
    /// The invalid instruction argument.
    #[error(
        "invalid argument {0}: expected `{1}`, found `{2}`",
        index,
        expected,
        found
    )]
    InvalidArgument {
        /// The argument position, starts from `0`.
        index: usize,
        /// The expected argument description.
        expected: &'static str,
        /// The invalid argument representation.
        found: String,
    },
    #[error("failed to parse generic operand location: received `{0}`")]
    InvalidGenericOperand(String),
    #[error("failed to parse absolute-like `reg + imm` location: received `{0}`")]
    InvalidAbsoluteLikeAddress(String),
    #[error("failed to parse labeled constant operand location: received `{0}`")]
    InvalidLabeledConstantOperand(String),
    /// The invalid instruction argument.
    #[error("found immediate `{0}` for location where register only is expected")]
    InvalidOperandImmInRegLocation(String),
    #[error(
        "invalid operand for location that should be generic: on position `{index}`: {found:?}"
    )]
    InvalidOperandForGenericLocation { index: usize, found: FullOperand },
    /// The invalid instruction argument.
    #[error("invalid operand for location that is reg-only: on position `{index}`: {found:?}")]
    InvalidOperandForRegLocation { index: usize, found: FullOperand },
    #[error("invalid operand for location that is reg-only or imm-only: on position `{index}`: {found:?}")]
    InvalidOperandForRegImmLocation { index: usize, found: FullOperand },
    #[error("invalid operand for location that is reg-only in this version: on position `{index}`: {found:?}")]
    InvalidRegImmInPlaceOfReg {
        index: usize,
        found: NonMemoryOperand,
    },
    /// The invalid instruction argument.
    #[error("invalid operand for location that is label-only: on position `{index}`: {found:?}")]
    InvalidOperandForLabelLocation { index: usize, found: FullOperand },
    /// The invalid number of arguments.
    #[error(
        "invalid number of arguments: expected `{0}`, found `{1}`",
        expected,
        found
    )]
    InvalidArgumentCount {
        /// The expected number of arguments.
        expected: usize,
        /// The invalid actual number of arguments.
        found: usize,
    },
    /// The unknown argument error.
    #[error("unknown argument `{0}`")]
    UnknownArgument(String),
    #[error(
        "subtraction and negative literals are only supported in memory offsets, not in immediates"
    )]
    UnexpectedSubtraction,
    #[error("integer overflow when computing the immediate")]
    IntegerOverflow,
    #[error("unknown symbol or label `{0}`")]
    UnknownLabel(String),
    #[error("unknown mnemonic `{0}`")]
    UnknownMnemonic(String),
    #[error("unexpected constant-like line {0:?} not in section")]
    UnexpectedConstant(String),
    #[error("unexpected line {0:?} in Text section")]
    UnexpectedInstruction(String),
    #[error("duplicate modifier `{0}` in the instruction")]
    DuplicateModifier(String),
    #[error("code is too long, can address {0} opcodes at maximum, encountered {1}")]
    TooManyOpcodes(u64, u64),
    #[error("code is too long, can address {0} words at maximum, encountered {1}")]
    CodeIsTooLong(u64, u64),
    // #[error("opcode has specific requirements for source and destination for it's variant `{0}`")]
    // UnknownSourceOrDestination(String),
}

#[derive(Debug, Error, PartialEq)]
pub enum BinaryParseError {
    #[error("use_mem flag must be reset in Memory instruction")]
    MemoryOpcodeInvalidFlag,
    #[error("force stack flag can only be set for Stack memory type")]
    UnexpectedForceStackFlag,
    #[error("invalid register selector. At most one register can be selected per position.")]
    InvalidRegisterSelector,
    #[error("bytecode cannot be empty")]
    EmptyBytecode,
    #[error("bytecode length in bytes must be a multiple of {0}")]
    InvalidBytecodeLength(usize),
    #[error("bytecode length in bytes must be less than {0}")]
    BytecodeTooLong(usize),
    #[error("invalid opcode")]
    InvalidOpcode,
    #[error("Supported context fields indices: 0-5")]
    UnknownContextField,
}
