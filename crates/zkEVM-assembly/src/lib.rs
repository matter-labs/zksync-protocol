//!
//! The zkEVM common library.
//!

#![allow(dead_code)]

#[cfg(test)]
#[rustfmt::skip]
mod tests;

pub(crate) mod assembly;
pub(crate) mod error;

pub use zkevm_opcode_defs;
pub use zkevm_opcode_defs::ISAVersion;

pub use self::assembly::instruction::add::Add as AddInstruction;
pub use self::assembly::instruction::bitwise::Bitwise as BitwiseInstruction;
pub use self::assembly::instruction::context::Context as ContextInstruction;
pub use self::assembly::instruction::div::Div as DivInstruction;
pub use self::assembly::instruction::far_call::FarCall as ExternalCallInstruction;
pub use self::assembly::instruction::jump::Jump as JumpInstruction;
pub use self::assembly::instruction::mul::Mul as MulInstruction;
pub use self::assembly::instruction::near_call::NearCall as LocalCallInstruction;
pub use self::assembly::instruction::nop::Nop as NopInstruction;
pub use self::assembly::instruction::ret::Ret as ReturnInstruction;
pub use self::assembly::instruction::shift::Shift as ShiftInstruction;
pub use self::assembly::instruction::sub::Sub as SubInstruction;

pub use self::assembly::instruction::Instruction;
pub use self::assembly::operand::FullOperand;
pub use self::assembly::operand::RegisterOperand;
pub use self::assembly::Assembly;
pub use self::error::{AssemblyParseError, BinaryParseError, InstructionReadError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum RunningVmEncodingMode {
    Production = 0,
    Testing = 1,
}

impl RunningVmEncodingMode {
    pub const fn from_u64(value: u64) -> Self {
        match value {
            x if x == Self::Production as u64 => Self::Production,
            x if x == Self::Testing as u64 => Self::Testing,
            _ => unreachable!(),
        }
    }

    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

use std::sync::atomic::AtomicU64;

pub static ENCODING_MODE: AtomicU64 = AtomicU64::new(RunningVmEncodingMode::Production as u64);

pub fn set_encoding_mode(value: RunningVmEncodingMode) {
    ENCODING_MODE.store(value.as_u64(), std::sync::atomic::Ordering::SeqCst);
}

pub fn get_encoding_mode() -> RunningVmEncodingMode {
    RunningVmEncodingMode::from_u64(ENCODING_MODE.load(std::sync::atomic::Ordering::Relaxed))
}

pub const DEFAULT_ISA_VERSION: ISAVersion = ISAVersion(2);

const _: () = if DEFAULT_ISA_VERSION.0 != zkevm_opcode_defs::DEFAULT_ISA_VERSION.0 {
    panic!()
} else {
};

pub static ISA_VERSION_U64: AtomicU64 = AtomicU64::new(DEFAULT_ISA_VERSION.0 as u64);

pub fn set_isa_version(value: ISAVersion) {
    ISA_VERSION_U64.store(value.0 as u64, std::sync::atomic::Ordering::SeqCst);
}

pub fn get_isa_version() -> ISAVersion {
    ISAVersion(ISA_VERSION_U64.load(std::sync::atomic::Ordering::Relaxed) as u8)
}
