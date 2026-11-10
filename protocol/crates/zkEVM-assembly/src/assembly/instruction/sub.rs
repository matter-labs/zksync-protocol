//!
//! The arithmetic subtraction instruction.
//!

// use crate::assembly::instruction::bytecode::InstructionBytecode;
use super::*;
use crate::assembly::operand::{FullOperand, RegisterOperand};
use crate::error::InstructionReadError;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

///
/// The arithmetic subtraction instruction.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sub {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Whether we set flags or not
    pub set_flags_option: SetFlags,
    /// The first operand.
    pub source_1: FullOperand,
    /// The second operand.
    pub source_2: RegisterOperand,
    /// The destination register.
    pub destination: FullOperand,
    /// if it is set then source operands have to be swapped.
    pub swap_operands: bool,
}

impl Sub {
    // Total number of arguments in canonical form
    pub const NUM_ARGUMENTS: usize = 3;

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = if let Ok(operands) = parse_canonical_operands_sequence(
            operands.clone(),
            &[marker_full_operand(), marker_register_operand()],
            &[marker_full_operand()],
        ) {
            operands
        } else {
            // try loading label
            parse_canonical_operands_sequence(
                operands,
                &[OperandType::Label, marker_register_operand()],
                &[marker_full_operand()],
            )?
        };

        let src0 = operands[0].clone();
        let src1 = operands[1].clone();
        let dst0 = operands[2].clone();

        let condition = pick_condition(&mut modifiers)?;
        let set_flags_option = pick_setting_flags(&mut modifiers)?;

        let mut swap_operands = false;
        if modifiers.remove("s") {
            swap_operands = true;
        }

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Sub instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self {
            condition,
            set_flags_option,
            source_1: src0,
            source_2: src1.as_register_operand(1)?,
            destination: dst0,
            swap_operands,
        };

        Ok(new)
    }

    #[track_caller]
    pub(crate) fn link<const N: usize, E: VmEncodingMode<N>>(
        &mut self,
        function_labels_to_pc: &HashMap<String, usize>,
        constant_labels_to_offset: &HashMap<String, usize>,
        globals_to_offsets: &HashMap<String, usize>,
    ) -> Result<(), AssemblyParseError> {
        link_operand::<N, E>(
            &mut self.source_1,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        link_operand::<N, E>(
            &mut self.destination,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Sub> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Sub) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Sub(SubOpcode::Sub),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_full_operand(&value.source_1.as_generic_operand(0)?, &mut new, false);
        set_register_operand(&value.source_2, &mut new, false);
        set_src0_or_dst0_full_operand(&value.destination.as_generic_operand(2)?, &mut new, true);
        new.condition = value.condition.0;
        new.variant.flags[SET_FLAGS_FLAG_IDX] = value.set_flags_option.0;
        new.variant.flags[SWAP_OPERANDS_FLAG_IDX_FOR_ARITH_OPCODES] = value.swap_operands;

        Ok(new)
    }
}
