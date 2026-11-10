//!
//! The control flow jump instruction.
//!

use super::*;

use crate::error::InstructionReadError;

use std::convert::TryFrom;

///
/// The control flow jump instruction.
///
#[derive(Debug, Clone, PartialEq)]
pub struct Jump {
    /// Condition for execution
    pub condition: ConditionCase,
    /// The `true` condition destination bytecode address.
    /// We use full operand here, so we can properly link later on
    pub destination_true: FullOperand,
}

impl Jump {
    // Total number of arguments in canonical form
    pub const NUM_ARGUMENTS: usize = 1;

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        // for convenience we accept both
        // "jump @LABEL"
        // and
        // "jump rX"
        let operands = if let Ok(operands) =
            parse_canonical_operands_sequence(operands.clone(), &[marker_full_operand()], &[])
        {
            operands
        } else {
            parse_canonical_operands_sequence(operands, &[OperandType::Label], &[])?
        };

        let dst_true = operands[0].clone();

        let condition = pick_condition(&mut modifiers)?;

        let new = Self {
            condition,
            destination_true: dst_true,
        };

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Jump instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

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
            &mut self.destination_true,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Jump> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Jump) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Jump(JumpOpcode),
            ..OpcodeVariant::default()
        };
        new.condition = value.condition.0;
        set_src0_or_dst0_full_operand(
            &value.destination_true.as_generic_operand(0)?,
            &mut new,
            false,
        );

        Ok(new)
    }
}
