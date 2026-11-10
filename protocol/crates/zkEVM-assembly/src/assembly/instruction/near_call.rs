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
pub struct NearCall {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Ergs parameter
    pub source_for_passed_ergs: RegisterOperand,
    /// Destination to jump-call
    pub destination: FullOperand,
    /// Exception handler
    pub exception_handler: FullOperand,
}

impl NearCall {
    // Total number of arguments in canonical form
    pub const NUM_ARGUMENTS: usize = 1;

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = parse_canonical_operands_sequence(
            operands,
            &[
                marker_register_operand(),
                OperandType::Label,
                OperandType::Label,
            ],
            &[],
        )?;

        let src0 = operands[0].clone().as_register_operand(0)?;
        let dst = operands[1].clone();
        let exception_handler = operands[2].clone();
        let condition = pick_condition(&mut modifiers)?;
        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Near call instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self {
            condition,
            source_for_passed_ergs: src0,
            destination: dst,
            exception_handler,
        };

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "{:?}",
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
            &mut self.destination,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;
        link_operand::<N, E>(
            &mut self.exception_handler,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<NearCall> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: NearCall) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::NearCall(NearCallOpcode),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_register_operand(&value.source_for_passed_ergs, &mut new, false);
        new.condition = value.condition.0;

        let offset_for_dest = value.destination.as_generic_operand(1)?.as_pc_offset();
        let offset_for_eh = value
            .exception_handler
            .as_generic_operand(2)?
            .as_pc_offset();
        new.imm_0 = E::PcOrImm::from_u64_clipped(offset_for_dest);
        new.imm_1 = E::PcOrImm::from_u64_clipped(offset_for_eh);

        Ok(new)
    }
}
