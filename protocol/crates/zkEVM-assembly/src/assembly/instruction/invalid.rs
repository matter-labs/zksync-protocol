//!
//! The Invalid instruction
//!

use super::*;

///
/// The INVALID instruction. It's puspose is some
/// form of penalty, e.g. calling page number 0, or something
/// similar
///
#[derive(Debug, Clone, PartialEq)]
pub struct Invalid {
    /// Condition for execution
    pub condition: ConditionCase,
}

impl Invalid {
    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let _operands = parse_canonical_operands_sequence(operands, &[], &[])?;

        let condition = pick_condition(&mut modifiers)?;

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Invalid instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self { condition };

        Ok(new)
    }

    #[track_caller]
    pub(crate) fn link<const N: usize, E: VmEncodingMode<N>>(
        &mut self,
        _function_labels_to_pc: &HashMap<String, usize>,
        _constant_labels_to_offset: &HashMap<String, usize>,
        _globals_to_offsets: &HashMap<String, usize>,
    ) -> Result<(), AssemblyParseError> {
        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Invalid> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Invalid) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = zkevm_opcode_defs::INVALID_OPCODE_VARIANT;
        new.condition = value.condition.0;

        Ok(new)
    }
}
