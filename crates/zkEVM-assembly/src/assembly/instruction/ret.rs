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
pub struct Ret {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Source register for return parameters
    pub source_for_meta_args: RegisterOperand,
    /// Type of return
    pub variant: RetOpcode,
    /// Return to specific label
    pub is_to_label: bool,
    /// Label to use
    pub label_for_return: Option<FullOperand>,
}

impl Ret {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 3] = ["ok", "revert", "panic"];

    // Total number of arguments in canonical form
    pub const NUM_ARGUMENTS: usize = 1;

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let condition = pick_condition(&mut modifiers)?;

        let mut result = None;
        for (idx, modifier) in Self::ALL_CANONICAL_MODIFIERS.iter().enumerate() {
            if modifiers.contains(modifier) {
                if result.is_some() {
                    return Err(InstructionReadError::UnknownArgument(format!(
                        "duplicate variant in modifiers: already have {:?}, got {}",
                        result.unwrap(),
                        modifier
                    )));
                } else {
                    modifiers.remove(modifier);
                    let variant = match idx {
                        0 => RetOpcode::Ok,
                        1 => RetOpcode::Revert,
                        2 => RetOpcode::Panic,
                        _ => unreachable!(),
                    };
                    result = Some(variant);
                }
            }
        }

        if result.is_none() {
            // our default behavior
            result = Some(RetOpcode::Ok);
        }

        let is_to_label = modifiers.remove("to_label");

        let (src0, label) = if !is_to_label {
            let operands =
                parse_canonical_operands_sequence(operands, &[marker_register_operand()], &[])?;

            let src0 = operands[0].clone().as_register_operand(0)?;

            (src0, None)
        } else {
            let operands = parse_canonical_operands_sequence(
                operands,
                &[marker_register_operand(), OperandType::Label],
                &[],
            )?;

            let src0 = operands[0].clone().as_register_operand(0)?;
            let label = operands[1].clone();

            (src0, Some(label))
        };

        let variant = result.ok_or(InstructionReadError::UnknownArgument(
            "Ret instruction contains no modifier".to_owned(),
        ))?;

        let new = Self {
            condition,
            source_for_meta_args: src0,
            variant,
            is_to_label,
            label_for_return: label,
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
        if !self.is_to_label {
            return Ok(());
        }

        let label = self
            .label_for_return
            .as_mut()
            .expect("if we return to label we should have a label");
        link_operand::<N, E>(
            label,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Ret> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Ret) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Ret(value.variant),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_register_operand(&value.source_for_meta_args, &mut new, false);
        new.condition = value.condition.0;
        if value.is_to_label {
            let offset = value
                .label_for_return
                .expect("if we return to label we should have a label")
                .as_generic_operand(1)?
                .as_pc_offset();
            new.imm_0 = E::PcOrImm::from_u64_clipped(offset);
            new.variant.flags[0] = true;
        } else {
            assert!(value.label_for_return.is_none());
            new.variant.flags[0] = false;
        }

        Ok(new)
    }
}
