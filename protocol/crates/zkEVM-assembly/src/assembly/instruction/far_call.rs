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
pub struct FarCall {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Called address parameter
    pub source_for_address_to_call: RegisterOperand,
    /// Ergs parameter
    pub source_for_meta_args: RegisterOperand,
    /// Exception handler
    pub exception_handler: FullOperand,
    /// Call variant
    pub variant: FarCallOpcode,
    /// Perform a call under static context restrictions
    pub is_static: bool,
    /// Perform a call to another shard
    pub is_call_shard: bool,
}

impl FarCall {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 2] = ["delegate", "mimic"];

    // Total number of arguments in canonical form
    pub const NUM_ARGUMENTS: usize = 3;

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = parse_canonical_operands_sequence(
            operands,
            &[
                marker_register_operand(),
                marker_register_operand(),
                OperandType::Label,
            ],
            &[],
        )?;

        let src0 = operands[0].clone().as_register_operand(0)?;
        let src1 = operands[1].clone().as_register_operand(1)?;

        let is_static = modifiers.remove("static");

        let is_call_shard = modifiers.remove("shard");

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
                        0 => FarCallOpcode::Delegate,
                        1 => FarCallOpcode::Mimic,
                        _ => unreachable!(),
                    };
                    result = Some(variant);
                }
            }
        }
        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "{:?}",
                modifiers
            )));
        }

        if result.is_none() {
            // our default behavior
            result = Some(FarCallOpcode::Normal);
        }

        let variant = result.ok_or(InstructionReadError::UnknownArgument(
            "Far Call instruction contains no modifier".to_owned(),
        ))?;

        let exception_handler = operands[2].clone();

        let new = Self {
            condition,
            source_for_address_to_call: src0,
            source_for_meta_args: src1,
            exception_handler,
            variant,
            is_static,
            is_call_shard,
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
            &mut self.exception_handler,
            function_labels_to_pc,
            constant_labels_to_offset,
            globals_to_offsets,
        )?;

        Ok(())
    }
}

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<FarCall> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: FarCall) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::FarCall(value.variant),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_register_operand(&value.source_for_address_to_call, &mut new, false);
        set_register_operand(&value.source_for_meta_args, &mut new, false);
        new.condition = value.condition.0;
        new.variant.flags[FAR_CALL_STATIC_FLAG_IDX] = value.is_static;
        new.variant.flags[FAR_CALL_SHARD_FLAG_IDX] = value.is_call_shard;
        new.imm_0 = E::PcOrImm::from_u64_clipped(
            value
                .exception_handler
                .as_generic_operand(2)?
                .as_pc_offset(),
        );

        Ok(new)
    }
}
