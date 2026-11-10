//!
//! Read value from execution context.
//!

use super::*;

use crate::error::InstructionReadError;
use std::collections::HashMap;
use std::convert::TryFrom;

///
/// Read value from execution context.
///
#[derive(Debug, Clone, PartialEq)]
pub struct Log {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Source register for key
    pub key: RegisterOperand,
    /// Source register for value on write
    pub value_source: RegisterOperand,
    /// The destination register for value on read
    pub value_destination: RegisterOperand,
    /// Type of log
    pub log_type: LogOpcode,
    /// Indicator of the initial message
    pub is_initial: bool,
}

impl Log {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 8] = [
        "sread",
        "swrite",
        "event",
        "to_l1",
        "precompile",
        "decommit",
        "tread",
        "twrite",
    ];

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = parse_canonical_operands_sequence(
            operands,
            &[marker_register_operand(), marker_register_operand()],
            &[marker_register_operand()],
        )?;

        let is_initial = modifiers.remove("first");

        if modifiers.is_empty() {
            return Err(InstructionReadError::InvalidArgument {
                index: 0,
                expected: "Log opcode must contain a type modifier",
                found: "no modifiers".to_owned(),
            });
        }

        let condition = pick_condition(&mut modifiers)?;

        let mut result = None;
        for (idx, modifier) in Self::ALL_CANONICAL_MODIFIERS.iter().enumerate() {
            if modifiers.contains(modifier) {
                if result.is_some() {
                    return Err(InstructionReadError::UnknownArgument(format!(
                        "Log opcode: duplicate variant in modifiers: already have {:?}, got {}",
                        result.unwrap(),
                        modifier
                    )));
                } else {
                    modifiers.remove(modifier);
                    let variant = match idx {
                        0 => LogOpcode::StorageRead,
                        1 => LogOpcode::StorageWrite,
                        2 => LogOpcode::Event,
                        3 => LogOpcode::ToL1Message,
                        4 => LogOpcode::PrecompileCall,
                        5 => LogOpcode::Decommit,
                        6 => LogOpcode::TransientStorageRead,
                        7 => LogOpcode::TransientStorageWrite,
                        _ => {
                            unreachable!()
                        }
                    };
                    result = Some(variant);
                }
            }
        }

        let variant = result.ok_or(InstructionReadError::UnknownArgument(
            "Log instruction contains no modifier".to_owned(),
        ))?;

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Log instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self {
            condition,
            key: operands[0].clone().as_register_operand(0)?,
            value_source: operands[1].clone().as_register_operand(1)?,
            value_destination: operands[2].clone().as_register_operand(2)?,
            log_type: variant,
            is_initial,
        };

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

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Log> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Log) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Log(value.log_type),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_register_operand(&value.key, &mut new, false);
        set_register_operand(&value.value_source, &mut new, false);
        set_src0_or_dst0_register_operand(&value.value_destination, &mut new, true);
        new.condition = value.condition.0;
        new.variant.flags[0] = value.is_initial;

        Ok(new)
    }
}
