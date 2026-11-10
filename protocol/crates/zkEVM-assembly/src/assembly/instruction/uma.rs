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
pub struct UMA {
    /// Condition for execution
    pub condition: ConditionCase,
    /// Source register for key
    pub src_0: NonMemoryOperand,
    /// Source register for value on write
    pub src_1: RegisterOperand,
    /// The destination register for value on read, or incremented source on write
    pub dst_0: RegisterOperand,
    /// The destination register incremented source on read
    pub dst_1: RegisterOperand,
    /// Type of log
    pub uma_type: UMAOpcode,
    /// increment offset or not
    pub increment_offset: bool,
}

impl UMA {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 7] = [
        "heap_read",
        "heap_write",
        "aux_heap_read",
        "aux_heap_write",
        "fat_ptr_read",
        "static_read",
        "static_write",
    ];

    pub const INCREMENT_OFFSET_MODIFIER: &'static str = "inc";

    pub const ALL_SHORTHARD_MODIFIERS: [&'static str; 7] =
        ["rh", "wh", "rah", "wah", "rptr", "rs", "ws"];

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        let operands = parse_canonical_operands_sequence(
            operands,
            &[marker_non_mem_operand(), marker_register_operand()],
            &[marker_register_operand(), marker_register_operand()],
        )?;

        if modifiers.is_empty() {
            return Err(InstructionReadError::InvalidArgument {
                index: 0,
                expected: "UMA opcode must contain a type modifier",
                found: "no modifiers".to_owned(),
            });
        }

        let condition = pick_condition(&mut modifiers)?;

        let mut result = None;
        for (idx, modifier) in Self::ALL_CANONICAL_MODIFIERS.iter().enumerate() {
            if modifiers.contains(modifier) {
                if result.is_some() {
                    return Err(InstructionReadError::UnknownArgument(format!(
                        "UMA: duplicate variant in modifiers: already have {:?}, got {}",
                        result.unwrap(),
                        modifier
                    )));
                } else {
                    modifiers.remove(modifier);
                    let variant = match idx {
                        0 => UMAOpcode::HeapRead,
                        1 => UMAOpcode::HeapWrite,
                        2 => UMAOpcode::AuxHeapRead,
                        3 => UMAOpcode::AuxHeapWrite,
                        4 => UMAOpcode::FatPointerRead,
                        5 => UMAOpcode::StaticMemoryRead,
                        6 => UMAOpcode::StaticMemoryWrite,
                        _ => {
                            unreachable!()
                        }
                    };
                    result = Some(variant);
                }
            }
        }

        if result.is_none() {
            for (idx, modifier) in Self::ALL_SHORTHARD_MODIFIERS.iter().enumerate() {
                if modifiers.contains(modifier) {
                    if result.is_some() {
                        return Err(InstructionReadError::UnknownArgument(
                            format!("UMA: duplicate shorthand variant in modifiers: already have {:?}, got {}",
                            result.unwrap(),
                            modifier
                        )));
                    } else {
                        modifiers.remove(modifier);
                        let variant = match idx {
                            0 => UMAOpcode::HeapRead,
                            1 => UMAOpcode::HeapWrite,
                            2 => UMAOpcode::AuxHeapRead,
                            3 => UMAOpcode::AuxHeapWrite,
                            4 => UMAOpcode::FatPointerRead,
                            5 => UMAOpcode::StaticMemoryRead,
                            6 => UMAOpcode::StaticMemoryWrite,
                            _ => {
                                unreachable!()
                            }
                        };
                        result = Some(variant);
                    }
                }
            }
        }

        let variant = result.ok_or(InstructionReadError::UnknownArgument(
            "UMA instruction contains no modifier, but should containt access type".to_owned(),
        ))?;

        let increment_offset = modifiers.remove(Self::INCREMENT_OFFSET_MODIFIER);

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "UMA instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let new = Self {
            condition,
            src_0: operands[0].clone().as_non_memory_operand(0)?,
            src_1: operands[1].clone().as_register_operand(1)?,
            dst_0: operands[2].clone().as_register_operand(0)?,
            dst_1: operands[3].clone().as_register_operand(1)?,
            uma_type: variant,
            increment_offset,
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

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<UMA> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: UMA) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::UMA(value.uma_type),
            ..OpcodeVariant::default()
        };
        match new.variant.opcode.input_operands(crate::get_isa_version())[0] {
            Operand::RegOrImm(_) => {
                assert!(crate::get_isa_version().0 >= 1);
                set_src_non_memory_operand(&value.src_0, &mut new);
            }
            Operand::RegOnly => {
                let as_register = value.src_0.as_register_operand(0)?;
                set_src0_or_dst0_register_operand(&as_register, &mut new, false);
            }
            _ => unreachable!(),
        }
        set_register_operand(&value.src_1, &mut new, false);
        set_src0_or_dst0_register_operand(&value.dst_0, &mut new, true);
        set_register_operand(&value.dst_1, &mut new, true);
        new.condition = value.condition.0;
        new.variant.flags[zkevm_opcode_defs::UMA_INCREMENT_FLAG_IDX] = value.increment_offset;

        Ok(new)
    }
}
