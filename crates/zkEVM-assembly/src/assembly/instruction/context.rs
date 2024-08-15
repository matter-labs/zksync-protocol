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
pub struct Context {
    /// Condition for execution
    pub condition: ConditionCase,
    /// The formal source location
    pub source_location: RegisterOperand,
    /// The formal destination location
    pub destination_location: RegisterOperand,
    /// Information to get
    pub field: ContextOpcode,
}

impl Context {
    // must follow in the same sequence as variants of the opcode
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 10] = [
        "this",
        "caller",
        "code_source",
        "meta",
        "ergs_left",
        "sp",
        "get_context_u128",
        "set_context_u128",
        "set_ergs_per_pubdata",
        "inc_tx_num",
    ];

    #[track_caller]
    pub fn build_from_parts(
        mut modifiers: HashSet<&str>,
        operands: Vec<&str>,
    ) -> Result<Self, InstructionReadError> {
        // since we are interested in register only, we parse as-is, but later on deside how to use it

        if modifiers.is_empty() {
            return Err(InstructionReadError::InvalidArgument {
                index: 0,
                expected: "context opcode must containt a modifier",
                found: "no modifiers".to_owned(),
            });
        }

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
                        i if i == ContextOpcode::This.variant_index() => ContextOpcode::This,
                        i if i == ContextOpcode::Caller.variant_index() => ContextOpcode::Caller,
                        i if i == ContextOpcode::CodeAddress.variant_index() => {
                            ContextOpcode::CodeAddress
                        }
                        i if i == ContextOpcode::Meta.variant_index() => ContextOpcode::Meta,
                        i if i == ContextOpcode::ErgsLeft.variant_index() => {
                            ContextOpcode::ErgsLeft
                        }
                        i if i == ContextOpcode::Sp.variant_index() => ContextOpcode::Sp,
                        i if i == ContextOpcode::GetContextU128.variant_index() => {
                            ContextOpcode::GetContextU128
                        }
                        i if i == ContextOpcode::SetContextU128.variant_index() => {
                            ContextOpcode::SetContextU128
                        }
                        i if i == ContextOpcode::AuxMutating0.variant_index() => {
                            ContextOpcode::AuxMutating0
                        }
                        i if i == ContextOpcode::IncrementTxNumber.variant_index() => {
                            ContextOpcode::IncrementTxNumber
                        }
                        _ => {
                            unreachable!()
                        }
                    };
                    result = Some(variant);
                }
            }
        }

        let variant = result.ok_or(InstructionReadError::UnknownArgument(
            "Context instruction contains no modifier".to_owned(),
        ))?;

        let condition = pick_condition(&mut modifiers)?;

        if !modifiers.is_empty() {
            return Err(InstructionReadError::UnknownArgument(format!(
                "Context instruction contains unknown modifiers: {:?}",
                modifiers
            )));
        }

        let (source_location, destination_location) = match variant {
            ContextOpcode::SetContextU128 | ContextOpcode::AuxMutating0 => {
                let operands =
                    parse_canonical_operands_sequence(operands, &[], &[marker_register_operand()])?;

                let location = operands[0].clone();
                let src = location.as_register_operand(0)?;

                (src, RegisterOperand::Null)
            }
            ContextOpcode::IncrementTxNumber => {
                let _operands = parse_canonical_operands_sequence(operands, &[], &[])?;

                (RegisterOperand::Null, RegisterOperand::Null)
            }
            _ => {
                let operands =
                    parse_canonical_operands_sequence(operands, &[marker_register_operand()], &[])?;

                let location = operands[0].clone();
                let dst = location.as_register_operand(0)?;

                (RegisterOperand::Null, dst)
            }
        };

        let new = Self {
            condition,
            source_location,
            destination_location,
            field: variant,
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

impl<const N: usize, E: VmEncodingMode<N>> TryFrom<Context> for DecodedOpcode<N, E> {
    type Error = InstructionReadError;
    fn try_from(value: Context) -> Result<Self, Self::Error> {
        let mut new = DecodedOpcode::default();
        new.variant = OpcodeVariant {
            opcode: Opcode::Context(value.field),
            ..OpcodeVariant::default()
        };
        set_src0_or_dst0_register_operand(&value.source_location, &mut new, false);
        set_src0_or_dst0_register_operand(&value.destination_location, &mut new, true);
        new.condition = value.condition.0;

        Ok(new)
    }
}
