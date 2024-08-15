//!
//! Condition to apply the operation
//!

use crate::InstructionReadError;
use zkevm_opcode_defs::Condition;

///
/// The control flow jump instruction flag.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConditionCase(pub(crate) Condition);

impl std::default::Default for ConditionCase {
    fn default() -> Self {
        ConditionCase(Condition::Always)
    }
}

impl ConditionCase {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 8] =
        ["gt", "lt", "eq", "ge", "le", "ne", "gtlt", "of"];

    pub fn from_modifier(modifier: &str) -> Result<Self, InstructionReadError> {
        match modifier {
            m if m == Self::ALL_CANONICAL_MODIFIERS[0] => Ok(ConditionCase(Condition::Gt)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[1] => Ok(ConditionCase(Condition::Lt)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[2] => Ok(ConditionCase(Condition::Eq)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[3] => Ok(ConditionCase(Condition::Ge)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[4] => Ok(ConditionCase(Condition::Le)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[5] => Ok(ConditionCase(Condition::Ne)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[6] => Ok(ConditionCase(Condition::GtOrLt)),
            m if m == Self::ALL_CANONICAL_MODIFIERS[7] => Ok(ConditionCase(Condition::Lt)),
            _ => Err(InstructionReadError::UnknownArgument(modifier.to_owned())),
        }
    }
}
