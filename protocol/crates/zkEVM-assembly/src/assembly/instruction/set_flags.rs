//!
//! Condition to apply the operation
//!

use crate::InstructionReadError;

///
/// The control flow jump instruction flag.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SetFlags(pub bool);

impl SetFlags {
    pub const ALL_CANONICAL_MODIFIERS: [&'static str; 1] = ["set_flags"];

    pub fn from_modifier(modifier: &str) -> Result<Self, InstructionReadError> {
        match modifier {
            "set_flags" => Ok(SetFlags(true)),
            _ => Err(InstructionReadError::UnknownArgument(modifier.to_owned())),
        }
    }
}
