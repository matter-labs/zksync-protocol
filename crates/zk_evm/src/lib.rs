#![allow(
    clippy::bool_comparison, // Local preference.
    clippy::bool_assert_comparison, // Local preference.
    clippy::match_like_matches_macro, // Doesn't always look better.
    clippy::let_and_return, // Worsens readability.
    clippy::collapsible_else_if, // Local preference.
    clippy::collapsible_if, // Local preference.
    clippy::collapsible_match, // Local preference.
    clippy::assign_op_pattern, // Local preference.
    clippy::single_match, // Local preference.
)]

pub mod block_properties;
pub mod errors;
pub mod flags;
pub mod opcodes;
pub mod reference_impls;
pub mod testing;
pub mod tracing;
pub mod utils;
pub mod vm_state;
pub mod witness_trace;

pub use self::utils::*;

pub use crate::zkevm_opcode_defs::{bitflags, ethereum_types};

use self::ethereum_types::{Address, U256};

pub use crate::zkevm_opcode_defs::blake2;
pub use crate::zkevm_opcode_defs::k256;
pub use crate::zkevm_opcode_defs::sha2;
pub use crate::zkevm_opcode_defs::sha3;
pub use zk_evm_abstractions;
pub use zk_evm_abstractions::zkevm_opcode_defs;

// Re-export abstractions.
pub mod abstractions {
    pub use zk_evm_abstractions::vm::*;
}
pub mod aux_structures {
    pub use zk_evm_abstractions::aux::*;
    pub use zk_evm_abstractions::queries::*;
}
