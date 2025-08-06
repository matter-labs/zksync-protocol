#![no_std]
#![feature(allocator_api)]

extern crate alloc;

pub mod auxiliary;
pub use auxiliary as aux;
pub mod precompiles;
pub mod queries;
pub mod utils;
pub mod vm;
pub use zkevm_opcode_defs;
