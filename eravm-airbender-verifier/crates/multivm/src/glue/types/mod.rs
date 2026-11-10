//! Glue for the basic types that are used in the VM.
//! This is "internal" glue that converts between shared `zksync_types` forms and
//! the active VM implementation types.
//!
//! This "glue layer" is generally not visible outside of the crate.

mod vm;
mod zk_evm_1_5_2;
