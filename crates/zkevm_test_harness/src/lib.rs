#![recursion_limit = "64"]
#![feature(allocator_api)]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(bigint_helper_methods)]
#![allow(unused_imports)]
#![allow(
    dropping_references,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_range_loop
)]

use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;

pub use circuit_definitions::boojum;
pub use circuit_definitions::snark_wrapper;
pub use circuit_definitions::zk_evm;
pub use circuit_definitions::zkevm_circuits;
pub use rescue_poseidon::franklin_crypto;
pub use snark_wrapper::rescue_poseidon;

pub use crate::zk_evm::blake2;
pub use crate::zk_evm::sha2;
pub use crate::zk_evm::sha3;

pub mod data_source;
pub mod entry_point;
pub mod tracers;
pub use circuit_sequencer_api::geometry_config;
pub use kzg;
pub mod prover_utils;
pub mod snark_wrapper_test;
pub mod utils;
pub mod witness;

// Debugging tools (for example for failed proofs).
pub mod debug;

pub use crate::zk_evm::ethereum_types;

use self::utils::*;

pub mod capacity_estimator;
pub mod external_calls;
pub mod toolset;
// pub mod circuit_limit_estimator;

pub use circuit_sequencer_api::INITIAL_MONOTONIC_CYCLE_COUNTER;

// #[cfg(test)]
pub mod helper;
pub(crate) mod tests;

pub mod compute_setups;
pub mod proof_wrapper_utils;

pub use tests::complex_tests::utils::empty_node_proof;

mod run_vms;
