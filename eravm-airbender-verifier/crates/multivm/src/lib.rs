#![warn(unused_imports)]
// This reduced verifier port intentionally keeps upstream VM surfaces that are not all exercised
// by the current verifier-only build.
#![allow(dead_code)]

// The circuit tracer is sequencer-only machinery the proving guest must compile
// out (see versions/vm_fast/tracers/circuits.rs). The guest opts out via
// `default-features = false`, but Cargo feature unification can silently
// re-enable the feature (e.g. reverting the explicit path deps in
// guest/Cargo.toml or crates/airbender_verifier/Cargo.toml to
// `workspace = true`, or a new dependency pulling this crate with default
// features into the guest graph) — so fail any riscv32 build that has it on.
#[cfg(all(target_arch = "riscv32", feature = "circuit_tracer"))]
compile_error!(
    "`circuit_tracer` must be disabled in guest (riscv32) builds: check that \
     guest/Cargo.toml and crates/airbender_verifier/Cargo.toml still disable default \
     features, and that no dependency pulls zksync_multivm with default features."
);

pub use zksync_types::vm::VmVersion;
pub use zksync_vm_interface as interface;

pub use crate::{
    glue::{
        history_mode::HistoryMode,
        tracers::{IntoOldVmTracer, MultiVmTracer, MultiVmTracerPointer},
    },
    versions::{vm_fast, vm_latest},
    vm_instance::{is_supported_by_fast_vm, FastVmInstance, LegacyVmInstance},
};

mod glue;
pub mod pubdata_builders;
pub mod tracers;
pub mod utils;
mod versions;
mod vm_instance;
