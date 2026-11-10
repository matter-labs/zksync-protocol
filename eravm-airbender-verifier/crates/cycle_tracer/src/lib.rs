//! Fast-VM (`zksync_vm2`) tracer for the Airbender cycle-cost model.
//!
//! The sequencer attaches a [`CycleFeatureTracer`] while it executes a batch on
//! the fast VM (it is passive — no VM-state mutation, so execution is identical
//! to a proved run). After the batch finishes it feeds the tracer's counts to
//! the VM-agnostic estimator:
//!
//! ```ignore
//! use zksync_era_airbender_cycles_estimator::estimate_from_features;
//! let est = estimate_from_features(tracer.snapshot(), pubdata, diffs, txs, leaves);
//! ```
//!
//! The feature schema, fitted cost model, and result type live in the
//! [`zksync_era_airbender_cycles_estimator`] crate; this crate is only the
//! `zksync_vm2` half that observes a live execution.
pub mod tracer;

pub use tracer::CycleFeatureTracer;
