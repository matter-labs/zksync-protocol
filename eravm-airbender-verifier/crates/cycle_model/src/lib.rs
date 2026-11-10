//! Airbender cycle-cost calibration harness (offline).
//!
//! Measures real batches — cheap `zksync_vm2` features paired with ground-truth
//! Airbender RISC-V guest cycles — and produces the dataset the cost model is fit
//! from. The feature schema, cost model, and estimator live in the lean
//! [`zksync_era_airbender_cycles_estimator`] crate; the passive vm2 tracer lives
//! in [`zksync_era_airbender_cycles_tracer`] (both of which the sequencer uses);
//! this crate builds the labelled dataset on top of them.
pub mod dataset;
pub mod provenance;
pub mod runner;

pub use dataset::{extract_features, write_dataset, DatasetRow};
pub use provenance::DatasetProvenance;
pub use runner::{run_guest, GuestMeasurement};

// Re-export the shared schema/model + vm2 tracer so existing
// `zksync_cycle_model::{FeatureId, ...}` paths keep working and
// callers need only this crate.
pub use zksync_era_airbender_cycles_estimator::{
    estimate_from_features, CostTable, CycleEstimate, FeatureId, FeatureVector,
};
pub use zksync_era_airbender_cycles_tracer::CycleFeatureTracer;
