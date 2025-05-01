use super::*;

pub mod compression;
pub mod interblock;
pub mod leaf_layer;
pub mod node_layer;
pub mod recursion_tip;

pub const VK_COMMITMENT_LENGTH: usize = 4;
pub const NUM_BASE_LAYER_CIRCUITS: usize = 20;
