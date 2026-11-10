use serde::{Deserialize, Serialize};
use zksync_types::{block::L2BlockExecutionData, InteropRoot, H256};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct L2BlockEnv {
    pub number: u32,
    pub timestamp: u64,
    pub prev_block_hash: H256,
    pub max_virtual_blocks_to_create: u32,
    pub interop_roots: Vec<InteropRoot>,
}

impl L2BlockEnv {
    pub fn from_l2_block_data(execution_data: &L2BlockExecutionData) -> Self {
        Self {
            number: execution_data.number.0,
            timestamp: execution_data.timestamp,
            prev_block_hash: execution_data.prev_block_hash,
            max_virtual_blocks_to_create: execution_data.virtual_blocks,
            interop_roots: execution_data.interop_roots.clone(),
        }
    }
}
